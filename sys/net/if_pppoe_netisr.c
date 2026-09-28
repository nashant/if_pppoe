/* $NetBSD: if_pppoe.c,v 1.187 2026/03/05 09:59:17 riastradh Exp $ */

/*-
 * Copyright (c) 2002, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Martin Husemann <martin@NetBSD.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Netisr seam of the split if_pppoe(4) module.
 *
 * Everything that touches the private netisr protocol lives here: the
 * protocol block (NETISR_PPPOE_DATA with POLICY_CPU + HYBRID dispatch), the
 * inner-flow software hash, the per-CPU spreading decision, and the
 * net.pppoe.cpu_hits evidence counters that prove the spreading is real.
 * pppoe_data_input() (the handler's payload, counting into the shared per-vnet
 * stats) and V_pppoe_reflect stay in if_pppoe.c; the cross-file surface is
 * if_pppoe_var.h.
 *
 * Moved verbatim from if_pppoe.c (same NetBSD lineage); the only deltas are
 * the dropped `static` on symbols the core calls and the include list.
 */

#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/cpuset.h>
#include <sys/endian.h>
#include <sys/epoch.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/pcpu.h>
#include <sys/random.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/if_pppoe.h>
#include <net/if_pppoe_var.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/*
 * ---------------------------------------------------------------------------
 * The private netisr protocol (spec section 6.4) -- the reason this driver
 * exists.  mpd5/netgraph processes a PPPoE session on whichever CPU the parent
 * NIC's receive queue lands on, so one session cannot exceed one core.  Here
 * each decapsulated frame is handed to NETISR_PPPOE_DATA with
 * NETISR_POLICY_CPU + NETISR_DISPATCH_HYBRID: netisr_dispatch_src() asks
 * pppoe_m2cpuid() for a CPU and runs the handler in place when that is curcpu
 * (netisr.c:1201-1203), otherwise queues to that CPU's workstream (:1174,
 * :1228-1229).
 * The global net.isr.dispatch is never touched; netisr.c:1147-1155 is the
 * global direct-dispatch shortcut this deliberately avoids.
 */

/*
 * Per-boot seed for the inner-flow hash.  Random so that a peer cannot pick
 * addresses that all land on one workstream; fixed once random(4) is seeded
 * so that one flow always maps to one CPU (per-flow ordering).
 *
 * A module preloaded from loader.conf runs MOD_LOAD at SI_SUB_PSEUDO, and
 * random(4) need not be seeded by then (no /boot/entropy stash, no RDRAND).
 * Before seeding, arc4random(9) does not wait: with the default
 * kern.random.initial_seeding.bypass_before_seeding=1 (releng/14.3
 * sys/dev/random/random_infra.c:50) it keys ChaCha20 from uninitialised
 * stack, get_cyclecount() and __FreeBSD_version (sys/libkern/arc4random.c:
 * 93-125).  It re-keys itself once random(4) seeds (randomdev_unblock()
 * moves arc4rand_iniseed_state to HAVE, sys/dev/random/randomdev.c:373, and
 * the next arc4rand() stirs, arc4random.c:205-210), but a value already
 * drawn stays weak.  So MOD_LOAD draws an interim seed and, when
 * is_random_seeded() says no, flags it; the first hashed frame at least a
 * second after that kicks pppoe_hash_task, which redraws with read_random()
 * once random(4) is seeded.  read_random() rather than arc4random(): fortuna
 * calls randomdev_unblock() before it counts the first reseed
 * (sys/dev/random/fortuna.c:433-435), and another CPU can still be
 * mid-stir, so an arc4random() right after is_random_seeded() turns true
 * could still come from the weak key; read_random() does not block once
 * seeded (randomdev.c:267-285).  The one seed change remaps every flow once,
 * a reorder window like a dispatch map rebuild (docs/PERF-DESIGN.md).
 *
 * pppoe_hash_unseeded is zero, "seeded", unless pppoe_hash_init() sets it,
 * so the hot path pays one predicted load.
 */
static u_int pppoe_hash_seed;
static u_int pppoe_hash_unseeded;
static u_int pppoe_hash_pending;
static int pppoe_hash_kicked;		/* ticks of the last seeding attempt */
static struct task pppoe_hash_task;

static void
pppoe_hash_task_fn(void *ctx __unused, int pending __unused)
{
	uint32_t seed;

	if (is_random_seeded()) {
		read_random(&seed, sizeof(seed));
		atomic_store_int(&pppoe_hash_seed, seed);
		atomic_store_rel_int(&pppoe_hash_unseeded, 0);
	}
	pppoe_hash_kicked = ticks;
	atomic_store_rel_int(&pppoe_hash_pending, 0);
}

void
pppoe_hash_init(void)
{

	TASK_INIT(&pppoe_hash_task, 0, pppoe_hash_task_fn, NULL);
	pppoe_hash_kicked = ticks;
	pppoe_hash_unseeded = !is_random_seeded();
	pppoe_hash_seed = arc4random();
}

/* After the pfil sweep: no pppoe_hash_inner() can run or start. */
void
pppoe_hash_fini(void)
{

	taskqueue_drain(pppoe_taskq, &pppoe_hash_task);
}

/*
 * Hash the decapsulated payload and stamp it on the mbuf; true on success.
 * m points at the 2-byte PPP protocol field (pppoe_sess_input() has already
 * stripped the 20-byte Ethernet+PPPoE header), so the inner IP header starts
 * two bytes in -- and is therefore only 2-byte aligned, hence the memcpy()s
 * (which compile to plain unaligned loads on amd64).
 *
 * The parent NIC may already have stamped a flowid for the *outer* frame.
 * For PPPoE that hash is over a single MAC pair and a single session, so it
 * is the same value for every frame of a session and would spread nothing.
 * The caller therefore clears it when this returns false, rather than letting
 * pppoe_m2cpuid() inherit it.
 *
 * Always compiled, whatever the kernel's `options RSS`.  The old arm called
 * rss_proto_software_hash_v4/v6() -- a software Toeplitz over a 40-byte key,
 * several hundred cycles a frame, on the one CPU the whole session's receive
 * stage is pinned to (docs/RX-SCALING.md) -- and without `options RSS` it
 * returned false for everything, so a non-RSS kernel did not spread at all.
 * Nothing downstream needs a Toeplitz value: pppoe_m2cpuid() only takes it
 * modulo the workstream count, and ip_input() (called in place from the
 * netisr handler) never re-dispatches.  jenkins_hash32() (sys/hash.h,
 * libkern) over 3 or 9 words is a few dozen cycles.  The type is
 * M_HASHTYPE_OPAQUE_HASH -- "ordering, not affinity" plus the hash
 * property (sys/mbuf.h) -- because it is not an RSS hash and must not be
 * mistaken for one by a consumer that checks (the in_pcb RSS lookup, or a
 * LAN NIC's TX queue selection, which is happy with any hashed type).
 *
 * The key.  TCP/UDP: addresses, protocol and both ports.  Anything else,
 * and ANY IPv4 fragment -- MF set or a non-zero offset, the first fragment
 * included -- hashes addresses and protocol only, so every fragment of a
 * datagram lands on the same workstream as its siblings and they stay in
 * order relative to each other (the first fragment carries ports, the rest
 * do not; hashing the first on ports would split the datagram).  IPv6 does
 * the same by construction: a fragment's next header is IPPROTO_FRAGMENT,
 * so it never reaches the ports arm.  No extension-header walk: anything
 * but a bare TCP/UDP next header hashes as addresses + next header, which
 * still pins the flow to one CPU and so still preserves its ordering.
 *
 * The remaining reorder window is the one ordering cannot close without
 * the fragment arm: a TCP/UDP flow that sends some packets fragmented and
 * some whole can see the two kinds on different workstreams.  TCP sets DF
 * (path MTU discovery) and so never fragments in practice; a UDP
 * application that mixes both is already reorder-tolerant by protocol.
 */
bool
pppoe_hash_inner(struct mbuf *m)
{
	uint32_t w[9], hash;
	const uint8_t *p;
	uint16_t proto;
	size_t n;

	if (m->m_len < 2)
		return (false);
	p = mtod(m, const uint8_t *);
	proto = be16dec(p);
	p += 2;

	if (proto == PPP_IP) {
		const struct ip *ip;
		int hlen;

		if (m->m_len < 2 + (int)sizeof(struct ip))
			return (false);
		ip = (const struct ip *)p;
		if (ip->ip_v != IPVERSION || ip->ip_hl < 5)
			return (false);
		hlen = ip->ip_hl << 2;
		memcpy(&w[0], &ip->ip_src, sizeof(w[0]));
		memcpy(&w[1], &ip->ip_dst, sizeof(w[1]));
		w[2] = ip->ip_p;
		if ((ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) == 0 &&
		    (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) &&
		    m->m_len >= 2 + hlen + 4) {
			uint32_t ports;

			memcpy(&ports, p + hlen, sizeof(ports));
			w[2] ^= ports;
		}
		n = 3;
	} else if (proto == PPP_IPV6) {
		const struct ip6_hdr *ip6;
		uint8_t nxt;

		if (m->m_len < 2 + (int)sizeof(struct ip6_hdr))
			return (false);
		ip6 = (const struct ip6_hdr *)p;
		if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return (false);
		/* src and dst are contiguous: 32 bytes, 8 words. */
		memcpy(&w[0], &ip6->ip6_src, 2 * sizeof(struct in6_addr));
		nxt = ip6->ip6_nxt;
		w[8] = nxt;
		if ((nxt == IPPROTO_TCP || nxt == IPPROTO_UDP) &&
		    m->m_len >= 2 + (int)sizeof(struct ip6_hdr) + 4) {
			uint32_t ports;

			memcpy(&ports, p + sizeof(struct ip6_hdr),
			    sizeof(ports));
			w[8] ^= ports;
		}
		n = 9;
	} else
		return (false);

	if (__predict_false(atomic_load_acq_int(&pppoe_hash_unseeded) != 0) &&
	    ticks - pppoe_hash_kicked >= hz &&
	    atomic_cmpset_int(&pppoe_hash_pending, 0, 1))
		taskqueue_enqueue(pppoe_taskq, &pppoe_hash_task);
	hash = jenkins_hash32(w, n, atomic_load_int(&pppoe_hash_seed));
	m->m_pkthdr.flowid = hash;
	M_HASHTYPE_SET(m, M_HASHTYPE_OPAQUE_HASH);
	return (true);
}

/*
 * net.pppoe.dispatch_cpus (R4): the CPUs decapsulated flows are spread over.
 * A session's frames all arrive on one parent RX queue/CPU (RSS cannot hash
 * PPPoE), and HYBRID dispatch ran 1/n of the flows' whole forwarding in place
 * on that already-saturated CPU.  "auto" (default) excludes CPU 0, the usual
 * RX-queue CPU; "all" is the old behaviour; or a list like "1-3,5".  A set
 * naming no netisr CPU falls back to all.  Fixed at configuration time, never
 * derived per frame, so a flow keeps one workstream (per-flow ordering).
 * docs/PERF-DESIGN.md has the tradeoffs.
 *
 * The map holds RAW workstream indices (see pppoe_m2cpuid()), is published
 * by pointer, read in the net epoch and freed with NET_EPOCH_CALL().  A
 * module loaded from loader.conf builds it (SI_SUB_PSEUDO) before netisr
 * starts its per-CPU workstreams (SI_SUB_SMP): a map built for another
 * workstream count is ignored and the first frame kicks a rebuild.
 */
struct pppoe_dispatch_map {
	u_int			 dm_nws;	/* netisr_get_cpucount() built for */
	u_int			 dm_n;		/* entries in dm_idx, >= 1 */
	struct epoch_context	 dm_ctx;
	u_int			 dm_idx[];	/* raw workstream indices */
};

#define	PPPOE_DISPATCH_SPECLEN	128

static struct pppoe_dispatch_map *pppoe_dispatch_map;
static char pppoe_dispatch_spec[PPPOE_DISPATCH_SPECLEN] = "auto";
TUNABLE_STR("net.pppoe.dispatch_cpus", pppoe_dispatch_spec,
    sizeof(pppoe_dispatch_spec));
static u_int pppoe_dispatch_pending;
static bool pppoe_dispatch_dead;	/* pppoe_dispatch_fini() ran */
static struct task pppoe_dispatch_task;
/* Serialises the spec string and every map swap. */
static struct sx pppoe_dispatch_lock;
SX_SYSINIT(pppoe_dispatch_lock, &pppoe_dispatch_lock, "pppoe dispatch");

/* "auto" / "" -> *autop; "all" -> every CPU; else "a,b-c,...". */
static int
pppoe_dispatch_parse(const char *s, cpuset_t *set, bool *autop)
{
	u_long a, b;
	char *ep;

	CPU_ZERO(set);
	*autop = false;
	if (*s == '\0' || strcmp(s, "auto") == 0) {
		*autop = true;
		return (0);
	}
	if (strcmp(s, "all") == 0) {
		CPU_FILL(set);
		return (0);
	}
	while (*s != '\0') {
		a = strtoul(s, &ep, 10);
		if (ep == s)
			return (EINVAL);
		b = a;
		if (*ep == '-') {
			s = ep + 1;
			b = strtoul(s, &ep, 10);
			if (ep == s)
				return (EINVAL);
		}
		if (a > b || b >= CPU_SETSIZE)
			return (EINVAL);
		for (; a <= b; a++)
			CPU_SET((int)a, set);
		if (*ep == ',')
			ep++;
		else if (*ep != '\0')
			return (EINVAL);
		s = ep;
	}
	return (0);
}

static void
pppoe_dispatch_map_free(struct epoch_context *ctx)
{

	free(__containerof(ctx, struct pppoe_dispatch_map, dm_ctx), M_PPPOE);
}

/* Build and publish a map for the current spec and workstream count. */
static void
pppoe_dispatch_rebuild(void)
{
	struct pppoe_dispatch_map *map, *old;
	cpuset_t set;
	u_int cpu, i, nws;
	bool autosel;

	sx_assert(&pppoe_dispatch_lock, SA_XLOCKED);
	if (pppoe_dispatch_dead)
		return;		/* a sysctl write racing the unload */
	if (pppoe_dispatch_parse(pppoe_dispatch_spec, &set, &autosel) != 0) {
		/* Only a bad loader tunable gets here; the sysctl validates. */
		printf("pppoe: net.pppoe.dispatch_cpus \"%s\" is not a CPU "
		    "list; using \"auto\"\n", pppoe_dispatch_spec);
		strlcpy(pppoe_dispatch_spec, "auto",
		    sizeof(pppoe_dispatch_spec));
		autosel = true;
	}
	nws = netisr_get_cpucount();
	map = malloc(sizeof(*map) + nws * sizeof(map->dm_idx[0]), M_PPPOE,
	    M_WAITOK | M_ZERO);
	map->dm_nws = nws;
	for (i = 0; i < nws; i++) {
		cpu = netisr_get_cpuid(i);
		if (autosel ? (cpu != 0) : CPU_ISSET(cpu, &set))
			map->dm_idx[map->dm_n++] = i;
	}
	if (map->dm_n == 0) {
		/* One workstream, or a set naming none of them: use all. */
		for (i = 0; i < nws; i++)
			map->dm_idx[i] = i;
		map->dm_n = nws;
	}
	old = pppoe_dispatch_map;
	atomic_store_rel_ptr((volatile uintptr_t *)&pppoe_dispatch_map,
	    (uintptr_t)map);
	if (old != NULL)
		NET_EPOCH_CALL(pppoe_dispatch_map_free, &old->dm_ctx);
}

static void
pppoe_dispatch_task_fn(void *ctx __unused, int pending __unused)
{

	sx_xlock(&pppoe_dispatch_lock);
	/* Cleared first: a count change after the build re-kicks us. */
	atomic_store_rel_int(&pppoe_dispatch_pending, 0);
	pppoe_dispatch_rebuild();
	sx_xunlock(&pppoe_dispatch_lock);
}

void
pppoe_dispatch_init(void)
{

	TASK_INIT(&pppoe_dispatch_task, 0, pppoe_dispatch_task_fn, NULL);
	sx_xlock(&pppoe_dispatch_lock);
	pppoe_dispatch_rebuild();
	sx_xunlock(&pppoe_dispatch_lock);
}

/*
 * After pppoe_netisr_unregister(): no m2cpuid call can be running or start,
 * so the current map can go straight to free(9).  Replaced maps still in
 * NET_EPOCH_CALL() flight are drained by pppoe_vnet_uninit()'s
 * NET_EPOCH_DRAIN_CALLBACKS(), which runs after MOD_UNLOAD.
 */
void
pppoe_dispatch_fini(void)
{

	taskqueue_drain(pppoe_taskq, &pppoe_dispatch_task);
	sx_xlock(&pppoe_dispatch_lock);
	free(pppoe_dispatch_map, M_PPPOE);
	pppoe_dispatch_map = NULL;
	pppoe_dispatch_dead = true;
	sx_xunlock(&pppoe_dispatch_lock);
}

static int
pppoe_sysctl_dispatch_cpus(SYSCTL_HANDLER_ARGS)
{
	char buf[PPPOE_DISPATCH_SPECLEN];
	cpuset_t set;
	bool autosel;
	int error;

	sx_slock(&pppoe_dispatch_lock);
	strlcpy(buf, pppoe_dispatch_spec, sizeof(buf));
	sx_sunlock(&pppoe_dispatch_lock);
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (pppoe_dispatch_parse(buf, &set, &autosel) != 0)
		return (EINVAL);
	sx_xlock(&pppoe_dispatch_lock);
	strlcpy(pppoe_dispatch_spec, buf, sizeof(pppoe_dispatch_spec));
	pppoe_dispatch_rebuild();
	sx_xunlock(&pppoe_dispatch_lock);
	return (0);
}

/*
 * Not CTLFLAG_TUN: the TUNABLE_STR above seeds the string, and a TUN proc
 * would be called at oid registration, before SX_SYSINIT has run.
 */
SYSCTL_PROC(_net_pppoe, OID_AUTO, dispatch_cpus,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    pppoe_sysctl_dispatch_cpus, "A",
    "CPUs decapsulated flows are spread over: \"auto\" (all netisr CPUs "
    "but CPU 0, the usual RX-queue CPU), \"all\", or a list like \"1-3\"");

/* What the spec resolved to: the CPU of every map entry, in map order. */
static int
pppoe_sysctl_dispatch_map(SYSCTL_HANDLER_ARGS)
{
	struct pppoe_dispatch_map *map;
	struct sbuf sb;
	u_int i;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 64, req);
	sx_slock(&pppoe_dispatch_lock);
	map = pppoe_dispatch_map;
	if (map != NULL) {
		for (i = 0; i < map->dm_n; i++)
			sbuf_printf(&sb, "%scpu%u", i == 0 ? "" : " ",
			    netisr_get_cpuid(map->dm_idx[i]));
		if (map->dm_nws != netisr_get_cpucount())
			sbuf_printf(&sb, " (stale: rebuilt on the next frame)");
	}
	sx_sunlock(&pppoe_dispatch_lock);
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_net_pppoe, OID_AUTO, dispatch_map,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    pppoe_sysctl_dispatch_map, "A",
    "netisr CPUs decapsulated flows are currently spread over");

/*
 * netisr's nh_m2cpuid callback.  Called from netisr_select_cpuid() before the
 * frame is enqueued, so m_pkthdr.rcvif is still the live pointer this file set
 * in pppoe_sess_input() (netisr.c:997 only serialises it at enqueue time).
 * Never returns NULL, so it never has an mbuf to dispose of.
 *
 * *cpuid is a RAW index, not a workstream CPU id.  netisr_select_cpuid()
 * normalises whatever we hand back with netisr_get_cpuid() itself
 * (netisr.c:835-837), so calling netisr_get_cpuid() here too would map twice
 * -- nws_array[nws_array[idx] % n] -- which is the identity only while
 * nws_array is [0,1,2,..n-1].  Let the gaps in it (a disabled core, an
 * asymmetric topology) make nws_array [0,1,3] and idx 2 lands on workstream 0
 * instead of 3, starving one workstream outright.  rss_m2cpuid()
 * (net/rss_config.c) is the in-tree precedent: it returns rss_hash2cpuid()'s
 * value raw.  netisr.c:836 is also what satisfies netisr_dispatch_src()'s
 * KASSERT(!CPU_ABSENT(cpuid)), for any value at all -- we owe it nothing.
 * The dispatch map's entries are raw indices for the same reason.
 *
 * The fallback keeps all the *unhashable* frames of a session mutually
 * ordered, which scattering them to curcpu would not (the reordering risk
 * this avoids).  It does not order them against that session's hashed
 * frames -- sc_session and flowid pick
 * different workstreams in general -- but the unhashable frames are the
 * control protocols (LCP, IPCP, ...) and malformed IP, which carry no flow
 * ordering to keep.  sc_session is read without sc_mtx: it only picks a CPU,
 * and a stale read costs at most one frame's placement.
 */
static struct mbuf *
pppoe_m2cpuid(struct mbuf *m, uintptr_t source __unused, u_int *cpuid)
{
	struct pppoe_dispatch_map *map;
	struct pppoe_softc *sc;
	u_int n, key;

	NET_EPOCH_ASSERT();
	n = netisr_get_cpucount();
	if (n <= 1) {
		/* Unreachable via netisr.c:811-814, which shortcuts first. */
		*cpuid = curcpu;
		return (m);
	}
	if (M_HASHTYPE_GET(m) != M_HASHTYPE_NONE) {
		key = m->m_pkthdr.flowid;
	} else {
		sc = (m->m_pkthdr.rcvif != NULL) ?
		    if_getsoftc(m->m_pkthdr.rcvif) : NULL;
		key = (sc != NULL ? sc->sc_session : 0);
	}
	map = (struct pppoe_dispatch_map *)atomic_load_acq_ptr(
	    (volatile uintptr_t *)&pppoe_dispatch_map);
	if (__predict_true(map != NULL && map->dm_nws == n)) {
		*cpuid = map->dm_idx[key % map->dm_n];
		return (m);
	}
	/* Built for another workstream count (see above): all, until rebuilt. */
	if (atomic_cmpset_int(&pppoe_dispatch_pending, 0, 1))
		taskqueue_enqueue(pppoe_taskq, &pppoe_dispatch_task);
	*cpuid = key % n;
	return (m);
}

/*
 * Per-CPU handler invocations, the evidence that the spreading is real.
 * A counter_u64_t per CPU, not counter_u64_t[MAXCPU]: MAXCPU is 1024 on amd64
 * (sys/amd64/include/param.h:67) and every loadable module's virtualised
 * globals share one VNET_MODMIN == 8 pages (sys/net/vnet.c:172), so the array
 * itself is malloc'd and only a pointer lives in vnet data.
 */
VNET_DEFINE_STATIC(counter_u64_t *, pppoe_cpu_hits);
#define	V_pppoe_cpu_hits	VNET(pppoe_cpu_hits)

void
pppoe_cpu_hits_init(void)
{

	V_pppoe_cpu_hits = malloc(sizeof(counter_u64_t) * (mp_maxid + 1),
	    M_PPPOE, M_WAITOK);
	COUNTER_ARRAY_ALLOC(V_pppoe_cpu_hits, mp_maxid + 1, M_WAITOK);
}

/*
 * Callers must have quiesced pppoe_netisr_input() first -- see
 * pppoe_netisr_unregister().
 */
void
pppoe_cpu_hits_fini(void)
{

	COUNTER_ARRAY_FREE(V_pppoe_cpu_hits, mp_maxid + 1);
	free(V_pppoe_cpu_hits, M_PPPOE);
	V_pppoe_cpu_hits = NULL;
}

static int
pppoe_sysctl_cpu_hits(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	const char *sep = "";
	int error, i;

	sbuf_new_for_sysctl(&sb, NULL, 128, req);
	for (i = 0; i <= mp_maxid; i++) {
		if (CPU_ABSENT(i))
			continue;
		sbuf_printf(&sb, "%scpu%d=%ju", sep, i,
		    (uintmax_t)counter_u64_fetch(V_pppoe_cpu_hits[i]));
		sep = " ";
	}
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_net_pppoe, OID_AUTO, cpu_hits,
    CTLTYPE_STRING | CTLFLAG_VNET | CTLFLAG_RD | CTLFLAG_MPSAFE, 0, 0,
    pppoe_sysctl_cpu_hits, "A",
    "per-CPU netisr handler invocations for decapsulated PPPoE frames");

/*
 * The netisr handler.  Task 12's carried ruling 1 asks whether this needs
 * NET_EPOCH_ENTER or CURVNET_SET of its own.  It needs neither, on either arm,
 * and both answers are load-bearing -- pppoe_data_input()'s reflect arm calls
 * pppoe_transmit() -> ether_output_frame(), which reads V_link_pfil_head
 * (if_ethersubr.c:479) and V_vlan_mtag_pcp (:1416), and V_pppoe_stats is
 * per-vnet too:
 *
 *   Net epoch.  In place: netisr_dispatch_src() asserts the caller holds it
 *   (netisr.c:1119), and pppoe_pfil_in() runs inside ether_demux()'s section.
 *   Queued: netisr's workstreams are swi handlers registered with
 *   INTR_TYPE_NET (netisr.c:1276), which sets IH_NET (kern_intr.c:627-628)
 *   into ie_hflags (:237), and ithread_loop() wraps every dispatch of an
 *   IH_NET event in NET_EPOCH_ENTER/EXIT (:1282-1298).
 *
 *   curvnet.  In place: inherited from pppoe_pfil_in(), whose vnet is the one
 *   the softc lives in.  Queued: netisr_process_workstream_proto() does
 *   CURVNET_SET(m->m_pkthdr.rcvif->if_vnet) around the handler
 *   (netisr.c:926-928), and pppoe_sess_input() set rcvif to sc->sc_ifp, so
 *   that is the same vnet.  (That arm also drops the frame outright if the
 *   ifnet has gone away in the meantime, netisr.c:922-924, which is how a
 *   queued frame for a destroyed clone is disposed of.)
 *
 * NETISR_LOCKING is compiled out (netisr.c:127), so netisr_unregister() does
 * not exclude a handler already running: the epoch is also what makes the
 * teardown in pppoe_netisr_unregister() safe.
 */
static void
pppoe_netisr_input(struct mbuf *m)
{

	NET_EPOCH_ASSERT();
	counter_u64_add(V_pppoe_cpu_hits[curcpu], 1);
	pppoe_data_input(m);
}

struct netisr_handler pppoe_nh = {
	.nh_name = "pppoe",
	.nh_handler = pppoe_netisr_input,
	.nh_m2cpuid = pppoe_m2cpuid,
	.nh_proto = NETISR_PPPOE_DATA,
	/* .nh_qlimit: net.pppoe.netisr_qlimit, set by pppoe_netisr_register() */
	.nh_policy = NETISR_POLICY_CPU,
	.nh_dispatch = NETISR_DISPATCH_HYBRID,
};

/*
 * Whether pppoe_nh is registered globally.  pppoe_vnet_uninit() needs it
 * because MOD_UNLOAD runs before the VNET_SYSUNINITs (kern_linker.c:720 vs
 * :748), so by then netisr_unregister() has already NULLed np_handler and
 * netisr_unregister_vnet() would trip its own
 * KASSERT(netisr_proto[proto].np_handler != NULL) at netisr.c:766-767.  That
 * assertion is compiled out here but plan 3 builds a WITNESS/INVARIANTS
 * kernel, where it is a panic.  Written only from pppoe_modevent(), which
 * kldload(8)/kldunload(8) serialise on kld_sx.
 */
bool pppoe_netisr_registered;

/*
 * Per-workstream queue limit.  The old fixed 1000 (net.inet.ip's default)
 * is ~12 ms of a 1 Gbit/s session and under 1 ms at 10G on ONE workstream:
 * a burst from the single RX CPU overflowed it before the worker woke
 * (netstat -Q QDrops; net.pppoe.netisr_enqueue_drop counts them).
 * netisr_register() caps it at net.isr.maxqlimit (default 10240) with a
 * console note; a run-time write goes through netisr_setqlimit(), which
 * refuses (EINVAL) anything above that cap.
 */
static u_int pppoe_netisr_qlimit = 4096;

static int
pppoe_sysctl_netisr_qlimit(SYSCTL_HANDLER_ARGS)
{
	u_int qlimit;
	int error;

	qlimit = pppoe_netisr_qlimit;
	error = sysctl_handle_int(oidp, &qlimit, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (qlimit == 0)
		return (EINVAL);
	/* Also reached at oid registration with a loader tunable: not yet. */
	if (pppoe_netisr_registered) {
		error = netisr_setqlimit(&pppoe_nh, qlimit);
		if (error != 0)
			return (error);
	}
	pppoe_netisr_qlimit = qlimit;
	return (0);
}

SYSCTL_PROC(_net_pppoe, OID_AUTO, netisr_qlimit,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, NULL, 0,
    pppoe_sysctl_netisr_qlimit, "IU",
    "per-CPU queue limit of the pppoe netisr protocol (<= net.isr.maxqlimit)");

/*
 * netisr_register() must run in vnet0 (netisr.c:460-462); pppoe_modevent() is
 * the only place this file has that is not per-vnet, and kern_kldload() sets
 * curvnet for it (kern_linker.c:1180).  Additional vnets enable the protocol
 * for themselves with netisr_register_vnet() from pppoe_vnet_init().
 */
void
pppoe_netisr_register(void)
{

	pppoe_nh.nh_qlimit = pppoe_netisr_qlimit;
	netisr_register(&pppoe_nh);
	pppoe_netisr_registered = true;
}

/*
 * Ruling 2, carried from the Task 1 spike: quiesce before freeing.  The spike
 * freed its per-CPU counters straight after netisr_unregister() while handlers
 * were still running on remote CPUs.  netisr_unregister() clears the handler
 * and frees every queued mbuf, but it does not wait for an invocation already
 * in flight (NETISR_LOCKING is off, netisr.c:127) -- NET_EPOCH_WAIT() does,
 * because every arm of pppoe_netisr_input() runs inside the net epoch.  It is
 * what lets pppoe_vnet_uninit(), which linker_file_unload() runs strictly
 * later (kern_linker.c:720 vs :748), free V_pppoe_cpu_hits and V_pppoe_stats.
 *
 * Task 13 closed the race this comment used to document.  The old
 * ordering left the pfil hook attached -- pppoe_pfil_detach() lived only in
 * the per-vnet SYSUNINIT that runs after this call -- so frames kept
 * arriving throughout.  netisr_unregister() zeroes V_netisr_enable in every
 * vnet (netisr.c:659) and only then NULLs np_handler, np_m2cpuid and
 * np_policy (:665-670), with no barrier and no quiesce between the two --
 * NETISR_WLOCK() excludes nothing on the dispatch side with NETISR_LOCKING
 * off.  A dispatcher that had already passed the enable check at
 * netisr.c:1130 could therefore reach np_handler(m) at :1152 or :1203 after
 * it was NULL: a live NULL dereference on every configuration, VIMAGE or
 * not.  The only ordering that closes it is the one MOD_UNLOAD now follows:
 * detach every vnet's pfil hook first (pppoe_vnet_pfil_sweep(), which is why
 * the pppoe_pfil_detach() the per-vnet SYSUNINIT still calls is a no-op on
 * the kldunload path), NET_EPOCH_WAIT() to quiesce in-flight
 * pppoe_pfil_in()/netisr handlers from every vnet, and only then this
 * function.  The pfil hook was the only thing that could dispatch
 * NETISR_PPPOE_DATA, so once the sweep has run nothing can still be heading
 * for np_handler.  The NET_EPOCH_WAIT() below stays as the second
 * module-level quiesce: it covers a netisr handler already running on a
 * frame dequeued before the drain inside netisr_unregister(), the same
 * disposition pppoe_vnet_uninit() keeps per vnet -- see its two waits.
 *
 * One residual window remains, and it is base-kernel, not module-causable
 * (M001/S03 review finding I1): NET_EPOCH_WAIT() waits only on epoch
 * sections that are active, and queued work is not one of them.  Frames
 * enqueued before the sweep can still sit in a workstream's nws_work queue
 * with NWS_SCHEDULED pending, and a swi_net that starts processing between
 * the wait above and netisr_unregister() reaching np_handler = NULL at
 * netisr.c:665-670 reads a NULL handler -- the exposure the base kernel
 * itself documents as inherent with NETISR_LOCKING off (netisr.c:127).  No
 * public netisr API lets a module drain or park another protocol's queues,
 * so the module side can only document the window; the unload probe's
 * netstat -Q queue-depth assertion before every kldunload (finding I1's
 * belt-and-braces) is the witness that keeps it loud.
 */
void
pppoe_netisr_unregister(void)
{

	netisr_unregister(&pppoe_nh);
	NET_EPOCH_WAIT();
	pppoe_netisr_registered = false;
}
