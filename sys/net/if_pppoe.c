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
 * FreeBSD port notice
 * -------------------
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sys/net/if_pppoe.c.
 *
 * Deliberately NOT ported (they reintroduce serialisation this port exists to
 * remove; design spec section 9):
 *   - the global ppoeinq/ppoediscinq ifqueues and pppoe_softintr
 *     (NetBSD if_pppoe.c:206-210, :592-631, :2128-2167);
 *   - the global pppoe_softc_list_lock plus per-softc lock taken inside
 *     pppoe_find_softc_by_session() (NetBSD if_pppoe.c:516-537);
 *   - PPPOE_LOCK held across pppoe_transmit() (NetBSD if_pppoe.c:2038-2060).
 * Input arrives instead on a PFIL_TYPE_ETHERNET hook and is spread with a
 * private netisr protocol; session lookup is epoch-protected.
 */

/*
 * kmod.mk force-includes opt_global.h (:126), so VIMAGE and SMP arrive on
 * their own; INET6 and RSS do not, and without these three lines an
 * #ifdef INET6 / #ifdef RSS arm would silently compile out of a kernel that
 * has the option.  The Makefile's SRCS is what makes kmod.mk:389-398 symlink
 * KERNBUILDDIR's copies into .OBJDIR.
 */
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_rss.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/callout.h>
#include <sys/ck.h>
#include <sys/counter.h>
#include <sys/devctl.h>
#include <sys/endian.h>
#include <sys/epoch.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/priv.h>
#include <sys/refcount.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/taskqueue.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>	/* struct ifnet/if_snd details (S03/T2 ALTQ probe) */
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_clone.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/pfil.h>
#include <net/route.h>
#include <net/rss_config.h>
#include <net/vnet.h>
#include <net/if_pppoe.h>
#include <net/if_pppoe_var.h>
#include <net/if_sppp.h>
#include <net/ppp_defs.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#endif
#ifdef RSS
#include <netinet/in_rss.h>
#ifdef INET6
#include <netinet6/in6_rss.h>
#endif
#endif

MALLOC_DEFINE(M_PPPOE, "pppoe", "PPPoE interface state");

SYSCTL_NODE(_net, OID_AUTO, pppoe, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "in-kernel PPPoE client");

VNET_DEFINE_STATIC(struct if_clone *, pppoe_cloner);
#define	V_pppoe_cloner		VNET(pppoe_cloner)

static int	pppoe_ioctl(if_t ifp, u_long cmd, caddr_t data);
static void	pppoe_softc_free(struct epoch_context *ctx);
static void	pppoe_parent_altq_check(struct pppoe_softc *sc);

/*
 * The parent set: every Ethernet/vlan ifnet any pppoe(4) clone in this vnet is
 * bound to.  It is the RX hook's first fast reject (spec section 6.1), so the
 * read side runs in the receive thread under NET_EPOCH with no lock at all
 * (spec section 9's do-not-port list).  Writers are ioctl/clone-destroy only
 * and serialise on a global sx.
 */
#define	PPPOE_MAX_PARENTS	8

struct pppoe_parent {
	if_t		 pp_ifp;
	u_int		 pp_refs;
};

VNET_DEFINE_STATIC(struct pppoe_parent, pppoe_parents[PPPOE_MAX_PARENTS]);
#define	V_pppoe_parents		VNET(pppoe_parents)

static struct sx pppoe_parents_lock;
SX_SYSINIT(pppoe_parents_lock, &pppoe_parents_lock, "pppoe parents");

/*
 * Softc lifetime anchor.  Every sleepable path that uses a softc obtained
 * from ifp->if_softc -- pppoe_ioctl() and the departure/arrival handlers --
 * calls pppoe_softc_hold() first, which takes one sc_refs hold under
 * pppoe_sc_hold_lock.  The per-packet paths -- pppoe_output(),
 * pppoe_transmit() and pppoe_data_input() -- never sleep, so they take no
 * hold (T1: the global lock and two sc_refs atomics per transmitted packet
 * were a cross-CPU serialisation point): they load if_softc once inside
 * the net epoch and use it only until they leave it (docs/PERF-DESIGN.md).
 * pppoe_clone_destroy() clears ifp->if_softc under
 * the same lock, NET_EPOCH_WAIT()s out the epoch readers, then waits for
 * sc_refs to fall to the interface's own ref (init 1 in
 * pppoe_clone_create()) -- and only then tears the PPP state machine down
 * and drops that last ref.  So sppp_detach() never runs under a holder or
 * an epoch reader, and the free is scheduled by the destroy itself via
 * NET_EPOCH_CALL(), which is what keeps the discovery/netisr readers that
 * looked the softc up without a hold (pppoe_find_by_hunique(),
 * pppoe_m2cpuid()) covered (M001/S03 review finding I2, decision D012).
 */
static struct mtx pppoe_sc_hold_lock;
MTX_SYSINIT(pppoe_sc_hold_lock, &pppoe_sc_hold_lock, "pppoe sc hold", MTX_DEF);

static struct pppoe_softc *
pppoe_softc_hold(if_t ifp)
{
	struct pppoe_softc *sc;

	mtx_lock(&pppoe_sc_hold_lock);
	sc = atomic_load_ptr(&ifp->if_softc);
	if (sc != NULL)
		refcount_acquire(&sc->sc_refs);
	mtx_unlock(&pppoe_sc_hold_lock);
	return (sc);
}

static void
pppoe_softc_rele(struct pppoe_softc *sc)
{

	if (refcount_release(&sc->sc_refs))
		NET_EPOCH_CALL(pppoe_softc_free, &sc->sc_epoch_ctx);
}

/* Read side: epoch only, no locks.  Pointer-sized loads, racy-but-safe. */
static bool
pppoe_parent_is_ours(if_t ifp)
{
	int i;

	NET_EPOCH_ASSERT();
	for (i = 0; i < PPPOE_MAX_PARENTS; i++)
		if (atomic_load_ptr(&V_pppoe_parents[i].pp_ifp) == ifp)
			return (true);
	return (false);
}

static int
pppoe_parent_add(if_t ifp)
{
	int i, slot = -1;

	sx_xlock(&pppoe_parents_lock);
	for (i = 0; i < PPPOE_MAX_PARENTS; i++) {
		if (V_pppoe_parents[i].pp_ifp == ifp) {
			V_pppoe_parents[i].pp_refs++;
			sx_xunlock(&pppoe_parents_lock);
			return (0);
		}
		if (V_pppoe_parents[i].pp_ifp == NULL && slot < 0)
			slot = i;
	}
	if (slot < 0) {
		sx_xunlock(&pppoe_parents_lock);
		return (ENOSPC);
	}
	V_pppoe_parents[slot].pp_refs = 1;
	atomic_store_ptr(&V_pppoe_parents[slot].pp_ifp, ifp);
	sx_xunlock(&pppoe_parents_lock);
	return (0);
}

static void
pppoe_parent_del(if_t ifp)
{
	int i;

	if (ifp == NULL)
		return;
	sx_xlock(&pppoe_parents_lock);
	for (i = 0; i < PPPOE_MAX_PARENTS; i++) {
		if (V_pppoe_parents[i].pp_ifp != ifp)
			continue;
		if (--V_pppoe_parents[i].pp_refs == 0)
			atomic_store_ptr(&V_pppoe_parents[i].pp_ifp,
			    (if_t)NULL);
		break;
	}
	sx_xunlock(&pppoe_parents_lock);
}

/*
 * Per-vnet counters.  counter(9) is per-CPU and lock-free, so the RX hook can
 * account without touching a shared cache line (spec section 9's do-not-port
 * list: no lock on the RX path).
 */
VNET_DEFINE(struct pppoe_stats, pppoe_stats);

static void
pppoe_stats_init(void)
{

	V_pppoe_stats.hook_seen = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.disc_in = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.disc_malformed = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.disc_err_tag = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.padt_rx = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.padt_tx = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.sess_in = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.sess_nosession = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.padt_unknown = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.sess_short = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.data_in = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.tx_frames = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.tx_errors = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.tx_parent_down = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.mss_clamped = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.passed_foreign = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.nomem = counter_u64_alloc(M_WAITOK);
	V_pppoe_stats.netisr_enqueue_drop = counter_u64_alloc(M_WAITOK);
}

static void
pppoe_stats_fini(void)
{

	counter_u64_free(V_pppoe_stats.hook_seen);
	counter_u64_free(V_pppoe_stats.disc_in);
	counter_u64_free(V_pppoe_stats.disc_malformed);
	counter_u64_free(V_pppoe_stats.disc_err_tag);
	counter_u64_free(V_pppoe_stats.padt_rx);
	counter_u64_free(V_pppoe_stats.padt_tx);
	counter_u64_free(V_pppoe_stats.sess_in);
	counter_u64_free(V_pppoe_stats.sess_nosession);
	counter_u64_free(V_pppoe_stats.padt_unknown);
	counter_u64_free(V_pppoe_stats.sess_short);
	counter_u64_free(V_pppoe_stats.data_in);
	counter_u64_free(V_pppoe_stats.tx_frames);
	counter_u64_free(V_pppoe_stats.tx_errors);
	counter_u64_free(V_pppoe_stats.tx_parent_down);
	counter_u64_free(V_pppoe_stats.mss_clamped);
	counter_u64_free(V_pppoe_stats.passed_foreign);
	counter_u64_free(V_pppoe_stats.nomem);
	counter_u64_free(V_pppoe_stats.netisr_enqueue_drop);
}

SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, hook_seen, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.hook_seen), "Ethernet frames inspected by the hook");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, disc_in, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.disc_in),
    "PPPoE discovery frames consumed (naming a pppoe(4) softc)");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, disc_malformed,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.disc_malformed),
    "discovery frames dropped as malformed or unparseable");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, disc_err_tag,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.disc_err_tag),
    "discovery frames carrying Service-Name-Error, AC-System-Error or Generic-Error");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, padt_rx, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.padt_rx), "PADT frames received");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, padt_tx, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.padt_tx), "PADT frames sent");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, sess_in, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.sess_in), "PPPoE session frames consumed");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, sess_nosession,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.sess_nosession),
    "PPPoE session frames with no matching session");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, padt_unknown,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.padt_unknown),
    "PADTs sent for stale PPPoE sessions of ours (see term_unknown)");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, sess_short, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.sess_short),
    "malformed or truncated PPPoE session frames");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, data_in, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.data_in), "decapsulated PPP frames delivered");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, tx_frames, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.tx_frames),
    "discovery and session frames the parent accepted for transmit");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, tx_errors, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.tx_errors),
    "frames the driver could not hand to the parent, or the parent refused");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, tx_parent_down,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.tx_parent_down),
    "frames dropped because the parent was not up and running "
    "(also counted in tx_errors)");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, mss_clamped, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.mss_clamped),
    "TCP SYNs (either direction) whose MSS option was lowered");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, passed_foreign,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.passed_foreign),
    "PPPoE frames on a bound parent that are not ours, passed up the stack "
    "untouched (e.g. to ng_ether for mpd5)");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, nomem, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_stats.nomem),
    "mbuf or malloc allocation failures (frame dropped or not sent)");
SYSCTL_COUNTER_U64(_net_pppoe, OID_AUTO, netisr_enqueue_drop,
    CTLFLAG_VNET | CTLFLAG_RD, &VNET_NAME(pppoe_stats.netisr_enqueue_drop),
    "session frames netisr_dispatch() refused (queue full or protocol off)");

/*
 * kern.features.if_pppoe_pfil_pass_foreign: the RX hook consumes only
 * frames it can attribute to one of its softcs and PFIL_PASSes every other
 * PPPoE frame, so mpd5 (ng_ether's orphans hook, reached after the link
 * pfil chain) can share the parent.  The OPNsense plugin gates eligibility
 * on it (docs/plugin/risk-register.md C9).
 */
FEATURE(if_pppoe_pfil_pass_foreign,
    "pppoe(4) passes PPPoE frames that are not its own up the stack");

/*
 * kern.features.if_pppoe_single_bytecount: pppoeN's packet and byte
 * counters are charged once, here (pppoe_data_input(),
 * pppoe_encap_output()); sppp's own adds are compiled out
 * (SPPP_LOWER_COUNTS_BYTES).
 */
FEATURE(if_pppoe_single_bytecount,
    "pppoe(4) interface byte counters count each byte once");

/*
 * Every softc in this vnet.  pppoe_find_by_hunique() walks it from the RX
 * hook, so the read side must run under NET_EPOCH with no lock at all (spec
 * section 9's do-not-port list; this replaces NetBSD's
 * pppoe_find_softc_by_hunique(), if_pppoe.c:539-570, which took a global
 * rwlock plus the per-softc lock on every discovery frame).  A CK_LIST gives
 * that: CK_LIST_REMOVE() leaves the removed element's forward pointer valid
 * for a walker already inside the list, and pppoe_clone_destroy() defers the
 * softc free with NET_EPOCH_CALL().  Writers are clone create/destroy only and
 * borrow pppoe_parents_lock.
 */
CK_LIST_HEAD(pppoe_sc_head, pppoe_softc);
VNET_DEFINE_STATIC(struct pppoe_sc_head, pppoe_softcs) =
    CK_LIST_HEAD_INITIALIZER(pppoe_softcs);
#define	V_pppoe_softcs		VNET(pppoe_softcs)

/*
 * Host-Uniq is this softc's 64-bit sc_hunique in network byte order, so a PADO
 * or PADS can be matched back to the softc that sent the PADI/PADR without a
 * lock.  sc_all links every softc; sc_hash links only sessions (Task 10).
 */
struct pppoe_softc *
pppoe_find_by_hunique(const uint8_t *token, size_t len)
{
	struct pppoe_softc *sc;
	uint64_t hu;

	NET_EPOCH_ASSERT();
	if (len != sizeof(hu))
		return (NULL);
	memcpy(&hu, token, sizeof(hu));		/* token may be unaligned */
	hu = be64toh(hu);
	CK_LIST_FOREACH(sc, &V_pppoe_softcs, sc_all)
		if (sc->sc_hunique == hu)
			return (sc);
	return (NULL);
}

/*
 * Draw this softc a fresh random Host-Uniq, so a PADO/PADS cannot be forged
 * by guessing a counter and a late answer to an earlier dial matches nothing.
 * Redraw on a collision with another softc: the token is the lookup key.
 */
static void
pppoe_hunique_new(struct pppoe_softc *sc)
{
	struct epoch_tracker et;
	struct pppoe_softc *other;
	uint64_t hu, tok;

	do {
		arc4random_buf(&hu, sizeof(hu));
		tok = htobe64(hu);
		NET_EPOCH_ENTER(et);
		other = pppoe_find_by_hunique((const uint8_t *)&tok,
		    sizeof(tok));
		NET_EPOCH_EXIT(et);
	} while (other != NULL && other != sc);
	sc->sc_hunique = hu;
}

/*
 * Only PADT needs this: every other discovery code we act on answers a
 * PADI/PADR of ours and so echoes our Host-Uniq, but RFC 2516 does not require
 * a PADT to carry one.  Key on what spec section 6.1 item 3 says identifies a
 * session -- parent, session id, peer MAC.  Those fields are stable only under
 * sc_mtx, so this is a hint the PADT arm re-validates under the lock.  Task
 * 10's session hash table replaces the linear walk.
 */
struct pppoe_softc *
pppoe_find_by_session(if_t ifp, uint16_t session, const struct ether_addr *peer)
{
	struct pppoe_softc *sc;

	NET_EPOCH_ASSERT();
	if (session == 0)
		return (NULL);
	CK_LIST_FOREACH(sc, &V_pppoe_softcs, sc_all)
		if (sc->sc_parent == ifp &&
		    sc->sc_state == PPPOE_STATE_SESSION &&
		    sc->sc_session == session &&
		    memcmp(&sc->sc_dest, peer, sizeof(sc->sc_dest)) == 0)
			return (sc);
	return (NULL);
}

/*
 * net.pppoe.term_unknown's attribution test: is (parent, session, peer) the
 * session one of our softcs closed within the last `window` seconds?  That
 * is the only unknown session the RX hook may claim.  Any other may belong
 * to another PPPoE client on the parent (mpd5 through ng_ether) and must be
 * passed, never PADTed -- including our old id once the window is past,
 * because a same-NIC mpd5 shares our MAC and so the RFC 2516 key, and the
 * AC may have reissued the id to it.
 *
 * Never while the softc is negotiating or holding a session on that id:
 * the table insert is deferred to pppoe_session_task(), so an AC that
 * reissues our last id sends its first frames before the lookup can find
 * them, and PADTing those would kill our own new session (and, if the AC
 * reissues the id on every redial, loop).  The PADS arm also forgets the
 * record when it accepts the same id; PADR_SENT covers a PADS still ahead.
 *
 * The unlocked sc_last_session compare is a cheap filter; the full key is
 * re-checked under sc_mtx, where pppoe_clear_softc() and the PADS arm
 * write it.  Called only with term_unknown set, so the default fast path
 * never walks.
 */
static bool
pppoe_stale_session_is_ours(if_t ifp, uint16_t session, const uint8_t *peer,
    u_int window)
{
	struct pppoe_softc *sc;
	bool ours;

	NET_EPOCH_ASSERT();
	if (session == 0)
		return (false);
	CK_LIST_FOREACH(sc, &V_pppoe_softcs, sc_all) {
		if (sc->sc_last_session != session)
			continue;
		PPPOE_SC_LOCK(sc);
		ours = !sc->sc_detaching && sc->sc_parent == ifp &&
		    sc->sc_last_session == session &&
		    sc->sc_state != PPPOE_STATE_PADR_SENT &&
		    !(sc->sc_state == PPPOE_STATE_SESSION &&
		    sc->sc_session == session) &&
		    time_uptime - sc->sc_last_closed <= (time_t)window &&
		    memcmp(&sc->sc_last_dest, peer,
		    sizeof(sc->sc_last_dest)) == 0;
		PPPOE_SC_UNLOCK(sc);
		if (ours)
			return (true);
	}
	return (false);
}


/*
 * The session table: the RX hook's demux from (parent, session id, peer MAC)
 * to a softc (spec section 6.3).  Keyed on the session id, with the full
 * three-part key compared on the bucket walk.
 *
 * The index mixes rather than masking.  The brief's bare low-bit mask does not
 * spread a real AC at all: accel-ppp issues session ids in steps of 64 --
 * 14016, 15104, 24064, 24128 measured here, 48768, 48896, 49024, 49216 in Task
 * 8's dmesg -- so their low six bits are always zero, every one of them would
 * land in bucket 0, and the table would be exactly the linear walk it replaced.
 *
 * Fold instead, by the width of the index itself.  That is what ng_pppoe(4)
 * does (sys/netgraph/ng_pppoe.c:280-281: a 0x100-entry table indexed
 * ((x) ^ ((x) >> 8)) & mask), and one fold suffices there because 8 + 8 covers
 * a 16-bit session id.  A 64-entry table is six bits wide, so it takes two
 * folds -- 6 and 12 -- to bring all sixteen bits down onto [5:0].  Measured
 * over the whole id space and over 64-id runs at strides 1, 64 and 4096, this
 * spreads every one of them; dropping the >> 12 term still handles the AC in
 * front of us but collapses stride 4096 back onto a single bucket.
 *
 * Readers are epoch-only, exactly like V_pppoe_softcs above: CK_LIST_REMOVE()
 * leaves the removed element's forward pointer valid for a walker already
 * inside the bucket, and the softc itself is freed only via NET_EPOCH_CALL()
 * in pppoe_clone_destroy().  Writers borrow pppoe_parents_lock, the module's
 * single global sx (spec section 9).
 */
#define	PPPOE_SESSHASH_SIZE	64
/* `id` is evaluated three times; every caller passes a plain lvalue. */
#define	PPPOE_SESSHASH(id)						\
	(((id) ^ ((id) >> 6) ^ ((id) >> 12)) & (PPPOE_SESSHASH_SIZE - 1))

CK_LIST_HEAD(pppoe_sess_head, pppoe_softc);
VNET_DEFINE_STATIC(struct pppoe_sess_head,
    pppoe_sessions[PPPOE_SESSHASH_SIZE]);
#define	V_pppoe_sessions	VNET(pppoe_sessions)

static struct pppoe_softc *
pppoe_session_lookup(if_t parent, uint16_t session, const uint8_t *peer)
{
	struct pppoe_softc *sc;

	NET_EPOCH_ASSERT();
	CK_LIST_FOREACH(sc, &V_pppoe_sessions[PPPOE_SESSHASH(session)],
	    sc_hash) {
		if (sc->sc_session == session && sc->sc_parent == parent &&
		    memcmp(&sc->sc_dest, peer, sizeof(sc->sc_dest)) == 0)
			return (sc);
	}
	return (NULL);
}

/*
 * Copy an Ethernet ifnet's link address into dst (ETHER_ADDR_LEN bytes);
 * false if it has none.  Every frame this driver builds takes its source MAC
 * from a parent through here rather than if_getlladdr(), which dereferences
 * if_addr unconditionally: a departing parent loses its link address once
 * the ifnet_departure_event handlers return (if_detach_internal(), assumed
 * for 14.3, not read against its tree), and a transmitter that lifted the
 * parent before pppoe_parent_departed() cleared it can still get here.
 * if_addr is loaded once and used only inside the caller's net epoch, which
 * the link ifaddr's free is deferred past (ifa_free()).
 */
bool
pppoe_lladdr_copy(if_t ifp, void *dst)
{
	struct ifaddr *ifa;

	NET_EPOCH_ASSERT();
	ifa = atomic_load_ptr(&ifp->if_addr);
	if (ifa == NULL || ifp->if_addrlen != ETHER_ADDR_LEN)
		return (false);
	memcpy(dst, LLADDR((struct sockaddr_dl *)ifa->ifa_addr),
	    ETHER_ADDR_LEN);
	return (true);
}

static void
pppoe_tx_snap_free(struct epoch_context *ctx)
{

	free(__containerof(ctx, struct pppoe_tx_snap, ts_ctx), M_PPPOE);
}

/*
 * Swap the session's transmit snapshot (struct pppoe_tx_snap) for `ts`
 * (NULL clears it).  The release store orders the snapshot's contents
 * before its pointer, for pppoe_encap_output()'s acquire load; the old one
 * is freed only after every net-epoch section that could have loaded it.
 */
static void
pppoe_tx_snap_set(struct pppoe_softc *sc, struct pppoe_tx_snap *ts)
{
	struct pppoe_tx_snap *old;

	PPPOE_SC_ASSERT(sc);
	old = sc->sc_txsnap;
	atomic_store_rel_ptr((volatile uintptr_t *)&sc->sc_txsnap,
	    (uintptr_t)ts);
	if (old != NULL)
		NET_EPOCH_CALL(pppoe_tx_snap_free, &old->ts_ctx);
}

/*
 * Fill `ts` from the session the PADS arm has just established and publish
 * it; consumes `ts` either way.  Called under sc_mtx inside the RX hook's
 * net epoch, which pppoe_lladdr_copy() needs.  ts_parent borrows the
 * softc's own if_ref on sc_parent: every path that lifts sc_parent and
 * if_rele()s it goes through pppoe_clear_softc() -- which clears the
 * snapshot -- first, and the ifnet's free is NET_EPOCH_CALL()'d past any
 * transmitter still holding the old snapshot.  The parent's MAC is copied
 * once here, so the transmit path never touches if_addr.  No
 * iflladdr_event handler republishes it: the AC keys the session on the MAC
 * it learned in discovery, so a parent MAC change ends the session whatever
 * we send, and the LCP keepalive redials with the new one
 * (docs/PERF-DESIGN.md, "Accepted staleness").
 */
void
pppoe_tx_snap_publish(struct pppoe_softc *sc, struct pppoe_tx_snap *ts)
{
	uint8_t *p = ts->ts_hdr;
	int maxlen;

	PPPOE_SC_ASSERT(sc);
	NET_EPOCH_ASSERT();
	if (sc->sc_parent == NULL || !pppoe_lladdr_copy(sc->sc_parent,
	    p + ETHER_ADDR_LEN)) {
		/* A departing parent: its handler clears the session next. */
		free(ts, M_PPPOE);
		pppoe_tx_snap_set(sc, NULL);
		return;
	}
	memcpy(p, &sc->sc_dest, ETHER_ADDR_LEN);
	be16enc(p + 2 * ETHER_ADDR_LEN, ETHERTYPE_PPPOE);
	p[ETHER_HDR_LEN] = PPPOE_VERTYPE;
	p[ETHER_HDR_LEN + 1] = 0;		/* code 0 == session data */
	be16enc(p + ETHER_HDR_LEN + 2, sc->sc_session);
	/*
	 * SIOCSIFMTU raises if_mtu without renegotiating, so if_mtu can be
	 * larger than the payload this session actually negotiated (Task 9
	 * split the fields for exactly this: sc_max_payload_req is what the
	 * administrator asked for, sc_max_payload what is in force now, and
	 * it only changes during discovery).  Bound the frame on
	 * sc_max_payload rather than on if_mtu, and reject rather than clamp
	 * -- clamping a PPP frame is silent corruption.  With RFC 4638 off
	 * (sc_max_payload == 0) the limit is the standard 1492, and the +2 is
	 * the PPP protocol field, which sits inside the PPPoE length but
	 * outside the MTU (see the PADS arm's if_setmtu()).
	 */
	maxlen = (sc->sc_max_payload != 0 ? sc->sc_max_payload :
	    PPPOE_MAXMTU) + 2;
	if (maxlen > USHRT_MAX)
		maxlen = USHRT_MAX;	/* the PPPoE length field is 16 bits */
	ts->ts_maxlen = maxlen;
	ts->ts_parent = sc->sc_parent;
	pppoe_tx_snap_set(sc, ts);
}

#ifdef INET6
/*
 * Seed sppp's IPv6CP interface identifier from the parent Ethernet MAC
 * (T2, R009).
 *
 * pppoe0 is IFT_PPP with if_addrlen 0, so FreeBSD's in6 machinery can
 * never auto-derive a link-local for it (in6_ifattach's in6_get_hw_ifid
 * requires a MAC; in6_ifattach.c:260-311).  IPv6CP nevertheless needs a
 * non-trivial Interface-Identifier for its first Configure-Request or
 * the peer cannot Ack the NCP into Opened state.  Bridge the gap with
 * the same EUI-64 mapping FreeBSD uses for IFT_ETHER (in6_ifattach.c
 * in6_get_hw_ifid: addr[0..2] ^ 0x02, ff:fe, addr[3..5] -- the U/L bit
 * inversion marks the IID locally generated), deterministic per parent
 * and never the peer's address.
 *
 * Runs from pppoe_session_task() once per session, before pp_up()
 * starts LCP and the NCPs; sppp's get_ip6_addrs() falls back to it
 * while pppoe0 still has no link-local ifaddr.  pp_lock is an mtx in
 * this port (krwlock_t -> struct mtx), taken here because the sppp
 * workqueue reads/writes ipv6cp fields under it.
 */
static void
pppoe_seed_ip6_ifid(struct pppoe_softc *sc)
{
	struct sppp *sp = PPPOE_SC2SPPP(sc);
	struct ifnet *ifp = sc->sc_ifp;
	struct epoch_tracker et;
	struct ifnet *parent;
	char pname[IFNAMSIZ];
	u_char mac[ETHER_ADDR_LEN];
	u_int i;
	bool present = false;

	/*
	 * Keep the kernel's auto-link-local machinery out of pppoe0 (T2):
	 * IPv6CP owns the link-local on this interface.  With
	 * ND6_IFF_AUTO_LINKLOCAL set (the IFT_PPP default) FreeBSD's
	 * in6_ifattach re-attaches its own fe80 (with a random ifid) on
	 * every IFF_UP / link event and re-runs DAD against the address
	 * IPv6CP applied, which kept pppoe0's fe80 flickering tentative
	 * and made ping6 unreliable (verified live; the failing standalone
	 * pings traced to exactly this).  Safe here: the interface is fully
	 * attached when the session task runs (clone-create time crashes on
	 * the not-yet-allocated if_af[] slot), and curvnet is set.
	 */
	if (if_getafdata(ifp, AF_INET6) != NULL)
		ND_IFINFO(ifp)->flags &= ~ND6_IFF_AUTO_LINKLOCAL;

	/*
	 * Read the parent under sc_mtx and copy what we need from it inside
	 * the net epoch, entered before the unlock (as pppoe_disconnect()
	 * does): this runs on pppoe_taskq, and a departure or a rebind
	 * can clear sc_parent and drop the softc's reference to it at any
	 * time.  pppoe_parent_departed() NET_EPOCH_WAIT()s after clearing
	 * sc_parent, so the departing ifnet's link address stays put until
	 * we leave the epoch.
	 */
	PPPOE_SC_LOCK(sc);
	parent = sc->sc_parent;
	NET_EPOCH_ENTER(et);
	PPPOE_SC_UNLOCK(sc);
	if (parent == NULL || !pppoe_lladdr_copy(parent, mac)) {
		NET_EPOCH_EXIT(et);
		return;
	}
	strlcpy(pname, if_name(parent), sizeof(pname));
	NET_EPOCH_EXIT(et);

	mtx_lock(&sp->pp_lock);
	for (i = 0; i < sizeof(sp->ipv6cp.my_ifid); i++) {
		if (sp->ipv6cp.my_ifid[i] != 0) {
			present = true;
			break;
		}
	}
	if (!present) {
		sp->ipv6cp.my_ifid[0] = mac[0] ^ 0x02;	/* invert U/L bit */
		sp->ipv6cp.my_ifid[1] = mac[1];
		sp->ipv6cp.my_ifid[2] = mac[2];
		sp->ipv6cp.my_ifid[3] = 0xff;
		sp->ipv6cp.my_ifid[4] = 0xfe;
		sp->ipv6cp.my_ifid[5] = mac[3];
		sp->ipv6cp.my_ifid[6] = mac[4];
		sp->ipv6cp.my_ifid[7] = mac[5];
		log(LOG_INFO, "%s: seeded IPv6CP ifid from %s's MAC "
		    "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		    if_name(sc->sc_ifp), pname,
		    sp->ipv6cp.my_ifid[0], sp->ipv6cp.my_ifid[1],
		    sp->ipv6cp.my_ifid[2], sp->ipv6cp.my_ifid[3],
		    sp->ipv6cp.my_ifid[4], sp->ipv6cp.my_ifid[5],
		    sp->ipv6cp.my_ifid[6], sp->ipv6cp.my_ifid[7]);
	}
	mtx_unlock(&sp->pp_lock);
}
#endif

/*
 * devctl(4) records for the plugin's ppp-linkup/-linkdown mirror (p3-events):
 * `!system=PPPOE subsystem=<ifname> type=<type> <data>`.  Only from sleepable
 * context with no driver or sppp lock held (pppoe_addr_apply(),
 * pppoe_session_task(), sppp_lcp_tld()'s unlocked window), curvnet set.
 * Default vnet only, matching
 * the base kernel's IFNET LINK_UP/LINK_DOWN records (do_link_state_change()):
 * devd runs there, and ifnames are not unique across vnets.
 */
void
pppoe_devctl(struct ifnet *ifp, const char *type, const char *data)
{

	if (!IS_DEFAULT_VNET(curvnet))
		return;
	devctl_notify("PPPOE", if_name(ifp), type, data);
}

#define	PPPOE_MAC_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define	PPPOE_MAC_ARGS(_a)						\
	(_a)[0], (_a)[1], (_a)[2], (_a)[3], (_a)[4], (_a)[5]

/*
 * SESSION_UP/SESSION_DOWN, reconciled level-triggered from
 * pppoe_session_task(): `session` is the live session (0 = none) snapshotted
 * under sc_mtx.  sc_ev_session/sc_ev_ac -- what was last announced -- are
 * touched only here, and pppoe_taskq never runs the task concurrently
 * with itself, so coalesced enqueues still give every DOWN a matching UP.
 */
static void
pppoe_session_devctl(struct pppoe_softc *sc, uint16_t session,
    const struct ether_addr *ac, const char *parent)
{
	char ev[80];

	if (sc->sc_ev_session != 0 && sc->sc_ev_session != session) {
		snprintf(ev, sizeof(ev), "session=%u ac=" PPPOE_MAC_FMT,
		    sc->sc_ev_session, PPPOE_MAC_ARGS(sc->sc_ev_ac.octet));
		pppoe_devctl(sc->sc_ifp, "SESSION_DOWN", ev);
		sc->sc_ev_session = 0;
	}
	if (session != 0 && sc->sc_ev_session == 0) {
		snprintf(ev, sizeof(ev), "session=%u ac=" PPPOE_MAC_FMT
		    " parent=%s", session, PPPOE_MAC_ARGS(ac->octet), parent);
		pppoe_devctl(sc->sc_ifp, "SESSION_UP", ev);
		sc->sc_ev_session = session;
		sc->sc_ev_ac = *ac;
	}
}

/*
 * The one writer.  It runs from pppoe_taskq, never from the pfil hook or
 * the discovery FSM: publishing takes pppoe_parents_lock, sx_xlock() sleeps,
 * and every caller that knows a session has come or gone holds sc_mtx (an
 * MTX_DEF mutex) inside the net epoch.  Those callers just
 * taskqueue_enqueue() and let this reconcile the table with the softc.
 *
 * Lock order is the file's usual one -- sx first, then sc_mtx -- so this never
 * has to drop and re-take either.  curvnet is NULL in a pppoe_taskq
 * thread and V_pppoe_sessions is per-vnet state, so the whole body runs under
 * CURVNET_SET, as pppoe_timeout() does for the same reason.
 *
 * Because publishing is asynchronous, a session id can be live on the wire
 * before it is in the table.  That window costs sess_nosession counts only: a
 * lookup that misses drops the frame, it never delivers it to the wrong softc.
 */
static void
pppoe_session_task(void *ctx, int pending __unused)
{
	struct pppoe_softc *sc = ctx;
	struct sppp *sp;
	struct ether_addr ev_ac;
	char ev_parent[IFNAMSIZ];
	uint16_t ev_session;
	bool want, up, down;

	CURVNET_SET(if_getvnet(sc->sc_ifp));
	sx_xlock(&pppoe_parents_lock);
	PPPOE_SC_LOCK(sc);
	want = !sc->sc_detaching && sc->sc_state == PPPOE_STATE_SESSION &&
	    sc->sc_session != 0;
	/*
	 * sc_hashed_session, not sc_session, decides whether the existing link
	 * is still in the right bucket: taskqueue_enqueue() coalesces, so one
	 * run of this task can have to answer for a session that went away and
	 * a different one that replaced it.  Leaving the softc linked in the
	 * old session's bucket would make the new session unreachable for good.
	 */
	if (sc->sc_in_hash &&
	    (!want || sc->sc_hashed_session != sc->sc_session)) {
		CK_LIST_REMOVE(sc, sc_hash);
		sc->sc_in_hash = false;
	}
	if (want && !sc->sc_in_hash) {
		sc->sc_hashed_session = sc->sc_session;
		CK_LIST_INSERT_HEAD(
		    &V_pppoe_sessions[PPPOE_SESSHASH(sc->sc_session)],
		    sc, sc_hash);
		sc->sc_in_hash = true;
	}
	/*
	 * Deliver the latched link-up/link-down notification to the PPP layer.
	 * pp_up()/pp_down() enqueue on sppp's taskqueue and may take the sppp
	 * lock, so they run here -- outside sc_mtx, on pppoe_taskq where
	 * the whole body already holds curvnet -- never from the PADS arm or
	 * pppoe_clear_softc() (which both hold sc_mtx inside the net epoch).
	 */
	up = sc->sc_want_up;
	down = sc->sc_want_down;
	sc->sc_want_up = sc->sc_want_down = false;
	ev_session = want ? sc->sc_session : 0;
	ev_ac = sc->sc_dest;
	if (sc->sc_parent != NULL)
		strlcpy(ev_parent, if_name(sc->sc_parent), sizeof(ev_parent));
	else
		ev_parent[0] = '\0';
	PPPOE_SC_UNLOCK(sc);
	sx_xunlock(&pppoe_parents_lock);
	pppoe_session_devctl(sc, ev_session, &ev_ac, ev_parent);
	sp = PPPOE_SC2SPPP(sc);
#ifdef INET6
	/*
	 * Seed the IPv6CP interface identifier (parent-MAC EUI-64, T2/R009)
	 * before pp_up() starts LCP and the NCPs: the first IPv6CP
	 * Configure-Request must already have a non-trivial ifid to offer,
	 * and pppoe0 has no link-local of its own to read it back from.
	 */
	pppoe_seed_ip6_ifid(sc);
#endif
	if (down && sp->pp_down != NULL)
		sp->pp_down(sp);
	if (up && sp->pp_up != NULL)
		sp->pp_up(sp);
	CURVNET_RESTORE();
}

/*
 * NCP devctl records (p3-events).  The IPCP/IPv6CP tlu/tld call
 * pppoe_ncp_event() under pp_lock when their pp_ncp_up bit flips; it only
 * latches into sc_ncp_ev[] and enqueues sc_addr_task.  pppoe_addr_apply()
 * snapshots the latch in the same pp_lock section as the addresses and,
 * after its SIOCDIFADDR/SIOCAIFADDR work, reconciles level-triggered with
 * pppoe_ncp_devctl(): *_DOWN (replaying the announced *_UP data) when the
 * NCP went down or re-opened since, *_UP once the address is on the
 * interface.  So a devd action for IPCP_UP finds pppoe0's inet address and
 * peer already applied (mpd5 runs its up-script after addressing too), every
 * *_DOWN pairs an earlier *_UP, and an NCP that opens and closes between
 * two task runs announces neither.
 */
struct pppoe_ncp_snap {
	bool	want;
	u_int	gen;
	char	data[SPPP_EVDATA_LEN];
};

void
pppoe_ncp_event(struct sppp *sp, int idx, const char *data)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);
	struct pppoe_ncp_ev *ev;

	mtx_assert(&sp->pp_lock, MA_OWNED);

	ev = &sc->sc_ncp_ev[idx == IDX_IPV6CP ? PPPOE_EV_IPV6CP : PPPOE_EV_IPCP];
	if (data != NULL) {
		strlcpy(ev->data, data, sizeof(ev->data));
		ev->gen++;
		ev->want = true;
	} else
		ev->want = false;
	taskqueue_enqueue(pppoe_taskq, &sc->sc_addr_task);
}

/* Under pp_lock, from pppoe_addr_apply(). */
static void
pppoe_ncp_snapshot(struct pppoe_softc *sc, struct pppoe_ncp_snap *snap)
{
	u_int i;

	for (i = 0; i < PPPOE_EV_COUNT; i++) {
		snap[i].want = sc->sc_ncp_ev[i].want;
		snap[i].gen = sc->sc_ncp_ev[i].gen;
		if (snap[i].want)
			memcpy(snap[i].data, sc->sc_ncp_ev[i].data,
			    sizeof(snap[i].data));
		else
			snap[i].data[0] = '\0';
	}
}

/*
 * No lock held, curvnet set (pppoe_addr_apply()).  up_ok is false while the
 * NCP's address has not been applied yet; its *_UP then waits for the run
 * that applies it.
 */
static void
pppoe_ncp_devctl(struct pppoe_softc *sc, int i,
    const struct pppoe_ncp_snap *snap, bool up_ok)
{
	static const char *const up_type[] = { "IPCP_UP", "IPV6CP_UP" };
	static const char *const down_type[] = { "IPCP_DOWN", "IPV6CP_DOWN" };
	struct pppoe_ncp_ev *ev = &sc->sc_ncp_ev[i];

	if (ev->ann && (!snap->want || snap->gen != ev->ann_gen)) {
		pppoe_devctl(sc->sc_ifp, down_type[i], ev->ann_data);
		ev->ann = false;
	}
	if (snap->want && !ev->ann && up_ok) {
		pppoe_devctl(sc->sc_ifp, up_type[i], snap->data);
		memcpy(ev->ann_data, snap->data, sizeof(ev->ann_data));
		ev->ann_gen = snap->gen;
		ev->ann = true;
	}
}

/*
 * The IPCP address-application task (spike S2 recipe, R009; plan 2 Task 6
 * Step 1).  sppp's IPCP tlu/tld record the negotiated IPv4 endpoint
 * addresses into sp->pp_want_local / pp_want_remote (under pp_lock) and
 * enqueue this per-interface task; the assignment itself runs here, from
 * the module's pppoe_taskq, NEVER from the netisr handler, a callout,
 * or a workqueue handler holding pp_lock -- in_control_ioctl() takes
 * sx_xlock(&in_control_sx) (sys/netinet/in.c:369) and so needs a
 * sleepable context with no mutex held, and V_ state (in_control walks
 * per-vnet tables) needs a vnet current, which pppoe_taskq does NOT
 * carry -- hence the CURVNET_SET, exactly as pppoe_session_task() does
 * and as spike S2 measured (a bare taskqueue call page-faults in
 * ifunit_ref(): fault addr 0x28 == NULL + vnet_data_base).
 *
 * The whole ioctl body runs with pp_lock held by NOBODY: the want values
 * are snapshotted under SPPP_LOCK and released before in_control_ioctl().
 */
static void
pppoe_addr_apply(void *ctx, int pending __unused)
{
	struct pppoe_softc *sc = ctx;
	struct sppp *sp = PPPOE_SC2SPPP(sc);
	struct in_aliasreq ifra;
	struct ifnet *ifp = sc->sc_ifp;
	struct pppoe_ncp_snap ncp[PPPOE_EV_COUNT];
	uint32_t local, remote, applied;
#ifdef INET6
	struct in6_addr ll6;
	bool ll6_set;
#endif
	bool clear, ll6_pending;
	int error;

	CURVNET_SET(if_getvnet(ifp));

	mtx_lock(&sp->pp_lock);
	local = sp->pp_want_local;
	remote = sp->pp_want_remote;
	clear = (local == 0);
#ifdef INET6
	ll6 = sc->sc_want_ll6;
	ll6_set = sc->sc_want_ll6_set;
#endif
	pppoe_ncp_snapshot(sc, ncp);
	mtx_unlock(&sp->pp_lock);
	/* p3-events: an IPv6CP link-local latched but not yet applied. */
#ifdef INET6
	ll6_pending = ll6_set;
#else
	ll6_pending = false;
#endif
	/*
	 * MEM068 (S03/T1) root cause: the teardown clear used to issue
	 * SIOCDIFADDR with a zeroed ifr_addr.  in_difaddr_ioctl() treats a
	 * well-formed AF_INET ifr_addr as an EXACT-match request -- it
	 * searched for an address literally equal to 0.0.0.0, found none,
	 * returned EADDRNOTAVAIL and the (void) cast swallowed it.  The
	 * negotiated pool address therefore stayed on pppoe0 across the
	 * reconnect and the fresh session's SIOCAIFADDR stacked a SECOND
	 * address next to it (live proof 2026-09-25: after one restart_link,
	 * pppoe0 carried 10.99.0.181 AND 10.99.0.182; the "stale address
	 * persists" symptom was the stale twin still being ifconfig's first
	 * inet line).  The delete must name the address this driver last
	 * APPLIED -- sc_applied_local -- not a wildcard.
	 *
	 * This is deliberately a want-vs-applied TRANSITION step rather than
	 * an arm of the clear/apply dichotomy: a fast redial can reach
	 * sppp_ipcp_tlu before this task's first run, so the coalesced task
	 * may only ever see want != 0 and must delete the stale address in
	 * the same breath as it applies the fresh one.
	 */
	applied = sc->sc_applied_local;
	if (applied != 0 && applied != local) {
		struct ifreq ifr;
		struct sockaddr_in *sin;

		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, if_name(ifp), sizeof(ifr.ifr_name));
		ifr.ifr_addr.sa_family = AF_INET;
		ifr.ifr_addr.sa_len = sizeof(struct sockaddr_in);
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_addr.s_addr = htonl(applied);
		error = in_control_ioctl(SIOCDIFADDR, &ifr, ifp,
		    curthread->td_ucred);
		if (error == 0 || error == EADDRNOTAVAIL) {
			/* gone (or someone else removed it already) */
			sc->sc_applied_local = applied = 0;
		} else {
			log(LOG_ERR,
			    "%s: could not clear the stale IPCP address: %d\n",
			    if_name(ifp), error);
		}
	}

	if (clear) {
#ifdef INET6
		/*
		 * MEM068 (S03/T1): also remove the IPv6CP link-local here so
		 * teardown leaves NO session-negotiated address on pppoe0 and
		 * the next session's tlu rebuilds a fresh one (the "ll is
		 * rebuilt, not stale" contract).  sc_want_ll6 keeps the last
		 * negotiated value -- pppoe_clear_ip_addrs() clears only
		 * sc_want_ll6_set, not the value (if_pppoe_var.h) -- so it is
		 * the authoritative snapshot to delete.  The delete gate is
		 * IN6_IS_ADDR_LINKLOCAL(): sc_want_ll6 is zero before the first
		 * IPv6CP tlu, and a zero delete would just be rejected anyway.
		 *
		 * MEM125/S03-T3: SIOCDIFADDR_IN6 is _IOW('i', 25, struct
		 * in6_ifreq) -- a 44-byte object.  The pre-T3 version passed a
		 * 32-byte struct ifreq whose sin6_scope_id (offset 40..44) was
		 * never written: in6_control_ioctl() reads ifr_addr AS a full
		 * sockaddr_in6, found stack garbage in sin6_scope_id, and
		 * sa6_embedscope() then corrupted the address bytes so
		 * in6ifa_ifpwithaddr() missed -- EADDRNOTAVAIL, swallowed by the
		 * (void) cast.  The link-local therefore survived every teardown
		 * (T3 diag2 trace: no `delete addr fe80::` message across a whole
		 * restart_link outage while the address stayed applied for all 56
		 * fast-poll samples).  Same MEM125 lesson as the IPv4 clear: the
		 * ioctl buffer must match the kernel ABI and every delete error
		 * except EADDRNOTAVAIL (there never was one -- IPv4-only session)
		 * must be logged.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&ll6)) {
			struct in6_ifreq ifr6;

			memset(&ifr6, 0, sizeof(ifr6));
			strlcpy(ifr6.ifr_name, if_name(ifp),
			    sizeof(ifr6.ifr_name));
			ifr6.ifr_addr.sin6_family = AF_INET6;
			ifr6.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
			ifr6.ifr_addr.sin6_addr = ll6;
			ifr6.ifr_addr.sin6_scope_id = 0;
			error = in6_control_ioctl(SIOCDIFADDR_IN6, &ifr6, ifp,
			    curthread->td_ucred);
			if (error != 0 && error != EADDRNOTAVAIL)
				log(LOG_ERR, "%s: could not clear the IPv6CP "
				    "link-local: %d\n", if_name(ifp), error);
		}
#endif
		goto out;
	}

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin_family = AF_INET;
	ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_addr.sin_addr.s_addr = htonl(local);
	ifra.ifra_dstaddr.sin_family = AF_INET;
	ifra.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_dstaddr.sin_addr.s_addr = htonl(remote);
	ifra.ifra_mask.sin_family = AF_INET;
	ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_mask.sin_addr.s_addr = htonl(0xFFFFFFFF);

	error = in_control_ioctl(SIOCAIFADDR, &ifra, ifp,
	    curthread->td_ucred);
	if (error != 0)
		log(LOG_ERR, "%s: could not set the IPCP address: %d\n",
		    if_name(ifp), error);
	else {
		/*
		 * MEM068 (S03/T1): record the applied address so the next
		 * want-vs-applied transition (teardown tld or a renegotiated
		 * address) deletes exactly this one by name.
		 */
		sc->sc_applied_local = local;
		rt_ifmsg(ifp, RTF_UP);
	}

#ifdef INET6
	/*
	 * IPv6CP half (T2, R009): apply the negotiated link-local address
	 * with in6_control_ioctl(SIOCAIFADDR_IN6, ...), the spike S2
	 * recipe for this kernel.  pppoe0 is IFT_PPP with if_addrlen 0, so
	 * FreeBSD cannot auto-derive a link-local for it (in6_ifattach's
	 * in6_get_hw_ifid needs a MAC); the address must be installed
	 * explicitly, and IPv6CP only has a value once it reached Opened.
	 * Same sleepable/vnet discipline as the IPv4 arm above: never run
	 * from the sppp workqueue under pp_lock, always here on
	 * pppoe_taskq under CURVNET_SET.
	 */
	if (ll6_set) {
		struct in6_aliasreq ifra6;

		memset(&ifra6, 0, sizeof(ifra6));
		strlcpy(ifra6.ifra_name, if_name(ifp), sizeof(ifra6.ifra_name));
		ifra6.ifra_addr.sin6_family = AF_INET6;
		ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifra6.ifra_addr.sin6_addr = ll6;
		ifra6.ifra_prefixmask.sin6_family = AF_INET6;
		ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		memset(&ifra6.ifra_prefixmask.sin6_addr, 0xff, 8);
		ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
		error = in6_control_ioctl(SIOCAIFADDR_IN6, &ifra6, ifp,
		    curthread->td_ucred);
		if (error != 0)
			log(LOG_ERR, "%s: could not set the IPv6CP "
			    "link-local address: %d\n", if_name(ifp), error);
		else
			rt_ifmsg(ifp, RTF_UP);
		/*
		 * Consume the latch: the assignment is done.  A tlu re-arms it
		 * for the next session; without this, every later run of the
		 * coalesced addr task (IPCP tlu enqueues on redials, MTU
		 * changes, etc.) would in6_update_ifa() the same address again
		 * and re-trigger DAD, leaving pppoe0's fe80 permanent-tentative
		 * and unbindable (T2, verified live).
		 */
		mtx_lock(&sp->pp_lock);
		sc->sc_want_ll6_set = false;
		mtx_unlock(&sp->pp_lock);
		ll6_pending = false;
	}
#endif

out:
	/*
	 * p3-events: with the address work done, announce.  IPCP_UP needs no
	 * gate: the tlu latched it in the same pp_lock hold that set
	 * pp_want_local, so this pass has just run the SIOCAIFADDR (a failure
	 * is logged and the record still goes out, keeping UP/DOWN paired).
	 * IPV6CP_UP
	 * waits while the link-local is still latched: the clear arm above
	 * skips the SIOCAIFADDR_IN6 until IPCP has an address.
	 */
	pppoe_ncp_devctl(sc, PPPOE_EV_IPCP, &ncp[PPPOE_EV_IPCP], true);
	pppoe_ncp_devctl(sc, PPPOE_EV_IPV6CP, &ncp[PPPOE_EV_IPV6CP],
	    !ll6_pending);
	CURVNET_RESTORE();
}

/*
 * Called by sppp's IPCP tlu/tld with pp_lock held (sppp_set_ip_addrs /
 * sppp_clear_ip_addrs run on the sppp workqueue).  Records the wanted
 * addresses and defers the actual in_control_ioctl() assignment to the
 * sleepable sc_addr_task -- pppoe_addr_apply() above.  The enqueue is
 * sleep-free, so this is safe from the workqueue handler holding pp_lock.
 */
void
pppoe_set_ip_addrs(struct sppp *sp, uint32_t local, uint32_t remote)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	sp->pp_want_local = local;
	sp->pp_want_remote = remote;
	taskqueue_enqueue(pppoe_taskq, &sc->sc_addr_task);
}

/*
 * The one writer of if_mtu once the interface exists, under sc_mtx: the link
 * MTU (SIOCSIFMTU's value, or the PADS arm's RFC 4638 result) capped by the
 * peer's MRU while LCP is up.  Recomputing from both, rather than saving and
 * restoring a copy at LCP up/down, keeps a change to one input from being
 * undone by the other.  if_setmtu() is a plain store (sys/net/if.c:4457-4461);
 * the rt_ifmsg()/if_notifymtu() that ifhwioctl() sends after an MTU change
 * cannot run under sc_mtx or inside the PADS arm's net epoch (see there), so
 * sc_mtu_task sends them.  On the SIOCSIFMTU path ifhwioctl() sends them
 * too; a second announcement of the same MTU is harmless.
 */
static void
pppoe_mtu_update(struct pppoe_softc *sc)
{
	u_int mtu;

	PPPOE_SC_ASSERT(sc);
	mtu = sc->sc_mtu_link;
	if (sc->sc_mtu_peer != 0 && sc->sc_mtu_peer < mtu)
		mtu = sc->sc_mtu_peer;
	if ((u_int)if_getmtu(sc->sc_ifp) == mtu)
		return;
	if_setmtu(sc->sc_ifp, mtu);
	taskqueue_enqueue(pppoe_taskq, &sc->sc_mtu_task);
}

void
pppoe_mtu_set_link(struct pppoe_softc *sc, u_int mtu)
{

	PPPOE_SC_ASSERT(sc);
	sc->sc_mtu_link = mtu;
	pppoe_mtu_update(sc);
}

/*
 * From sppp's LCP tlu (the peer's MRU, already bounded by
 * sppp_lcp_confreq()) and tld (0), with pp_lock dropped.
 */
void
pppoe_set_peer_mru(struct sppp *sp, u_int mru)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	PPPOE_SC_LOCK(sc);
	sc->sc_mtu_peer = mru;
	pppoe_mtu_update(sc);
	PPPOE_SC_UNLOCK(sc);
}

/*
 * On pppoe_taskq: a kthread of its own, so sleepable; no lock held; and
 * outside the net epoch -- taskqueue_run_locked() enters it only for a
 * TASK_NETWORK task (subr_taskqueue.c:510-517), and TASK_INIT() leaves
 * ta_flags 0 (sys/taskqueue.h:127).  Drained in pppoe_clone_destroy().
 */
static void
pppoe_mtu_task(void *ctx, int pending __unused)
{
	struct pppoe_softc *sc = ctx;
	if_t ifp = sc->sc_ifp;

	CURVNET_SET(if_getvnet(ifp));
	rt_ifmsg(ifp, 0);
	if_notifymtu(ifp);
	CURVNET_RESTORE();
}

void
pppoe_clear_ip_addrs(struct sppp *sp)
{
#ifdef INET6
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	sc->sc_want_ll6_set = false;
#endif
	pppoe_set_ip_addrs(sp, 0, 0);
}

#ifdef INET6
/*
 * IPv6CP half of pppoe_set_ip_addrs() (T2, R009): snapshot the
 * negotiated link-local address under pp_lock and defer the actual
 * in6_control_ioctl(SIOCAIFADDR_IN6) assignment to the sleepable
 * sc_addr_task -- pppoe_addr_apply() above.  Called from sppp's IPv6CP
 * tlu with pp_lock held; the enqueue is sleep-free.  The want state
 * lives in the driver's own softc (NOT in struct sppp) so the vendored
 * sppp layout stays byte-identical to the S03/S04-T1-proof build.
 */
void
pppoe_set_ip6_addr(struct sppp *sp, const struct in6_addr *ll)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	sc->sc_want_ll6 = *ll;
	sc->sc_want_ll6_set = true;
	taskqueue_enqueue(pppoe_taskq, &sc->sc_addr_task);
}

/*
 * IPv6CP owns pppoe0's link-local (see pppoe_seed_ip6_ifid()).  Called on
 * every SIOCSIFFLAGS, which ifhwioctl() issues before if_up() -> in6_if_up():
 * clearing ND6_IFF_AUTO_LINKLOCAL only from the session task is too late for
 * the first IFF_UP, where in6_ifattach() would add an fe80:: whose IID is
 * borrowed from another interface or random, alongside the negotiated one.
 */
static void
pppoe_ip6_no_autoll(if_t ifp)
{

	if (if_getafdata(ifp, AF_INET6) != NULL)
		ND_IFINFO(ifp)->flags &= ~ND6_IFF_AUTO_LINKLOCAL;
}

/* Plugin IPv6 eligibility gate (docs/plugin/risk-register.md C9). */
FEATURE(if_pppoe_ipv6, "pppoe(4) delivers received IPv6 once IPv6CP is open");
#endif

static int
pppoe_connect(struct pppoe_softc *sc)
{

	PPPOE_SC_ASSERT(sc);
	if (sc->sc_detaching || sc->sc_parent == NULL)
		return (ENXIO);
	if (sc->sc_state != PPPOE_STATE_INITIAL)
		return (EBUSY);
	sc->sc_padi_retried = 0;
	sc->sc_padr_retried = 0;
	memset(&sc->sc_dest, 0xff, sizeof(sc->sc_dest));
	pppoe_hunique_new(sc);
	sc->sc_state = PPPOE_STATE_PADI_SENT;
	/*
	 * S03/T2 detection point 2: every session start re-samples the
	 * parent's ALTQ state so the sysctl tracks the live parent, and the
	 * one-shot warning fires on the first ALTQ-enabled session if the
	 * bind-time check somehow missed it.
	 */
	pppoe_parent_altq_check(sc);
	(void)pppoe_send_padi(sc);
	/* sc_mtx was dropped around the transmit -- re-validate. */
	if (!sc->sc_detaching && sc->sc_state == PPPOE_STATE_PADI_SENT)
		callout_reset(&sc->sc_timeout, PPPOE_DISC_TIMEOUT,
		    pppoe_timeout, sc);
	return (0);
}

/*
 * Return the softc to PPPOE_STATE_INITIAL, dropping everything the closed
 * session negotiated.  The AC-Cookie and Relay-Session-Id in particular belong
 * to that session only: replaying either into the next PADR makes an AC answer
 * with a Generic-Error.  sc_dest goes back to broadcast so the next PADI is
 * not aimed at the AC that just went away.
 */
void
pppoe_clear_softc(struct pppoe_softc *sc, const char *why)
{
	bool was_session;

	PPPOE_SC_ASSERT(sc);
	/*
	 * Only a session that existed can close.  Every `ifconfig pppoeN down`
	 * and every clone destroy reaches here, most of them with nothing open;
	 * "session 0 closed" in a router's log would be noise, not a record.
	 */
	if (sc->sc_session != 0) {
		log(LOG_INFO, "%s: session %u closed: %s\n",
		    if_name(sc->sc_ifp), sc->sc_session, why);
		/* The one unknown session term_unknown may attribute to us. */
		sc->sc_last_session = sc->sc_session;
		sc->sc_last_dest = sc->sc_dest;
		sc->sc_last_closed = time_uptime;
	}
	was_session = sc->sc_state == PPPOE_STATE_SESSION;
	sc->sc_session = 0;
	sc->sc_state = PPPOE_STATE_INITIAL;
	/*
	 * No more session transmits (T2).  Every path that lifts sc_parent
	 * and if_rele()s it comes through here first, which is what lets the
	 * snapshot borrow the softc's parent reference.
	 */
	pppoe_tx_snap_set(sc, NULL);
	sc->sc_padi_retried = 0;
	sc->sc_padr_retried = 0;
	free(sc->sc_ac_cookie, M_PPPOE);
	sc->sc_ac_cookie = NULL;
	sc->sc_ac_cookie_len = 0;
	free(sc->sc_relay_sid, M_PPPOE);
	sc->sc_relay_sid = NULL;
	sc->sc_relay_sid_len = 0;
	memset(&sc->sc_dest, 0xff, sizeof(sc->sc_dest));
	/*
	 * The PPP layer must hear the link went down (LCP Down/close), and it
	 * must not see a stale Up: latched under sc_mtx, delivered by
	 * pppoe_session_task() outside it.  No link-state write here: the NCP
	 * tlds that LCP Down triggers take it DOWN (sppp_ncp_link()).
	 * Only a SESSION close latches the Down: callers enqueue
	 * sc_session_task for that state alone, so a Down latched from any
	 * other would sit until the next PADS delivered it with the Up.
	 */
	sc->sc_want_up = false;
	if (was_session)
		sc->sc_want_down = true;
}

/*
 * Local shutdown: `ifconfig pppoeN down` and pppoe_clone_destroy().  Tell the
 * AC with a PADT -- an ISP that never sees one holds the session open and
 * refuses the re-connect (spec section 11).
 *
 * Called with sc_mtx held and returns with it held, but DROPS it around the
 * transmit, so both callers must re-validate the softc afterwards.  The parent,
 * peer and session id are lifted into locals first: pppoe_clear_softc() has
 * already wiped them by the time the frame is built.
 */
static void
pppoe_disconnect(struct pppoe_softc *sc)
{
	struct epoch_tracker et;
	struct ether_addr peer;
	if_t parent;
	uint16_t session;

	PPPOE_SC_ASSERT(sc);
	parent = sc->sc_parent;
	peer = sc->sc_dest;
	session = sc->sc_session;
	if (sc->sc_state == PPPOE_STATE_SESSION)
		taskqueue_enqueue(pppoe_taskq, &sc->sc_session_task);
	pppoe_clear_softc(sc, "local shutdown");
	if (session != 0 && parent != NULL) {
		/*
		 * Net epoch around the transmit, entered before the unlock so
		 * a concurrent setparms release of `parent` cannot precede it:
		 * see pppoe_send_padi().
		 */
		NET_EPOCH_ENTER(et);
		PPPOE_SC_UNLOCK(sc);
		(void)pppoe_send_padt(parent, session, &peer);
		NET_EPOCH_EXIT(et);
		PPPOE_SC_LOCK(sc);
	}
}

static pfil_return_t	pppoe_sess_input(if_t, struct mbuf **);
static int		pppoe_transmit(if_t, struct mbuf *);
static int		pppoe_xmit_proto(struct sppp *, struct mbuf *,
			    uint16_t);

/*
 * The RX entry point: a PFIL_TYPE_ETHERNET PFIL_IN hook on V_link_pfil_head,
 * so it sees every frame ether_demux() handles in this vnet.  The fast rejects
 * are in spec section 6.1's order -- parent set, then VLAN tag, then ethertype
 * -- cheapest and most selective first, because the overwhelming majority of
 * frames through here are not ours.
 *
 * ether_demux() calls us inside the net epoch (sys/net/if_ethersubr.c:884-889),
 * so there is no NET_EPOCH_ENTER here, and the Ethernet header is still on the
 * mbuf: ether_demux() strips it only after we return
 * (sys/net/if_ethersubr.c:959).
 */
static pfil_return_t
pppoe_pfil_in(struct mbuf **mp, struct ifnet *ifp, int flags __unused,
    void *ruleset __unused, struct inpcb *inp __unused)
{
	struct mbuf *m = *mp;
	const struct ether_header *eh;
	uint16_t etype;

	NET_EPOCH_ASSERT();

	if (!pppoe_parent_is_ours(ifp))
		return (PFIL_PASS);
	/*
	 * A frame still carrying a non-zero VLAN tag belongs to the vlan
	 * child ifnet, not to us: ether_demux() reads the inner ethertype
	 * before the VLAN branch (sys/net/if_ethersubr.c:901-913), so a
	 * PPPoE-over-VLAN frame reaches this hook twice -- once on igc0 with
	 * M_VLANTAG set, once on vlanN without it.  Take only the second.
	 */
	if ((m->m_flags & M_VLANTAG) != 0 &&
	    EVL_VLANOFTAG(m->m_pkthdr.ether_vtag) != 0)
		return (PFIL_PASS);
	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL) {
			counter_u64_add(V_pppoe_stats.nomem, 1);
			*mp = NULL;
			return (PFIL_CONSUMED);
		}
		*mp = m;
	}
	counter_u64_add(V_pppoe_stats.hook_seen, 1);
	eh = mtod(m, const struct ether_header *);
	etype = ntohs(eh->ether_type);
	if (etype == ETHERTYPE_PPPOEDISC) {
		/*
		 * Not ours -> PFIL_PASS with *mp intact (pfil(9): a PASS
		 * verdict hands the possibly re-pointed mbuf back to
		 * ether_demux()).  pppoe_disc_input() owns *mp either way.
		 */
		switch (pppoe_disc_input(ifp, mp)) {
		case PPPOE_DISC_FOREIGN:
			counter_u64_add(V_pppoe_stats.passed_foreign, 1);
			return (PFIL_PASS);
		case PPPOE_DISC_OURS:
			counter_u64_add(V_pppoe_stats.disc_in, 1);
			break;
		case PPPOE_DISC_FREED:
			break;
		}
		return (PFIL_CONSUMED);
	}
	if (etype == ETHERTYPE_PPPOE)
		return (pppoe_sess_input(ifp, mp));
	return (PFIL_PASS);
}


/*
 * A per-vnet int knob bounded to [0, arg2].  Plain SYSCTL_INT takes any
 * int, and a negative value is not harmless here: ppsratecheck(9) treats a
 * negative maxpps as "no limit", so term_unknown_pps=-1 would lift the
 * PADT rate limit.  An out-of-range write fails with EINVAL and leaves the
 * value alone.  CTLFLAG_VNET makes sysctl_root() rebase arg1 onto curvnet
 * before the call, exactly as it does for SYSCTL_INT.
 */
static int
pppoe_sysctl_int_range(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = *(int *)arg1;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < 0 || val > arg2)
		return (EINVAL);
	*(int *)arg1 = val;
	return (0);
}

/*
 * net.pppoe.reflect -- a plan-1 test hook, not a feature.  With it set, every
 * decapsulated PPP frame is re-encapsulated and sent straight back to the AC,
 * which is the only way to exercise pppoe_transmit() before plan 2 brings the
 * PPP layer that will own the frame.  Plan 2 replaces the arm below with
 * sppp_input() and this knob goes with it.  Default off: left on, a router
 * bounces every PPP frame its peer sends it.
 */
#ifdef PPPOE_TEST_REFLECT
/*
 * Compiled in only with -DPPPOE_TEST_REFLECT (sys/modules/if_pppoe/Makefile
 * PPPOE_TEST_REFLECT=1, which lab/vm/build-module.sh passes): a release
 * module must not carry a knob that turns the router into a PPP echo.
 */
VNET_DEFINE_STATIC(int, pppoe_reflect);
#define	V_pppoe_reflect		VNET(pppoe_reflect)
SYSCTL_PROC(_net_pppoe, OID_AUTO, reflect,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &VNET_NAME(pppoe_reflect), 1, pppoe_sysctl_int_range, "I",
    "test hook (PPPOE_TEST_REFLECT builds only): echo each decapsulated "
    "PPP frame back to the AC instead of handing it to the PPP layer");
#endif

/*
 * TCP MSS clamp (mpd5's tcpmssfix, on by default; PPPOESETMSSFIX turns it
 * off per interface).  Every TCP SYN / SYN-ACK crossing the session, either
 * direction, has an MSS option larger than the session MTU minus 40 (IPv4)
 * or 60 (IPv6) lowered to it, with the TCP checksum fixed up incrementally
 * (RFC 1624 eqn. 3).  Called with the IP header `off` bytes into the mbuf:
 * 0 from pppoe_output() (TX, before sppp_output() prepends the PPP
 * protocol field) and 2 from pppoe_data_input() (RX, the protocol field
 * still in front).
 *
 * Fast path: one flag load, then the IP version/protocol/fragment-offset
 * bytes, then th_flags -- non-TCP, non-first-fragment and non-SYN packets
 * leave after at most three byte compares, with no lock, no allocation and
 * no write.  m_pullup() only runs when the headers are not already in the
 * first mbuf, which the stack never does for IP+TCP (tcp_output() builds
 * the whole header in one mbuf, and an RX frame is one NIC cluster).
 * IPv6 clamps only when TCP is the first next-header; a SYN behind
 * extension headers is left alone (bounded work beats a header-chain walk).
 *
 * Checksum state: with CSUM_TCP / CSUM_TCP_IPV6 set (a delayed checksum
 * that something below will still compute), th_sum holds only the
 * pseudo-header seed, which does not cover the options -- rewriting the
 * option is enough, and "fixing" th_sum would corrupt it.  pppoeN
 * advertises no if_hwassist, so ip_output()/ip6_output() normally finish
 * it before if_output and this arm is defensive.  Otherwise th_sum is a
 * complete checksum and is adjusted; the adjustment keeps the ones'-
 * complement sum over the whole segment unchanged, so an RX csum_data
 * partial sum (CSUM_DATA_VALID) stays valid too.
 */
FEATURE(if_pppoe_mssfix,
    "if_pppoe(4) clamps the TCP MSS of SYNs crossing the session");

#define	PPPOE_MSS_V4_OVERHEAD	40	/* IPv4 + TCP headers, no options */
#define	PPPOE_MSS_V6_OVERHEAD	60	/* IPv6 + TCP headers, no options */
#define	PPPOE_IP4_MINHLEN	20
#define	PPPOE_IP6_HLEN		40
#define	PPPOE_TH_MINLEN		20	/* TCP header without options */
#define	PPPOE_TH_FLAGS_OFF	13
#define	PPPOE_TH_SUM_OFF	16

static uint16_t
pppoe_cksum_adjust(uint16_t sum, uint16_t oldw, uint16_t neww)
{
	uint32_t x;

	/* HC' = ~(~HC + ~m + m') */
	x = (uint32_t)(uint16_t)~sum + (uint16_t)~oldw + neww;
	x = (x & 0xffff) + (x >> 16);
	x = (x & 0xffff) + (x >> 16);
	return ((uint16_t)~x);
}

/*
 * Lower an MSS option above maxmss in the TCP header th (thlen > 20 bytes,
 * all contiguous and writable).  The walk is bounded by thlen (<= 60) and
 * advances at least one byte per step; a malformed option list stops it.
 * fixsum: th_sum is a complete checksum to adjust (see above).
 */
static bool
pppoe_mss_fix_th(uint8_t *th, int thlen, uint16_t maxmss, bool fixsum)
{
	uint16_t mss, oldw, neww;
	int i, olen, pos;

	for (i = PPPOE_TH_MINLEN; i < thlen; i += olen) {
		if (th[i] == TCPOPT_EOL)
			break;
		if (th[i] == TCPOPT_NOP) {
			olen = 1;
			continue;
		}
		if (i + 1 >= thlen)
			break;
		olen = th[i + 1];
		if (olen < 2 || i + olen > thlen)
			break;
		if (th[i] != TCPOPT_MAXSEG || olen != TCPOLEN_MAXSEG)
			continue;
		pos = i + 2;
		mss = be16dec(th + pos);
		if (mss <= maxmss)
			return (false);
		be16enc(th + pos, maxmss);
		if (fixsum) {
			/*
			 * The checksum sums 16-bit words aligned on the TCP
			 * header (the pseudo-header is 12 or 40 bytes, so the
			 * alignment carries over).  An MSS value at an odd
			 * offset straddles two words, which is the same as
			 * summing it byte-swapped.
			 */
			oldw = mss;
			neww = maxmss;
			if ((pos & 1) != 0) {
				oldw = bswap16(oldw);
				neww = bswap16(neww);
			}
			be16enc(th + PPPOE_TH_SUM_OFF, pppoe_cksum_adjust(
			    be16dec(th + PPPOE_TH_SUM_OFF), oldw, neww));
		}
		return (true);
	}
	return (false);
}

/*
 * Make the first `need` bytes contiguous.  False means stop: the packet is
 * shorter than that (leave it alone, *mp intact) or m_pullup() failed and
 * freed the chain (*mp is NULL).
 */
static bool
pppoe_mss_pullup(struct mbuf **mp, int need)
{

	if (__predict_true((*mp)->m_len >= need))
		return (true);
	if ((*mp)->m_pkthdr.len < need)
		return (false);
	*mp = m_pullup(*mp, need);
	return (*mp != NULL);
}

/*
 * Returns the mbuf to carry on with (m_pullup() may have replaced it), or
 * NULL when m_pullup() failed and freed it.
 */
static struct mbuf *
pppoe_mss_clamp(struct pppoe_softc *sc, if_t ifp, struct mbuf *m, int off,
    int af)
{
	uint8_t *ip, *th;
	u_int mtu, lim;
	int iphlen, thlen, overhead;
	bool fixsum;

	if (atomic_load_int(&sc->sc_nomssfix) != 0)
		return (m);
	if (af == AF_INET) {
		if (!pppoe_mss_pullup(&m, off + PPPOE_IP4_MINHLEN))
			return (m);
		ip = mtod(m, uint8_t *) + off;
		if ((ip[0] >> 4) != IPVERSION || ip[9] != IPPROTO_TCP ||
		    (be16dec(ip + 6) & IP_OFFMASK) != 0)
			return (m);
		iphlen = (ip[0] & 0x0f) << 2;
		if (iphlen < PPPOE_IP4_MINHLEN)
			return (m);
		overhead = PPPOE_MSS_V4_OVERHEAD;
#ifdef INET6
	} else if (af == AF_INET6) {
		if (!pppoe_mss_pullup(&m, off + PPPOE_IP6_HLEN))
			return (m);
		ip = mtod(m, uint8_t *) + off;
		if ((ip[0] >> 4) != 6 || ip[6] != IPPROTO_TCP)
			return (m);
		iphlen = PPPOE_IP6_HLEN;
		overhead = PPPOE_MSS_V6_OVERHEAD;
#endif
	} else
		return (m);

	if (!pppoe_mss_pullup(&m, off + iphlen + PPPOE_TH_FLAGS_OFF + 1))
		return (m);
	th = mtod(m, uint8_t *) + off + iphlen;
	if (__predict_true((th[PPPOE_TH_FLAGS_OFF] & TH_SYN) == 0))
		return (m);

	/* A SYN: rare, so from here on cost does not matter. */
	thlen = (th[12] >> 4) << 2;
	if (thlen <= PPPOE_TH_MINLEN)
		return (m);		/* no options, so no MSS */
	if (!pppoe_mss_pullup(&m, off + iphlen + thlen))
		return (m);
	if (!M_WRITABLE(m))
		return (m);		/* shared cluster: never write it */
	th = mtod(m, uint8_t *) + off + iphlen;

	/*
	 * The session MTU: sppp lowers if_mtu to the peer's MRU at LCP up
	 * (sppp_lcp_tlu), but SIOCSIFMTU can raise it past what this session
	 * negotiated, so bound it by the payload pppoe_transmit() enforces.
	 * sc_max_payload is written under sc_mtx; this unlocked read of an
	 * aligned uint16_t can only see the old or the new value.
	 */
	mtu = if_getmtu(ifp);
	lim = sc->sc_max_payload != 0 ? (u_int)sc->sc_max_payload :
	    (u_int)PPPOE_MAXMTU;
	if (mtu > lim)
		mtu = lim;
	if (mtu <= (u_int)overhead)
		return (m);
	fixsum = (m->m_pkthdr.csum_flags & (CSUM_TCP | CSUM_TCP_IPV6)) == 0;
	if (pppoe_mss_fix_th(th, thlen, (uint16_t)(mtu - overhead), fixsum))
		counter_u64_add(V_pppoe_stats.mss_clamped, 1);
	return (m);
}

/*
 * RX half of the clamp, for pppoe_data_input(): the mbuf still carries the
 * 2-byte PPP protocol field in front of the IP header.  sc is the caller's
 * single epoch-protected load of if_softc (already checked non-NULL and
 * not detaching); it is not reloaded here.
 */
static struct mbuf *
pppoe_mss_input(struct pppoe_softc *sc, if_t ifp, struct mbuf *m,
    uint16_t proto)
{

	return (pppoe_mss_clamp(sc, ifp, m, (int)sizeof(uint16_t),
	    proto == PPP_IP ? AF_INET : AF_INET6));
}

/*
 * bpf(4) sees every frame as DLT_PPP (bpfattach() in pppoe_clone_create()):
 * the HDLC-like address and control octets, then the protocol field and the
 * payload.  That is the layout libpcap compiles DLT_PPP filters against --
 * link type at offset 2, network layer at 4 (contrib/libpcap/gencode.c:
 * 1259-1268) -- and bpf_movein()'s PPP_HDRLEN (sys/net/bpf.c:628-630).  The
 * mbuf starts at the protocol field in both directions, without the PPPoE
 * header that DLT_PPP_ETHER's offsets (6 and 8, gencode.c:1270-1279)
 * assume, and without address/control, so those two octets are prepended
 * here; proto != NULL is the transmit path whose protocol field is not on
 * the mbuf yet.  BPF_MTAP2() is a bpf_peers_present() test when nobody is
 * listening (sys/net/bpf.c:2494-2500), so the header costs nothing then.
 */
static void
pppoe_bpf_tap(if_t ifp, struct mbuf *m, const uint16_t *proto)
{
	uint8_t hdr[PPP_HDRLEN];
	u_int hlen;

	hdr[0] = PPP_ALLSTATIONS;
	hdr[1] = PPP_UI;
	hlen = 2;
	if (proto != NULL) {
		memcpy(&hdr[2], proto, sizeof(*proto));
		hlen += sizeof(*proto);
	}
	BPF_MTAP2(ifp, hdr, hlen, m);
}

/*
 * A decapsulated PPP frame, protocol field first.  Every protocol -- control
 * frames and the PPP_IP/PPP_IPV6 payload alike -- goes to sppp_input(),
 * which pokes pp_last_receive (keepalive liveness) for each frame and
 * delivers payload only while the gating NCP (IPCP/IPv6CP) is OPENED.
 *
 * Reached only from pppoe_netisr_input(), so it runs in the net epoch with
 * curvnet set on both the in-place and the queued arm -- see the citations
 * there.  V_pppoe_reflect, pppoe_transmit() and sppp_input() all need exactly
 * that.
 */
void
pppoe_data_input(struct mbuf *m)
{
	struct pppoe_softc *sc;
	if_t ifp = m->m_pkthdr.rcvif;
	uint16_t proto;

	NET_EPOCH_ASSERT();
	counter_u64_add(V_pppoe_stats.data_in, 1);
	if (ifp == NULL)
		goto drop;
	/*
	 * One load of the softc, used for the rest of this frame.  A queued
	 * frame can outlive the session lookup that dispatched it, so this is
	 * where a destroy in progress is caught: pppoe_clone_destroy() NULLs
	 * if_softc and then NET_EPOCH_WAIT()s before sppp_detach(), so a
	 * non-NULL load here keeps the embedded struct sppp live until we
	 * leave the epoch.  sc_detaching is only an earlier, racy exit.
	 */
	sc = atomic_load_ptr(&ifp->if_softc);
	if (sc == NULL || sc->sc_detaching)
		goto drop;
	/*
	 * Charged here, spread across the workers, not in the serial RX stage,
	 * and the only IPACKETS/IBYTES charge (SPPP_LOWER_COUNTS_BYTES: sppp
	 * adds none).  pppoe_sess_input() trimmed the frame to the PPPoE
	 * length, so m_pkthdr.len is the PPPoE payload (PPP protocol field
	 * included) -- the plen it used to charge there.
	 */
	if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	pppoe_bpf_tap(ifp, m, NULL);
#ifdef PPPOE_TEST_REFLECT
	if (V_pppoe_reflect != 0) {
		/*
		 * pppoe_transmit() owns the mbuf from here, including on
		 * every error path, and re-checks the session state itself.
		 */
		(void)pppoe_transmit(ifp, m);
		return;
	}
#endif
	/*
	 * sppp_input()'s PP_DEVF_NOFRAMING arm memcpy()s the 2-byte protocol
	 * field straight from mtod(), so it must be contiguous.  m_pullup()
	 * consumes the chain and returns NULL on failure.
	 */
	if (m->m_len < 2) {
		m = m_pullup(m, 2);
		if (m == NULL) {
			counter_u64_add(V_pppoe_stats.nomem, 1);
			return;
		}
	}
	proto = ntohs(*mtod(m, uint16_t *));
	if (proto == PPP_IP || proto == PPP_IPV6) {
		m = pppoe_mss_input(sc, ifp, m, proto);	/* TCP MSS clamp */
		if (m == NULL)
			return;
	}
	/*
	 * Control protocols and PPP_IP/PPP_IPV6 payload alike: the PPP state
	 * machine owns the frame now.  sppp_input() pokes pp_last_receive for
	 * every frame (keepalive liveness), hands PPP_IP to ip_input() while
	 * IPCP is OPENED and PPP_IPV6 to ip6_input() while IPv6CP is OPENED,
	 * and does the reject/drop accounting for everything else.
	 */
	sppp_input(ifp, m);
	return;

drop:
	m_freem(m);
}


/*
 * net.pppoe.term_unknown / net.pppoe.term_unknown_pps -- spec section 6.3's
 * rate-limited PADT for unknown sessions (NetBSD's pppoe_session_input()
 * behaviour, if_pppoe.c:1136-1141), narrowed to sessions we can attribute.
 * A PPPoE access concentrator can hold a dead session open forever if the
 * client behind us never tells it; with term_unknown set, a 0x8864 frame
 * addressed to us for the session a softc on this parent last closed, from
 * that session's AC, draws one PADT, rate-limited by ppsratecheck() to
 * term_unknown_pps per second so an attacker (or a peer's timer bug)
 * flooding frames cannot turn us into a PADT amplifier.  Any other unknown
 * session is passed up the stack untouched, never answered: it may belong
 * to another PPPoE client on the same parent (mpd5 through ng_ether).
 *
 * Default off: it answers frames the driver would otherwise pass on,
 * which is exactly what an idle WAN does not need on every stray packet.
 * The rate-limit state (last time and pps budget) is per-vnet, like every
 * other knob and counter here.
 */
VNET_DEFINE_STATIC(int, pppoe_term_unknown);
#define	V_pppoe_term_unknown		VNET(pppoe_term_unknown)
VNET_DEFINE_STATIC(int, pppoe_term_unknown_pps) = 1;
#define	V_pppoe_term_unknown_pps	VNET(pppoe_term_unknown_pps)
SYSCTL_PROC(_net_pppoe, OID_AUTO, term_unknown,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &VNET_NAME(pppoe_term_unknown), 1, pppoe_sysctl_int_range, "I",
    "send a PADT for stale PPPoE sessions of ours (0 disables, default; 1)");
SYSCTL_PROC(_net_pppoe, OID_AUTO, term_unknown_pps,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &VNET_NAME(pppoe_term_unknown_pps), INT_MAX, pppoe_sysctl_int_range, "I",
    "max PADTs per second for stale sessions (>= 0; 0 sends none)");
VNET_DEFINE_STATIC(struct timeval, pppoe_term_unknown_lasttime);
#define	V_pppoe_term_unknown_lasttime	VNET(pppoe_term_unknown_lasttime)
VNET_DEFINE_STATIC(int, pppoe_term_unknown_curpps);
#define	V_pppoe_term_unknown_curpps	VNET(pppoe_term_unknown_curpps)
/*
 * How long a closed session stays attributable to us.  Of the order of an
 * AC's keepalive timeout: long enough to answer the frames an AC sends a
 * session it has not noticed is dead, short enough that an id the AC has
 * since reissued (possibly to a same-NIC mpd5) is not ours to PADT.
 */
VNET_DEFINE_STATIC(u_int, pppoe_term_unknown_window) = 180;
#define	V_pppoe_term_unknown_window	VNET(pppoe_term_unknown_window)
SYSCTL_UINT(_net_pppoe, OID_AUTO, term_unknown_window,
    CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(pppoe_term_unknown_window), 0,
    "seconds after its close a stale session of ours may draw a PADT");

/*
 * net.pppoe.parent_altq (S03/T2): per-vnet advisory read-only indicator that
 * is 1 when a bound parent interface has ALTQ enabled.  ALTQ on the parent
 * silently disables iflib multi-queue TX selection (iflib.c:4321-4322 in
 * releng/14.3), so a pf(4) shaping mistake on the parent costs throughput
 * with no other symptom -- this knob and the one-shot log below make that
 * state observable instead of "pretend"-silent.  Written only by
 * pppoe_parent_altq_check() at the two detection points (parent bind via
 * pppoe_ioctl_setparms() and every session start via pppoe_connect()), so it
 * tracks the live state across re-binds; read by sysctl consumers.
 *
 * Like term_unknown, the state is per-vnet: the module can be loaded in
 * several vnets and each tracks its own parents.
 */
VNET_DEFINE_STATIC(int, pppoe_parent_altq);
#define	V_pppoe_parent_altq		VNET(pppoe_parent_altq)
SYSCTL_INT(_net_pppoe, OID_AUTO, parent_altq, CTLFLAG_VNET | CTLFLAG_RD,
    &VNET_NAME(pppoe_parent_altq), 0,
    "1 if a bound parent interface has ALTQ enabled (iflib multi-queue TX "
    "is disabled then); read-only, updated at parent bind and session start");

/*
 * The session data path (spec section 6.3).  Runs in the RX hook, inside the
 * net epoch, with the Ethernet header still on the mbuf.
 *
 * Strips 14 Ethernet + 6 PPPoE = 20 bytes (PPPOE_RX_STRIP), leaving the
 * 2-byte PPP protocol field at the front for sppp_input(). A commonly
 * quoted figure of 22 bytes includes that protocol field, which this
 * driver deliberately leaves on.
 */
static pfil_return_t
pppoe_sess_input(if_t ifp, struct mbuf **mp)
{
	struct mbuf *m = *mp;
	const struct ether_header *eh;
	const struct pppoehdr *ph;
	struct pppoe_softc *sc;
	if_t sifp;		/* pppoeN, for the enqueue-drop count */
	uint16_t session, plen;
	int need;
	u_char lladdr[ETHER_ADDR_LEN];

	NET_EPOCH_ASSERT();

	need = ETHER_HDR_LEN + PPPOE_HEADERLEN + 2;	/* + PPP protocol */
	if (m->m_pkthdr.len < need) {
		counter_u64_add(V_pppoe_stats.sess_short, 1);
		goto pass;
	}
	if (m->m_len < need) {
		/* Under MHLEN, so this misses m_pullup()'s cluster arm. */
		m = m_pullup(m, need);
		if (m == NULL) {
			/*
			 * Counted, not dropped silently: an mbuf-exhaustion
			 * drop that shows up nowhere in net.pppoe.* is the
			 * hardest kind to diagnose on a live router.
			 */
			counter_u64_add(V_pppoe_stats.nomem, 1);
			*mp = NULL;
			return (PFIL_CONSUMED);
		}
		*mp = m;
	}
	eh = mtod(m, const struct ether_header *);
	ph = (const struct pppoehdr *)(mtod(m, const uint8_t *) +
	    ETHER_HDR_LEN);
	if (ph->vertype != PPPOE_VERTYPE || ph->code != 0) {
		counter_u64_add(V_pppoe_stats.sess_short, 1);
		goto pass;
	}
	session = ntohs(ph->session);
	plen = ntohs(ph->plen);
	if (plen < 2 ||
	    m->m_pkthdr.len < ETHER_HDR_LEN + (int)PPPOE_HEADERLEN + plen) {
		counter_u64_add(V_pppoe_stats.sess_short, 1);
		goto pass;
	}

	sc = pppoe_session_lookup(ifp, session, eh->ether_shost);
	if (sc == NULL) {
		/*
		 * Also the brief window after a PADS in which the session is
		 * live on the wire but pppoe_session_task() has not published
		 * it yet -- see there.  Rate-limited PADTs for a session this
		 * window cannot find yet are what net.pppoe.term_unknown buys,
		 * so a PADS-to-first-frame gap does not have the driver tell
		 * the AC its brand-new session is dead.
		 */
		counter_u64_add(V_pppoe_stats.sess_nosession, 1);
		/*
		 * Not a live session of ours.  With term_unknown set, a frame
		 * unicast to this parent for the session one of our softcs
		 * last closed (pppoe_stale_session_is_ours()) is ours: drop
		 * it and answer with a PADT so the AC tears the session down
		 * instead of holding it, rate-limited by ppsratecheck() to
		 * term_unknown_pps.  The PADT is fresh (pppoe_send_padt()
		 * builds its own mbuf) and runs in the net epoch this hook
		 * already sits in, the same context pppoe_disconnect()
		 * transmits under; curvnet is the receiving vnet.
		 *
		 * Everything else -- the default, with term_unknown off -- is
		 * passed up the stack untouched: another PPPoE client on this
		 * parent (mpd5 via ng_ether's orphans hook) may own it.
		 */
		if (V_pppoe_term_unknown != 0 &&
		    pppoe_lladdr_copy(ifp, lladdr) &&
		    memcmp(eh->ether_dhost, lladdr, ETHER_ADDR_LEN) == 0 &&
		    pppoe_stale_session_is_ours(ifp, session,
		    eh->ether_shost, V_pppoe_term_unknown_window)) {
			if (ppsratecheck(&V_pppoe_term_unknown_lasttime,
			    &V_pppoe_term_unknown_curpps,
			    V_pppoe_term_unknown_pps)) {
				counter_u64_add(V_pppoe_stats.padt_unknown, 1);
				(void)pppoe_send_padt(ifp, session,
				    (const struct ether_addr *)eh->ether_shost);
			}
			goto drop;
		}
		goto pass;
	}

	counter_u64_add(V_pppoe_stats.sess_in, 1);

	m_adj(m, PPPOE_RX_STRIP);		/* 14 + 6 == 20 */
	/* Drop any Ethernet padding past the PPPoE length field. */
	if (m->m_pkthdr.len > plen)
		m_adj(m, plen - m->m_pkthdr.len);
	/*
	 * The frame now arrives on pppoeN, so what the parent's receive path
	 * stamped for the outer Ethernet frame goes, as in if_gif.c:443-444
	 * and if_gre.c:587-589 (OPNsense 25.7).  This hook runs from
	 * ether_demux() (if_ethersubr.c:889) before its own
	 * m_clrprotoflags() (:929), so the parent's layer-specific M_PROTO*
	 * flags are still set, and the layers above give those bits their
	 * own meanings.  The NIC's checksum verdict was taken over the
	 * outer frame, with the PPPoE and PPP headers in front of whatever
	 * it took for L3; whether it covers the inner packet is unverified
	 * per NIC (one that parses through PPPoE may well mean the inner
	 * IP/L4), so it is dropped at the cost of a software check.  The
	 * flow hash is re-derived from the inner headers just below.  Clear
	 * M_VLANTAG here too: ether_demux()/vlan_input() clear it alongside
	 * m_clrprotoflags() (if_ethersubr.c:921-922, if_vlan.c:1575), and a
	 * priority-tagged VID-0 frame reaches here with it still set.
	 */
	m_clrprotoflags(m);
	m->m_flags &= ~M_VLANTAG;
	m->m_pkthdr.csum_flags = 0;
	m->m_pkthdr.rcvif = sc->sc_ifp;
	M_SETFIB(m, if_getfib(sc->sc_ifp));

	/*
	 * No interface counters and no BPF tap here: pppoe_data_input()
	 * charges them on the netisr worker.  This function runs on the one
	 * CPU every frame of the session arrives on, so it does only the
	 * parent check, lookup, strip, hash and enqueue.
	 *
	 * Hand off to the private netisr protocol.  Clearing the hash type on
	 * failure matters: without it pppoe_m2cpuid() would inherit whatever
	 * the parent NIC stamped for the outer PPPoE frame, which is one value
	 * for the whole session and spreads nothing.  netisr owns the mbuf from
	 * here on every path, including a queue overflow (netisr.c:1023-1024)
	 * and a disabled protocol (:1130-1133); both return non-zero, and that
	 * drop is otherwise visible only in netstat -Q.
	 */
	if (!pppoe_hash_inner(m))
		M_HASHTYPE_SET(m, M_HASHTYPE_NONE);
	/*
	 * The IPACKETS/IBYTES charge and the BPF tap happen on the worker, so a
	 * frame netisr refuses never reaches them: count it as an input drop
	 * on pppoeN, or netstat -i would silently under-report.
	 */
	sifp = sc->sc_ifp;
	if (netisr_dispatch(NETISR_PPPOE_DATA, m) != 0) {
		counter_u64_add(V_pppoe_stats.netisr_enqueue_drop, 1);
		if_inc_counter(sifp, IFCOUNTER_IQDROPS, 1);
	}
	*mp = NULL;
	return (PFIL_CONSUMED);

drop:
	m_freem(m);
	*mp = NULL;
	return (PFIL_CONSUMED);

pass:
	/* Not ours: hand the (possibly pulled-up) frame back intact. */
	counter_u64_add(V_pppoe_stats.passed_foreign, 1);
	*mp = m;
	return (PFIL_PASS);
}

VNET_DEFINE_STATIC(pfil_hook_t, pppoe_pfil_hook);
#define	V_pppoe_pfil_hook	VNET(pppoe_pfil_hook)

static void
pppoe_pfil_attach(void)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN,
		.pa_type = PFIL_TYPE_ETHERNET,
		.pa_mbuf_chk = pppoe_pfil_in,
		.pa_modname = "if_pppoe",
		.pa_rulname = "default",
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR,
	};
	int error;

	V_pppoe_pfil_hook = pfil_add_hook(&pha);
	pla.pa_head = V_link_pfil_head;
	pla.pa_hook = V_pppoe_pfil_hook;
	error = pfil_link(&pla);
	if (error != 0) {
		/*
		 * Not expected: pppoe_vnet_init() sorts after
		 * vnet_ether_init(), which registers V_link_pfil_head
		 * (see VNET_SYSINIT(pppoe_vnet_init) below).  If it does
		 * happen, this vnet's hook never attaches, so make it
		 * loud and continue loading.  The literal
		 * "pppoe: pfil_link" prefix is the unload probe's dmesg
		 * grep key.
		 */
		printf("pppoe: pfil_link(%s) failed: %d (vnet %p has no link pfil head - hook not attached)\n",
		    pha.pa_modname, error, (void *)curvnet);
	}
}

/*
 * pfil_remove_hook() unlinks the hook from every head itself -- it walks
 * V_pfil_head_list and pfil_link_remove()s us from each head_in/head_out
 * (sys/net/pfil.c:487-502) -- so no explicit pfil_link(PFIL_UNLINK) is needed.
 * It does NOT wait for the net epoch, though: the unlinked struct pfil_link is
 * only NET_EPOCH_CALL()'d for free (sys/net/pfil.c:493, :499), and
 * pfil_mbuf_common() calls link->link_mbuf_chk() from inside the epoch
 * (sys/net/pfil.c:203, :211-213).  A caller can therefore still be inside
 * pppoe_pfil_in() when this returns; pppoe_vnet_uninit() does the
 * NET_EPOCH_WAIT() before freeing the counters those callers touch.
 */
static void
pppoe_pfil_detach(void)
{

	if (V_pppoe_pfil_hook != NULL) {
		pfil_remove_hook(V_pppoe_pfil_hook);
		V_pppoe_pfil_hook = NULL;
	}
}

/*
 * Sweep the pfil hook out of every vnet.  MOD_UNLOAD must detach
 * V_pppoe_pfil_hook per vnet -- pfil_remove_hook() walks only the curvnet's
 * V_pfil_head_list (sys/net/pfil.c:481-510), which is per-vnet -- and must do
 * it before pppoe_netisr_unregister(): the hook is the only thing that can
 * dispatch NETISR_PPPOE_DATA, so once it is gone everywhere, nothing can
 * still be heading for np_handler by the time it goes NULL (the race
 * pppoe_netisr_unregister() documents).  The iteration is
 * netisr_unregister()'s own idiom (netisr.c:659-668): VNET_LIST_RLOCK_NOSLEEP()
 * holds the vnet list while CURVNET_SET() selects each vnet in turn.  FreeBSD's
 * vnet_iterate() helper wraps exactly this rlock/select sequence, but the
 * OPNsense 25.7 tree carries no definition of it -- grep across sys/ finds
 * nothing -- so the open-coded form above is used rather than a callback that
 * would not link.  The
 * callback path takes pfil(9)'s mutex (pfil_lock), which may briefly block on
 * a concurrent hook add or remove, but nothing in pfil(9) acquires the vnet
 * list locks, so there is no lock-order cycle.  pppoe_pfil_detach() is
 * NULL-guarded, which covers vnets whose hook was never attached (the
 * pfil_link() failure pppoe_pfil_attach() makes loud, where
 * pfil_add_hook() succeeded, or where the hook was never added).  The
 * caller's NET_EPOCH_WAIT() after this returns quiesces in-flight
 * pppoe_pfil_in() callers from every vnet before the netisr handler goes
 * away.
 */
static void
pppoe_vnet_pfil_sweep(void)
{
	struct vnet *vnet_iter;

	VNET_LIST_RLOCK_NOSLEEP();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		pppoe_pfil_detach();
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK_NOSLEEP();
}

static void
pppoe_softc_free(struct epoch_context *ctx)
{
	struct pppoe_softc *sc;

	sc = __containerof(ctx, struct pppoe_softc, sc_epoch_ctx);
	/* Cleared by the destroy's pppoe_disconnect(); belt and braces. */
	free(sc->sc_txsnap, M_PPPOE);
	free(sc->sc_service_name, M_PPPOE);
	free(sc->sc_ac_name, M_PPPOE);
	free(sc->sc_ac_cookie, M_PPPOE);
	free(sc->sc_relay_sid, M_PPPOE);
	/* sppp_detach() leaves pp_lock to us: see pppoe_clone_destroy(). */
	mtx_destroy(&sc->ppp.pp_lock);
	mtx_destroy(&sc->sc_mtx);
	free(sc, M_PPPOE);
}

/*
 * if_output.  if_attach() below publishes the ifnet to the stack, and
 * if_attach_internal() installs no default if_output at all (sys/net/if.c has
 * exactly one assignment to if_output, in if_setoutputfn()); its default
 * if_transmit is if_transmit_default() (sys/net/if.c:4090), which hands off to
 * an equally NULL if_start.  Both paths must therefore be non-NULL before
 * if_attach().  Task 11 (plan 1) set if_transmit to pppoe_transmit(); plan 2
 * (S02/T1) hands if_output to the PPP layer: sppp_attach() assigns it
 * herself (the vendored `sp->pp_if->if_output = sppp_output;`), and
 * sppp_output() hands IP to pppoe_xmit_proto() with the PPP protocol number
 * alongside (T4); if_transmit (pppoe_transmit()) still takes sppp's control
 * frames with the field already on the mbuf.  pppoe_output_frame() above
 * is NOT either function's replacement -- it is the discovery helper that
 * puts a frame on the parent.
 */

/*
 * The if_output entry the stack calls (ip_output, ip6_output, mld, ...).
 * The vendored sppp_attach() assigns if_output directly to the sppp
 * layer's sppp_output(); this driver wraps it so the embedded struct sppp
 * cannot be torn down under a caller that raced pppoe_clone_destroy()
 * (M002/S03/T2 live finding: run-keepalive.sh storm round 7 panicked with
 * 'panic: page fault' in __mtx_lock_sleep from sppp_output()).
 *
 * The guard is the net epoch, not a softc hold (T1).  The softc is loaded
 * once inside the section; pppoe_clone_destroy() unpublishes it and then
 * NET_EPOCH_WAIT()s before sppp_detach(), so a non-NULL load keeps the
 * softc and its sppp alive until NET_EPOCH_EXIT(), and a NULL load means
 * the interface is on its way out and only a drop is legal.  ip_output()
 * and ip6_output() both NET_EPOCH_ASSERT() (releng/14.3), so the enter
 * normally nests inside the caller's section -- legal, each section has
 * its own tracker -- and it keeps any caller that is not in one safe.
 * sppp_output() never sleeps (pp_lock is a mutex; sppp_wq_add() only
 * enqueues).
 */
static int
pppoe_output(struct ifnet *ifp, struct mbuf *m,
    const struct sockaddr *dst, struct route *rt)
{
	struct epoch_tracker et;
	struct pppoe_softc *sc;
	int error;

	NET_EPOCH_ENTER(et);
	sc = atomic_load_ptr(&ifp->if_softc);
	if (sc == NULL) {
		/* Destroy has unpublished the softc; the ifp is on its way out. */
		NET_EPOCH_EXIT(et);
		m_freem(m);
		return (EINVAL);
	}
	if (dst->sa_family == AF_INET || dst->sa_family == AF_INET6) {
		m = pppoe_mss_clamp(sc, ifp, m, 0, dst->sa_family);
		if (m == NULL) {
			/* m_pullup() freed the chain. */
			NET_EPOCH_EXIT(et);
			return (ENOBUFS);
		}
	}
	error = sppp_output(ifp, m, dst, rt);
	NET_EPOCH_EXIT(et);
	return (error);
}

/*
 * The sppp lower-half callbacks.  sppp calls these from its own
 * taskqueue -- a sleepable context, and WITHOUT sc_mtx held -- when LCP
 * decides the lower link is required (pp_tls) or no longer is (pp_tlf),
 * so discovery is driven by the PPP layer: `ifconfig pppoe0 up` opens
 * LCP, LCP asks for the link, pppoe_tls() starts PADI.  The reverse
 * chain (`ifconfig pppoe0 down`) closes LCP, and pppoe_tlf() tears the
 * session down and stops discovery unless the administrative state
 * (IFF_UP) says the caller wants to keep re-dialling -- M001's PADT
 * auto-reconnect semantics (POE_RECON_PADTRCVD) must survive a
 * This-Layer-Down that followed a lost session.
 */
static void
pppoe_tls(struct sppp *sp)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	PPPOE_SC_LOCK(sc);
	/* Recorded even when connect fails for want of a parent: see setparms. */
	sc->sc_link_wanted = true;
	if (!sc->sc_detaching && sc->sc_state == PPPOE_STATE_INITIAL)
		(void)pppoe_connect(sc);
	PPPOE_SC_UNLOCK(sc);
}

static void
pppoe_tlf(struct sppp *sp)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	PPPOE_SC_LOCK(sc);
	sc->sc_link_wanted = false;
	if (sc->sc_detaching)
		goto out;
	if ((if_getflags(sc->sc_ifp) & IFF_UP) == 0)
		callout_stop(&sc->sc_timeout);
	/* Session still up: send PADT; otherwise a stateless no-op. */
	pppoe_disconnect(sc);
out:
	PPPOE_SC_UNLOCK(sc);
}

/*
 * The session transmit path (spec section 7).
 *
 * The mbuf arrives with the 2-byte PPP protocol field at the front -- exactly
 * the layout pppoe_sess_input() leaves behind on receive -- and 6 bytes of
 * PPPoE header plus 14 of Ethernet go on in front of it.  Out via
 * ether_output_frame() (sys/net/ethernet.h:448, sys/net/if_ethersubr.c:474)
 * rather than the parent's if_transmit directly, so the parent's VLAN PCP
 * tagging (ether_do_pcp, :476) and the outbound Ethernet pfil chain (:479-484)
 * both still apply; it ends in the parent's if_transmit at :516.
 *
 * m_pkthdr.flowid and the RSS hash type are deliberately NOT saved and
 * restored around the M_PREPEND: M_PREPEND either moves m_data back inside
 * the same mbuf or calls m_prepend() (sys/kern/uipc_mbuf.c:503-523), which
 * hands the whole pkthdr over with `to->m_pkthdr = from->m_pkthdr`
 * (m_move_pkthdr(), :451).  Both survive by construction.  That they survive
 * matters: iflib selects a parent TX queue only when M_HASHTYPE_GET(m) is
 * non-zero (sys/net/iflib.c:4321-4322), so losing the hash type here would
 * funnel every session frame onto the parent's TX queue 0.
 *
 * Locking: none (T1/T2).  The softc is kept alive by the net epoch (see
 * pppoe_output()), and everything the frame needs -- parent, peer, session
 * id, payload bound, even the parent's MAC -- comes from the session's
 * immutable transmit snapshot (struct pppoe_tx_snap), loaded once with an
 * acquire load.  The old per-packet sc_mtx round trip to copy four fields
 * is gone, and so is the if_addr read (pppoe_lladdr_copy()) per packet.
 * Spec section 9's do-not-port list names PPPOE_LOCK held across NetBSD's
 * pppoe_transmit() (if_pppoe.c:2038-2060); this takes no lock at all.  The
 * snapshot's parent is safe to hand to ether_output_frame() for the whole
 * section: see pppoe_tx_snap_publish().
 *
 * Callers must have curvnet set, as pppoe_send_padt() does: V_pppoe_stats and
 * ether_output_frame()'s V_link_pfil_head (if_ethersubr.c:479) are both
 * per-vnet.  Both callers do -- if_transmit from the stack, and the RX hook.
 */
static int
pppoe_encap_output(struct pppoe_softc *sc, if_t ifp, struct mbuf *m,
    const uint16_t *proto)
{
	const struct pppoe_tx_snap *ts;
	uint8_t *p;
	int error, hdrlen, len;

	NET_EPOCH_ASSERT();
	/*
	 * proto != NULL (T4): the data path, from sppp_output() via
	 * pppoe_xmit_proto(), with the PPP protocol field NOT yet on the
	 * mbuf.  It goes on here with the rest of the header -- ONE 22-byte
	 * M_PREPEND instead of sppp's 2 then our 20, which cost a second
	 * leading-space check, and a second mbuf when the first prepend used
	 * up the space the stack left.  proto == NULL: if_transmit's frames,
	 * which already carry it.  Either way len is the PPPoE payload
	 * length, protocol field included.
	 */
	hdrlen = ETHER_HDR_LEN + PPPOE_HEADERLEN;
	len = m->m_pkthdr.len;
	if (proto != NULL) {
		hdrlen += sizeof(*proto);
		len += sizeof(*proto);
	}
	ts = (const struct pppoe_tx_snap *)atomic_load_acq_ptr(
	    (volatile uintptr_t *)&sc->sc_txsnap);
	if (ts == NULL) {
		/* No session (or it is being torn down). */
		error = ENETDOWN;
		goto drop;
	}
	if (len > ts->ts_maxlen) {
		error = EMSGSIZE;
		goto drop;
	}
	if (!pppoe_parent_can_tx(ts->ts_parent, false)) {
		counter_u64_add(V_pppoe_stats.tx_parent_down, 1);
		error = ENETDOWN;
		goto drop;
	}

	pppoe_bpf_tap(ifp, m, proto);

	M_PREPEND(m, hdrlen, M_NOWAIT);
	if (m == NULL) {
		/* M_PREPEND freed the chain on failure (uipc_mbuf.c:511-514). */
		counter_u64_add(V_pppoe_stats.nomem, 1);
		error = ENOBUFS;
		goto fail;
	}
	p = mtod(m, uint8_t *);
	memcpy(p, ts->ts_hdr, sizeof(ts->ts_hdr));
	be16enc(p + sizeof(ts->ts_hdr), len);	/* PPPoE length */
	if (proto != NULL)
		memcpy(p + ETHER_HDR_LEN + PPPOE_HEADERLEN, proto,
		    sizeof(*proto));

	error = ether_output_frame(ts->ts_parent, m);
	if (error != 0) {
		/* The refusing layer already freed the mbuf; see
		 * pppoe_output_frame(). */
		goto fail;
	}
	counter_u64_add(V_pppoe_stats.tx_frames, 1);
	if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
	/*
	 * OBYTES is the PPPoE payload length, as IBYTES is on receive, and
	 * this is its only charge (SPPP_LOWER_COUNTS_BYTES).
	 */
	if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
	return (0);

drop:
	m_freem(m);
fail:
	counter_u64_add(V_pppoe_stats.tx_errors, 1);
	if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
	return (error);
}

/*
 * if_transmit: frames that already carry the 2-byte PPP protocol field --
 * sppp's control protocols (sppp_cp_send() and the auth senders, from its
 * taskqueue) and the net.pppoe.reflect test hook.
 */
static int
pppoe_transmit(if_t ifp, struct mbuf *m)
{
	struct epoch_tracker et;
	struct pppoe_softc *sc;
	int error;

	if (m == NULL)
		return (EINVAL);
	/* Softc lifetime: the net epoch (T1, see pppoe_output()). */
	NET_EPOCH_ENTER(et);
	sc = atomic_load_ptr(&ifp->if_softc);
	if (sc == NULL) {
		/* Destroy has taken the softc; the ifp is on its way out. */
		NET_EPOCH_EXIT(et);
		m_freem(m);
		return (EINVAL);
	}
	error = pppoe_encap_output(sc, ifp, m, NULL);
	NET_EPOCH_EXIT(et);
	return (error);
}

/*
 * sppp's pp_xmit_proto hook (T4): IP from sppp_output(), which pppoe_output()
 * called inside the net epoch with the softc loaded, so the softc behind sp
 * is live for the whole call.  proto is in network order.
 */
static int
pppoe_xmit_proto(struct sppp *sp, struct mbuf *m, uint16_t proto)
{
	struct pppoe_softc *sc = PPPOE_SPPP2SC(sp);

	return (pppoe_encap_output(sc, sc->sc_ifp, m, &proto));
}

/*
 * No IFQ and no if_start: pppoe_transmit() hands each frame straight to the
 * parent, so there is never anything of ours queued to flush.  It still has to
 * be non-NULL: if_down() calls it unconditionally (sys/net/if.c:2175), and
 * if_attach_internal() KASSERTs that if_transmit and if_qflush are set or
 * cleared together (:851-857).  The stack's own if_qflush() (:2204) would drain
 * ifp->if_snd, which this driver never puts anything on.
 */
static void
pppoe_qflush(if_t ifp __unused)
{

}

static int
pppoe_clone_create(struct if_clone *ifc __unused, char *name __unused,
    size_t len __unused, struct ifc_data *ifd, struct ifnet **ifpp)
{
	struct pppoe_softc *sc;
	struct ifnet *ifp;

	/* sc_txsnap is __aligned(CACHE_LINE_SIZE): see if_pppoe_var.h. */
	sc = malloc_aligned(sizeof(*sc), CACHE_LINE_SIZE, M_PPPOE,
	    M_WAITOK | M_ZERO);
	mtx_init(&sc->sc_mtx, "pppoe softc", NULL, MTX_DEF);
	/* The interface owns ref 1; pppoe_clone_destroy() drops it at teardown. */
	refcount_init(&sc->sc_refs, 1);
	callout_init_mtx(&sc->sc_timeout, &sc->sc_mtx, 0);
	TASK_INIT(&sc->sc_session_task, 0, pppoe_session_task, sc);
	TASK_INIT(&sc->sc_addr_task, 0, pppoe_addr_apply, sc);
	TASK_INIT(&sc->sc_mtu_task, 0, pppoe_mtu_task, sc);
	sc->sc_state = PPPOE_STATE_INITIAL;
	pppoe_hunique_new(sc);
	memset(&sc->sc_dest, 0xff, sizeof(sc->sc_dest));	/* broadcast */

	ifp = if_alloc(IFT_PPP);
	sc->sc_ifp = ifp;
	if_initname(ifp, "pppoe", ifd->unit);
	if_setsoftc(ifp, sc);
	/*
	 * The softc-embed contract (docs/PORTING-sppp.md): sppp_from_ifp()
	 * reads this slot, so it must be set before sppp_attach() (which
	 * calls sppp_from_ifp() itself) and before any frame can reach the
	 * softc.  sc->ppp.pp_if is the vendored back-pointer every
	 * `sp->pp_if` site resolves through.
	 */
	if_setllsoftc(ifp, &sc->ppp);
	sc->ppp.pp_if = ifp;
	/* Before if_attach(): not yet pppoe_mtu_update()'s, nothing to tell. */
	sc->sc_mtu_link = PPPOE_MAXMTU;
	if_setmtu(ifp, PPPOE_MAXMTU);
	if_setflags(ifp, IFF_SIMPLEX | IFF_POINTOPOINT | IFF_MULTICAST);
	if_setioctlfn(ifp, pppoe_ioctl);
	if_settransmitfn(ifp, pppoe_transmit);
	if_setqflushfn(ifp, pppoe_qflush);
	/*
	 * No offload capabilities are advertised (spec section 4): the parent
	 * NIC commonly has none enabled and a forwarding router never takes
	 * in_delayed_cksum() anyway.
	 */
	/*
	 * Wire the PPP state machine BEFORE if_attach() publishes the ifnet:
	 * from that point on the stack can call if_output and if_ioctl, and
	 * both lead into sppp.  sppp_attach() takes over if_output
	 * (sppp_output prepends the 2-byte PPP protocol field pppoe_transmit()
	 * expects) and fills pp_up/pp_down; this driver fills the tls/tlf half
	 * and the device flags PPPoE needs (no serial framing, LCP keepalive)
	 * plus the one-prepend IP transmit hook (T4), then puts its own
	 * epoch-guarded pppoe_output() in front of sppp's.
	 *
	 * sppp_attach() also calls if_link_state_change(LINK_STATE_DOWN),
	 * which would enqueue if_linktask for an ifnet that is not attached
	 * yet.  Start the link state at DOWN so that call is a no-op (it
	 * returns early on an unchanged state); DOWN is where the old
	 * post-attach if_link_state_change() left it anyway.
	 */
	ifp->if_link_state = LINK_STATE_DOWN;
	sppp_attach(ifp);
	sc->ppp.pp_tls = pppoe_tls;
	sc->ppp.pp_tlf = pppoe_tlf;
	sc->ppp.pp_xmit_proto = pppoe_xmit_proto;
	sc->ppp.pp_framebytes = PPPOE_HEADERLEN;
	SET(sc->ppp.pp_dev_flags,
	    (PP_DEVF_KEEPALIVE |	/* use LCP keepalive */
	     PP_DEVF_NOFRAMING));	/* no serial encapsulation */
	if_setoutputfn(ifp, pppoe_output);
	if_attach(ifp);
	bpfattach(ifp, DLT_PPP, PPP_HDRLEN);	/* see pppoe_bpf_tap() */

	/*
	 * Publish to the per-vnet softc list last: pppoe_find_by_hunique() walks
	 * it from the RX hook with no lock, so the softc must be fully built and
	 * attached before a discovery frame can reach it.
	 */
	sx_xlock(&pppoe_parents_lock);
	CK_LIST_INSERT_HEAD(&V_pppoe_softcs, sc, sc_all);
	sc->sc_listed = true;
	sx_xunlock(&pppoe_parents_lock);

	*ifpp = ifp;
	return (0);
}

static int
pppoe_clone_destroy(struct if_clone *ifc __unused, struct ifnet *ifp,
    uint32_t flags __unused)
{
	struct pppoe_softc *sc = if_getsoftc(ifp);
	if_t old;

	/*
	 * ifioctl() holds only its own ifunit_ref() on ifp, so a PPPOESETPARMS
	 * can be inside pppoe_ioctl_setparms() right now.  sc_detaching (set
	 * and tested under sc_mtx) makes a NEW ioctl back out rather than
	 * store a parent into a softc that is going away, and sc_parent is
	 * lifted under the same lock so only one of the two paths ever
	 * releases it.
	 *
	 * An ioctl already blocked on sc_mtx is safe because every ioctl took
	 * a pppoe_softc_hold() before touching the softc, and every transmit
	 * runs inside the net epoch; this function NET_EPOCH_WAIT()s and waits
	 * for sc_refs to drain before it tears anything down that either could
	 * reach (see below; M001/S03 review finding I2, decision D012).
	 * ifunit_ref() pins the ifp, not the softc.
	 */
	PPPOE_SC_LOCK(sc);
	sc->sc_detaching = true;
	callout_stop(&sc->sc_timeout);
	/*
	 * Tell the AC the session is gone before the parent goes away -- an
	 * ISP that never sees a PADT holds the session open and refuses the
	 * re-connect (spec section 11).  sc_detaching and the callout_stop()
	 * above must precede it: pppoe_disconnect() drops sc_mtx around the
	 * transmit, and in that window a PPPOESETPARMS would otherwise swap
	 * sc_parent out from under us instead of backing out with ENXIO, and
	 * an already-running pppoe_timeout() would re-arm instead of returning.
	 */
	pppoe_disconnect(sc);
	old = sc->sc_parent;
	sc->sc_parent = NULL;
	PPPOE_SC_UNLOCK(sc);
	callout_drain(&sc->sc_timeout);

	/*
	 * Unpublish only now, with sc_detaching set and the parent lifted:
	 * until then a pppoe_parent_departed() racing us for the same parent
	 * must still find this softc on V_pppoe_softcs, or it would skip its
	 * NET_EPOCH_WAIT() and let the parent's link address go while our
	 * PADT (or a transmit holder that still sees the old sc_parent) is
	 * using it.  Staying listed a little longer is harmless: discovery
	 * backs out on sc_detaching.  A walker already inside
	 * pppoe_find_by_hunique() stays safe: CK_LIST_REMOVE leaves our
	 * forward pointer intact and the softc free below is
	 * NET_EPOCH_CALL()'d.  A softc caught between an if_vmove()'s
	 * departure and arrival is on no list; clearing sc_vmoving keeps
	 * pppoe_ifattach() from re-linking it.
	 */
	sx_xlock(&pppoe_parents_lock);
	if (sc->sc_listed)
		CK_LIST_REMOVE(sc, sc_all);
	sc->sc_listed = false;
	sc->sc_vmoving = false;
	sx_xunlock(&pppoe_parents_lock);
	/*
	 * pppoe_disconnect() above was the last thing that could enqueue this:
	 * sc_detaching makes pppoe_disc_input() back out before the FSM arms,
	 * and nothing can re-enter PPPOE_STATE_SESSION once it has cleared.
	 * Drain, then make sure the table really is clear of a softc that is
	 * about to be freed -- the unpublish belongs here or in the task, never
	 * in the epoch callback, which runs with no curvnet (Task 13).
	 */
	taskqueue_drain(pppoe_taskq, &sc->sc_session_task);
	sx_xlock(&pppoe_parents_lock);
	if (sc->sc_in_hash) {
		CK_LIST_REMOVE(sc, sc_hash);
		sc->sc_in_hash = false;
	}
	sx_xunlock(&pppoe_parents_lock);

	/* Neither pppoe_parent_del() (sx) nor if_rele() may run under sc_mtx. */
	if (old != NULL) {
		pppoe_parent_del(old);
		if_rele(old);
	}

	/*
	 * Unpublish the softc, then wait out everyone who can still reach it
	 * through the ifnet, BEFORE the PPP state machine goes: the ifnet
	 * stays attached until if_detach() below, and pppoe_output(),
	 * pppoe_ioctl(), pppoe_transmit() and pppoe_data_input() all resolve
	 * the softc from it.  sppp_detach() frees the sppp workqueue, so any
	 * of them reaching sppp_output()/sppp_ioctl()/sppp_input() after it
	 * is a use-after-free.
	 *
	 * The NULL store is the point of no return for pppoe_softc_hold()
	 * and for the per-packet loads: every later one bails out.
	 * NET_EPOCH_WAIT() then drains pppoe_output(), pppoe_transmit() and
	 * pppoe_data_input(), which load if_softc inside the epoch rather
	 * than taking a hold (no per-packet lock, T1), along with any
	 * pppoe_sess_input() that found the softc in the session table
	 * before the unhash above.  Last, the holds taken before the store
	 * drain: each holder releases exactly once and none can drop sc_refs
	 * below the interface's own ref, so sc_refs == 1 means none is left.
	 * This polls rather than sleeping on a wakeup from
	 * pppoe_softc_rele(): a releaser must not touch the softc after its
	 * decrement (the destroy may already be past this loop), and taking
	 * pppoe_sc_hold_lock around every release would put a second global
	 * lock on the ioctl path.  Holders are one ioctl or one event handler
	 * long, so the loop rarely turns.
	 */
	mtx_lock(&pppoe_sc_hold_lock);
	atomic_store_ptr(&ifp->if_softc, NULL);
	mtx_unlock(&pppoe_sc_hold_lock);
	NET_EPOCH_WAIT();
	while (atomic_load_acq_int(&sc->sc_refs) > 1)
		pause("pppoedt", 1);

	/*
	 * Tear the PPP state machine down (M001 teardown ruling #1).
	 * sppp_detach() removes the interface from the keepalive list, waits
	 * out every pending work item (sppp_cp_fini's sppp_wq_wait() per CP)
	 * and drains the taskqueue before destroying the per-interface
	 * workqueue -- including any work queued by the pp_down() the
	 * session-task drain above delivered, or by an ioctl that held the
	 * softc until just now.  It leaves pp_lock alive for the address
	 * task below; pppoe_softc_free() destroys it.
	 */
	sppp_detach(ifp);

	/*
	 * sppp_detach() above waited out every IPCP work item, so any
	 * pppoe_set_ip_addrs()/pppoe_clear_ip_addrs() enqueued by the tlu/tld
	 * handlers has already run past our enqueue point, and nothing can
	 * enqueue it again.  Drain the address task itself so no
	 * pppoe_addr_apply() can still be mid-in_control_ioctl() on this
	 * softc, or holding pp_lock, once the ifnet goes.
	 */
	taskqueue_drain(pppoe_taskq, &sc->sc_addr_task);
	/*
	 * Its enqueuers are gone too: the LCP tlu/tld (sppp_detach() above),
	 * the ioctls (sc_refs) and the PADS arm (the NET_EPOCH_WAIT()).
	 */
	taskqueue_drain(pppoe_taskq, &sc->sc_mtu_task);

	bpfdetach(ifp);
	/*
	 * if_detach() sends no second PADT and cannot reach the softc: its
	 * if_down() (sys/net/if.c:2169-2182) never calls ifp->if_ioctl, and
	 * the multicast purge's SIOCDELMULTI lands in pppoe_ioctl(), which
	 * finds if_softc NULL and returns ENXIO.
	 *
	 * No netisr drain is needed before if_free(), although frames for
	 * this ifnet can still sit in another CPU's NETISR_PPPOE_DATA
	 * workstream (POLICY_CPU + HYBRID queues them outside any epoch
	 * section).  Enqueue does not keep the rcvif pointer: it swaps it for
	 * the ifnet's index and generation (m_rcvif_serialize(), netisr.c:997),
	 * and swi_net resolves them back with m_rcvif_restore() inside its
	 * epoch section, freeing the frame if the lookup fails (netisr.c:922-925,
	 * verified against the 14.x tree).  So a queued frame either resolves
	 * while the ifnet is still indexed -- and pppoe_data_input() finds
	 * if_softc NULL and drops it, with if_destroy() NET_EPOCH_CALL()'d
	 * past its epoch section -- or
	 * fails to resolve once if_free() has dropped the index and never
	 * reaches the handler; the generation stops a reused index resolving
	 * to a newer ifnet.
	 */
	if_detach(ifp);
	if_free(ifp);
	/*
	 * The interface's own ref.  Every other hold is gone (the wait
	 * above), so this is the last release and schedules the sole
	 * pppoe_softc_free(); it stays NET_EPOCH_CALL()'d so a discovery
	 * reader that found the softc on a list before the unpublish keeps
	 * its epoch-grace guarantee.
	 */
	if (refcount_release(&sc->sc_refs))
		NET_EPOCH_CALL(pppoe_softc_free, &sc->sc_epoch_ctx);
	return (0);
}

/*
 * ifnet_departure_event: a parent is going away.  if_detach_internal() posts
 * it for a real detach (a vlan destroyed, a NIC gone) and for if_vmove() out
 * of this vnet alike -- a vnet jail's interfaces going home when the jail
 * dies included -- and in both cases the parent's pointer stops being one
 * this softc may transmit on.  Without this a clone keeps its session and
 * its sc_parent across the departure: PADTs and session frames go to a
 * detached (or foreign-vnet) ifnet, and the parent set pins it.
 *
 * Each bound softc gets a best-effort PADT on the departing ifnet first,
 * but only while its driver still reports IFF_DRV_RUNNING -- the driver's
 * own "I accept transmits" bit -- since this runs inside if_detach_internal()
 * and a NIC mid-detach need not tolerate one.  On an if_vmove() -- jail -r
 * handing an epair or a NIC back to its home vnet -- the ifnet has only been
 * unlinked and if_down()'d, which clears IFF_UP but never tells the driver,
 * so it still runs and transmits.  Every departure is if_down()'d first, so
 * the PADT goes through pppoe_send_padt_departing(), which ignores IFF_UP
 * (pppoe_parent_can_tx()).  A vlan being destroyed is still configured
 * on its trunk during ether_ifdetach() (vlan_clone_destroy() unconfigures it
 * afterwards); a NIC detach normally stops the device first, clearing
 * IFF_DRV_RUNNING, and gets no PADT.  (sys/net/if.c, if_vlan.c and iflib
 * ordering assumed for 14.3, not read against its tree.)  An AC that never
 * hears the session end holds it until its own LCP echo gives up (spec
 * section 11: the ISP refuses the re-connect).  The session is then cleared
 * and its link-down latched as for a local shutdown, and the clone stays at
 * INITIAL with no parent.  A PPPOESETPARMS binding a new one (legal at
 * INITIAL) redials straight away if LCP still wants the link, which it does
 * when the interface is still up (sc_link_wanted).
 *
 * The walk restarts after each softc because the PADT and the parent-set
 * and ifnet releases all need both locks dropped (the transmit must not run
 * under sc_mtx; pppoe_parent_del() takes the sx itself); the softc's own
 * if_ref keeps the ifnet valid until our if_rele().  Each pass clears one
 * sc_parent, so the loop ends.  A destroying clone stays on V_pppoe_softcs
 * until it has lifted its own sc_parent, so this walk still sees it (and
 * still waits for its PADT, below) -- both paths lift sc_parent under sc_mtx,
 * so only one ever releases it.
 *
 * V_pppoe_depart_gen closes the race with a concurrent PPPOESETPARMS:
 * if_detach() unlinks the ifnet before it posts this event, so a setparms
 * whose ifunit_ref() won that race would otherwise bind the parent after
 * this walk found nothing.  It is bumped under pppoe_parents_lock before the
 * walk; setparms samples it before its lookup and re-validates the parent,
 * under the same lock as the store, if it moved.
 */
VNET_DEFINE_STATIC(u_int, pppoe_depart_gen);
#define	V_pppoe_depart_gen	VNET(pppoe_depart_gen)

static eventhandler_tag pppoe_ifdetach_tag;
static eventhandler_tag pppoe_ifattach_tag;

/* One of our own pppoeN clones (IFT_PPP alone would also match ppp/sppp). */
static bool
pppoe_ifp_is_ours(struct ifnet *ifp)
{

	return (if_gettype(ifp) == IFT_PPP && ifp->if_ioctl == pppoe_ioctl);
}

static void
pppoe_parent_departed(struct ifnet *ifp)
{
	struct epoch_tracker et;
	struct ether_addr peer;
	struct pppoe_softc *sc;
	uint16_t session;
	bool cleared = false;

	sx_xlock(&pppoe_parents_lock);
	V_pppoe_depart_gen++;
	for (;;) {
		CK_LIST_FOREACH(sc, &V_pppoe_softcs, sc_all) {
			PPPOE_SC_LOCK(sc);
			if (sc->sc_parent == ifp)
				break;
			PPPOE_SC_UNLOCK(sc);
		}
		if (sc == NULL)
			break;
		/* sc_mtx is held for the softc the walk stopped on. */
		log(LOG_NOTICE, "%s: parent %s departed\n",
		    if_name(sc->sc_ifp), if_name(ifp));
		callout_stop(&sc->sc_timeout);
		session = 0;
		if (sc->sc_state == PPPOE_STATE_SESSION) {
			session = sc->sc_session;
			peer = sc->sc_dest;
			taskqueue_enqueue(pppoe_taskq,
			    &sc->sc_session_task);
		}
		pppoe_clear_softc(sc, "parent departed");
		sc->sc_parent = NULL;
		cleared = true;
		PPPOE_SC_UNLOCK(sc);
		sx_xunlock(&pppoe_parents_lock);
		/*
		 * pppoe_send_padt_departing() re-checks IFF_DRV_RUNNING;
		 * testing it here too keeps a stopped NIC's detach out of
		 * tx_parent_down and tx_errors.
		 */
		if (session != 0 &&
		    (if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0) {
			NET_EPOCH_ENTER(et);
			(void)pppoe_send_padt_departing(ifp, session, &peer);
			NET_EPOCH_EXIT(et);
		}
		pppoe_parent_del(ifp);
		if_rele(ifp);
		sx_xlock(&pppoe_parents_lock);
	}
	sx_xunlock(&pppoe_parents_lock);
	/*
	 * pppoe_transmit() and pppoe_seed_ip6_ifid() lift sc_parent under
	 * sc_mtx and use it inside the net epoch after dropping the lock.
	 * if_detach_internal() removes and frees the departing ifnet's link
	 * address right after this event returns (assumed from 14.3's
	 * sys/net/if.c ordering: ifnet_departure_event, then the !vmove
	 * if_addr teardown), so let every such user leave first.
	 */
	if (cleared)
		NET_EPOCH_WAIT();
}

/*
 * One of our own clones leaving its vnet: `ifconfig pppoeN vnet <jail>`, or
 * jail -r returning one that was moved in.  Everything this softc is a
 * member of is per-vnet -- the session hash, V_pppoe_softcs, the parent set
 * -- and its parent (an ifnet of the vnet it is leaving) cannot follow it.
 * So hang up (PADT on the parent, which is still here), drop the parent and
 * leave the session hash here, and unlink from V_pppoe_softcs; the arrival
 * that follows in the destination vnet re-links it there (pppoe_ifattach()),
 * where it waits at INITIAL for a PPPOESETPARMS naming a parent of that vnet.
 * Left alone, the session task and clone destroy would both edit the wrong
 * vnet's tables once if_vnet had moved, and a softc still linked into a
 * jail's V_pppoe_softcs would point into freed vnet memory once the jail
 * died.
 *
 * pppoe_clone_destroy()'s own if_detach() also lands here, after it cleared
 * if_softc: the hold then fails and there is nothing to do.
 */
static void
pppoe_vmove_out(struct ifnet *ifp)
{
	struct pppoe_softc *sc;
	if_t old;

	sc = pppoe_softc_hold(ifp);
	if (sc == NULL)
		return;
	PPPOE_SC_LOCK(sc);
	callout_stop(&sc->sc_timeout);
	/* Drops sc_mtx around the PADT transmit. */
	pppoe_disconnect(sc);
	old = sc->sc_parent;
	sc->sc_parent = NULL;
	PPPOE_SC_UNLOCK(sc);
	sx_xlock(&pppoe_parents_lock);
	if (sc->sc_in_hash) {
		CK_LIST_REMOVE(sc, sc_hash);
		sc->sc_in_hash = false;
	}
	if (sc->sc_listed) {
		CK_LIST_REMOVE(sc, sc_all);
		sc->sc_listed = false;
		sc->sc_vmoving = true;
	}
	sx_xunlock(&pppoe_parents_lock);
	/*
	 * And off this vnet's sppp keepalive list, which would otherwise
	 * keep echoing on the moved interface under this vnet's curvnet
	 * (and keep a pointer to it after a destroy from the other vnet).
	 */
	sppp_vnet_move(ifp, NULL);
	if (old != NULL) {
		pppoe_parent_del(old);
		if_rele(old);
	}
	log(LOG_NOTICE, "%s: leaving its vnet, session and parent dropped\n",
	    if_name(ifp));
	pppoe_softc_rele(sc);
}

static void
pppoe_ifdetach(void *arg __unused, struct ifnet *ifp)
{

	/* A rename posts a departure too, but the ifnet stays put. */
	if ((if_getflags(ifp) & IFF_RENAMING) != 0)
		return;
	CURVNET_SET_QUIET(if_getvnet(ifp));
	if (pppoe_ifp_is_ours(ifp))
		pppoe_vmove_out(ifp);
	else if (if_gettype(ifp) == IFT_ETHER ||
	    if_gettype(ifp) == IFT_L2VLAN)
		pppoe_parent_departed(ifp);
	CURVNET_RESTORE();
}

/*
 * ifnet_arrival_event: the second half of pppoe_vmove_out().  if_vmove()
 * re-attaches the ifnet in the destination vnet, with if_vnet already
 * pointing there, and posts this (assumed for 14.3's if_attach_internal(),
 * not read against its tree -- if it did not, the softc would stay on no
 * list: unreachable for discovery, but safe).  Every clone create posts it
 * too, from if_attach(), before the create links the softc itself;
 * sc_vmoving is false then.
 *
 * The NET_EPOCH_WAIT() comes first because relinking rewrites sc_all's
 * forward pointer: a pppoe_find_by_hunique() still walking the old vnet's
 * list through this softc must be gone before it would follow that pointer
 * into another vnet's list.
 */
static void
pppoe_ifattach(void *arg __unused, struct ifnet *ifp)
{
	struct pppoe_softc *sc;
	bool moving;

	if (!pppoe_ifp_is_ours(ifp))
		return;
	sc = pppoe_softc_hold(ifp);
	if (sc == NULL)
		return;
	sx_xlock(&pppoe_parents_lock);
	moving = sc->sc_vmoving;
	sx_xunlock(&pppoe_parents_lock);
	if (moving) {
		NET_EPOCH_WAIT();
		CURVNET_SET_QUIET(if_getvnet(ifp));
		sx_xlock(&pppoe_parents_lock);
		/* A destroy may have claimed the softc meanwhile. */
		moving = sc->sc_vmoving;
		if (moving) {
			CK_LIST_INSERT_HEAD(&V_pppoe_softcs, sc, sc_all);
			sc->sc_listed = true;
			sc->sc_vmoving = false;
		}
		sx_xunlock(&pppoe_parents_lock);
		/*
		 * Onto this vnet's keepalive list.  Our hold keeps the destroy
		 * (and its sppp_detach()) waiting until we are done.
		 */
		if (moving)
			sppp_vnet_move(ifp, curvnet);
		CURVNET_RESTORE();
	}
	pppoe_softc_rele(sc);
}

static void
pppoe_vnet_init(const void *unused __unused)
{
	struct if_clone_addreq req = {
		.flags = IFC_F_AUTOUNIT,
		.create_f = pppoe_clone_create,
		.destroy_f = pppoe_clone_destroy,
	};

	/*
	 * MOD_LOAD failed (see pppoe_modevent()), yet the file's other
	 * SYSINITs, this one in every vnet, still run before the file is
	 * unloaded: by linker_load_file() at kldload (kern_linker.c:480,
	 * :488), by linker_preload_finish() at boot (:1815-1818).  Attach
	 * nothing that could enqueue on a taskqueue that does not exist.
	 */
	if (pppoe_taskq == NULL)
		return;
	pppoe_stats_init();
	pppoe_cpu_hits_init();
	/*
	 * vnet0's registration is netisr_register()'s own doing
	 * (netisr.c:464-468); every other vnet enables the protocol for itself.
	 * Both counter sets are up before this, and the pfil hook -- the only
	 * thing that can dispatch -- goes on after it.
	 */
	if (!IS_DEFAULT_VNET(curvnet))
		netisr_register_vnet(&pppoe_nh);
	pppoe_pfil_attach();
	V_pppoe_cloner = ifc_attach_cloner("pppoe", &req);
	if (V_pppoe_cloner == NULL) {
		printf("pppoe: ifc_attach_cloner failed\n");
		return;
	}
}

/*
 * SI_SUB_PROTO_IF, SI_ORDER_ANY: pppoe_pfil_attach() links to
 * V_link_pfil_head, which vnet_ether_init() registers at SI_SUB_PROTO_IF,
 * SI_ORDER_ANY (if_ethersubr.c:795, OPNsense 25.7).  At SI_SUB_PSEUDO this
 * ran first in every vnet created after kldload, and in vnet0 when the
 * module is preloaded at boot, so pfil_link() saw a NULL head, failed with
 * ENOENT (pfil.c:391-405) and that vnet's sessions were never taken.
 * Equal keys keep the kernel's constructor first: vnet_register_sysinit()
 * inserts after entries with the same key (vnet.c:490-499), and at boot
 * linker_preload()'s sysinit_add() (kern_linker.c:1783) merges a module's
 * SYSINITs after the kernel's equal ones (init_main.c:219-223,
 * queue_mergesort.h:70-74).  sppp's keepalive constructor (SI_SUB_PSEUDO)
 * runs before this one, and MOD_LOAD (SI_SUB_PSEUDO) has registered the
 * netisr handler.
 */
VNET_SYSINIT(pppoe_vnet_init, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    pppoe_vnet_init, NULL);

/*
 * Clones still on this vnet's V_pppoe_softcs once its own cloner has
 * destroyed its own: clones created in another vnet and if_vmove()d in
 * (pppoe_ifattach() linked them here).  Their cloner is their home vnet's,
 * so ifc_detach_cloner() above never saw them, and on a kldunload with the
 * jail still alive the home vnet's detach may run only after this vnet's
 * per-vnet state below is freed -- vnet_deregister_sysuninit() runs each
 * VNET_SYSUNINIT across every vnet in list order, and which vnet comes
 * first is not ours to choose.  A destroy that late would count into freed
 * V_pppoe_stats.  So destroy them now, while this vnet is intact:
 * if_clone_destroy() finds the cloner through the ifnet's home vnet
 * (assumed for 14.3's sys/net/if_clone.c, not read against its tree) and
 * takes the clone off that cloner's list, so the home vnet's detach does
 * not see it again.  On a jail's own teardown this finds nothing: the
 * vnet_if_return() SYSUNINIT has already sent every guest home.
 */
static void
pppoe_vnet_destroy_guests(void)
{
	struct pppoe_softc *sc;
	char name[IFNAMSIZ];
	int error;

	for (;;) {
		sx_xlock(&pppoe_parents_lock);
		sc = CK_LIST_FIRST(&V_pppoe_softcs);
		if (sc != NULL)
			strlcpy(name, if_name(sc->sc_ifp), sizeof(name));
		sx_xunlock(&pppoe_parents_lock);
		if (sc == NULL)
			break;
		error = if_clone_destroy(name);
		if (error == 0)
			continue;
		/*
		 * A concurrent destroy or rename.  Do not spin: a softc still
		 * listed is still allocated (destroy unlists before freeing).
		 */
		printf("pppoe: cannot destroy %s leaving its vnet (%d)\n",
		    name, error);
		sx_xlock(&pppoe_parents_lock);
		if (CK_LIST_FIRST(&V_pppoe_softcs) == sc && sc->sc_listed) {
			CK_LIST_REMOVE(sc, sc_all);
			sc->sc_listed = false;
		}
		sx_xunlock(&pppoe_parents_lock);
	}
}

static void
pppoe_vnet_uninit(const void *unused __unused)
{

	/* pppoe_vnet_init() set nothing up: MOD_LOAD had failed. */
	if (pppoe_taskq == NULL)
		return;
	/*
	 * ifc_attach_cloner() can fail; ifc_detach_cloner() is a bare wrapper
	 * whose first act is LIST_REMOVE(ifc, ifc_list), so a NULL handle is a
	 * NULL dereference.  The drain below stays reachable either way.
	 */
	if (V_pppoe_cloner != NULL) {
		ifc_detach_cloner(V_pppoe_cloner);
		V_pppoe_cloner = NULL;
	}
	pppoe_vnet_destroy_guests();
	/*
	 * Unlink the hook before freeing what it accounts into, and make the
	 * unlink stick before the free: pfil_remove_hook() only epoch-defers
	 * the freeing of the pfil_link, it does not wait for in-flight callers
	 * (sys/net/pfil.c:487-502), so without this NET_EPOCH_WAIT() a
	 * pppoe_pfil_in() already running on another CPU would counter_u64_add()
	 * into per-CPU counters pppoe_stats_fini() had just freed (the Task 1
	 * spike hit exactly that shape).
	 */
	pppoe_pfil_detach();
	NET_EPOCH_WAIT();
	/*
	 * Only now that no pppoe_sess_input() can still be running is it safe
	 * to drain this vnet's netisr queues: netisr_unregister_vnet() clears
	 * V_netisr_enable and frees what is queued, but a dispatcher that had
	 * already passed the enable check could otherwise enqueue behind the
	 * drain.  The second wait then covers a handler that was already
	 * running on a frame dequeued before the drain.  (This ordering is the
	 * real work for vnet jail teardown, where the module stays loaded.  On
	 * kldunload MOD_UNLOAD has already swept every vnet's pfil hook
	 * (pppoe_vnet_pfil_sweep()) and run pppoe_netisr_unregister(), so the
	 * detach above is a no-op, and np_handler is already NULL -- which is
	 * why the call below must be skipped rather than merely being a no-op:
	 * netisr_unregister_vnet() asserts np_handler != NULL at netisr.c:766-767,
	 * which is a panic on the WITNESS/INVARIANTS kernel plan 3 builds.)
	 */
	if (!IS_DEFAULT_VNET(curvnet) && pppoe_netisr_registered)
		netisr_unregister_vnet(&pppoe_nh);
	NET_EPOCH_WAIT();
	pppoe_stats_fini();
	pppoe_cpu_hits_fini();
	/*
	 * ifc_detach_cloner() destroys any remaining clones, and each
	 * pppoe_clone_destroy() defers its softc free with NET_EPOCH_CALL().
	 * Those callbacks run from a gtaskqueue thread and would otherwise
	 * fire after kldunload(8) has freed this module's text.  Drain them
	 * here, as if_bridge.c:661 does for the same reason.
	 */
	NET_EPOCH_DRAIN_CALLBACKS();
}
/*
 * The same key as pppoe_vnet_init(), as if_tuntap.c:695/:711 pairs them.
 * vnet_sysuninit() walks the destructors in reverse (vnet.c:605-609), so
 * this now runs before vnet_ether_pfil_destroy() (SI_SUB_PROTO_PFIL,
 * if_ethersubr.c:805) frees the link pfil head the hook is on, and before
 * sppp_keepalive_vnet_uninit() (SI_SUB_PSEUDO) drains the keepalive
 * callout: the clones' sppp_detach() takes them off V_spppq first.  At
 * SI_SUB_PSEUDO/SI_ORDER_ANY, the key sppp's shares, the two ran in
 * whatever order their registrations landed.  The key is also that of
 * vnet_ether_destroy() (if_ethersubr.c:813-814); it registered first (see
 * pppoe_vnet_init()), so this runs before its netisr_unregister_vnet() of
 * ether's handler, which nothing here needs gone.
 */
VNET_SYSUNINIT(pppoe_vnet_uninit, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    pppoe_vnet_uninit, NULL);

/*
 * struct pppoediscparms carries userland pointers, so the service and AC names
 * move with copyinstr()/copyout().  Neither name is a secret; nothing in this
 * file ever logs a credential (Global Constraint).
 *
 * Both directions stage into kernel buffers OUTSIDE the softc mutex:
 * copyinstr()/copyout() may fault and malloc(M_WAITOK) may sleep, and
 * sc_mtx is an ordinary (non-sleepable) mutex.
 */
#define	PPPOE_MAX_NAMELEN	256

/*
 * `len` is the NetBSD ABI's *_name_len: strlen() of the string, NOT the size
 * of a buffer holding it.  pppoectl(8) sets `parms.service_name_len =
 * strlen(service)` with no +1 (NetBSD 5ee7eb6e, sbin/pppoectl/pppoectl.c), and
 * NetBSD's pppoe_parm_cpyinstr() allocates len + 1 and bounds copyinstr() by
 * that.  Using `len` directly as the copyinstr() bound would make copyinstr()
 * return ENAMETOOLONG for every non-empty name.  len == 0 is the empty string,
 * not an error.
 */
static int
pppoe_copyin_string(const char *user, size_t len, char **out)
{
	char *buf;
	size_t done, bufsiz;
	int error;

	*out = NULL;
	if (user == NULL)
		return (0);
	if (len > PPPOE_MAX_NAMELEN)
		return (EINVAL);
	bufsiz = len + 1;
	buf = malloc(bufsiz, M_PPPOE, M_WAITOK | M_ZERO);
	error = copyinstr(user, buf, bufsiz, &done);
	if (error != 0) {
		free(buf, M_PPPOE);
		return (error);
	}
	/*
	 * copyinstr() NUL-terminates within bufsiz; belt and braces.  NetBSD's
	 * stricter `cpysiz != bufsiz` check is deliberately NOT ported: it
	 * rejects a caller that passes a buffer size rather than a strlen().
	 */
	buf[bufsiz - 1] = '\0';
	*out = buf;
	return (0);
}

static int
pppoe_copyout_string(char *src, const char *user, size_t ulen)
{
	char *s = (src != NULL) ? src : "";
	size_t len;

	if (user == NULL || ulen == 0)
		return (0);
	len = strlen(s) + 1;
	if (len > ulen) {
		/*
		 * Truncate inside our own staging buffer rather than handing
		 * userland ulen bytes with no NUL on the end.  src == NULL
		 * cannot reach here: "" always fits a ulen >= 1 buffer.
		 */
		s[ulen - 1] = '\0';
		len = ulen;
	}
	return (copyout(s, __DECONST(void *, user), len));
}

/*
 * ALTQ detection on the parent (S03/T2).  The state is read config-
 * independently straight from the ALTQF_ENABLED bit (0x02) of the embedded
 * struct ifaltq: net/altq/if_altq.h is unconditional and altq_flags is 0 on
 * kernels built without ALTQ, so no #ifdef ALTQ is needed (and none may be
 * -- per-TU divergence in this kmod's struct layouts ODR-panicked loads in
 * M002).  The ALTQ_IS_ENABLED() macro is deliberately NOT used: it collapses
 * to literal 0 when ALTQ is not defined, i.e. in every kmod compile without
 * opt_altq.h -- a permanent false negative.  Likewise if_altq_is_enabled()
 * does not exist in sys/net/if_private.h on this tree (releng/14.3).
 *
 * altq_flags is read as a plain unlocked flags word: an advisory indicator
 * sampled at bind/session-start time, not a synchronised state machine --
 * altq_enable()/altq_disable() flip the bit under the queue lock, and a torn
 * read would at worst report one detection cycle stale.
 *
 * Caller must hold PPPOE_SC_LOCK (both detection points do: the tail of
 * pppoe_ioctl_setparms() and pppoe_connect()); that keeps the
 * sc_parent_altq_warned latch and the sc_parent read consistent.
 */
static void
pppoe_parent_altq_check(struct pppoe_softc *sc)
{
	if_t parent = sc->sc_parent;
	int altq;

	if (parent == NULL) {
		/* Nothing bound: the per-vnet indicator is trivially 0. */
		V_pppoe_parent_altq = 0;
		return;
	}
	altq = (parent->if_snd.altq_flags & ALTQF_ENABLED) != 0;
	if (altq) {
		V_pppoe_parent_altq = 1;
		if (!sc->sc_parent_altq_warned) {
			/*
			 * One-shot per softc: re-binds and re-dials would
			 * otherwise re-warn on every session start.
			 */
			sc->sc_parent_altq_warned = true;
			log(LOG_WARNING,
			    "%s: parent %s has ALTQ enabled -- iflib multi-queue "
			    "TX is disabled; shape on pppoeN/dummynet instead\n",
			    if_name(sc->sc_ifp), if_name(parent));
		}
	} else {
		/*
		 * Plain assignment, not a counted clear: a second clone bound
		 * to an ALTQ-free parent would unconditionally drop the flag
		 * even if another clone's parent still has ALTQ.  That is the
		 * honest OR-semantics reading for this driver's single-clone
		 * lab/router usage (one pppoeN per vnet); a multi-clone vnet
		 * with mixed parents would need per-clone bookkeeping that the
		 * advisory value does not justify.
		 */
		V_pppoe_parent_altq = 0;
	}
}

static int
pppoe_ioctl_setparms(struct pppoe_softc *sc, struct pppoediscparms *parms)
{
	if_t parent = NULL, old, now;
	char *svc, *acn, *old_svc, *old_acn;
	u_int gen = 0;
	int error;

	/* The whole struct came from userland: ifname fields may be unterminated. */
	parms->eth_ifname[sizeof(parms->eth_ifname) - 1] = '\0';

	error = pppoe_copyin_string(parms->service_name,
	    parms->service_name_len, &svc);
	if (error == 0)
		error = pppoe_copyin_string(parms->ac_name,
		    parms->ac_name_len, &acn);
	else
		acn = NULL;
	if (error != 0) {
		free(svc, M_PPPOE);
		return (error);
	}

	if (parms->eth_ifname[0] != '\0') {
		/* Before the lookup, or a departure could slip between: below. */
		gen = atomic_load_acq_int(&V_pppoe_depart_gen);
		parent = ifunit_ref(parms->eth_ifname);
		if (parent == NULL) {
			free(svc, M_PPPOE);
			free(acn, M_PPPOE);
			return (ENXIO);
		}
		if (if_gettype(parent) != IFT_ETHER &&
		    if_gettype(parent) != IFT_L2VLAN) {
			if_rele(parent);
			free(svc, M_PPPOE);
			free(acn, M_PPPOE);
			return (EINVAL);
		}
		error = pppoe_parent_add(parent);
		if (error != 0) {
			if_rele(parent);
			free(svc, M_PPPOE);
			free(acn, M_PPPOE);
			return (error);
		}
	}

	/*
	 * The parent store happens under pppoe_parents_lock as well as sc_mtx
	 * (the file's order: sx first), which serialises it with
	 * pppoe_parent_departed().  If a departure walk started since our
	 * sample, it may have been for this very parent and found nothing to
	 * clear yet: the parent must still be what its name resolves to in
	 * this vnet, or it is gone (ENXIO).  A departure that has not started
	 * yet will find the stored parent and clear it.  ifunit_ref() only
	 * enters the net epoch, which is fine under the sx.
	 */
	sx_xlock(&pppoe_parents_lock);
	if (parent != NULL && V_pppoe_depart_gen != gen) {
		now = ifunit_ref(parms->eth_ifname);
		if (now != parent)
			error = ENXIO;
		if (now != NULL)
			if_rele(now);
	}
	PPPOE_SC_LOCK(sc);
	/*
	 * pppoe_clone_destroy() may own the softc now (ENXIO).  Otherwise the
	 * parms may only change at INITIAL (EBUSY): swapping the parent under
	 * a session or a discovery exchange black-holes it -- frames keep
	 * leaving on the old session while the RX hook stops recognising it
	 * on the new parent.  `ifconfig pppoeN down` first.  Either way, undo
	 * our side.
	 */
	if (error == 0 && sc->sc_detaching)
		error = ENXIO;
	else if (error == 0 && sc->sc_state != PPPOE_STATE_INITIAL)
		error = EBUSY;
	if (error != 0) {
		PPPOE_SC_UNLOCK(sc);
		sx_xunlock(&pppoe_parents_lock);
		if (parent != NULL) {
			pppoe_parent_del(parent);
			if_rele(parent);
		}
		free(svc, M_PPPOE);
		free(acn, M_PPPOE);
		return (error);
	}
	old = sc->sc_parent;
	sc->sc_parent = parent;
	old_svc = sc->sc_service_name;
	sc->sc_service_name = svc;
	old_acn = sc->sc_ac_name;
	sc->sc_ac_name = acn;
	sx_xunlock(&pppoe_parents_lock);
	/*
	 * S03/T2 detection point 1: the parent (re-)bind just happened under
	 * this lock, so sample the new parent's ALTQ state here -- the sysctl
	 * must track re-binds, not just the first one.
	 */
	pppoe_parent_altq_check(sc);
	/*
	 * LCP is still waiting for a lower layer it asked for while there was
	 * no parent to dial on (the parent departed, or the interface came up
	 * unbound): start discovery now, as pppoe_tls() would have.  IFF_UP
	 * guards the window between `ifconfig down` and the pppoe_tlf() that
	 * clears sc_link_wanted.  pppoe_connect() drops sc_mtx around the
	 * PADI and re-validates.
	 */
	if (parent != NULL && sc->sc_link_wanted &&
	    (if_getflags(sc->sc_ifp) & IFF_UP) != 0)
		(void)pppoe_connect(sc);
	PPPOE_SC_UNLOCK(sc);

	free(old_svc, M_PPPOE);
	free(old_acn, M_PPPOE);
	if (old != NULL) {
		pppoe_parent_del(old);
		if_rele(old);
	}
	return (0);
}

static int
pppoe_ioctl_getparms(struct pppoe_softc *sc, struct pppoediscparms *parms)
{
	char *svc, *acn;
	int error;

	/*
	 * malloc(M_WAITOK) can sleep, so both staging buffers are allocated
	 * before the softc mutex is taken.  PPPOE_MAX_NAMELEN is the strlen()
	 * cap pppoe_copyin_string() enforces, so + 1 for the NUL always fits.
	 */
	svc = malloc(PPPOE_MAX_NAMELEN + 1, M_PPPOE, M_WAITOK | M_ZERO);
	acn = malloc(PPPOE_MAX_NAMELEN + 1, M_PPPOE, M_WAITOK | M_ZERO);

	PPPOE_SC_LOCK(sc);
	if (sc->sc_detaching) {
		/* pppoe_clone_destroy() owns the softc now; undo our side. */
		PPPOE_SC_UNLOCK(sc);
		free(svc, M_PPPOE);
		free(acn, M_PPPOE);
		return (ENXIO);
	}
	if (sc->sc_parent != NULL)
		strlcpy(parms->eth_ifname, if_name(sc->sc_parent),
		    sizeof(parms->eth_ifname));
	else
		parms->eth_ifname[0] = '\0';
	if (sc->sc_service_name != NULL)
		strlcpy(svc, sc->sc_service_name, PPPOE_MAX_NAMELEN + 1);
	if (sc->sc_ac_name != NULL)
		strlcpy(acn, sc->sc_ac_name, PPPOE_MAX_NAMELEN + 1);
	PPPOE_SC_UNLOCK(sc);

	/* copyout() may fault, so it must not run under the softc mutex. */
	error = pppoe_copyout_string(svc, parms->service_name,
	    parms->service_name_len);
	if (error == 0)
		error = pppoe_copyout_string(acn, parms->ac_name,
		    parms->ac_name_len);
	free(svc, M_PPPOE);
	free(acn, M_PPPOE);
	return (error);
}

static int
pppoe_ioctl_getsession(struct pppoe_softc *sc, struct pppoeconnectionstate *st)
{

	PPPOE_SC_LOCK(sc);
	if (sc->sc_detaching) {
		/* pppoe_clone_destroy() owns the softc now. */
		PPPOE_SC_UNLOCK(sc);
		return (ENXIO);
	}
	st->state = sc->sc_state;
	st->session_id = sc->sc_session;
	st->padi_retry_no = sc->sc_padi_retried;
	st->padr_retry_no = sc->sc_padr_retried;
	PPPOE_SC_UNLOCK(sc);
	return (0);
}

static int
pppoe_ioctl(if_t ifp, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct pppoe_softc *sc;
	int error = 0;

	/*
	 * Take the lifetime hold first: it is the only thing standing
	 * between a concurrent pppoe_clone_destroy() and free(sc) for the
	 * whole of this call.  A NULL here means destroy cleared
	 * ifp->if_softc, so the interface is gone; ifioctl() held its own
	 * ifunit_ref() to get here (M001/S03 review finding I2, D012).
	 */
	sc = pppoe_softc_hold(ifp);
	if (sc == NULL)
		return (ENXIO);

	switch (cmd) {
	case SIOCSIFFLAGS: {
		/*
		 * The local half: stop the discovery timers and clear any open
		 * session (PADT on the wire) when the administrator clears
		 * IFF_UP.  The plan-1 direct pppoe_connect() on IFF_UP is
		 * GONE: sppp_ioctl() below drives LCP open/close, which calls
		 * back into pppoe_tls()/pppoe_tlf() -- that is what starts
		 * discovery on `ifconfig pppoe0 up` and tears it down on
		 * `down`, one chained hop later than plan 1 (Task 3 Step 6).
		 */
		PPPOE_SC_LOCK(sc);
		if ((if_getflags(ifp) & IFF_UP) == 0) {
			callout_stop(&sc->sc_timeout);
			/* Drops sc_mtx around the PADT transmit. */
			pppoe_disconnect(sc);
		}
		PPPOE_SC_UNLOCK(sc);
#ifdef INET6
		pppoe_ip6_no_autoll(ifp);
#endif
		error = sppp_ioctl(ifp, cmd, data);
		break;
	}
	case SIOCSIFMTU: {
		int mtu = ifr->ifr_mtu;

		if (mtu < 68) {
			error = EINVAL;
			break;
		}
		PPPOE_SC_LOCK(sc);
		if (mtu > PPPOE_MAXMTU) {
			/*
			 * RFC 4638: only offer a bigger payload if the parent
			 * can actually carry it -- 8 bytes of PPPoE+PPP header
			 * sit in front of it inside the parent's MTU, so the
			 * parent needs at least mtu + PPPOE_OVERHEAD.  It must
			 * also still fit the 16-bit PPP-Max-Payload tag it is
			 * about to be advertised in.
			 *
			 * if_getmtu() is a plain if_mtu read (sys/net/if.c:
			 * 4473-4476), so it cannot sleep under sc_mtx.
			 */
			if (mtu > USHRT_MAX || sc->sc_parent == NULL ||
			    if_getmtu(sc->sc_parent) <
			    mtu + (int)PPPOE_OVERHEAD) {
				PPPOE_SC_UNLOCK(sc);
				error = EINVAL;
				break;
			}
			sc->sc_max_payload_req = mtu;
		} else {
			sc->sc_max_payload_req = 0;
		}
		/*
		 * Still under sc_mtx, so a PADS landing mid-ioctl cannot leave
		 * if_mtu and the request disagreeing.  While LCP is up the
		 * peer's MRU still caps if_mtu (pppoe_mtu_update()).
		 * sc_max_payload itself is left alone: it belongs to whatever
		 * negotiation is in flight, and the next PADI re-seeds it.
		 *
		 * Deliberately NOT chained to sppp_ioctl()'s SIOCSIFMTU: its
		 * arm rejects mtu < PPP_MINMRU (128) or > PP_MTU (1500), which
		 * would regress this arm's RFC 4638 / 68-byte floor behaviour;
		 * the LCP MRU option is re-derived from if_mtu at every session
		 * start (sppp_lcp_defaults), so negotiation follows if_mtu
		 * without it (S03 owns the live-MRU renegotiation).
		 */
		pppoe_mtu_set_link(sc, mtu);
		PPPOE_SC_UNLOCK(sc);
		break;
	}
	case PPPOESETPARMS:
		error = priv_check(curthread, PRIV_NET_SETIFPHYS);
		if (error == 0)
			error = pppoe_ioctl_setparms(sc,
			    (struct pppoediscparms *)data);
		break;
	case PPPOEGETPARMS:
		error = pppoe_ioctl_getparms(sc,
		    (struct pppoediscparms *)data);
		break;
	case PPPOEGETSESSION:
		error = pppoe_ioctl_getsession(sc,
		    (struct pppoeconnectionstate *)data);
		break;
	case PPPOESETMSSFIX: {
		struct pppoemssfixparms *mp = (struct pppoemssfixparms *)data;

		error = priv_check(curthread, PRIV_NET_SETIFPHYS);
		if (error != 0)
			break;
		if (mp->enable > 1) {
			error = EINVAL;
			break;
		}
		atomic_store_int(&sc->sc_nomssfix, mp->enable != 0 ? 0 : 1);
		break;
	}
	case PPPOEGETMSSFIX:
		((struct pppoemssfixparms *)data)->enable =
		    atomic_load_int(&sc->sc_nomssfix) != 0 ? 0 : 1;
		break;
	default:
		/*
		 * The SPPP* range (SPPPGET/SETAUTHCFG, SPPP*LCPCFG, SPPP*STATUS,
		 * SPPP*IDLETO, ...), SIOCADDMULTI/SIOCDELMULTI and whatever
		 * else the stack or a peer tool asks for falls through to the
		 * PPP layer.  This replaces the plan-1 default EINVAL (M001
		 * plan-mandated) and lands before SIOCSIFADDR-style cmds are
		 * answered by the stack's own arms.
		 */
		error = sppp_ioctl(ifp, cmd, data);
		break;
	}
	pppoe_softc_rele(sc);
	return (error);
}

/*
 * Every deferred task of the module -- the session, address and MTU tasks,
 * the sppp work queues, the netisr dispatch rebuild and hash reseed -- runs
 * here rather than on the shared taskqueue_thread, whose one thread every
 * other subsystem also feeds.  One thread, PWAIT, exactly as
 * TASKQUEUE_DEFINE_THREAD() starts taskqueue_thread
 * (sys/sys/taskqueue.h:164-165), so the FIFO order across tasks the
 * handlers depend on is unchanged.
 *
 * Created at MOD_LOAD, before anything can enqueue.  Freed by a SYSUNINIT
 * rather than at MOD_UNLOAD: the module event runs before the SYSUNINITs
 * (kern_linker.c:720 vs :748), and the VNET_SYSUNINIT's clone destroys
 * still drain their tasks here.  linker_file_sysuninit() runs the
 * SYSUNINITs in reverse (subsystem, order) (:264-274), so SI_SUB_PSEUDO/
 * SI_ORDER_FIRST comes after pppoe_vnet_uninit() (SI_SUB_PROTO_IF) and
 * sppp_keepalive_vnet_uninit().  taskqueue_free() would itself run what is
 * left (subr_taskqueue.c:840) and wait for the thread (:207-214); the
 * explicit drain makes that visible.
 */
struct taskqueue *pppoe_taskq;

static void
pppoe_taskq_fini(void *arg __unused)
{

	if (pppoe_taskq == NULL)
		return;
	taskqueue_drain_all(pppoe_taskq);
	taskqueue_free(pppoe_taskq);
	pppoe_taskq = NULL;
}
SYSUNINIT(pppoe_taskq, SI_SUB_PSEUDO, SI_ORDER_FIRST, pppoe_taskq_fini, NULL);

static int
pppoe_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		pppoe_taskq = taskqueue_create("pppoe_taskq", M_WAITOK,
		    taskqueue_thread_enqueue, &pppoe_taskq);
		error = taskqueue_start_threads(&pppoe_taskq, 1, PWAIT,
		    "pppoe taskq");
		if (error != 0) {
			taskqueue_free(pppoe_taskq);
			pppoe_taskq = NULL;
			return (error);
		}
		/* Before anything can dispatch: see pppoe_hash_inner(). */
		pppoe_hash_init();
		pppoe_dispatch_init();
		/*
		 * T4: locally originated packets reserve max_linkhdr (16 by
		 * default, sys/kern/uipc_mbuf.c) of leading space, 6 short of
		 * pppoe_encap_output()'s 22-byte prepend, which then costs a
		 * second mbuf per packet.  Grow it to 24 (22, 4-aligned so
		 * the IP header stays aligned).  One-way and global: the
		 * stack has no shrink, and 8 more bytes of headroom harm
		 * nobody once the module is gone.
		 */
		max_linkhdr_grow(roundup2(ETHER_HDR_LEN + PPPOE_OVERHEAD,
		    sizeof(uint32_t)));
		pppoe_netisr_register();
		pppoe_ifdetach_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
		    pppoe_ifdetach, NULL, EVENTHANDLER_PRI_ANY);
		pppoe_ifattach_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
		    pppoe_ifattach, NULL, EVENTHANDLER_PRI_ANY);
		return (0);
	case MOD_UNLOAD:
		/*
		 * A failed MOD_LOAD is followed straight away by MOD_UNLOAD
		 * (kern_module.c:121-123).  The only failure is above, before
		 * anything else was set up, so there is nothing to undo; in
		 * particular a NULL tag makes EVENTHANDLER_DEREGISTER() empty
		 * the whole system-wide list (subr_eventhandler.c:204-212).
		 * On a normal unload pppoe_taskq is still up here: it goes in
		 * pppoe_taskq_fini(), after the module event.
		 */
		if (pppoe_taskq == NULL)
			return (0);
		/*
		 * Task 13: detach every vnet's pfil hook, quiesce, then
		 * unregister.  pppoe_netisr_unregister() documents why any other
		 * order leaves a live NULL dereference (a dispatcher that passed
		 * the enable check reaching np_handler after it is NULL); the
		 * sweep is the ordering fix.  The second module-level
		 * NET_EPOCH_WAIT() lives inside pppoe_netisr_unregister().
		 *
		 * One residual window remains, and it is base-kernel, not
		 * module-causable (M001/S03 review finding I1): NET_EPOCH_WAIT()
		 * blocks only on epoch sections that are active, and queued
		 * work is not one of them.  A frame enqueued before the sweep
		 * can still sit in a workstream's nws_work queue with
		 * NWS_SCHEDULED pending, and a swi_net that starts processing
		 * between the wait above and netisr_unregister() reaching
		 * np_handler = NULL (netisr.c:665-670) reads a NULL handler --
		 * the exposure the base kernel itself documents as inherent
		 * with NETISR_LOCKING off (netisr.c:127).  No public netisr
		 * API lets a module drain or park another protocol's queues,
		 * so the module side can only document the window; the unload
		 * probe's netstat -Q queue-depth assertion before every
		 * kldunload is the belt-and-braces witness that keeps the
		 * window loud rather than silent.
		 *
		 * The departure and arrival handlers go first:
		 * EVENTHANDLER_DEREGISTER() waits out a running invocation, and
		 * the clones they act on are destroyed (releasing their parents
		 * themselves) by the VNET_SYSUNINITs that follow.
		 */
		EVENTHANDLER_DEREGISTER(ifnet_departure_event,
		    pppoe_ifdetach_tag);
		EVENTHANDLER_DEREGISTER(ifnet_arrival_event,
		    pppoe_ifattach_tag);
		pppoe_vnet_pfil_sweep();
		NET_EPOCH_WAIT();
		pppoe_netisr_unregister();
		pppoe_dispatch_fini();
		pppoe_hash_fini();
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t pppoe_mod = { "if_pppoe", pppoe_modevent, NULL };
/*
 * MOD_LOAD must run before pppoe_vnet_init() (SI_SUB_PROTO_IF): otherwise it
 * would call netisr_register_vnet() for an already-existing vnet jail and set
 * V_netisr_enable for a protocol whose handler is still NULL, and the next
 * session frame in that jail would be dispatched straight through it.
 * SI_SUB_PSEUDO guarantees that; SI_ORDER_FIRST also puts it ahead of sppp's
 * SI_SUB_PSEUDO keepalive constructor.  MOD_UNLOAD needs no such care:
 * linker_file_unload() always runs the module events before
 * linker_file_sysuninit().
 */
/*
 * Load gating: DECLARE_MODULE_TIED pins the kernel dependency to exactly the
 * __FreeBSD_version this .ko was built against (sys/module.h), where plain
 * DECLARE_MODULE accepts any kernel up to the branch's MODULE_KERNEL_MAXVER.
 * __FreeBSD_version does not move on -pN patch releases; the plugin's
 * per-kern.build_id module directories cover that (risk register C9).
 */
#ifndef DECLARE_MODULE_TIED
#error "DECLARE_MODULE_TIED missing: if_pppoe must not load on a foreign kernel"
#endif
DECLARE_MODULE_TIED(if_pppoe, pppoe_mod, SI_SUB_PSEUDO, SI_ORDER_FIRST);
MODULE_VERSION(if_pppoe, 1);

/*
 * Capability flags, ALL declared here: kern.features.if_pppoe_<name> = 1
 * while this module is loaded (FEATURE(9) sysctls live in the module's
 * linker set).  The OPNsense plugin gates eligibility on them; a missing
 * sysctl reads as "absent" (docs/plugin/risk-register.md C9).  Add a line
 * per shipped capability; never remove or rename one.
 */
FEATURE(if_pppoe_linkevents, "if_pppoe: devctl PPPOE link events and a "
    "single NCP-driven link-state writer");
