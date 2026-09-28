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
 * Private seam header for the split if_pppoe(4) module.
 *
 * if_pppoe.c (core and session), if_pppoe_disc.c (the discovery FSM) and
 * if_pppoe_netisr.c (the netisr seam) share only what lives here: the softc
 * (the discovery FSM's state, locked by sc_mtx), the per-vnet counter block
 * both seams account into, the PPPOE_SC_* lock macros, and the prototypes of
 * every function that crosses a file boundary.  Public ABI stays in
 * net/if_pppoe.h (NETISR_PPPOE_DATA, ioctls, structs); nothing here is
 * visible to userland.
 *
 * This is a kernel-only header.  Do not add includes or declarations that the
 * seams do not share -- keep whole unrelated core blocks in if_pppoe.c.
 */

#ifndef _NET_IF_PPPOE_VAR_H_
#define _NET_IF_PPPOE_VAR_H_

#include <sys/callout.h>
#include <sys/ck.h>
#include <sys/counter.h>
#include <sys/epoch.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/ethernet.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <net/vnet.h>

/*
 * The softc embeds one struct sppp (docs/PORTING-sppp.md "softc-embed
 * contract").  if_setllsoftc(ifp, &sc->ppp) at clone create makes
 * sppp_from_ifp() a pure read of the link-layer softc slot; sc_ifp stays
 * if_getsoftc's payload.  This include pulls the vendored NetBSD PPP
 * state machine in, so every seam that touches the softc sees it.
 */
#include <net/if_spppvar.h>

MALLOC_DECLARE(M_PPPOE);

/* NetBSD-style container-of helpers for the embedded PPP state machine. */
#define	PPPOE_SC2SPPP(sc)	(&(sc)->ppp)
#define	PPPOE_SPPP2SC(sp)	(__containerof((sp), struct pppoe_softc, ppp))
#define	PPPOE_IFP2SC(ifp)	((struct pppoe_softc *)if_getsoftc(ifp))

/* struct pppoe_softc sc_ncp_ev[] indices (p3-events). */
#define	PPPOE_EV_IPCP		0
#define	PPPOE_EV_IPV6CP		1
#define	PPPOE_EV_COUNT		2

/*
 * The immutable per-session transmit snapshot (T2).  Everything the session
 * transmit path needs, frozen when the session is established: a prebuilt
 * Ethernet + PPPoE header (AC MAC, the parent's MAC, 0x8864, VER/TYPE,
 * code 0, session id -- everything but the length), the parent to send on
 * and the payload bound.  Published with a release store under sc_mtx by
 * the PADS arm, cleared (NULL) by pppoe_clear_softc() before any path lets
 * go of the parent, and read with an acquire load inside the net epoch;
 * a replaced or cleared snapshot is freed with NET_EPOCH_CALL().  So a
 * transmitter needs no lock: what it loads is complete, stays allocated
 * until it leaves the epoch, and its ts_parent stays allocated as long as
 * that (docs/PERF-DESIGN.md).
 */
struct pppoe_tx_snap {
	if_t		 ts_parent;	/* borrowed from the softc's if_ref */
	int		 ts_maxlen;	/* max PPPoE payload, PPP proto incl. */
	uint8_t		 ts_hdr[ETHER_HDR_LEN + 4]; /* all but PPPoE length */
	struct epoch_context ts_ctx;
} __aligned(CACHE_LINE_SIZE);	/* read-only once published: own line;
				   malloc_aligned(9) it (the PADS arm) */

/*
 * One cloned pppoeN interface.  sc_mtx guards the discovery FSM, the timers
 * and the parameters; the softc list links are epoch-protected (see
 * pppoe_find_by_hunique() in if_pppoe.c).
 */
struct pppoe_softc {
	struct sppp	 ppp;		/* PPP state machine; ppp.pp_if == sc_ifp */
	struct ifnet	*sc_ifp;	/* our cloned interface */
	struct ifnet	*sc_parent;	/* Ethernet or vlan parent, or NULL */
	struct mtx	 sc_mtx;	/* discovery FSM, timers, parms */
	struct callout	 sc_timeout;	/* discovery retransmit timer */
	int		 sc_state;	/* PPPOE_STATE_* */
	uint16_t	 sc_session;	/* PPPoE session id, host order */
	struct ether_addr sc_dest;	/* AC MAC, broadcast until PADO */
	uint64_t	 sc_hunique;	/* our Host-Uniq token */
	char		*sc_service_name;	/* malloc'd, M_PPPOE, or NULL */
	char		*sc_ac_name;		/* malloc'd, M_PPPOE, or NULL */
	uint8_t		*sc_ac_cookie;		/* malloc'd, M_PPPOE, or NULL */
	size_t		 sc_ac_cookie_len;
	uint8_t		*sc_relay_sid;		/* malloc'd, M_PPPOE, or NULL */
	size_t		 sc_relay_sid_len;
	uint16_t	 sc_max_payload_req;	/* RFC 4638 ask, from ioctl */
	uint16_t	 sc_max_payload;	/* ...as negotiated now */
	/* if_mtu's inputs, under sc_mtx; see pppoe_mtu_update(). */
	u_int		 sc_mtu_link;	/* SIOCSIFMTU value, or the PADS's */
	u_int		 sc_mtu_peer;	/* peer MRU while LCP is up, else 0 */
	/*
	 * Desired IPv6 link-local address after IPv6CP (T2/R009), snapshotted
	 * by pppoe_set_ip6_addr() (called from sppp's IPv6CP tlu with
	 * pp_lock held) and applied by the sc_addr_task -- pppoe_addr_apply()
	 * -- on pppoe_taskq under CURVNET_SET via
	 * in6_control_ioctl(SIOCAIFADDR_IN6).  Read under pp_lock only;
	 * deliberately NOT in struct sppp to keep that layout untouched.
	 *
	 * These fields are UNCONDITIONAL (no #ifdef INET6): struct
	 * pppoe_softc is compiled by the four module seams with different
	 * opt_* sets (if_pppoe_disc.c has no opt_inet6.h), and an
	 * INET6-conditional member would give each TU a different layout --
	 * the ODR violation that panicked every load during T2 bisection.
	 */
	struct in6_addr	 sc_want_ll6;
	bool		 sc_want_ll6_set;
	/*
	 * MEM068 (S03/T1): the IPv4 address this driver last successfully
	 * SIOCAIFADDR'd onto the interface, in host order (0 = none applied).
	 * The sc_addr_task uses it as the SIOCDIFADDR delete target for
	 * teardown and renegotiation: in_difaddr_ioctl() treats a well-formed
	 * AF_INET ifr_addr as an exact-match request, so the delete must name
	 * the real address, not a wildcard.  Touched only by the task itself
	 * (pppoe_taskq runs it single-threaded and coalesced), so it
	 * carries no lock of its own.  Unconditional field (no #ifdef): the
	 * ODR rule above applies to every member of this struct.
	 */
	uint32_t	 sc_applied_local;
	int		 sc_padi_retried;
	int		 sc_padr_retried;
	bool		 sc_detaching;	/* clone_destroy has claimed the softc */
	/*
	 * One-shot latch for the parent-ALTQ warning (S03/T2): pppoe_connect()
	 * and pppoe_ioctl_setparms() run the detection under PPPOE_SC_LOCK,
	 * so this field is only ever touched there.  Latched once per softc --
	 * re-binds and re-dials must not repeat the warning.
	 */
	bool		 sc_parent_altq_warned;
	bool		 sc_in_hash;	/* linked into V_pppoe_sessions */
	/*
	 * sc_all membership, under pppoe_parents_lock.  sc_listed: linked
	 * into its vnet's V_pppoe_softcs.  sc_vmoving: unlinked by an
	 * if_vmove() departure, to be re-linked into the destination vnet's
	 * list by the arrival that follows (pppoe_ifdetach/pppoe_ifattach).
	 */
	bool		 sc_listed;
	bool		 sc_vmoving;
	/*
	 * LCP asked for the lower layer (pppoe_tls()) and has not let go
	 * of it (pppoe_tlf()), under sc_mtx.  A PPPOESETPARMS that binds a
	 * parent to a softc in that state starts discovery itself, as
	 * pppoe_tls() would have had the parent been there -- after a
	 * parent departure, or an `ifconfig up` with no parent bound.
	 */
	bool		 sc_link_wanted;
	/*
	 * Link up/down notifications to the PPP layer, latched under sc_mtx
	 * by the PADS arm and pppoe_clear_softc() and delivered by
	 * pppoe_session_task() (which runs outside sc_mtx) so pp_up()/pp_down()
	 * -- which enqueue on sppp's taskqueue -- never run under our lock.
	 */
	bool		 sc_want_up;
	bool		 sc_want_down;
	uint16_t	 sc_hashed_session;	/* id sc_hash is bucketed on */
	/* Last SESSION_UP devctl announced (0 = none) and its AC; touched only
	   by pppoe_session_task() (p3-events). */
	uint16_t	 sc_ev_session;
	struct ether_addr sc_ev_ac;
	/*
	 * NCP devctl records (p3-events), [PPPOE_EV_IPCP] and [PPPOE_EV_IPV6CP].
	 * want/gen/data: latched by pppoe_ncp_event() from the NCP tlu/tld
	 * under pp_lock (gen counts UP edges, so a coalesced UP-DOWN-UP is
	 * still seen).  ann*: what was last announced, touched only by
	 * pppoe_addr_apply(), which emits *_UP after it has applied the
	 * address and replays ann_data in the matching *_DOWN.  Unconditional
	 * (ODR rule above).
	 */
	struct pppoe_ncp_ev {
		bool	 want;
		bool	 ann;
		u_int	 gen;
		u_int	 ann_gen;
		char	 data[SPPP_EVDATA_LEN];
		char	 ann_data[SPPP_EVDATA_LEN];
	} sc_ncp_ev[PPPOE_EV_COUNT];
	/*
	 * The last session this softc closed, its AC and when (time_uptime),
	 * recorded by pppoe_clear_softc() under sc_mtx; the PADS arm zeroes
	 * sc_last_session when the AC hands that id back.  The only unknown
	 * session the RX hook may attribute to us for net.pppoe.term_unknown,
	 * and only for net.pppoe.term_unknown_window seconds: any other
	 * unknown session may belong to another PPPoE client on the same
	 * parent (mpd5 via ng_ether) and is passed up the stack untouched.
	 */
	uint16_t	 sc_last_session;
	struct ether_addr sc_last_dest;
	time_t		 sc_last_closed;
	/*
	 * ppsratecheck() state for the AC-triggerable discovery logs
	 * (pppoe_disc_log()); under sc_mtx.
	 */
	struct timeval	 sc_disclog_last;
	int		 sc_disclog_pps;
	u_int		 sc_refs;	/* lifetime holds: 1 owner (the interface)
				   plus one per in-flight pppoe_ioctl() or
				   departure/arrival handler (the per-packet
				   paths use the net epoch instead, T1); clone
				   destroy waits for 1, then drops it (D012) */
	struct task	 sc_session_task;	/* (un)publishes the session */
	struct task	 sc_addr_task;	/* applies IPCP-negotiated IP addrs */
	struct task	 sc_mtu_task;	/* announces an if_mtu change */
	CK_LIST_ENTRY(pppoe_softc) sc_all;	/* V_pppoe_softcs, every softc */
	CK_LIST_ENTRY(pppoe_softc) sc_hash;	/* V_pppoe_sessions bucket */
	struct epoch_context sc_epoch_ctx;
	/*
	 * TCP MSS clamp off (PPPOESETMSSFIX enable=0).  Inverted so the
	 * M_ZERO allocation leaves the clamp on by default.  Read lock-free
	 * per packet with atomic_load_int(), written by the ioctl with
	 * atomic_store_int(); a packet racing a toggle may go either way.
	 */
	u_int		 sc_nomssfix;
	/*
	 * The session's transmit snapshot, or NULL outside PPPOE_STATE_SESSION
	 * (T2): written under sc_mtx with atomic_store_rel_ptr(), read without
	 * it by pppoe_encap_output() inside the net epoch.
	 *
	 * On a cache line of its own (the struct's size rounds up to the
	 * alignment, so nothing follows it on the line).  With T1 the
	 * per-packet paths write nothing in the softc any more, but the
	 * control plane still does -- sc_mtx and sc_refs on every ioctl (a
	 * router's monitoring polls them every few seconds), sc_state and
	 * the timers during discovery -- and every one of those writes used
	 * to invalidate the line every transmitting CPU read.  The member's
	 * __aligned makes the whole softc a CACHE_LINE_SIZE-aligned type, so
	 * pppoe_clone_create() allocates it with malloc_aligned(9): plain
	 * malloc(9) only promises alignment "for storage of any type of
	 * object", and handing out an over-aligned type from it is UB (UBSan
	 * trips on it), whatever UMA's power-of-two zones happen to do.
	 */
	struct pppoe_tx_snap *sc_txsnap __aligned(CACHE_LINE_SIZE);
};

#define	PPPOE_SC_LOCK(sc)	mtx_lock(&(sc)->sc_mtx)
#define	PPPOE_SC_UNLOCK(sc)	mtx_unlock(&(sc)->sc_mtx)
#define	PPPOE_SC_ASSERT(sc)	mtx_assert(&(sc)->sc_mtx, MA_OWNED)

/*
 * Per-vnet counters shared by every seam: the RX hook and pppoe_data_input()
 * (if_pppoe.c), the discovery FSM's output and receive paths
 * (if_pppoe_disc.c) and -- via the init/fini pair -- the netisr seam.  Defined
 * in if_pppoe.c, declared here so if_pppoe_disc.c can account into it.
 */
struct pppoe_stats {
	counter_u64_t	hook_seen;	/* frames the hook inspected */
	counter_u64_t	disc_in;	/* 0x8863 frames taken */
	counter_u64_t	disc_malformed;	/* 0x8863 frames we could not parse */
	counter_u64_t	disc_err_tag;	/* 0x8863 frames carrying an error tag */
	counter_u64_t	padt_rx;	/* well-formed PADTs seen on a parent */
	counter_u64_t	padt_tx;	/* PADTs we put on the wire */
	counter_u64_t	sess_in;	/* 0x8864 frames taken */
	counter_u64_t	sess_nosession;	/* 0x8864 with no matching session */
	counter_u64_t	padt_unknown;	/* PADTs sent for unknown sessions */
	counter_u64_t	sess_short;	/* malformed or truncated 0x8864 */
	counter_u64_t	data_in;	/* decapsulated PPP frames delivered */
	counter_u64_t	tx_frames;	/* frames the parent accepted */
	counter_u64_t	tx_errors;	/* ...and frames it refused */
	counter_u64_t	tx_parent_down;	/* dropped: parent not up and running */
	counter_u64_t	mss_clamped;	/* TCP SYNs whose MSS was lowered */
	counter_u64_t	passed_foreign;	/* PPPoE frames not ours, PFIL_PASS */
	counter_u64_t	nomem;		/* mbuf/malloc allocation failures */
	counter_u64_t	netisr_enqueue_drop; /* netisr_dispatch() refused */
};

VNET_DECLARE(struct pppoe_stats, pppoe_stats);
#define	V_pppoe_stats		VNET(pppoe_stats)

SYSCTL_DECL(_net_pppoe);

/*
 * Whether a frame may be handed to parent at all.  Not every driver checks
 * IFF_DRV_RUNNING before touching its queues: vtnet_txq_mq_start() divides
 * by a queue-pair count that is zero until vtnet_init() has run, so the
 * first PADI after a reboot panicked the lab client with an integer divide
 * fault.  Checked at the two places a frame reaches ether_output_frame():
 * pppoe_output_frame() and pppoe_encap_output().  Dropped frames are
 * counted in tx_parent_down and tx_errors before any BPF tap, like an
 * EMSGSIZE drop.
 *
 * departing skips the IFF_UP half, which only the crash-free case needs:
 * if_detach_internal() if_down()s every parent before it posts
 * ifnet_departure_event, so pppoe_parent_departed()'s PADT
 * (pppoe_send_padt_departing()) would otherwise never go out, even to a
 * vlan whose trunk still runs.
 *
 * The flags are read unlocked just before the transmit, so this narrows
 * the window against a parent being stopped concurrently rather than
 * closing it; a driver must still survive a transmit racing its own stop.
 */
static __inline bool
pppoe_parent_can_tx(if_t parent, bool departing)
{

	return ((departing || (if_getflags(parent) & IFF_UP) != 0) &&
	    (if_getdrvflags(parent) & IFF_DRV_RUNNING) != 0);
}

/* Discovery FSM seam (if_pppoe_disc.c) exports to the core. */
int			 pppoe_output_frame(if_t parent,
			    const struct ether_addr *dst, uint16_t etype,
			    struct mbuf *m);
void			 pppoe_add_16(uint8_t **p, uint16_t v);
int			 pppoe_send_padi(struct pppoe_softc *sc);
int			 pppoe_send_padr(struct pppoe_softc *sc);
int			 pppoe_send_padt(if_t parent, uint16_t session,
			    const struct ether_addr *peer);
int			 pppoe_send_padt_departing(if_t parent,
			    uint16_t session, const struct ether_addr *peer);
void			 pppoe_timeout(void *arg);
/*
 * pppoe_disc_input() verdicts.  OURS and FREED: the mbuf is gone and *mp is
 * NULL (FREED is an allocation failure inside the input path).  FOREIGN:
 * the frame names no softc of ours on this parent; *mp is the intact frame
 * (possibly re-pointed by m_pullup()) for the hook to PFIL_PASS.
 */
enum pppoe_disc_verdict {
	PPPOE_DISC_OURS,
	PPPOE_DISC_FREED,
	PPPOE_DISC_FOREIGN,
};
enum pppoe_disc_verdict	 pppoe_disc_input(if_t ifp, struct mbuf **mp);

/* Core (if_pppoe.c) exports to the discovery FSM. */
bool			 pppoe_lladdr_copy(if_t ifp, void *dst);
void			 pppoe_tx_snap_publish(struct pppoe_softc *sc,
			    struct pppoe_tx_snap *ts);
void			 pppoe_clear_softc(struct pppoe_softc *sc,
			    const char *why);
void			 pppoe_mtu_set_link(struct pppoe_softc *sc, u_int mtu);
struct pppoe_softc	*pppoe_find_by_hunique(const uint8_t *token,
			    size_t len);
struct pppoe_softc	*pppoe_find_by_session(if_t ifp, uint16_t session,
			    const struct ether_addr *peer);

/* Netisr seam (if_pppoe_netisr.c) exports to the core. */
void			 pppoe_netisr_register(void);
void			 pppoe_netisr_unregister(void);
extern bool		 pppoe_netisr_registered;
extern struct netisr_handler pppoe_nh;
void			 pppoe_cpu_hits_init(void);
void			 pppoe_cpu_hits_fini(void);
void			 pppoe_hash_init(void);
void			 pppoe_hash_fini(void);
void			 pppoe_dispatch_init(void);
void			 pppoe_dispatch_fini(void);
bool			 pppoe_hash_inner(struct mbuf *m);

/* Core (if_pppoe.c) exports to the netisr seam. */
void			 pppoe_data_input(struct mbuf *m);

#endif /* _NET_IF_PPPOE_VAR_H_ */