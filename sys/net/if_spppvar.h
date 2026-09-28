/*	$NetBSD: if_spppvar.h,v 1.56 2026/07/28 07:10:43 yamaguchi Exp $	*/

#ifndef _NET_IF_SPPPVAR_H_
#define _NET_IF_SPPPVAR_H_

/*
 * Defines for synchronous PPP/Cisco link level subroutines.
 *
 * Copyright (C) 1994 Cronyx Ltd.
 * Author: Serge Vakulenko, <vak@cronyx.ru>
 *
 * Heavily revamped to conform to RFC 1661.
 * Copyright (C) 1997, Joerg Wunsch.
 *
 * This software is distributed with NO WARRANTIES, not even the implied
 * warranties for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Authors grant any other persons or organizations permission to use
 * or modify this software as long as this message is kept with the software,
 * all derivative works or modified versions.
 *
 * From: Version 2.0, Fri Oct  6 20:39:21 MSK 1995
 *
 * From: if_sppp.h,v 1.8 1997/10/11 11:25:20 joerg Exp
 *
 * From: Id: if_sppp.h,v 1.7 1998/12/01 20:20:19 hm Exp
 */

/*
 * FreeBSD port notice
 * -------------------
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sys/net/if_spppvar.h.
 *
 * NetBSD KPIs are mapped to FreeBSD ones in <net/if_sppp_compat.h>; see
 * docs/PORTING-sppp.md for the full recipe and for the list of features
 * deliberately not ported (idle timeout, dial filters, SPPP_FILTER,
 * Cisco HDLC keepalives, PPPOE_SERVER, MS-CHAP, EAP, VJ/deflate).
 *
 * S01 struct surgery (T2) versus the pristine NetBSD layout:
 *   - the value-embedded ifnet member (historically "must be first")
 *     is now a `struct ifnet *pp_if` back-pointer; the driver embeds
 *     struct sppp and points llsoftc at the embedded member
 *     (sppp_from_ifp()).
 *   - the two NetBSD-only `struct ifqueue` fields (pp_fastq, pp_cpq)
 *     are deleted; SPPPSUBR_MPSAFE output transmits directly.
 *   - `struct work work` in struct sppp_work is deleted (no per-work
 *     task); the (func, arg, state) triple stays plus a wq_next link
 *     for the single per-interface taskqueue shim.
 *   - the dead `#if defined(__FreeBSD__) && __FreeBSD__ >= 3` block
 *     (the dead FreeBSD-ifs callout-array block) is deleted (no such type on
 *     FreeBSD 14.3 -- compile breaker).
 *   - pp_sysctl_log (sysctllog) and its sysctl-node helpers are
 *     dropped.
 */

/* KPI section: NetBSD names -> FreeBSD 14.3 names (see compat header). */
#include <net/if_sppp_compat.h>
struct sppp;

struct sppp_work {
	void		*arg;
	void		(*func)(struct sppp *, void *);
	unsigned int	 state;
	struct sppp_work	*wq_next;	/* pending-chain link (compat) */
#define SPPP_WK_FREE	0
#define SPPP_WK_BUSY	1
#define SPPP_WK_UNAVAIL	2
};

#define IDX_LCP 0		/* idx into state table */

struct slcp {
	u_long	opts;		/* LCP options to send (bitfield) */
	u_long  magic;          /* local magic number */
	u_long	mru;		/* our max receive unit */
	u_long	their_mru;	/* their max receive unit */
	u_long	protos;		/* bitmask of protos that are started */
	u_char  echoid;         /* id of last keepalive echo request */
	/* restart max values, see RFC 1661 */
	int	timeout;
	int	max_terminate;
	int	max_configure;
	int	max_failure;
	/* multilink variables */
	u_long	mrru;		/* our   max received reconstructed unit */
	u_long	their_mrru;	/* their max receive dreconstructed unit */
	bool	lower_running;	/* Whether the lower layer is running */
};

#define IDX_IPCP 1		/* idx into state table */
#define IDX_IPV6CP 2		/* idx into state table */

struct sipcp {
	u_long	opts;		/* IPCP options to send (bitfield) */
	u_int	flags;
#define IPCP_HISADDR_SEEN 1	/* have seen his address already */
#define IPCP_MYADDR_SEEN  2	/* have a local address assigned already */
#define IPCP_MYADDR_DYN   4	/* my address is dynamically assigned */
#define	IPCP_HISADDR_DYN  8	/* his address is dynamically assigned */
#ifdef notdef
#define IPV6CP_MYIFID_DYN   2	/* my ifid is dynamically assigned */
#endif
#define IPV6CP_MYIFID_SEEN  4	/* have seen his ifid already */
	uint32_t saved_hisaddr;/* if hisaddr (IPv4) is dynamic, save original one here, in network byte order */
	uint32_t req_hisaddr;	/* remote address requested */
	uint32_t req_myaddr;	/* local address requested */
	int	max_failure;	/* RFC 1661 Max-Failure (NAKs before REJ) */

	uint8_t my_ifid[8];	/* IPv6CP my ifid*/
	uint8_t his_ifid[8];	/* IPv6CP his ifid*/
};

struct sauth {
	u_short	proto;			/* authentication protocol to use */
	u_short	flags;
	char	*name;			/* system identification name */
	char	*secret;		/* secret password */
	u_char	name_len;		/* no need to have a bigger size */
	u_char	secret_len;		/* because proto gives size in a byte */
};

struct schap {
	char	 challenge[16];		/* random challenge
					   [don't change size! it's really hardcoded!] */
	char	 digest[16];
	u_char	 digest_len;
	bool	 rechallenging;		/* sent challenge after open */
	bool	 response_rcvd;		/* receive response, stop sending challenge */

	struct sppp_work	 work_challenge_rcvd;
};

#define IDX_PAP		3
#define IDX_CHAP	4

#define IDX_COUNT (IDX_CHAP + 1) /* bump this when adding cp's! */

struct sppp_cp {
	u_long		 seq;		/* local sequence number */
	u_long		 rseq;		/* remote sequence number */
	int		 state;		/* state machine */
	u_char		 confid;	/* local id of last configuration request */
	u_char		 rconfid;	/* remote id of last configuration request */
	int		 rst_counter;	/* restart counter */
	int		 fail_counter;	/* negotiation failure counter */
	struct callout	 ch;		/* per-proto and if callouts */
	u_char		 rcr_type;	/* parsing result of conf-req */
	struct mbuf	*mbuf_confreq;	/* received conf-req */
	struct mbuf	*mbuf_confnak;	/* received conf-nak or conf-rej */

	struct sppp_work	 work_up;
	struct sppp_work	 work_down;
	struct sppp_work	 work_open;
	struct sppp_work	 work_close;
	struct sppp_work	 work_to;
	struct sppp_work	 work_rcr;
	struct sppp_work	 work_rca;
	struct sppp_work	 work_rcn;
	struct sppp_work	 work_rtr;
	struct sppp_work	 work_rta;
	struct sppp_work	 work_rxj;
};

struct sppp {
	struct  ifnet *pp_if;   /* back-pointer to ifnet (sppp_from_ifp) */
	struct  sppp *pp_next;  /* next interface in keepalive list */
	/*
	 * Port: the vnet whose V_spppq pp_next links into (valid while
	 * pp_listed; spppq_lock).  Not curvnet after an if_vmove().
	 */
	struct  vnet *pp_vnet;
	bool	pp_listed;

#define PP_DEVF_KEEPALIVE	__BIT(0)	/* use keepalive protocol */
#define PP_DEVF_NOFRAMING	__BIT(1)	/* do not add/expect encapsulation
						 * around PPP frames (i.e. the serial
						 * HDLC like encapsulation, RFC1662) */
	uint32_t	pp_dev_flags; /* immutable device flags after attach*/
	size_t		pp_framebytes; /* number of bytes added by (hardware) framing */

	u_int   pp_flags;       /* use Cisco protocol instead of PPP */
	u_int	pp_ncpflags;	/* enable or disable each NCP */
	u_int   pp_alivecnt;    /* keepalive packets counter */
	u_int	pp_alive_interval;	/* keepalive interval */
	u_int   pp_loopcnt;     /* loopback detection counter */
	u_int	pp_maxalive;	/* number or echo req. w/o reply */
	uint64_t	pp_saved_mtu;	/* unused: if_mtu is the driver's,
					   pppoe_set_peer_mru(); kept for the
					   vendored layout */
	volatile uint32_t pp_last_receive;
					/* peer's last "sign of life" */
	uint32_t	pp_max_noreceive;
					/* seconds since last receive before
					   we start to worry and send echo
					   requests */
	/*
	 * Port (R1/T3): the data-plane gate.  Bit (1 << IDX_IPCP) /
	 * (1 << IDX_IPV6CP) is set iff that NCP's scp[].state is
	 * STATE_OPENED; written with atomics only by sppp_cp_change_state()
	 * and sppp_cp_init(), under pp_lock, and read lock-free by
	 * sppp_input()/sppp_output() on every IP packet (SPPP_DP_OPEN()).
	 * Unconditional (ODR rule, see if_pppoe_var.h).
	 */
	u_int		pp_dp_open;	/* atomic(9) access only */
	int	pp_auth_failures;	/* authorization failures */
	int	pp_max_auth_fail;	/* max. allowed authorization failures */
	bool	pp_connecting;		/* MP-safe IFF_RUNNING flag */
	bool	pp_ondemand;		/* MP-safe IFF_AUTO (= IFF_LINK1) flag */
	int	pp_phase;	/* phase we're currently in */
	krwlock_t	pp_lock;	/* lock for sppp structure */
	int	query_dns;	/* 1 if we want to know the dns addresses */
	uint32_t	dns_addrs[2];
	struct workqueue *wq_cp;
	struct sppp_work work_ifdown;
	struct sppp_work work_dial;	/* backed-off pp_tls, see pp_dial_ch */
	callout_t	pp_dial_ch;	/* auth-failure redial backoff */
	bool		pp_dial_armed;	/* pp_dial_ch/work_dial owes a pp_tls */
	struct sppp_cp scp[IDX_COUNT];
	struct slcp lcp;		/* LCP params */
	struct sipcp ipcp;		/* IPCP params */
	struct sipcp ipv6cp;		/* IPv6CP params */
	struct sauth myauth;		/* auth params, i'm peer */
	struct sauth hisauth;		/* auth params, i'm authenticator */
	struct schap chap;		/* CHAP params */
	/*
	 * These functions are filled in by sppp_attach(), and are
	 * expected to be used by the lower layer (hardware) drivers
	 * in order to communicate the (un)availability of the
	 * communication link.  Lower layer drivers that are always
	 * ready to communicate (like hardware HDLC) can shortcut
	 * pp_up from pp_tls, and pp_down from pp_tlf.
	 */
	void	(*pp_up)(struct sppp *);
	void	(*pp_down)(struct sppp *);
	/*
	 * Desired IPv4 endpoint addresses after IPCP, recorded by
	 * pppoe_set_ip_addrs() (called from sppp's IPCP tlu with pp_lock
	 * held) and applied by the driver's sc_addr_task on
	 * pppoe_taskq under CURVNET_SET.  Read under pp_lock only.
	 */
	uint32_t	pp_want_local;
	uint32_t	pp_want_remote;
	/*
	 * MEM068 belt: the dynamic-address clear on IPCP layer-down is
	 * asynchronous (sc_addr_task on pppoe_taskq), so a fast redial's
	 * sppp_ipcp_open() can still observe the stale, still-applied address
	 * before the SIOCDIFADDR task drains.  Latched in sppp_ipcp_tld() with
	 * the dying session's IPCP_{MY,HIS}ADDR_DYN flags, consumed in
	 * sppp_ipcp_open() to renegotiate exactly those endpoints (a static
	 * one stays static), and cleared in sppp_ipcp_tlu() once the fresh
	 * session's addresses are recorded.  pppoe_taskq is FIFO, so the
	 * pending clear always lands before the next session's apply.
	 * Unconditional field (no #ifdef INET6) -- per-TU struct-layout
	 * divergence ODR-panicked module loads in M002 (see if_pppoe_var.h).
	 */
	u_int		pp_prev_dyn_addrs;
	/* ppsratecheck() state for peer-triggerable input-path logs
	 * (sppp_rxlog_ok()); under pp_lock.  Unconditional (ODR rule). */
	struct timeval	pp_rxlog_last;
	int		pp_rxlog_pps;
	/*
	 * p3-events: the NCPs currently Opened, as (1 << IDX_IPCP) |
	 * (1 << IDX_IPV6CP), set by their tlu and cleared by their tld under
	 * pp_lock.  sppp_ncp_link() -- the ONE writer of the interface link
	 * state -- derives LINK_STATE_UP iff non-zero; the tlu/tld hand the
	 * NCP devctl record to the driver (pppoe_ncp_event()) only when the
	 * bit flips.  Unconditional (ODR rule).
	 */
	u_int		pp_ncp_up;
	/*
	 * p3-events: AUTH_FAIL devctl record pending (PPP_PAP Nak / PPP_CHAP
	 * Failure from the peer; 0 = none).  Latched under pp_lock on the
	 * input path, cleared by a later PAP Ack / CHAP Success (only a
	 * failure of the current LCP incarnation is reported);
	 * sppp_lcp_tld() emits it with pp_lock dropped.
	 */
	u_short		pp_authfail_proto;
	/*
	 * These functions need to be filled in by the lower layer
	 * (hardware) drivers if they request notification from the
	 * PPP layer whether the link is actually required.  They
	 * correspond to the tls and tlf actions.
	 */
	void	(*pp_tls)(struct sppp *);
	void	(*pp_tlf)(struct sppp *);
	/*
	 * Port (T4): optional lower-layer IP transmit, honoured with
	 * PP_DEVF_NOFRAMING.  When set, sppp_output() hands it the packet and
	 * the PPP protocol number (network order) instead of prepending the
	 * 2-byte protocol field itself and calling if_transmit(), so the
	 * lower layer builds its whole header in one prepend.  Consumes the
	 * mbuf; runs in sppp_output()'s context (if_pppoe: the net epoch).
	 */
	int	(*pp_xmit_proto)(struct sppp *, struct mbuf *, uint16_t);

#ifdef SPPP_FILTER
	/*
	 * Filter for trigger packets of on-demand dialing,
	 * protected by pp_lock (SPPP_LOCK()).
	 */
	struct	bpf_program	 pp_dial_filt;

	/*
	 * Filter for idle-timeout packets,
	 * protected by pserialize and psref.
	 */
	pserialize_t		 pp_psz;
	bool			 pp_active_filt_enabled;
	struct sppp_bpf {
		struct psref_target	sb_psref;
		size_t			sb_len;
		struct bpf_insn		sb_insns[];
	} *pp_active_filt_in, *pp_active_filt_out;
#endif
};

#define PP_IFDOWN	0x01	/* if_down() when no ECHO_REPLY received
				   or loopback detected */
				/* 0x02 was PP_CISCO */
				/* 0x04 was PP_TIMO */
				/* 0x08 was PP_CALLIN */
#define PP_NEEDAUTH	0x10	/* remote requested authentication */

#define PP_MTU          1500    /* default/minimal MRU */
#define PP_MAX_MRU	2048	/* maximal MRU we want to negotiate */

/* sppp-dependent shim surface (struct workqueue, sppp_wq_*, ...). */
#define SPPP_COMPAT_STRUCTS_READY	1
#include <net/if_sppp_compat.h>

#ifdef _KERNEL
void sppp_attach (struct ifnet *);
void sppp_detach (struct ifnet *);
void sppp_vnet_move(struct ifnet *, struct vnet *);
void sppp_input (struct ifnet *, struct mbuf *);
int sppp_ioctl(struct ifnet *, u_long, void *);
struct mbuf *sppp_dequeue (struct ifnet *);
int sppp_isempty (struct ifnet *);
void sppp_flush (struct ifnet *);
void sppp_abort_connect(struct ifnet *);
/*
 * The vendored if_output entry (the driver's pppoe_output() wraps it with
 * a softc lifetime hold; see its comment in if_pppoe.c).
 */
int sppp_output(struct ifnet *, struct mbuf *,
    const struct sockaddr *, struct route *);

/*
 * Driver-provided IPCP address application (if_pppoe.c), called from
 * sppp's IPCP tlu/tld with pp_lock held; the assignment itself runs on
 * the driver's pppoe_taskq task (spike S2 recipe, R009).
 */
void pppoe_set_ip_addrs(struct sppp *, uint32_t, uint32_t);
/*
 * Driver MTU hand-off (if_pppoe.c), from sppp's LCP tlu (the peer's MRU)
 * and tld (0).  Takes the driver's softc mutex: never call it with
 * pp_lock held.
 */
void pppoe_set_peer_mru(struct sppp *, u_int);
void pppoe_clear_ip_addrs(struct sppp *);
#ifdef INET6
void pppoe_set_ip6_addr(struct sppp *, const struct in6_addr *);
#endif
/*
 * Driver devctl(4) emitter (if_pppoe.c): `!system=PPPOE subsystem=<ifname>
 * type=<type> <data>`.  Never call it with pp_lock held.
 */
void pppoe_devctl(struct ifnet *, const char *, const char *);
/*
 * NCP devctl hand-off (if_pppoe.c), called from the IPCP/IPv6CP tlu/tld
 * with pp_lock held when the NCP's pp_ncp_up bit flips.  idx is IDX_IPCP or
 * IDX_IPV6CP; data is the *_UP record's data (NUL-terminated, shorter than
 * SPPP_EVDATA_LEN), or NULL for down.  Latch-and-enqueue only: the record
 * goes out from the driver's address task after the address is applied.
 */
#define	SPPP_EVDATA_LEN	128	/* longest NCP devctl data (IPCP, <= 102) */
void pppoe_ncp_event(struct sppp *, int, const char *);

/*
 * An interface to read pp_connecting for layer-violation
 * optimization.
 *
 * If pp_connecting is false when read by a lower layer, a Close event
 * for LCP has been scheduled but pp_tlf() has not yet been called.
 * This allows the lower layer to abort connection retries during a Down
 * (This-Layer-Down) before pp_tlf() is invoked.
 *
 * Since pp_tlf() is guaranteed to be called eventually, this check is
 * purely optional for optimization; therefore, acquiring pp_lock
 * (SPPP_LOCK()) is not required.
 */
static inline bool
sppp_is_connecting(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	return atomic_load_relaxed(&sp->pp_connecting);
}

/*
 * An interface to check if Dial-on-Demand is enabled.
 *
 * If Dial-on-Demand is enabled, the lower layer can abort connection
 * retries asynchronously with the sppp layer. On aborting, the lower
 * layer is expected to invoke sppp_abort_connect(), which evaluates
 * pp_ondemand while holding pp_lock.
 *
 * Since this function serves as the initial unlocked check for a
 * Double-checked locking pattern, acquiring pp_lock (SPPP_LOCK())
 * is not required.
 */
static inline bool
sppp_ondemand_enabled(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	return atomic_load_relaxed(&sp->pp_ondemand);
}
#endif

/*
 * Locking notes:
 * + spppq is a per-vnet list (VNET_DEFINE'd, M002/S03/T2 -- each vnet's
 *   PPPoE interfaces keep alive independently, with their own keepalive_ch
 *   callout and sppp_keepalive_cnt tick counter); it is protected by the
 *   single module-level spppq_lock (an adaptive mutex).  spppq is used for
 *   sending keepalive packets; the list head lives in the vnet data block,
 *   the mutex does not.
 * + struct sppp is protected by sppp->pp_lock (an rwlock)
 *     sppp holds configuration parameters for line,
 *     authentication and addresses. It also has pointers
 *     of functions to notify events to lower layer.
 *     When notify events, sppp->pp_lock must be released.
 *     Because the event handler implemented in a lower
 *     layer often call functions implemented in
 *     if_spppsubr.c.
 *
 * Locking order:
 *    - IFNET_LOCK => spppq_lock => struct sppp->pp_lock
 *
 * NOTICE
 * - Lower layers must not acquire sppp->pp_lock
 */
#endif /* !_NET_IF_SPPPVAR_H_ */