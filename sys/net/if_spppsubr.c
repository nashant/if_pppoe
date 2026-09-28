/*	$NetBSD: if_spppsubr.c,v 1.308 2026/07/28 07:10:42 yamaguchi Exp $	 */

/*
 * Synchronous PPP/Cisco link level subroutines.
 * Keepalive protocol implemented in both Cisco and PPP modes.
 *
 * Copyright (C) 1994-1996 Cronyx Engineering Ltd.
 * Author: Serge Vakulenko, <vak@cronyx.ru>
 *
 * Heavily revamped to conform to RFC 1661.
 * Copyright (C) 1997, Joerg Wunsch.
 *
 * RFC2472 IPv6CP support.
 * Copyright (C) 2000, Jun-ichiro itojun Hagino <itojun@iijlab.net>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE FREEBSD PROJECT ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE FREEBSD PROJECT OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * From: Version 2.4, Thu Apr 30 17:17:21 MSD 1997
 *
 * From: if_spppsubr.c,v 1.39 1998/04/04 13:26:03 phk Exp
 *
 * From: Id: if_spppsubr.c,v 1.23 1999/02/23 14:47:50 hm Exp
 */

/*
 * FreeBSD port notice
 * -------------------
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sys/net/if_spppsubr.c.
 *
 * NetBSD KPIs are mapped to FreeBSD ones in <net/if_sppp_compat.h>; see
 * docs/PORTING-sppp.md for the full recipe and for the list of features
 * deliberately not ported (idle timeout, dial filters, SPPP_FILTER,
 * Cisco HDLC keepalives, PPPOE_SERVER, MS-CHAP, EAP, VJ/deflate).
 */

#include <sys/cdefs.h>
/* __KERNEL_RCSID is NetBSD-only; FreeBSD cdefs has no equivalent (T3). */

#if defined(_KERNEL_OPT) || defined(HAVE_KERNEL_OPTION_HEADERS)
#include "opt_inet.h"
#include "opt_inet6.h"
#endif

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/callout.h>
#include <sys/sysctl.h>
#include <sys/md5.h>
#include <sys/stdint.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#ifdef SPPP_FILTER
/* pserialize/psref are NetBSD-only; SPPP_FILTER is not ported. */
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/ppp_defs.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#ifdef INET
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif
#include <net/ethernet.h>

#ifdef INET6
#include <netinet6/scope6_var.h>
#endif

#include <net/if_sppp.h>
#include <net/if_spppvar.h>

#ifdef NET_MPSAFE
#define SPPPSUBR_MPSAFE	1
#endif

#define DEFAULT_KEEPALIVE_INTERVAL	10	/* seconds between checks */
#define DEFAULT_ALIVE_INTERVAL		1	/* count of sppp_keepalive */
#define LOOPALIVECNT     		3	/* loopback detection tries */
#define DEFAULT_MAXALIVECNT    		3	/* max. missed alive packets */
#define	DEFAULT_NORECV_TIME		15	/* before we get worried */
#define DEFAULT_MAX_AUTH_FAILURES	5	/* max. auth. failures */
#define DEFAULT_AUTH_BACKOFF_MAX	300	/* max. redial delay, seconds */
#define AUTH_BACKOFF_LIMIT		86400	/* clamp: delay * hz fits an int */

#ifndef SPPP_KEEPALIVE_INTERVAL
#define SPPP_KEEPALIVE_INTERVAL		DEFAULT_KEEPALIVE_INTERVAL
#endif

#ifndef SPPP_NORECV_TIME
#define SPPP_NORECV_TIME	DEFAULT_NORECV_TIME
#endif

#ifndef SPPP_ALIVE_INTERVAL
#define SPPP_ALIVE_INTERVAL		DEFAULT_ALIVE_INTERVAL
#endif

#define SPPP_CPTYPE_NAMELEN	5	/* buf size of cp type name */
#define SPPP_AUTHTYPE_NAMELEN	32	/* buf size of auth type name */
#define SPPP_LCPOPT_NAMELEN	5	/* buf size of lcp option name  */
#define SPPP_IPCPOPT_NAMELEN	5	/* buf size of ipcp option name */
#define SPPP_IPV6CPOPT_NAMELEN	5	/* buf size of ipv6cp option name */
#define SPPP_PROTO_NAMELEN	7	/* buf size of protocol name */
#define SPPP_DOTQUAD_BUFLEN	16	/* length of "aa.bb.cc.dd" */

/*
 * Interface flags that can be set in an ifconfig command.
 *
 * Setting link0 will make the link passive, i.e. it will be marked
 * as being administrative openable, but won't be opened to begin
 * with.  Incoming calls will be answered, or subsequent calls with
 * -link1 will cause the administrative open of the LCP layer.
 *
 * Setting link1 will cause the link to auto-dial only as packets
 * arrive to be sent.
 *
 * Setting IFF_DEBUG will syslog the option negotiation and state
 * transitions at level kern.debug.  Note: all logs consistently look
 * like
 *
 *   <if-name><unit>: <proto-name> <additional info...>
 *
 * with <if-name><unit> being something like "bppp0", and <proto-name>
 * being one of "lcp", "ipcp", "cisco", "chap", "pap", etc.
 */

#define IFF_PASSIVE	IFF_LINK0	/* wait passively for connection */
#define IFF_AUTO	IFF_LINK1	/* auto-dial on output */

#define CONF_REQ	1		/* PPP configure request */
#define CONF_ACK	2		/* PPP configure acknowledge */
#define CONF_NAK	3		/* PPP configure negative ack */
#define CONF_REJ	4		/* PPP configure reject */
#define TERM_REQ	5		/* PPP terminate request */
#define TERM_ACK	6		/* PPP terminate acknowledge */
#define CODE_REJ	7		/* PPP code reject */
#define PROTO_REJ	8		/* PPP protocol reject */
#define ECHO_REQ	9		/* PPP echo request */
#define ECHO_REPLY	10		/* PPP echo reply */
#define DISC_REQ	11		/* PPP discard request */

#define LCP_OPT_MRU		1	/* maximum receive unit */
#define LCP_OPT_ASYNC_MAP	2	/* async control character map */
#define LCP_OPT_AUTH_PROTO	3	/* authentication protocol */
#define LCP_OPT_QUAL_PROTO	4	/* quality protocol */
#define LCP_OPT_MAGIC		5	/* magic number */
#define LCP_OPT_RESERVED	6	/* reserved */
#define LCP_OPT_PROTO_COMP	7	/* protocol field compression */
#define LCP_OPT_ADDR_COMP	8	/* address/control field compression */
#define LCP_OPT_FCS_ALTS	9	/* FCS alternatives */
#define LCP_OPT_SELF_DESC_PAD	10	/* self-describing padding */
#define LCP_OPT_CALL_BACK	13	/* callback */
#define LCP_OPT_COMPOUND_FRMS	15	/* compound frames */
#define LCP_OPT_MP_MRRU		17	/* multilink MRRU */
#define LCP_OPT_MP_SSNHF	18	/* multilink short seq. numbers */
#define LCP_OPT_MP_EID		19	/* multilink endpoint discriminator */

#define IPCP_OPT_ADDRESSES	1	/* both IP addresses; deprecated */
#define IPCP_OPT_COMPRESSION	2	/* IP compression protocol */
#define IPCP_OPT_ADDRESS	3	/* local IP address */
#define	IPCP_OPT_PRIMDNS	129	/* primary remote dns address */
#define	IPCP_OPT_SECDNS		131	/* secondary remote dns address */

#define IPCP_UPDATE_LIMIT	8	/* limit of pending IP updating job */
#define IPCP_SET_ADDRS		1	/* marker for IP address setting job */
#define IPCP_CLEAR_ADDRS	2	/* marker for IP address clearing job */

#define IPV6CP_OPT_IFID		1	/* interface identifier */
#define IPV6CP_OPT_COMPRESSION	2	/* IPv6 compression protocol */

#define PAP_REQ			1	/* PAP name/password request */
#define PAP_ACK			2	/* PAP acknowledge */
#define PAP_NAK			3	/* PAP fail */

#define CHAP_CHALLENGE		1	/* CHAP challenge request */
#define CHAP_RESPONSE		2	/* CHAP challenge response */
#define CHAP_SUCCESS		3	/* CHAP response ok */
#define CHAP_FAILURE		4	/* CHAP response failed */

#define CHAP_MD5		5	/* hash algorithm - MD5 */

#define CISCO_MULTICAST		0x8f	/* Cisco multicast address */
#define CISCO_UNICAST		0x0f	/* Cisco unicast address */
#define CISCO_KEEPALIVE		0x8035	/* Cisco keepalive protocol */
#define CISCO_ADDR_REQ		0	/* Cisco address request */
#define CISCO_ADDR_REPLY	1	/* Cisco address reply */
#define CISCO_KEEPALIVE_REQ	2	/* Cisco keepalive request */

#define PPP_NOPROTO		0	/* no authentication protocol */

enum {
	STATE_INITIAL = SPPP_STATE_INITIAL,
	STATE_STARTING = SPPP_STATE_STARTING,
	STATE_CLOSED = SPPP_STATE_CLOSED,
	STATE_STOPPED = SPPP_STATE_STOPPED,
	STATE_CLOSING = SPPP_STATE_CLOSING,
	STATE_STOPPING = SPPP_STATE_STOPPING,
	STATE_REQ_SENT = SPPP_STATE_REQ_SENT,
	STATE_ACK_RCVD = SPPP_STATE_ACK_RCVD,
	STATE_ACK_SENT = SPPP_STATE_ACK_SENT,
	STATE_OPENED = SPPP_STATE_OPENED,
};

enum cp_rcr_type {
	CP_RCR_NONE = 0,	/* initial value */
	CP_RCR_ACK,	/* RCR+ */
	CP_RCR_NAK,	/* RCR- */
	CP_RCR_REJ,	/* RCR- */
	CP_RCR_DROP,	/* DROP message */
	CP_RCR_ERR,	/* internal error */
};

struct ppp_header {
	uint8_t address;
	uint8_t control;
	uint16_t protocol;
} __packed;
#define PPP_HEADER_LEN          sizeof (struct ppp_header)

struct lcp_header {
	uint8_t type;
	uint8_t ident;
	uint16_t len;
} __packed;
#define LCP_HEADER_LEN          sizeof (struct lcp_header)

struct cisco_packet {
	uint32_t type;
	uint32_t par1;
	uint32_t par2;
	uint16_t rel;
	uint16_t time0;
	uint16_t time1;
} __packed;
#define CISCO_PACKET_LEN 18

/*
 * We follow the spelling and capitalization of RFC 1661 here, to make
 * it easier comparing with the standard.  Please refer to this RFC in
 * case you can't make sense out of these abbreviation; it will also
 * explain the semantics related to the various events and actions.
 */
struct cp {
	u_short	proto;		/* PPP control protocol number */
	u_char protoidx;	/* index into state table in struct sppp */
	u_char flags;
#define CP_LCP		0x01	/* this is the LCP */
#define CP_AUTH		0x02	/* this is an authentication protocol */
#define CP_NCP		0x04	/* this is a NCP */
#define CP_QUAL		0x08	/* this is a quality reporting protocol */
	const char *name;	/* name of this control protocol */
	/* event handlers */
	void	(*Up)(struct sppp *, void *);
	void	(*Down)(struct sppp *, void *);
	void	(*Open)(struct sppp *, void *);
	void	(*Close)(struct sppp *, void *);
	void	(*TO)(struct sppp *, void *);
	/* actions */
	void	(*tlu)(struct sppp *);
	void	(*tld)(struct sppp *);
	void	(*tls)(const struct cp *, struct sppp *);
	void	(*tlf)(const struct cp *, struct sppp *);
	void	(*scr)(struct sppp *);
	void	(*screply)(const struct cp *, struct sppp *, u_char,
		    uint8_t, size_t, void *);

	/* message parser */
	enum cp_rcr_type
		(*parse_confreq)(struct sppp *, struct lcp_header *, int,
			    uint8_t **, size_t *, size_t *);
	void	(*parse_confrej)(struct sppp *, struct lcp_header *, int);
	void	(*parse_confnak)(struct sppp *, struct lcp_header *, int);
};

enum auth_role {
	SPPP_AUTH_NOROLE = 0,
	SPPP_AUTH_SERV = __BIT(0),
	SPPP_AUTH_PEER = __BIT(1),
};

/*
 * Per-vnet keepalive machinery (M002/S03/T2): every piece of sppp keepalive
 * state is VNET_DEFINE'd -- the interface list (spppq), the callout that
 * walks it (keepalive_ch), the tick counter (sppp_keepalive_cnt) and the
 * schedule period (sppp_keepalive_interval) -- matching M001's per-vnet
 * discipline and the research structural finding that a vnet's PPPoE
 * interfaces must keep alive independently of every other vnet.
 *
 * The vnet data block that a fresh vnet receives is a COPY of vnet0's
 * current values, and a scheduled callout is linked into vnet0's softclock
 * wheel, so sppp_keepalive_vnet_init() MUST re-initialize the copy
 * (callout_init bzeroes the embedded struct callout, discarding the copied
 * cc_links) and capture the vnet pointer as the callout arg: softclock
 * runs the handler with curvnet NULL/foreign, and the handler must touch
 * only THIS vnet's list (V_spppq) -- it sets curvnet from that captured
 * pointer.  sppp_keepalive_vnet_uninit() drains the callout before the
 * vnet data block (and the vnet itself) is freed.
 *
 * spppq_lock stays a single MODULE-level mutex (initialized by spppinit()
 * on first sppp_attach, exactly as before T2): it is a sync
 * primitive for the per-vnet list heads, is never embedded in per-vnet
 * data, and a per-vnet instance would add kldload-time allocation for
 * vnets that never attach a pppoe interface plus an unload leak with no
 * correctness win (the locking order IFNET_LOCK => spppq_lock => pp_lock
 * is unchanged).
 */
VNET_DEFINE_STATIC(struct sppp *, spppq);
#define	V_spppq			VNET(spppq)
static kmutex_t		*spppq_lock = NULL;
/*
 * Static storage for spppq_lock.  The module-level list mutex used to be
 * kmem_alloc'd from M_PPPOE by sppp_mutex_obj_alloc() on first attach, and
 * nothing ever freed it (the vendored sppp layer has no mutex_obj_free
 * counterpart): every kldunload after the first sppp_attach leaked exactly
 * one sizeof(kmutex_t) == sizeof(struct mtx) == 32-byte allocation -- the
 * MEM093 "Warning: memory type pppoe leaked memory on destroy (1
 * allocations, 32 bytes leaked)" signature, which only appears on unloads
 * that followed at least one attach (a bare load/unload never runs
 * spppinit's RUN_ONCE).  Statically embedded storage is initialized once
 * per module load by spppinit() below and dies with the module's own
 * memory: nothing to free, nothing to leak, and SPPPQ_LOCK still goes
 * through the same pointer, so the locking semantics are unchanged.
 */
static kmutex_t		spppq_lock_storage;
VNET_DEFINE_STATIC(callout_t, keepalive_ch);
#define	V_keepalive_ch		VNET(keepalive_ch)
VNET_DEFINE_STATIC(unsigned int, sppp_keepalive_cnt);
#define	V_sppp_keepalive_cnt	VNET(sppp_keepalive_cnt)
VNET_DEFINE_STATIC(unsigned int, sppp_keepalive_interval) =
			    SPPP_KEEPALIVE_INTERVAL;
#define	V_sppp_keepalive_interval VNET(sppp_keepalive_interval)

/*
 * Consecutive authentication failures (an ISP whose RADIUS is down NAKs
 * every attempt) delay the next dial 1, 2, 4 ... seconds, capped here;
 * 0 disables the delay.  This replaces NetBSD's permanent latch, which
 * if_down'ed the interface after pp_max_auth_fail failures.
 */
SYSCTL_DECL(_net_pppoe);
static u_int sppp_auth_backoff_max = DEFAULT_AUTH_BACKOFF_MAX;
SYSCTL_UINT(_net_pppoe, OID_AUTO, auth_backoff_max,
    CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &sppp_auth_backoff_max, 0,
    "maximum seconds between redials after consecutive auth failures");

pktq_rps_hash_func_t sppp_pktq_rps_hash_p;
#ifdef SPPP_FILTER
static struct psref_class *sppp_psref_class __read_mostly = NULL;
#endif

#define SPPPQ_LOCK()	if (spppq_lock) \
				mutex_enter(spppq_lock);
#define SPPPQ_UNLOCK()	if (spppq_lock) \
				mutex_exit(spppq_lock);

#define SPPP_LOCK(_sp, _op)	rw_enter(&(_sp)->pp_lock, (_op))
#define SPPP_UNLOCK(_sp)	rw_exit(&(_sp)->pp_lock)
#define SPPP_WLOCKED(_sp)	rw_write_held(&(_sp)->pp_lock)
#define SPPP_WQ_SET(_wk, _func, _arg)	\
	sppp_wq_set((_wk), (_func), __UNCONST((_arg)))
/* NetBSD log()/addlog(): whole records, one log(9) each; see sppp_log(). */
static void sppp_log(struct sppp *, int, const char *, ...) __printflike(3, 4);
static void sppp_addlog(const char *, ...) __printflike(1, 2);
#define	addlog(_fmt, _args...)	sppp_addlog((_fmt), ##_args)
#define SPPP_LOG(_sp, _lvl, _fmt, _args...)			\
	sppp_log((_sp), (_lvl), (_fmt), ##_args)
#define SPPP_DLOG(_sp, _fmt, _args...)	do {	\
	if (!sppp_debug_enabled(_sp))			\
		break;					\
	SPPP_LOG(_sp, LOG_DEBUG, _fmt, ##_args);	\
} while (0)

#ifdef INET
#ifndef SPPPSUBR_MPSAFE
/*
 * The following disgusting hack gets around the problem that IP TOS
 * can't be set yet.  We want to put "interactive" traffic on a high
 * priority queue.  To decide if traffic is interactive, we check that
 * a) it is TCP and b) one of its ports is telnet, rlogin or ftp control.
 *
 * XXX is this really still necessary?  - joerg -
 */
static u_short interactive_ports[8] = {
	0,	513,	0,	0,
	0,	21,	0,	23,
};
#define INTERACTIVE(p)	(interactive_ports[(p) & 7] == (p))
#endif /* SPPPSUBR_MPSAFE */
#endif

/* almost every function needs these */

static bool sppp_debug_enabled(struct sppp *sp);
/* M002/S03/T2: exported non-static so the driver's pppoe_output() wrapper
 * (softc lifetime hold, see if_pppoe.c) can delegate to it; the prototype
 * lives in net/if_spppvar.h (cross-TU rule). */
int sppp_output(struct ifnet *, struct mbuf *,
		       const struct sockaddr *, struct route *);

static void sppp_cp_init(const struct cp *, struct sppp *);
static void sppp_cp_fini(const struct cp *, struct sppp *);
static void sppp_cp_input(const struct cp *, struct sppp *,
			  struct mbuf *);
static void sppp_cp_send(struct sppp *, u_short, u_char,
			 u_char, u_short, void *);
/* static void sppp_cp_timeout(void *arg); */
static void sppp_cp_change_state(const struct cp *, struct sppp *, int);
static void sppp_cp_to_lcp(void *);
static void sppp_cp_to_ipcp(void *);
static void sppp_cp_to_ipv6cp(void *);
static void sppp_auth_send(const struct cp *, struct sppp *,
			    unsigned int, unsigned int, ...);
static int sppp_auth_role(const struct cp *, struct sppp *);
static void sppp_auth_to_event(struct sppp *, void *);
static bool sppp_auth_awaited(struct sppp *, const struct cp *);
static void sppp_auth_unanswered(struct sppp *, const struct cp *,
			    const char *);
static void sppp_auth_screply(const struct cp *, struct sppp *,
			    u_char, uint8_t, size_t, void *);
static void sppp_up_event(struct sppp *, void *);
static void sppp_down_event(struct sppp *, void *);
static void sppp_open_event(struct sppp *, void *);
static void sppp_close_event(struct sppp *, void *);
static void sppp_to_event(struct sppp *, void *);
static void sppp_rcr_event(struct sppp *, void *);
static void sppp_rca_event(struct sppp *, void *);
static void sppp_rcn_event(struct sppp *, void *);
static void sppp_rtr_event(struct sppp *, void *);
static void sppp_rta_event(struct sppp *, void *);
static void sppp_rxj_event(struct sppp *, void *);

static void sppp_null(struct sppp *);
static void sppp_tls(const struct cp *, struct sppp *);
static void sppp_tlf(const struct cp *, struct sppp *);
static void sppp_screply(const struct cp *, struct sppp *,
		    u_char, uint8_t, size_t, void *);
static void sppp_ifdown(struct sppp *, void *);
static u_int sppp_auth_backoff(struct sppp *);
static void sppp_dial_timeout(void *);
static void sppp_dial(struct sppp *, void *);
static void sppp_dial_now(struct sppp *);

static void sppp_lcp_init(struct sppp *);
static void sppp_lcp_defaults(struct sppp *);
static void sppp_lcp_up(struct sppp *, void *);
static void sppp_lcp_down(struct sppp *, void *);
static void sppp_lcp_open(struct sppp *, void *);
static enum cp_rcr_type
	    sppp_lcp_confreq(struct sppp *, struct lcp_header *, int,
		    uint8_t **, size_t *, size_t *);
static void sppp_lcp_confrej(struct sppp *, struct lcp_header *, int);
static void sppp_lcp_confnak(struct sppp *, struct lcp_header *, int);
static void sppp_lcp_tlu(struct sppp *);
static void sppp_lcp_tld(struct sppp *);
static void sppp_lcp_tls(const struct cp *, struct sppp *);
static void sppp_lcp_tlf(const struct cp *, struct sppp *);
static void sppp_lcp_scr(struct sppp *);
static void sppp_lcp_check_and_close(struct sppp *);
static int sppp_cp_check(struct sppp *, u_char);
static bool sppp_is_ncp_opened(struct sppp *);

static void sppp_ipcp_init(struct sppp *);
static void sppp_ipcp_open(struct sppp *, void *);
static void sppp_ipcp_close(struct sppp *, void *);
static enum cp_rcr_type
	    sppp_ipcp_confreq(struct sppp *, struct lcp_header *, int,
		    uint8_t **, size_t *, size_t *);
static void sppp_ipcp_confrej(struct sppp *, struct lcp_header *, int);
static void sppp_ipcp_confnak(struct sppp *, struct lcp_header *, int);
static void sppp_ipcp_tlu(struct sppp *);
static void sppp_ipcp_tld(struct sppp *);
static void sppp_ipcp_scr(struct sppp *);

static void sppp_ipv6cp_init(struct sppp *);
static void sppp_ipv6cp_open(struct sppp *, void *);
static enum cp_rcr_type
	    sppp_ipv6cp_confreq(struct sppp *, struct lcp_header *, int,
		    uint8_t **, size_t *, size_t *);
static void sppp_ipv6cp_confrej(struct sppp *, struct lcp_header *, int);
static void sppp_ipv6cp_confnak(struct sppp *, struct lcp_header *, int);
static void sppp_ipv6cp_tlu(struct sppp *);
static void sppp_ipv6cp_tld(struct sppp *);
static void sppp_ipv6cp_scr(struct sppp *);

static void sppp_pap_input(struct sppp *, struct mbuf *);
static void sppp_pap_init(struct sppp *);
static void sppp_pap_tlu(struct sppp *);
static void sppp_pap_scr(struct sppp *);

static void sppp_chap_input(struct sppp *, struct mbuf *);
static void sppp_chap_init(struct sppp *);
static void sppp_chap_open(struct sppp *, void *);
static void sppp_chap_tlu(struct sppp *);
static void sppp_chap_scr(struct sppp *);
static void sppp_chap_rcv_challenge_event(struct sppp *, void *);

static const char *sppp_auth_type_name(char *, size_t, u_short, u_char);
static const char *sppp_cp_type_name(char *, size_t, u_char);
static const char *sppp_dotted_quad(char *, size_t, uint32_t);
static const char *sppp_ipcp_opt_name(char *, size_t, u_char);
#ifdef INET6
static const char *sppp_ipv6cp_opt_name(char *, size_t, u_char);
#endif
static const char *sppp_lcp_opt_name(char *, size_t, u_char);
static const char *sppp_phase_name(int);
static const char *sppp_proto_name(char *, size_t, u_short);
static const char *sppp_state_name(int);
static int sppp_params(struct sppp *, u_long, void *);
static void sppp_auth_buf_free(char *);
#ifdef INET
static void sppp_get_ip_addrs(struct sppp *, uint32_t *, uint32_t *, uint32_t *);
static void sppp_set_ip_addrs(struct sppp *);
static void sppp_clear_ip_addrs(struct sppp *);
#endif
static void sppp_keepalive(void *);
static void sppp_phase_network(struct sppp *);
static void sppp_print_bytes(const u_char *, u_short);
static void sppp_print_string(const char *, u_short);
#ifdef INET6
static bool sppp_ip6_ifid_present(const uint8_t *);
static void sppp_get_ip6_addrs(struct sppp *, struct in6_addr *,
				struct in6_addr *, struct in6_addr *);
static void sppp_update_ip6_addr(struct sppp *, const struct in6_addr *);
static void sppp_suggest_ip6_addr(struct sppp *, struct in6_addr *);
#endif

static void sppp_notify_up(struct sppp *);
static void sppp_notify_down(struct sppp *);
static void sppp_notify_tls_wlocked(struct sppp *);
static void sppp_notify_tlf_wlocked(struct sppp *);

#ifdef SPPP_FILTER
static void	sppp_update_last_activity(struct sppp *, struct mbuf *,
		    struct sppp_bpf **);
static int	sppp_set_filter(struct sppp *, struct bpf_program *,
		    struct sppp_bpf **);
#endif

/* our control protocol descriptors */
static const struct cp lcp = {
	PPP_LCP, IDX_LCP, CP_LCP, "lcp",
	sppp_lcp_up, sppp_lcp_down, sppp_lcp_open,
	sppp_close_event, sppp_to_event,
	sppp_lcp_tlu, sppp_lcp_tld, sppp_lcp_tls,
	sppp_lcp_tlf, sppp_lcp_scr, sppp_screply,
	sppp_lcp_confreq, sppp_lcp_confrej, sppp_lcp_confnak
};

static const struct cp ipcp = {
	PPP_IPCP, IDX_IPCP,
#ifdef INET
	CP_NCP,	/*don't run IPCP if there's no IPv4 support*/
#else
	0,
#endif
	"ipcp",
	sppp_up_event, sppp_down_event, sppp_ipcp_open,
	sppp_ipcp_close, sppp_to_event,
	sppp_ipcp_tlu, sppp_ipcp_tld, sppp_tls,
	sppp_tlf, sppp_ipcp_scr, sppp_screply,
	sppp_ipcp_confreq, sppp_ipcp_confrej, sppp_ipcp_confnak,
};

static const struct cp ipv6cp = {
	PPP_IPV6CP, IDX_IPV6CP,
#ifdef INET6	/*don't run IPv6CP if there's no IPv6 support*/
	CP_NCP,
#else
	0,
#endif
	"ipv6cp",
	sppp_up_event, sppp_down_event, sppp_ipv6cp_open,
	sppp_close_event, sppp_to_event,
	sppp_ipv6cp_tlu, sppp_ipv6cp_tld, sppp_tls,
	sppp_tlf, sppp_ipv6cp_scr, sppp_screply,
	sppp_ipv6cp_confreq, sppp_ipv6cp_confrej, sppp_ipv6cp_confnak,
};

static const struct cp pap = {
	PPP_PAP, IDX_PAP, CP_AUTH, "pap",
	sppp_up_event, sppp_down_event, sppp_open_event,
	sppp_close_event, sppp_auth_to_event,
	sppp_pap_tlu, sppp_null, sppp_tls, sppp_tlf,
	sppp_pap_scr, sppp_auth_screply,
	NULL, NULL, NULL
};

static const struct cp chap = {
	PPP_CHAP, IDX_CHAP, CP_AUTH, "chap",
	sppp_up_event, sppp_down_event, sppp_chap_open,
	sppp_close_event, sppp_auth_to_event,
	sppp_chap_tlu, sppp_null, sppp_tls, sppp_tlf,
	sppp_chap_scr, sppp_auth_screply,
	NULL, NULL, NULL
};

static const struct cp *cps[IDX_COUNT] = {
	&lcp,			/* IDX_LCP */
	&ipcp,			/* IDX_IPCP */
	&ipv6cp,		/* IDX_IPV6CP */
	&pap,			/* IDX_PAP */
	&chap,			/* IDX_CHAP */
};

static int
spppinit(void)
{

	mtx_init(&spppq_lock_storage, "spppq", NULL, MTX_DEF);
	spppq_lock = &spppq_lock_storage;
#ifdef SPPP_FILTER
	sppp_psref_class = psref_class_create("sppp_psref", IPL_SOFTNET);
#endif
	return 0;
}

/*
 * Per-vnet keepalive state lifecycle.  These run once per vnet: at boot
 * for vnet0, at kldload for every vnet that already exists, and at
 * vnet_alloc for every vnet created later (net/vnet.c 480-490 runs the
 * constructor with curvnet set to the vnet).  The list head must be reset
 * to NULL because the fresh vnet data block is a copy of vnet0's current
 * values (vnet_data_copy) and vnet0 has interfaces on its own list.
 */
static void
sppp_keepalive_vnet_init(const void *unused __unused)
{

	V_spppq = NULL;
	V_sppp_keepalive_cnt = 0;
	callout_init(&V_keepalive_ch, CALLOUT_MPSAFE);
	/*
	 * Pin THIS vnet as the callout arg: softclock invokes the handler
	 * with curvnet NULL or some other thread's vnet, and the handler
	 * must walk only this vnet's list (V_spppq) -- it sets curvnet from
	 * the pointer captured here.  The callout is drained in
	 * sppp_keepalive_vnet_uninit() (and by sppp_detach() when the last
	 * interface leaves the list) before the vnet struct itself can be
	 * freed, so the pointer never dangles.
	 */
	callout_setfunc(&V_keepalive_ch, sppp_keepalive, curvnet);
}
VNET_SYSINIT(sppp_keepalive_mach, SI_SUB_PSEUDO, SI_ORDER_ANY,
    sppp_keepalive_vnet_init, NULL);

static void
sppp_keepalive_vnet_uninit(const void *unused __unused)
{

	/*
	 * Stop the walker and wait for any in-flight run (vnet_destroy holds
	 * ifnet_detach_sxlock for the whole vnet_sysuninit pass) BEFORE the
	 * vnet data block holding V_spppq/V_keepalive_ch is freed.  If the
	 * last interface already detached, sppp_detach()'s callout_stop made
	 * this a no-op.
	 */
	callout_drain(&V_keepalive_ch);
	V_spppq = NULL;
}
VNET_SYSUNINIT(sppp_keepalive_mach, SI_SUB_PSEUDO, SI_ORDER_ANY,
    sppp_keepalive_vnet_uninit, NULL);

static inline u_int
sppp_proto2authproto(u_short proto)
{

	switch (proto) {
	case PPP_PAP:
		return SPPP_AUTHPROTO_PAP;
	case PPP_CHAP:
		return SPPP_AUTHPROTO_CHAP;
	}

	return SPPP_AUTHPROTO_NONE;
}

static inline u_short
sppp_authproto2proto(u_int authproto)
{

	switch (authproto) {
	case SPPP_AUTHPROTO_PAP:
		return PPP_PAP;
	case SPPP_AUTHPROTO_CHAP:
		return PPP_CHAP;
	}

	return PPP_NOPROTO;
}

static inline bool
sppp_debug_enabled(struct sppp *sp)
{

	if (__predict_false(sp == NULL))
		return false;

	if ((sp->pp_if->if_flags & IFF_DEBUG) == 0)
		return false;

	return true;
}

/*
 * Gate for log records a peer can trigger at will on the input path:
 * always with IFF_DEBUG, else at most SPPP_RXLOG_MAXPPS per second.
 */
#define	SPPP_RXLOG_MAXPPS	1

static bool
sppp_rxlog_ok(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (sppp_debug_enabled(sp))
		return true;
	return ppsratecheck(&sp->pp_rxlog_last, &sp->pp_rxlog_pps,
	    SPPP_RXLOG_MAXPPS) != 0;
}

/*
 * Control-packet parsers walk (and NAK-rewrite) the packet in place from
 * mtod(); the lower layer only guarantees the protocol field is contiguous.
 * m_pullup() fails over MHLEN on a cluster (see pppoe_disc_input()), so
 * longer packets use m_defrag(): one cluster, up to MCLBYTES, larger ones
 * dropped.  Consumes m on failure.
 */
static struct mbuf *
sppp_pullup_ctl(struct mbuf *m)
{
	struct mbuf *n;
	int len = m->m_pkthdr.len;

	if (m->m_len >= len)
		return m;
	if (len <= MHLEN)
		return m_pullup(m, len);
	/* m_defrag() leaves the chain alone on failure. */
	n = m_defrag(m, M_NOWAIT);
	if (n == NULL) {
		m_freem(m);
		return NULL;
	}
	if (n->m_len < len) {
		m_freem(n);
		return NULL;
	}
	return n;
}

static inline void
sppp_connect(struct sppp *sp)
{
	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/*
	 * RUNNING is a driver flag in FreeBSD (if_drv_flags, IFF_DRV_RUNNING);
	 * the NetBSD spelling (via a compat alias) wrote bit 0x40 of
	 * if_flags instead, so every in-kernel if_drv_flags reader saw the
	 * interface as never running.
	 */
	if_setdrvflagbits(sp->pp_if, IFF_DRV_RUNNING, 0);
	atomic_store_relaxed(&sp->pp_connecting, true);
	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
}

static inline void
sppp_disconnect(struct sppp *sp)
{
	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if_setdrvflagbits(sp->pp_if, 0, IFF_DRV_RUNNING);
	atomic_store_relaxed(&sp->pp_connecting, false);
	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
}

/*
 * Phase changes no longer write the link state (p3-events): the old
 * NETWORK -> UP / anything else -> DOWN mapping, plus the driver's PADS UP,
 * made every dial go UP, DOWN, UP.  sppp_ncp_link() is the only writer.
 */
static void
sppp_change_phase(struct sppp *sp, int phase)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (sp->pp_phase == phase)
		return;

	sp->pp_phase = phase;

	SPPP_DLOG(sp, "phase %s\n",
	    sppp_phase_name(sp->pp_phase));
}

/*
 * The single link-state writer (p3-events): LINK_STATE_UP iff IPCP or
 * IPv6CP is Opened.  Called by the NCP tlu (up) / tld (down) under pp_lock;
 * if_link_state_change() only stores the state and enqueues if_linktask,
 * and dedups an unchanged state.  Returns whether this NCP's bit flipped.
 */
static bool
sppp_ncp_link(struct sppp *sp, int idx, bool up)
{
	u_int bit = 1U << idx;
	u_int was = sp->pp_ncp_up;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (up)
		sp->pp_ncp_up |= bit;
	else
		sp->pp_ncp_up &= ~bit;
	if_link_state_change(sp->pp_if,
	    sp->pp_ncp_up != 0 ? LINK_STATE_UP : LINK_STATE_DOWN);
	return (((was ^ sp->pp_ncp_up) & bit) != 0);
}

/*
 * The data-plane gate (R1/T3).  The IP arms of sppp_input()/sppp_output()
 * used to take pp_lock -- an exclusive mutex in this port, RW_READER
 * included (if_sppp_compat.h) -- on every packet, from every netisr CPU,
 * only to read scp[IDX_IPCP/IPV6CP].state: one contended lock per session
 * serialising the whole data path.  pp_dp_open mirrors "that NCP is
 * Opened" in one word, updated wherever the state is written (under
 * pp_lock), and the data path reads it with a plain atomic load.
 *
 * The lock never bought the data path more than this: it was dropped
 * straight after the read, so the state could change before the packet
 * was delivered or sent either way.  A packet racing a state change is
 * delivered or dropped on one side of the change or the other, exactly as
 * before.  The struct sppp being read stays valid for the call: the lower
 * layer only enters sppp_input()/sppp_output() inside the net epoch with
 * the softc still published, and its destroy unpublishes and
 * NET_EPOCH_WAIT()s before sppp_detach() (if_pppoe.c).
 */
#define	SPPP_DP_OPEN(sp, idx)						\
	((atomic_load_int(&(sp)->pp_dp_open) & (1U << (idx))) != 0)

static inline void
sppp_dp_update(struct sppp *sp, u_char idx, int state)
{

	if (idx != IDX_IPCP && idx != IDX_IPV6CP)
		return;
	if (state == STATE_OPENED)
		atomic_set_int(&sp->pp_dp_open, 1U << idx);
	else
		atomic_clear_int(&sp->pp_dp_open, 1U << idx);
}

/*
 * Exported functions, comprising our interface to the lower layer.
 */

/*
 * Process the received packet.
 */
void
sppp_input(struct ifnet *ifp, struct mbuf *m)
{
	struct ppp_header *h = NULL;
	pktqueue_t *pktq = NULL;
	uint16_t protocol;
	struct sppp *sp = sppp_from_ifp(ifp);

	/* No RPS for not-IP. */
	pktq_rps_hash_func_t rps_hash = NULL;

	if (ifp->if_flags & IFF_UP) {
#ifndef SPPP_LOWER_COUNTS_BYTES
		/* Count received bytes, add hardware framing */
		if_statadd(ifp, if_ibytes, m->m_pkthdr.len + sp->pp_framebytes);
#endif
		/* Note time of last receive (store only on change: R2) */
		sppp_note_receive(sp);
	}

	if (m->m_pkthdr.len <= PPP_HEADER_LEN) {
		/* Too small packet, drop it. */
		SPPP_DLOG(sp, "input packet is too small, "
		    "%d bytes\n", m->m_pkthdr.len);
		goto error;
	}

	if (ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING)) {
		memcpy(&protocol, mtod(m, void *), 2);
		protocol = ntohs(protocol);
		m_adj(m, 2);
	} else {

		/* Get PPP header. */
		h = mtod(m, struct ppp_header *);
		m_adj(m, PPP_HEADER_LEN);

		switch (h->address) {
		case PPP_ALLSTATIONS:
			if (h->control != PPP_UI)
				goto invalid;
			break;
		case CISCO_MULTICAST:
		case CISCO_UNICAST:
			/* Don't check the control field here (RFC 1547). */
			SPPP_DLOG(sp, "Cisco packet in PPP mode "
			    "<addr=0x%x ctrl=0x%x proto=0x%x>\n",
			    h->address, h->control, ntohs(h->protocol));
			goto drop;
		default:        /* Invalid PPP packet. */
		  invalid:
			SPPP_DLOG(sp, "invalid input packet "
			    "<addr=0x%x ctrl=0x%x proto=0x%x>\n",
			    h->address, h->control, ntohs(h->protocol));
			goto drop;
		}
		protocol = ntohs(h->protocol);
	}

	switch (protocol) {
	case PPP_LCP:
	case PPP_PAP:
	case PPP_CHAP:
	case PPP_IPCP:
	case PPP_IPV6CP:
		/* h points into the old chain from here on; it isn't used. */
		m = sppp_pullup_ctl(m);
		if (m == NULL) {
			SPPP_DLOG(sp, "cannot make proto 0x%x packet "
			    "contiguous, dropping\n", protocol);
			if_statinc(ifp, if_ierrors);
			return;
		}
		break;
	}

	switch (protocol) {
	reject_protocol:
		SPPP_KASSERT(SPPP_WLOCKED(sp));

		if (sp->scp[IDX_LCP].state == STATE_OPENED) {
			uint16_t prot = htons(protocol);
			uint8_t *rej;
			size_t rejlen;

			/*
			 * RFC 1661 5.7: the protocol, then the rejected packet
			 * (sppp_cp_send() truncates it to the peer's MRU).
			 */
			rejlen = sizeof(prot) + MIN(m->m_pkthdr.len, MCLBYTES);
			rej = kmem_intr_alloc(rejlen, KM_NOSLEEP);
			if (rej != NULL) {
				memcpy(rej, &prot, sizeof(prot));
				m_copydata(m, 0, rejlen - sizeof(prot),
				    (caddr_t)(rej + sizeof(prot)));
				sppp_cp_send(sp, PPP_LCP, PROTO_REJ,
				    ++sp->scp[IDX_LCP].seq, rejlen, rej);
				kmem_intr_free(rej, rejlen);
			} else
				sppp_cp_send(sp, PPP_LCP, PROTO_REJ,
				    ++sp->scp[IDX_LCP].seq, sizeof(prot), &prot);
		}
		SPPP_UNLOCK(sp);
		goto noproto;
	default:
		/*
		 * reject_protocol asserts and drops the lock; NetBSD jumped
		 * there without it, a remote panic on any unknown protocol.
		 */
		SPPP_LOCK(sp, RW_WRITER);
		SPPP_DLOG(sp, "invalid input protocol "
		    "<proto=0x%x>\n", protocol);
		goto reject_protocol;
	case PPP_LCP:
		SPPP_LOCK(sp, RW_WRITER);
		sppp_cp_input(&lcp, sp, m);
		/* already m_freem(m) */
		SPPP_UNLOCK(sp);
		return;
	case PPP_PAP:
		SPPP_LOCK(sp, RW_WRITER);
		if (sp->pp_phase >= SPPP_PHASE_AUTHENTICATE) {
			sppp_pap_input(sp, m);
		} else {
			SPPP_UNLOCK(sp);
			goto drop;
		}
		SPPP_UNLOCK(sp);
		m_freem(m);
		return;
	case PPP_CHAP:
		SPPP_LOCK(sp, RW_WRITER);
		if (sp->pp_phase >= SPPP_PHASE_AUTHENTICATE) {
			sppp_chap_input(sp, m);
		} else {
			SPPP_UNLOCK(sp);
			goto drop;
		}
		SPPP_UNLOCK(sp);
		m_freem(m);
		return;
#ifdef INET
	case PPP_IPCP:
		SPPP_LOCK(sp, RW_WRITER);
		if (!ISSET(sp->pp_ncpflags, SPPP_NCP_IPCP)) {
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_INFO, "reject IPCP packet "
				    "because IPCP is disabled\n");
			goto reject_protocol;
		}
		if (sp->pp_phase == SPPP_PHASE_NETWORK) {
			sppp_cp_input(&ipcp, sp, m);
			/* already m_freem(m) */
		} else {
			SPPP_UNLOCK(sp);
			goto drop;
		}
		SPPP_UNLOCK(sp);
		return;
	case PPP_IP:
		/* Lock-free: see SPPP_DP_OPEN(). */
		if (SPPP_DP_OPEN(sp, IDX_IPCP)) {
			pktq = ip_pktq;
			rps_hash = atomic_load_relaxed(&sppp_pktq_rps_hash_p);
		}
		break;
#endif
#ifdef INET6
	case PPP_IPV6CP:
		SPPP_LOCK(sp, RW_WRITER);
		if (!ISSET(sp->pp_ncpflags, SPPP_NCP_IPV6CP)) {
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_INFO, "reject IPv6CP packet "
				    "because IPv6CP is disabled\n");
			goto reject_protocol;
		}
		if (sp->pp_phase == SPPP_PHASE_NETWORK) {
			sppp_cp_input(&ipv6cp, sp, m);
			/* already m_freem(m) */
		} else {
			SPPP_UNLOCK(sp);
			goto drop;
		}
		SPPP_UNLOCK(sp);
		return;

	case PPP_IPV6:
		/* Lock-free: see SPPP_DP_OPEN(). */
		if (SPPP_DP_OPEN(sp, IDX_IPV6CP)) {
			pktq = ip6_pktq;
			rps_hash = atomic_load_relaxed(&sppp_pktq_rps_hash_p);
		}
		break;
#endif
	}

	if ((ifp->if_flags & IFF_UP) == 0 || pktq == NULL) {
		goto drop;
	}

#ifdef SPPP_FILTER
	sppp_update_last_activity(sp, m, &sp->pp_active_filt_in);
#endif

	/* Check queue. */
	const uint32_t hash = rps_hash ? pktq_rps_hash(&rps_hash, m) : 0;
	if (__predict_false(!pktq_enqueue(pktq, m, hash))) {
		goto drop;
	}
	return;

drop:
	if_statinc(ifp, if_iqdrops);
	m_freem(m);
	return;

error:
	if_statinc(ifp, if_ierrors);
	m_freem(m);
	return;

noproto:
	if_statinc(ifp, if_noproto);
	m_freem(m);
	return;
}

/*
 * Enqueue transmit packet.
 */
int
sppp_output(struct ifnet *ifp, struct mbuf *m,
    const struct sockaddr *dst, struct route *rt)
{
	struct sppp *sp = sppp_from_ifp(ifp);
	struct ppp_header *h = NULL;
#ifndef SPPPSUBR_MPSAFE
	struct ifqueue *ifq = NULL;		/* XXX */
#endif
	int error = 0;
	uint16_t protocol;
	size_t pktlen;
	bool lowerproto;

#ifdef SPPP_FILTER
	sppp_update_last_activity(sp, m, &sp->pp_active_filt_out);
#endif

	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		if_statinc(ifp, if_oerrors);
		return (ENETDOWN);
	}

	if (!sppp_is_connecting(ifp)) {
		SPPP_LOCK(sp, RW_WRITER);
		if (!sp->pp_ondemand) {
			SPPP_UNLOCK(sp);
			m_freem(m);
			if_statinc(ifp, if_oerrors);
			return (ENETDOWN);
		} else {
			/* ignore packets that have no enabled NCP */
			if ((dst->sa_family == AF_INET &&
			    !ISSET(sp->pp_ncpflags, SPPP_NCP_IPCP)) ||
			    (dst->sa_family == AF_INET6 &&
			    !ISSET(sp->pp_ncpflags, SPPP_NCP_IPV6CP))) {
				SPPP_UNLOCK(sp);

				m_freem(m);
				if_statinc(ifp, if_oerrors);
				return (ENETDOWN);
			}
#ifdef SPPP_FILTER
			if (sp->pp_dial_filt.bf_insns != NULL &&
			    bpf_filter(sp->pp_dial_filt.bf_insns,
			    (u_char *)m, m_length(m), 0) == 0) {
				SPPP_UNLOCK(sp);

				SPPP_DLOG(sp,
				    "%s filtered by pass filter, dropped\n",
				    __func__);
				IF_DROP(&ifp->if_snd);
				m_freem(m);
				return 0;
			}
#endif
			/*
			 * Interface is not yet running, but auto-dial.  Need
			 * to start LCP for it.
			 * Re-check sp->pp_connecting
			 * under lock (Double-Checked Locking)
			 */
			if (!sp->pp_connecting)
				sppp_connect(sp);
		}
		SPPP_UNLOCK(sp);
	}

	/*
	 * If the queueing discipline needs packet classification,
	 * do it before prepending link headers.
	 */
	IFQ_CLASSIFY(&ifp->if_snd, m, dst->sa_family);

#ifdef INET
	if (dst->sa_family == AF_INET) {
		struct ip *ip = NULL;
#ifndef SPPPSUBR_MPSAFE
		struct tcphdr *th = NULL;
#endif

		if (m->m_len >= sizeof(struct ip)) {
			ip = mtod(m, struct ip *);
#ifndef SPPPSUBR_MPSAFE
			if (ip->ip_p == IPPROTO_TCP &&
			    m->m_len >= sizeof(struct ip) + (ip->ip_hl << 2) +
			    sizeof(struct tcphdr)) {
				th = (struct tcphdr *)
				    ((char *)ip + (ip->ip_hl << 2));
			}
#endif
		} else
			ip = NULL;

		/*
		 * When using dynamic local IP address assignment by using
		 * 0.0.0.0 as a local address, the first TCP session will
		 * not connect because the local TCP checksum is computed
		 * using 0.0.0.0 which will later become our real IP address
		 * so the TCP checksum computed at the remote end will
		 * become invalid. So we
		 * - don't let packets with src ip addr 0 thru
		 * - we flag TCP packets with src ip 0 as an error
		 */
		if (ip && ip->ip_src.s_addr == INADDR_ANY) {
			uint8_t proto = ip->ip_p;

			m_freem(m);
			if (proto == IPPROTO_TCP)
				return (EADDRNOTAVAIL);
			else
				return (0);
		}

#ifndef SPPPSUBR_MPSAFE
		/*
		 * Put low delay, telnet, rlogin and ftp control packets
		 * in front of the queue.
		 */
		if (!IF_QFULL(&sp->pp_fastq) &&
		    ((ip && (ip->ip_tos & IPTOS_LOWDELAY)) ||
		     (th && (INTERACTIVE(ntohs(th->th_sport)) ||
		      INTERACTIVE(ntohs(th->th_dport))))))
			ifq = &sp->pp_fastq;
#endif /* !SPPPSUBR_MPSAFE */
	}
#endif

#ifdef INET6
	if (dst->sa_family == AF_INET6) {
		/* XXX do something tricky here? */
	}
#endif

	if (!ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING)) {
		/*
		 * Prepend general data packet PPP header. For now, IP only.
		 */
		M_PREPEND(m, PPP_HEADER_LEN, M_DONTWAIT);
		if (! m) {
			SPPP_DLOG(sp, "no memory for transmit header\n");
			if_statinc(ifp, if_oerrors);
			return (ENOBUFS);
		}
		/*
		 * May want to check size of packet
		 * (albeit due to the implementation it's always enough)
		 */
		h = mtod(m, struct ppp_header *);
		h->address = PPP_ALLSTATIONS;        /* broadcast address */
		h->control = PPP_UI;                 /* Unnumbered Info */
	}

	switch (dst->sa_family) {
#ifdef INET
	case AF_INET:   /* Internet Protocol */
		/*
		 * Don't choke with an ENETDOWN early.  It's
		 * possible that we just started dialing out,
		 * so don't drop the packet immediately.  If
		 * we notice that we run out of buffer space
		 * below, we will however remember that we are
		 * not ready to carry IP packets, and return
		 * ENETDOWN, as opposed to ENOBUFS.
		 */
		protocol = htons(PPP_IP);
		/* Lock-free: see SPPP_DP_OPEN(). */
		if (!SPPP_DP_OPEN(sp, IDX_IPCP)) {
			if (ifp->if_flags & IFF_AUTO) {
				error = ENETDOWN;
			} else {
				m_freem(m);
				if_statinc(ifp, if_oerrors);
				return (ENETDOWN);
			}
		}
		break;
#endif
#ifdef INET6
	case AF_INET6:   /* Internet Protocol version 6 */
		/*
		 * Don't choke with an ENETDOWN early.  It's
		 * possible that we just started dialing out,
		 * so don't drop the packet immediately.  If
		 * we notice that we run out of buffer space
		 * below, we will however remember that we are
		 * not ready to carry IP packets, and return
		 * ENETDOWN, as opposed to ENOBUFS.
		 */
		protocol = htons(PPP_IPV6);
		/* Lock-free: see SPPP_DP_OPEN(). */
		if (!SPPP_DP_OPEN(sp, IDX_IPV6CP)) {
			if (ifp->if_flags & IFF_AUTO) {
				error = ENETDOWN;
			} else {
				m_freem(m);
				if_statinc(ifp, if_oerrors);
				return (ENETDOWN);
			}
		}
		break;
#endif
	default:
		m_freem(m);
		if_statinc(ifp, if_oerrors);
		return (EAFNOSUPPORT);
	}

	if (error == ENETDOWN) {
		IF_DROP(&ifp->if_snd);
		m_freem(m);
		return error;
	}

	/* T4: the lower layer puts the protocol field on itself. */
	lowerproto = ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING) &&
	    sp->pp_xmit_proto != NULL;
	if (ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING) && !lowerproto) {
		M_PREPEND(m, 2, M_DONTWAIT);
		if (m == NULL) {
			SPPP_DLOG(sp, "no memory for transmit header\n");
			if_statinc(ifp, if_oerrors);
			return (ENOBUFS);
		}
		*mtod(m, uint16_t *) = protocol;
	} else if (h != NULL) {
		h->protocol = protocol;
	}

	pktlen = m->m_pkthdr.len;
#ifdef SPPPSUBR_MPSAFE
	if (lowerproto) {
		pktlen += sizeof(protocol);	/* same count as the prepend */
		error = sp->pp_xmit_proto(sp, m, protocol);
	} else
		error = if_transmit_lock(ifp, m);
#ifndef SPPP_LOWER_COUNTS_BYTES
	if (error == 0)
		if_statadd(ifp, if_obytes, pktlen + sp->pp_framebytes);
#else
	(void)pktlen;
#endif
#else /* !SPPPSUBR_MPSAFE */
	error = ifq_enqueue2(ifp, ifq, m);

	if (error == 0) {
		/*
		 * Count output packets and bytes.
		 * The packet length includes header + additional hardware
		 * framing according to RFC 1333.
		 */
		if (!(ifp->if_flags & IFF_OACTIVE)) {
			if_start_lock(ifp);
		}
#ifndef SPPP_LOWER_COUNTS_BYTES
		if_statadd(ifp, if_obytes, pktlen + sp->pp_framebytes);
#endif
	}
#endif /* !SPPPSUBR_MPSAFE */
	return error;
}

/* the NetBSD sysctllog node helpers are not
 * ported; the T_UN variables under net.sppp.<ifname> are dropped with
 * pp_sysctl_log (see docs/PORTING-sppp.md compile-breaker list). */
/*
 * Keepalive list membership, with spppq_lock held.  The list, its callout
 * and its tick live in the vnet that sp->pp_vnet names, which is curvnet at
 * sppp_attach() but not necessarily later: the owning driver can hand the
 * ifnet to another vnet (if_vmove()), and it is then detached with curvnet
 * set to wherever the ifnet sits.  So the unlink switches to the vnet the
 * link was made in rather than trusting curvnet.
 */
static void
sppp_keepalive_link(struct sppp *sp, struct vnet *vnet)
{

	CURVNET_SET_QUIET(vnet);
	if (V_spppq == NULL)
		callout_schedule(&V_keepalive_ch,
		    hz * V_sppp_keepalive_interval);
	sp->pp_next = V_spppq;
	V_spppq = sp;
	sp->pp_vnet = vnet;
	sp->pp_listed = true;
	CURVNET_RESTORE();
}

static void
sppp_keepalive_unlink(struct sppp *sp)
{
	struct sppp **q, *p;

	if (!sp->pp_listed)
		return;
	CURVNET_SET_QUIET(sp->pp_vnet);
	for (q = &V_spppq; (p = *q) != NULL; q = &p->pp_next)
		if (p == sp) {
			*q = p->pp_next;
			break;
		}
	if (V_spppq == NULL)
		callout_stop(&V_keepalive_ch);
	CURVNET_RESTORE();
	sp->pp_next = NULL;
	sp->pp_vnet = NULL;
	sp->pp_listed = false;
}

/*
 * Move the interface onto the keepalive list of vnet `to', or off every
 * list when `to' is NULL: the owning driver's half of an if_vmove(), called
 * on departure (NULL) and again on arrival.  Without it the interface would
 * stay on the list of the vnet it left, driven by that vnet's callout under
 * that vnet's curvnet, and a detach from the new vnet would leave it linked
 * there after the free.
 */
void
sppp_vnet_move(struct ifnet *ifp, struct vnet *to)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	SPPPQ_LOCK();
	sppp_keepalive_unlink(sp);
	if (to != NULL)
		sppp_keepalive_link(sp, to);
	SPPPQ_UNLOCK();
}

void
sppp_attach(struct ifnet *ifp)
{
	static ONCE_DECL(control);
	struct sppp *sp = sppp_from_ifp(ifp);
	char xnamebuf[MAXCOMLEN];

	RUN_ONCE(&control, spppinit);

	sp->pp_if->if_type = IFT_PPP;
	sp->pp_if->if_output = sppp_output;
	/* pp_fastq/pp_cpq ifqueues deleted (SPPPSUBR_MPSAFE direct tx). */
	sp->pp_loopcnt = 0;
	sp->pp_alivecnt = 0;
	sp->pp_alive_interval = SPPP_ALIVE_INTERVAL;
	sp->pp_last_receive = 0;
	sp->pp_maxalive = DEFAULT_MAXALIVECNT;
	sp->pp_max_noreceive = SPPP_NORECV_TIME;
	sp->pp_max_auth_fail = DEFAULT_MAX_AUTH_FAILURES;
	sp->pp_phase = SPPP_PHASE_DEAD;
	sp->pp_up = sppp_notify_up;
	sp->pp_down = sppp_notify_down;
	sp->pp_ncpflags = SPPP_NCP_IPCP | SPPP_NCP_IPV6CP;
#ifdef SPPP_IFDOWN_RECONNECT
	sp->pp_flags |= PP_IFDOWN;
#endif
	sppp_wq_set(&sp->work_ifdown, sppp_ifdown, NULL);
	sppp_wq_set(&sp->work_dial, sppp_dial, NULL);
	callout_init(&sp->pp_dial_ch, CALLOUT_MPSAFE);
	callout_setfunc(&sp->pp_dial_ch, sppp_dial_timeout, sp);
	memset(sp->scp, 0, sizeof(sp->scp));
	rw_init(&sp->pp_lock);
#ifdef SPPP_FILTER
	sp->pp_psz = pserialize_create();
#endif
	/* the NetBSD sadl helper is NetBSD-only; dropped. */

	/* Initial state; sppp_ncp_link() is the only writer after this. */
	sp->pp_ncp_up = 0;
	if_link_state_change(ifp, LINK_STATE_DOWN);

	snprintf(xnamebuf, sizeof(xnamebuf), "%s.wq_cp", ifp->if_xname);
	sp->wq_cp = sppp_wq_create(sp, xnamebuf,
	    PRI_SOFTNET, IPL_SOFTNET, WQ_MPSAFE);

	memset(&sp->myauth, 0, sizeof sp->myauth);
	memset(&sp->hisauth, 0, sizeof sp->hisauth);
	SPPP_LOCK(sp, RW_WRITER);
	sppp_lcp_init(sp);
	sppp_ipcp_init(sp);
	sppp_ipv6cp_init(sp);
	sppp_pap_init(sp);
	sppp_chap_init(sp);
	SPPP_UNLOCK(sp);

	SPPPQ_LOCK();
	sppp_keepalive_link(sp, curvnet);
	SPPPQ_UNLOCK();
}

void
sppp_detach(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	/* Remove the entry from whichever vnet's keepalive list holds it. */
	SPPPQ_LOCK();
	sppp_keepalive_unlink(sp);
	SPPPQ_UNLOCK();

	sppp_cp_fini(&lcp, sp);
	sppp_cp_fini(&ipcp, sp);
	sppp_cp_fini(&pap, sp);
	sppp_cp_fini(&chap, sp);
#ifdef INET6
	sppp_cp_fini(&ipv6cp, sp);
#endif
	/*
	 * Only now: the LCP work waited out above can still re-arm the
	 * backed-off dial (sppp_lcp_tls()), and sppp_dial() never does.
	 */
	callout_halt(&sp->pp_dial_ch, NULL);
	sppp_wq_wait(sp->wq_cp, &sp->work_dial);
	sppp_wq_destroy(sp, sp->wq_cp);

	/* free (and wipe) authentication info */
	sppp_auth_buf_free(sp->myauth.name);
	sppp_auth_buf_free(sp->myauth.secret);
	sppp_auth_buf_free(sp->hisauth.name);
	sppp_auth_buf_free(sp->hisauth.secret);

#ifdef SPPP_FILTER
	{
		struct bpf_program bp_zero = { .bf_insns = NULL, .bf_len = 0};
		struct bpf_program *bpp = &sp->pp_dial_filt;
		if (bpp->bf_insns != NULL)
			kmem_free(bpp->bf_insns,
			    sizeof(bpp->bf_insns[0]) * bpp->bf_len);
		*bpp = bp_zero;
		sppp_set_filter(sp, &bp_zero, &sp->pp_active_filt_in);
		sppp_set_filter(sp, &bp_zero, &sp->pp_active_filt_out);
	}

	pserialize_destroy(sp->pp_psz);
#endif
	/*
	 * pp_lock is NOT destroyed here (FreeBSD port): the owning driver's
	 * address task can still take it after the workqueue drains above,
	 * so the driver destroys it with the softc -- if_pppoe.c
	 * pppoe_softc_free().
	 */
}

/*
 * Flush the interface output queue.
 */
void
sppp_flush(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	SPPP_LOCK(sp, RW_WRITER);
	IFQ_PURGE(&sp->pp_if->if_snd);
	SPPP_UNLOCK(sp);
}

/*
 * Check if the output queue is empty.
 */
int
sppp_isempty(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);
	int empty;

	SPPP_LOCK(sp, RW_READER);
	empty = IFQ_IS_EMPTY(&sp->pp_if->if_snd);
	SPPP_UNLOCK(sp);
	return (empty);
}

/*
 * Get next packet to send.
 */
struct mbuf *
sppp_dequeue(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);
	struct mbuf *m;

	SPPP_LOCK(sp, RW_WRITER);
	/*
	 * Process only the control protocol queue until we have at
	 * least one NCP opened.
	 */
	IFQ_DEQUEUE(&sp->pp_if->if_snd, m);
	SPPP_UNLOCK(sp);
	return m;
}

void
sppp_abort_connect(struct ifnet *ifp)
{
	struct sppp *sp = sppp_from_ifp(ifp);

	SPPP_LOCK(sp, RW_WRITER);
	if (sp->pp_ondemand) {
		if (sp->pp_connecting)
			sppp_disconnect(sp);
	} else {
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
	}
	SPPP_UNLOCK(sp);
}

/*
 * Process an ioctl request.  Called on low priority level.
 */
int
sppp_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct thread *td = curthread;	/* port: priv_check KPI */
	struct ifreq *ifr = (struct ifreq *) data;
#ifdef SPPP_FILTER
	struct spppfilter *sf = (struct spppfilter *)data;
	struct bpf_program *nbp = &sf->bf;
#endif
	struct sppp *sp = sppp_from_ifp(ifp);
	int error=0, going_up, going_down;
	u_long lcp_mru;

	switch (cmd) {
	case SIOCSIFADDR:
		/*
		 * M002/S03/T1: in_aifaddr_ioctl() (sys/netinet/in.c) calls
		 * if_ioctl(SIOCSIFADDR, ia) after it has already inserted the
		 * new in_ifaddr into if_addrhead, so the driver's only job
		 * here is to validate/acknowledge.  sppp keeps no per-address
		 * state beyond what in_aifaddr_ioctl() maintains, so this is
		 * a no-op success - exactly the contract of SIOCINITIFADDR
		 * below (NetBSD's in_ifinit did not call if_ioctl this way;
		 * on FreeBSD the address is already in the list).  Returning
		 * EOPNOTSUPP (the old default) makes in_aifaddr_ioctl() fail1
		 * and roll back, which is what produced the live "could not
		 * set the IPCP address: 45" on the dynamic IPCP dial.
		 */
		break;

	case SIOCINITIFADDR:
		/* ifa_rtrequest removed on FreeBSD 14.3 (no ifp->if_rtrequest
		 * either); p2p route cloning is handled by ifioctl/SIOCAIFADDR
		 * in S03's address application. */
		break;

	case SIOCSIFFLAGS:
		SPPP_LOCK(sp, RW_WRITER);
		going_up =
		     (ifp->if_flags & IFF_UP) && !sp->pp_connecting;
		going_down =
		     ((ifp->if_flags & IFF_UP) == 0) && sp->pp_connecting;
		if ((ifp->if_flags & IFF_AUTO) &&
		    (ifp->if_flags & IFF_PASSIVE)) {
			ifp->if_flags &= ~IFF_AUTO;
		}

		atomic_store_relaxed(&sp->pp_ondemand,
		    (ifp->if_flags & IFF_AUTO) ? true : false);

		if (going_up || going_down) {
			sppp_disconnect(sp);
		}
		if (going_up) {
			/* Always-on connection */
			if (!sp->pp_ondemand)
				sppp_connect(sp);
		} else if (going_down) {
			SPPP_UNLOCK(sp);
			sppp_flush(ifp);
			SPPP_LOCK(sp, RW_WRITER);
		}
		SPPP_UNLOCK(sp);
		break;

	case SIOCSIFMTU:
		if (ifr->ifr_mtu < PPP_MINMRU ||
		    ifr->ifr_mtu > PP_MTU) {
			error = EINVAL;
			break;
		}

		SPPP_LOCK(sp, RW_WRITER);
		lcp_mru = sp->lcp.mru;
		if (ifp->if_mtu < PP_MTU) {
			sp->lcp.mru = ifp->if_mtu;
		} else {
			sp->lcp.mru = PP_MTU;
		}
		if (lcp_mru != sp->lcp.mru)
			SET(sp->lcp.opts, SPPP_LCP_OPT_MRU);
		/* if_mtu itself is the driver's: see pppoe_set_peer_mru(). */
		SPPP_UNLOCK(sp);
		break;

	case SIOCGIFMTU:
		error = 0;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

	case SPPPSETAUTHCFG:
	case SPPPSETLCPCFG:
	case SPPPSETNCPCFG:
	case SPPPSETIDLETO:
	case SPPPSETAUTHFAILURE:
	case SPPPSETDNSOPTS:
	case SPPPSETKEEPALIVE:
#if defined(COMPAT_50) || defined(MODULAR)
	case __SPPPSETIDLETO50:
	case __SPPPSETKEEPALIVE50:
#endif /* COMPAT_50 || MODULAR */
		error = priv_check(td, PRIV_NET_SETIFPHYS);
		if (error)
			break;
		error = sppp_params(sp, cmd, data);
		break;

	case SPPPGETAUTHCFG:
	case SPPPGETLCPCFG:
	case SPPPGETNCPCFG:
	case SPPPGETAUTHFAILURES:
		error = priv_check(td, PRIV_NET_SETIFPHYS);
		if (error)
			break;
		error = sppp_params(sp, cmd, data);
		break;

	case SPPPGETSTATUS:
	case SPPPGETSTATUSNCP:
	case SPPPGETIDLETO:
	case SPPPGETDNSOPTS:
	case SPPPGETDNSADDRS:
	case SPPPGETKEEPALIVE:
#if defined(COMPAT_50) || defined(MODULAR)
	case __SPPPGETIDLETO50:
	case __SPPPGETKEEPALIVE50:
#endif /* COMPAT_50 || MODULAR */
	case SPPPGETLCPSTATUS:
	case SPPPGETIPCPSTATUS:
	case SPPPGETIPV6CPSTATUS:
		error = sppp_params(sp, cmd, data);
		break;

#ifdef SPPP_FILTER
	case SPPPIOCSDIALFILT: {
		/* sp->pp_dial_filt is protected by pp_lock (SPP_LOCK()) */
		struct bpf_program *bp = &sp->pp_dial_filt;

		if (nbp->bf_len > BPF_MAXINSNS)
			return EINVAL;

		SPPP_LOCK(sp, RW_WRITER);
		if (bp->bf_insns != NULL) {
			kmem_free(bp->bf_insns,
			    sizeof(bp->bf_insns[0]) * bp->bf_len);
			bp->bf_insns = NULL;
			bp->bf_len = 0;
		}

		if (nbp->bf_len != 0) {
			struct bpf_insn *newcode;
			size_t newsize = sizeof(newcode[0]) * nbp->bf_len;

			newcode = kmem_alloc(newsize, KM_SLEEP);
			error = copyin((void *)nbp->bf_insns,
			    (void *)newcode, newsize);
			if (error != 0) {
				SPPP_UNLOCK(sp);
				kmem_free(newcode, newsize);
				return error;
			}

			if (!bpf_validate(newcode, nbp->bf_len)) {
				SPPP_UNLOCK(sp);
				kmem_free(newcode, newsize);
				return EINVAL;
			}

			bp->bf_insns = newcode;
			bp->bf_len = nbp->bf_len;
		}
		SPPP_UNLOCK(sp);
		break;
	}
	case SPPPIOCSIACTIVE:
		/* sp->pp_active_filt_in is protected by pserialize & psref */
		error = sppp_set_filter(sp, nbp, &sp->pp_active_filt_in);
		break;
	case SPPPIOCSOACTIVE:
		/* sp->pp_active_filt_out is protected by pserialize & psref */
		error = sppp_set_filter(sp, nbp, &sp->pp_active_filt_out);
		break;
#endif

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

/*
 * PPP protocol implementation.
 */

/*
 * Send PPP control protocol packet.
 */
static void
sppp_cp_send(struct sppp *sp, u_short proto, u_char type,
	     u_char ident, u_short len, void *data)
{
	struct ifnet *ifp = sp->pp_if;
	struct lcp_header *lh;
	struct mbuf *m;
	size_t pkthdrlen, maxlen;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	pkthdrlen = ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING) ?
	     2 : PPP_HEADER_LEN;

	/*
	 * NetBSD clamped to one header mbuf, cutting long ConfAcks mid-option.
	 * Use a cluster up to the peer's MRU (peer-supplied: never below MHLEN).
	 */
	maxlen = MIN(sp->lcp.their_mru, ifp->if_mtu);
	maxlen = MAX(MIN(maxlen, MCLBYTES - pkthdrlen),
	    MHLEN - pkthdrlen) - LCP_HEADER_LEN;
	if (len > maxlen)
		len = maxlen;
	if (pkthdrlen + LCP_HEADER_LEN + len > MHLEN)
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	else
		MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (! m) {
		return;
	}
	m->m_pkthdr.len = m->m_len = pkthdrlen + LCP_HEADER_LEN + len;
	m_reset_rcvif(m);

	if (ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING)) {
		*mtod(m, uint16_t *) = htons(proto);
		lh = (struct lcp_header *)(mtod(m, uint8_t *) + 2);
	} else {
		struct ppp_header *h;
		h = mtod(m, struct ppp_header *);
		h->address = PPP_ALLSTATIONS;        /* broadcast address */
		h->control = PPP_UI;                 /* Unnumbered Info */
		h->protocol = htons(proto);         /* Link Control Protocol */
		lh = (struct lcp_header *)(h + 1);
	}
	lh->type = type;
	lh->ident = ident;
	lh->len = htons(LCP_HEADER_LEN + len);
	if (len)
		memcpy(lh + 1, data, len);

	if (sppp_debug_enabled(sp)) {
		char pbuf[SPPP_PROTO_NAMELEN];
		char tbuf[SPPP_CPTYPE_NAMELEN];
		const char *pname, *cpname;

		pname = sppp_proto_name(pbuf, sizeof(pbuf), proto);
		cpname = sppp_cp_type_name(tbuf, sizeof(tbuf), lh->type);
		SPPP_LOG(sp, LOG_DEBUG, "%s output <%s id=0x%x len=%d",
		    pname, cpname, lh->ident, ntohs(lh->len));
		if (len)
			sppp_print_bytes((u_char *)(lh + 1), len);
		addlog(">\n");
	}
	/* SPPPSUBR_MPSAFE direct transmit (pp_cpq/if_start_lock removed;
	 * S01 compat: sppp lock is dropped around the transmit). */
#ifndef SPPP_LOWER_COUNTS_BYTES
	if_statadd(ifp, if_obytes, m->m_pkthdr.len + sp->pp_framebytes);
#endif
	SPPP_UNLOCK(sp);
	(void)if_transmit_lock(ifp, m);
	SPPP_LOCK(sp, RW_WRITER);
}

static void
sppp_cp_to_lcp(void *xsp)
{
	struct sppp *sp = xsp;

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_to);
}

static void
sppp_cp_to_ipcp(void *xsp)
{
	struct sppp *sp = xsp;

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_IPCP].work_to);
}

static void
sppp_cp_to_ipv6cp(void *xsp)
{
	struct sppp *sp = xsp;

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_IPV6CP].work_to);
}

static void
sppp_cp_to_pap(void *xsp)
{
	struct sppp *sp = xsp;

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_PAP].work_to);
}

static void
sppp_cp_to_chap(void *xsp)
{
	struct sppp *sp = xsp;

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_to);
}

static void
sppp_cp_init(const struct cp *cp, struct sppp *sp)
{
	struct sppp_cp *scp;
	typedef void (*sppp_co_cb_t)(void *);
	static const sppp_co_cb_t to_cb[IDX_COUNT] = {
		[IDX_LCP] = sppp_cp_to_lcp,
		[IDX_IPCP] = sppp_cp_to_ipcp,
		[IDX_IPV6CP] = sppp_cp_to_ipv6cp,
		[IDX_PAP] = sppp_cp_to_pap,
		[IDX_CHAP] = sppp_cp_to_chap,
	};

	scp = &sp->scp[cp->protoidx];
	scp->state = STATE_INITIAL;
	sppp_dp_update(sp, cp->protoidx, STATE_INITIAL);
	scp->fail_counter = 0;
	scp->seq = 0;
	scp->rseq = 0;

	SPPP_WQ_SET(&scp->work_up, cp->Up, cp);
	SPPP_WQ_SET(&scp->work_down, cp->Down,  cp);
	SPPP_WQ_SET(&scp->work_open, cp->Open, cp);
	SPPP_WQ_SET(&scp->work_close, cp->Close, cp);
	SPPP_WQ_SET(&scp->work_to, cp->TO, cp);
	SPPP_WQ_SET(&scp->work_rcr, sppp_rcr_event, cp);
	SPPP_WQ_SET(&scp->work_rca, sppp_rca_event, cp);
	SPPP_WQ_SET(&scp->work_rcn, sppp_rcn_event, cp);
	SPPP_WQ_SET(&scp->work_rtr, sppp_rtr_event, cp);
	SPPP_WQ_SET(&scp->work_rta, sppp_rta_event, cp);
	SPPP_WQ_SET(&scp->work_rxj, sppp_rxj_event, cp);

	callout_init(&scp->ch, CALLOUT_MPSAFE);
	callout_setfunc(&scp->ch, to_cb[cp->protoidx], sp);
}

static void
sppp_cp_fini(const struct cp *cp, struct sppp *sp)
{
	struct sppp_cp *scp;
	scp = &sp->scp[cp->protoidx];

	sppp_wq_wait(sp->wq_cp, &scp->work_up);
	sppp_wq_wait(sp->wq_cp, &scp->work_down);
	sppp_wq_wait(sp->wq_cp, &scp->work_open);
	sppp_wq_wait(sp->wq_cp, &scp->work_close);
	sppp_wq_wait(sp->wq_cp, &scp->work_to);
	sppp_wq_wait(sp->wq_cp, &scp->work_rcr);
	sppp_wq_wait(sp->wq_cp, &scp->work_rca);
	sppp_wq_wait(sp->wq_cp, &scp->work_rcn);
	sppp_wq_wait(sp->wq_cp, &scp->work_rtr);
	sppp_wq_wait(sp->wq_cp, &scp->work_rta);
	sppp_wq_wait(sp->wq_cp, &scp->work_rxj);

	callout_halt(&scp->ch, NULL);
	callout_destroy(&scp->ch);

	m_freem(scp->mbuf_confreq);
	scp->mbuf_confreq = NULL;
	m_freem(scp->mbuf_confnak);
	scp->mbuf_confnak = NULL;
}

/*
 * Handle incoming PPP control protocol packets.
 */
static void
sppp_cp_input(const struct cp *cp, struct sppp *sp, struct mbuf *m)
{
	const bool debug = sppp_debug_enabled(sp);
	struct ifnet *ifp = sp->pp_if;
	struct sppp_cp *scp = &sp->scp[cp->protoidx];
	struct lcp_header *h;
	int printlen, len = m->m_pkthdr.len;
	u_char *p;
	uint32_t u32;
	char tbuf[SPPP_CPTYPE_NAMELEN];
	const char *cpname;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len < 4) {
		SPPP_DLOG(sp, "%s invalid packet length: %d bytes\n",
		    cp->name, len);
		goto out;
	}
	h = mtod(m, struct lcp_header *);
	if (debug) {
		printlen = ntohs(h->len);
		cpname = sppp_cp_type_name(tbuf, sizeof(tbuf), h->type);
		SPPP_LOG(sp, LOG_DEBUG, "%s input(%s): <%s id=0x%x len=%d",
		    cp->name, sppp_state_name(scp->state),
		    cpname, h->ident, printlen);
		if (len < printlen)
			printlen = len;
		if (printlen > 4)
			sppp_print_bytes((u_char *)(h + 1), printlen - 4);
		addlog(">\n");
	}
	if (len > ntohs(h->len))
		len = ntohs(h->len);
	p = (u_char *)(h + 1);
	switch (h->type) {
	case CONF_REQ:
		if (len < 4) {
			SPPP_DLOG(sp,"%s invalid conf-req length %d\n",
			    cp->name, len);
			if_statinc(ifp, if_ierrors);
			break;
		}

		scp->rcr_type = CP_RCR_NONE;
		scp->rconfid = h->ident;
		m_freem(scp->mbuf_confreq);
		scp->mbuf_confreq = m;
		m = NULL;
		sppp_wq_add(sp->wq_cp, &scp->work_rcr);
		break;
	case CONF_ACK:
		if (h->ident != scp->confid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    cp->name, h->ident, scp->confid);
			if_statinc(ifp, if_ierrors);
			break;
		}
		sppp_wq_add(sp->wq_cp, &scp->work_rca);
		break;
	case CONF_NAK:
	case CONF_REJ:
		if (h->ident != scp->confid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    cp->name, h->ident, scp->confid);
			if_statinc(ifp, if_ierrors);
			break;
		}

		m_freem(scp->mbuf_confnak);
		scp->mbuf_confnak = m;
		m = NULL;
		sppp_wq_add(sp->wq_cp, &scp->work_rcn);
		break;
	case TERM_REQ:
		scp->rseq = h->ident;
		sppp_wq_add(sp->wq_cp, &scp->work_rtr);
		break;
	case TERM_ACK:
		if (h->ident != scp->confid &&
		    h->ident != scp->seq) {
			SPPP_DLOG(sp, "%s id mismatch "
			    "0x%x != 0x%x and 0x%x != %0lx\n",
			    cp->name, h->ident, scp->confid,
			    h->ident, scp->seq);
			if_statinc(ifp, if_ierrors);
			break;
		}

		sppp_wq_add(sp->wq_cp, &scp->work_rta);
		break;
	case CODE_REJ:
		/* XXX catastrophic rejects (RXJ-) aren't handled yet. */
		if (sppp_rxlog_ok(sp)) {
			cpname = sppp_cp_type_name(tbuf, sizeof(tbuf),
			    h->type);
			SPPP_LOG(sp, LOG_INFO, "%s: ignoring RXJ (%s) for "
			    "code ?, danger will robinson\n", cp->name,
			    cpname);
		}
		sppp_wq_add(sp->wq_cp, &scp->work_rxj);
		break;
	case PROTO_REJ:
	    {
		int catastrophic;
		const struct cp *upper;
		int i;
		uint16_t proto;

		/* Header plus the 2-byte rejected protocol read below. */
		if (len < 6) {
			SPPP_DLOG(sp, "%s invalid proto-rej length %d\n",
			    cp->name, len);
			if_statinc(ifp, if_ierrors);
			break;
		}
		catastrophic = 0;
		upper = NULL;
		proto = p[0] << 8 | p[1];
		for (i = 0; i < IDX_COUNT; i++) {
			if (cps[i]->proto == proto) {
				upper = cps[i];
				break;
			}
		}
		if (upper == NULL)
			catastrophic++;

		if (debug) {
			cpname = sppp_cp_type_name(tbuf, sizeof(tbuf), h->type);
			SPPP_LOG(sp, LOG_INFO,
			    "%s: RXJ%c (%s) for proto 0x%x (%s/%s)\n",
			    cp->name, catastrophic ? '-' : '+',
			    cpname, proto, upper ? upper->name : "unknown",
			    upper ? sppp_state_name(sp->scp[upper->protoidx].state) : "?");
		}

		/*
		 * if we got RXJ+ against conf-req, the peer does not implement
		 * this particular protocol type.  terminate the protocol.
		 */
		if (upper && !catastrophic) {
			if (sp->scp[upper->protoidx].state == STATE_REQ_SENT) {
				sppp_wq_add(sp->wq_cp,
				    &sp->scp[upper->protoidx].work_close);
				break;
			}
		}
		sppp_wq_add(sp->wq_cp, &scp->work_rxj);
		break;
	    }
	case DISC_REQ:
		if (cp->proto != PPP_LCP)
			goto illegal;
		/* Discard the packet. */
		break;
	case ECHO_REQ:
		if (cp->proto != PPP_LCP)
			goto illegal;
		if (scp->state != STATE_OPENED) {
			SPPP_DLOG(sp, "lcp echo req but lcp closed\n");
			if_statinc(ifp, if_ierrors);
			break;
		}
		if (len < 8) {
			SPPP_DLOG(sp, "invalid lcp echo request "
			       "packet length: %d bytes\n", len);
			break;
		}
		memcpy(&u32, h + 1, sizeof u32);
		/* Without a negotiated magic both ends send 0: no loop test. */
		if (ISSET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC) &&
		    ntohl(u32) == sp->lcp.magic) {
			/* Line loopback mode detected. */
			SPPP_DLOG(sp, "loopback\n");

			/* Shut down the PPP link. */
			if (sp->pp_flags & PP_IFDOWN)
				sppp_wq_add(sp->wq_cp, &sp->work_ifdown);

			/* Reset the PPP link. */
			sppp_wq_add(sp->wq_cp,
			    &sp->scp[IDX_LCP].work_close);
			sppp_wq_add(sp->wq_cp,
			    &sp->scp[IDX_LCP].work_open);
			break;
		}
		u32 = htonl(sp->lcp.magic);
		memcpy(h + 1, &u32, sizeof u32);
		SPPP_DLOG(sp, "got lcp echo req, sending echo rep\n");
		sppp_cp_send(sp, PPP_LCP, ECHO_REPLY, h->ident, len - 4,
		    h + 1);
		break;
	case ECHO_REPLY:
		if (cp->proto != PPP_LCP)
			goto illegal;
		if (h->ident != sp->lcp.echoid) {
			if_statinc(ifp, if_ierrors);
			break;
		}
		if (len < 8) {
			SPPP_DLOG(sp, "lcp invalid echo reply "
			    "packet length: %d bytes\n", len);
			break;
		}
		SPPP_DLOG(sp, "lcp got echo rep\n");
		memcpy(&u32, h + 1, sizeof u32);
		if (! ISSET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC) ||
		    ntohl(u32) != sp->lcp.magic)
			sp->pp_alivecnt = 0;
		break;
	default:
		/* Unknown packet type -- send Code-Reject packet. */
	  illegal:
		SPPP_DLOG(sp, "%s send code-rej for 0x%x\n",
		    cp->name, h->type);
		sppp_cp_send(sp, cp->proto, CODE_REJ,
		    ++scp->seq, m->m_pkthdr.len, h);
		if_statinc(ifp, if_ierrors);
	}

out:
	m_freem(m);
}

/*
 * The generic part of all Up/Down/Open/Close/TO event handlers.
 * Basically, the state transition handling in the automaton.
 */
static void
sppp_up_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if ((cp->flags & CP_AUTH) != 0 &&
	    sppp_auth_role(cp, sp) == SPPP_AUTH_NOROLE)
		return;

	SPPP_DLOG(sp, "%s up(%s)\n", cp->name,
	    sppp_state_name(sp->scp[cp->protoidx].state));

	switch (sp->scp[cp->protoidx].state) {
	case STATE_INITIAL:
		sppp_cp_change_state(cp, sp, STATE_CLOSED);
		break;
	case STATE_STARTING:
		sp->scp[cp->protoidx].rst_counter = sp->lcp.max_configure;
		(cp->scr)(sp);
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG,
		    "%s illegal up in state %s\n", cp->name,
		    sppp_state_name(sp->scp[cp->protoidx].state));
	}
}

static void
sppp_down_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if ((cp->flags & CP_AUTH) != 0 &&
	    sppp_auth_role(cp, sp) == SPPP_AUTH_NOROLE)
		return;

	SPPP_DLOG(sp, "%s down(%s)\n", cp->name,
	    sppp_state_name(sp->scp[cp->protoidx].state));

	switch (sp->scp[cp->protoidx].state) {
	case STATE_CLOSED:
	case STATE_CLOSING:
		sppp_cp_change_state(cp, sp, STATE_INITIAL);
		break;
	case STATE_STOPPED:
		(cp->tls)(cp, sp);
		/* fall through */
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		break;
	case STATE_OPENED:
		(cp->tld)(sp);
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		break;
	default:
		/*
		 * a down event may be caused regardless
		 * of state just in LCP case.
		 */
		if (cp->proto == PPP_LCP)
			break;

		SPPP_LOG(sp, LOG_DEBUG,
		    "%s illegal down in state %s\n", cp->name,
		    sppp_state_name(sp->scp[cp->protoidx].state));
	}
}

static void
sppp_open_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if ((cp->flags & CP_AUTH) != 0 &&
	    sppp_auth_role(cp, sp) == SPPP_AUTH_NOROLE)
		return;

	SPPP_DLOG(sp, "%s open(%s)\n", cp->name,
	    sppp_state_name(sp->scp[cp->protoidx].state));

	switch (sp->scp[cp->protoidx].state) {
	case STATE_INITIAL:
		sppp_cp_change_state(cp, sp, STATE_STARTING);
		(cp->tls)(cp, sp);
		break;
	case STATE_STARTING:
		break;
	case STATE_CLOSED:
		sp->scp[cp->protoidx].rst_counter = sp->lcp.max_configure;
		sp->lcp.protos |= (1 << cp->protoidx);
		(cp->scr)(sp);
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	case STATE_STOPPED:
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
	case STATE_OPENED:
		break;
	case STATE_CLOSING:
		sppp_cp_change_state(cp, sp, STATE_STOPPING);
		break;
	}
}

static void
sppp_close_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if ((cp->flags & CP_AUTH) != 0 &&
	    sppp_auth_role(cp, sp) == SPPP_AUTH_NOROLE)
		return;

	SPPP_DLOG(sp, "%s close(%s)\n", cp->name,
	    sppp_state_name(sp->scp[cp->protoidx].state));

	switch (sp->scp[cp->protoidx].state) {
	case STATE_INITIAL:
	case STATE_CLOSED:
	case STATE_CLOSING:
		break;
	case STATE_STARTING:
		sppp_cp_change_state(cp, sp, STATE_INITIAL);
		(cp->tlf)(cp, sp);
		break;
	case STATE_STOPPED:
		sppp_cp_change_state(cp, sp, STATE_CLOSED);
		break;
	case STATE_STOPPING:
		sppp_cp_change_state(cp, sp, STATE_CLOSING);
		break;
	case STATE_OPENED:
		(cp->tld)(sp);
		/* fall through */
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		sp->scp[cp->protoidx].rst_counter = sp->lcp.max_terminate;
		if ((cp->flags & CP_AUTH) == 0) {
			sppp_cp_send(sp, cp->proto, TERM_REQ,
			    ++sp->scp[cp->protoidx].seq, 0, 0);
		}
		sppp_cp_change_state(cp, sp, STATE_CLOSING);
		break;
	}
}

static void
sppp_to_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	SPPP_DLOG(sp, "%s TO(%s) rst_counter = %d\n", cp->name,
	    sppp_state_name(sp->scp[cp->protoidx].state),
	    sp->scp[cp->protoidx].rst_counter);

	if (--sp->scp[cp->protoidx].rst_counter < 0)
		/* TO- event */
		switch (sp->scp[cp->protoidx].state) {
		case STATE_CLOSING:
			sppp_cp_change_state(cp, sp, STATE_CLOSED);
			(cp->tlf)(cp, sp);
			break;
		case STATE_STOPPING:
			sppp_cp_change_state(cp, sp, STATE_STOPPED);
			(cp->tlf)(cp, sp);
			break;
		case STATE_REQ_SENT:
		case STATE_ACK_RCVD:
		case STATE_ACK_SENT:
			sppp_cp_change_state(cp, sp, STATE_STOPPED);
			(cp->tlf)(cp, sp);
			break;
		}
	else
		/* TO+ event */
		switch (sp->scp[cp->protoidx].state) {
		case STATE_CLOSING:
		case STATE_STOPPING:
			if ((cp->flags & CP_AUTH) == 0) {
				sppp_cp_send(sp, cp->proto, TERM_REQ,
				    ++sp->scp[cp->protoidx].seq, 0, 0);
			}
			callout_schedule(&sp->scp[cp->protoidx].ch, sp->lcp.timeout);
			break;
		case STATE_REQ_SENT:
		case STATE_ACK_RCVD:
			(cp->scr)(sp);
			/* sppp_cp_change_state() will restart the timer */
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			break;
		case STATE_ACK_SENT:
			(cp->scr)(sp);
			callout_schedule(&sp->scp[cp->protoidx].ch, sp->lcp.timeout);
			break;
		}
}
static void
sppp_rcr_update_state(const struct cp *cp, struct sppp *sp,
    enum cp_rcr_type type, uint8_t ident, size_t msglen, void *msg)
{
	struct ifnet *ifp = sp->pp_if;
	u_char ctype;

	if (type == CP_RCR_ERR) {
		/* parse error, shut down */
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
	} else if (type == CP_RCR_ACK) {
		/* RCR+ event */
		ctype = CONF_ACK;
		switch (sp->scp[cp->protoidx].state) {
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
			cp->tld(sp);
			cp->scr(sp);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_REQ_SENT:
			sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
			/* fall through */
		case STATE_ACK_SENT:
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_STOPPED:
			sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
			cp->scr(sp);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_OPENED);
			SPPP_DLOG(sp, "%s tlu\n", cp->name);
			cp->tlu(sp);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_CLOSING:
		case STATE_STOPPING:
			break;
		case STATE_CLOSED:
			if ((cp->flags & CP_AUTH) == 0) {
				sppp_cp_send(sp, cp->proto, TERM_ACK,
				    ident, 0, 0);
			}
			break;
		default:
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "%s illegal RCR+ in state %s\n", cp->name,
				    sppp_state_name(
				    sp->scp[cp->protoidx].state));
			if_statinc(ifp, if_ierrors);
		}
	} else if (type == CP_RCR_NAK || type == CP_RCR_REJ) {
		ctype = type == CP_RCR_NAK ? CONF_NAK : CONF_REJ;
		/* RCR- event */
		switch (sp->scp[cp->protoidx].state) {
		case STATE_OPENED:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			cp->tld(sp);
			cp->scr(sp);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_ACK_SENT:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			/* fall through */
		case STATE_REQ_SENT:
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_STOPPED:
			sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
			cp->scr(sp);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_ACK_RCVD:
			sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
			cp->screply(cp, sp, ctype, ident, msglen, msg);
			break;
		case STATE_CLOSING:
		case STATE_STOPPING:
			break;
		case STATE_CLOSED:
			sppp_cp_change_state(cp, sp, STATE_CLOSED);
			if ((cp->flags & CP_AUTH) == 0) {
				sppp_cp_send(sp, cp->proto, TERM_ACK,
				    ident, 0, 0);
			}
			break;
		default:
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "%s illegal RCR- in state %s\n", cp->name,
				    sppp_state_name(
				    sp->scp[cp->protoidx].state));
			if_statinc(ifp, if_ierrors);
		}
	}
}

static void
sppp_rcr_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	struct sppp_cp *scp;
	struct lcp_header *h;
	struct mbuf *m;
	enum cp_rcr_type type;
	size_t len;
	uint8_t *buf;
	size_t blen, rlen;
	uint8_t ident;

	SPPP_KASSERT(!cpu_softintr_p());

	scp = &sp->scp[cp->protoidx];

	if (cp->parse_confreq != NULL) {
		m = scp->mbuf_confreq;
		if (m == NULL)
			return;
		scp->mbuf_confreq = NULL;

		h = mtod(m, struct lcp_header *);
		if (h->type != CONF_REQ) {
			m_freem(m);
			return;
		}

		ident = h->ident;
		len = MIN(m->m_pkthdr.len, ntohs(h->len));

		/*
		 * The parsers leave these unset on CP_RCR_DROP/CP_RCR_ERR;
		 * NetBSD then freed an uninitialized buf below.
		 */
		buf = NULL;
		blen = rlen = 0;
		type = (cp->parse_confreq)(sp, h, len,
		    &buf, &blen, &rlen);
		m_freem(m);
	} else {
		/* mbuf_cofreq is already parsed and freed */
		type = scp->rcr_type;
		ident = scp->rconfid;
		buf = NULL;
		blen = rlen = 0;
	}

	sppp_rcr_update_state(cp, sp, type, ident, rlen, (void *)buf);

	if (buf != NULL)
		kmem_free(buf, blen);
}

static void
sppp_rca_event(struct sppp *sp, void *xcp)
{
	struct ifnet *ifp = sp->pp_if;
	const struct cp *cp = xcp;

	SPPP_KASSERT(!cpu_softintr_p());

	switch (sp->scp[cp->protoidx].state) {
	case STATE_CLOSED:
	case STATE_STOPPED:
		if ((cp->flags & CP_AUTH) == 0) {
			sppp_cp_send(sp, cp->proto, TERM_ACK,
			    sp->scp[cp->protoidx].rconfid, 0, 0);
		}
		break;
	case STATE_CLOSING:
	case STATE_STOPPING:
		break;
	case STATE_REQ_SENT:
		sp->scp[cp->protoidx].rst_counter = sp->lcp.max_configure;
		sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
		break;
	case STATE_OPENED:
		(cp->tld)(sp);
		/* fall through */
	case STATE_ACK_RCVD:
		(cp->scr)(sp);
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	case STATE_ACK_SENT:
		sppp_cp_change_state(cp, sp, STATE_OPENED);
		sp->scp[cp->protoidx].rst_counter = sp->lcp.max_configure;
		SPPP_DLOG(sp, "%s tlu\n", cp->name);
		(cp->tlu)(sp);
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG,
		    "%s illegal RCA in state %s\n", cp->name,
		    sppp_state_name(sp->scp[cp->protoidx].state));
		if_statinc(ifp, if_ierrors);
	}
}

static void
sppp_rcn_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	struct sppp_cp *scp;
	struct lcp_header *h;
	struct mbuf *m;
	struct ifnet *ifp = sp->pp_if;
	size_t len;

	SPPP_KASSERT(!cpu_softintr_p());

	scp = &sp->scp[cp->protoidx];
	m = scp->mbuf_confnak;
	if (m == NULL)
		return;
	scp->mbuf_confnak = NULL;

	h = mtod(m, struct lcp_header *);
	len = MIN(m->m_pkthdr.len, ntohs(h->len));

	switch (h->type) {
	case CONF_NAK:
		(cp->parse_confnak)(sp, h, len);
		break;
	case CONF_REJ:
		(cp->parse_confrej)(sp, h, len);
		break;
	default:
		m_freem(m);
		return;
	}

	m_freem(m);

	switch (scp->state) {
	case STATE_CLOSED:
	case STATE_STOPPED:
		if ((cp->flags & CP_AUTH) == 0) {
			sppp_cp_send(sp, cp->proto, TERM_ACK,
			    scp->rconfid, 0, 0);
		}
		break;
	case STATE_REQ_SENT:
	case STATE_ACK_SENT:
		scp->rst_counter = sp->lcp.max_configure;
		(cp->scr)(sp);
		break;
	case STATE_OPENED:
		(cp->tld)(sp);
		/* fall through */
	case STATE_ACK_RCVD:
		sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
		(cp->scr)(sp);
		break;
	case STATE_CLOSING:
	case STATE_STOPPING:
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG, "%s illegal RCN in state %s\n",
		    cp->name, sppp_state_name(scp->state));
		if_statinc(ifp, if_ierrors);
	}
}

static void
sppp_rtr_event(struct sppp *sp, void *xcp)
{
	struct ifnet *ifp = sp->pp_if;
	const struct cp *cp = xcp;

	SPPP_KASSERT(!cpu_softintr_p());

	switch (sp->scp[cp->protoidx].state) {
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_CLOSING:
	case STATE_STOPPING:
	case STATE_REQ_SENT:
		break;
	case STATE_OPENED:
		/* Hung up on our auth without a NAK: count it before tld. */
		if ((cp->flags & CP_LCP) != 0 &&
		    sp->pp_phase == SPPP_PHASE_AUTHENTICATE) {
			if (sppp_auth_awaited(sp, &pap))
				sppp_auth_unanswered(sp, &pap,
				    "terminated by peer");
			else if (sppp_auth_awaited(sp, &chap))
				sppp_auth_unanswered(sp, &chap,
				    "terminated by peer");
		}
		(cp->tld)(sp);
		sp->scp[cp->protoidx].rst_counter = 0;
		sppp_cp_change_state(cp, sp, STATE_STOPPING);
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG, "%s illegal RTR in state %s\n",
		    cp->name,
		    sppp_state_name(sp->scp[cp->protoidx].state));
		if_statinc(ifp, if_ierrors);
		return;
	}

	/* Send Terminate-Ack packet. */
	SPPP_DLOG(sp, "%s send terminate-ack\n", cp->name);
	if ((cp->flags & CP_AUTH) == 0) {
		sppp_cp_send(sp, cp->proto, TERM_ACK,
		    sp->scp[cp->protoidx].rseq, 0, 0);
	}
}

static void
sppp_rta_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	struct ifnet *ifp = sp->pp_if;

	SPPP_KASSERT(!cpu_softintr_p());

	switch (sp->scp[cp->protoidx].state) {
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_REQ_SENT:
	case STATE_ACK_SENT:
		break;
	case STATE_CLOSING:
		sppp_cp_change_state(cp, sp, STATE_CLOSED);
		(cp->tlf)(cp, sp);
		break;
	case STATE_STOPPING:
		sppp_cp_change_state(cp, sp, STATE_STOPPED);
		(cp->tlf)(cp, sp);
		break;
	case STATE_ACK_RCVD:
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	case STATE_OPENED:
		(cp->tld)(sp);
		(cp->scr)(sp);
		sppp_cp_change_state(cp, sp, STATE_ACK_RCVD);
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG, "%s illegal RTA in state %s\n",
		    cp->name,  sppp_state_name(sp->scp[cp->protoidx].state));
		if_statinc(ifp, if_ierrors);
	}
}

static void
sppp_rxj_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	struct ifnet *ifp = sp->pp_if;

	SPPP_KASSERT(!cpu_softintr_p());

	/* XXX catastrophic rejects (RXJ-) aren't handled yet. */
	switch (sp->scp[cp->protoidx].state) {
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_REQ_SENT:
	case STATE_ACK_SENT:
	case STATE_CLOSING:
	case STATE_STOPPING:
	case STATE_OPENED:
		break;
	case STATE_ACK_RCVD:
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		break;
	default:
		SPPP_LOG(sp, LOG_DEBUG, "%s illegal RXJ- in state %s\n",
		    cp->name,  sppp_state_name(sp->scp[cp->protoidx].state));
		if_statinc(ifp, if_ierrors);
	}
}

/*
 * Change the state of a control protocol in the state automaton.
 * Takes care of starting/stopping the restart timer.
 */
void
sppp_cp_change_state(const struct cp *cp, struct sppp *sp, int newstate)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sp->scp[cp->protoidx].state = newstate;
	sppp_dp_update(sp, cp->protoidx, newstate);
	callout_stop(&sp->scp[cp->protoidx].ch);
	switch (newstate) {
	case STATE_INITIAL:
	case STATE_STARTING:
	case STATE_CLOSED:
	case STATE_STOPPED:
	case STATE_OPENED:
		break;
	case STATE_CLOSING:
	case STATE_STOPPING:
	case STATE_REQ_SENT:
	case STATE_ACK_RCVD:
	case STATE_ACK_SENT:
		callout_schedule(&sp->scp[cp->protoidx].ch, sp->lcp.timeout);
		break;
	}
}

/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                         The LCP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */
static void
sppp_lcp_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_cp_init(&lcp, sp);

	SET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC);
	sp->lcp.magic = 0;
	sp->lcp.protos = 0;
	sp->lcp.max_terminate = 2;
	sp->lcp.max_configure = 10;
	sp->lcp.max_failure = 10;
	sp->lcp.lower_running = false;
	/* The RFC 1661 default until sppp_lcp_open(); bounds sppp_cp_send(). */
	sp->lcp.their_mru = PP_MTU;

	/*
	 * Initialize counters and timeout values.  Note that we don't
	 * use the 3 seconds suggested in RFC 1661 since we are likely
	 * running on a fast link.  XXX We should probably implement
	 * the exponential backoff option.  Note that these values are
	 * relevant for all control protocols, not just LCP only.
	 */
	sp->lcp.timeout = 1 * hz;
}

static void
sppp_lcp_up(struct sppp *sp, void *xcp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/* Initialize timestamps: opening a connection is a sign of life */
	atomic_store_relaxed(&sp->pp_last_receive, time_uptime32);

	/* A new session: an illegal Up must not reset an open one. */
	if (sp->scp[IDX_LCP].state == STATE_INITIAL ||
	    sp->scp[IDX_LCP].state == STATE_STARTING)
		sppp_lcp_defaults(sp);
	sppp_up_event(sp, xcp);
}

static void
sppp_lcp_down(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	int pidx = cp->protoidx;
	int ostate;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	ostate = sp->scp[pidx].state;
	sppp_down_event(sp, xcp);

	switch (sp->scp[pidx].state) {
	case STATE_STARTING:
		/*
		 * The lower layer went down under a live LCP (Stopping, the
		 * ISP's PADT beating its Terminate-Ack after an auth NAK, or
		 * Req-Sent ... Opened) and no tlf released it, so the tls
		 * below would be a no-op and the driver's own PADT redial
		 * would dial every PPPOE_RECON_PADTRCVD.  While an auth
		 * backoff applies, release it here so tls holds the dial.
		 * Not from Starting (defence in depth; the driver no longer
		 * latches a stale Down): a Down there must not tear down the
		 * dial the backoff let through.
		 */
		if (ostate != STATE_STARTING && sp->lcp.lower_running &&
		    !sp->pp_dial_armed && sppp_auth_backoff(sp) > 0)
			cp->tlf(cp, sp);
		/*
		 * Req-Sent/Ack-Sent/Ack-Rcvd -> Starting:
		 * This transition requires an extra TLS action.
		 * * sequence of events/actions:
		 * 1. Closing -> Closed      : Triggers TLF  action.
		 * 2. Closed  -> Req-Sent    : Occurs on Open event.
		 * 3. Req-Sent -> Ack-Sent...: (Optional state progression)
		 * 4. Req-Sent/Ack-Sent/Ack-Rcvd -> Starting:
		 *    - Triggered by a Down event caused by the previous TLF action.
		 *    - This specific transition does NOT trigger another TLS action.
		 */
		cp->tls(cp, sp);
		break;
	case STATE_INITIAL:
		/*
		 * Closing -> Initial:
		 * A Down event in the Closing state triggers a transition to
		 * Initial state without a TLF action. Since the lower layer
		 * will attempt to reconnect, we explicitly stop it here.
		 */
		cp->tlf(cp, sp);
		break;
	}

	SPPP_DLOG(sp, "Down event (carrier loss)\n");

	sp->scp[pidx].fail_counter = 0;
}

static void
sppp_lcp_open(struct sppp *sp, void *xcp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	sp->scp[IDX_LCP].fail_counter = 0;
	sppp_lcp_defaults(sp);
	sppp_open_event(sp, xcp);
}

/*
 * Put the LCP options back to their configured defaults, so that what a
 * previous session's peer rejected or nak'ed, and its MRU, cannot carry
 * over.  Run at LCP Open and at every lower-layer Up: for PPPoE the Up is
 * a new session, and it comes after the PADS has set if_mtu (the RFC 4638
 * grant or its 1492 fallback), which Open usually precedes.
 */
static void
sppp_lcp_defaults(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (sp->pp_if->if_mtu < PP_MTU) {
		sp->lcp.mru = sp->pp_if->if_mtu;
		SET(sp->lcp.opts, SPPP_LCP_OPT_MRU);
	} else {
		sp->lcp.mru = PP_MTU;
		CLR(sp->lcp.opts, SPPP_LCP_OPT_MRU);
	}
	sp->lcp.their_mru = PP_MTU;
	SET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC);

	/*
	 * If we are authenticator, negotiate LCP_AUTH
	 */
	if (sp->hisauth.proto != PPP_NOPROTO)
		SET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);
	else
		CLR(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);
	sp->pp_flags &= ~PP_NEEDAUTH;
}

/*
 * Analyze a configure request.  Return true if it was agreeable, and
 * caused action sca, false if it has been rejected or nak'ed, and
 * caused action scn.  (The return value is used to make the state
 * transition decision in the state automaton.)
 */
static enum cp_rcr_type
sppp_lcp_confreq(struct sppp *sp, struct lcp_header *h, int origlen,
    uint8_t **msgbuf, size_t *buflen, size_t *msglen)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *buf, *r, *p, l, naklen;
	size_t blen;
	enum cp_rcr_type type;
	int len, rlen;
	uint32_t nmagic;
	u_short authproto;
	char lbuf[SPPP_LCPOPT_NAMELEN];

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (origlen < sizeof(*h))
		return CP_RCR_DROP;

	origlen -= sizeof(*h);
	type = CP_RCR_NONE;
	type = 0;

	/*
	 * RFC 1661 5.1: no options asks for all defaults and is ACK'd;
	 * NetBSD dropped it.  kmem(9) wants a non-zero size.
	 */
	blen = MAX(1, origlen);

	buf = kmem_intr_alloc(blen, KM_NOSLEEP);
	if (buf == NULL)
		return CP_RCR_DROP;

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "lcp parse opts:");

	/* pass 1: check for things that need to be rejected */
	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	for (len = origlen; len > 1; len-= l, p += l) {
		l = p[1];
		if (l < 2) {
			/*
			 * An option can't be shorter than its own type and
			 * length octets.  NetBSD stopped parsing here and went
			 * on to ACK the whole list, copying it into buf.
			 */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "lcp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		/* Sanity check option length */
		if (l > len) {
			/*
			 * Malicious option - drop immediately.
			 * XXX Maybe we should just RXJ it?
			 */
			if (debug)
				addlog("\n");

			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious LCP option 0x%02x, "
				    "length 0x%02x, (len: 0x%02x) dropping.\n",
				    p[0], l, len);
			type = CP_RCR_ERR;
			goto end;
		}
		if (debug)
			addlog(" %s", sppp_lcp_opt_name(lbuf, sizeof(lbuf), *p));
		switch (p[0]) {
		case LCP_OPT_MAGIC:
			/* Magic number. */
			/* fall through, both are same length */
		case LCP_OPT_ASYNC_MAP:
			/* Async control character map. */
			if (len >= 6 && l == 6)
				continue;
			if (debug)
				addlog(" [invalid]");
			break;
		case LCP_OPT_MP_EID:
			if (len >= l && l >= 3) {
				switch (p[2]) {
				case 0: if (l==3+ 0) continue;break;
				case 2: if (l==3+ 4) continue;break;
				case 3: if (l==3+ 6) continue;break;
				case 6: if (l==3+16) continue;break;
				case 1: /* FALLTHROUGH */
				case 4: if (l<=3+20) continue;break;
				case 5: if (l<=3+15) continue;break;
				/* XXX should it be default: continue;? */
				}
			}
			/* l < 3 means no class octet (p[2]) on the wire. */
			if (debug) {
				if (l >= 3)
					addlog(" [invalid class %d len %d]",
					    p[2], l);
				else
					addlog(" [invalid len %d]", l);
			}
			break;
		case LCP_OPT_MP_SSNHF:
			if (len >= 2 && l == 2) {
				if (debug)
					addlog(" [rej]");
				break;
			}
			if (debug)
				addlog(" [invalid]");
			break;
		case LCP_OPT_MP_MRRU:
			/* Multilink maximum received reconstructed unit */
			/* should be fall through, both are same length */
			/* FALLTHROUGH */
		case LCP_OPT_MRU:
			/* Maximum receive unit. */
			if (len >= 4 && l == 4)
				continue;
			if (debug)
				addlog(" [invalid]");
			break;
		case LCP_OPT_AUTH_PROTO:
			if (l < 4) {
				if (debug)
					addlog(" [invalid]");
				break;
			}
			authproto = (p[2] << 8) + p[3];
			if (authproto == PPP_CHAP && l != 5) {
				if (debug)
					addlog(" [invalid chap len]");
				break;
			}
			if (ISSET(sp->myauth.flags, SPPP_AUTHFLAG_PASSIVEAUTHPROTO)) {
				if (authproto == PPP_PAP || authproto == PPP_CHAP)
					sp->myauth.proto = authproto;
			}
			if (sp->myauth.proto == PPP_NOPROTO) {
				/* we are not configured to do auth */
				if (debug)
					addlog(" [not configured]");
				break;
			}
			/*
			 * Remote want us to authenticate, remember this,
			 * so we stay in SPPP_PHASE_AUTHENTICATE after LCP got
			 * up.
			 */
			sp->pp_flags |= PP_NEEDAUTH;
			continue;
		default:
			/* Others not supported. */
			if (debug)
				addlog(" [rej]");
			break;
		}
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		/* Add the option to rejected list. */
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	/*
	 * The loop leaves len at 0 or 1; 1 is a lone octet after the
	 * last option, which NetBSD went on to REJ/NAK/ACK with it.
	 */
	if (len != 0) {
		if (debug)
			addlog("\n");
		SPPP_DLOG(sp, "lcp trailing octet 0x%02x, "
		    "dropping\n", p[0]);
		type = CP_RCR_DROP;
		goto end;
	}

	if (rlen > 0) {
		type = CP_RCR_REJ;
		goto end;
	}

	if (debug)
		addlog("\n");

	/*
	 * pass 2: check for option values that are unacceptable and
	 * thus require to be nak'ed.
	 */
	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "lcp parse opt values:");

	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	for (len = origlen; len > 1; len -= l, p += l) {
		l = p[1];
		if (l < 2 || l > len) {
			/* Sanity check option length, same as pass 1. */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "lcp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		if (debug)
			addlog(" %s", sppp_lcp_opt_name(lbuf, sizeof(lbuf), *p));
		switch (p[0]) {
		case LCP_OPT_MAGIC:
			/* Magic number -- extract. */
			nmagic = (uint32_t)p[2] << 24 |
				(uint32_t)p[3] << 16 | p[4] << 8 | p[5];
			if (nmagic != sp->lcp.magic) {
				if (debug)
					addlog(" 0x%x", nmagic);
				continue;
			}
			/*
			 * Local and remote magics equal -- loopback?
			 */
			if (sp->pp_loopcnt >= LOOPALIVECNT*5) {
				SPPP_DLOG(sp, "loopback\n");
				sp->pp_loopcnt = 0;

				if (sp->pp_flags & PP_IFDOWN)
					sppp_wq_add(sp->wq_cp, &sp->work_ifdown);
				sppp_wq_add(sp->wq_cp,
				    &sp->scp[IDX_LCP].work_close);
				sppp_wq_add(sp->wq_cp,
				    &sp->scp[IDX_LCP].work_open);
			} else {
				if (debug)
					addlog(" [glitch]");
				++sp->pp_loopcnt;
			}
			/*
			 * We negate our magic here, and NAK it.  If
			 * we see it later in an NAK packet, we
			 * suggest a new one.
			 */
			nmagic = ~sp->lcp.magic;
			/* Gonna NAK it. */
			p[2] = nmagic >> 24;
			p[3] = nmagic >> 16;
			p[4] = nmagic >> 8;
			p[5] = nmagic;
			break;

		case LCP_OPT_ASYNC_MAP:
			/*
			 * Async control character map -- just ignore it.
			 *
			 * Quote from RFC 1662, chapter 6:
			 * To enable this functionality, synchronous PPP
			 * implementations MUST always respond to the
			 * Async-Control-Character-Map Configuration
			 * Option with the LCP Configure-Ack.  However,
			 * acceptance of the Configuration Option does
			 * not imply that the synchronous implementation
			 * will do any ACCM mapping.  Instead, all such
			 * octet mapping will be performed by the
			 * asynchronous-to-synchronous converter.
			 */
			continue;

		case LCP_OPT_MRU:
			/*
			 * Maximum receive unit; if_mtu follows it from LCP
			 * up (sppp_lcp_tlu).  Accepted range [PPP_MINMRU (128),
			 * 65535]: the top is the 16-bit field, and the driver
			 * caps if_mtu by the link MTU.  Below 128, the floor
			 * SIOCSIFMTU and our own Nak handling use too, nak
			 * with 128 (RFC 1661 5.3) rather than shrink if_mtu.
			 */
			if (p[2] * 256 + p[3] < PPP_MINMRU) {
				if (debug)
					addlog(" %d [too small]",
					    p[2] * 256 + p[3]);
				p[2] = PPP_MINMRU >> 8;
				p[3] = PPP_MINMRU & 0xff;
				break;
			}
			sp->lcp.their_mru = p[2] * 256 + p[3];
			if (debug)
				addlog(" %ld", sp->lcp.their_mru);
			continue;

		case LCP_OPT_AUTH_PROTO:
			authproto = (p[2] << 8) + p[3];
			if (ISSET(sp->myauth.flags, SPPP_AUTHFLAG_PASSIVEAUTHPROTO)) {
				if (authproto == PPP_PAP || authproto == PPP_CHAP)
					sp->myauth.proto = authproto;
			}
			if (sp->myauth.proto == authproto) {
				if (authproto != PPP_CHAP || p[4] == CHAP_MD5) {
					continue;
				}
				if (debug)
					addlog(" [chap without MD5]");
			} else {
				if (debug) {
					char pbuf1[SPPP_PROTO_NAMELEN];
					char pbuf2[SPPP_PROTO_NAMELEN];
					const char *pname1, *pname2;

					pname1 = sppp_proto_name(pbuf1,
					    sizeof(pbuf1), sp->myauth.proto);
					pname2 = sppp_proto_name(pbuf2,
					    sizeof(pbuf2), authproto);
					addlog(" [mine %s != his %s]",
					       pname1, pname2);
				}
			}
			/* not agreed, nak: naklen != l, the loop stride */
			if (sp->myauth.proto == PPP_CHAP) {
				naklen = 5;
			} else {
				naklen = 4;
			}

			if (rlen + naklen > blen) {
				if (debug)
					addlog(" [overflow]");
				continue;
			}

			r[0] = LCP_OPT_AUTH_PROTO;
			r[1] = naklen;
			r[2] = sp->myauth.proto >> 8;
			r[3] = sp->myauth.proto & 0xff;
			if (sp->myauth.proto == PPP_CHAP)
				r[4] = CHAP_MD5;
			rlen += naklen;
			r += naklen;
			continue;
		case LCP_OPT_MP_EID:
			/*
			 * Endpoint identification.
			 * Always agreeable,
			 * but ignored by now.
			 */
			if (debug) {
				addlog(" type %d", p[2]);
				if (l > 3)
					sppp_print_bytes(p+3, l-3);
			}
			continue;
		case LCP_OPT_MP_MRRU:
			/*
			 * Maximum received reconstructed unit. 
			 * Always agreeable,
			 * but ignored by now.
			 */
			sp->lcp.their_mrru = p[2] * 256 + p[3];
			if (debug)
				addlog(" %ld", sp->lcp.their_mrru);
			continue;
		}
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		/* Add the option to nak'ed list. */
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	if (rlen > 0) {
		if (++sp->scp[IDX_LCP].fail_counter >= sp->lcp.max_failure) {
			if (debug)
				addlog(" max_failure (%d) exceeded, ",
				    sp->lcp.max_failure);
			type = CP_RCR_REJ;
		} else {
			type = CP_RCR_NAK;
		}
	} else {
		type = CP_RCR_ACK;
		rlen = origlen;
		memcpy(r, h + 1, rlen);
		sp->scp[IDX_LCP].fail_counter = 0;
		sp->pp_loopcnt = 0;
	}

end:
	if (debug)
		addlog("\n");

	if (type == CP_RCR_ERR || type == CP_RCR_DROP) {
		if (buf != NULL)
			kmem_intr_free(buf, blen);
	} else {
		*msgbuf = buf;
		*buflen = blen;
		*msglen = rlen;
	}

	return type;
}

/*
 * Analyze the LCP Configure-Reject option list, and adjust our
 * negotiation.
 */
static void
sppp_lcp_confrej(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len <= sizeof(*h))
		return;

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "lcp rej opts:");

	p = (void *)(h + 1);
	for (; len > 1 && (l = p[1]) != 0; len -= l, p += l) {
		/* Sanity check option length */
		if (l > len) {
			/*
			 * Malicious option - drop immediately.
			 * XXX Maybe we should just RXJ it?
			 */
			if (debug)
				addlog("\n");

			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious LCP option, "
				    "dropping.\n");
			goto end;
		}
		if (debug) {
			char lbuf[SPPP_LCPOPT_NAMELEN];
			addlog(" %s", sppp_lcp_opt_name(lbuf, sizeof(lbuf), *p));
		}
		switch (p[0]) {
		case LCP_OPT_MAGIC:
			/* Magic number -- can't use it, use 0 */
			CLR(sp->lcp.opts, SPPP_LCP_OPT_MAGIC);
			sp->lcp.magic = 0;
			break;
		case LCP_OPT_MRU:
			/*
			 * We try to negotiate a lower MRU if the underlying
			 * link's MTU is less than PP_MTU (e.g. PPPoE). If the
			 * peer rejects this lower rate, fallback to the
			 * default.
			 */
			if (!debug) {
				SPPP_LOG(sp, LOG_INFO,
				    "peer rejected our MRU of "
				    "%ld bytes. Defaulting to %d bytes\n",
				    sp->lcp.mru, PP_MTU);
			}
			CLR(sp->lcp.opts, SPPP_LCP_OPT_MRU);
			sp->lcp.mru = PP_MTU;
			break;
		case LCP_OPT_AUTH_PROTO:
			/*
			 * Peer doesn't want to authenticate himself,
			 * deny unless SPPP_AUTHFLAG_NOCALLOUT is set.
			 */
			if ((sp->hisauth.flags & SPPP_AUTHFLAG_NOCALLOUT) != 0) {
				if (debug) {
					addlog(" [don't insist on auth "
					       "for callout]");
				}
				CLR(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);
				break;
			}
			if (debug)
				addlog("[access denied]\n");
			sppp_disconnect(sp);
			break;
		}
	}
	if (debug)
		addlog("\n");
end:
	return;
}

/*
 * Analyze the LCP Configure-NAK option list, and adjust our
 * negotiation.
 */
static void
sppp_lcp_confnak(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;
	uint32_t magic;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len <= sizeof(*h))
		return;

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "lcp nak opts:");

	p = (void *)(h + 1);
	for (; len > 1 && (l = p[1]) != 0; len -= l, p += l) {
		/* Sanity check option length */
		if (l > len) {
			/*
			 * Malicious option - drop immediately.
			 * XXX Maybe we should just RXJ it?
			 */
			if (debug)
				addlog("\n");

			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious LCP option, "
				    "dropping.\n");
			goto end;
		}
		if (debug) {
			char lbuf[SPPP_LCPOPT_NAMELEN];
			addlog(" %s", sppp_lcp_opt_name(lbuf, sizeof(lbuf),*p));
		}
		switch (p[0]) {
		case LCP_OPT_MAGIC:
			/* Magic number -- renegotiate */
			if (ISSET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC) &&
			    len >= 6 && l == 6) {
				magic = (uint32_t)p[2] << 24 |
					(uint32_t)p[3] << 16 | p[4] << 8 | p[5];
				/*
				 * If the remote magic is our negated one,
				 * this looks like a loopback problem.
				 * Suggest a new magic to make sure.
				 */
				if (magic == (uint32_t)~sp->lcp.magic) {
					if (debug)
						addlog(" magic glitch");
					sp->lcp.magic = cprng_fast32();
				} else {
					sp->lcp.magic = magic;
					if (debug)
						addlog(" %d", magic);
				}
			}
			break;
		case LCP_OPT_MRU:
			/*
			 * Peer wants to advise us to negotiate an MRU.
			 * Agree on it if it's reasonable, or use
			 * default otherwise.
			 */
			if (len >= 4 && l == 4) {
				u_int mru = p[2] * 256 + p[3];
				if (debug)
					addlog(" %d", mru);
				if (mru < PPP_MINMRU || mru > sp->pp_if->if_mtu)
					mru = sp->pp_if->if_mtu;
				sp->lcp.mru = mru;
				SET(sp->lcp.opts, SPPP_LCP_OPT_MRU);
			}
			break;
		case LCP_OPT_AUTH_PROTO:
			/*
			 * Peer doesn't like our authentication method,
			 * deny.
			 */
			if (debug)
				addlog("[access denied]\n");
			sppp_disconnect(sp);
			break;
		}
	}
	if (debug)
		addlog("\n");
end:
	return;
}

static void
sppp_lcp_tlu(struct sppp *sp)
{
	struct ifnet *ifp = sp->pp_if;
	struct sppp_cp *scp;
	u_int mru;
	int i;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	mru = sp->lcp.their_mru;
	/* unlock for if_up() and the driver's softc lock */
	SPPP_UNLOCK(sp);

	/* the interface was down by PP_IFDOWN flag */
	if ((if_getflags(ifp) & IFF_UP) == 0 &&
	    (if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0) {
		SPPP_LOG(sp, LOG_DEBUG, "interface is going up\n");
		if_up(ifp);
	}

	/* if_mtu is the driver's to write: capped by the peer's MRU now. */
	SPPP_DLOG(sp, "peer MRU %u bytes\n", mru);
	pppoe_set_peer_mru(sp, mru);

	SPPP_LOCK(sp, RW_WRITER);

	if (ISSET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO) ||
	    (sp->pp_flags & PP_NEEDAUTH) != 0)
		sppp_change_phase(sp, SPPP_PHASE_AUTHENTICATE);
	else
		sppp_change_phase(sp, SPPP_PHASE_NETWORK);

	for (i = 0; i < IDX_COUNT; i++) {
		scp = &sp->scp[(cps[i])->protoidx];

		if (((cps[i])->flags & CP_LCP) == 0)
			sppp_wq_add(sp->wq_cp, &scp->work_up);

		/*
		 * Open all authentication protocols.  This is even required
		 * if we already proceeded to network phase, since it might be
		 * that remote wants us to authenticate, so we might have to
		 * send a PAP request.  Undesired authentication protocols
		 * don't do anything when they get an Open event.
		 */
		if ((cps[i])->flags & CP_AUTH)
			sppp_wq_add(sp->wq_cp, &scp->work_open);

		/* Open all NCPs. */
		if (sp->pp_phase == SPPP_PHASE_NETWORK &&
		    ((cps[i])->flags & CP_NCP) != 0) {
			sppp_wq_add(sp->wq_cp, &scp->work_open);
		}
	}
}

static void
sppp_lcp_tld(struct sppp *sp)
{
	struct ifnet *ifp;
	struct sppp_cp *scp;
	int i, phase;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	phase = sp->pp_phase;

	sppp_change_phase(sp, SPPP_PHASE_TERMINATE);

	/* The peer's MRU no longer caps if_mtu: back to the link MTU. */
	SPPP_UNLOCK(sp);
	pppoe_set_peer_mru(sp, 0);
	SPPP_LOCK(sp, RW_WRITER);

	/*
	 * Take upper layers down.  We send the Down event first and
	 * the Close second to prevent the upper layers from sending
	 * ``a flurry of terminate-request packets'', as the RFC
	 * describes it.
	 */
	for (i = 0; i < IDX_COUNT; i++) {
		scp = &sp->scp[(cps[i])->protoidx];

		if (((cps[i])->flags & CP_LCP) == 0)
			sppp_wq_add(sp->wq_cp, &scp->work_down);

		if ((cps[i])->flags & CP_AUTH) {
			sppp_wq_add(sp->wq_cp, &scp->work_close);
		}

		/* Close all NCPs. */
		if (phase == SPPP_PHASE_NETWORK &&
		    ((cps[i])->flags & CP_NCP) != 0) {
			sppp_wq_add(sp->wq_cp, &scp->work_close);
		}
	}

	/*
	 * p3-events: a peer that refused our credentials terminates LCP (or
	 * the auth timeout closes it), so this workqueue tld is where the
	 * latched AUTH_FAIL goes out, with pp_lock dropped as for the MTU arm.
	 */
	if (sp->pp_authfail_proto != 0) {
		char ev[40];

		snprintf(ev, sizeof(ev), "proto=%s failures=%d",
		    sp->pp_authfail_proto == PPP_CHAP ? "chap" : "pap",
		    sp->pp_auth_failures);
		sp->pp_authfail_proto = 0;
		ifp = sp->pp_if;
		SPPP_UNLOCK(sp);
		pppoe_devctl(ifp, "AUTH_FAIL", ev);
		SPPP_LOCK(sp, RW_WRITER);
	}
}

static void
sppp_lcp_tls(const struct cp *cp __unused, struct sppp *sp)
{
	u_int delay;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_change_phase(sp, SPPP_PHASE_ESTABLISH);

	/* Notify lower layer if desired. */
	if (!sp->lcp.lower_running) {
		sp->lcp.lower_running = true;
		delay = sppp_auth_backoff(sp);
		if (delay > 0) {
			SPPP_DLOG(sp, "%d auth failures, dialing in %u "
			    "seconds\n", sp->pp_auth_failures, delay);
			sp->pp_dial_armed = true;
			callout_schedule(&sp->pp_dial_ch, delay * hz);
		} else
			sppp_notify_tls_wlocked(sp);
	}
}

static void
sppp_lcp_tlf(const struct cp *cp __unused, struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_change_phase(sp, SPPP_PHASE_DEAD);

	/* Notify lower layer if desired. */
	if (sp->lcp.lower_running) {
		sp->lcp.lower_running = false;
		callout_stop(&sp->pp_dial_ch);	/* a backed-off dial */
		sp->pp_dial_armed = false;	/* ... even one already queued */
		sppp_notify_tlf_wlocked(sp);
	}
}

static void
sppp_lcp_scr(struct sppp *sp)
{
	char opt[6 /* magicnum */ + 4 /* mru */ + 5 /* chap */];
	int i = 0;
	u_short authproto;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (ISSET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC)) {
		if (! sp->lcp.magic)
			sp->lcp.magic = cprng_fast32();
		opt[i++] = LCP_OPT_MAGIC;
		opt[i++] = 6;
		opt[i++] = sp->lcp.magic >> 24;
		opt[i++] = sp->lcp.magic >> 16;
		opt[i++] = sp->lcp.magic >> 8;
		opt[i++] = sp->lcp.magic;
	}

	if (ISSET(sp->lcp.opts,SPPP_LCP_OPT_MRU)) {
		opt[i++] = LCP_OPT_MRU;
		opt[i++] = 4;
		opt[i++] = sp->lcp.mru >> 8;
		opt[i++] = sp->lcp.mru;
	}

	if (ISSET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO)) {
		authproto = sp->hisauth.proto;
		opt[i++] = LCP_OPT_AUTH_PROTO;
		opt[i++] = authproto == PPP_CHAP? 5: 4;
		opt[i++] = authproto >> 8;
		opt[i++] = authproto;
		if (authproto == PPP_CHAP)
			opt[i++] = CHAP_MD5;
	}

	sp->scp[IDX_LCP].confid = ++sp->scp[IDX_LCP].seq;
	sppp_cp_send(sp, PPP_LCP, CONF_REQ, sp->scp[IDX_LCP].confid, i, &opt);
}

/*
 * Check the open NCPs, return true if at least one NCP is open.
 */

static int
sppp_cp_check(struct sppp *sp, u_char cp_flags)
{
	int i, mask;

	for (i = 0, mask = 1; i < IDX_COUNT; i++, mask <<= 1)
		if ((sp->lcp.protos & mask) && (cps[i])->flags & cp_flags)
			return 1;
	return 0;
}

/*
 * Check the opened NCPs, return true if at least one NCP is opened.
 */
static bool
sppp_is_ncp_opened(struct sppp *sp)
{
	size_t i;

	for (i = 0; i < IDX_COUNT; i++)
		if (((cps[i])->flags & CP_NCP) &&
		    (sp->scp[i].state == STATE_OPENED))
			return true;
	return false;
}

/*
 * Re-check the open NCPs and see if we should terminate the link.
 * Called by the NCPs during their tlf action handling.
 */
static void
sppp_lcp_check_and_close(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (sp->pp_phase < SPPP_PHASE_AUTHENTICATE) {
		/* don't bother, we are already going down */
		return;
	}

	if (sp->pp_phase == SPPP_PHASE_AUTHENTICATE &&
	    sppp_cp_check(sp, CP_AUTH))
		return;

	if (sp->pp_phase >= SPPP_PHASE_NETWORK &&
	    sppp_cp_check(sp, CP_NCP))
		return;

	/*
	 * Past pp_max_auth_fail the link is no longer given up for good (an
	 * ISP-side RADIUS outage would then down the WAN until an admin
	 * stepped in); sppp_lcp_tls() backs the redial off instead.
	 */
	if (sp->pp_max_auth_fail != 0 &&
	    sp->pp_auth_failures >= sp->pp_max_auth_fail) {
		SPPP_LOG(sp, LOG_INFO, "authentication failed %d times, "
		    "retrying in %u seconds\n", sp->pp_auth_failures,
		    sppp_auth_backoff(sp));
	}
	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
}

/*
 * Seconds to hold off the next dial: 0 with no auth failure since the
 * last success, then 1, 2, 4 ... capped at net.pppoe.auth_backoff_max.
 */
static u_int
sppp_auth_backoff(struct sppp *sp)
{
	u_int max = sppp_auth_backoff_max;
	int n = sp->pp_auth_failures;

	if (max > AUTH_BACKOFF_LIMIT)
		max = AUTH_BACKOFF_LIMIT;
	if (n <= 0 || max == 0)
		return 0;
	if (n > 31 || (1U << (n - 1)) > max)
		return max;
	return 1U << (n - 1);
}

static void
sppp_dial_timeout(void *arg)
{
	struct sppp *sp = arg;

	sppp_wq_add(sp->wq_cp, &sp->work_dial);
}

static void
sppp_dial(struct sppp *sp, void *xcp __unused)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/* LCP gave the link up, or asked again, while the dial was queued. */
	if (!sp->pp_dial_armed || callout_pending(&sp->pp_dial_ch))
		return;
	sp->pp_dial_armed = false;
	sppp_notify_tls_wlocked(sp);
}

/* New credentials or clear-auth-failure: a backed-off dial goes now. */
static void
sppp_dial_now(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (callout_stop(&sp->pp_dial_ch) > 0)
		sppp_wq_add(sp->wq_cp, &sp->work_dial);
}

/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                        The IPCP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */

static void
sppp_ipcp_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_cp_init(&ipcp, sp);

	sp->ipcp.opts = 0;
	sp->ipcp.flags = 0;
	sp->ipcp.max_failure = 5;	/* RFC 1661 4.6 default */
}

static void
sppp_ipcp_open(struct sppp *sp, void *xcp)
{
	uint32_t myaddr, hisaddr;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if (!ISSET(sp->pp_ncpflags, SPPP_NCP_IPCP))
		return;

	sp->ipcp.flags &= ~(IPCP_HISADDR_SEEN|IPCP_MYADDR_SEEN|IPCP_MYADDR_DYN|IPCP_HISADDR_DYN);
	sp->ipcp.req_myaddr = 0;
	sp->ipcp.req_hisaddr = 0;
	sp->scp[IDX_IPCP].fail_counter = 0;
	memset(&sp->dns_addrs, 0, sizeof sp->dns_addrs);

#ifdef INET
	sppp_get_ip_addrs(sp, &myaddr, &hisaddr, 0);
	/*
	 * MEM068 (S03/T1): the previous session's dynamic-address clear runs
	 * asynchronously (IPCP tld -> sppp_clear_ip_addrs -> the driver's
	 * sc_addr_task on pppoe_taskq), so a fast redial can reach this
	 * open while the stale, still-applied pool address has not yet been
	 * SIOCDIFADDR'd away.  Without the latch below, sppp_get_ip_addrs()
	 * would then report non-zero endpoints, no dynamic flag would be set,
	 * and sppp_ipcp_confnak() would refuse the server's NAKed pool
	 * address forever -- the ConfReq/ConfNak loop -> LCP Term-Req ->
	 * PADT -> ~5s backoff that made reconnect impossible.
	 *
	 * pp_prev_dyn_addrs was latched in sppp_ipcp_tld() with the dying
	 * session's IPCP_{MY,HIS}ADDR_DYN flags; a latched endpoint reads as
	 * unconfigured (local 0, remote the 0.0.0.1 hack) so it is
	 * renegotiated exactly as a fresh dynamic dial would.  Only the
	 * negotiated endpoints are latched: a static local address (0.0.0.1
	 * dynamic-remote setups) stays static, or the peer's ACK of it would
	 * find IPCP_MYADDR_DYN without IPCP_MYADDR_SEEN and close IPCP at
	 * tlu.  pppoe_taskq is FIFO, so the pending clear lands before
	 * this session's apply.  The latch is re-armed by the next tld and
	 * cleared at tlu once the fresh addresses are recorded.
	 */
	if (sp->pp_prev_dyn_addrs & IPCP_MYADDR_DYN)
		myaddr = 0;
	if (sp->pp_prev_dyn_addrs & IPCP_HISADDR_DYN)
		hisaddr = 1;
#endif
	/*
	 * M002/S03/T1: a PPPoE client with a fully-empty address list (no
	 * local AND no remote) is the normal dynamic bring-up - the dial
	 * performs NO userland ifconfig address assignment (spike S2
	 * recipe, R009), so IPCP must negotiate BOTH addresses from the
	 * peer.  NetBSD's original gate ("no IP interface") bailed whenever
	 * hisaddr == 0, which is right for a link that is genuinely not
	 * IP-capable (e.g. IPX-only), but wrong for a dynamic PPPoE dial.
	 *
	 * Cases:
	 *  - both zero (dynamic client): negotiate local + remote, proceed.
	 *  - local set, remote zero: nothing to reach - don't open IPCP.
	 *  - remote set (static or the NetBSD 0.0.0.1 HISADDR_DYN hack):
	 *    fall through to the per-address flag logic below.
	 *
	 * A latched pp_prev_dyn_addrs (redial after a PADT'ed dynamic
	 * session) has already overridden the stale addresses
	 * sppp_get_ip_addrs() may still see, above.
	 */
	if (hisaddr == 0) {
		if (myaddr != 0) {
			/* XXX this message should go away */
			SPPP_DLOG(sp, "ipcp_open(): no IP interface\n");
			return;
		}
		sp->ipcp.flags |= IPCP_MYADDR_DYN | IPCP_HISADDR_DYN;
		sp->ipcp.saved_hisaddr = 0;
		SET(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS);
	} else {
		if (myaddr == 0) {
			/*
			 * I don't have an assigned address, so i need to
			 * negotiate my address.
			 */
			sp->ipcp.flags |= IPCP_MYADDR_DYN;
			SET(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS);
		}
		if (hisaddr == 1) {
			/*
			 * XXX - remove this hack!
			 * remote has no valid address, we need to get one assigned.
			 */
			sp->ipcp.flags |= IPCP_HISADDR_DYN;
			sp->ipcp.saved_hisaddr = htonl(hisaddr);
		}
	}

	if (sp->query_dns & 1) {
		SET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS);
	} else {
		CLR(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS);
	}

	if (sp->query_dns & 2) {
		SET(sp->ipcp.opts, SPPP_IPCP_OPT_SECDNS);
	} else {
		CLR(sp->ipcp.opts, SPPP_IPCP_OPT_SECDNS);
	}
	sppp_open_event(sp, xcp);
}

static void
sppp_ipcp_close(struct sppp *sp, void *xcp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	sppp_close_event(sp, xcp);

#ifdef INET
	if (sp->ipcp.flags & IPCP_MYADDR_DYN) {
		/*
		 * The local address was dynamic, clear it again.  A static
		 * one stays (its ifaddr carries the remote too; the next
		 * session's tlu replaces a negotiated remote).
		 */
		sppp_clear_ip_addrs(sp);
	}
#endif
	memset(&sp->dns_addrs, 0, sizeof sp->dns_addrs);
}

/*
 * Analyze a configure request.  Return true if it was agreeable, and
 * caused action sca, false if it has been rejected or nak'ed, and
 * caused action scn.  (The return value is used to make the state
 * transition decision in the state automaton.)
 */
static enum cp_rcr_type
sppp_ipcp_confreq(struct sppp *sp, struct lcp_header *h, int origlen,
   uint8_t **msgbuf, size_t *buflen, size_t *msglen)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *buf, *r, *p, l;
	size_t blen;
	enum cp_rcr_type type;
	int rlen, len;
	uint32_t hisaddr, desiredaddr;
	char ipbuf[SPPP_IPCPOPT_NAMELEN];
	char dqbuf[SPPP_DOTQUAD_BUFLEN];
	const char *dq;
	bool maxfail;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	type = CP_RCR_NONE;
	origlen -= sizeof(*h);

	if (origlen < 0)
		return CP_RCR_DROP;

	/*
	 * Make sure to allocate a buf that can at least hold a
	 * conf-nak with an `address' option.  We might need it below.
	 */
	blen = MAX(6, origlen);

	buf = kmem_intr_alloc(blen, KM_NOSLEEP);
	if (buf == NULL)
		return CP_RCR_DROP;

	/* pass 1: see if we can recognize them */
	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipcp parse opts:");
	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	for (len = origlen; len > 1; len -= l, p += l) {
		l = p[1];
		if (l < 2) {
			/* Malformed; see sppp_lcp_confreq(). */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "ipcp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		/* Sanity check option length */
		if (l > len) {
			/* XXX should we just RXJ? */
			if (debug)
				addlog("\n");

			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    " malicious IPCP option received, "
				    "dropping\n");
			type = CP_RCR_ERR;
			goto end;
		}
		if (debug) {
			addlog(" %s",
			    sppp_ipcp_opt_name(ipbuf, sizeof(ipbuf), *p));
		}
		switch (p[0]) {
#ifdef notyet
		case IPCP_OPT_COMPRESSION:
			if (len >= 6 && l >= 6) {
				/* correctly formed compress option */
				continue;
			}
			if (debug)
				addlog(" [invalid]");
			break;
#endif
		case IPCP_OPT_ADDRESS:
			if (len >= 6 && l == 6) {
				/* correctly formed address option */
				continue;
			}
			if (debug)
				addlog(" [invalid]");
			break;
		default:
			/* Others not supported. */
			if (debug)
				addlog(" [rej]");
			break;
		}
		/* Add the option to rejected list. */
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	/* A lone trailing octet; see sppp_lcp_confreq(). */
	if (len != 0) {
		if (debug)
			addlog("\n");
		SPPP_DLOG(sp, "ipcp trailing octet 0x%02x, "
		    "dropping\n", p[0]);
		type = CP_RCR_DROP;
		goto end;
	}

	if (rlen > 0) {
		type = CP_RCR_REJ;
		goto end;
	}

	if (debug)
		addlog("\n");

	/*
	 * RFC 1661 4.6 Max-Failure: after that many Configure-Naks without a
	 * Configure-Ack the negotiation is not converging; reject the
	 * offending options instead of NAKing them again.
	 */
	maxfail = sp->scp[IDX_IPCP].fail_counter >= sp->ipcp.max_failure;

	/* pass 2: parse option values */
	if (sp->ipcp.flags & IPCP_HISADDR_SEEN)
		hisaddr = sp->ipcp.req_hisaddr;	/* we already aggreed on that */
	else
#ifdef INET
		sppp_get_ip_addrs(sp, 0, &hisaddr, 0);	/* user configuration */
#else
		hisaddr = 0;
#endif
	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipcp parse opt values:");
	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	for (len = origlen; len > 1; len -= l, p += l) {
		l = p[1];
		if (l < 2 || l > len) {
			/* Sanity check option length, same as pass 1. */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "ipcp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		if (debug) {
			addlog(" %s",
			    sppp_ipcp_opt_name(ipbuf, sizeof(ipbuf), *p));
		}
		switch (p[0]) {
#ifdef notyet
		case IPCP_OPT_COMPRESSION:
			continue;
#endif
		case IPCP_OPT_ADDRESS:
			desiredaddr = (uint32_t)p[2] << 24 | p[3] << 16 |
				p[4] << 8 | p[5];
			if (desiredaddr == hisaddr ||
		    	   ((sp->ipcp.flags & IPCP_HISADDR_DYN) && desiredaddr != 0)) {
				/*
			 	* Peer's address is same as our value,
			 	* this is agreeable.  Gonna conf-ack
			 	* it.
			 	*/
				if (debug) {
					dq = sppp_dotted_quad(dqbuf,
					    sizeof(dqbuf), hisaddr);
					addlog(" %s [ack]", dq);
				}
				/* record that we've seen it already */
				sp->ipcp.flags |= IPCP_HISADDR_SEEN;
				sp->ipcp.req_hisaddr = desiredaddr;
				hisaddr = desiredaddr;
				continue;
			}
			/*
		 	* The address wasn't agreeable.  This is either
		 	* he sent us 0.0.0.0, asking to assign him an
		 	* address, or he send us another address not
		 	* matching our value.  Either case, we gonna
		 	* conf-nak it with our value.
		 	*/
			if (debug) {
				if (desiredaddr == 0) {
					addlog(" [addr requested]");
				} else {
					dq = sppp_dotted_quad(dqbuf,
					    sizeof(dqbuf), desiredaddr);
					addlog(" %s [not agreed]", dq);
				}
			}
			if (maxfail)
				break;	/* reject it as the peer sent it */

			p[2] = hisaddr >> 24;
			p[3] = hisaddr >> 16;
			p[4] = hisaddr >> 8;
			p[5] = hisaddr;
			break;
		}
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		/* Add the option to nak'ed list. */
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	if (rlen > 0) {
		if (maxfail) {
			if (debug)
				addlog(" max_failure (%d) exceeded, [rej]",
				    sp->ipcp.max_failure);
			type = CP_RCR_REJ;
		} else {
			sp->scp[IDX_IPCP].fail_counter++;
			type = CP_RCR_NAK;
		}
	} else {
		if ((sp->ipcp.flags & IPCP_HISADDR_SEEN) == 0 && !maxfail) {
			/*
			 * If we are about to conf-ack the request, but haven't seen
			 * his address so far, gonna conf-nak it instead, with the
			 * `address' option present and our idea of his address being
			 * filled in there, to request negotiation of both addresses.
			 *
			 * The peer never sent the option, so there is nothing to
			 * reject: after Max-Failure we stop asking and ACK.
			 */
			sp->scp[IDX_IPCP].fail_counter++;
			buf[0] = IPCP_OPT_ADDRESS;
			buf[1] = 6;
			buf[2] = hisaddr >> 24;
			buf[3] = hisaddr >> 16;
			buf[4] = hisaddr >> 8;
			buf[5] = hisaddr;
			rlen = 6;
			if (debug)
				addlog(" still need hisaddr");
			type = CP_RCR_NAK;
		} else {
			type = CP_RCR_ACK;
			rlen = origlen;
			memcpy(r, h + 1, rlen);
			sp->scp[IDX_IPCP].fail_counter = 0;
		}
	}

end:
	if (debug)
		addlog("\n");

	if (type == CP_RCR_ERR || type == CP_RCR_DROP) {
		if (buf != NULL)
			kmem_intr_free(buf, blen);
	} else {
		*msgbuf = buf;
		*buflen = blen;
		*msglen = rlen;
	}

	return type;
}

/*
 * Analyze the IPCP Configure-Reject option list, and adjust our
 * negotiation.
 */
static void
sppp_ipcp_confrej(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len <= sizeof(*h))
		return;

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipcp rej opts:");

	p = (void *)(h + 1);
	for (; len > 1; len -= l, p += l) {
		l = p[1];
		if (l == 0)
			break;

		/* Sanity check option length */
		if (l > len) {
			/* XXX should we just RXJ? */
			if (debug)
				addlog("\n");
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "malicious IPCP option received, "
				    "dropping\n");
			goto end;
		}
		if (debug) {
			char ipbuf[SPPP_IPCPOPT_NAMELEN];
			addlog(" %s",
			    sppp_ipcp_opt_name(ipbuf, sizeof(ipbuf), *p));
		}
		switch (p[0]) {
		case IPCP_OPT_ADDRESS:
			/*
			 * Peer doesn't grok address option.  This is
			 * bad.  XXX  Should we better give up here?
			 */
			if (!debug) {
				SPPP_LOG(sp, LOG_ERR,
				    "IPCP address option rejected\n");
			}
			CLR(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS);
			break;
#ifdef notyet
		case IPCP_OPT_COMPRESS:
			CLR(sp->ipcp.opts, SPPP_IPCP_OPT_COMPRESS);
			break;
#endif
		case IPCP_OPT_PRIMDNS:
			CLR(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS);
			break;

		case IPCP_OPT_SECDNS:
			CLR(sp->ipcp.opts, SPPP_IPCP_OPT_SECDNS);
			break;
		}
	}
	if (debug)
		addlog("\n");
end:
	return;
}

/*
 * Analyze the IPCP Configure-NAK option list, and adjust our
 * negotiation.
 */
static void
sppp_ipcp_confnak(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;
	uint32_t wantaddr;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipcp nak opts:");

	p = (void *)(h + 1);
	for (; len > 1; len -= l, p += l) {
		l = p[1];
		if (l == 0)
			break;

		/* Sanity check option length */
		if (l > len) {
			/* XXX should we just RXJ? */
			if (debug)
				addlog("\n");
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "malicious IPCP option received, "
				    "dropping\n");
			return;
		}
		if (debug) {
			char ipbuf[SPPP_IPCPOPT_NAMELEN];
			addlog(" %s",
			    sppp_ipcp_opt_name(ipbuf, sizeof(ipbuf), *p));
		}
		switch (*p) {
		case IPCP_OPT_ADDRESS:
			/*
			 * Peer doesn't like our local IP address.  See
			 * if we can do something for him.  We'll drop
			 * him our address then.
			 */
			if (len >= 6 && l == 6) {
				wantaddr = (uint32_t)p[2] << 24 | p[3] << 16 |
					p[4] << 8 | p[5];
				SET(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS);
				if (debug) {
					char dqbuf[SPPP_DOTQUAD_BUFLEN];
					const char *dq;

					dq = sppp_dotted_quad(dqbuf,
					    sizeof(dqbuf), wantaddr);
					addlog(" [wantaddr %s]", dq);
				}
				/*
				 * When doing dynamic address assignment,
				 * we accept his offer.  Otherwise, we
				 * ignore it and thus continue to negotiate
				 * our already existing value.
				 */
				if (sp->ipcp.flags & IPCP_MYADDR_DYN) {
					if (ntohl(wantaddr) != INADDR_ANY) {
						if (debug)
							addlog(" [agree]");
						sp->ipcp.flags |= IPCP_MYADDR_SEEN;
						sp->ipcp.req_myaddr = wantaddr;
					} else {
						if (debug)
							addlog(" [not agreed]");
					}
				}
			}
			break;

		case IPCP_OPT_PRIMDNS:
			if (ISSET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS) &&
			    len >= 6 && l == 6) {
				sp->dns_addrs[0] = (uint32_t)p[2] << 24 |
					p[3] << 16 | p[4] << 8 | p[5];
			}
			break;

		case IPCP_OPT_SECDNS:
			if (ISSET(sp->ipcp.opts, SPPP_IPCP_OPT_SECDNS) &&
			    len >= 6 && l == 6) {
				sp->dns_addrs[1] = (uint32_t)p[2] << 24 |
					p[3] << 16 | p[4] << 8 | p[5];
			}
			break;
#ifdef notyet
		case IPCP_OPT_COMPRESS:
			/*
			 * Peer wants different compression parameters.
			 */
			break;
#endif
		}
	}
	if (debug)
		addlog("\n");
}

/*
 * rt_ifmsg requires sppp to be unlocked as it will attempt to lock it again.
 * unlocking sppp is safe here because this logic runs in a single thread,
 * the workqueue, so concurrent state transitions are excluded on that basis;
 * other tlu functions already release and re-acquire the lock already,
 * which is only for coordination with threads _other_ than the workqueue
 * thread which doesn't change the state.
 */
static void
sppp_rt_ifmsg(struct sppp *sp)
{
	struct ifnet *ifp = sp->pp_if;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	SPPP_UNLOCK(sp);
	rt_ifmsg(ifp, 0);
	SPPP_LOCK(sp, RW_WRITER);
}

#ifdef INET
#define	SPPP_IP4_FMT	"%u.%u.%u.%u"
#define	SPPP_IP4_ARGS(_a)						\
	(u_int)(((_a) >> 24) & 0xff), (u_int)(((_a) >> 16) & 0xff),	\
	(u_int)(((_a) >> 8) & 0xff), (u_int)((_a) & 0xff)

/*
 * IPCP_UP data, under pp_lock: the endpoints sppp_set_ip_addrs() just
 * recorded (host order) and the IPCP-negotiated DNS servers.  The driver
 * replays the same string in the matching IPCP_DOWN.
 */
static void
sppp_ipcp_evdata(struct sppp *sp, char *buf, size_t len)
{
	uint32_t l = sp->pp_want_local, r = sp->pp_want_remote;
	uint32_t d1 = sp->dns_addrs[0], d2 = sp->dns_addrs[1];

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	snprintf(buf, len, "local=" SPPP_IP4_FMT " remote=" SPPP_IP4_FMT
	    " dns1=" SPPP_IP4_FMT " dns2=" SPPP_IP4_FMT " mtu=%d",
	    SPPP_IP4_ARGS(l), SPPP_IP4_ARGS(r), SPPP_IP4_ARGS(d1),
	    SPPP_IP4_ARGS(d2), if_getmtu(sp->pp_if));
}
#endif

static void
sppp_ipcp_tlu(struct sppp *sp)
{
#ifdef INET
	char ev[SPPP_EVDATA_LEN];

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/* One whole record (the T1 recipe asserts on this line). */
	SPPP_LOG(sp, LOG_INFO, "IPCP layer up\n");
	if ((sp->ipcp.flags & IPCP_MYADDR_DYN) &&
	    ((sp->ipcp.flags & IPCP_MYADDR_SEEN) == 0)) {
		SPPP_LOG(sp, LOG_WARNING,
		    "no IP address, closing IPCP\n");
		sppp_wq_add(sp->wq_cp,
		    &sp->scp[IDX_IPCP].work_close);
	} else {
		/* we are up. Set addresses and notify anyone interested */
		sppp_set_ip_addrs(sp);
		/*
		 * MEM068 (S03/T1): the fresh session's addresses are recorded --
		 * the async-clear belt no longer applies.  Re-armed by the next
		 * sppp_ipcp_tld() when a session holding dynamic addresses goes
		 * down.  (The failure arm above deliberately leaves the latch
		 * set: the next redial must still negotiate dynamically even if
		 * the previous attempt never reached tlu.)
		 */
		sp->pp_prev_dyn_addrs = 0;
		/*
		 * p3-events: hand IPCP_UP to the driver in the same pp_lock
		 * hold as the pp_want_* it describes; it goes out from the
		 * address task once SIOCAIFADDR has put the address on.
		 */
		if (sppp_ncp_link(sp, IDX_IPCP, true)) {
			sppp_ipcp_evdata(sp, ev, sizeof(ev));
			pppoe_ncp_event(sp, IDX_IPCP, ev);
		}
		sppp_rt_ifmsg(sp);
	}
#endif
}

static void
sppp_ipcp_tld(struct sppp *sp)
{
#ifdef INET

	SPPP_LOG(sp, LOG_INFO, "IPCP layer down\n");
	/*
	 * MEM068 (S03/T1): this is the PADT/session-loss path.  Before this
	 * fix, tld only logged and sent the routing-socket message; the
	 * negotiated pool address stayed applied on the interface because
	 * sppp_clear_ip_addrs() ran only from sppp_ipcp_close()
	 * (administrative close).  The next dial then saw the stale address,
	 * negotiated nothing dynamically, and the server's NAKed pool address
	 * was refused forever (ConfReq/ConfNak loop -> Term -> PADT).
	 *
	 * The DYN flags still reflect the dying session here (ipcp_open only
	 * resets them at the next open), so gate on them.  sppp_clear_ip_addrs()
	 * is sleep-free from this context (snapshot + taskqueue_enqueue on
	 * pppoe_taskq under pp_lock), exactly like the sppp_ipcp_close()
	 * call site.  pp_prev_dyn_addrs is the belt for the async clear: the
	 * next sppp_ipcp_open() consults it in case it races the SIOCDIFADDR
	 * task.  sppp_ipcp_tlu() clears the latch once the fresh session's
	 * addresses are recorded.
	 */
	sp->pp_prev_dyn_addrs = sp->ipcp.flags &
	    (IPCP_MYADDR_DYN|IPCP_HISADDR_DYN);
	/* A static local address stays applied; see sppp_ipcp_close(). */
	if (sp->ipcp.flags & IPCP_MYADDR_DYN)
		sppp_clear_ip_addrs(sp);
	if (sppp_ncp_link(sp, IDX_IPCP, false))
		pppoe_ncp_event(sp, IDX_IPCP, NULL);	/* p3-events */
	sppp_rt_ifmsg(sp);
#endif
}

static void
sppp_ipcp_scr(struct sppp *sp)
{
	uint8_t opt[6 /* compression */ + 6 /* address */ + 12 /* dns addresses */];
#ifdef INET
	uint32_t ouraddr;
#endif
	int i = 0;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

#ifdef notyet
	if (ISSET(sp->ipcp.opts,SPPP_IPCP_OPT_COMPRESSION)) {
		opt[i++] = IPCP_OPT_COMPRESSION;
		opt[i++] = 6;
		opt[i++] = 0;	/* VJ header compression */
		opt[i++] = 0x2d; /* VJ header compression */
		opt[i++] = max_slot_id;
		opt[i++] = comp_slot_id;
	}
#endif

#ifdef INET
	if (ISSET(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS)) {
		if (sp->ipcp.flags & IPCP_MYADDR_SEEN) {
			ouraddr = sp->ipcp.req_myaddr;	/* the peer's NAK */
		} else if (sp->ipcp.flags & IPCP_MYADDR_DYN) {
			/*
			 * Ask for an address; never the ifaddr, which on a
			 * redial may still be the last session's (the clear
			 * is asynchronous, see sppp_ipcp_open()).
			 */
			ouraddr = 0;
		} else {
			sppp_get_ip_addrs(sp, &ouraddr, 0, 0);
		}
		opt[i++] = IPCP_OPT_ADDRESS;
		opt[i++] = 6;
		opt[i++] = ouraddr >> 24;
		opt[i++] = ouraddr >> 16;
		opt[i++] = ouraddr >> 8;
		opt[i++] = ouraddr;
	}
#endif

	if (ISSET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS)) {
		opt[i++] = IPCP_OPT_PRIMDNS;
		opt[i++] = 6;
		opt[i++] = sp->dns_addrs[0] >> 24;
		opt[i++] = sp->dns_addrs[0] >> 16;
		opt[i++] = sp->dns_addrs[0] >> 8;
		opt[i++] = sp->dns_addrs[0];
	}
	if (ISSET(sp->ipcp.opts, SPPP_IPCP_OPT_SECDNS)) {
		opt[i++] = IPCP_OPT_SECDNS;
		opt[i++] = 6;
		opt[i++] = sp->dns_addrs[1] >> 24;
		opt[i++] = sp->dns_addrs[1] >> 16;
		opt[i++] = sp->dns_addrs[1] >> 8;
		opt[i++] = sp->dns_addrs[1];
	}

	sp->scp[IDX_IPCP].confid = ++sp->scp[IDX_IPCP].seq;
	sppp_cp_send(sp, PPP_IPCP, CONF_REQ, sp->scp[IDX_IPCP].confid, i, &opt);
}

/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                      The IPv6CP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */

#ifdef INET6
static void
sppp_ipv6cp_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_cp_init(&ipv6cp, sp);

	sp->ipv6cp.opts = 0;
	sp->ipv6cp.flags = 0;
	sp->ipv6cp.max_failure = 5;	/* RFC 1661 4.6 default */
}

static void
sppp_ipv6cp_open(struct sppp *sp, void *xcp)
{
	struct in6_addr myaddr, hisaddr;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	if (!ISSET(sp->pp_ncpflags, SPPP_NCP_IPV6CP))
		return;

#ifdef IPV6CP_MYIFID_DYN
	sp->ipv6cp.flags &= ~(IPV6CP_MYIFID_SEEN|IPV6CP_MYIFID_DYN);
#else
	sp->ipv6cp.flags &= ~IPV6CP_MYIFID_SEEN;
#endif
	sp->scp[IDX_IPV6CP].fail_counter = 0;

	sppp_get_ip6_addrs(sp, &myaddr, &hisaddr, 0);
	/*
	 * If we don't have our address, this probably means our
	 * interface doesn't want to talk IPv6 at all.  (This could
	 * be the case if somebody wants to speak only IPX, for
	 * example.)  Don't open IPv6CP in this case.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&myaddr)) {
		/* XXX this message should go away */
		SPPP_DLOG(sp, "ipv6cp_open(): no IPv6 interface\n");
		return;
	}

	sp->ipv6cp.flags |= IPV6CP_MYIFID_SEEN;
	SET(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_IFID);
	sppp_open_event(sp, xcp);
}

/*
 * Analyze a configure request.  Return true if it was agreeable, and
 * caused action sca, false if it has been rejected or nak'ed, and
 * caused action scn.  (The return value is used to make the state
 * transition decision in the state automaton.)
 */
static enum cp_rcr_type
sppp_ipv6cp_confreq(struct sppp *sp, struct lcp_header *h, int origlen,
    uint8_t **msgbuf, size_t *buflen, size_t *msglen)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *buf, *r, *p, l;
	size_t blen;
	int rlen, len;
	struct in6_addr myaddr, desiredaddr, suggestaddr;
	enum cp_rcr_type type;
	int ifidcount;
	int collision, nohisaddr;
	char ip6buf[INET6_ADDRSTRLEN];
	char tbuf[SPPP_CPTYPE_NAMELEN];
	char ipv6buf[SPPP_IPV6CPOPT_NAMELEN];
	const char *cpname;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	type = CP_RCR_NONE;
	origlen -= sizeof(*h);

	if (origlen < 0)
		return CP_RCR_DROP;

	/*
	 * Make sure to allocate a buf that can at least hold a
	 * conf-nak with an `address' option.  We might need it below.
	 */
	blen = MAX(6, origlen);

	buf = kmem_intr_alloc(blen, KM_NOSLEEP);
	if (buf == NULL)
		return CP_RCR_DROP;

	/* pass 1: see if we can recognize them */
	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipv6cp parse opts:");
	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	ifidcount = 0;
	for (len = origlen; len > 1; len -= l, p += l) {
		l = p[1];
		if (l < 2) {
			/* Malformed; see sppp_lcp_confreq(). */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "ipv6cp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		/* Sanity check option length */
		if (l > len) {
			/* XXX just RXJ? */
			if (debug)
				addlog("\n");
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious IPCPv6 option, "
				    "dropping\n");
			type = CP_RCR_ERR;
			goto end;
		}
		if (debug) {
			addlog(" %s", sppp_ipv6cp_opt_name(ipv6buf,
			    sizeof(ipv6buf),*p));
		}
		switch (p[0]) {
		case IPV6CP_OPT_IFID:
			if (len >= 10 && l == 10 && ifidcount == 0) {
				/* correctly formed address option */
				ifidcount++;
				continue;
			}
			if (debug)
				addlog(" [invalid]");
			break;
#ifdef notyet
		case IPV6CP_OPT_COMPRESSION:
			if (len >= 4 && l >= 4) {
				/* correctly formed compress option */
				continue;
			}
			if (debug)
				addlog(" [invalid]");
			break;
#endif
		default:
			/* Others not supported. */
			if (debug)
				addlog(" [rej]");
			break;
		}
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		/* Add the option to rejected list. */
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	/* A lone trailing octet; see sppp_lcp_confreq(). */
	if (len != 0) {
		if (debug)
			addlog("\n");
		SPPP_DLOG(sp, "ipv6cp trailing octet 0x%02x, "
		    "dropping\n", p[0]);
		type = CP_RCR_DROP;
		goto end;
	}

	if (rlen > 0) {
		type = CP_RCR_REJ;
		goto end;
	}

	if (debug)
		addlog("\n");

	/* pass 2: parse option values */
	sppp_get_ip6_addrs(sp, &myaddr, 0, 0);
	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipv6cp parse opt values:");
	p = (void *)(h + 1);
	r = buf;
	rlen = 0;
	type = CP_RCR_ACK;
	for (len = origlen; len > 1; len -= l, p += l) {
		l = p[1];
		if (l < 2 || l > len) {
			/* Sanity check option length, same as pass 1. */
			if (debug)
				addlog("\n");
			SPPP_DLOG(sp, "ipv6cp option 0x%02x length %d, "
			    "dropping\n", p[0], l);
			type = CP_RCR_DROP;
			goto end;
		}

		if (debug) {
			addlog(" %s", sppp_ipv6cp_opt_name(ipv6buf,
			    sizeof(ipv6buf), *p));
		}
		switch (p[0]) {
#ifdef notyet
		case IPV6CP_OPT_COMPRESSION:
			continue;
#endif
		case IPV6CP_OPT_IFID:
			memset(&desiredaddr, 0, sizeof(desiredaddr));
			memcpy(&desiredaddr.s6_addr[8], &p[2], 8);
			collision = (memcmp(&desiredaddr.s6_addr[8],
					&myaddr.s6_addr[8], 8) == 0);
			nohisaddr = IN6_IS_ADDR_UNSPECIFIED(&desiredaddr);

			desiredaddr.s6_addr16[0] = htons(0xfe80);
			(void)in6_setscope(&desiredaddr, sp->pp_if, NULL);

			if (!collision && !nohisaddr) {
				/* no collision, hisaddr known - Conf-Ack */
				type = CP_RCR_ACK;
				memcpy(sp->ipv6cp.my_ifid, &myaddr.s6_addr[8],
				    sizeof(sp->ipv6cp.my_ifid));
				memcpy(sp->ipv6cp.his_ifid,
				    &desiredaddr.s6_addr[8],
				    sizeof(sp->ipv6cp.my_ifid));

				if (debug) {
					cpname = sppp_cp_type_name(tbuf,
					    sizeof(tbuf), CONF_ACK);
					addlog(" %s [%s]",
					    IN6_PRINT(ip6buf, &desiredaddr),
					    cpname);
				}
				continue;
			}

			memset(&suggestaddr, 0, sizeof(suggestaddr));
			if (collision && nohisaddr) {
				/* collision, hisaddr unknown - Conf-Rej */
				type = CP_RCR_REJ;
				memset(&p[2], 0, 8);
			} else if (sp->scp[IDX_IPV6CP].fail_counter >=
			    sp->ipv6cp.max_failure) {
				/*
				 * RFC 1661 4.6 Max-Failure: not converging,
				 * reject the option as the peer sent it.
				 */
				type = CP_RCR_REJ;
			} else {
				/*
				 * - no collision, hisaddr unknown, or
				 * - collision, hisaddr known
				 * Conf-Nak, suggest hisaddr
				 */
				type = CP_RCR_NAK;
				sppp_suggest_ip6_addr(sp, &suggestaddr);
				memcpy(&p[2], &suggestaddr.s6_addr[8], 8);
			}
			if (debug) {
				int ctype = type == CP_RCR_REJ ? CONF_REJ : CONF_NAK;

				cpname = sppp_cp_type_name(tbuf, sizeof(tbuf), ctype);
				addlog(" %s [%s]", IN6_PRINT(ip6buf, &desiredaddr),
				   cpname);
			}
			break;
		}
		if (rlen + l > blen) {
			if (debug)
				addlog(" [overflow]");
			continue;
		}
		/* Add the option to nak'ed list. */
		memcpy(r, p, l);
		r += l;
		rlen += l;
	}

	if (rlen > 0) {
		if (type != CP_RCR_ACK) {
			if (debug) {
				int ctype ;
				ctype = type == CP_RCR_REJ ?
				    CONF_REJ : CONF_NAK;
				cpname =  sppp_cp_type_name(tbuf, sizeof(tbuf), ctype);
				addlog(" send %s suggest %s\n",
				    cpname, IN6_PRINT(ip6buf, &suggestaddr));
			}
		}
#ifdef notdef
		if (type == CP_RCR_ACK)
			panic("IPv6CP RCR: CONF_ACK with non-zero rlen");
#endif
	} else {
		if (type == CP_RCR_ACK) {
			rlen = origlen;
			memcpy(r, h + 1, rlen);
		}
	}
	if (type == CP_RCR_NAK)
		sp->scp[IDX_IPV6CP].fail_counter++;
	else if (type == CP_RCR_ACK)
		sp->scp[IDX_IPV6CP].fail_counter = 0;
end:
	if (debug)
		addlog("\n");

	if (type == CP_RCR_ERR || type == CP_RCR_DROP) {
		if (buf != NULL)
			kmem_intr_free(buf, blen);
	} else {
		*msgbuf = buf;
		*buflen = blen;
		*msglen = rlen;
	}

	return type;
}

/*
 * Analyze the IPv6CP Configure-Reject option list, and adjust our
 * negotiation.
 */
static void
sppp_ipv6cp_confrej(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len <= sizeof(*h))
		return;

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipv6cp rej opts:");

	p = (void *)(h + 1);
	for (; len > 1; len -= l, p += l) {
		l = p[1];
		if (l == 0)
			break;

		if (l > len) {
			/* XXX just RXJ? */
			if (debug)
				addlog("\n");
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious IPCPv6 option, "
				    "dropping\n");
			goto end;
		}
		if (debug) {
			char ipv6buf[SPPP_IPV6CPOPT_NAMELEN];
			addlog(" %s", sppp_ipv6cp_opt_name(ipv6buf,
			    sizeof(ipv6buf), *p));
		}
		switch (p[0]) {
		case IPV6CP_OPT_IFID:
			/*
			 * Peer doesn't grok address option.  This is
			 * bad.  XXX  Should we better give up here?
			 */
			CLR(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_IFID);
			break;
#ifdef notyet
		case IPV6CP_OPT_COMPRESS:
			CLR(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_COMPRESS);
			break;
#endif
		}
	}
	if (debug)
		addlog("\n");
end:
	return;
}

/*
 * Analyze the IPv6CP Configure-NAK option list, and adjust our
 * negotiation.
 */
static void
sppp_ipv6cp_confnak(struct sppp *sp, struct lcp_header *h, int len)
{
	const bool debug = sppp_debug_enabled(sp);
	u_char *p, l;
	struct in6_addr suggestaddr;
	char ip6buf[INET6_ADDRSTRLEN];

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len <= sizeof(*h))
		return;

	len -= sizeof(*h);

	if (debug)
		SPPP_LOG(sp, LOG_DEBUG, "ipv6cp nak opts:");

	p = (void *)(h + 1);
	for (; len > 1; len -= l, p += l) {
		l = p[1];
		if (l == 0)
			break;

		if (l > len) {
			/* XXX just RXJ? */
			if (debug)
				addlog("\n");
			if (sppp_rxlog_ok(sp))
				SPPP_LOG(sp, LOG_DEBUG,
				    "received malicious IPCPv6 option, "
				    "dropping\n");
			goto end;
		}
		if (debug) {
			char ipv6buf[SPPP_IPV6CPOPT_NAMELEN];
			addlog(" %s", sppp_ipv6cp_opt_name(ipv6buf,
			    sizeof(ipv6buf), *p));
		}
		switch (p[0]) {
		case IPV6CP_OPT_IFID:
			/*
			 * Peer doesn't like our local ifid.  See
			 * if we can do something for him.  We'll drop
			 * him our address then.
			 */
			if (len < 10 || l != 10)
				break;
			memset(&suggestaddr, 0, sizeof(suggestaddr));
			suggestaddr.s6_addr16[0] = htons(0xfe80);
			(void)in6_setscope(&suggestaddr, sp->pp_if, NULL);
			memcpy(&suggestaddr.s6_addr[8], &p[2], 8);

			SET(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_IFID);
			if (debug)
				addlog(" [suggestaddr %s]",
				       IN6_PRINT(ip6buf, &suggestaddr));
#ifdef IPV6CP_MYIFID_DYN
			/*
			 * When doing dynamic address assignment,
			 * we accept his offer.
			 */
			if (sp->ipv6cp.flags & IPV6CP_MYIFID_DYN) {
				struct in6_addr lastsuggest;
				/*
				 * If <suggested myaddr from peer> equals to
				 * <hisaddr we have suggested last time>,
				 * we have a collision.  generate new random
				 * ifid.
				 */
				sppp_suggest_ip6_addr(&lastsuggest);
				if (IN6_ARE_ADDR_EQUAL(&suggestaddr,
						 lastsuggest)) {
					if (debug)
						addlog(" [random]");
					sppp_gen_ip6_addr(sp, &suggestaddr);
				}
				sppp_set_ip6_addr(sp, &suggestaddr, 0);
				if (debug)
					addlog(" [agree]");
				sp->ipv6cp.flags |= IPV6CP_MYIFID_SEEN;
			}
#else
			/*
			 * Since we do not do dynamic address assignment,
			 * we ignore it and thus continue to negotiate
			 * our already existing value.  This can possibly
			 * go into infinite request-reject loop.
			 *
			 * This is not likely because we normally use
			 * ifid based on MAC-address.
			 * If you have no ethernet card on the node, too bad.
			 * XXX should we use fail_counter?
			 */
#endif
			break;
#ifdef notyet
		case IPV6CP_OPT_COMPRESS:
			/*
			 * Peer wants different compression parameters.
			 */
			break;
#endif
		}
	}
	if (debug)
		addlog("\n");
end:
	return;
}

/*
 * IPV6CP_UP data, under pp_lock: the link-locals built from the negotiated
 * interface identifiers (uncompressed groups; consumers parse).  The driver
 * replays the same string in the matching IPV6CP_DOWN.
 */
static void
sppp_ipv6cp_evdata(struct sppp *sp, char *buf, size_t len)
{
	const uint8_t *m = sp->ipv6cp.my_ifid, *h = sp->ipv6cp.his_ifid;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

#define	SPPP_IFID_GRP(_p, _i)	(u_int)(((_p)[(_i)] << 8) | (_p)[(_i) + 1])
	snprintf(buf, len,
	    "local=fe80::%x:%x:%x:%x remote=fe80::%x:%x:%x:%x mtu=%d",
	    SPPP_IFID_GRP(m, 0), SPPP_IFID_GRP(m, 2), SPPP_IFID_GRP(m, 4),
	    SPPP_IFID_GRP(m, 6), SPPP_IFID_GRP(h, 0), SPPP_IFID_GRP(h, 2),
	    SPPP_IFID_GRP(h, 4), SPPP_IFID_GRP(h, 6), if_getmtu(sp->pp_if));
#undef	SPPP_IFID_GRP
}

static void
sppp_ipv6cp_tlu(struct sppp *sp)
{
	struct in6_addr ll;
	char ev[SPPP_EVDATA_LEN];

	SPPP_LOG(sp, LOG_INFO, "IPv6CP layer up\n");

	/*
	 * IPv6CP reached Opened (T2, R009): apply the negotiated
	 * link-local on pppoe0 from inside the kernel -- no userland
	 * step.  my_ifid is what we offered and the peer Ack'd (either
	 * the driver-seeded MAC-derived identifier on the first dial or
	 * the interface's existing link-local ifaddr on later ones); an
	 * all-zero one means we never offered anything, so there is
	 * nothing to apply.
	 */
	if (sppp_ip6_ifid_present(sp->ipv6cp.my_ifid)) {
		memset(&ll, 0, sizeof(ll));
		ll.s6_addr16[0] = htons(0xfe80);
		memcpy(&ll.s6_addr[8], sp->ipv6cp.my_ifid, 8);
		sppp_update_ip6_addr(sp, &ll);
	} else {
		SPPP_DLOG(sp, "ipv6cp tlu without a local ifid -- "
		    "no link-local applied\n");
	}
	/* p3-events: out from the address task after the link-local. */
	if (sppp_ncp_link(sp, IDX_IPV6CP, true)) {
		sppp_ipv6cp_evdata(sp, ev, sizeof(ev));
		pppoe_ncp_event(sp, IDX_IPV6CP, ev);
	}
	sppp_rt_ifmsg(sp);
}

static void
sppp_ipv6cp_tld(struct sppp *sp)
{

	SPPP_LOG(sp, LOG_INFO, "IPv6CP layer down\n");
	if (sppp_ncp_link(sp, IDX_IPV6CP, false))
		pppoe_ncp_event(sp, IDX_IPV6CP, NULL);	/* p3-events */
	sppp_rt_ifmsg(sp);
}

static void
sppp_ipv6cp_scr(struct sppp *sp)
{
	char opt[10 /* ifid */ + 4 /* compression, minimum */];
	struct in6_addr ouraddr;
	int i = 0;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (ISSET(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_IFID)) {
		sppp_get_ip6_addrs(sp, &ouraddr, 0, 0);

		opt[i++] = IPV6CP_OPT_IFID;
		opt[i++] = 10;
		memcpy(&opt[i], &ouraddr.s6_addr[8], 8);
		i += 8;
	}

#ifdef notyet
	if (ISSET(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_COMPRESSION)) {
		opt[i++] = IPV6CP_OPT_COMPRESSION;
		opt[i++] = 4;
		opt[i++] = 0;	/* TBD */
		opt[i++] = 0;	/* TBD */
		/* variable length data may follow */
	}
#endif

	sp->scp[IDX_IPV6CP].confid = ++sp->scp[IDX_IPV6CP].seq;
	sppp_cp_send(sp, PPP_IPV6CP, CONF_REQ, sp->scp[IDX_IPV6CP].confid, i, &opt);
}
#else /*INET6*/
static void
sppp_ipv6cp_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static void
sppp_ipv6cp_open(struct sppp *sp, void *xcp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static enum cp_rcr_type
sppp_ipv6cp_confreq(struct sppp *sp, struct lcp_header *h,
    int len, uint8_t **msgbuf, size_t *buflen, size_t *msglen)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	return 0;
}

static void
sppp_ipv6cp_confrej(struct sppp *sp, struct lcp_header *h,
		    int len)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static void
sppp_ipv6cp_confnak(struct sppp *sp, struct lcp_header *h,
		    int len)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static void
sppp_ipv6cp_tlu(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static void
sppp_ipv6cp_tld(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}

static void
sppp_ipv6cp_scr(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
}
#endif /*INET6*/

/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                        The CHAP implementation.                          *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */
/*
 * The authentication protocols is implemented on the state machine for
 * control protocols. And it uses following actions and events.
 *
 * Actions:
 *    - scr: send CHAP_CHALLENGE and CHAP_RESPONSE
 *    - sca: send CHAP_SUCCESS
 *    - scn: send CHAP_FAILURE and shutdown lcp
 * Events:
 *    - RCR+: receive CHAP_RESPONSE containing correct digest
 *    - RCR-: receive CHAP_RESPONSE containing wrong digest
 *    - RCA: receive CHAP_SUCCESS
 *    - RCN: (this event is unused)
 *    - TO+: re-send CHAP_CHALLENGE and CHAP_RESPONSE
 *    - TO-: this layer finish
 */

/*
 * Handle incoming CHAP packets.
 */
void
sppp_chap_input(struct sppp *sp, struct mbuf *m)
{
	const bool debug = sppp_debug_enabled(sp);
	struct ifnet *ifp = sp->pp_if;
	struct lcp_header *h;
	int len = m->m_pkthdr.len;
	u_char *value, *name, digest[sizeof(sp->chap.challenge)];
	int value_len, name_len;
	MD5_CTX ctx;
	char abuf[SPPP_AUTHTYPE_NAMELEN];
	const char *authname;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (len < 4) {
		SPPP_DLOG(sp, "chap invalid packet length: "
		    "%d bytes\n", len);
		return;
	}
	h = mtod(m, struct lcp_header *);
	if (len > ntohs(h->len))
		len = ntohs(h->len);

	switch (h->type) {
	/* challenge, failure and success are his authproto */
	case CHAP_CHALLENGE:
		if (sp->myauth.secret == NULL || sp->myauth.name == NULL) {
			/* can't do anything useful */
			sp->pp_auth_failures++;
			SPPP_DLOG(sp, "chap input "
			    "without my name and my secret being set\n");
			break;
		}
		value = 1 + (u_char *)(h + 1);
		/* A bare header has no Value-Size octet; -1 name_len below. */
		value_len = len >= 5 ? value[-1] : 0;
		name = value + value_len;
		name_len = len - value_len - 5;
		if (name_len < 0) {
			if (debug) {
				authname = sppp_auth_type_name(abuf,
				    sizeof(abuf), PPP_CHAP, h->type);
				SPPP_LOG(sp, LOG_DEBUG,
				    "chap corrupted challenge "
				    "<%s id=0x%x len=%d",
				    authname, h->ident, ntohs(h->len));
				if (len > 4)
					sppp_print_bytes((u_char *)(h + 1),
					    len - 4);
				addlog(">\n");
			}
			break;
		}

		if (debug) {
			authname = sppp_auth_type_name(abuf,
			    sizeof(abuf), PPP_CHAP, h->type);
			SPPP_LOG(sp, LOG_DEBUG,
			    "chap input <%s id=0x%x len=%d name=",
			    authname, h->ident, ntohs(h->len));
			sppp_print_string((char *) name, name_len);
			addlog(" value-size=%d value=", value_len);
			sppp_print_bytes(value, value_len);
			addlog(">\n");
		}

		/* Compute reply value. */
		MD5Init(&ctx);
		MD5Update(&ctx, &h->ident, 1);
		MD5Update(&ctx, sp->myauth.secret, sp->myauth.secret_len);
		MD5Update(&ctx, value, value_len);
		MD5Final(sp->chap.digest, &ctx);
		sp->chap.digest_len = sizeof(sp->chap.digest);
		sp->scp[IDX_CHAP].rconfid = h->ident;

		sppp_wq_add(sp->wq_cp, &sp->chap.work_challenge_rcvd);
		break;

	case CHAP_SUCCESS:
		if (debug) {
			SPPP_LOG(sp, LOG_DEBUG, "chap success");
			if (len > 4) {
				addlog(": ");
				sppp_print_string((char *)(h + 1), len - 4);
			}
			addlog("\n");
		}

		if (h->ident != sp->scp[IDX_CHAP].rconfid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    chap.name, h->ident,
			    sp->scp[IDX_CHAP].rconfid);
			if_statinc(ifp, if_ierrors);
			break;
		}

		if (sp->chap.digest_len == 0) {
			SPPP_DLOG(sp, "receive CHAP success"
			    " without challenge\n");
			if_statinc(ifp, if_ierrors);
			break;
		}

		sp->pp_auth_failures = 0;
		sp->pp_authfail_proto = 0;	/* stale AUTH_FAIL latch */
		sp->pp_flags &= ~PP_NEEDAUTH;
		memset(sp->chap.digest, 0, sizeof(sp->chap.digest));
		sp->chap.digest_len = 0;

		if (!ISSET(sppp_auth_role(&chap, sp), SPPP_AUTH_SERV)) {
			/*
			 * we are not authenticator for CHAP,
			 * generate a dummy RCR+ event without CHAP_RESPONSE
			 */
			sp->scp[IDX_CHAP].rcr_type = CP_RCR_ACK;
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_rcr);
		}
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_rca);
		break;

	case CHAP_FAILURE:
		if (h->ident != sp->scp[IDX_CHAP].rconfid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    chap.name, h->ident, sp->scp[IDX_CHAP].rconfid);
			if_statinc(ifp, if_ierrors);
			break;
		}

		if (sp->chap.digest_len == 0) {
			SPPP_DLOG(sp, "receive CHAP failure "
			    "without challenge\n");
			if_statinc(ifp, if_ierrors);
			break;
		}

		sp->pp_auth_failures++;
		sp->pp_authfail_proto = PPP_CHAP;	/* devctl AUTH_FAIL */
		if (sppp_rxlog_ok(sp)) {
			SPPP_LOG(sp, LOG_INFO, "chap failure");
			if (debug && len > 4) {
				addlog(": ");
				sppp_print_string((char *)(h + 1), len - 4);
			}
			addlog("\n");
		}

		memset(sp->chap.digest, 0, sizeof(sp->chap.digest));
		sp->chap.digest_len = 0;
		/*
		 * await LCP shutdown by authenticator,
		 * so we don't have to enqueue sc->scp[IDX_CHAP].work_rcn
		 */
		break;

	/* response is my authproto */
	case CHAP_RESPONSE:
		if (sp->hisauth.name == NULL || sp->hisauth.secret == NULL) {
			/* can't do anything useful */
			SPPP_DLOG(sp, "chap response "
			    "without his name and his secret being set\n");
			break;
		}
		value = 1 + (u_char *)(h + 1);
		/* A bare header has no Value-Size octet; -1 name_len below. */
		value_len = len >= 5 ? value[-1] : 0;
		name = value + value_len;
		name_len = len - value_len - 5;
		if (name_len < 0) {
			if (debug) {
				authname = sppp_auth_type_name(abuf,
				    sizeof(abuf), PPP_CHAP, h->type);
				SPPP_LOG(sp, LOG_DEBUG,
				    "chap corrupted response "
				    "<%s id=0x%x len=%d",
				    authname, h->ident, ntohs(h->len));
				if (len > 4)
					sppp_print_bytes((u_char *)(h + 1),
					    len - 4);
				addlog(">\n");
			}
			break;
		}
		if (h->ident != sp->scp[IDX_CHAP].confid) {
			SPPP_DLOG(sp, "chap dropping response for old ID "
			    "(got %d, expected %d)\n",
			    h->ident, sp->scp[IDX_CHAP].confid);
			break;
		} else {
			sp->scp[IDX_CHAP].rconfid = h->ident;
		}

		if (sp->hisauth.name != NULL &&
		    (name_len != sp->hisauth.name_len
		    || memcmp(name, sp->hisauth.name, name_len) != 0)) {
			SPPP_LOG(sp, LOG_INFO,
			    "chap response, his name ");
			sppp_print_string(name, name_len);
			addlog(" != expected ");
			sppp_print_string(sp->hisauth.name,
					  sp->hisauth.name_len);
			addlog("\n");

			/* generate RCR- event */
			sp->scp[IDX_CHAP].rcr_type = CP_RCR_NAK;
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_rcr);
			break;
		}

		if (debug) {
			authname = sppp_auth_type_name(abuf,
			    sizeof(abuf), PPP_CHAP, h->type);
			SPPP_LOG(sp, LOG_DEBUG, "chap input(%s) "
			    "<%s id=0x%x len=%d name=",
			    sppp_state_name(sp->scp[IDX_CHAP].state),
			    authname, h->ident, ntohs(h->len));
			sppp_print_string((char *)name, name_len);
			addlog(" value-size=%d value=", value_len);
			sppp_print_bytes(value, value_len);
			addlog(">\n");
		}

		if (value_len == sizeof(sp->chap.challenge) &&
		    value_len == sizeof(sp->chap.digest)) {
			MD5Init(&ctx);
			MD5Update(&ctx, &h->ident, 1);
			MD5Update(&ctx, sp->hisauth.secret, sp->hisauth.secret_len);
			MD5Update(&ctx, sp->chap.challenge, sizeof(sp->chap.challenge));
			MD5Final(digest, &ctx);

			if (memcmp(digest, value, value_len) == 0) {
				sp->scp[IDX_CHAP].rcr_type = CP_RCR_ACK;
			} else {
				sp->scp[IDX_CHAP].rcr_type = CP_RCR_NAK;
			}
		} else {
			if (debug) {
				SPPP_LOG(sp, LOG_DEBUG,
				    "chap bad hash value length: "
				    "%d bytes, should be %zu\n",
				    value_len, sizeof(sp->chap.challenge));
			}

			sp->scp[IDX_CHAP].rcr_type = CP_RCR_NAK;
		}

		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_rcr);

		/* generate a dummy RCA event */
		if (sp->scp[IDX_CHAP].rcr_type == CP_RCR_ACK &&
		    (!ISSET(sppp_auth_role(&chap, sp), SPPP_AUTH_PEER) ||
		    sp->chap.rechallenging)) {
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_CHAP].work_rca);
		}
		break;

	default:
		/* Unknown CHAP packet type -- ignore. */
		if (debug) {
			SPPP_LOG(sp, LOG_DEBUG, "chap unknown input(%s) "
			    "<0x%x id=0x%xh len=%d",
			    sppp_state_name(sp->scp[IDX_CHAP].state),
			    h->type, h->ident, ntohs(h->len));
			if (len > 4)
				sppp_print_bytes((u_char *)(h + 1), len - 4);
			addlog(">\n");
		}
		break;

	}
}

static void
sppp_chap_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_cp_init(&chap, sp);

	SPPP_WQ_SET(&sp->chap.work_challenge_rcvd,
	    sppp_chap_rcv_challenge_event, &chap);
}

static void
sppp_chap_open(struct sppp *sp, void *xcp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	memset(sp->chap.digest, 0, sizeof(sp->chap.digest));
	sp->chap.digest_len = 0;
	sp->chap.rechallenging = false;
	sp->chap.response_rcvd = false;
	sppp_open_event(sp, xcp);
}

static void
sppp_chap_tlu(struct sppp *sp)
{
	int i;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	i = 0;
	sp->scp[IDX_CHAP].rst_counter = sp->lcp.max_configure;
	sp->pp_auth_failures = 0;

	SPPP_LOG(sp, LOG_DEBUG, "chap %s",
	    sp->pp_phase == SPPP_PHASE_NETWORK ? "reconfirmed" : "tlu");

	/*
	 * Some broken CHAP implementations (Conware CoNet, firmware
	 * 4.0.?) don't want to re-authenticate their CHAP once the
	 * initial challenge-response exchange has taken place.
	 * Provide for an option to avoid rechallenges.
	 */
	if (ISSET(sppp_auth_role(&chap, sp), SPPP_AUTH_SERV) &&
	    (sp->hisauth.flags & SPPP_AUTHFLAG_NORECHALLENGE) == 0) {
		/*
		 * Compute the re-challenge timeout.  This will yield
		 * a number between 300 and 810 seconds.
		 */
		i = 300 + ((unsigned)(cprng_fast32() & 0xff00) >> 7);
		callout_schedule(&sp->scp[IDX_CHAP].ch, i * hz);

		if (sppp_debug_enabled(sp)) {
			addlog(", next rechallenge in %d seconds", i);
		}
	}

	addlog("\n");

	/*
	 * If we are already in phase network, we are done here.  This
	 * is the case if this is a dummy tlu event after a re-challenge.
	 */
	if (sp->pp_phase != SPPP_PHASE_NETWORK)
		sppp_phase_network(sp);
}

static void
sppp_chap_scr(struct sppp *sp)
{
	uint32_t *ch;
	u_char clen, dsize;
	int role;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	role = sppp_auth_role(&chap, sp);

	if (ISSET(role, SPPP_AUTH_SERV) &&
	    !sp->chap.response_rcvd) {
		/* we are authenticator for CHAP, send challenge */
		ch = (uint32_t *)sp->chap.challenge;
		clen = sizeof(sp->chap.challenge);
		/* Compute random challenge. */
		cprng_strong(kern_cprng, ch, clen, 0);

		sp->scp[IDX_CHAP].confid = ++sp->scp[IDX_CHAP].seq;
		sppp_auth_send(&chap, sp, CHAP_CHALLENGE, sp->scp[IDX_CHAP].confid,
		    sizeof(clen), (const char *)&clen,
		    sizeof(sp->chap.challenge), sp->chap.challenge,
		    0);
	}

	if (ISSET(role, SPPP_AUTH_PEER) &&
	    sp->chap.digest_len > 0) {
		/* we are peer for CHAP, send response */
		dsize = sp->chap.digest_len;

		sppp_auth_send(&chap, sp, CHAP_RESPONSE, sp->scp[IDX_CHAP].rconfid,
		    sizeof(dsize), (const char *)&dsize,
		    sp->chap.digest_len, sp->chap.digest,
		    sp->myauth.name_len, sp->myauth.name, 0);
	}
}

static void
sppp_chap_rcv_challenge_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;

	SPPP_KASSERT(!cpu_softintr_p());

	sp->chap.rechallenging = false;

	switch (sp->scp[IDX_CHAP].state) {
	case STATE_REQ_SENT:
		sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
		cp->scr(sp);
		break;
	case STATE_OPENED:
		sppp_cp_change_state(cp, sp, STATE_ACK_SENT);
		cp->scr(sp);
		break;
	}
}

/*
 *--------------------------------------------------------------------------*
 *                                                                          *
 *                        The PAP implementation.                           *
 *                                                                          *
 *--------------------------------------------------------------------------*
 */
/*
 * PAP uses following actions and events.
 * Actions:
 *    - scr: send PAP_REQ
 *    - sca: send PAP_ACK
 *    - scn: send PAP_NAK
 * Events:
 *    - RCR+: receive PAP_REQ containing correct username and password
 *    - RCR-: receive PAP_REQ containing wrong username and password
 *    - RCA: receive PAP_ACK
 *    - RCN: (this event is unused)
 *    - TO+: re-send PAP_REQ
 *    - TO-: this layer finish
 */

/*
 * Handle incoming PAP packets.  */
static void
sppp_pap_input(struct sppp *sp, struct mbuf *m)
{
	const bool debug = sppp_debug_enabled(sp);
	struct ifnet *ifp = sp->pp_if;
	struct lcp_header *h;
	int len;
	char *name, *secret;
	int name_len, secret_len;
	char abuf[SPPP_AUTHTYPE_NAMELEN];
	const char *authname;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	/*
	 * Malicious input might leave this uninitialized, so
	 * init to an impossible value.
	 */
	secret_len = -1;

	len = m->m_pkthdr.len;
	if (len < 5) {
		SPPP_DLOG(sp, "pap invalid packet length: "
		    "%d bytes\n", len);
		return;
	}
	h = mtod(m, struct lcp_header *);
	if (len > ntohs(h->len))
		len = ntohs(h->len);

	switch (h->type) {
	/* PAP request is my authproto */
	case PAP_REQ:
		if (sp->hisauth.name == NULL || sp->hisauth.secret == NULL) {
			/* can't do anything useful */
			SPPP_DLOG(sp, "pap request"
			    " without his name and his secret being set\n");
			break;
		}
		name = 1 + (u_char *)(h + 1);
		name_len = (u_char)name[-1];
		secret = name + name_len + 1;
		if (name_len > len - 6 ||
		    (secret_len = (u_char)secret[-1]) > len - 6 - name_len) {
			if (debug) {
				authname = sppp_auth_type_name(abuf,
				    sizeof(abuf), PPP_PAP, h->type);
				SPPP_LOG(sp, LOG_DEBUG, "pap corrupted input "
				    "<%s id=0x%x len=%d",
				    authname, h->ident, ntohs(h->len));
				if (len > 4)
					sppp_print_bytes((u_char *)(h + 1),
					    len - 4);
				addlog(">\n");
			}
			break;
		}
		if (debug) {
			authname = sppp_auth_type_name(abuf,
			    sizeof(abuf), PPP_PAP, h->type);
			SPPP_LOG(sp, LOG_DEBUG, "pap input(%s) "
			    "<%s id=0x%x len=%d name=",
			    sppp_state_name(sp->scp[IDX_PAP].state),
			    authname, h->ident, ntohs(h->len));
			sppp_print_string((char *)name, name_len);
			/* Port (R011): never log the peer's PAP secret. */
			addlog(" secret=<redacted>>\n");
		}

		sp->scp[IDX_PAP].rconfid = h->ident;

		if (name_len == sp->hisauth.name_len &&
		    memcmp(name, sp->hisauth.name, name_len) == 0 &&
		    secret_len == sp->hisauth.secret_len &&
		    memcmp(secret, sp->hisauth.secret, secret_len) == 0) {
			sp->scp[IDX_PAP].rcr_type = CP_RCR_ACK;
		} else {
			sp->scp[IDX_PAP].rcr_type = CP_RCR_NAK;
		}

		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_PAP].work_rcr);

		/* generate a dummy RCA event */
		if (sp->scp[IDX_PAP].rcr_type == CP_RCR_ACK &&
		    !ISSET(sppp_auth_role(&pap, sp), SPPP_AUTH_PEER)) {
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_PAP].work_rca);
		}
		break;

	/* ack and nak are his authproto */
	case PAP_ACK:
		if (debug) {
			SPPP_LOG(sp, LOG_DEBUG, "pap success");
			name = 1 + (u_char *)(h + 1);
			/*
			 * Msg-Length is octet 4, unsigned (name is a char *,
			 * signed on amd64: 0xff read back as -1 before).
			 */
			if (len > 5 &&
			    (name_len = (u_char)name[-1]) <= len - 5) {
				addlog(": ");
				sppp_print_string(name, name_len);
			}
			addlog("\n");
		}

		if (h->ident != sp->scp[IDX_PAP].confid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    pap.name, h->ident, sp->scp[IDX_PAP].rconfid);
			if_statinc(ifp, if_ierrors);
			break;
		}

		sp->pp_auth_failures = 0;
		sp->pp_authfail_proto = 0;	/* stale AUTH_FAIL latch */
		sp->pp_flags &= ~PP_NEEDAUTH;

		/* we are not authenticator, generate a dummy RCR+ event */
		if (!ISSET(sppp_auth_role(&pap, sp), SPPP_AUTH_SERV)) {
			sp->scp[IDX_PAP].rcr_type = CP_RCR_ACK;
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_PAP].work_rcr);
		}

		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_PAP].work_rca);
		break;

	case PAP_NAK:
		if (debug) {
			SPPP_LOG(sp, LOG_INFO, "pap failure");
			name = 1 + (u_char *)(h + 1);
			/*
			 * Msg-Length is octet 4, unsigned (name is a char *,
			 * signed on amd64: 0xff read back as -1 before).
			 */
			if (len > 5 &&
			    (name_len = (u_char)name[-1]) <= len - 5) {
				addlog(": ");
				sppp_print_string(name, name_len);
			}
			addlog("\n");
		} else if (sppp_rxlog_ok(sp)) {
			SPPP_LOG(sp, LOG_INFO, "pap failure\n");
		}

		if (h->ident != sp->scp[IDX_PAP].confid) {
			SPPP_DLOG(sp, "%s id mismatch 0x%x != 0x%x\n",
			    pap.name, h->ident, sp->scp[IDX_PAP].rconfid);
			if_statinc(ifp, if_ierrors);
			break;
		}

		sp->pp_auth_failures++;
		sp->pp_authfail_proto = PPP_PAP;	/* devctl AUTH_FAIL */
		/*
		 * await LCP shutdown by authenticator,
		 * so we don't have to enqueue sc->scp[IDX_PAP].work_rcn
		 */
		break;

	default:
		/* Unknown PAP packet type -- ignore. */
		if (debug) {
			SPPP_LOG(sp, LOG_DEBUG, "pap corrupted input "
			    "<0x%x id=0x%x len=%d",
			    h->type, h->ident, ntohs(h->len));
			if (len > 4)
				sppp_print_bytes((u_char *)(h + 1), len - 4);
			addlog(">\n");
		}
		break;
	}
}

static void
sppp_pap_init(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	sppp_cp_init(&pap, sp);
}

static void
sppp_pap_tlu(struct sppp *sp)
{

	SPPP_DLOG(sp, "%s tlu\n", pap.name);

	sp->scp[IDX_PAP].rst_counter = sp->lcp.max_configure;
	sp->pp_auth_failures = 0;

	if (sp->pp_phase < SPPP_PHASE_NETWORK)
		sppp_phase_network(sp);
}

static void
sppp_pap_scr(struct sppp *sp)
{
	u_char idlen, pwdlen;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (ISSET(sppp_auth_role(&pap, sp), SPPP_AUTH_PEER) &&
	    sp->scp[IDX_PAP].state != STATE_ACK_RCVD) {
		if (sp->myauth.secret == NULL ||
		    sp->myauth.name == NULL) {
			SPPP_LOG(sp, LOG_DEBUG,
			    "couldn't send PAP_REQ "
			    "because of no name or no secret\n");
		} else {
			sp->scp[IDX_PAP].confid = ++sp->scp[IDX_PAP].seq;
			pwdlen = sp->myauth.secret_len;
			idlen = sp->myauth.name_len;

			sppp_auth_send(&pap, sp, PAP_REQ, sp->scp[IDX_PAP].confid,
			    sizeof idlen, (const char *)&idlen,
			    idlen, sp->myauth.name,
			    sizeof pwdlen, (const char *)&pwdlen,
			    pwdlen, sp->myauth.secret,
			    0);
		}
	}
}

/*
 * Random miscellaneous functions.
 */

/*
 * Send a PAP or CHAP proto packet.
 *
 * Variadic function, each of the elements for the ellipsis is of type
 * ``size_t mlen, const u_char *msg''.  Processing will stop iff
 * mlen == 0.
 * NOTE: never declare variadic functions with types subject to type
 * promotion (i.e. u_char). This is asking for big trouble depending
 * on the architecture you are on...
 */

static void
sppp_auth_send(const struct cp *cp, struct sppp *sp,
               unsigned int type, unsigned int id,
	       ...)
{
	struct ifnet *ifp = sp->pp_if;
	struct lcp_header *lh;
	struct mbuf *m;
	u_char *p;
	int len;
	size_t pkthdrlen;
	unsigned int mlen;
	const char *msg;
	va_list ap;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m_reset_rcvif(m);

	if (ISSET(sp->pp_dev_flags, PP_DEVF_NOFRAMING)) {
		*mtod(m, uint16_t *) = htons(cp->proto);
		pkthdrlen = 2;
		lh = (struct lcp_header *)(mtod(m, uint8_t *)+2);
	} else {
		struct ppp_header *h;
		h = mtod(m, struct ppp_header *);
		h->address = PPP_ALLSTATIONS;		/* broadcast address */
		h->control = PPP_UI;			/* Unnumbered Info */
		h->protocol = htons(cp->proto);
		pkthdrlen = PPP_HEADER_LEN;

		lh = (struct lcp_header *)(h + 1);
	}

	lh->type = type;
	lh->ident = id;
	p = (u_char *)(lh + 1);

	va_start(ap, id);
	len = 0;

	while ((mlen = (unsigned int)va_arg(ap, size_t)) != 0) {
		msg = va_arg(ap, const char *);
		len += mlen;
		if (len > MHLEN - pkthdrlen - LCP_HEADER_LEN) {
			va_end(ap);
			m_freem(m);
			return;
		}

		memcpy(p, msg, mlen);
		p += mlen;
	}
	va_end(ap);

	m->m_pkthdr.len = m->m_len = pkthdrlen + LCP_HEADER_LEN + len;
	lh->len = htons(LCP_HEADER_LEN + len);

	if (sppp_debug_enabled(sp)) {
		char abuf[SPPP_AUTHTYPE_NAMELEN];
		const char *authname;

		authname = sppp_auth_type_name(abuf,
		    sizeof(abuf), cp->proto, lh->type);
		SPPP_LOG(sp, LOG_DEBUG, "%s output <%s id=0x%x len=%d",
		    cp->name, authname,
		    lh->ident, ntohs(lh->len));
		if (len) {
			/*
			 * Port (R011): a PAP Authenticate-Request carries the
			 * password in the clear -- never dump it to the log.
			 * Print the peer name (from the packet's idlen/name
			 * prefix) and a fixed redaction placeholder instead of
			 * the raw bytes.  Other auth packets (CHAP challenge/
			 * response digests, PAP ack/nak messages) contain no
			 * plaintext secret, so those still print as bytes.
			 */
			const u_char *p = (u_char *)(lh + 1);
			const u_char idlen = p[0];
			if (cp->proto == PPP_PAP && lh->type == PAP_REQ &&
			    len >= 2 && idlen > 0 && idlen <= len - 2) {
				addlog(" name=");
				sppp_print_string((const char *)(p + 1), idlen);
				addlog(" secret=<redacted>");
			} else {
				sppp_print_bytes(p, len);
			}
		}
		addlog(">\n");
	}
	/* SPPPSUBR_MPSAFE direct transmit (pp_cpq/if_start_lock removed;
	 * S01 compat: sppp lock is dropped around the transmit). */
#ifndef SPPP_LOWER_COUNTS_BYTES
	if_statadd(ifp, if_obytes, m->m_pkthdr.len + sp->pp_framebytes);
#endif
	SPPP_UNLOCK(sp);
	(void)if_transmit_lock(ifp, m);
	SPPP_LOCK(sp, RW_WRITER);
}

static int
sppp_auth_role(const struct cp *cp, struct sppp *sp)
{
	int role;

	role = SPPP_AUTH_NOROLE;

	if (sp->hisauth.proto == cp->proto &&
	    ISSET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO))
		SET(role, SPPP_AUTH_SERV);

	if (sp->myauth.proto == cp->proto)
		SET(role, SPPP_AUTH_PEER);

	return role;
}

static void
sppp_auth_to_event(struct sppp *sp, void *xcp)
{
	const struct cp *cp = xcp;
	bool override;
	int state;

	SPPP_KASSERT(SPPP_WLOCKED(sp));
	SPPP_KASSERT(!cpu_softintr_p());

	override = false;
	state = sp->scp[cp->protoidx].state;

	if (sp->scp[cp->protoidx].rst_counter > 0) {
		/* override TO+ event */
		switch (state) {
		case STATE_OPENED:
			if ((sp->hisauth.flags & SPPP_AUTHFLAG_NORECHALLENGE) == 0) {
				override = true;
				sp->chap.rechallenging = true;
				sp->chap.response_rcvd = false;
				sppp_cp_change_state(cp, sp, STATE_REQ_SENT);
				cp->scr(sp);
			}
			break;

		case STATE_ACK_RCVD:
			override = true;
			cp->scr(sp);
			callout_schedule(&sp->scp[cp->protoidx].ch, sp->lcp.timeout);
			break;
		}
	}

	if (override) {
		SPPP_DLOG(sp, "%s TO(%s) rst_counter = %d\n",
		    cp->name, sppp_state_name(state),
		    sp->scp[cp->protoidx].rst_counter);
		sp->scp[cp->protoidx].rst_counter--;
	} else {
		/*
		 * TO- with our auth unanswered: a failure for the backoff,
		 * or every redial would go out at once.
		 */
		if (sp->scp[cp->protoidx].rst_counter <= 0 &&
		    sppp_auth_awaited(sp, cp))
			sppp_auth_unanswered(sp, cp, "timed out");
		sppp_to_event(sp, xcp);
	}
}

/*
 * The peer asked us to authenticate with `cp` (PP_NEEDAUTH; sppp_lcp_tlu()
 * opens every auth CP regardless) and has not accepted us yet: REQ_SENT or
 * ACK_SENT.  ACK_RCVD means we were accepted and wait on the peer.
 */
static bool
sppp_auth_awaited(struct sppp *sp, const struct cp *cp)
{
	int state = sp->scp[cp->protoidx].state;

	return ((sp->pp_flags & PP_NEEDAUTH) != 0 &&
	    ISSET(sppp_auth_role(cp, sp), SPPP_AUTH_PEER) &&
	    (state == STATE_REQ_SENT || state == STATE_ACK_SENT));
}

/*
 * No Ack/NAK for our auth: count a failure and latch AUTH_FAIL, unless a
 * NAK already latched in pp_authfail_proto counted this attempt.
 */
static void
sppp_auth_unanswered(struct sppp *sp, const struct cp *cp, const char *why)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (sp->pp_authfail_proto != 0)
		return;
	sp->pp_auth_failures++;
	sp->pp_authfail_proto = cp->proto;
	SPPP_LOG(sp, LOG_INFO, "%s authentication %s\n", cp->name, why);
}

static void
sppp_auth_screply(const struct cp *cp, struct sppp *sp, u_char ctype,
    uint8_t ident, size_t _mlen __unused, void *_msg __unused)
{
	static const char *succmsg = "Welcome!";
	static const char *failmsg = "Failed...";
	const char *msg;
	u_char type, mlen;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (!ISSET(sppp_auth_role(cp, sp), SPPP_AUTH_SERV))
		return;

	if (ctype == CONF_ACK) {
		type = cp->proto == PPP_CHAP ? CHAP_SUCCESS : PAP_ACK;
		msg = succmsg;
		mlen = sizeof(succmsg) - 1;

		sp->pp_auth_failures = 0;
	} else {
		type = cp->proto == PPP_CHAP ? CHAP_FAILURE : PAP_NAK;
		msg = failmsg;
		mlen = sizeof(failmsg) - 1;

		/* Reset LCP if auth failed */
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
		sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
		sp->pp_auth_failures++;
	}

	sppp_auth_send(cp, sp, type, ident, mlen, (const u_char *)msg, 0);
}

/*
 * Send keepalive packets, every sppp_keepalive_interval seconds.
 *
 * M002/S03/T2: the keepalive list and the callout are per-vnet.  The
 * callout fires from softclock with curvnet NULL or foreign, so the vnet
 * captured at schedule time (callout setfunc arg, set in
 * sppp_keepalive_vnet_init()) is made current before V_spppq (or any
 * other V_ state) is touched; the per-interface CURVNET_SET around the
 * ECHO_REQ transmit is no longer needed because every interface on this
 * list lives in this same vnet.
 */
static void
sppp_keepalive(void *arg)
{
	struct sppp *sp;
	uint32_t now, last_receive;
	struct vnet *vnet = arg;

	CURVNET_SET(vnet);
	SPPPQ_LOCK();

	now = time_uptime32;
	for (sp = V_spppq; sp; sp = sp->pp_next) {
		SPPP_LOCK(sp, RW_WRITER);
		last_receive = atomic_load_relaxed(&sp->pp_last_receive);

		/* Keepalive mode disabled or channel down? */
		if (! ISSET(sp->pp_dev_flags, PP_DEVF_KEEPALIVE) ||
		    ! sp->pp_connecting) {
			SPPP_UNLOCK(sp);
			continue;
		}

		/* No keepalive in PPP mode if LCP not opened yet. */
		if (sp->pp_phase < SPPP_PHASE_AUTHENTICATE) {
			SPPP_UNLOCK(sp);
			continue;
		}

		/* No echo reply, but maybe user data passed through? */
		if (sp->pp_max_noreceive != 0 &&
		    (now - last_receive) < sp->pp_max_noreceive) {
			sp->pp_alivecnt = 0;
			SPPP_UNLOCK(sp);
			continue;
		}

		/* No echo request */
		if (sp->pp_alive_interval == 0) {
			SPPP_UNLOCK(sp);
			continue;
		}

		/* send a ECHO_REQ once in sp->pp_alive_interval times */
		if ((V_sppp_keepalive_cnt % sp->pp_alive_interval) != 0) {
			SPPP_UNLOCK(sp);
			continue;
		}

		if (sp->pp_alivecnt >= sp->pp_maxalive) {
			/* No keepalive packets got. Stop the interface. */
			SPPP_LOG(sp, LOG_INFO,"LCP keepalive timed out, "
			    "going to restart the connection\n");

			sp->pp_alivecnt = 0;

			if (sp->pp_flags & PP_IFDOWN)
				sppp_wq_add(sp->wq_cp, &sp->work_ifdown);
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_close);
			sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);

			SPPP_UNLOCK(sp);
			continue;
		}
		if (sp->pp_alivecnt < sp->pp_maxalive)
			++sp->pp_alivecnt;
		if (sp->pp_phase >= SPPP_PHASE_AUTHENTICATE) {
			int32_t nmagic = ISSET(sp->lcp.opts,
			    SPPP_LCP_OPT_MAGIC) ? htonl(sp->lcp.magic) : 0;
			sp->lcp.echoid = ++sp->scp[IDX_LCP].seq;
			/*
			 * Port: this runs from softclock under the curvnet set
			 * above; sppp_cp_send() ends in if_transmit() ->
			 * pppoe_transmit(), which reads per-vnet state
			 * (V_pppoe_stats, V_link_pfil_head) -- M001 ruling #3
			 * requires that vnet to be current.  The outer
			 * SPPPQ_LOCK ensures a concurrent sppp_detach() cannot
			 * free sp while we are inside this section.
			 */
			sppp_cp_send(sp, PPP_LCP, ECHO_REQ,
				sp->lcp.echoid, 4, &nmagic);
		}

		SPPP_UNLOCK(sp);
	}
	V_sppp_keepalive_cnt++;
	callout_schedule(&V_keepalive_ch,
	    hz * V_sppp_keepalive_interval);

	SPPPQ_UNLOCK();
	CURVNET_RESTORE();
}

#ifdef INET
/*
 * Get both IP addresses.
 */
static void
sppp_get_ip_addrs(struct sppp *sp, uint32_t *src, uint32_t *dst, uint32_t *srcmask)
{
	struct ifnet *ifp = sp->pp_if;
	struct ifaddr *ifa;
	uint32_t ssrc, ddst;

	ssrc = ddst = 0;
	/*
	 * Pick the first AF_INET address from the list,
	 * aliases don't make any sense on a p2p link anyway.
	 * Native FreeBSD if_addrhead walk (locks via if_addr_lock;
	 * S03 owns the full SIOCAIFADDR address recipe).
	 */
	IF_ADDR_WLOCK(ifp);
	CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr_in *si, *sm;

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		si = satosin(ifa->ifa_addr);
		sm = satosin(ifa->ifa_netmask);
		if (si->sin_addr.s_addr) {
			ssrc = si->sin_addr.s_addr;
			if (srcmask)
				*srcmask = ntohl(sm->sin_addr.s_addr);
		}

		si = satosin(ifa->ifa_dstaddr);
		if (si && si->sin_addr.s_addr)
			ddst = si->sin_addr.s_addr;
		break;
	}
	IF_ADDR_WUNLOCK(ifp);

	if (dst) *dst = ntohl(ddst);
	if (src) *src = ntohl(ssrc);
}

/*
 * Set IP addresses.
 * If an address is 0, leave it the way it is.
 */
static void
sppp_set_ip_addrs(struct sppp *sp)
{
	struct ifnet *ifp = sp->pp_if;
	struct ifaddr *ifa;
	struct sockaddr_in *si, *dest;
	uint32_t myaddr = 0, hisaddr = 0;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/*
	 * S01 T3: NetBSD applied the negotiated IPv4 addresses with
	 * in_ifinit() (route/hash/pfil plumbing).  FreeBSD has no
	 * in_ifinit KPI; S03 owns the SIOCAIFADDR recipe (KPI table
	 * row "sppp_set_ip_addrs", rewritten (S03)).  The old stand-in
	 * patched the ifaddr in place; the driver now runs the recipe.
	 *
	 * The ifaddr walk below only supplies fall-back values for
	 * NON-negotiated (statically configured) addresses; the IPCP
	 * req_myaddr/req_hisaddr values are authoritative whenever the
	 * dynamic flags were agreed, regardless of whether an ifaddr
	 * exists yet (first dial: none does).
	 */
	si = dest = NULL;
	IF_ADDR_WLOCK(ifp);
	CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		si = satosin(ifa->ifa_addr);
		dest = satosin(ifa->ifa_dstaddr);
		break;
	}
	IF_ADDR_WUNLOCK(ifp);

	SPPP_DLOG(sp, "%s: address apply is S03's SIOCAIFADDR recipe\n",
	    __func__);

	if ((sp->ipcp.flags & IPCP_MYADDR_DYN) && (sp->ipcp.flags & IPCP_MYADDR_SEEN))
		myaddr = sp->ipcp.req_myaddr;
	else if (si != NULL)
		myaddr = ntohl(si->sin_addr.s_addr);

	if ((sp->ipcp.flags & IPCP_HISADDR_DYN) && (sp->ipcp.flags & IPCP_HISADDR_SEEN))
		hisaddr = sp->ipcp.req_hisaddr;
	else if (dest != NULL)
		hisaddr = ntohl(dest->sin_addr.s_addr);

	/*
	 * Record the negotiated endpoints and let the driver's sc_addr_task
	 * (pppoe_taskq, CURVNET_SET, spike S2 recipe) run
	 * in_control_ioctl(SIOCAIFADDR, ...).  We hold pp_lock here (IPCP
	 * tlu runs on the sppp workqueue); pppoe_set_ip_addrs() only
	 * snapshots the values and enqueues, so no sleepable or V_ path runs
	 * under pp_lock.
	 */
	pppoe_set_ip_addrs(sp, myaddr, hisaddr);
}

/*
 * Clear IP addresses.
 */
static void
sppp_clear_ip_addrs(struct sppp *sp)
{
	SPPP_KASSERT(SPPP_WLOCKED(sp));

	/*
	 * S03 T1: NetBSD cleared the address with in_ifinit()/psref (both
	 * NetBSD-only); the old stand-in zeroed the ifaddr in place under
	 * if_addr_lock.  The driver's sc_addr_task now runs
	 * in_control_ioctl(SIOCDIFADDR, ...) on pppoe_taskq under
	 * CURVNET_SET (spike S2 recipe, R009); pppoe_clear_ip_addrs() only
	 * snapshots and enqueues under pp_lock.
	 */
	SPPP_DLOG(sp, "%s: deferring address clear to the driver's "
	    "SIOCDIFADDR task (S03 T1)\n", __func__);

	pppoe_clear_ip_addrs(sp);
}
#endif

#ifdef INET6
/*
 * Get both IPv6 addresses.
 */
static void
sppp_get_ip6_addrs(struct sppp *sp, struct in6_addr *src, struct in6_addr *dst,
		   struct in6_addr *srcmask)
{
	struct ifnet *ifp = sp->pp_if;
	struct ifaddr *ifa;
	struct in6_addr ssrc, ddst;

	memset(&ssrc, 0, sizeof(ssrc));
	memset(&ddst, 0, sizeof(ddst));
	/*
	 * Pick the first link-local AF_INET6 address from the list,
	 * aliases don't make any sense on a p2p link anyway.  Native
	 * FreeBSD if_addrhead walk (S04 owns the address recipe).
	 */
	IF_ADDR_WLOCK(ifp);
	CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr_in6 *si, *sm;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		si = satosin6(ifa->ifa_addr);
		if (!IN6_IS_ADDR_LINKLOCAL(&si->sin6_addr))
			continue;
		sm = satosin6(ifa->ifa_netmask);
		if (!IN6_IS_ADDR_UNSPECIFIED(&si->sin6_addr)) {
			memcpy(&ssrc, &si->sin6_addr, sizeof(ssrc));
			if (srcmask) {
				memcpy(srcmask, &sm->sin6_addr,
				    sizeof(*srcmask));
			}
		}

		si = satosin6(ifa->ifa_dstaddr);
		if (si && !IN6_IS_ADDR_UNSPECIFIED(&si->sin6_addr))
			memcpy(&ddst, &si->sin6_addr, sizeof(ddst));
		break;
	}
	IF_ADDR_WUNLOCK(ifp);

	/*
	 * First dial: pppoe0 has no link-local ifaddr yet (there is none to
	 * copy -- IPv6CP applies one only once it reaches Opened, T2/R009).
	 * Fall back to the interface identifier the lower layer (if_pppoe)
	 * seeded from the parent Ethernet MAC at session establishment, so
	 * the first IPv6CP Configure-Request still carries a non-trivial
	 * Interface-Identifier that the peer can Ack into Opened.
	 */
	if (src != NULL && IN6_IS_ADDR_UNSPECIFIED(&ssrc) &&
	    sppp_ip6_ifid_present(sp->ipv6cp.my_ifid)) {
		memset(&ssrc, 0, sizeof(ssrc));
		ssrc.s6_addr16[0] = htons(0xfe80);
		(void)in6_setscope(&ssrc, ifp, NULL);
		memcpy(&ssrc.s6_addr[8], sp->ipv6cp.my_ifid, 8);
	}

	if (dst)
		memcpy(dst, &ddst, sizeof(*dst));
	if (src)
		memcpy(src, &ssrc, sizeof(*src));
}

/*
 * True when an 8-byte IPv6CP interface identifier has been populated
 * (i.e. is not all-zero).
 */
static bool
sppp_ip6_ifid_present(const uint8_t *ifid)
{
	u_int i;

	for (i = 0; i < 8; i++) {
		if (ifid[i] != 0)
			return (true);
	}
	return (false);
}

/*
 * Apply an IPv6CP-negotiated link-local address to the interface (T2,
 * R009; design spec KPI row "sppp_update_ip6_addr", reviewed).
 *
 * NetBSD's reference implementation (sppp_set_ip6_addr, under
 * IPV6CP_MYIFID_DYN) patched the existing link-local ifaddr in place
 * via in6_ifinit()/pfil_run_addrhooks and took curlwp_bind()/psref --
 * all NetBSD-only KPIs.  This port defers the assignment to the driver
 * instead, exactly as sppp_set_ip_addrs() does for IPv4 since S03:
 * snapshot the wanted address under pp_lock and enqueue the driver's
 * sc_addr_task, which runs in6_control_ioctl(SIOCAIFADDR_IN6, ...) on
 * pppoe_taskq under CURVNET_SET (spike S2 recipe, R009).  With
 * IPV6CP_MYIFID_DYN still undefined the NetBSD dynamic-ifid path
 * (sppp_gen_ip6_addr) stays dead; our ifid is fixed per parent MAC.
 */
static void
sppp_update_ip6_addr(struct sppp *sp, const struct in6_addr *ll)
{
	SPPP_KASSERT(SPPP_WLOCKED(sp));

	SPPP_DLOG(sp, "%s: deferring link-local assignment to the "
	    "driver's SIOCAIFADDR_IN6 task (T2)\n", __func__);

	pppoe_set_ip6_addr(sp, ll);
}

/*
 * Suggest a candidate address to be used by peer.
 */
static void
sppp_suggest_ip6_addr(struct sppp *sp, struct in6_addr *suggest)
{
	struct in6_addr myaddr;
	struct timeval tv;

	sppp_get_ip6_addrs(sp, &myaddr, 0, 0);

	myaddr.s6_addr[8] &= ~0x02;	/* u bit to "local" */
	microtime(&tv);
	if ((tv.tv_usec & 0xff) == 0 && (tv.tv_sec & 0xff) == 0) {
		myaddr.s6_addr[14] ^= 0xff;
		myaddr.s6_addr[15] ^= 0xff;
	} else {
		myaddr.s6_addr[14] ^= (tv.tv_usec & 0xff);
		myaddr.s6_addr[15] ^= (tv.tv_sec & 0xff);
	}
	if (suggest)
		memcpy(suggest, &myaddr, sizeof(myaddr));
}
#endif /*INET6*/

/*
 * pp_lock is a MTX_DEF mutex in this port, so nothing that may sleep
 * (malloc(M_WAITOK), copyin(), copyout()) runs under it: the auth ioctls
 * stage buffers outside the lock and only swap/snapshot under it.
 * name_len/secret_len are u_char, so a credential buffer holds at most
 * SPPP_AUTH_BUFMAX bytes including the NUL.
 */
#define	SPPP_AUTH_BUFMAX	(UCHAR_MAX + 1)

/* Credential buffers are wiped on free. */
static void
sppp_auth_buf_free(char *buf)
{

	if (buf != NULL)
		zfree(buf, M_DEVBUF);
}

/*
 * Copy in one credential of ulen bytes (NUL included).  A NULL pointer or
 * zero length yields no buffer, which clears that credential (NetBSD).
 */
static int
sppp_auth_copyin(const char *ubuf, u_int ulen, char **bufp, u_char *lenp)
{
	char *buf;
	int error;

	*bufp = NULL;
	*lenp = 0;
	if (ubuf == NULL || ulen == 0)
		return (0);
	if (ulen > SPPP_AUTH_BUFMAX)
		return (ENAMETOOLONG);
	buf = malloc(ulen, M_DEVBUF, M_WAITOK);
	error = copyin(ubuf, buf, ulen);
	if (error != 0) {
		zfree(buf, M_DEVBUF);
		return (error);
	}
	buf[ulen - 1] = '\0';
	*bufp = buf;
	*lenp = ulen - 1;
	return (0);
}

/* A zero-length request asks for the size; a name must fit the buffer. */
static int
sppp_auth_name_copyout(const char *name, size_t len, char *ubuf, u_int *ulenp)
{

	if (*ulenp == 0) {
		*ulenp = len;
		return (0);
	}
	if (len == 0) {
		*ulenp = 0;
		return (0);
	}
	if (*ulenp < len)
		return (ENAMETOOLONG);
	return (copyout(name, ubuf, len));
}

/*
 * Process ioctl requests specific to the PPP interface.
 * Permissions have already been checked.
 */
static int
sppp_params(struct sppp *sp, u_long cmd, void *data)
{
	switch (cmd) {
	case SPPPGETAUTHCFG:
	    {
		struct spppauthcfg *cfg = (struct spppauthcfg *)data;
		char myname[SPPP_AUTH_BUFMAX], hisname[SPPP_AUTH_BUFMAX];
		size_t mylen, hislen;
		int error;

		/* Lengths include the NUL; 0 means no name is set. */
		mylen = hislen = 0;
		SPPP_LOCK(sp, RW_READER);

		cfg->myauthflags = sp->myauth.flags;
		cfg->hisauthflags = sp->hisauth.flags;
		strlcpy(cfg->ifname, if_name(sp->pp_if), sizeof(cfg->ifname));
		cfg->hisauth = sppp_proto2authproto(sp->hisauth.proto);
		cfg->myauth = sppp_proto2authproto(sp->myauth.proto);
		if (sp->myauth.name != NULL) {
			mylen = sp->myauth.name_len + 1;
			memcpy(myname, sp->myauth.name, mylen);
		}
		if (sp->hisauth.name != NULL) {
			hislen = sp->hisauth.name_len + 1;
			memcpy(hisname, sp->hisauth.name, hislen);
		}
		SPPP_UNLOCK(sp);

		error = sppp_auth_name_copyout(myname, mylen, cfg->myname,
		    &cfg->myname_length);
		if (error == 0)
			error = sppp_auth_name_copyout(hisname, hislen,
			    cfg->hisname, &cfg->hisname_length);
		if (error != 0)
			return (error);
	    }
	    break;
	case SPPPSETAUTHCFG:
	    {
		struct spppauthcfg *cfg = (struct spppauthcfg *)data;
		struct sauth nmy, nhis;
		struct sauth omy, ohis;
		int error;

		/*
		 * Validate and stage all four credentials first: a set that
		 * fails leaves the stored ones untouched.
		 */
		memset(&nmy, 0, sizeof(nmy));
		memset(&nhis, 0, sizeof(nhis));
		error = sppp_auth_copyin(cfg->hisname, cfg->hisname_length,
		    &nhis.name, &nhis.name_len);
		if (error == 0)
			error = sppp_auth_copyin(cfg->hissecret,
			    cfg->hissecret_length, &nhis.secret,
			    &nhis.secret_len);
		if (error == 0)
			error = sppp_auth_copyin(cfg->myname,
			    cfg->myname_length, &nmy.name, &nmy.name_len);
		if (error == 0)
			error = sppp_auth_copyin(cfg->mysecret,
			    cfg->mysecret_length, &nmy.secret,
			    &nmy.secret_len);
		if (error != 0) {
			sppp_auth_buf_free(nhis.name);
			sppp_auth_buf_free(nhis.secret);
			sppp_auth_buf_free(nmy.name);
			sppp_auth_buf_free(nmy.secret);
			return (error);
		}

		SPPP_LOCK(sp, RW_WRITER);

		omy = sp->myauth;
		ohis = sp->hisauth;
		sp->myauth.name = nmy.name;
		sp->myauth.name_len = nmy.name_len;
		sp->myauth.secret = nmy.secret;
		sp->myauth.secret_len = nmy.secret_len;
		sp->hisauth.name = nhis.name;
		sp->hisauth.name_len = nhis.name_len;
		sp->hisauth.secret = nhis.secret;
		sp->hisauth.secret_len = nhis.secret_len;

		sp->myauth.flags = cfg->myauthflags;
		if (cfg->myauth != SPPP_AUTHPROTO_NOCHG) {
			sp->myauth.proto = sppp_authproto2proto(cfg->myauth);
		}
		sp->hisauth.flags = cfg->hisauthflags;
		if (cfg->hisauth != SPPP_AUTHPROTO_NOCHG) {
			sp->hisauth.proto = sppp_authproto2proto(cfg->hisauth);
		}
		sp->pp_auth_failures = 0;
		sppp_dial_now(sp);
		if (sp->hisauth.proto != PPP_NOPROTO)
			SET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);
		else
			CLR(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);

		SPPP_UNLOCK(sp);

		sppp_auth_buf_free(omy.name);
		sppp_auth_buf_free(omy.secret);
		sppp_auth_buf_free(ohis.name);
		sppp_auth_buf_free(ohis.secret);
	    }
	    break;
	case SPPPGETLCPCFG:
	    {
		struct sppplcpcfg *lcpp = (struct sppplcpcfg *)data;

		SPPP_LOCK(sp, RW_READER);
		lcpp->lcp_timeout = sp->lcp.timeout;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPSETLCPCFG:
	    {
		struct sppplcpcfg *lcpp = (struct sppplcpcfg *)data;

		SPPP_LOCK(sp, RW_WRITER);
		sp->lcp.timeout = lcpp->lcp_timeout;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETNCPCFG:
	    {
		struct spppncpcfg *ncpp = (struct spppncpcfg *) data;

		SPPP_LOCK(sp, RW_READER);
		ncpp->ncp_flags = sp->pp_ncpflags;
		SPPP_UNLOCK(sp);
	    }
		break;
	case SPPPSETNCPCFG:
	    {
		struct spppncpcfg *ncpp = (struct spppncpcfg *) data;

		SPPP_LOCK(sp, RW_WRITER);
		sp->pp_ncpflags = ncpp->ncp_flags;
		SPPP_UNLOCK(sp);
	    }
		break;
	case SPPPGETSTATUS:
	    {
		struct spppstatus *status = (struct spppstatus *)data;

		SPPP_LOCK(sp, RW_READER);
		status->phase = sp->pp_phase;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETSTATUSNCP:
	    {
		struct spppstatusncp *status = (struct spppstatusncp *)data;

		SPPP_LOCK(sp, RW_READER);
		status->phase = sp->pp_phase;
		status->ncpup = sppp_cp_check(sp, CP_NCP);
		SPPP_UNLOCK(sp);
	    }
	    break;
/*
 * The idle-timeout ioctls are always-disabled stubs by design (spec
 * section 8 "Not implemented", PORTING-sppp.md do-not-port table): the
 * idle-timeout mechanism is deliberately not ported, but NetBSD pppoectl
 * list mode calls SPPPGETIDLETO unconditionally, so the driver must
 * answer 125 with a zeroed struct and 126 with accept-and-ignore rather
 * than ENOTTY (R005, research amendment 2).  There is no idle-timeout
 * code anywhere else in the port.  Dial filters 144-146 remain absent.
 */
	case SPPPGETIDLETO:
	    {
	    	struct spppidletimeout *to = (struct spppidletimeout *)data;

		/* Always-disabled stub: report idle timeout disabled. */
		to->idle_seconds = 0;
	    }
	    break;
	case SPPPSETIDLETO:
	    /* Always-disabled stub: accept and ignore. */
	    break;
	case SPPPSETAUTHFAILURE:
	    {
	    	struct spppauthfailuresettings *afsettings =
		    (struct spppauthfailuresettings *)data;

		SPPP_LOCK(sp, RW_WRITER);
		sp->pp_max_auth_fail = afsettings->max_failures;
		sp->pp_auth_failures = 0;
		sppp_dial_now(sp);
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETAUTHFAILURES:
	    {
	    	struct spppauthfailurestats *stats = (struct spppauthfailurestats *)data;

		SPPP_LOCK(sp, RW_READER);
		stats->auth_failures = sp->pp_auth_failures;
		stats->max_failures = sp->pp_max_auth_fail;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPSETDNSOPTS:
	    {
		struct spppdnssettings *req = (struct spppdnssettings *)data;

		SPPP_LOCK(sp, RW_WRITER);
		sp->query_dns = req->query_dns & 3;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETDNSOPTS:
	    {
		struct spppdnssettings *req = (struct spppdnssettings *)data;

		SPPP_LOCK(sp, RW_READER);
		req->query_dns = sp->query_dns;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETDNSADDRS:
	    {
		struct spppdnsaddrs *addrs = (struct spppdnsaddrs *)data;

		SPPP_LOCK(sp, RW_READER);
		memcpy(&addrs->dns, &sp->dns_addrs, sizeof addrs->dns);
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETKEEPALIVE:
	    {
	    	struct spppkeepalivesettings *settings =
		     (struct spppkeepalivesettings*)data;

		SPPP_LOCK(sp, RW_READER);
		settings->maxalive = sp->pp_maxalive;
		settings->max_noreceive = sp->pp_max_noreceive;
		settings->alive_interval = sp->pp_alive_interval;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPSETKEEPALIVE:
	    {
	    	struct spppkeepalivesettings *settings =
		     (struct spppkeepalivesettings*)data;

		SPPP_LOCK(sp, RW_WRITER);
		sp->pp_maxalive = settings->maxalive;
		sp->pp_max_noreceive = MIN(settings->max_noreceive,
		    INT32_MAX/2);
		sp->pp_alive_interval = settings->alive_interval;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETLCPSTATUS:
	    {
		struct sppplcpstatus *status =
		    (struct sppplcpstatus *)data;

		SPPP_LOCK(sp, RW_READER);
		status->state = sp->scp[IDX_LCP].state;
		status->opts = sp->lcp.opts;
		status->magic = sp->lcp.magic;
		status->mru = sp->lcp.mru;
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETIPCPSTATUS:
	    {
		struct spppipcpstatus *status =
		    (struct spppipcpstatus *)data;
		u_int32_t myaddr;

		SPPP_LOCK(sp, RW_READER);
		status->state = sp->scp[IDX_IPCP].state;
		status->opts = sp->ipcp.opts;
#ifdef INET
		sppp_get_ip_addrs(sp, &myaddr, 0, 0);
#else
		myaddr = 0;
#endif
		status->myaddr = ntohl(myaddr);
		SPPP_UNLOCK(sp);
	    }
	    break;
	case SPPPGETIPV6CPSTATUS:
	    {
		struct spppipv6cpstatus *status =
		    (struct spppipv6cpstatus *)data;

		SPPP_LOCK(sp, RW_READER);
		status->state = sp->scp[IDX_IPV6CP].state;
		memcpy(status->my_ifid, sp->ipv6cp.my_ifid,
		    sizeof(status->my_ifid));
		memcpy(status->his_ifid, sp->ipv6cp.his_ifid,
		    sizeof(status->his_ifid));
		SPPP_UNLOCK(sp);
	    }
	    break;
	default:
	    {
		/* NetBSD compat-stub hook (sppp_params_50_hook) dropped:
		 * legacy 50-series ioctls are in the do-not-port table
		 * (docs/PORTING-sppp.md), so unknown cmds are EINVAL. */
		return (EINVAL);
	    }
	}
	return (0);
}

static void
sppp_phase_network(struct sppp *sp)
{
	int i;

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	sppp_change_phase(sp, SPPP_PHASE_NETWORK);

	/* Notify NCPs now. */
	for (i = 0; i < IDX_COUNT; i++)
		if ((cps[i])->flags & CP_NCP)
			sppp_wq_add(sp->wq_cp, &sp->scp[i].work_open);
}

static const char *
sppp_cp_type_name(char *buf, size_t buflen, u_char type)
{

	switch (type) {
	case CONF_REQ:   return "conf-req";
	case CONF_ACK:   return "conf-ack";
	case CONF_NAK:   return "conf-nak";
	case CONF_REJ:   return "conf-rej";
	case TERM_REQ:   return "term-req";
	case TERM_ACK:   return "term-ack";
	case CODE_REJ:   return "code-rej";
	case PROTO_REJ:  return "proto-rej";
	case ECHO_REQ:   return "echo-req";
	case ECHO_REPLY: return "echo-reply";
	case DISC_REQ:   return "discard-req";
	}
	if (buf != NULL)
		snprintf(buf, buflen, "0x%02x", type);
	return buf;
}

static const char *
sppp_auth_type_name(char *buf, size_t buflen, u_short proto, u_char type)
{
	const char *name;

	switch (proto) {
	case PPP_CHAP:
		switch (type) {
		case CHAP_CHALLENGE:	return "challenge";
		case CHAP_RESPONSE:	return "response";
		case CHAP_SUCCESS:	return "success";
		case CHAP_FAILURE:	return "failure";
		default:		name = "chap"; break;
		}
		break;

	case PPP_PAP:
		switch (type) {
		case PAP_REQ:		return "req";
		case PAP_ACK:		return "ack";
		case PAP_NAK:		return "nak";
		default:		name = "pap";	break;
		}
		break;

	default:
		name = "bad";
		break;
	}

	if (buf != NULL)
		snprintf(buf, buflen, "%s(%#x) 0x%02x", name, proto, type);
	return buf;
}

static const char *
sppp_lcp_opt_name(char *buf, size_t buflen, u_char opt)
{

	switch (opt) {
	case LCP_OPT_MRU:		return "mru";
	case LCP_OPT_ASYNC_MAP:		return "async-map";
	case LCP_OPT_AUTH_PROTO:	return "auth-proto";
	case LCP_OPT_QUAL_PROTO:	return "qual-proto";
	case LCP_OPT_MAGIC:		return "magic";
	case LCP_OPT_PROTO_COMP:	return "proto-comp";
	case LCP_OPT_ADDR_COMP:		return "addr-comp";
	case LCP_OPT_SELF_DESC_PAD:	return "sdpad";
	case LCP_OPT_CALL_BACK:		return "callback";
	case LCP_OPT_COMPOUND_FRMS:	return "cmpd-frms";
	case LCP_OPT_MP_MRRU:		return "mrru";
	case LCP_OPT_MP_SSNHF:		return "mp-ssnhf";
	case LCP_OPT_MP_EID:		return "mp-eid";
	}
	if (buf != NULL)
		snprintf(buf, buflen, "0x%02x", opt);
	return buf;
}

static const char *
sppp_ipcp_opt_name(char *buf, size_t buflen, u_char opt)
{

	switch (opt) {
	case IPCP_OPT_ADDRESSES:	return "addresses";
	case IPCP_OPT_COMPRESSION:	return "compression";
	case IPCP_OPT_ADDRESS:		return "address";
	case IPCP_OPT_PRIMDNS:		return "primdns";
	case IPCP_OPT_SECDNS:		return "secdns";
	}
	if (buf != NULL)
		snprintf(buf, buflen, "0x%02x", opt);
	return buf;
}

#ifdef INET6
static const char *
sppp_ipv6cp_opt_name(char *buf, size_t buflen, u_char opt)
{

	switch (opt) {
	case IPV6CP_OPT_IFID:		return "ifid";
	case IPV6CP_OPT_COMPRESSION:	return "compression";
	}
	if (buf != NULL)
		snprintf(buf, buflen, "0x%02x", opt);
	return buf;
}
#endif

static const char *
sppp_state_name(int state)
{

	switch (state) {
	case STATE_INITIAL:	return "initial";
	case STATE_STARTING:	return "starting";
	case STATE_CLOSED:	return "closed";
	case STATE_STOPPED:	return "stopped";
	case STATE_CLOSING:	return "closing";
	case STATE_STOPPING:	return "stopping";
	case STATE_REQ_SENT:	return "req-sent";
	case STATE_ACK_RCVD:	return "ack-rcvd";
	case STATE_ACK_SENT:	return "ack-sent";
	case STATE_OPENED:	return "opened";
	}
	return "illegal";
}

static const char *
sppp_phase_name(int phase)
{

	switch (phase) {
	case SPPP_PHASE_DEAD:		return "dead";
	case SPPP_PHASE_ESTABLISH:	return "establish";
	case SPPP_PHASE_TERMINATE:	return "terminate";
	case SPPP_PHASE_AUTHENTICATE: 	return "authenticate";
	case SPPP_PHASE_NETWORK:	return "network";
	}
	return "illegal";
}

static const char *
sppp_proto_name(char *buf, size_t buflen, u_short proto)
{

	switch (proto) {
	case PPP_LCP:	return "lcp";
	case PPP_IPCP:	return "ipcp";
	case PPP_PAP:	return "pap";
	case PPP_CHAP:	return "chap";
	case PPP_IPV6CP: return "ipv6cp";
	}
	if (buf != NULL) {
		snprintf(buf, sizeof(buf), "0x%04x",
		    (unsigned)proto);
	}
	return buf;
}

static void
sppp_print_bytes(const u_char *p, u_short len)
{
	/* --len below would wrap a zero length to a 64KiB read. */
	if (len == 0)
		return;
	addlog(" %02x", *p++);
	while (--len > 0)
		addlog("-%02x", *p++);
}

static void
sppp_print_string(const char *p, u_short len)
{
	u_char c;

	while (len-- > 0) {
		c = *p++;
		/*
		 * Print only ASCII chars directly.  RFC 1994 recommends
		 * using only them, but we don't rely on it.  */
		if (c < ' ' || c > '~')
			addlog("\\x%x", c);
		else
			addlog("%c", c);
	}
}

/*
 * NetBSD log()/addlog() on FreeBSD.  FreeBSD's log(9) has no append API,
 * and a log(9) call at a different priority from the unterminated msgbuf
 * line before it starts a new line -- logging the "<ifname>: " prefix and
 * the text separately put the text at the wrong priority.  So a record is
 * assembled whole and emitted with a single log(9) call.
 *
 * Records built piecewise (SPPP_LOG() without a newline, then addlog()s)
 * live in a small table of slots keyed by the building thread, so builders
 * on different netisr CPUs, the taskqueue and callouts never append to each
 * other's records.  sppp_log_mtx is a leaf lock, held only around
 * vsnprintf() and log(9), neither of which sleeps.  A thread's unterminated
 * record is flushed when it opens a new one (NetBSD log() semantics); a
 * record that fills its slot is emitted and continued on a new line at the
 * same priority; when every slot is busy the next one in turn is flushed
 * and reused.
 */
#define	SPPP_LOG_SLOTS		8
#define	SPPP_LOG_RECLEN		512

struct sppp_logrec {
	struct thread	*lr_owner;	/* building thread, NULL if free */
	int		 lr_prio;
	int		 lr_len;	/* bytes in lr_buf, NUL excluded */
	char		 lr_buf[SPPP_LOG_RECLEN];
};

static struct mtx sppp_log_mtx;
MTX_SYSINIT(sppp_log, &sppp_log_mtx, "sppp log", MTX_DEF);
static struct sppp_logrec sppp_logrecs[SPPP_LOG_SLOTS];
static u_int sppp_log_rotor;

static void
sppp_logrec_flush(struct sppp_logrec *lr)
{

	mtx_assert(&sppp_log_mtx, MA_OWNED);
	if (lr->lr_len > 0)
		log(lr->lr_prio, "%s%s", lr->lr_buf,
		    lr->lr_buf[lr->lr_len - 1] == '\n' ? "" : "\n");
	lr->lr_len = 0;
	lr->lr_buf[0] = '\0';
}

/* The calling thread's open record, or a fresh one at prio. */
static struct sppp_logrec *
sppp_logrec_get(int prio)
{
	struct sppp_logrec *lr, *nlr;
	int i;

	mtx_assert(&sppp_log_mtx, MA_OWNED);
	nlr = NULL;
	for (i = 0; i < SPPP_LOG_SLOTS; i++) {
		lr = &sppp_logrecs[i];
		if (lr->lr_owner == curthread)
			return (lr);
		if (lr->lr_owner == NULL && nlr == NULL)
			nlr = lr;
	}
	if (nlr == NULL) {
		nlr = &sppp_logrecs[sppp_log_rotor++ % SPPP_LOG_SLOTS];
		sppp_logrec_flush(nlr);
	}
	nlr->lr_owner = curthread;
	nlr->lr_prio = prio;
	nlr->lr_len = 0;
	nlr->lr_buf[0] = '\0';
	return (nlr);
}

static void
sppp_logrec_append(struct sppp_logrec *lr, const char *fmt, va_list ap)
{
	va_list aq;
	int room, n;

	mtx_assert(&sppp_log_mtx, MA_OWNED);
	room = SPPP_LOG_RECLEN - lr->lr_len;
	va_copy(aq, ap);
	n = vsnprintf(lr->lr_buf + lr->lr_len, room, fmt, aq);
	va_end(aq);
	if (n >= room && lr->lr_len > 0) {
		/* Does not fit behind the text so far: emit that first. */
		lr->lr_buf[lr->lr_len] = '\0';
		sppp_logrec_flush(lr);
		room = SPPP_LOG_RECLEN;
		n = vsnprintf(lr->lr_buf, room, fmt, ap);
	}
	if (n < 0)
		n = 0;
	if (n >= room)
		n = room - 1;		/* truncated to the slot */
	lr->lr_len += n;
	if (lr->lr_len > 0 && lr->lr_buf[lr->lr_len - 1] == '\n') {
		sppp_logrec_flush(lr);
		lr->lr_owner = NULL;
	} else if (lr->lr_len >= SPPP_LOG_RECLEN - 1)
		sppp_logrec_flush(lr);	/* full: continue on a new line */
}

static void
sppp_log(struct sppp *sp, int prio, const char *fmt, ...)
{
	struct sppp_logrec *lr;
	va_list ap;

	mtx_lock(&sppp_log_mtx);
	lr = sppp_logrec_get(prio);
	sppp_logrec_flush(lr);		/* a new record ends the open one */
	lr->lr_prio = prio;
	if (__predict_true(sp != NULL))
		lr->lr_len = snprintf(lr->lr_buf, SPPP_LOG_RECLEN, "%s: ",
		    if_name(sp->pp_if));
	va_start(ap, fmt);
	sppp_logrec_append(lr, fmt, ap);
	va_end(ap);
	mtx_unlock(&sppp_log_mtx);
}

static void
sppp_addlog(const char *fmt, ...)
{
	struct sppp_logrec *lr;
	va_list ap;

	mtx_lock(&sppp_log_mtx);
	lr = sppp_logrec_get(LOG_DEBUG);
	va_start(ap, fmt);
	sppp_logrec_append(lr, fmt, ap);
	va_end(ap);
	mtx_unlock(&sppp_log_mtx);
}

static const char *
sppp_dotted_quad(char *buf, size_t buflen, uint32_t addr)
{

	if (buf != NULL) {
		snprintf(buf, buflen, "%u.%u.%u.%u",
			(unsigned int)((addr >> 24) & 0xff),
			(unsigned int)((addr >> 16) & 0xff),
			(unsigned int)((addr >> 8) & 0xff),
			(unsigned int)(addr & 0xff));
	}
	return buf;
}

/* a dummy, used to drop uninteresting events */
static void
sppp_null(struct sppp *unused)
{
	/* do just nothing */
}

static void
sppp_tls(const struct cp *cp, struct sppp *sp)
{

	SPPP_DLOG(sp, "%s tls\n", cp->name);

	/* notify lcp that is lower layer */
	sp->lcp.protos |= (1 << cp->protoidx);
}

static void
sppp_tlf(const struct cp *cp, struct sppp *sp)
{

	SPPP_DLOG(sp, "%s tlf\n", cp->name);

	/* notify lcp that is lower layer */
	sp->lcp.protos &= ~(1 << cp->protoidx);

	/* cleanup */
	m_freem(sp->scp[cp->protoidx].mbuf_confreq);
	sp->scp[cp->protoidx].mbuf_confreq = NULL;
	m_freem(sp->scp[cp->protoidx].mbuf_confnak);
	sp->scp[cp->protoidx].mbuf_confnak = NULL;

	sppp_lcp_check_and_close(sp);
}

static void
sppp_screply(const struct cp *cp, struct sppp *sp, u_char type,
    uint8_t ident, size_t msglen, void *msg)
{

	/* An empty ConfReq gets an empty ConfAck (RFC 1661 5.1). */
	if (msglen == 0 && type != CONF_ACK)
		return;

	switch (type) {
	case CONF_ACK:
	case CONF_NAK:
	case CONF_REJ:
		break;
	default:
		return;
	}

	if (sppp_debug_enabled(sp)) {
		char tbuf[SPPP_CPTYPE_NAMELEN];
		const char *cpname;

		cpname = sppp_cp_type_name(tbuf, sizeof(tbuf), type);
		SPPP_LOG(sp, LOG_DEBUG, "send %s\n", cpname);
	}

	sppp_cp_send(sp, cp->proto, type, ident, msglen, msg);
}

static void
sppp_ifdown(struct sppp *sp, void *xcp __unused)
{

	SPPP_UNLOCK(sp);
	if_down(sp->pp_if);
	SPPP_LOCK(sp, RW_WRITER);
}

static void
sppp_notify_up(struct sppp *sp)
{

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_up);
}

static void
sppp_notify_down(struct sppp *sp)
{

	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_down);
}

static void
sppp_notify_tls_wlocked(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (!sp->pp_tls)
		return;

	SPPP_UNLOCK(sp);
	sp->pp_tls(sp);
	SPPP_LOCK(sp, RW_WRITER);
}

static void
sppp_notify_tlf_wlocked(struct sppp *sp)
{

	SPPP_KASSERT(SPPP_WLOCKED(sp));

	if (!sp->pp_tlf)
		return;

	SPPP_UNLOCK(sp);
	sp->pp_tlf(sp);
	SPPP_LOCK(sp, RW_WRITER);
}

/*
 * sppp_wq_* is provided by <net/if_sppp_compat.h> (section B): one
 * module-level pppoe_taskq, one struct task per interface, a
 * spin-locked FIFO of pending work items chained by wq_next.  The
 * NetBSD workqueue(9) implementation is not portable and is deleted.
 */
#ifdef SPPP_FILTER
static void
sppp_update_last_activity(struct sppp *sp, struct mbuf *m,
    struct sppp_bpf **sbp)
{
	struct sppp_bpf *sb;
	struct psref psref;
	int s, bound;

	if (!atomic_load_relaxed(&sp->pp_active_filt_enabled))
		return;

	s = pserialize_read_enter();
	sb = atomic_load_acquire(sbp);
	if (sb != NULL) {
		bound = curlwp_bind();
		psref_acquire(&psref, &sb->sb_psref, sppp_psref_class);
	}
	pserialize_read_exit(s);

	/*
	 * NetBSD cleared-recorded the frame against the active-filter
	 * pass/fail gate here and bumped the activity timestamp on a pass
	 * (the idle-timeout mechanism's payload liveness marker).  Both
	 * the dial/active filters (SPPP_FILTER) and the idle-timeout
	 * mechanism are deliberately not ported (spec section 8,
	 * PORTING-sppp.md), so there is nothing to record; keep only the
	 * psref release discipline.
	 */
	(void)m;

	if (sb != NULL) {
		psref_release(&psref, &sb->sb_psref, sppp_psref_class);
		curlwp_bindx(bound);
	}
}

static int
sppp_set_filter(struct sppp *sp, struct bpf_program *nbp,
    struct sppp_bpf **dst)
{
	struct sppp_bpf *new = NULL, *old;

	if (nbp->bf_len > BPF_MAXINSNS)
		return EINVAL;

	if (nbp->bf_len != 0) {
		size_t inssize = sizeof(new->sb_insns[0]) * nbp->bf_len;
		size_t newsize = sizeof(*new) + inssize;
		int error;

		new = kmem_alloc(newsize, KM_SLEEP);
		new->sb_len = nbp->bf_len;
		error = copyin((void *)nbp->bf_insns,
		    (void *)new->sb_insns, inssize);
		if (error != 0) {
			kmem_free(new, newsize);
			return error;
		}

		if (!bpf_validate(new->sb_insns, new->sb_len)) {
			kmem_free(new, newsize);
			return EINVAL;
		}

		psref_target_init(&new->sb_psref, sppp_psref_class);
	}

	SPPP_LOCK(sp, RW_WRITER);
	old = *dst;
	atomic_store_release(dst, new);
	SPPP_UNLOCK(sp);
	pserialize_perform(sp->pp_psz);
	if (old != NULL) {
		size_t oldlen = sizeof(*old) +
		    sizeof(old->sb_insns[0]) * old->sb_len;
		psref_target_destroy(&old->sb_psref, sppp_psref_class);
		kmem_free(old, oldlen);
	}

	return 0;
}
#endif

/*
 * This file is large.  Tell emacs to highlight it nevertheless.
 *
 * Local Variables:
 * hilit-auto-highlight-maxout: 120000
 * End:
 */

/*
 * NetBSD MODULE glue (MODULE(MODULE_CLASS_MISC, sppp_subr, NULL) +
 * sppp_subr_modcmd) dropped: FreeBSD module glue lives in the driver
 * (if_pppoe.c holds the module event handler); the vendored file is an
 * ordinary kernel source compiled into that module.  T3.
 */
