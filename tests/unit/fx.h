/*
 * fx.h -- fixtures shared by unit tests and fuzz targets.  Each fx_*
 * function lives in the tu/ translation unit that #includes the kernel
 * source it needs static access to.
 */
#ifndef _FX_H_
#define _FX_H_

#include "kshim.h"

/* Fixture-internal assertion (works outside the test runner too). */
#define	KT_FX_ASSERT(c)	do { if (!(c)) panic("fixture: %s", #c); } while (0)

struct pppoe_softc;
struct sppp;

/* tu/pppoe.c -- a real pppoe(4) clone (pppoe_clone_create()). */
struct pppoe_softc *fx_pppoe_new(void);
void	fx_pppoe_free(struct pppoe_softc *);
struct ifnet *fx_pppoe_ifp(struct pppoe_softc *);
struct sppp *fx_pppoe_sppp(struct pppoe_softc *);
/* An Ethernet parent (lladdr 02:00:00:00:00:01) bound by PPPOESETPARMS. */
struct ifnet *fx_parent_new(const char *name);
void	fx_parent_free(struct ifnet *);
int	fx_pppoe_bind(struct pppoe_softc *, struct ifnet *parent);
/* The whole RX hook, as ether_demux() would call it (inside the epoch). */
int	fx_pfil_in(struct ifnet *parent, struct mbuf **mp);
/* Publish a session in the session table (pppoe_session_task()). */
void	fx_pppoe_session_up(struct pppoe_softc *, uint16_t session,
	    const uint8_t peer[6]);
extern const uint8_t fx_ac_mac[6];	/* 02:00:00:00:00:aa */
extern const uint8_t fx_our_mac[6];	/* 02:00:00:00:00:01 */

/* tu/sppp.c -- the control-protocol layer. */
#define	FX_IDX_LCP	0
#define	FX_IDX_IPCP	1
#define	FX_IDX_IPV6CP	2
/* Run a CP's ConfReq parser on a copy of pkt (CP header first). */
int	fx_sppp_confreq(struct sppp *, int idx, const uint8_t *pkt, size_t len,
	    uint8_t *out, size_t outsz, size_t *outlen);
void	fx_sppp_confnak(struct sppp *, int idx, const uint8_t *pkt, size_t len);
void	fx_sppp_confrej(struct sppp *, int idx, const uint8_t *pkt, size_t len);
/* sppp_input() of [proto][cp packet] then run the taskqueue. */
void	fx_sppp_input(struct sppp *, uint16_t proto, const uint8_t *pkt,
	    size_t len);
/* Drive the LCP/NCP state machines to a phase for input-path tests. */
void	fx_sppp_force_phase(struct sppp *, int phase, int lcp_state);
/*
 * An auth failure while LCP is Opened on a live lower layer: set
 * pp_auth_failures, run sppp_lcp_check_and_close() and the taskqueue
 * (LCP Close + Open: Opened -> Closing -> Stopping).
 */
void	fx_sppp_auth_fail_close(struct sppp *, int failures);
/*
 * LCP Opened on a live lower layer in the authenticate phase with
 * pp_auth_failures already at `failures` (no close run).
 */
void	fx_sppp_opened_authenticating(struct sppp *, int failures);

#endif /* _FX_H_ */
