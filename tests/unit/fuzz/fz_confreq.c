/*
 * ConfReq/ConfNak/ConfRej option parsers for one CP (FZ_CP = FX_IDX_*).
 * Input: [flags][CP packet].  flags picks debug logging and the auth/
 * address configuration, so the option arms that depend on them run.
 */
#include "fx.h"

#include <net/if_sppp.h>
#include <net/if_spppvar.h>

#ifndef FZ_CP
#define	FZ_CP	FX_IDX_LCP
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct pppoe_softc *sc;
	struct sppp *sp;
	uint8_t flags, out[2048];
	size_t rlen;

	if (size < 1 || size > 1600)
		return (0);
	flags = data[0];
	data++;
	size--;

	kshim_reset();
	sc = fx_pppoe_new();
	sp = fx_pppoe_sppp(sc);
	fx_pppoe_ifp(sc)->if_transmit = kshim_tx_capture;
	if (flags & 0x01)
		fx_pppoe_ifp(sc)->if_flags |= IFF_DEBUG;
	if (flags & 0x02)
		sp->myauth.proto = (flags & 0x04) ? PPP_CHAP : PPP_PAP;
	if (flags & 0x08)
		sp->myauth.flags |= SPPP_AUTHFLAG_PASSIVEAUTHPROTO;
	if (flags & 0x10)
		sp->ipcp.flags |= IPCP_HISADDR_DYN | IPCP_MYADDR_DYN;
	if (flags & 0x20)
		memcpy(sp->ipv6cp.my_ifid, "\x02\0\0\xff\xfe\0\0\1", 8);
	sp->lcp.magic = 0x01020304;

	(void)fx_sppp_confreq(sp, FZ_CP, data, size, out, sizeof(out), &rlen);
	fx_sppp_confnak(sp, FZ_CP, data, size);
	fx_sppp_confrej(sp, FZ_CP, data, size);

	kshim_run_tasks();
	kshim_tx_flush(fx_pppoe_ifp(sc));
	fx_pppoe_free(sc);
	KT_FX_ASSERT(kshim_locks_held() == 0);
	return (0);
}
