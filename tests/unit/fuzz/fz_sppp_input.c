/*
 * sppp control-frame input through the state machines.  Input:
 *   [ctl][len16 frame]...   frame = 2-byte PPP protocol + CP packet
 * ctl sets the starting phase / LCP state / auth config; frames feed
 * sppp_input() in order with the taskqueue run after each, then every CP
 * timeout fires once.
 */
#include "fx.h"

#include <net/if_sppp.h>
#include <net/if_spppvar.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void
fz_auth(struct sppp *sp, uint8_t ctl)
{
	struct spppauthcfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.myauth = (ctl & 0x10) ? SPPP_AUTHPROTO_CHAP : SPPP_AUTHPROTO_PAP;
	cfg.hisauth = (ctl & 0x20) ? cfg.myauth : SPPP_AUTHPROTO_NONE;
	cfg.myname = "me";
	cfg.myname_length = 3;
	cfg.mysecret = "sec";
	cfg.mysecret_length = 4;
	cfg.hisname = "peer";
	cfg.hisname_length = 5;
	cfg.hissecret = "psec";
	cfg.hissecret_length = 5;
	KT_FX_ASSERT(sppp_ioctl(sp->pp_if, SPPPSETAUTHCFG, &cfg) == 0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const int lcp_states[4] = { 0 /* INITIAL */, 6 /* REQ_SENT */,
	    8 /* ACK_SENT */, 9 /* OPENED */ };
	struct pppoe_softc *sc;
	struct sppp *sp;
	struct ifnet *ifp;
	uint8_t ctl;
	int frames = 0;

	if (size < 1 || size > 8192)
		return (0);
	ctl = *data++;
	size--;

	kshim_reset();
	sc = fx_pppoe_new();
	sp = fx_pppoe_sppp(sc);
	ifp = fx_pppoe_ifp(sc);
	ifp->if_transmit = kshim_tx_capture;
	ifp->if_flags |= IFF_UP;
	if (ctl & 0x40)
		ifp->if_flags |= IFF_DEBUG;
	if (ctl & 0x08)
		fz_auth(sp, ctl);
	fx_sppp_force_phase(sp, (ctl & 7) > 4 ? 4 : (ctl & 7),
	    lcp_states[(ctl >> 1) & 3]);

	while (size >= 2 && frames++ < 32) {
		size_t n = (size_t)(data[0] << 8 | data[1]);

		data += 2;
		size -= 2;
		if (n > size)
			n = size;
		if (n >= 2)
			fx_sppp_input(sp, (uint16_t)(data[0] << 8 | data[1]),
			    data + 2, n - 2);
		data += n;
		size -= n;
		kshim_tx_flush(ifp);
	}
	for (int i = 0; i < 5; i++)	/* IDX_LCP .. IDX_CHAP */
		(void)kshim_callout_fire(&sp->scp[i].ch);
	kshim_run_tasks();

	kshim_tx_flush(ifp);
	fx_pppoe_free(sc);
	KT_FX_ASSERT(kshim_locks_held() == 0);
	return (0);
}
