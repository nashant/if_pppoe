/*
 * The whole pfil RX hook: discovery (pppoe_disc_input tag walk + FSM) and
 * session (pppoe_sess_input header checks).  Input:
 *   [ctl][seglen][PPPoE header + payload ...]
 * ctl bit 0 picks 0x8864 over 0x8863, bits 1-2 the FSM state; the softc's
 * Host-Uniq is the fixed token "HUNIQUE!" and its session id 0x1234 (seeds
 * carry both), and seglen splits the frame into an mbuf chain.  A frame
 * the hook PFIL_PASSes comes back intact and is freed here.
 */
#include "fx.h"

#include <net/if_pppoe.h>
#include <net/if_pppoe_var.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const int states[4] = { PPPOE_STATE_INITIAL,
	    PPPOE_STATE_PADI_SENT, PPPOE_STATE_PADR_SENT,
	    PPPOE_STATE_SESSION };
	struct pppoe_softc *sc;
	struct ifnet *parent;
	struct mbuf *m;
	uint8_t frame[1600], ctl, seg;
	size_t len;

	if (size < 2 || size - 2 > sizeof(frame) - ETHER_HDR_LEN)
		return (0);
	ctl = data[0];
	seg = data[1];
	data += 2;
	size -= 2;

	kshim_reset();
	sc = fx_pppoe_new();
	parent = fx_parent_new("em0");
	KT_FX_ASSERT(fx_pppoe_bind(sc, parent) == 0);
	sc->sc_hunique = 0x48554e4951554521ULL;	/* "HUNIQUE!" */
	if (ctl & 0x08)
		sc->sc_max_payload_req = sc->sc_max_payload = 1500;
	if (states[(ctl >> 1) & 3] == PPPOE_STATE_SESSION)
		fx_pppoe_session_up(sc, 0x1234, fx_ac_mac);
	else {
		PPPOE_SC_LOCK(sc);
		sc->sc_state = states[(ctl >> 1) & 3];
		/* The chosen AC: a PADS must come from it. */
		if (sc->sc_state == PPPOE_STATE_PADR_SENT)
			memcpy(&sc->sc_dest, fx_ac_mac, ETHER_ADDR_LEN);
		PPPOE_SC_UNLOCK(sc);
	}
	kshim_tx_flush(parent);

	memcpy(frame, fx_our_mac, 6);
	memcpy(frame + 6, fx_ac_mac, 6);
	frame[12] = 0x88;
	frame[13] = (ctl & 1) ? 0x64 : 0x63;
	memcpy(frame + ETHER_HDR_LEN, data, size);
	len = ETHER_HDR_LEN + size;
	m = seg != 0 ? kshim_mbuf_chain(frame, (int)len, seg) :
	    kshim_mbuf_from(frame, (int)len);
	m->m_pkthdr.rcvif = parent;
	/*
	 * PFIL_PASS (a foreign or malformed frame, p3-pfil-counters) hands
	 * the frame back intact: ether_demux() would own it next, so free it
	 * here.  Every other verdict means the hook took the mbuf.
	 */
	if (fx_pfil_in(parent, &m) == PFIL_PASS) {
		KT_FX_ASSERT(m != NULL);
		m_freem(m);
	} else
		KT_FX_ASSERT(m == NULL);

	kshim_run_tasks();
	kshim_netisr_flush();
	PPPOE_SC_LOCK(sc);
	callout_stop(&sc->sc_timeout);
	PPPOE_SC_UNLOCK(sc);
	kshim_tx_flush(parent);
	fx_pppoe_free(sc);
	fx_parent_free(parent);
	KT_FX_ASSERT(kshim_locks_held() == 0);
	return (0);
}
