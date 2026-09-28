/* Helpers for the sppp control-protocol tests (tu/sppp.c only). */
#include "ktest.h"

/* A pppoe(4) clone whose sppp layer transmits into the kshim tx queue. */
#define	SPPP_FX_BEGIN							\
	struct pppoe_softc *fx_sc = fx_pppoe_new();			\
	struct sppp *sp = fx_pppoe_sppp(fx_sc);				\
	struct ifnet *ifp = fx_pppoe_ifp(fx_sc);			\
	ifp->if_transmit = kshim_tx_capture;				\
	(void)sp
#define	SPPP_FX_END	do {						\
	kshim_tx_flush(ifp);						\
	fx_pppoe_free(fx_sc);						\
} while (0)

/* [code][id][len16] + opts into buf; returns the packet length. */
static inline size_t
cp_pkt(uint8_t *buf, uint8_t code, uint8_t id, const void *opts, size_t olen)
{
	size_t n = 4 + olen;

	buf[0] = code;
	buf[1] = id;
	buf[2] = (uint8_t)(n >> 8);
	buf[3] = (uint8_t)n;
	if (olen != 0)
		memcpy(buf + 4, opts, olen);
	return (n);
}

/*
 * Pop the next frame sppp transmitted (PP_DEVF_NOFRAMING: 2-byte protocol,
 * then the CP packet) into buf; returns its length, or -1 if none.
 */
static inline int
cp_tx_pop(struct ifnet *ifp, uint16_t *proto, uint8_t *buf, size_t bufsz)
{
	struct mbuf *m = kshim_tx_pop(ifp);
	int len;

	if (m == NULL)
		return (-1);
	len = m->m_pkthdr.len;
	KT_ASSERT(len >= 2 && (size_t)len - 2 <= bufsz);
	m_copydata(m, 0, 2, (caddr_t)buf);
	*proto = (uint16_t)(buf[0] << 8 | buf[1]);
	m_copydata(m, 2, len - 2, (caddr_t)buf);
	m_freem(m);
	return (len - 2);
}
