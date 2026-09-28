/* Unit-test TU for sys/net/if_spppsubr.c: the real source, then fixtures and
 * the tests that need its statics. */
#include <net/if_spppsubr.c>

#include "fx.h"

int
fx_sppp_confreq(struct sppp *sp, int idx, const uint8_t *pkt, size_t len,
    uint8_t *out, size_t outsz, size_t *outlen)
{
	const struct cp *cp = cps[idx];
	struct lcp_header *h;
	uint8_t *buf = NULL;
	size_t blen = 0, rlen = 0;
	enum cp_rcr_type type;

	/* An exact-size heap copy: ASan then bounds every parser read. */
	h = kshim_malloc(len, M_TEMP, M_WAITOK);
	memcpy(h, pkt, len);
	SPPP_LOCK(sp, RW_WRITER);
	type = cp->parse_confreq(sp, h, (int)len, &buf, &blen, &rlen);
	SPPP_UNLOCK(sp);
	kshim_free(h, M_TEMP);
	if (buf != NULL) {
		KT_FX_ASSERT(rlen <= blen);
		if (out != NULL)
			memcpy(out, buf, MIN(rlen, outsz));
		kmem_free(buf, blen);
	} else
		KT_FX_ASSERT(type == CP_RCR_DROP || type == CP_RCR_ERR);
	if (outlen != NULL)
		*outlen = rlen;
	return (type);
}

static void
fx_sppp_parse(struct sppp *sp, int idx, const uint8_t *pkt, size_t len,
    bool nak)
{
	const struct cp *cp = cps[idx];
	struct lcp_header *h;

	h = kshim_malloc(len, M_TEMP, M_WAITOK);
	memcpy(h, pkt, len);
	SPPP_LOCK(sp, RW_WRITER);
	if (nak)
		cp->parse_confnak(sp, h, (int)len);
	else
		cp->parse_confrej(sp, h, (int)len);
	SPPP_UNLOCK(sp);
	kshim_free(h, M_TEMP);
}

void
fx_sppp_confnak(struct sppp *sp, int idx, const uint8_t *pkt, size_t len)
{
	fx_sppp_parse(sp, idx, pkt, len, true);
}

void
fx_sppp_confrej(struct sppp *sp, int idx, const uint8_t *pkt, size_t len)
{
	fx_sppp_parse(sp, idx, pkt, len, false);
}

void
fx_sppp_input(struct sppp *sp, uint16_t proto, const uint8_t *pkt,
    size_t len)
{
	uint8_t *b = kshim_malloc(len + 2, M_TEMP, M_WAITOK);
	struct mbuf *m;

	b[0] = proto >> 8;
	b[1] = proto & 0xff;
	if (len != 0)
		memcpy(b + 2, pkt, len);
	m = kshim_mbuf_from(b, (int)len + 2);
	kshim_free(b, M_TEMP);
	m->m_pkthdr.rcvif = sp->pp_if;
	sppp_input(sp->pp_if, m);
	kshim_run_tasks();
}

void
fx_sppp_force_phase(struct sppp *sp, int phase, int lcp_state)
{
	SPPP_LOCK(sp, RW_WRITER);
	sp->pp_phase = phase;
	sp->scp[IDX_LCP].state = lcp_state;
	SPPP_UNLOCK(sp);
}

void
fx_sppp_auth_fail_close(struct sppp *sp, int failures)
{
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_OPENED;
	sp->lcp.lower_running = true;
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_auth_failures = failures;
	sppp_lcp_check_and_close(sp);
	SPPP_UNLOCK(sp);
	kshim_run_tasks();
}

void
fx_sppp_opened_authenticating(struct sppp *sp, int failures)
{
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_OPENED;
	sp->lcp.lower_running = true;
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_auth_failures = failures;
	SPPP_UNLOCK(sp);
}

/* The fuzz build links the fixtures above but not the tests. */
#ifndef KTEST_NO_TESTS
#include "../t/cp_util.h"
#include "../t/sppp_lcp.c"
#include "../t/sppp_ipcp.c"
#include "../t/sppp_ipv6cp.c"
#include "../t/sppp_input.c"
#include "../t/sppp_auth.c"
#include "../t/sppp_misc.c"
#endif
