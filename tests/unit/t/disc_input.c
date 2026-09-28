/* pppoe_disc_input(): discovery tag walk and FSM -- sys/net/if_pppoe_disc.c */
#include "ktest.h"
#include "frames.h"
#include <net/if_sppp.h>

#define	DCNT(c)	(*V_pppoe_stats.c)

struct disc_fx {
	struct pppoe_softc *sc;
	struct ifnet *parent;
	uint8_t hu[8];
	uint64_t malformed0, errtag0, padt0;
};

static void
disc_setup(struct disc_fx *x, int state)
{
	uint64_t t;

	x->sc = fx_pppoe_new();
	x->parent = fx_parent_new("em0");
	KT_EQ(fx_pppoe_bind(x->sc, x->parent), 0);
	t = htobe64(x->sc->sc_hunique);
	memcpy(x->hu, &t, 8);
	PPPOE_SC_LOCK(x->sc);
	x->sc->sc_state = state;
	/* PADR_SENT means a PADO from fx_ac_mac was chosen. */
	if (state == PPPOE_STATE_PADR_SENT)
		memcpy(&x->sc->sc_dest, fx_ac_mac, 6);
	PPPOE_SC_UNLOCK(x->sc);
	x->malformed0 = DCNT(disc_malformed);
	x->errtag0 = DCNT(disc_err_tag);
	x->padt0 = DCNT(padt_rx);
}

static void
disc_teardown(struct disc_fx *x)
{
	PPPOE_SC_LOCK(x->sc);
	callout_stop(&x->sc->sc_timeout);
	PPPOE_SC_UNLOCK(x->sc);
	kshim_run_tasks();
	kshim_tx_flush(x->parent);
	fx_pppoe_free(x->sc);
	fx_parent_free(x->parent);
}

static void
disc_frame(struct fr *f, uint8_t code, uint16_t session)
{
	fr_start(f, fx_our_mac, fx_ac_mac, ETHERTYPE_PPPOEDISC, code, session);
}

static void
disc_deliver(struct disc_fx *x, struct fr *f, int seglen)
{
	struct mbuf *m = seglen > 0 ?
	    kshim_mbuf_chain(f->b, (int)f->len, seglen) :
	    kshim_mbuf_from(f->b, (int)f->len);

	uint64_t foreign0 = DCNT(passed_foreign);

	m->m_pkthdr.rcvif = x->parent;
	KT_EQ(fx_pfil_in(x->parent, &m), PFIL_CONSUMED);
	KT_ASSERT(m == NULL);
	KT_EQ(DCNT(passed_foreign), foreign0);
}

/* Like disc_deliver(), for a frame p3-pfil-counters expects PFIL_PASS
 * (unattributable or malformed): the mbuf comes back intact and nothing
 * downstream of this test harness will free it. */
static void
disc_deliver_pass(struct disc_fx *x, struct fr *f, int seglen)
{
	struct mbuf *m = seglen > 0 ?
	    kshim_mbuf_chain(f->b, (int)f->len, seglen) :
	    kshim_mbuf_from(f->b, (int)f->len);

	uint64_t foreign0 = DCNT(passed_foreign), in0 = DCNT(disc_in);

	m->m_pkthdr.rcvif = x->parent;
	KT_EQ(fx_pfil_in(x->parent, &m), PFIL_PASS);
	KT_ASSERT(m != NULL);
	/* Counted as passed, never as taken. */
	KT_EQ(DCNT(passed_foreign), foreign0 + 1);
	KT_EQ(DCNT(disc_in), in0);
	m_freem(m);
}

/* Walk a transmitted discovery frame's tags: returns the value of tag. */
static const uint8_t *
disc_tx_tag(const uint8_t *frame, size_t len, uint16_t tag, uint16_t *tlen)
{
	size_t plen = frame[18] << 8 | frame[19], off = 20;

	if (20 + plen > len)
		return (NULL);
	while (off + 4 <= 20 + plen) {
		uint16_t t = frame[off] << 8 | frame[off + 1];
		uint16_t l = frame[off + 2] << 8 | frame[off + 3];

		if (t == tag) {
			*tlen = l;
			return (&frame[off + 4]);
		}
		off += 4 + l;
	}
	return (NULL);
}

static int
disc_tx_pop(struct disc_fx *x, uint8_t *buf, size_t bufsz)
{
	struct mbuf *m = kshim_tx_pop(x->parent);
	int len;

	if (m == NULL)
		return (-1);
	len = m->m_pkthdr.len;
	KT_ASSERT((size_t)len <= bufsz);
	m_copydata(m, 0, len, (caddr_t)buf);
	m_freem(m);
	return (len);
}

static void
pado(struct disc_fx *x, struct fr *f)
{
	disc_frame(f, PPPOE_CODE_PADO, 0);
	fr_tag(f, PPPOE_TAG_SNAME, NULL, 0);
	fr_tag(f, PPPOE_TAG_ACNAME, "ac1", 3);
	fr_tag(f, PPPOE_TAG_HUNIQUE, x->hu, 8);
}

KTEST(disc_input, pado_moves_to_padr_with_cookie_and_relay)
{
	struct disc_fx x;
	struct fr f;
	uint8_t tx[2048];
	const uint8_t *v;
	uint16_t l;
	int n;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_tag(&f, PPPOE_TAG_ACCOOKIE, "COOKIE", 6);
	fr_tag(&f, PPPOE_TAG_RELAYSID, "RLY", 3);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	KT_MEMEQ(&x.sc->sc_dest, fx_ac_mac, 6);
	KT_ASSERT(callout_pending(&x.sc->sc_timeout));
	n = disc_tx_pop(&x, tx, sizeof(tx));
	KT_ASSERT(n > 20);
	KT_MEMEQ(tx, fx_ac_mac, 6);
	KT_EQ(tx[15], PPPOE_CODE_PADR);
	v = disc_tx_tag(tx, n, PPPOE_TAG_ACCOOKIE, &l);
	KT_ASSERT(v != NULL && l == 6);
	KT_MEMEQ(v, "COOKIE", 6);
	v = disc_tx_tag(tx, n, PPPOE_TAG_RELAYSID, &l);
	KT_ASSERT(v != NULL && l == 3);
	v = disc_tx_tag(tx, n, PPPOE_TAG_HUNIQUE, &l);
	KT_ASSERT(v != NULL && l == 8);
	KT_MEMEQ(v, x.hu, 8);
	disc_teardown(&x);
}

KTEST(disc_input, chained_pado_past_mhlen_parsed)
{
	struct disc_fx x;
	struct fr f;
	uint8_t vendor[200];

	memset(vendor, 0x33, sizeof(vendor));
	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_VENDOR, vendor, sizeof(vendor));
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 64);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, truncated_tag_is_malformed)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_tag(&f, PPPOE_TAG_ACCOOKIE, "abcd", 4);
	f.len -= 2;		/* value runs past the payload */
	fr_finish(&f);
	/* p3-pfil-counters: too malformed to attribute -> passed. */
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(DCNT(disc_malformed), x.malformed0 + 1);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, trailing_partial_tag_header_ignored)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_bytes(&f, "\x01\x04\x00", 3);	/* 3 octets: no full TLV header */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(DCNT(disc_malformed), x.malformed0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, plen_past_frame_or_ethermtu_is_malformed)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_finish(&f);
	fr_set_plen(&f, (uint16_t)(f.len - 20 + 1));
	/* p3-pfil-counters: too malformed to attribute -> passed. */
	disc_deliver_pass(&x, &f, 0);
	pado(&x, &f);
	while (f.len < 20 + ETHERMTU)
		fr_tag(&f, PPPOE_TAG_VENDOR, "vvvvvvvvvvvvvvvvvvvv", 20);
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);		/* plen > 1494 */
	KT_EQ(DCNT(disc_malformed), x.malformed0 + 2);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, runt_and_bad_vertype_are_malformed)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	f.len = 19;
	/* p3-pfil-counters: too malformed to attribute -> passed. */
	disc_deliver_pass(&x, &f, 0);
	pado(&x, &f);
	fr_finish(&f);
	f.b[14] = 0x12;
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(DCNT(disc_malformed), x.malformed0 + 2);
	disc_teardown(&x);
}

static void
cookie_len_case(size_t clen, bool kept, uint16_t tag)
{
	struct disc_fx x;
	struct fr f;
	uint8_t val[300], tx[2048];
	const uint8_t *v;
	uint16_t l;
	int n;

	memset(val, 0xc5, sizeof(val));
	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_tag(&f, tag, val, (uint16_t)clen);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	if (tag == PPPOE_TAG_ACCOOKIE)
		KT_EQ(x.sc->sc_ac_cookie_len, kept ? clen : 0);
	else
		KT_EQ(x.sc->sc_relay_sid_len, kept ? clen : 0);
	n = disc_tx_pop(&x, tx, sizeof(tx));
	v = disc_tx_tag(tx, n, tag, &l);
	if (kept)
		KT_ASSERT(v != NULL && l == clen);
	else
		KT_ASSERT(v == NULL);
	disc_teardown(&x);
}

KTEST(disc_input, ac_cookie_256_kept_257_dropped)
{
	cookie_len_case(256, true, PPPOE_TAG_ACCOOKIE);
	cookie_len_case(257, false, PPPOE_TAG_ACCOOKIE);
}

KTEST(disc_input, relay_id_256_kept_257_dropped)
{
	cookie_len_case(256, true, PPPOE_TAG_RELAYSID);
	cookie_len_case(257, false, PPPOE_TAG_RELAYSID);
}

KTEST(disc_input, error_tag_pado_counted_and_ignored)
{
	static const uint16_t tags[] = { PPPOE_TAG_SNAME_ERR,
	    PPPOE_TAG_ACSYS_ERR, PPPOE_TAG_GENERIC_ERR };

	for (size_t i = 0; i < nitems(tags); i++) {
		struct disc_fx x;
		struct fr f;

		disc_setup(&x, PPPOE_STATE_PADI_SENT);
		pado(&x, &f);
		fr_tag(&f, tags[i], "nope", 4);
		fr_finish(&f);
		disc_deliver(&x, &f, 0);
		KT_EQ(DCNT(disc_err_tag), x.errtag0 + 1);
		KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
		KT_LOGGED("PADO carried an error tag");
		KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
		disc_teardown(&x);
	}
}

static int
disc_log_count(const char *needle)
{
	int n = 0;

	for (int i = 0; i < kshim_log_count(); i++)
		if (strstr(kshim_log_get(i, NULL), needle) != NULL)
			n++;
	return (n);
}

KTEST(disc_input, error_tag_text_logged_sanitised_and_rate_limited)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	for (int i = 0; i < 3; i++) {
		pado(&x, &f);
		fr_tag(&f, PPPOE_TAG_GENERIC_ERR, "no\nroom", 7);
		fr_finish(&f);
		disc_deliver(&x, &f, 0);
	}
	KT_EQ(DCNT(disc_err_tag), x.errtag0 + 3);
	/* The AC's text, with the newline it smuggled in defused... */
	KT_LOGGED("PADO carried an error tag: no?room");
	/* ...and a flood of them costs one line a second. */
	KT_EQ(disc_log_count("carried an error tag"), 1);
	kshim_time_uptime += 2;
	pado(&x, &f);
	fr_tag(&f, PPPOE_TAG_SNAME_ERR, NULL, 0);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(disc_log_count("carried an error tag"), 2);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, eol_stops_tag_walk)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_tag(&f, PPPOE_TAG_EOL, NULL, 0);
	fr_tag(&f, PPPOE_TAG_GENERIC_ERR, "x", 1);	/* after EOL: unseen */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(DCNT(disc_err_tag), x.errtag0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, host_uniq_must_match_exactly)
{
	struct disc_fx x;
	struct fr f;
	uint8_t wrong[8];

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	memcpy(wrong, x.hu, 8);
	wrong[7] ^= 1;
	/* p3-pfil-counters: none of these name our softc -> passed. */
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, wrong, 8);
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 7);		/* short token */
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADO, 0);		/* no Host-Uniq */
	fr_tag(&f, PPPOE_TAG_ACNAME, "ac1", 3);
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	disc_teardown(&x);
}

KTEST(disc_input, host_uniq_on_other_parent_dropped)
{
	struct disc_fx x;
	struct fr f;
	struct ifnet *other = fx_parent_new("em1");
	struct mbuf *m;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	pado(&x, &f);
	fr_finish(&f);
	m = kshim_mbuf_from(f.b, (int)f.len);
	/* em1 is not a bound parent: the hook passes it untouched. */
	KT_EQ(fx_pfil_in(other, &m), PFIL_PASS);
	m_freem(m);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	fx_parent_free(other);
	disc_teardown(&x);
}

/* Set a configured name the way pppoe_ioctl_setparms() stores it. */
static void
disc_set_name(struct disc_fx *x, char **slot, const char *name)
{
	char *p = malloc(strlen(name) + 1, M_PPPOE, M_WAITOK);

	strcpy(p, name);
	PPPOE_SC_LOCK(x->sc);
	free(*slot, M_PPPOE);
	*slot = p;
	PPPOE_SC_UNLOCK(x->sc);
}

KTEST(disc_input, pado_ac_name_must_match_configured)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	disc_set_name(&x, &x.sc->sc_ac_name, "ac2");
	pado(&x, &f);				/* AC-Name "ac1" */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADO, 0);	/* no AC-Name at all */
	fr_tag(&f, PPPOE_TAG_SNAME, NULL, 0);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADO, 0);	/* prefix is not a match */
	fr_tag(&f, PPPOE_TAG_ACNAME, "ac", 2);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_ACNAME, "ac2", 3);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, pado_service_name_must_match_configured)
{
	struct disc_fx x;
	struct fr f;
	uint8_t tx[256];
	const uint8_t *v;
	uint16_t l;
	int n;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	disc_set_name(&x, &x.sc->sc_service_name, "isp");
	pado(&x, &f);				/* empty Service-Name only */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_SNAME, "isp2", 4);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	/* An AC may offer several services: any one of them will do. */
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_SNAME, "other", 5);
	fr_tag(&f, PPPOE_TAG_SNAME, "isp", 3);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	n = disc_tx_pop(&x, tx, sizeof(tx));
	v = disc_tx_tag(tx, n, PPPOE_TAG_SNAME, &l);
	KT_ASSERT(v != NULL && l == 3);
	KT_MEMEQ(v, "isp", 3);
	disc_teardown(&x);
}

KTEST(disc_input, pado_empty_configured_names_match_anything)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	disc_set_name(&x, &x.sc->sc_ac_name, "");
	disc_set_name(&x, &x.sc->sc_service_name, "");
	disc_frame(&f, PPPOE_CODE_PADO, 0);
	fr_tag(&f, PPPOE_TAG_SNAME, "any", 3);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

KTEST(disc_input, extra_pado_in_padr_sent_ignored)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pado(&x, &f);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	disc_teardown(&x);
}

static void
pads(struct disc_fx *x, struct fr *f, uint16_t session)
{
	disc_frame(f, PPPOE_CODE_PADS, session);
	fr_tag(f, PPPOE_TAG_SNAME, NULL, 0);
	fr_tag(f, PPPOE_TAG_HUNIQUE, x->hu, 8);
}

KTEST(disc_input, pads_opens_session)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0x2a2a);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	KT_EQ(x.sc->sc_session, 0x2a2a);
	KT_ASSERT(x.sc->sc_want_up);
	/* Both __aligned(CACHE_LINE_SIZE) types came from malloc_aligned(9)
	 * (kshim's plain malloc() is only ever 16-byte aligned). */
	KT_ASSERT(x.sc->sc_txsnap != NULL);
	KT_EQ((uintptr_t)x.sc->sc_txsnap % CACHE_LINE_SIZE, 0);
	KT_EQ((uintptr_t)&x.sc->sc_txsnap % CACHE_LINE_SIZE, 0);
	KT_EQ(kshim_tasks_pending(), 1);
	kshim_run_tasks();
	KT_ASSERT(x.sc->sc_in_hash);
	disc_teardown(&x);
}

KTEST(disc_input, pads_only_from_chosen_ac)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0x2a2a);
	f.b[11] = 0xbb;				/* not the PADO's source */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	KT_EQ(x.sc->sc_session, 0);
	KT_EQ(kshim_tasks_pending(), 0);
	pads(&x, &f, 0x2a2a);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	KT_EQ(x.sc->sc_session, 0x2a2a);
	disc_teardown(&x);
}

KTEST(disc_input, pads_session_zero_refused)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	KT_LOGGED("PADS refused the session");
	disc_teardown(&x);
}

KTEST(disc_input, pads_error_tag_refused)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0x10);
	fr_tag(&f, PPPOE_TAG_SNAME_ERR, NULL, 0);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADR_SENT);
	disc_teardown(&x);
}

/* RFC 2516 section 4: session id 0xffff is reserved for future use. */
KTEST(disc_input, pads_session_ffff_refused)
{
	struct disc_fx x;
	struct fr f;
	int state;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0xffff);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	state = x.sc->sc_state;
	disc_teardown(&x);
	KT_EQ(state, PPPOE_STATE_PADR_SENT);
}

KTEST(disc_input, max_payload_tag_needs_two_octets)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	x.sc->sc_max_payload = 1500;
	pads(&x, &f, 0x11);
	fr_tag(&f, PPPOE_TAG_MAX_PAYLOAD, "\x05\xdc\x00", 3);	/* ignored */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	/* No usable tag: RFC 4638 says 1492 stays in force. */
	KT_EQ(x.sc->sc_max_payload, 0);
	KT_EQ(x.sc->sc_ifp->if_mtu, PPPOE_MAXMTU);
	disc_teardown(&x);
}

KTEST(disc_input, max_payload_granted_above_1492)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	x.sc->sc_max_payload = 1500;
	pads(&x, &f, 0x11);
	fr_tag(&f, PPPOE_TAG_MAX_PAYLOAD, "\x05\xdc", 2);	/* 1500 */
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_max_payload, 1500);
	KT_EQ(x.sc->sc_ifp->if_mtu, 1500);
	disc_teardown(&x);
}

/* The PADS arm's MTU change reaches the routing layer (if_notifymtu()),
 * deferred off the epoch-and-sc_mtx RX path to a task on pppoe_taskq. */
KTEST(disc_input, max_payload_mtu_change_notified)
{
	struct disc_fx x;
	struct fr f;
	int n, shared0, own0;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	x.sc->sc_max_payload = 1500;
	pads(&x, &f, 0x11);
	fr_tag(&f, PPPOE_TAG_MAX_PAYLOAD, "\x05\xdc", 2);	/* 1500 */
	fr_finish(&f);
	n = kshim_notifymtu_calls;
	shared0 = taskqueue_thread->tq_enqueued;
	own0 = pppoe_taskq->tq_enqueued;
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(x.sc->sc_ifp->if_mtu, 1500);
	KT_EQ(kshim_notifymtu_calls, n + 1);
	KT_EQ(taskqueue_thread->tq_enqueued, shared0);
	KT_ASSERT(pppoe_taskq->tq_enqueued > own0);
	disc_teardown(&x);
}

KTEST(disc_input, max_payload_tiny_value_does_not_shrink_mtu)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	x.sc->sc_max_payload = 1500;
	pads(&x, &f, 0x11);
	fr_tag(&f, PPPOE_TAG_MAX_PAYLOAD, "\x00\x01", 2);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(x.sc->sc_ifp->if_mtu, PPPOE_MAXMTU);
	disc_teardown(&x);
}

static void
padt_setup(struct disc_fx *x, uint16_t session)
{
	disc_setup(x, PPPOE_STATE_SESSION);
	PPPOE_SC_LOCK(x->sc);
	x->sc->sc_session = session;
	memcpy(&x->sc->sc_dest, fx_ac_mac, 6);
	PPPOE_SC_UNLOCK(x->sc);
}

KTEST(disc_input, padt_for_our_session_redials)
{
	struct disc_fx x;
	struct fr f;

	padt_setup(&x, 0x77);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_EQ(DCNT(padt_rx), x.padt0 + 1);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_EQ(x.sc->sc_session, 0);
	KT_ASSERT(callout_pending(&x.sc->sc_timeout));
	disc_teardown(&x);
}

/*
 * An auth NAK closes LCP (Opened -> Closing -> Stopping) and the ISP's
 * PADT lands before its Terminate-Ack: the Down event takes Stopping to
 * Starting with the lower layer still "running", and the PADT arm has
 * already re-armed discovery for PPPOE_RECON_PADTRCVD.  The auth backoff
 * must still hold the redial off: pp_dial_ch armed, and no fixed 5 s
 * PADI_SENT redial left behind in the driver.
 */
KTEST(disc_input, padt_before_rta_after_auth_fail_backs_off)
{
	struct disc_fx x;
	struct fr f;
	struct sppp *sp;

	padt_setup(&x, 0x77);
	sp = fx_pppoe_sppp(x.sc);
	fx_sppp_auth_fail_close(sp, 3);
	KT_EQ(sp->scp[FX_IDX_LCP].state, SPPP_STATE_STOPPING);
	kshim_tx_flush(x.parent);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(sp->scp[FX_IDX_LCP].state, SPPP_STATE_STARTING);
	/* 3 failures: 1 << 2 s before the next dial. */
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	KT_EQ(sp->pp_dial_ch.c_time - kshim_ticks, 4 * hz);
	KT_ASSERT(!(x.sc->sc_state == PPPOE_STATE_PADI_SENT &&
	    callout_pending(&x.sc->sc_timeout)));
	/* The backed-off dial goes out when pp_dial_ch fires ... */
	KT_EQ(kshim_callout_fire(&sp->pp_dial_ch), 1);
	kshim_run_tasks();
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	/*
	 * ... and the session it finds comes up: the release above cleared
	 * the softc from PADI_SENT, which latches no Down for the PADS.
	 */
	KT_ASSERT(!x.sc->sc_want_down);
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_want_up = true;	/* what the PADS arm latches */
	PPPOE_SC_UNLOCK(x.sc);
	fx_pppoe_session_up(x.sc, 0x78, fx_ac_mac);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	KT_EQ(sp->scp[FX_IDX_LCP].state, SPPP_STATE_REQ_SENT);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	disc_teardown(&x);
}

/*
 * The ISP's PADT lands while LCP is still Opened after earlier auth
 * failures (no NAK this time): the Down event takes Opened to Starting with
 * the lower layer running, and the backoff must still hold the redial off.
 */
KTEST(disc_input, padt_in_opened_after_auth_fail_backs_off)
{
	struct disc_fx x;
	struct fr f;
	struct sppp *sp;

	padt_setup(&x, 0x77);
	sp = fx_pppoe_sppp(x.sc);
	fx_sppp_opened_authenticating(sp, 2);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(sp->scp[FX_IDX_LCP].state, SPPP_STATE_STARTING);
	/* 2 failures: 1 << 1 s, and the driver's own redial is released. */
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	KT_EQ(sp->pp_dial_ch.c_time - kshim_ticks, 2 * hz);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_INITIAL);
	disc_teardown(&x);
}

/* Without an auth failure a PADT keeps the driver's fixed redial. */
KTEST(disc_input, padt_in_opened_no_auth_fail_redials)
{
	struct disc_fx x;
	struct fr f;
	struct sppp *sp;

	padt_setup(&x, 0x77);
	sp = fx_pppoe_sppp(x.sc);
	fx_sppp_opened_authenticating(sp, 0);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(sp->scp[FX_IDX_LCP].state, SPPP_STATE_STARTING);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_ASSERT(callout_pending(&x.sc->sc_timeout));
	disc_teardown(&x);
}

/*
 * 4 failures: an 8 s backoff.  The PADT arm's PPPOE_RECON_PADTRCVD
 * sc_timeout, if the release left one behind, must be inert: no PADI goes
 * out before pp_dial_ch fires.
 */
KTEST(disc_input, padt_redial_timer_inert_under_backoff)
{
	struct disc_fx x;
	struct fr f;
	struct sppp *sp;

	padt_setup(&x, 0x77);
	sp = fx_pppoe_sppp(x.sc);
	fx_sppp_auth_fail_close(sp, 4);
	kshim_tx_flush(x.parent);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(sp->pp_dial_ch.c_time - kshim_ticks, 8 * hz);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_INITIAL);
	kshim_tx_flush(x.parent);
	if (callout_pending(&x.sc->sc_timeout)) {
		PPPOE_SC_LOCK(x.sc);
		kshim_callout_fire(&x.sc->sc_timeout);
		PPPOE_SC_UNLOCK(x.sc);
	}
	KT_EQ(x.sc->sc_state, PPPOE_STATE_INITIAL);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	disc_teardown(&x);
}

/*
 * Only a SESSION clear latches sc_want_down: nothing enqueues the session
 * task for a clear from discovery, so a Down latched there would wait for
 * the next PADS and reach LCP together with its Up.
 */
KTEST(disc_input, clear_from_padi_sent_latches_no_down)
{
	struct disc_fx x;
	struct fr f;

	padt_setup(&x, 0x77);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	KT_ASSERT(x.sc->sc_want_down);		/* the session's own Down */
	kshim_run_tasks();
	KT_ASSERT(!x.sc->sc_want_down);		/* ... delivered */
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	PPPOE_SC_LOCK(x.sc);
	pppoe_clear_softc(x.sc, "test");
	KT_ASSERT(!x.sc->sc_want_down);
	KT_ASSERT(!x.sc->sc_want_up);
	PPPOE_SC_UNLOCK(x.sc);
	disc_teardown(&x);
}

KTEST(disc_input, padt_other_session_or_peer_ignored)
{
	struct disc_fx x;
	struct fr f;

	/* p3-pfil-counters: none of these attribute to our live session ->
	 * passed (frame-level padt_rx is still counted, below). */
	padt_setup(&x, 0x77);
	disc_frame(&f, PPPOE_CODE_PADT, 0x78);
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	disc_frame(&f, PPPOE_CODE_PADT, 0x77);
	f.b[11] = 0xbb;				/* not our AC */
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	/* Host-Uniq finds the softc, but the session key must match too. */
	disc_frame(&f, PPPOE_CODE_PADT, 0x78);
	fr_tag(&f, PPPOE_TAG_HUNIQUE, x.hu, 8);
	fr_finish(&f);
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	KT_EQ(x.sc->sc_session, 0x77);
	KT_EQ(DCNT(padt_rx), x.padt0 + 3);
	disc_teardown(&x);
}

KTEST(disc_input, padt_session_zero_matches_nothing)
{
	struct disc_fx x;
	struct fr f;

	padt_setup(&x, 0x77);
	disc_frame(&f, PPPOE_CODE_PADT, 0);
	fr_finish(&f);
	/* p3-pfil-counters: session 0 never matches -> passed. */
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	disc_teardown(&x);
}

KTEST(disc_input, detaching_softc_backs_out)
{
	struct disc_fx x;
	struct fr f;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_detaching = true;
	PPPOE_SC_UNLOCK(x.sc);
	pado(&x, &f);
	fr_finish(&f);
	/* p3-pfil-counters: a detaching softc backs out -> passed. */
	disc_deliver_pass(&x, &f, 0);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_detaching = false;
	PPPOE_SC_UNLOCK(x.sc);
	disc_teardown(&x);
}

/* Fire the retransmit timer from PADR_SENT on its last PADR. */
static void
padr_fallback(struct disc_fx *x, int padi_retried)
{
	PPPOE_SC_LOCK(x->sc);
	x->sc->sc_padi_retried = padi_retried;
	x->sc->sc_padr_retried = PPPOE_DISC_MAXPADR - 1;
	callout_reset(&x->sc->sc_timeout, PPPOE_DISC_TIMEOUT, pppoe_timeout,
	    x->sc);
	PPPOE_SC_UNLOCK(x->sc);
	KT_EQ(kshim_callout_fire(&x->sc->sc_timeout), 1);
	KT_EQ(x->sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_ASSERT(callout_pending(&x->sc->sc_timeout));
	kshim_tx_flush(x->parent);
}

/*
 * An AC that answers every PADI with a PADO but never sends the PADS must
 * not reset the PADI backoff on each PADR give-up: the fallback PADI counts
 * as one more retry and is spaced like any other.
 */
KTEST(disc_timeout, padr_fallback_keeps_padi_backoff)
{
	struct disc_fx x;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	padr_fallback(&x, 1);
	KT_EQ(x.sc->sc_padi_retried, 2);
	KT_EQ(x.sc->sc_timeout.c_time - kshim_ticks, PPPOE_DISC_TIMEOUT * 4);
	disc_teardown(&x);

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	padr_fallback(&x, PPPOE_DISC_MAXPADI);
	KT_EQ(x.sc->sc_padi_retried, PPPOE_DISC_MAXPADI + 1);
	KT_EQ(x.sc->sc_timeout.c_time - kshim_ticks, PPPOE_SLOW_RETRY);
	disc_teardown(&x);
}

/* The PADI builder: Service-Name, Host-Uniq, and RFC 4638 when asked. */
KTEST(disc_send_padi, tags_and_max_payload)
{
	struct disc_fx x;
	uint8_t tx[256];
	const uint8_t *v;
	uint16_t l;
	int n;

	disc_setup(&x, PPPOE_STATE_INITIAL);
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_max_payload_req = 1500;
	KT_EQ(pppoe_send_padi(x.sc), 0);
	PPPOE_SC_UNLOCK(x.sc);
	n = disc_tx_pop(&x, tx, sizeof(tx));
	KT_ASSERT(n > 20);
	KT_MEMEQ(tx, "\xff\xff\xff\xff\xff\xff", 6);
	KT_MEMEQ(tx + 6, fx_our_mac, 6);
	KT_EQ(tx[15], PPPOE_CODE_PADI);
	KT_EQ(tx[16] << 8 | tx[17], 0);
	KT_EQ((tx[18] << 8 | tx[19]) + 20, n);
	KT_ASSERT(disc_tx_tag(tx, n, PPPOE_TAG_SNAME, &l) != NULL && l == 0);
	v = disc_tx_tag(tx, n, PPPOE_TAG_HUNIQUE, &l);
	KT_ASSERT(v != NULL && l == 8);
	KT_MEMEQ(v, x.hu, 8);
	v = disc_tx_tag(tx, n, PPPOE_TAG_MAX_PAYLOAD, &l);
	KT_ASSERT(v != NULL && l == 2 && (v[0] << 8 | v[1]) == 1500);
	disc_teardown(&x);
}

KTEST(disc_send_padt, refuses_session_zero)
{
	struct disc_fx x;
	struct epoch_tracker et;

	disc_setup(&x, PPPOE_STATE_INITIAL);
	NET_EPOCH_ENTER(et);
	KT_EQ(pppoe_send_padt(x.parent, 0,
	    (const struct ether_addr *)fx_ac_mac), EINVAL);
	KT_EQ(pppoe_send_padt(NULL, 5,
	    (const struct ether_addr *)fx_ac_mac), EINVAL);
	NET_EPOCH_EXIT(et);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	disc_teardown(&x);
}

/*
 * Nothing goes to a parent that is down or whose driver is not running:
 * vtnet_txq_mq_start() divides by its active queue-pair count, which is zero
 * until vtnet_init() has run, and a PADI sent to a vtnet that was not yet
 * running took the lab client down with "Fatal trap 18: integer divide
 * fault".  Discovery frames are dropped in pppoe_output_frame() and
 * retried by sc_timeout.
 */
static void
disc_parent_flags(struct disc_fx *x, int flags, int drvflags)
{
	x->parent->if_flags = flags;
	x->parent->if_drv_flags = drvflags;
}

KTEST(disc_send, parent_not_running_drops_discovery)
{
	static const int fl[][2] = {
		{ IFF_UP, 0 },			/* up, driver not running */
		{ 0, IFF_DRV_RUNNING },		/* administratively down */
		{ 0, 0 },
	};
	struct disc_fx x;
	struct epoch_tracker et;
	struct mbuf *m;
	uint64_t err0, down0;
	size_t i;

	disc_setup(&x, PPPOE_STATE_INITIAL);
	for (i = 0; i < nitems(fl); i++) {
		disc_parent_flags(&x, fl[i][0], fl[i][1]);
		err0 = DCNT(tx_errors);
		down0 = DCNT(tx_parent_down);
		PPPOE_SC_LOCK(x.sc);
		(void)pppoe_send_padi(x.sc);
		(void)pppoe_send_padr(x.sc);
		PPPOE_SC_UNLOCK(x.sc);
		NET_EPOCH_ENTER(et);
		KT_EQ(pppoe_send_padt(x.parent, 5,
		    (const struct ether_addr *)fx_ac_mac), ENETDOWN);
		NET_EPOCH_EXIT(et);
		KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
		KT_EQ(DCNT(tx_errors), err0 + 3);
		KT_EQ(DCNT(tx_parent_down), down0 + 3);
	}
	/* Up and running again: the next PADI goes out. */
	disc_parent_flags(&x, IFF_UP, IFF_DRV_RUNNING);
	PPPOE_SC_LOCK(x.sc);
	KT_EQ(pppoe_send_padi(x.sc), 0);
	PPPOE_SC_UNLOCK(x.sc);
	KT_ASSERT((m = kshim_tx_pop(x.parent)) != NULL);
	m_freem(m);
	disc_teardown(&x);
}

/* Session frames: pppoe_encap_output(), reached here via if_transmit. */
KTEST(disc_send, parent_not_running_drops_session_frames)
{
	static const uint8_t lcp[] = {
		0xc0, 0x21, 0x09, 0x01, 0x00, 0x08, 0, 0, 0, 0,
	};
	struct disc_fx x;
	struct fr f;
	struct ifnet *ifp;
	struct mbuf *m;
	uint64_t err0, down0, oerr0;

	disc_setup(&x, PPPOE_STATE_PADR_SENT);
	pads(&x, &f, 0x2a2a);
	fr_finish(&f);
	disc_deliver(&x, &f, 0);
	kshim_run_tasks();
	KT_EQ(x.sc->sc_state, PPPOE_STATE_SESSION);
	ifp = x.sc->sc_ifp;
	kshim_tx_flush(x.parent);

	disc_parent_flags(&x, IFF_UP, 0);
	err0 = DCNT(tx_errors);
	down0 = DCNT(tx_parent_down);
	oerr0 = if_getcounter(ifp, IFCOUNTER_OERRORS);
	KT_EQ(if_transmit(ifp, kshim_mbuf_from(lcp, sizeof(lcp))), ENETDOWN);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	KT_EQ(DCNT(tx_errors), err0 + 1);
	KT_EQ(DCNT(tx_parent_down), down0 + 1);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_OERRORS), oerr0 + 1);

	disc_parent_flags(&x, IFF_UP, IFF_DRV_RUNNING);
	KT_EQ(if_transmit(ifp, kshim_mbuf_from(lcp, sizeof(lcp))), 0);
	KT_ASSERT((m = kshim_tx_pop(x.parent)) != NULL);
	m_freem(m);
	kshim_tx_flush(ifp);
	disc_teardown(&x);
}

/*
 * wb/parent-guard x wb/discovery: a PADI dropped because the parent is down
 * never reached the wire, so it must not advance the backoff.  Otherwise an
 * outage of a few minutes walks sc_padi_retried into PPPOE_SLOW_RETRY and
 * the first real PADI after the parent returns is up to a minute late.
 * While the parent is down discovery polls it at the fast interval; once it
 * is back the PADI goes out and the schedule restarts from the bottom.
 */
KTEST(disc_timeout, parent_down_padi_keeps_fast_backoff)
{
	struct disc_fx x;
	struct mbuf *m;
	uint64_t down0;
	int i;

	disc_setup(&x, PPPOE_STATE_PADI_SENT);
	PPPOE_SC_LOCK(x.sc);
	/* Deep into the backoff already when the parent drops. */
	x.sc->sc_padi_retried = PPPOE_DISC_MAXPADI;
	callout_reset(&x.sc->sc_timeout, PPPOE_SLOW_RETRY, pppoe_timeout,
	    x.sc);
	PPPOE_SC_UNLOCK(x.sc);
	disc_parent_flags(&x, IFF_UP, 0);
	down0 = DCNT(tx_parent_down);
	for (i = 0; i < 2 * PPPOE_DISC_MAXPADI; i++) {
		KT_EQ(kshim_callout_fire(&x.sc->sc_timeout), 1);
		KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
		KT_EQ(x.sc->sc_padi_retried, 0);
		KT_ASSERT(callout_pending(&x.sc->sc_timeout));
		KT_EQ(x.sc->sc_timeout.c_time - kshim_ticks,
		    PPPOE_DISC_TIMEOUT);
	}
	KT_EQ(DCNT(tx_parent_down), down0 + 2 * PPPOE_DISC_MAXPADI);

	/* The PADR give-up fallback PADI is held to the same rule. */
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_state = PPPOE_STATE_PADR_SENT;
	x.sc->sc_padi_retried = PPPOE_DISC_MAXPADI;
	x.sc->sc_padr_retried = PPPOE_DISC_MAXPADR - 1;
	PPPOE_SC_UNLOCK(x.sc);
	KT_EQ(kshim_callout_fire(&x.sc->sc_timeout), 1);
	KT_EQ(x.sc->sc_state, PPPOE_STATE_PADI_SENT);
	KT_EQ(x.sc->sc_padi_retried, 0);
	KT_EQ(x.sc->sc_timeout.c_time - kshim_ticks, PPPOE_DISC_TIMEOUT);

	/* Parent back: the next PADI goes out, first rung of the backoff. */
	disc_parent_flags(&x, IFF_UP, IFF_DRV_RUNNING);
	KT_EQ(kshim_callout_fire(&x.sc->sc_timeout), 1);
	KT_ASSERT((m = kshim_tx_pop(x.parent)) != NULL);
	m_freem(m);
	KT_EQ(x.sc->sc_padi_retried, 1);
	KT_EQ(x.sc->sc_timeout.c_time - kshim_ticks, PPPOE_DISC_TIMEOUT * 2);
	disc_teardown(&x);
}
