/* pppoe_pfil_in() / pppoe_sess_input(): session header validation --
 * sys/net/if_pppoe.c */
#include "ktest.h"
#include "frames.h"

#define	CNT(c)	(*V_pppoe_stats.c)

struct sess_fx {
	struct pppoe_softc *sc;
	struct ifnet *parent;
	uint64_t short0, nosess0, in0;
};

static void
sess_setup(struct sess_fx *x, uint16_t session)
{
	x->sc = fx_pppoe_new();
	x->parent = fx_parent_new("em0");
	KT_EQ(fx_pppoe_bind(x->sc, x->parent), 0);
	fx_pppoe_session_up(x->sc, session, fx_ac_mac);
	/* The session task's pp_up() started LCP; not this test's business. */
	kshim_tx_flush(x->sc->sc_ifp);
	kshim_tx_flush(x->parent);
	x->short0 = CNT(sess_short);
	x->nosess0 = CNT(sess_nosession);
	x->in0 = CNT(sess_in);
}

static void
sess_teardown(struct sess_fx *x)
{
	kshim_netisr_flush();
	fx_pppoe_free(x->sc);
	fx_parent_free(x->parent);
}

/* Session frame: PPP protocol + payload. */
static void
sess_frame(struct fr *f, uint16_t session, const void *ppp, size_t n)
{
	fr_start(f, fx_our_mac, fx_ac_mac, ETHERTYPE_PPPOE, 0, session);
	fr_bytes(f, ppp, n);
	fr_finish(f);
}

static int
sess_deliver(struct sess_fx *x, const struct fr *f, int seglen)
{
	struct mbuf *m = seglen > 0 ?
	    kshim_mbuf_chain(f->b, (int)f->len, seglen) :
	    kshim_mbuf_from(f->b, (int)f->len);
	uint64_t foreign0 = CNT(passed_foreign), in0 = CNT(sess_in);
	int r;

	m->m_pkthdr.rcvif = x->parent;
	r = fx_pfil_in(x->parent, &m);
	/* PFIL_PASS hands the mbuf back intact (p3-pfil-counters); nothing
	 * downstream of this test harness will free it.  A passed frame is
	 * counted as passed_foreign and never as taken (sess_in). */
	if (r == PFIL_PASS) {
		KT_ASSERT(m != NULL);
		KT_EQ(CNT(passed_foreign), foreign0 + 1);
		KT_EQ(CNT(sess_in), in0);
		m_freem(m);
	} else {
		KT_ASSERT(m == NULL);
		KT_EQ(CNT(passed_foreign), foreign0);
	}
	return (r);
}

KTEST(pppoe_sess_input, good_frame_stripped_and_dispatched)
{
	struct sess_fx x;
	struct fr f;
	uint8_t ppp[] = { 0xc0, 0x21, 1, 1, 0, 4 };
	struct mbuf *m;
	uint8_t got[16];

	sess_setup(&x, 0x1234);
	sess_frame(&f, 0x1234, ppp, sizeof(ppp));
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	KT_EQ(CNT(sess_in), x.in0 + 1);
	m = kshim_netisr_pop();
	KT_ASSERT(m != NULL);
	KT_EQ(m->m_pkthdr.len, (int)sizeof(ppp));
	KT_ASSERT(m->m_pkthdr.rcvif == x.sc->sc_ifp);
	m_copydata(m, 0, sizeof(ppp), (caddr_t)got);
	KT_MEMEQ(got, ppp, sizeof(ppp));
	m_freem(m);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, ethernet_padding_trimmed_to_plen)
{
	struct sess_fx x;
	struct fr f;
	uint8_t ppp[] = { 0x00, 0x21, 0x45 }, pad[40] = { 0 };
	struct mbuf *m;

	sess_setup(&x, 7);
	sess_frame(&f, 7, ppp, sizeof(ppp));
	fr_bytes(&f, pad, sizeof(pad));		/* after fr_finish: padding */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	m = kshim_netisr_pop();
	KT_ASSERT(m != NULL);
	KT_EQ(m->m_pkthdr.len, 3);
	KT_EQ(m_length(m, NULL), 3);
	m_freem(m);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, header_split_across_mbufs_pulled_up)
{
	struct sess_fx x;
	struct fr f;
	uint8_t ppp[64];
	struct mbuf *m;

	memset(ppp, 0x77, sizeof(ppp));
	ppp[0] = 0xc0;
	ppp[1] = 0x21;
	sess_setup(&x, 9);
	sess_frame(&f, 9, ppp, sizeof(ppp));
	KT_EQ(sess_deliver(&x, &f, 7), PFIL_CONSUMED);
	m = kshim_netisr_pop();
	KT_ASSERT(m != NULL);
	KT_EQ(m->m_pkthdr.len, (int)sizeof(ppp));
	m_freem(m);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, runt_counted_short)
{
	struct sess_fx x;
	struct fr f;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0", 1);	/* 14 + 6 + 1 < need */
	/* p3-pfil-counters: too short to attribute -> passed, not consumed. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_EQ(CNT(sess_short), x.short0 + 1);
	KT_ASSERT(kshim_netisr_pop() == NULL);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, bad_vertype_or_code_counted_short)
{
	struct sess_fx x;
	struct fr f;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0\x21", 2);
	f.b[14] = 0x21;
	/* p3-pfil-counters: malformed and unattributable -> passed. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	sess_frame(&f, 9, "\xc0\x21", 2);
	f.b[15] = PPPOE_CODE_PADS;
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_EQ(CNT(sess_short), x.short0 + 2);
	KT_ASSERT(kshim_netisr_pop() == NULL);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, plen_below_protocol_field_counted_short)
{
	struct sess_fx x;
	struct fr f;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0\x21\x01", 3);
	fr_set_plen(&f, 1);
	/* p3-pfil-counters: malformed and unattributable -> passed. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	fr_set_plen(&f, 0);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_EQ(CNT(sess_short), x.short0 + 2);
	KT_ASSERT(kshim_netisr_pop() == NULL);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, plen_past_frame_counted_short)
{
	struct sess_fx x;
	struct fr f;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0\x21\x01\x02", 4);
	fr_set_plen(&f, 5);
	/* p3-pfil-counters: malformed and unattributable -> passed. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	fr_set_plen(&f, 0xffff);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_EQ(CNT(sess_short), x.short0 + 2);
	fr_set_plen(&f, 4);		/* exactly the frame: accepted */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	KT_EQ(CNT(sess_in), x.in0 + 1);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, unknown_session_or_peer_not_delivered)
{
	struct sess_fx x;
	struct fr f;
	uint8_t other[6] = { 0x02, 0, 0, 0, 0, 0xbb };

	sess_setup(&x, 9);
	sess_frame(&f, 10, "\xc0\x21", 2);
	/* p3-pfil-counters: unattributed session -> passed, not consumed;
	 * it may belong to another PPPoE client sharing this parent. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	sess_frame(&f, 9, "\xc0\x21", 2);
	memcpy(f.b + 6, other, 6);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_EQ(CNT(sess_nosession), x.nosess0 + 2);
	KT_ASSERT(kshim_netisr_pop() == NULL);
	/* term_unknown is off by default: no PADT. */
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, term_unknown_padt_rate_limited)
{
	struct sess_fx x;
	struct fr f;
	struct mbuf *m;
	uint8_t hdr[20];

	sess_setup(&x, 9);
	kshim_time_uptime += 10;	/* a fresh ppsratecheck() second */
	V_pppoe_term_unknown = 1;
	/* p3-pfil-counters: term_unknown only PADTs a session this softc can
	 * attribute to itself (pppoe_stale_session_is_ours()); record 0x0bad
	 * as the one it last closed so the PADT + rate limit still fire. */
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_last_session = 0x0bad;
	memcpy(&x.sc->sc_last_dest, fx_ac_mac, ETHER_ADDR_LEN);
	x.sc->sc_last_closed = kshim_time_uptime;
	PPPOE_SC_UNLOCK(x.sc);
	sess_frame(&f, 0x0bad, "\xc0\x21", 2);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	m = kshim_tx_pop(x.parent);
	KT_ASSERT(m != NULL);
	m_copydata(m, 0, 20, (caddr_t)hdr);
	KT_MEMEQ(hdr, fx_ac_mac, 6);
	KT_EQ(hdr[15], PPPOE_CODE_PADT);
	KT_EQ(hdr[16] << 8 | hdr[17], 0x0bad);
	m_freem(m);
	/* Same second: over term_unknown_pps (1); still attributed, still
	 * consumed -- just no second PADT. */
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	/* Not unicast to us: never a PADT, and now unattributable -> passed. */
	kshim_time_uptime += 5;
	memset(f.b, 0xff, 6);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	V_pppoe_term_unknown = 0;
	sess_teardown(&x);
}

KTEST(pppoe_sess_input, term_unknown_not_ours_passed_no_padt)
{
	struct sess_fx x;
	struct fr f;
	uint64_t unk0;

	sess_setup(&x, 9);
	kshim_time_uptime += 10;	/* a fresh ppsratecheck() second */
	V_pppoe_term_unknown = 1;
	/* Our softc last closed 0x0bad, recently, with this AC. */
	PPPOE_SC_LOCK(x.sc);
	x.sc->sc_last_session = 0x0bad;
	memcpy(&x.sc->sc_last_dest, fx_ac_mac, ETHER_ADDR_LEN);
	x.sc->sc_last_closed = kshim_time_uptime;
	PPPOE_SC_UNLOCK(x.sc);
	unk0 = CNT(padt_unknown);
	/* Unicast to us, unknown session, but not the one we closed:
	 * pppoe_stale_session_is_ours() says no, so it is someone else's
	 * (mpd5 on the same parent) -- pass it, never PADT it. */
	sess_frame(&f, 0x0bae, "\xc0\x21", 2);
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	/* Our closed id from a different AC: also not ours. */
	sess_frame(&f, 0x0bad, "\xc0\x21", 2);
	f.b[11] ^= 0x01;
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_PASS);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	KT_EQ(CNT(padt_unknown), unk0);
	KT_EQ(CNT(sess_nosession), x.nosess0 + 2);
	KT_ASSERT(kshim_netisr_pop() == NULL);
	V_pppoe_term_unknown = 0;
	sess_teardown(&x);
}

KTEST(pppoe_pfil_in, foreign_parent_and_vlan_passed)
{
	struct sess_fx x;
	struct fr f;
	struct ifnet *other = fx_parent_new("em1");
	struct mbuf *m;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0\x21", 2);
	m = kshim_mbuf_from(f.b, (int)f.len);
	KT_EQ(fx_pfil_in(other, &m), PFIL_PASS);
	KT_ASSERT(m != NULL);
	m->m_flags |= M_VLANTAG;
	m->m_pkthdr.ether_vtag = 42;
	KT_EQ(fx_pfil_in(x.parent, &m), PFIL_PASS);
	m_freem(m);
	fx_parent_free(other);
	sess_teardown(&x);
}

KTEST(pppoe_pfil_in, needs_net_epoch)
{
	struct sess_fx x;
	struct fr f;
	struct mbuf *m;

	sess_setup(&x, 9);
	sess_frame(&f, 9, "\xc0\x21", 2);
	m = kshim_mbuf_from(f.b, (int)f.len);
	KT_EXPECT_PANIC(pppoe_pfil_in(&m, x.parent, PFIL_IN, NULL, NULL),
	    "net epoch");
	m_freem(m);
	sess_teardown(&x);
}

/*
 * pppoe_parent_departed() runs after if_detach_internal() has if_down()'d
 * the parent, so IFF_UP is always clear there; a parent whose driver still
 * runs (a vlan being destroyed) must still get the session's PADT, or the
 * AC holds the session until its own LCP echo gives up.  A parent whose
 * driver has stopped gets none, and nothing is counted as a drop.
 */
KTEST(pppoe_parent_departed, padt_needs_only_drv_running)
{
	struct sess_fx x;
	struct mbuf *m;
	uint64_t padt0, err0, down0;
	uint8_t hdr[20];

	sess_setup(&x, 9);
	x.parent->if_flags &= ~IFF_UP;
	padt0 = CNT(padt_tx);
	down0 = CNT(tx_parent_down);
	pppoe_parent_departed(x.parent);
	KT_ASSERT(x.sc->sc_parent == NULL);
	KT_ASSERT((m = kshim_tx_pop(x.parent)) != NULL);
	m_copydata(m, 0, 20, (caddr_t)hdr);
	KT_MEMEQ(hdr, fx_ac_mac, 6);
	KT_EQ(hdr[15], PPPOE_CODE_PADT);
	KT_EQ(hdr[16] << 8 | hdr[17], 9);
	m_freem(m);
	KT_EQ(CNT(padt_tx), padt0 + 1);
	KT_EQ(CNT(tx_parent_down), down0);
	kshim_run_tasks();
	sess_teardown(&x);

	sess_setup(&x, 9);
	x.parent->if_flags &= ~IFF_UP;
	x.parent->if_drv_flags &= ~IFF_DRV_RUNNING;
	padt0 = CNT(padt_tx);
	err0 = CNT(tx_errors);
	down0 = CNT(tx_parent_down);
	pppoe_parent_departed(x.parent);
	KT_ASSERT(x.sc->sc_parent == NULL);
	KT_ASSERT(kshim_tx_pop(x.parent) == NULL);
	KT_EQ(CNT(padt_tx), padt0);
	KT_EQ(CNT(tx_errors), err0);
	KT_EQ(CNT(tx_parent_down), down0);
	kshim_run_tasks();
	sess_teardown(&x);
}
