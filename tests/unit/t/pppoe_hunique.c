/* pppoe_find_by_hunique() / pppoe_find_by_session() -- sys/net/if_pppoe.c */

static struct pppoe_softc *
hu_find(const void *tok, size_t len)
{
	struct epoch_tracker et;
	struct pppoe_softc *sc;

	NET_EPOCH_ENTER(et);
	sc = pppoe_find_by_hunique(tok, len);
	NET_EPOCH_EXIT(et);
	return (sc);
}

KTEST(pppoe_hunique, matches_only_its_own_token)
{
	struct pppoe_softc *a = fx_pppoe_new(), *b = fx_pppoe_new();
	uint64_t ta = htobe64(a->sc_hunique), tb = htobe64(b->sc_hunique);
	uint64_t none = htobe64(0xfeedfacecafef00dULL);
	uint8_t unaligned[9];

	KT_NE(a->sc_hunique, b->sc_hunique);
	KT_ASSERT(hu_find(&ta, 8) == a);
	KT_ASSERT(hu_find(&tb, 8) == b);
	KT_ASSERT(hu_find(&none, 8) == NULL);
	memcpy(unaligned + 1, &tb, 8);
	KT_ASSERT(hu_find(unaligned + 1, 8) == b);
	fx_pppoe_free(a);
	fx_pppoe_free(b);
}

KTEST(pppoe_hunique, wrong_length_never_matches)
{
	struct pppoe_softc *a = fx_pppoe_new();
	uint8_t tok[16] = { 0 };
	uint64_t t = htobe64(a->sc_hunique);

	memcpy(tok, &t, 8);
	KT_ASSERT(hu_find(tok, 0) == NULL);
	KT_ASSERT(hu_find(tok, 7) == NULL);
	KT_ASSERT(hu_find(tok, 9) == NULL);
	KT_ASSERT(hu_find(tok, 16) == NULL);
	fx_pppoe_free(a);
}

KTEST(pppoe_hunique, destroyed_softc_unlisted)
{
	struct pppoe_softc *a = fx_pppoe_new();
	uint64_t t = htobe64(a->sc_hunique);

	fx_pppoe_free(a);
	KT_ASSERT(hu_find(&t, 8) == NULL);
}

static uint64_t
hu_connect(struct pppoe_softc *sc)
{
	uint64_t hu;

	PPPOE_SC_LOCK(sc);
	KT_EQ(pppoe_connect(sc), 0);
	hu = sc->sc_hunique;
	callout_stop(&sc->sc_timeout);
	pppoe_clear_softc(sc, "test");
	PPPOE_SC_UNLOCK(sc);
	kshim_run_tasks();
	kshim_tx_flush(sc->sc_parent);
	return (hu);
}

/* A fresh, unpredictable Host-Uniq per connect, never the previous one. */
KTEST(pppoe_hunique, connect_draws_a_fresh_token)
{
	struct pppoe_softc *a = fx_pppoe_new();
	struct ifnet *parent = fx_parent_new("em0");
	uint64_t h0, h1, h2, t;

	KT_EQ(fx_pppoe_bind(a, parent), 0);
	h0 = a->sc_hunique;
	h1 = hu_connect(a);
	h2 = hu_connect(a);
	KT_NE(h1, h0);
	KT_NE(h2, h1);
	KT_NE(h1, 0);
	KT_NE(h2, 0);
	t = htobe64(h2);
	KT_ASSERT(hu_find(&t, 8) == a);
	fx_pppoe_free(a);
	fx_parent_free(parent);
}

/* A draw that lands on another live softc's token is drawn again. */
KTEST(pppoe_hunique, connect_skips_a_token_in_use)
{
	struct pppoe_softc *a = fx_pppoe_new(), *b = fx_pppoe_new();
	struct ifnet *parent = fx_parent_new("em0");
	uint64_t ha, hb, t;

	KT_EQ(fx_pppoe_bind(a, parent), 0);
	KT_EQ(fx_pppoe_bind(b, parent), 0);
	kshim_arc4random_seed(0x1234567887654321ULL);
	ha = hu_connect(a);
	kshim_arc4random_seed(0x1234567887654321ULL);	/* same draw again */
	hb = hu_connect(b);
	KT_NE(ha, hb);
	KT_EQ(a->sc_hunique, ha);
	t = htobe64(ha);
	KT_ASSERT(hu_find(&t, 8) == a);
	t = htobe64(hb);
	KT_ASSERT(hu_find(&t, 8) == b);
	fx_pppoe_free(a);
	fx_pppoe_free(b);
	fx_parent_free(parent);
}

KTEST(pppoe_find_by_session, session_zero_never_matches)
{
	struct pppoe_softc *a = fx_pppoe_new();
	struct ifnet *parent = fx_parent_new("em0");
	struct epoch_tracker et;

	KT_EQ(fx_pppoe_bind(a, parent), 0);
	PPPOE_SC_LOCK(a);
	a->sc_state = PPPOE_STATE_SESSION;
	a->sc_session = 0;
	memcpy(&a->sc_dest, fx_ac_mac, 6);
	PPPOE_SC_UNLOCK(a);
	NET_EPOCH_ENTER(et);
	KT_ASSERT(pppoe_find_by_session(parent, 0,
	    (const struct ether_addr *)fx_ac_mac) == NULL);
	NET_EPOCH_EXIT(et);
	PPPOE_SC_LOCK(a);
	a->sc_state = PPPOE_STATE_INITIAL;
	PPPOE_SC_UNLOCK(a);
	fx_pppoe_free(a);
	fx_parent_free(parent);
}

/* A pure-function test: PPPOE_SESSHASH() spreads an AC's stride-64 ids. */
KTEST(pppoe_sesshash, spreads_stride_64_ids)
{
	int used[PPPOE_SESSHASH_SIZE] = { 0 }, distinct = 0, worst = 0;

	for (uint32_t id = 0; id < 64 * 64; id += 64)
		used[PPPOE_SESSHASH(id)]++;
	for (int i = 0; i < PPPOE_SESSHASH_SIZE; i++)
		distinct += used[i] != 0;
	KT_EQ(distinct, PPPOE_SESSHASH_SIZE);
	/* An unaligned run (accel-ppp's 14016...) stays near-perfect. */
	memset(used, 0, sizeof(used));
	for (uint32_t id = 14016; id < 14016 + 64 * 64; id += 64)
		used[PPPOE_SESSHASH(id)]++;
	for (int i = 0; i < PPPOE_SESSHASH_SIZE; i++)
		worst = MAX(worst, used[i]);
	KT_ASSERT(worst <= 2);
}
