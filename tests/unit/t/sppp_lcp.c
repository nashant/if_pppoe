/* sppp_lcp_confreq() / _confnak() / _confrej() -- sys/net/if_spppsubr.c */

static int
lcp_req(struct sppp *sp, const void *opts, size_t olen, uint8_t *out,
    size_t *outlen)
{
	uint8_t pkt[2048];
	size_t n = cp_pkt(pkt, CONF_REQ, 1, opts, olen);

	return (fx_sppp_confreq(sp, FX_IDX_LCP, pkt, n, out, 2048, outlen));
}

KTEST(lcp_confreq, needs_lock)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8] = { CONF_REQ, 1, 0, 8, LCP_OPT_MRU, 4, 0x05, 0xd4 };
	uint8_t *buf;
	size_t blen, rlen;

	/* The parser KASSERTs pp_lock: the WITNESS-lite hook must fire. */
	KT_EXPECT_PANIC(sppp_lcp_confreq(sp, (struct lcp_header *)pkt, 8,
	    &buf, &blen, &rlen), "sppp_lcp_confreq");
	SPPP_FX_END;
}

/*
 * RFC 1661 5.1: a Configure-Request with no options asks for all defaults
 * and must be Configure-Ack'd; NetBSD dropped it ('if (origlen <= 0)').
 */
KTEST(lcp_confreq, empty_option_list_acked)
{
	SPPP_FX_BEGIN;
	size_t rlen = 99;
	int t = lcp_req(sp, NULL, 0, NULL, &rlen);

	SPPP_FX_END;
	KT_EQ(t, CP_RCR_ACK);
	KT_EQ(rlen, 0);
}

KTEST(lcp_confreq, short_header_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[3] = { CONF_REQ, 1, 0 };

	KT_EQ(fx_sppp_confreq(sp, FX_IDX_LCP, pkt, 3, NULL, 0, NULL),
	    CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, zero_length_option_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 0, 0x05, 0xd4 };

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, one_length_option_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 1, 0, 0 };

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, zero_length_after_good_option_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0xd4, LCP_OPT_MAGIC, 0 };

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, overlong_option_is_error)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0x11, 0x22 };	/* 2 bytes short */

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_ERR);
	SPPP_FX_END;
}

KTEST(lcp_confreq, trailing_octet_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0xd4, 0x42 };

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, lone_octet_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU };

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, mru_acked_and_recorded)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0xd4 }, out[64];
	size_t rlen;

	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, sizeof(o));
	KT_MEMEQ(out, o, sizeof(o));
	KT_EQ(sp->lcp.their_mru, 1492);
	SPPP_FX_END;
}

KTEST(lcp_confreq, mru_bad_length_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 3, 0x05 }, out[64];
	size_t rlen;

	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 3);
	KT_MEMEQ(out, o, 3);
	SPPP_FX_END;
}

KTEST(lcp_confreq, magic_distinct_acked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0xde, 0xad, 0xbe, 0xef };
	size_t rlen;

	sp->lcp.magic = 0x01020304;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, &rlen), CP_RCR_ACK);
	KT_EQ(sp->pp_loopcnt, 0);
	SPPP_FX_END;
}

KTEST(lcp_confreq, magic_equal_naked_with_negated)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0x01, 0x02, 0x03, 0x04 }, out[64];
	size_t rlen;

	sp->lcp.magic = 0x01020304;
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 6);
	KT_EQ(out[0], LCP_OPT_MAGIC);
	KT_EQ((uint32_t)out[2] << 24 | (uint32_t)out[3] << 16 | out[4] << 8 | out[5],
	    ~0x01020304u);
	KT_EQ(sp->pp_loopcnt, 1);
	SPPP_FX_END;
}

KTEST(lcp_confreq, magic_bad_length_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 4, 0x01, 0x02 };
	size_t rlen;

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 4);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_unconfigured_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 4, 0xc0, 0x23 };
	size_t rlen;

	KT_EQ(sp->myauth.proto, PPP_NOPROTO);
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, &rlen), CP_RCR_REJ);
	KT_EQ(sp->pp_flags & PP_NEEDAUTH, 0);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_pap_acked_sets_needauth)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 4, 0xc0, 0x23 };
	size_t rlen;

	sp->myauth.proto = PPP_PAP;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, &rlen), CP_RCR_ACK);
	KT_NE(sp->pp_flags & PP_NEEDAUTH, 0);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_chap_md5_acked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 5, 0xc2, 0x23, CHAP_MD5 };

	sp->myauth.proto = PPP_CHAP;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_ACK);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_chap_without_algorithm_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 4, 0xc2, 0x23 };

	sp->myauth.proto = PPP_CHAP;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_REJ);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_chap_non_md5_naked_to_md5)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 5, 0xc2, 0x23, 0x80 }, out[16];
	uint8_t want[] = { LCP_OPT_AUTH_PROTO, 5, 0xc2, 0x23, CHAP_MD5 };
	size_t rlen;

	sp->myauth.proto = PPP_CHAP;
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 5);
	KT_MEMEQ(out, want, 5);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_mismatch_naked_with_ours)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 5, 0xc2, 0x23, CHAP_MD5 };
	uint8_t want[] = { LCP_OPT_AUTH_PROTO, 4, 0xc0, 0x23 }, out[16];
	size_t rlen;

	sp->myauth.proto = PPP_PAP;
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 4);
	KT_MEMEQ(out, want, 4);
	SPPP_FX_END;
}

KTEST(lcp_confreq, auth_passive_adopts_peer_choice)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 5, 0xc2, 0x23, CHAP_MD5 };

	sp->myauth.proto = PPP_PAP;
	sp->myauth.flags |= SPPP_AUTHFLAG_PASSIVEAUTHPROTO;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_ACK);
	KT_EQ(sp->myauth.proto, PPP_CHAP);
	SPPP_FX_END;
}

KTEST(lcp_confreq, unknown_options_rejected_alone)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0xd4,
	    LCP_OPT_PROTO_COMP, 2, LCP_OPT_ADDR_COMP, 2,
	    LCP_OPT_MAGIC, 6, 1, 2, 3, 4 };
	uint8_t want[] = { LCP_OPT_PROTO_COMP, 2, LCP_OPT_ADDR_COMP, 2 };
	uint8_t out[64];
	size_t rlen;

	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, sizeof(want));
	KT_MEMEQ(out, want, sizeof(want));
	SPPP_FX_END;
}

/* 64 ACCM options: 384 option bytes, well past a u_char length. */
KTEST(lcp_confreq, large_ack_keeps_full_length)
{
	SPPP_FX_BEGIN;
	uint8_t o[384], out[2048];
	size_t rlen;

	for (size_t i = 0; i < sizeof(o); i += 6) {
		o[i] = LCP_OPT_ASYNC_MAP;
		o[i + 1] = 6;
		memset(&o[i + 2], (int)i, 4);
	}
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, sizeof(o));
	KT_MEMEQ(out, o, sizeof(o));
	SPPP_FX_END;
}

/*
 * Regression for the u_char blen overflow: a 256-octet option list of
 * unknown options must come back as a 256-octet Configure-Reject, not as
 * 256 mod 256 == 0 (an empty REJ) or a truncated copy.
 */
static void
lcp_big_reject(struct sppp *sp, size_t total)
{
	uint8_t o[1600], out[2048];
	size_t rlen, off = 0;

	while (off < total) {
		size_t l = MIN(total - off, 200);

		if (total - off - l == 1)
			l--;		/* never leave a lone trailing octet */
		o[off] = 0x7f;	/* unassigned LCP option type */
		o[off + 1] = (uint8_t)l;
		memset(&o[off + 2], 0xa5, l - 2);
		off += l;
	}
	KT_EQ(lcp_req(sp, o, total, out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, total);
	KT_MEMEQ(out, o, total);
}

KTEST(lcp_confreq, reject_255_octets)
{
	SPPP_FX_BEGIN;
	lcp_big_reject(sp, 255);
	SPPP_FX_END;
}

KTEST(lcp_confreq, reject_256_octets)
{
	SPPP_FX_BEGIN;
	lcp_big_reject(sp, 256);
	SPPP_FX_END;
}

KTEST(lcp_confreq, reject_1400_octets)
{
	SPPP_FX_BEGIN;
	lcp_big_reject(sp, 1400);
	SPPP_FX_END;
}

KTEST(lcp_confreq, max_failure_turns_nak_into_rej)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0x01, 0x02, 0x03, 0x04 };

	sp->lcp.magic = 0x01020304;
	sp->lcp.max_failure = 2;
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_NAK);
	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_REJ);
	SPPP_FX_END;
}

KTEST(lcp_confreq, mp_eid_classes)
{
	SPPP_FX_BEGIN;
	uint8_t ok[] = { LCP_OPT_MP_EID, 3, 0 };		/* null class */
	uint8_t bad[] = { LCP_OPT_MP_EID, 4, 0, 9 };	/* null class, len 4 */
	uint8_t mac[] = { LCP_OPT_MP_EID, 9, 3, 1, 2, 3, 4, 5, 6 };

	KT_EQ(lcp_req(sp, ok, sizeof(ok), NULL, NULL), CP_RCR_ACK);
	KT_EQ(lcp_req(sp, bad, sizeof(bad), NULL, NULL), CP_RCR_REJ);
	KT_EQ(lcp_req(sp, mac, sizeof(mac), NULL, NULL), CP_RCR_ACK);
	SPPP_FX_END;
}

/* ---- Configure-Nak / Configure-Reject from the peer ---- */

static void
lcp_nak(struct sppp *sp, uint8_t code, const void *opts, size_t olen)
{
	uint8_t pkt[2048];
	size_t n = cp_pkt(pkt, code, 1, opts, olen);

	if (code == CONF_NAK)
		fx_sppp_confnak(sp, FX_IDX_LCP, pkt, n);
	else
		fx_sppp_confrej(sp, FX_IDX_LCP, pkt, n);
}

KTEST(lcp_confnak, mru_accepted_in_range)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0x00 };	/* 1280 */

	lcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->lcp.mru, 1280);
	KT_NE(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	SPPP_FX_END;
}

KTEST(lcp_confnak, mru_out_of_range_clamped_to_mtu)
{
	SPPP_FX_BEGIN;
	uint8_t lo[] = { LCP_OPT_MRU, 4, 0x00, 0x10 };	/* 16 < PPP_MINMRU */
	uint8_t hi[] = { LCP_OPT_MRU, 4, 0xff, 0xff };

	lcp_nak(sp, CONF_NAK, lo, sizeof(lo));
	KT_EQ(sp->lcp.mru, ifp->if_mtu);
	sp->lcp.mru = 0;
	lcp_nak(sp, CONF_NAK, hi, sizeof(hi));
	KT_EQ(sp->lcp.mru, ifp->if_mtu);
	SPPP_FX_END;
}

KTEST(lcp_confnak, mru_bad_length_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 3, 0x05 };

	sp->lcp.mru = 777;
	lcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->lcp.mru, 777);
	SPPP_FX_END;
}

KTEST(lcp_confnak, magic_adopted)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0x11, 0x22, 0x33, 0x44 };

	sp->lcp.magic = 0x01020304;
	lcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->lcp.magic, 0x11223344);
	SPPP_FX_END;
}

/*
 * A Nak carrying our own magic negated is the loopback glitch: pick a fresh
 * magic.  lcp.magic is a u_long, so the complement must be cut to 32 bits
 * before comparing it with the wire value on LP64.
 */
KTEST(lcp_confnak, negated_magic_regenerates)
{
	SPPP_FX_BEGIN;
	uint8_t neg[6] = { LCP_OPT_MAGIC, 6 };
	uint32_t m = ~(uint32_t)0x11223344;
	u_long got;

	sp->lcp.magic = 0x11223344;
	neg[2] = m >> 24; neg[3] = m >> 16; neg[4] = m >> 8; neg[5] = m;
	lcp_nak(sp, CONF_NAK, neg, sizeof(neg));
	got = sp->lcp.magic;
	SPPP_FX_END;
	KT_NE(got, m);
}

KTEST(lcp_confnak, overlong_option_stops_parse)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 9, 0x05, 0x00 };

	sp->lcp.mru = 777;
	lcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->lcp.mru, 777);
	SPPP_FX_END;
}

KTEST(lcp_confnak, zero_length_option_terminates)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 0, LCP_OPT_MRU, 4, 0x05, 0x00 };

	sp->lcp.mru = 777;
	lcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->lcp.mru, 777);
	SPPP_FX_END;
}

KTEST(lcp_confnak, header_only_is_noop)
{
	SPPP_FX_BEGIN;
	lcp_nak(sp, CONF_NAK, NULL, 0);
	lcp_nak(sp, CONF_REJ, NULL, 0);
	SPPP_FX_END;
}

KTEST(lcp_confrej, magic_cleared)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0, 0, 0, 1 };

	sp->lcp.magic = 0x01020304;
	lcp_nak(sp, CONF_REJ, o, sizeof(o));
	KT_EQ(sp->lcp.magic, 0);
	KT_EQ(sp->lcp.opts & SPPP_LCP_OPT_MAGIC, 0);
	SPPP_FX_END;
}

KTEST(lcp_confrej, mru_falls_back_to_default)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x05, 0xd4 };

	sp->lcp.mru = 1492;
	SET(sp->lcp.opts, SPPP_LCP_OPT_MRU);
	lcp_nak(sp, CONF_REJ, o, sizeof(o));
	KT_EQ(sp->lcp.mru, PP_MTU);
	KT_EQ(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	KT_LOGGED("peer rejected our MRU");
	SPPP_FX_END;
}

KTEST(lcp_confrej, auth_nocallout_drops_option)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_AUTH_PROTO, 4, 0xc0, 0x23 };

	SET(sp->lcp.opts, SPPP_LCP_OPT_AUTH_PROTO);
	sp->hisauth.flags |= SPPP_AUTHFLAG_NOCALLOUT;
	lcp_nak(sp, CONF_REJ, o, sizeof(o));
	KT_EQ(sp->lcp.opts & SPPP_LCP_OPT_AUTH_PROTO, 0);
	SPPP_FX_END;
}

/* REGRESSION (fz_lcp_confreq, crash-06fa0de8...): pass 2's Auth-Protocol
 * nak arm rewrote `l` (the loop stride) instead of `naklen`, desyncing
 * "len -= l, p += l" and reading past the buffer. Fixed. */
KTEST(lcp_confreq, fuzz_pass2_auth_stride_overread)
{
	SPPP_FX_BEGIN;
	static const uint8_t crash[] = {
		0x01, 0x09, 0xb1, 0x00, 0x03, 0x07, 0x06, 0x82, 0x03, 0x24,
		0x03 };
	int t;

	sp->myauth.proto = PPP_PAP;
	sp->myauth.flags |= SPPP_AUTHFLAG_PASSIVEAUTHPROTO;
	t = fx_sppp_confreq(sp, FX_IDX_LCP, crash, sizeof(crash),
	    NULL, 0, NULL);
	SPPP_FX_END;
	/* No ASan over-read; the auth-proto mismatch is naked normally. */
	KT_EQ(t, CP_RCR_NAK);
}

/* REGRESSION (fz_lcp_confreq, crash-0f6701b6...): pass 1's LCP_OPT_MP_EID
 * debug log read p[2] even when l < 3 (no class octet on the wire). Fixed
 * by only reading p[2] when l >= 3. */
KTEST(lcp_confreq, fuzz_mp_eid_short_option_overread)
{
	SPPP_FX_BEGIN;
	static const uint8_t crash[] = {
		0x01, 0x04, 0x02, 0x00, 0x0e, 0x06, 0x00, 0x00, 0x00, 0xf9,
		0x06, 0x02, 0x13, 0x02 };
	int t;

	ifp->if_flags |= IFF_DEBUG;	/* take the message-printing arm */
	t = fx_sppp_confreq(sp, FX_IDX_LCP, crash, sizeof(crash),
	    NULL, 0, NULL);
	SPPP_FX_END;
	/* No ASan over-read; the malformed option list is rejected. */
	KT_EQ(t, CP_RCR_REJ);
}

/* ------------------------------------------------ per-session LCP defaults */

/*
 * The lower layer coming up starts a new PPPoE session, and each session
 * negotiates from the configured defaults (RFC 1661 section 6: an option
 * not sent is at its default).  What the last session's peer rejected or
 * nak'ed, and its MRU, must not carry over.
 */
#define	LCP_T_LINK_MTU	1492	/* PPPOE_MAXMTU, pppoe0's MTU at clone */

static void
lcp_up_starting(struct sppp *sp)
{
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_STARTING;
	sppp_lcp_up(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
}

static void
lcp_open_starting(struct sppp *sp)
{
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_STARTING;
	sppp_lcp_open(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
}

KTEST(lcp_session, up_resets_negotiated_options)
{
	SPPP_FX_BEGIN;

	/* What a previous session's Reject / Nak / Configure-Request left. */
	sp->lcp.mru = 1300;
	CLR(sp->lcp.opts, SPPP_LCP_OPT_MRU);
	CLR(sp->lcp.opts, SPPP_LCP_OPT_MAGIC);
	sp->lcp.their_mru = 1000;
	lcp_up_starting(sp);
	KT_EQ(sp->lcp.mru, LCP_T_LINK_MTU);
	KT_NE(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	KT_NE(sp->lcp.opts & SPPP_LCP_OPT_MAGIC, 0);
	KT_EQ(sp->lcp.their_mru, PP_MTU);
	kshim_run_tasks();
	SPPP_FX_END;
}

/*
 * RFC 4638 fallback: LCP Open ran while if_mtu was the 1500 asked for, then
 * the PADS fell back to 1492, so the session must offer 1492 rather than
 * leave the MRU at the 1500 default.
 */
KTEST(lcp_session, rfc4638_fallback_offers_link_mru)
{
	SPPP_FX_BEGIN;

	ifp->if_mtu = 1500;
	lcp_open_starting(sp);
	KT_EQ(sp->lcp.mru, PP_MTU);
	ifp->if_mtu = LCP_T_LINK_MTU;		/* the PADS arm's fallback */
	lcp_up_starting(sp);
	KT_EQ(sp->lcp.mru, LCP_T_LINK_MTU);
	KT_NE(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

/* The reverse: a 1492 session, then RFC 4638 granted 1500 on the redial.
 * 1500 is the default, so the MRU option must not stay switched on. */
KTEST(lcp_session, redial_at_1500_drops_stale_mru_option)
{
	SPPP_FX_BEGIN;

	lcp_up_starting(sp);
	KT_NE(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	ifp->if_mtu = 1500;
	lcp_up_starting(sp);
	KT_EQ(sp->lcp.mru, PP_MTU);
	KT_EQ(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(lcp_session, open_drops_stale_mru_option)
{
	SPPP_FX_BEGIN;

	SET(sp->lcp.opts, SPPP_LCP_OPT_MRU);
	sp->lcp.mru = 1400;
	ifp->if_mtu = 1500;
	lcp_open_starting(sp);
	KT_EQ(sp->lcp.mru, PP_MTU);
	KT_EQ(sp->lcp.opts & SPPP_LCP_OPT_MRU, 0);
	SPPP_FX_END;
}

/* ------------------------------------------------------- peer MRU bound */

KTEST(lcp_confreq, mru_below_minimum_naked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x00, 0x40 }, out[64];	/* 64 */
	uint8_t want[] = { LCP_OPT_MRU, 4, PPP_MINMRU >> 8, PPP_MINMRU & 0xff };
	size_t rlen;

	sp->lcp.their_mru = PP_MTU;
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, sizeof(want));
	KT_MEMEQ(out, want, sizeof(want));
	/* A nak'ed value is not in force. */
	KT_EQ(sp->lcp.their_mru, PP_MTU);
	SPPP_FX_END;
}

KTEST(lcp_confreq, mru_zero_naked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, 0x00, 0x00 }, out[64];
	size_t rlen;

	sp->lcp.their_mru = PP_MTU;
	KT_EQ(lcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(sp->lcp.their_mru, PP_MTU);
	SPPP_FX_END;
}

KTEST(lcp_confreq, mru_at_minimum_acked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { LCP_OPT_MRU, 4, PPP_MINMRU >> 8, PPP_MINMRU & 0xff };
	size_t rlen;

	KT_EQ(lcp_req(sp, o, sizeof(o), NULL, &rlen), CP_RCR_ACK);
	KT_EQ(sp->lcp.their_mru, PPP_MINMRU);
	SPPP_FX_END;
}

/* ------------------------------------------------- the one if_mtu writer */

static int
lcp_set_mtu(struct ifnet *ifp, int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	return (ifp->if_ioctl(ifp, SIOCSIFMTU, (caddr_t)&ifr));
}

static void
lcp_tlu_tld(struct sppp *sp, bool up)
{
	SPPP_LOCK(sp, RW_WRITER);
	if (up)
		sppp_lcp_tlu(sp);
	else
		sppp_lcp_tld(sp);
	SPPP_UNLOCK(sp);
	kshim_run_tasks();
}

/* LCP down restores the link MTU in force now, not a copy saved at LCP up
 * that an MTU change during the session has made stale. */
KTEST(lcp_mtu, down_restores_current_link_mtu)
{
	SPPP_FX_BEGIN;

	KT_EQ(ifp->if_mtu, LCP_T_LINK_MTU);
	sp->lcp.their_mru = 1400;
	lcp_tlu_tld(sp, true);
	KT_EQ(ifp->if_mtu, 1400);
	KT_EQ(lcp_set_mtu(ifp, 1300), 0);
	KT_EQ(ifp->if_mtu, 1300);
	lcp_tlu_tld(sp, false);
	KT_EQ(ifp->if_mtu, 1300);
	SPPP_FX_END;
}

/* SIOCSIFMTU mid-session cannot lift if_mtu past what the peer can take. */
KTEST(lcp_mtu, admin_mtu_capped_by_peer_mru)
{
	SPPP_FX_BEGIN;

	KT_EQ(lcp_set_mtu(ifp, 1400), 0);
	sp->lcp.their_mru = 1450;
	lcp_tlu_tld(sp, true);
	KT_EQ(ifp->if_mtu, 1400);
	KT_EQ(lcp_set_mtu(ifp, LCP_T_LINK_MTU), 0);
	KT_EQ(ifp->if_mtu, 1450);
	lcp_tlu_tld(sp, false);
	KT_EQ(ifp->if_mtu, LCP_T_LINK_MTU);
	SPPP_FX_END;
}

/* Every change the writer makes is announced to the routing layer. */
KTEST(lcp_mtu, change_is_notified)
{
	SPPP_FX_BEGIN;
	int n;

	n = kshim_notifymtu_calls;
	sp->lcp.their_mru = 1400;
	lcp_tlu_tld(sp, true);
	KT_EQ(kshim_notifymtu_calls, n + 1);
	lcp_tlu_tld(sp, false);
	KT_EQ(kshim_notifymtu_calls, n + 2);
	/* No change, no notification. */
	lcp_tlu_tld(sp, false);
	KT_EQ(kshim_notifymtu_calls, n + 2);
	SPPP_FX_END;
}
