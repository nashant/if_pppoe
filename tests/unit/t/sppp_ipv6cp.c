/* sppp_ipv6cp_confreq() / _confnak() / _confrej() -- sys/net/if_spppsubr.c */

static const uint8_t v6_mine[8] = { 0x00, 0x00, 0x00, 0xff, 0xfe, 0, 0, 1 };

static int
v6_req(struct sppp *sp, const void *opts, size_t olen, uint8_t *out,
    size_t *outlen)
{
	uint8_t pkt[2048];
	size_t n = cp_pkt(pkt, CONF_REQ, 1, opts, olen);

	return (fx_sppp_confreq(sp, FX_IDX_IPV6CP, pkt, n, out, 2048,
	    outlen));
}

static void
v6_ifid_opt(uint8_t o[10], const uint8_t ifid[8])
{
	o[0] = IPV6CP_OPT_IFID;
	o[1] = 10;
	memcpy(&o[2], ifid, 8);
}

KTEST(ipv6cp_confreq, distinct_ifid_acked)
{
	SPPP_FX_BEGIN;
	uint8_t his[8] = { 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55 };
	uint8_t o[10], out[16];
	size_t rlen;

	memcpy(sp->ipv6cp.my_ifid, v6_mine, 8);
	v6_ifid_opt(o, his);
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, 10);
	KT_MEMEQ(out, o, 10);
	KT_MEMEQ(sp->ipv6cp.his_ifid, his, 8);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, colliding_ifid_naked)
{
	SPPP_FX_BEGIN;
	uint8_t o[10], out[16];
	size_t rlen;

	memcpy(sp->ipv6cp.my_ifid, v6_mine, 8);
	v6_ifid_opt(o, v6_mine);
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 10);
	KT_EQ(out[0], IPV6CP_OPT_IFID);
	KT_ASSERT(memcmp(&out[2], v6_mine, 8) != 0);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, zero_ifid_naked_with_suggestion)
{
	SPPP_FX_BEGIN;
	uint8_t zero[8] = { 0 }, o[10], out[16];
	size_t rlen;

	memcpy(sp->ipv6cp.my_ifid, v6_mine, 8);
	v6_ifid_opt(o, zero);
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 10);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, zero_ifid_both_sides_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t zero[8] = { 0 }, o[10], out[16];
	size_t rlen;

	v6_ifid_opt(o, zero);	/* my_ifid is zero too: collision + unknown */
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 10);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, second_ifid_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, o[20], out[32];
	size_t rlen;

	v6_ifid_opt(o, a);
	v6_ifid_opt(o + 10, a);
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 10);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, malformed_options)
{
	SPPP_FX_BEGIN;
	uint8_t shortid[] = { IPV6CP_OPT_IFID, 8, 1, 2, 3, 4, 5, 6 };
	uint8_t zero[] = { IPV6CP_OPT_IFID, 0, 1, 2 };
	uint8_t one[] = { IPV6CP_OPT_IFID, 1, 1, 2 };
	uint8_t over[] = { IPV6CP_OPT_IFID, 10, 1, 2 };
	uint8_t trail[] = { IPV6CP_OPT_COMPRESSION, 4, 0, 0x4f, 7 };
	uint8_t comp[] = { IPV6CP_OPT_COMPRESSION, 4, 0, 0x4f };

	KT_EQ(v6_req(sp, shortid, sizeof(shortid), NULL, NULL), CP_RCR_REJ);
	KT_EQ(v6_req(sp, zero, sizeof(zero), NULL, NULL), CP_RCR_DROP);
	KT_EQ(v6_req(sp, one, sizeof(one), NULL, NULL), CP_RCR_DROP);
	KT_EQ(v6_req(sp, over, sizeof(over), NULL, NULL), CP_RCR_ERR);
	KT_EQ(v6_req(sp, trail, sizeof(trail), NULL, NULL), CP_RCR_DROP);
	KT_EQ(v6_req(sp, comp, sizeof(comp), NULL, NULL), CP_RCR_REJ);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, empty_request_acked)
{
	SPPP_FX_BEGIN;
	size_t rlen = 99;

	KT_EQ(v6_req(sp, NULL, 0, NULL, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, 0);
	SPPP_FX_END;
}

KTEST(ipv6cp_confreq, reject_256_and_1000_octets)
{
	SPPP_FX_BEGIN;
	static const size_t sizes[] = { 255, 256, 1000 };
	uint8_t o[1600], out[2048];

	for (size_t s = 0; s < nitems(sizes); s++) {
		size_t total = sizes[s], off = 0, rlen;

		while (off < total) {
			size_t l = MIN(total - off, 250);

			if (total - off - l == 1)
				l--;
			o[off] = 0x33;
			o[off + 1] = (uint8_t)l;
			memset(&o[off + 2], 0x11, l - 2);
			off += l;
		}
		KT_EQ(v6_req(sp, o, total, out, &rlen), CP_RCR_REJ);
		KT_EQ(rlen, total);
		KT_MEMEQ(out, o, total);
	}
	SPPP_FX_END;
}

KTEST(ipv6cp_confnak, ifid_suggestion_sets_option)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[32], o[10], s[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
	uint8_t bad[] = { IPV6CP_OPT_IFID, 8, 1, 2, 3, 4, 5, 6 };
	size_t n;

	n = cp_pkt(pkt, CONF_NAK, 1, bad, sizeof(bad));
	fx_sppp_confnak(sp, FX_IDX_IPV6CP, pkt, n);
	KT_EQ(sp->ipv6cp.opts & SPPP_IPV6CP_OPT_IFID, 0);
	v6_ifid_opt(o, s);
	n = cp_pkt(pkt, CONF_NAK, 1, o, sizeof(o));
	fx_sppp_confnak(sp, FX_IDX_IPV6CP, pkt, n);
	KT_NE(sp->ipv6cp.opts & SPPP_IPV6CP_OPT_IFID, 0);
	SPPP_FX_END;
}

KTEST(ipv6cp_confrej, ifid_cleared)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[32], o[10], s[8] = { 1 };
	size_t n;

	SET(sp->ipv6cp.opts, SPPP_IPV6CP_OPT_IFID);
	v6_ifid_opt(o, s);
	n = cp_pkt(pkt, CONF_REJ, 1, o, sizeof(o));
	fx_sppp_confrej(sp, FX_IDX_IPV6CP, pkt, n);
	KT_EQ(sp->ipv6cp.opts & SPPP_IPV6CP_OPT_IFID, 0);
	SPPP_FX_END;
}

/* RFC 1661 Max-Failure: a peer that keeps sending our interface-id gets
 * max_failure NAKs, then a Configure-Reject of its option as sent. */
KTEST(ipv6cp_confreq, max_failure_turns_nak_into_rej)
{
	SPPP_FX_BEGIN;
	uint8_t o[10], out[16];
	size_t rlen;
	int i;

	KT_EQ(sp->ipv6cp.max_failure, 5);
	memcpy(sp->ipv6cp.my_ifid, v6_mine, 8);
	v6_ifid_opt(o, v6_mine);
	for (i = 0; i < 5; i++)
		KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(v6_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 10);
	KT_MEMEQ(out, o, 10);
	SPPP_FX_END;
}
