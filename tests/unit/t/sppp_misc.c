/* sppp logging helpers and shim self-checks -- sys/net/if_spppsubr.c */

/* The pre-53c0707 --len wrapped a zero length into a 64 KiB read. */
KTEST(sppp_print_bytes, zero_length_reads_nothing)
{
	SPPP_FX_BEGIN;
	/* A 1-byte heap block: any read past it is an ASan report. */
	u_char *p = kshim_malloc(1, M_TEMP, M_WAITOK);

	p[0] = 0xab;
	sppp_log(sp, LOG_DEBUG, "bytes:");
	sppp_print_bytes(p + 1, 0);
	addlog("\n");
	KT_LOGGED("bytes:\n");
	KT_NOT_LOGGED("ab");
	sppp_log(sp, LOG_DEBUG, "one:");
	sppp_print_bytes(p, 1);
	addlog("\n");
	KT_LOGGED("one: ab");
	kshim_free(p, M_TEMP);
	SPPP_FX_END;
}

KTEST(sppp_print_bytes, mp_eid_null_class_debug)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[16];
	uint8_t o[] = { LCP_OPT_MP_EID, 3, 0 };	/* l - 3 == 0 bytes */
	size_t n = cp_pkt(pkt, CONF_REQ, 1, o, sizeof(o));

	ifp->if_flags |= IFF_DEBUG;
	KT_EQ(fx_sppp_confreq(sp, FX_IDX_LCP, pkt, n, NULL, 0, NULL),
	    CP_RCR_ACK);
	SPPP_FX_END;
}

KTEST(sppp_log, records_are_whole_lines)
{
	SPPP_FX_BEGIN;
	int pri;

	char want[64];

	kshim_log_clear();
	sppp_log(sp, LOG_INFO, "part1");
	addlog(" part2");
	addlog(" part3\n");
	snprintf(want, sizeof(want), "%s: part1 part2 part3\n", ifp->if_xname);
	KT_EQ(kshim_log_count(), 1);
	KT_STREQ(kshim_log_get(0, &pri), want);
	KT_EQ(pri, LOG_INFO);
	SPPP_FX_END;
}

KTEST(sppp_proto_name, unknown_protocol_fits_buffer)
{
	char buf[SPPP_PROTO_NAMELEN];

	KT_STREQ(sppp_proto_name(buf, sizeof(buf), PPP_LCP), "lcp");
	KT_STREQ(sppp_proto_name(buf, sizeof(buf), 0xffff), "0xffff");
}

KTEST(kshim, md5_rfc1321_vectors)
{
	static const struct { const char *in, *hex; } v[] = {
		{ "", "d41d8cd98f00b204e9800998ecf8427e" },
		{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
		{ "12345678901234567890123456789012345678901234567890123456789"
		  "012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a" },
	};
	for (size_t i = 0; i < nitems(v); i++) {
		unsigned char d[16];
		char hex[33];
		MD5_CTX c;

		MD5Init(&c);
		MD5Update(&c, v[i].in, strlen(v[i].in));
		MD5Final(d, &c);
		for (int j = 0; j < 16; j++)
			snprintf(hex + 2 * j, 3, "%02x", d[j]);
		KT_STREQ(hex, v[i].hex);
	}
}

KTEST(kshim, witness_catches_recursion_and_unowned_unlock)
{
	struct mtx m;

	mtx_init(&m, "t", NULL, MTX_DEF);
	mtx_lock(&m);
	KT_EXPECT_PANIC(mtx_lock(&m), "recursed");
	mtx_init(&m, "t", NULL, MTX_DEF);
	KT_EXPECT_PANIC(mtx_unlock(&m), "unowned");
	KT_EXPECT_PANIC(mtx_assert(&m, MA_OWNED), "not owned");
}
