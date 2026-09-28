/* sppp_ipcp_confreq() / _confnak() / _confrej() -- sys/net/if_spppsubr.c */

static int
ipcp_req(struct sppp *sp, const void *opts, size_t olen, uint8_t *out,
    size_t *outlen)
{
	uint8_t pkt[2048];
	size_t n = cp_pkt(pkt, CONF_REQ, 1, opts, olen);

	return (fx_sppp_confreq(sp, FX_IDX_IPCP, pkt, n, out, 2048, outlen));
}

KTEST(ipcp_confreq, empty_request_naks_for_address)
{
	SPPP_FX_BEGIN;
	uint8_t out[16];
	uint8_t want[] = { IPCP_OPT_ADDRESS, 6, 0, 0, 0, 0 };
	size_t rlen;

	/* No address seen yet: NAK asking for one (blen >= 6 by design). */
	KT_EQ(ipcp_req(sp, NULL, 0, out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 6);
	KT_MEMEQ(out, want, 6);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, short_header_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[3] = { CONF_REQ, 1, 0 };

	KT_EQ(fx_sppp_confreq(sp, FX_IDX_IPCP, pkt, 3, NULL, 0, NULL),
	    CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, zero_and_one_length_options_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t z[] = { IPCP_OPT_ADDRESS, 0, 10, 0, 0, 1 };
	uint8_t o[] = { IPCP_OPT_ADDRESS, 1, 10, 0, 0, 1 };

	KT_EQ(ipcp_req(sp, z, sizeof(z), NULL, NULL), CP_RCR_DROP);
	KT_EQ(ipcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, overlong_option_is_error)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 10, 0 };

	KT_EQ(ipcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_ERR);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, trailing_octet_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 10, 0, 0, 1, 0x00 };

	KT_EQ(ipcp_req(sp, o, sizeof(o), NULL, NULL), CP_RCR_DROP);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, address_bad_length_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 4, 10, 0 }, out[16];
	size_t rlen;

	KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 4);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, unknown_options_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_COMPRESSION, 6, 0, 0x2d, 15, 1,
	    IPCP_OPT_ADDRESS, 6, 10, 0, 0, 1,
	    IPCP_OPT_PRIMDNS, 6, 0, 0, 0, 0 };
	uint8_t want[] = { IPCP_OPT_COMPRESSION, 6, 0, 0x2d, 15, 1,
	    IPCP_OPT_PRIMDNS, 6, 0, 0, 0, 0 };
	uint8_t out[64];
	size_t rlen;

	KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, sizeof(want));
	KT_MEMEQ(out, want, sizeof(want));
	SPPP_FX_END;
}

KTEST(ipcp_confreq, dynamic_peer_address_acked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 10, 0, 0, 1 }, out[16];
	size_t rlen;

	sp->ipcp.flags |= IPCP_HISADDR_DYN;
	KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, 6);
	KT_MEMEQ(out, o, 6);
	KT_NE(sp->ipcp.flags & IPCP_HISADDR_SEEN, 0);
	KT_EQ(sp->ipcp.req_hisaddr, 0x0a000001);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, zero_address_naked_with_ours)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 0, 0, 0, 0 }, out[16];
	uint8_t want[] = { IPCP_OPT_ADDRESS, 6, 192, 0, 2, 9 };
	size_t rlen;

	sp->ipcp.flags |= IPCP_HISADDR_SEEN | IPCP_HISADDR_DYN;
	sp->ipcp.req_hisaddr = 0xc0000209;
	KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
	KT_EQ(rlen, 6);
	KT_MEMEQ(out, want, 6);
	SPPP_FX_END;
}

static void
ipcp_big_reject(struct sppp *sp, size_t total)
{
	uint8_t o[1600], out[2048];
	size_t rlen, off = 0;

	while (off < total) {
		size_t l = MIN(total - off, 250);

		if (total - off - l == 1)
			l--;
		o[off] = 0x42;		/* unassigned IPCP option type */
		o[off + 1] = (uint8_t)l;
		memset(&o[off + 2], 0x5a, l - 2);
		off += l;
	}
	KT_EQ(ipcp_req(sp, o, total, out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, total);
	KT_MEMEQ(out, o, total);
}

KTEST(ipcp_confreq, reject_255_octets)
{
	SPPP_FX_BEGIN;
	ipcp_big_reject(sp, 255);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, reject_256_octets)
{
	SPPP_FX_BEGIN;
	ipcp_big_reject(sp, 256);
	SPPP_FX_END;
}

KTEST(ipcp_confreq, reject_1000_octets)
{
	SPPP_FX_BEGIN;
	ipcp_big_reject(sp, 1000);
	SPPP_FX_END;
}

static void
ipcp_nak(struct sppp *sp, uint8_t code, const void *opts, size_t olen)
{
	uint8_t pkt[2048];
	size_t n = cp_pkt(pkt, code, 1, opts, olen);

	if (code == CONF_NAK)
		fx_sppp_confnak(sp, FX_IDX_IPCP, pkt, n);
	else
		fx_sppp_confrej(sp, FX_IDX_IPCP, pkt, n);
}

KTEST(ipcp_confnak, dynamic_address_adopted)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 100, 64, 0, 7 };

	sp->ipcp.flags |= IPCP_MYADDR_DYN;
	ipcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_NE(sp->ipcp.flags & IPCP_MYADDR_SEEN, 0);
	KT_EQ(sp->ipcp.req_myaddr, 0x64400007);
	SPPP_FX_END;
}

KTEST(ipcp_confnak, zero_address_not_adopted)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 0, 0, 0, 0 };

	sp->ipcp.flags |= IPCP_MYADDR_DYN;
	ipcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->ipcp.flags & IPCP_MYADDR_SEEN, 0);
	SPPP_FX_END;
}

KTEST(ipcp_confnak, dns_recorded_only_when_asked)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_PRIMDNS, 6, 9, 9, 9, 9,
	    IPCP_OPT_SECDNS, 6, 1, 1, 1, 1 };

	ipcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->dns_addrs[0], 0);
	SET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS | SPPP_IPCP_OPT_SECDNS);
	ipcp_nak(sp, CONF_NAK, o, sizeof(o));
	KT_EQ(sp->dns_addrs[0], 0x09090909);
	KT_EQ(sp->dns_addrs[1], 0x01010101);
	SPPP_FX_END;
}

KTEST(ipcp_confnak, bad_lengths_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t shortopt[] = { IPCP_OPT_PRIMDNS, 5, 9, 9, 9 };
	uint8_t over[] = { IPCP_OPT_ADDRESS, 12, 1, 2 };
	uint8_t hdr[2] = { CONF_NAK, 1 };

	SET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS);
	sp->ipcp.flags |= IPCP_MYADDR_DYN;
	ipcp_nak(sp, CONF_NAK, shortopt, sizeof(shortopt));
	ipcp_nak(sp, CONF_NAK, over, sizeof(over));
	/* Shorter than a CP header: len - 4 < 0 must not walk. */
	fx_sppp_confnak(sp, FX_IDX_IPCP, hdr, sizeof(hdr));
	KT_EQ(sp->dns_addrs[0], 0);
	KT_EQ(sp->ipcp.flags & IPCP_MYADDR_SEEN, 0);
	SPPP_FX_END;
}

KTEST(ipcp_confrej, options_cleared)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_PRIMDNS, 6, 0, 0, 0, 0,
	    IPCP_OPT_SECDNS, 6, 0, 0, 0, 0, IPCP_OPT_ADDRESS, 6, 0, 0, 0, 0 };

	SET(sp->ipcp.opts, SPPP_IPCP_OPT_PRIMDNS | SPPP_IPCP_OPT_SECDNS |
	    SPPP_IPCP_OPT_ADDRESS);
	ipcp_nak(sp, CONF_REJ, o, sizeof(o));
	KT_EQ(sp->ipcp.opts & (SPPP_IPCP_OPT_PRIMDNS | SPPP_IPCP_OPT_SECDNS |
	    SPPP_IPCP_OPT_ADDRESS), 0);
	SPPP_FX_END;
}

/* REGRESSION (fz_ipcp_confreq, crash-1e2e511c...): the IPCP address,
 * wantaddr and DNS options built "p[2] << 24" on a signed int, undefined
 * for a peer octet >= 0x80. Now cast to (uint32_t) first, as LCP does. */
KTEST(ipcp_confreq, fuzz_address_signed_shift_ub)
{
	SPPP_FX_BEGIN;
	static const uint8_t crash[] = {
		0x01, 0x01, 0x00, 0x0a, 0x03, 0x06, 0x80, 0x00, 0x00, 0x00 };
	int t;

	sp->ipcp.flags |= IPCP_HISADDR_DYN;
	t = fx_sppp_confreq(sp, FX_IDX_IPCP, crash, sizeof(crash),
	    NULL, 0, NULL);
	SPPP_FX_END;
	/* No UBSan signed-shift trap; the high-half address is accepted. */
	KT_EQ(t, CP_RCR_ACK);
}

/* ---- RFC 1661 Max-Failure (default 5) ---- */

/* A peer that keeps asking for an address we won't agree to gets
 * max_failure NAKs, then a Configure-Reject of its option as sent. */
KTEST(ipcp_confreq, max_failure_turns_nak_into_rej)
{
	SPPP_FX_BEGIN;
	uint8_t o[] = { IPCP_OPT_ADDRESS, 6, 10, 0, 0, 1 }, out[16];
	uint8_t nak[] = { IPCP_OPT_ADDRESS, 6, 192, 0, 2, 9 };
	size_t rlen;
	int i;

	KT_EQ(sp->ipcp.max_failure, 5);
	sp->ipcp.flags |= IPCP_HISADDR_SEEN;
	sp->ipcp.req_hisaddr = 0xc0000209;
	for (i = 0; i < 5; i++) {
		KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_NAK);
		KT_EQ(rlen, 6);
		KT_MEMEQ(out, nak, 6);
	}
	KT_EQ(ipcp_req(sp, o, sizeof(o), out, &rlen), CP_RCR_REJ);
	KT_EQ(rlen, 6);
	KT_MEMEQ(out, o, 6);
	SPPP_FX_END;
}

/* The "still need hisaddr" NAK hints an option the peer never sent;
 * there is nothing to reject, so after max_failure we stop hinting. */
KTEST(ipcp_confreq, max_failure_stops_hisaddr_hint)
{
	SPPP_FX_BEGIN;
	size_t rlen;
	int i;

	for (i = 0; i < 5; i++)
		KT_EQ(ipcp_req(sp, NULL, 0, NULL, &rlen), CP_RCR_NAK);
	KT_EQ(ipcp_req(sp, NULL, 0, NULL, &rlen), CP_RCR_ACK);
	KT_EQ(rlen, 0);
	SPPP_FX_END;
}

/* Max-Failure counts NAKs sent without an ACK: an ACK restarts it. */
KTEST(ipcp_confreq, ack_resets_max_failure)
{
	SPPP_FX_BEGIN;
	uint8_t bad[] = { IPCP_OPT_ADDRESS, 6, 10, 0, 0, 1 };
	uint8_t good[] = { IPCP_OPT_ADDRESS, 6, 192, 0, 2, 9 };
	int i;

	sp->ipcp.flags |= IPCP_HISADDR_SEEN;
	sp->ipcp.req_hisaddr = 0xc0000209;
	for (i = 0; i < 4; i++)
		KT_EQ(ipcp_req(sp, bad, sizeof(bad), NULL, NULL), CP_RCR_NAK);
	KT_EQ(ipcp_req(sp, good, sizeof(good), NULL, NULL), CP_RCR_ACK);
	for (i = 0; i < 5; i++)
		KT_EQ(ipcp_req(sp, bad, sizeof(bad), NULL, NULL), CP_RCR_NAK);
	KT_EQ(ipcp_req(sp, bad, sizeof(bad), NULL, NULL), CP_RCR_REJ);
	SPPP_FX_END;
}

/* ---- redial: sppp_ipcp_open() / _scr() / _tlu() / _tld() ---- */

struct ipcp_ifa {
	struct ifaddr		ifa;
	struct sockaddr_in	addr, dst, mask;
};

/* An AF_INET ifaddr on pppoe0, as ifconfig (or the address task) left it. */
static void
ipcp_ifa_set(struct ifnet *ifp, struct ipcp_ifa *a, uint32_t local,
    uint32_t remote)
{
	memset(a, 0, sizeof(*a));
	a->addr.sin_len = sizeof(a->addr);
	a->addr.sin_family = AF_INET;
	a->dst = a->mask = a->addr;
	a->addr.sin_addr.s_addr = htonl(local);
	a->dst.sin_addr.s_addr = htonl(remote);
	a->mask.sin_addr.s_addr = 0xffffffff;
	a->ifa.ifa_addr = (struct sockaddr *)&a->addr;
	a->ifa.ifa_dstaddr = (struct sockaddr *)&a->dst;
	a->ifa.ifa_netmask = (struct sockaddr *)&a->mask;
	a->ifa.ifa_ifp = ifp;
	CK_STAILQ_INIT(&ifp->if_addrhead);
	CK_STAILQ_INSERT_TAIL(&ifp->if_addrhead, &a->ifa, ifa_link);
}

/* Open IPCP from Closed and return the address our ConfReq asked for. */
static uint32_t
ipcp_open_req_addr(struct sppp *sp, struct ifnet *ifp)
{
	uint8_t buf[64];
	uint16_t proto;
	int len;

	kshim_tx_flush(ifp);
	SPPP_LOCK(sp, RW_WRITER);
	SET(sp->pp_ncpflags, SPPP_NCP_IPCP);
	sp->scp[IDX_IPCP].state = STATE_CLOSED;
	sppp_ipcp_open(sp, __DECONST(void *, &ipcp));
	SPPP_UNLOCK(sp);
	len = cp_tx_pop(ifp, &proto, buf, sizeof(buf));
	KT_EQ(proto, PPP_IPCP);
	KT_EQ(buf[0], CONF_REQ);
	KT_ASSERT(len >= 10);
	KT_EQ(buf[4], IPCP_OPT_ADDRESS);
	return ((uint32_t)buf[6] << 24 | buf[7] << 16 | buf[8] << 8 | buf[9]);
}

static void
ipcp_session_up_down(struct sppp *sp)
{
	SPPP_LOCK(sp, RW_WRITER);
	sppp_ipcp_tlu(sp);
	sppp_ipcp_tld(sp);
	SPPP_UNLOCK(sp);
	kshim_run_tasks();
}

/* A dynamic redial asks for 0.0.0.0, not the previous session's address
 * that the asynchronous clear may not have removed yet. */
KTEST(ipcp_open, redial_does_not_rerequest_stale_address)
{
	SPPP_FX_BEGIN;
	uint8_t nak[] = { IPCP_OPT_ADDRESS, 6, 100, 64, 0, 7 };
	uint8_t pkt[16];
	struct ipcp_ifa a;

	KT_EQ(ipcp_open_req_addr(sp, ifp), 0);
	fx_sppp_confnak(sp, FX_IDX_IPCP, pkt,
	    cp_pkt(pkt, CONF_NAK, 1, nak, sizeof(nak)));
	ipcp_session_up_down(sp);
	/* The session's address is still applied at the redial. */
	ipcp_ifa_set(ifp, &a, 0x64400007, 0x0a000001);
	KT_EQ(ipcp_open_req_addr(sp, ifp), 0);
	KT_NE(sp->ipcp.flags & IPCP_MYADDR_DYN, 0);
	KT_NE(sp->ipcp.flags & IPCP_HISADDR_DYN, 0);
	CK_STAILQ_INIT(&ifp->if_addrhead);
	SPPP_FX_END;
}

/* Static local address, dynamic remote (the 0.0.0.1 convention): every
 * redial re-requests the static address, and the peer's ACK of it brings
 * IPCP up instead of closing it for want of a NAKed address. */
KTEST(ipcp_open, static_address_ack_on_redial_opens_ipcp)
{
	SPPP_FX_BEGIN;
	struct ipcp_ifa a;
	int i;

	ipcp_ifa_set(ifp, &a, 0xc0000201, 0x00000001);
	SET(sp->ipcp.opts, SPPP_IPCP_OPT_ADDRESS);
	for (i = 0; i < 2; i++) {
		KT_EQ(ipcp_open_req_addr(sp, ifp), 0xc0000201);
		KT_EQ(sp->ipcp.flags & IPCP_MYADDR_DYN, 0);
		KT_NE(sp->ipcp.flags & IPCP_HISADDR_DYN, 0);
		/* The peer ACKs our address; tlu must record, not close. */
		sp->pp_want_local = 0;
		SPPP_LOCK(sp, RW_WRITER);
		sppp_ipcp_tlu(sp);
		KT_EQ(sp->pp_want_local, 0xc0000201);
		sppp_ipcp_tld(sp);
		SPPP_UNLOCK(sp);
		kshim_run_tasks();
		/* tld leaves the static local address alone. */
		KT_EQ(sp->pp_want_local, 0xc0000201);
	}
	CK_STAILQ_INIT(&ifp->if_addrhead);
	SPPP_FX_END;
}

/* Each IPCP open starts a fresh Max-Failure count. */
KTEST(ipcp_open, open_resets_max_failure)
{
	SPPP_FX_BEGIN;

	sp->scp[IDX_IPCP].fail_counter = 5;
	(void)ipcp_open_req_addr(sp, ifp);
	KT_EQ(sp->scp[IDX_IPCP].fail_counter, 0);
	SPPP_FX_END;
}
