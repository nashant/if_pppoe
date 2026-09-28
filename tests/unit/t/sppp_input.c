/* sppp_input() dispatch and sppp_cp_input() -- sys/net/if_spppsubr.c */

#define	TX_EXPECT(proto_, code_, buf, len)	do {			\
	uint16_t _p;							\
	(len) = cp_tx_pop(ifp, &_p, (buf), sizeof(buf));		\
	KT_ASSERT((len) >= 4);						\
	KT_EQ(_p, (proto_));						\
	KT_EQ((buf)[0], (code_));					\
} while (0)

/*
 * NetBSD's default arm jumped to reject_protocol without pp_lock, whose
 * SPPP_KASSERT(SPPP_WLOCKED(sp)) is a remote panic on any unknown protocol
 * (fixed in 53c0707).  The kshim KASSERT is live, so a regression fails here.
 */
KTEST(sppp_input, unknown_protocol_rejected_with_lock)
{
	SPPP_FX_BEGIN;
	uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef }, buf[256];
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	fx_sppp_input(sp, 0x4321, payload, sizeof(payload));
	KT_EQ(kshim_locks_held(), 0);
	TX_EXPECT(PPP_LCP, PROTO_REJ, buf, len);
	/* RFC 1661 5.7: Rejected-Protocol, then the Rejected-Information. */
	KT_EQ(len, 4 + 2 + (int)sizeof(payload));
	KT_EQ(buf[4], 0x43);
	KT_EQ(buf[5], 0x21);
	KT_MEMEQ(&buf[6], payload, sizeof(payload));
	KT_EQ(if_getcounter(ifp, IFCOUNTER_NOPROTO), 1);
	SPPP_FX_END;
}

KTEST(sppp_input, unknown_protocol_lcp_closed_silent)
{
	SPPP_FX_BEGIN;
	uint8_t payload[] = { 1, 2, 3 }, buf[64];
	uint16_t p;

	fx_sppp_input(sp, 0x4321, payload, sizeof(payload));
	KT_EQ(cp_tx_pop(ifp, &p, buf, sizeof(buf)), -1);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_NOPROTO), 1);
	SPPP_FX_END;
}

KTEST(sppp_input, disabled_ncp_protocol_rejected)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[16], buf[64];
	size_t n = cp_pkt(pkt, CONF_REQ, 7, NULL, 0);
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	CLR(sp->pp_ncpflags, SPPP_NCP_IPCP);
	fx_sppp_input(sp, PPP_IPCP, pkt, n);
	TX_EXPECT(PPP_LCP, PROTO_REJ, buf, len);
	KT_EQ(buf[4] << 8 | buf[5], PPP_IPCP);
	SPPP_FX_END;
}

KTEST(sppp_input, runt_counted_as_error)
{
	SPPP_FX_BEGIN;
	uint8_t two[2] = { CONF_REQ, 1 };

	/* With PP_DEVF_NOFRAMING: 2-byte protocol + 2 bytes <= 4. */
	fx_sppp_input(sp, PPP_LCP, two, sizeof(two));
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 1);
	SPPP_FX_END;
}

KTEST(sppp_input, cp_header_shorter_than_4_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t three[3] = { CONF_REQ, 1, 0 };
	uint16_t p;
	uint8_t buf[64];

	fx_sppp_input(sp, PPP_LCP, three, sizeof(three));
	KT_EQ(cp_tx_pop(ifp, &p, buf, sizeof(buf)), -1);
	KT_EQ(sp->scp[IDX_LCP].mbuf_confreq, NULL);
	SPPP_FX_END;
}

KTEST(sppp_input, length_field_below_header_ignored)
{
	SPPP_FX_BEGIN;
	/* h->len == 2 clamps len below the 4-byte CP header. */
	uint8_t pkt[] = { CONF_REQ, 1, 0, 2, LCP_OPT_MRU, 4, 5, 0xd4 };

	fx_sppp_input(sp, PPP_LCP, pkt, sizeof(pkt));
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 1);
	SPPP_FX_END;
}

KTEST(sppp_input, proto_rej_shorter_than_6_counted)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8];
	size_t n = cp_pkt(pkt, PROTO_REJ, 1, "\x80", 1);	/* 5 octets */

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 1);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_OPENED);
	SPPP_FX_END;
}

KTEST(sppp_input, proto_rej_of_ipcp_in_req_sent_closes_it)
{
	SPPP_FX_BEGIN;
	uint8_t rej[] = { 0x80, 0x21 }, pkt[8];
	size_t n = cp_pkt(pkt, PROTO_REJ, 1, rej, sizeof(rej));

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_IPCP].state = STATE_REQ_SENT;
	SPPP_UNLOCK(sp);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	KT_EQ(sp->scp[IDX_IPCP].state, STATE_CLOSING);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 0);
	SPPP_FX_END;
}

KTEST(sppp_input, echo_request_answered_with_our_magic)
{
	SPPP_FX_BEGIN;
	uint8_t data[] = { 0x11, 0x22, 0x33, 0x44, 'h', 'i' }, pkt[16], buf[64];
	size_t n = cp_pkt(pkt, ECHO_REQ, 9, data, sizeof(data));
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	sp->lcp.magic = 0xa1b2c3d4;
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, ECHO_REPLY, buf, len);
	KT_EQ(len, (int)n);
	KT_EQ(buf[1], 9);
	KT_EQ(buf[4], 0xa1);
	KT_EQ(buf[7], 0xd4);
	KT_MEMEQ(&buf[8], "hi", 2);
	SPPP_FX_END;
}

KTEST(sppp_input, echo_request_short_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8], buf[64];
	size_t n = cp_pkt(pkt, ECHO_REQ, 9, "\x01\x02\x03", 3);
	uint16_t p;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	KT_EQ(cp_tx_pop(ifp, &p, buf, sizeof(buf)), -1);
	SPPP_FX_END;
}

KTEST(sppp_input, echo_request_own_magic_is_loopback)
{
	SPPP_FX_BEGIN;
	uint8_t data[] = { 0xa1, 0xb2, 0xc3, 0xd4 }, pkt[16], buf[64];
	size_t n = cp_pkt(pkt, ECHO_REQ, 9, data, sizeof(data));
	uint16_t p;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	sp->lcp.magic = 0xa1b2c3d4;
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	/* No reply to our own echo: LCP is closed and reopened instead. */
	while (cp_tx_pop(ifp, &p, buf, sizeof(buf)) >= 0)
		KT_ASSERT(buf[0] != ECHO_REPLY);
	SPPP_FX_END;
}

/*
 * Magic-Number rejected: Echo magics are 0 on both ends (RFC 1661 6.4), so
 * a magic compare must not flag loopback or ignore the reply.
 */
static void
reject_magic(struct sppp *sp)
{
	uint8_t o[] = { LCP_OPT_MAGIC, 6, 0x11, 0x22, 0x33, 0x44 }, pkt[16];
	size_t n = cp_pkt(pkt, CONF_REJ, 1, o, sizeof(o));

	fx_sppp_confrej(sp, FX_IDX_LCP, pkt, n);
	KT_FX_ASSERT(!ISSET(sp->lcp.opts, SPPP_LCP_OPT_MAGIC));
}

KTEST(sppp_input, echo_request_magic_rejected_not_loopback)
{
	SPPP_FX_BEGIN;
	uint8_t data[] = { 0, 0, 0, 0 }, pkt[16], buf[64];
	size_t n = cp_pkt(pkt, ECHO_REQ, 9, data, sizeof(data));
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	reject_magic(sp);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, ECHO_REPLY, buf, len);
	KT_EQ(len, (int)n);
	KT_EQ(buf[4] | buf[5] | buf[6] | buf[7], 0);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_OPENED);
	SPPP_FX_END;
}

KTEST(sppp_input, echo_reply_magic_rejected_resets_alivecnt)
{
	SPPP_FX_BEGIN;
	uint8_t data[] = { 0, 0, 0, 0 }, pkt[16];
	size_t n = cp_pkt(pkt, ECHO_REPLY, 7, data, sizeof(data));

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	reject_magic(sp);
	sp->lcp.echoid = 7;
	sp->pp_alivecnt = 2;
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	KT_EQ(sp->pp_alivecnt, 0);
	SPPP_FX_END;
}

KTEST(sppp_input, unknown_code_gets_code_reject)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8], buf[64];
	size_t n = cp_pkt(pkt, 0x77, 3, "\xaa\xbb", 2);
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, CODE_REJ, buf, len);
	KT_EQ(len, 4 + (int)n);
	KT_MEMEQ(&buf[4], pkt, n);
	SPPP_FX_END;
}

KTEST(sppp_input, ncp_echo_is_illegal_code)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[16], buf[64];
	size_t n = cp_pkt(pkt, ECHO_REQ, 3, "\0\0\0\0", 4);
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	fx_sppp_input(sp, PPP_IPCP, pkt, n);
	TX_EXPECT(PPP_IPCP, CODE_REJ, buf, len);
	(void)len;
	SPPP_FX_END;
}

KTEST(sppp_input, auth_before_auth_phase_dropped)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[16];
	size_t n = cp_pkt(pkt, PAP_REQ, 1, "\x01u\x01p", 4);

	fx_sppp_force_phase(sp, SPPP_PHASE_ESTABLISH, STATE_REQ_SENT);
	fx_sppp_input(sp, PPP_PAP, pkt, n);
	fx_sppp_input(sp, PPP_CHAP, pkt, n);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IQDROPS), 2);
	SPPP_FX_END;
}

KTEST(sppp_input, ip_needs_ipcp_opened)
{
	SPPP_FX_BEGIN;
	uint8_t ip[20] = { 0x45 };

	ifp->if_flags |= IFF_UP;
	fx_sppp_input(sp, PPP_IP, ip, sizeof(ip));
	KT_EQ(kshim_ip_input_calls, 0);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IQDROPS), 1);
	/* p2/scaling (R1/T3): the IP arm gates on pp_dp_open, which only the
	 * real state setter keeps in sync -- go through it, never write
	 * scp[].state or pp_dp_open here. */
	SPPP_LOCK(sp, RW_WRITER);
	sppp_cp_change_state(&ipcp, sp, STATE_OPENED);
	SPPP_UNLOCK(sp);
	KT_EQ(atomic_load_int(&sp->pp_dp_open), 1U << IDX_IPCP);
	fx_sppp_input(sp, PPP_IP, ip, sizeof(ip));
	KT_EQ(kshim_ip_input_calls, 1);
	/* ...and leaving Opened closes the gate again. */
	SPPP_LOCK(sp, RW_WRITER);
	sppp_cp_change_state(&ipcp, sp, STATE_CLOSED);
	SPPP_UNLOCK(sp);
	KT_EQ(atomic_load_int(&sp->pp_dp_open), 0);
	fx_sppp_input(sp, PPP_IP, ip, sizeof(ip));
	KT_EQ(kshim_ip_input_calls, 1);
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IQDROPS), 2);
	SPPP_FX_END;
}

/* A ConfReq split over a chain and past MHLEN still reaches the parser. */
KTEST(sppp_input, chained_confreq_made_contiguous)
{
	SPPP_FX_BEGIN;
	uint8_t frame[2 + 4 + 300];
	struct mbuf *m;

	frame[0] = 0xc0;
	frame[1] = 0x21;
	for (size_t i = 0; i < 300; i += 6) {
		frame[6 + i] = LCP_OPT_ASYNC_MAP;
		frame[6 + i + 1] = 6;
		memset(&frame[6 + i + 2], 0, 4);
	}
	cp_pkt(frame + 2, CONF_REQ, 5, frame + 6, 300);
	fx_sppp_force_phase(sp, SPPP_PHASE_ESTABLISH, STATE_REQ_SENT);
	m = kshim_mbuf_chain(frame, sizeof(frame), 50);
	m->m_pkthdr.rcvif = ifp;
	sppp_input(ifp, m);
	kshim_run_tasks();
	KT_EQ(sp->scp[IDX_LCP].state, STATE_ACK_SENT);
	SPPP_FX_END;
}

/* Over one cluster: dropped with ierrors, never parsed off the chain. */
KTEST(sppp_input, oversize_control_frame_dropped)
{
	SPPP_FX_BEGIN;
	static uint8_t frame[2 + MCLBYTES + 10];
	struct mbuf *m;

	frame[0] = 0xc0;
	frame[1] = 0x21;
	cp_pkt(frame + 2, CONF_REQ, 5, NULL, 0);
	m = kshim_mbuf_chain(frame, sizeof(frame), 1000);
	m->m_pkthdr.rcvif = ifp;
	sppp_input(ifp, m);
	kshim_run_tasks();
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 1);
	SPPP_FX_END;
}

/*
 * RFC 1661 5.2: a Configure-Ack echoes the Configure-Request's options
 * exactly.  NetBSD's sppp_cp_send() clamped every control packet to one
 * header mbuf (len > MHLEN - pkthdrlen - LCP_HEADER_LEN), so the Ack of a
 * long request was cut mid-option and the peer discarded it.
 */
KTEST(sppp_input, long_confreq_ack_not_truncated)
{
	SPPP_FX_BEGIN;
	uint8_t opts[300], pkt[400], buf[1024];
	size_t n;
	int len;

	for (size_t i = 0; i < sizeof(opts); i += 6) {
		opts[i] = LCP_OPT_ASYNC_MAP;
		opts[i + 1] = 6;
		memset(&opts[i + 2], (int)i, 4);
	}
	n = cp_pkt(pkt, CONF_REQ, 5, opts, sizeof(opts));
	fx_sppp_force_phase(sp, SPPP_PHASE_ESTABLISH, STATE_REQ_SENT);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, CONF_ACK, buf, len);
	kshim_tx_flush(ifp);
	fx_pppoe_free(fx_sc);
	KT_EQ(len, (int)n);
}

/* RFC 1661 5.7: the Rejected-Information is truncated to the peer's MRU. */
KTEST(sppp_input, proto_rej_truncated_to_peer_mru)
{
	SPPP_FX_BEGIN;
	static uint8_t payload[1000];
	uint8_t buf[1024];
	int len;

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)i;
	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	SPPP_LOCK(sp, RW_WRITER);
	sp->lcp.their_mru = 400;
	SPPP_UNLOCK(sp);
	fx_sppp_input(sp, 0x4321, payload, sizeof(payload));
	TX_EXPECT(PPP_LCP, PROTO_REJ, buf, len);
	KT_EQ(len, 400);
	KT_EQ(buf[2] << 8 | buf[3], 400);
	KT_EQ(buf[4] << 8 | buf[5], 0x4321);
	KT_MEMEQ(&buf[6], payload, 400 - 6);
	SPPP_FX_END;
}

/* An Echo-Reply echoes the whole Echo-Request, past one header mbuf. */
KTEST(sppp_input, long_echo_reply_not_truncated)
{
	SPPP_FX_BEGIN;
	uint8_t data[4 + 400], pkt[4 + sizeof(data)], buf[1024];
	size_t n;
	int len;

	memset(data, 0, 4);
	for (size_t i = 4; i < sizeof(data); i++)
		data[i] = (uint8_t)i;
	n = cp_pkt(pkt, ECHO_REQ, 9, data, sizeof(data));
	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	sp->lcp.magic = 0xa1b2c3d4;
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, ECHO_REPLY, buf, len);
	KT_EQ(len, (int)n);
	KT_EQ(buf[2] << 8 | buf[3], (int)n);
	KT_MEMEQ(&buf[8], &data[4], sizeof(data) - 4);
	SPPP_FX_END;
}

/*
 * RFC 1661 5.1: an empty Configure-Request is answered with an empty
 * Configure-Ack on the wire, not only by the parser (sppp_screply()
 * skipped every zero-length reply).
 */
KTEST(sppp_input, empty_confreq_acked_on_wire)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8], buf[64];
	size_t n = cp_pkt(pkt, CONF_REQ, 5, NULL, 0);
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_ESTABLISH, STATE_REQ_SENT);
	fx_sppp_input(sp, PPP_LCP, pkt, n);
	TX_EXPECT(PPP_LCP, CONF_ACK, buf, len);
	KT_EQ(len, 4);
	KT_EQ(buf[1], 5);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_ACK_SENT);
	SPPP_FX_END;
}

KTEST(sppp_input, empty_ipv6cp_confreq_acked_on_wire)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[8], buf[64];
	size_t n = cp_pkt(pkt, CONF_REQ, 6, NULL, 0);
	uint16_t p;
	int len;

	fx_sppp_force_phase(sp, SPPP_PHASE_NETWORK, STATE_OPENED);
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_IPV6CP].state = STATE_REQ_SENT;
	SPPP_UNLOCK(sp);
	fx_sppp_input(sp, PPP_IPV6CP, pkt, n);
	while ((len = cp_tx_pop(ifp, &p, buf, sizeof(buf))) >= 0 &&
	    !(p == PPP_IPV6CP && buf[0] == CONF_ACK))
		;
	KT_EQ(len, 4);
	KT_EQ(buf[1], 6);
	SPPP_FX_END;
}
