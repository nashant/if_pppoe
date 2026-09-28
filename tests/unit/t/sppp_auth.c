/* PAP / CHAP message parsing -- sppp_pap_input(), sppp_chap_input() */

static void
auth_cfg(struct sppp *sp, u_int my, u_int his)
{
	struct spppauthcfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.myauth = my;
	cfg.hisauth = his;
	cfg.myname = "me";
	cfg.myname_length = 3;
	cfg.mysecret = "mysecret";
	cfg.mysecret_length = 9;
	cfg.hisname = "peer";
	cfg.hisname_length = 5;
	cfg.hissecret = "hissecret";
	cfg.hissecret_length = 10;
	KT_EQ(sppp_params(sp, SPPPSETAUTHCFG, &cfg), 0);
}

/* Feed one auth packet straight to its parser, as sppp_input() does. */
static void
auth_in(struct sppp *sp, uint16_t proto, const uint8_t *pkt, size_t len)
{
	struct mbuf *m = kshim_mbuf_from(pkt, (int)len);

	SPPP_LOCK(sp, RW_WRITER);
	if (proto == PPP_PAP)
		sppp_pap_input(sp, m);
	else
		sppp_chap_input(sp, m);
	SPPP_UNLOCK(sp);
	m_freem(m);
}

static size_t
pap_req(uint8_t *pkt, const char *name, int nlen, const char *pw, int plen)
{
	uint8_t o[600];
	size_t n = 0;

	o[n++] = (uint8_t)nlen;
	memcpy(o + n, name, strlen(name));
	n += strlen(name);
	o[n++] = (uint8_t)plen;
	memcpy(o + n, pw, strlen(pw));
	n += strlen(pw);
	return (cp_pkt(pkt, PAP_REQ, 4, o, n));
}

KTEST(pap_input, good_request_acked)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 4, "hissecret", 9);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_ACK);
	KT_EQ(sp->scp[IDX_PAP].rconfid, 4);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(pap_input, wrong_secret_naked)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 4, "hissecreX", 9);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NAK);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(pap_input, secret_prefix_not_accepted)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 4, "his", 3);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NAK);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(pap_input, overlong_peer_id_length_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 200, "hissecret", 9);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NONE);
	KT_EQ(kshim_tasks_pending(), 0);
	SPPP_FX_END;
}

KTEST(pap_input, overlong_password_length_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 4, "hissecret", 10);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NONE);
	SPPP_FX_END;
}

KTEST(pap_input, id_length_255_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 255, "x", 1);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NONE);
	SPPP_FX_END;
}

KTEST(pap_input, length_field_truncates_request)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[64];
	size_t n = pap_req(pkt, "peer", 4, "hissecret", 9);

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_PAP);
	pkt[3] = (uint8_t)(n - 3);	/* h->len ends inside the password */
	auth_in(sp, PPP_PAP, pkt, n);
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NONE);
	SPPP_FX_END;
}

KTEST(pap_input, runts_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t four[4] = { PAP_REQ, 1, 0, 4 }, five[5] = { PAP_REQ, 1, 0, 5, 0 };
	uint8_t ack5[5] = { PAP_ACK, 1, 0, 5, 0xff };

	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_PAP);
	ifp->if_flags |= IFF_DEBUG;	/* take the message-printing arms */
	auth_in(sp, PPP_PAP, four, sizeof(four));
	auth_in(sp, PPP_PAP, five, sizeof(five));
	auth_in(sp, PPP_PAP, ack5, sizeof(ack5));
	KT_EQ(sp->scp[IDX_PAP].rcr_type, CP_RCR_NONE);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(pap_input, nak_msg_length_bounded)
{
	SPPP_FX_BEGIN;
	/* Msg-Length 0xff with 1 octet of message: printing must stop. */
	uint8_t nak[] = { PAP_NAK, 0, 0, 6, 0xff, 'x' };

	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_NONE);
	ifp->if_flags |= IFF_DEBUG;
	auth_in(sp, PPP_PAP, nak, sizeof(nak));
	KT_EQ(sp->pp_authfail_proto, PPP_PAP);
	SPPP_FX_END;
}

static size_t
chap_pkt(uint8_t *pkt, uint8_t code, uint8_t id, const uint8_t *val,
    int vlen_field, int vlen, const char *name)
{
	uint8_t o[600];
	size_t n = 0;

	o[n++] = (uint8_t)vlen_field;
	memcpy(o + n, val, vlen);
	n += vlen;
	memcpy(o + n, name, strlen(name));
	n += strlen(name);
	return (cp_pkt(pkt, code, id, o, n));
}

KTEST(chap_input, challenge_digest_matches_rfc1994)
{
	SPPP_FX_BEGIN;
	uint8_t val[16], pkt[64], want[16];
	size_t n;
	MD5_CTX ctx;
	uint8_t id = 0x2a;

	for (int i = 0; i < 16; i++)
		val[i] = (uint8_t)(i * 7);
	n = chap_pkt(pkt, CHAP_CHALLENGE, id, val, 16, 16, "ac");
	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	auth_in(sp, PPP_CHAP, pkt, n);
	/* RFC 1994 4.1: MD5(Identifier || secret || Challenge). */
	MD5Init(&ctx);
	MD5Update(&ctx, &id, 1);
	MD5Update(&ctx, "mysecret", 8);
	MD5Update(&ctx, val, 16);
	MD5Final(want, &ctx);
	KT_EQ(sp->chap.digest_len, 16);
	KT_MEMEQ(sp->chap.digest, want, 16);
	KT_EQ(sp->scp[IDX_CHAP].rconfid, id);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(chap_input, challenge_value_size_overlong_ignored)
{
	SPPP_FX_BEGIN;
	uint8_t val[16] = { 0 }, pkt[64];
	size_t n = chap_pkt(pkt, CHAP_CHALLENGE, 1, val, 200, 16, "ac");

	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	ifp->if_flags |= IFF_DEBUG;
	auth_in(sp, PPP_CHAP, pkt, n);
	KT_EQ(sp->chap.digest_len, 0);
	KT_EQ(kshim_tasks_pending(), 0);
	SPPP_FX_END;
}

KTEST(chap_input, bare_header_challenge_ignored)
{
	SPPP_FX_BEGIN;
	/* No Value-Size octet at all (the pre-53c0707 read past the header). */
	uint8_t pkt[4] = { CHAP_CHALLENGE, 1, 0, 4 };

	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	ifp->if_flags |= IFF_DEBUG;
	auth_in(sp, PPP_CHAP, pkt, sizeof(pkt));
	KT_EQ(sp->chap.digest_len, 0);
	SPPP_FX_END;
}

KTEST(chap_input, length_field_shorter_than_frame)
{
	SPPP_FX_BEGIN;
	uint8_t val[16] = { 0 }, pkt[64];
	size_t n = chap_pkt(pkt, CHAP_CHALLENGE, 1, val, 16, 16, "ac");

	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	pkt[3] = 10;		/* h->len cuts into the value */
	auth_in(sp, PPP_CHAP, pkt, n);
	KT_EQ(sp->chap.digest_len, 0);
	SPPP_FX_END;
}

KTEST(chap_input, success_without_challenge_is_error)
{
	SPPP_FX_BEGIN;
	uint8_t pkt[4] = { CHAP_SUCCESS, 0, 0, 4 };

	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	auth_in(sp, PPP_CHAP, pkt, sizeof(pkt));
	KT_EQ(if_getcounter(ifp, IFCOUNTER_IERRORS), 1);
	SPPP_FX_END;
}

KTEST(chap_input, failure_latches_authfail)
{
	SPPP_FX_BEGIN;
	uint8_t val[16] = { 1 }, pkt[64];
	uint8_t fail[] = { CHAP_FAILURE, 3, 0, 6, 'n', 'o' };
	size_t n = chap_pkt(pkt, CHAP_CHALLENGE, 3, val, 16, 16, "ac");

	auth_cfg(sp, SPPP_AUTHPROTO_CHAP, SPPP_AUTHPROTO_NONE);
	auth_in(sp, PPP_CHAP, pkt, n);
	kshim_run_tasks();
	auth_in(sp, PPP_CHAP, fail, sizeof(fail));
	KT_EQ(sp->pp_authfail_proto, PPP_CHAP);
	KT_EQ(sp->chap.digest_len, 0);
	SPPP_FX_END;
}

KTEST(chap_input, response_bad_value_size_naked)
{
	SPPP_FX_BEGIN;
	uint8_t val[15] = { 0 }, pkt[64];
	size_t n;

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_CHAP);
	n = chap_pkt(pkt, CHAP_RESPONSE, sp->scp[IDX_CHAP].confid, val, 15,
	    15, "peer");
	auth_in(sp, PPP_CHAP, pkt, n);
	KT_EQ(sp->scp[IDX_CHAP].rcr_type, CP_RCR_NAK);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(chap_input, response_correct_digest_acked)
{
	SPPP_FX_BEGIN;
	uint8_t digest[16], pkt[64], id;
	MD5_CTX ctx;
	size_t n;

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_CHAP);
	id = sp->scp[IDX_CHAP].confid;
	memset(sp->chap.challenge, 0x5c, sizeof(sp->chap.challenge));
	MD5Init(&ctx);
	MD5Update(&ctx, &id, 1);
	MD5Update(&ctx, "hissecret", 9);
	MD5Update(&ctx, sp->chap.challenge, 16);
	MD5Final(digest, &ctx);
	n = chap_pkt(pkt, CHAP_RESPONSE, id, digest, 16, 16, "peer");
	auth_in(sp, PPP_CHAP, pkt, n);
	KT_EQ(sp->scp[IDX_CHAP].rcr_type, CP_RCR_ACK);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(chap_input, response_wrong_name_naked)
{
	SPPP_FX_BEGIN;
	uint8_t digest[16] = { 0 }, pkt[64];
	size_t n;

	auth_cfg(sp, SPPP_AUTHPROTO_NONE, SPPP_AUTHPROTO_CHAP);
	n = chap_pkt(pkt, CHAP_RESPONSE, sp->scp[IDX_CHAP].confid, digest, 16,
	    16, "pee");
	auth_in(sp, PPP_CHAP, pkt, n);
	KT_EQ(sp->scp[IDX_CHAP].rcr_type, CP_RCR_NAK);
	kshim_run_tasks();
	SPPP_FX_END;
}

/*
 * Auth-failure backoff: a run of auth failures (an ISP RADIUS outage NAKs
 * every attempt) delays the next dial 1, 2, 4 ... s, capped by
 * net.pppoe.auth_backoff_max, instead of if_down'ing the interface for good
 * once pp_max_auth_fail is reached.
 */
static int backoff_tls_calls;

static void
backoff_count_tls(struct sppp *sp)
{
	backoff_tls_calls++;
}

/* The auth CP closed while authenticating: what sppp_tlf() leads to. */
static void
backoff_auth_closed(struct sppp *sp, int failures)
{
	backoff_tls_calls = 0;
	sp->pp_tls = backoff_count_tls;
	SPPP_LOCK(sp, RW_WRITER);
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_auth_failures = failures;
	sppp_lcp_check_and_close(sp);
	SPPP_UNLOCK(sp);
	kshim_run_tasks();
}

KTEST(auth_backoff, max_failures_redial_later_not_ifdown)
{
	SPPP_FX_BEGIN;

	ifp->if_flags |= IFF_UP;
	backoff_auth_closed(sp, sp->pp_max_auth_fail);
	KT_ASSERT((ifp->if_flags & IFF_UP) != 0);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STARTING);
	KT_LOGGED("authentication failed 5 times");
	/* 5 failures: 1 << 4 s before the lower layer is asked again. */
	KT_EQ(backoff_tls_calls, 0);
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	KT_EQ(sp->pp_dial_ch.c_time - kshim_ticks, 16 * hz);
	KT_EQ(kshim_callout_fire(&sp->pp_dial_ch), 1);
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 1);
	KT_EQ(sp->pp_auth_failures, 5);	/* SPPPGETAUTHFAILURES still sees it */
	SPPP_FX_END;
}

KTEST(auth_backoff, delay_doubles_and_caps)
{
	SPPP_FX_BEGIN;
	u_int max = sppp_auth_backoff_max;

	sp->pp_auth_failures = 0;
	KT_EQ(sppp_auth_backoff(sp), 0);
	sp->pp_auth_failures = 1;
	KT_EQ(sppp_auth_backoff(sp), 1);
	sp->pp_auth_failures = 2;
	KT_EQ(sppp_auth_backoff(sp), 2);
	sp->pp_auth_failures = 3;
	KT_EQ(sppp_auth_backoff(sp), 4);
	sp->pp_auth_failures = 9;
	KT_EQ(sppp_auth_backoff(sp), 256);
	sp->pp_auth_failures = 10;
	KT_EQ(sppp_auth_backoff(sp), 300);	/* the default cap */
	sp->pp_auth_failures = INT_MAX;
	KT_EQ(sppp_auth_backoff(sp), 300);
	sppp_auth_backoff_max = 10;
	sp->pp_auth_failures = 5;
	KT_EQ(sppp_auth_backoff(sp), 10);
	sppp_auth_backoff_max = 0;		/* 0: no backoff at all */
	KT_EQ(sppp_auth_backoff(sp), 0);
	/* A huge cap is clamped, so delay * hz cannot wrap the tick count. */
	sppp_auth_backoff_max = UINT_MAX;
	sp->pp_auth_failures = INT_MAX;
	KT_EQ(sppp_auth_backoff(sp), 86400);
	sppp_auth_backoff_max = max;
	SPPP_FX_END;
}

KTEST(auth_backoff, no_failures_dials_immediately)
{
	SPPP_FX_BEGIN;

	backoff_auth_closed(sp, 0);
	KT_EQ(backoff_tls_calls, 1);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	SPPP_FX_END;
}

KTEST(auth_backoff, success_resets_backoff)
{
	SPPP_FX_BEGIN;
	uint8_t ack[5] = { PAP_ACK, 0, 0, 5, 0 };

	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_NONE);
	sp->pp_auth_failures = 7;
	ack[1] = sp->scp[IDX_PAP].confid;
	auth_in(sp, PPP_PAP, ack, sizeof(ack));
	KT_EQ(sp->pp_auth_failures, 0);
	KT_EQ(sppp_auth_backoff(sp), 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(auth_backoff, tlf_cancels_deferred_dial)
{
	SPPP_FX_BEGIN;

	backoff_auth_closed(sp, 2);
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	SPPP_LOCK(sp, RW_WRITER);
	sppp_lcp_tlf(&lcp, sp);
	SPPP_UNLOCK(sp);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 0);
	SPPP_FX_END;
}

KTEST(auth_backoff, clear_auth_failure_dials_now)
{
	SPPP_FX_BEGIN;
	struct spppauthfailuresettings set = { .max_failures = 5 };

	backoff_auth_closed(sp, 6);
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	KT_EQ(sppp_params(sp, SPPPSETAUTHFAILURE, &set), 0);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 1);
	KT_EQ(sp->pp_auth_failures, 0);
	SPPP_FX_END;
}

/*
 * The realistic sequence behind the reschedule: an auth failure in Opened
 * closes and reopens LCP (Closing -> Stopping), the peer's Terminate-Ack
 * gives the lower layer up (tlf -> Stopped), and its Down event then
 * restarts it (tls) with lower_running false, so the dial is held off.
 */
KTEST(auth_backoff, opened_close_rta_down_defers_dial)
{
	SPPP_FX_BEGIN;

	backoff_tls_calls = 0;
	sp->pp_tls = backoff_count_tls;
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_OPENED;
	sp->lcp.lower_running = true;
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_auth_failures = 3;
	sppp_lcp_check_and_close(sp);
	SPPP_UNLOCK(sp);
	kshim_run_tasks();
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STOPPING);
	SPPP_LOCK(sp, RW_WRITER);
	sppp_rta_event(sp, __UNCONST(&lcp));
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STOPPED);
	KT_ASSERT(!sp->lcp.lower_running);
	sppp_lcp_down(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STARTING);
	KT_EQ(backoff_tls_calls, 0);
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	KT_EQ(sp->pp_dial_ch.c_time - kshim_ticks, 4 * hz);
	KT_EQ(kshim_callout_fire(&sp->pp_dial_ch), 1);
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 1);
	SPPP_FX_END;
}

/*
 * Detach must drain the dial callout after the LCP work it waits out: a
 * queued Open (sppp_lcp_check_and_close() queues one per auth failure)
 * reaches tls from Initial and re-arms pp_dial_ch, which would then fire
 * into the freed softc.
 */
KTEST(auth_backoff, detach_drains_dial_after_lcp_work)
{
	SPPP_FX_BEGIN;

	backoff_tls_calls = 0;
	sp->pp_tls = backoff_count_tls;
	SPPP_LOCK(sp, RW_WRITER);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_INITIAL);
	KT_ASSERT(!sp->lcp.lower_running);
	sp->pp_auth_failures = 2;
	sppp_wq_add(sp->wq_cp, &sp->scp[IDX_LCP].work_open);
	SPPP_UNLOCK(sp);
	sppp_detach(ifp);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	KT_EQ(backoff_tls_calls, 0);
	/* Re-attach so the fixture's own destroy has something to detach. */
	sppp_attach(ifp);
	SPPP_FX_END;
}

KTEST(auth_backoff, setauth_dials_now)
{
	SPPP_FX_BEGIN;

	backoff_auth_closed(sp, 6);
	KT_ASSERT(callout_pending(&sp->pp_dial_ch));
	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_NONE);
	KT_ASSERT(!callout_pending(&sp->pp_dial_ch));
	KT_EQ(sp->pp_auth_failures, 0);
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 1);
	SPPP_FX_END;
}

/*
 * The callout fired and queued the dial, then tlf + tls ran before it
 * (with the cap now 0, so tls dialed at once): the stale dial must not
 * ask the lower layer a second time.
 */
KTEST(auth_backoff, stale_queued_dial_dropped)
{
	SPPP_FX_BEGIN;
	u_int max = sppp_auth_backoff_max;

	backoff_auth_closed(sp, 2);
	KT_EQ(kshim_callout_fire(&sp->pp_dial_ch), 1);
	sppp_auth_backoff_max = 0;
	SPPP_LOCK(sp, RW_WRITER);
	sppp_lcp_tlf(&lcp, sp);
	sppp_lcp_tls(&lcp, sp);
	SPPP_UNLOCK(sp);
	KT_EQ(backoff_tls_calls, 1);
	kshim_run_tasks();
	KT_EQ(backoff_tls_calls, 1);
	sppp_auth_backoff_max = max;
	SPPP_FX_END;
}

/*
 * An authenticator that never answers (RADIUS down, no NAK): our PAP
 * Request times out (TO- -> Stopped -> tlf -> check_and_close) or the
 * peer terminates LCP mid-auth.  Either counts as an auth failure, so the
 * redial backs off instead of going out at once.
 */
static void
backoff_pap_pending(struct sppp *sp)
{
	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_NONE);
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_OPENED;
	sp->lcp.lower_running = true;
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_flags |= PP_NEEDAUTH;		/* the peer's CR asked for auth */
	sp->scp[IDX_PAP].state = STATE_REQ_SENT;
	sp->scp[IDX_PAP].rst_counter = 0;	/* the last try went out */
	sp->lcp.protos |= 1 << IDX_PAP;
	SPPP_UNLOCK(sp);
}

KTEST(auth_backoff, pap_timeout_counts_as_failure)
{
	SPPP_FX_BEGIN;

	backoff_pap_pending(sp);
	SPPP_LOCK(sp, RW_WRITER);
	sppp_auth_to_event(sp, __UNCONST(&pap));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->scp[IDX_PAP].state, STATE_STOPPED);
	KT_EQ(sp->pp_auth_failures, 1);
	KT_EQ(sp->pp_authfail_proto, PPP_PAP);
	KT_LOGGED("pap authentication timed out");
	KT_EQ(sppp_auth_backoff(sp), 1);
	kshim_run_tasks();
	/* check_and_close queued LCP Close + Open: Opened -> Stopping. */
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STOPPING);
	SPPP_FX_END;
}

KTEST(auth_backoff, pap_nak_then_timeout_counts_once)
{
	SPPP_FX_BEGIN;
	uint8_t nak[5] = { PAP_NAK, 0, 0, 5, 0 };

	backoff_pap_pending(sp);
	nak[1] = sp->scp[IDX_PAP].confid;
	auth_in(sp, PPP_PAP, nak, sizeof(nak));
	KT_EQ(sp->pp_auth_failures, 1);
	SPPP_LOCK(sp, RW_WRITER);
	sppp_auth_to_event(sp, __UNCONST(&pap));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->pp_auth_failures, 1);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(auth_backoff, pap_retry_left_not_counted)
{
	SPPP_FX_BEGIN;

	backoff_pap_pending(sp);
	sp->scp[IDX_PAP].rst_counter = 2;	/* TO+: resend, no failure */
	SPPP_LOCK(sp, RW_WRITER);
	sppp_auth_to_event(sp, __UNCONST(&pap));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->scp[IDX_PAP].state, STATE_REQ_SENT);
	KT_EQ(sp->pp_auth_failures, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(auth_backoff, peer_terminate_during_auth_counts_as_failure)
{
	SPPP_FX_BEGIN;

	backoff_pap_pending(sp);
	SPPP_LOCK(sp, RW_WRITER);
	sppp_rtr_event(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->scp[IDX_LCP].state, STATE_STOPPING);
	KT_EQ(sp->pp_auth_failures, 1);
	KT_LOGGED("pap authentication terminated by peer");
	kshim_run_tasks();
	SPPP_FX_END;
}

KTEST(auth_backoff, peer_terminate_after_auth_not_counted)
{
	SPPP_FX_BEGIN;

	backoff_pap_pending(sp);
	sp->scp[IDX_PAP].state = STATE_OPENED;
	SPPP_LOCK(sp, RW_WRITER);
	sppp_rtr_event(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->pp_auth_failures, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

/*
 * A peer that never asked us to authenticate: sppp_lcp_tlu() opened PAP
 * anyway, and its TO- at session end is no auth failure.
 */
KTEST(auth_backoff, pap_timeout_unrequested_not_counted)
{
	SPPP_FX_BEGIN;

	backoff_pap_pending(sp);
	SPPP_LOCK(sp, RW_WRITER);
	sp->pp_phase = SPPP_PHASE_NETWORK;
	sp->pp_flags &= ~PP_NEEDAUTH;
	sppp_auth_to_event(sp, __UNCONST(&pap));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->pp_auth_failures, 0);
	KT_EQ(sp->pp_authfail_proto, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}

/* Both roles: the peer's Ack took us to ACK_RCVD, so its Terminate is no failure. */
KTEST(auth_backoff, peer_terminate_both_roles_accepted_not_counted)
{
	SPPP_FX_BEGIN;

	auth_cfg(sp, SPPP_AUTHPROTO_PAP, SPPP_AUTHPROTO_PAP);
	SPPP_LOCK(sp, RW_WRITER);
	sp->scp[IDX_LCP].state = STATE_OPENED;
	sp->lcp.lower_running = true;
	sp->pp_phase = SPPP_PHASE_AUTHENTICATE;
	sp->pp_flags |= PP_NEEDAUTH;
	sp->scp[IDX_PAP].state = STATE_ACK_RCVD;
	sp->lcp.protos |= 1 << IDX_PAP;
	sppp_rtr_event(sp, __UNCONST(&lcp));
	SPPP_UNLOCK(sp);
	KT_EQ(sp->pp_auth_failures, 0);
	kshim_run_tasks();
	SPPP_FX_END;
}
