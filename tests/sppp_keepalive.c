/*
 * sppp_keepalive.c — in-process functional model of the sppp LCP keepalive
 * timer machinery (M002/S03/T2).
 *
 * The live timer logic lives in sys/net/if_spppsubr.c's sppp_keepalive()
 * callout, which is kernel-only (callouts, locks, mbuf tx).  This harness
 * transcribes the exact keepalive FSM -- constants, per-vnet list and tick
 * counter semantics, and the LCP ECHO_REQ/timeout event flow -- from the
 * vendored source into a self-contained userland model, then drives it
 * through the same tick sequences the lab performs and asserts T2's
 * keepalive contract:
 *
 *   (1) a dead peer (echo replies stop) is detected: after the configured
 *       max_noreceive silence grace, ECHO_REQs go out every alive_interval
 *       ticks and after maxalive unanswered requests the link restarts
 *       (LCP close+open scheduled, i.e. the "going to restart the
 *       connection" timeout path)
 *   (2) the payload liveness poke keeps pp_last_receive fresh, so
 *       max_noreceive waits for REAL silence -- traffic on the lock-free
 *       payload arm must prevent any alivecnt accumulation (research
 *       amendment 3 semantics; locking order and timer windows verified
 *       against the module log in the live run-keepalive.sh recipe)
 *   (3) alive_interval=0 disables the keepalive entirely (no ECHO_REQs,
 *       no timeout)
 *   (4) the PP_IFDOWN bit additionally schedules the if_down work on a
 *       keepalive timeout
 *   (5) the keepalive state is PER-VNET: two independent lists/tick
 *       counters -- one vnet's dying peer cannot disturb another vnet's
 *       healthy link (the M002/S03/T2 VNET_DEFINE'd spppq/keepalive_ch
 *       change; tick counters do not share a modulo)
 *   (6) detach storm: create+destroy 10 interfaces under a live echo
 *       storm (sppp_detach() on clone destroy), repeated 10x -- the list
 *       stays consistent, the last destroy stops the callout (no further
 *       ticks), and no state corruption surfaces (the kernel-side
 *       taskqueue drain is proven live by run-keepalive.sh's 10x no-panic
 *       gate; this model proves the list/timer invariants that drain
 *       depends on)
 *
 * Build and run (host gcc, no privileges, no network, no interfaces):
 *
 *   cc -Wall -Wextra -O2 -o tests/sppp_keepalive tests/sppp_keepalive.c
 *   ./tests/sppp_keepalive          (exit 0 == all assertions pass)
 *
 * Every assertion failure exits non-zero and names the exact scenario.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ==== Constants and FSM, transcribed from sys/net/if_spppsubr.c ====
 * (line refs are the M002/S03/T2 tree):
 *   - if_spppsubr.c:110-125  DEFAULT_KEEPALIVE_INTERVAL=10,
 *                            DEFAULT_ALIVE_INTERVAL=1, LOOPALIVECNT=3,
 *                            DEFAULT_MAXALIVECNT=3, DEFAULT_NORECV_TIME=15
 *   - if_spppsubr.c:151-152  PP_DEVF_KEEPALIVE, PP_IFDOWN flags
 *   - sppp_keepalive() at :5588 — the tick handler transcribed verbatim
 *   - ECHO_REPLY reset at :1943 (last_receive is poked by sppp_input for
 *     EVERY frame :685, so the freshness gate below is the real reset)
 */
#define	DEFAULT_KEEPALIVE_INTERVAL	10	/* seconds between ticks */
#define	DEFAULT_ALIVE_INTERVAL		1	/* ticks between ECHO_REQ */
#define	DEFAULT_MAXALIVECNT		3	/* max missed alive packets */
#define	DEFAULT_NORECV_TIME		15	/* sec before we worry */
#define	PP_DEVF_KEEPALIVE		(1U << 0)
#define	PP_IFDOWN			0x01
#define	PPP_PHASE_AUTHENTICATE		3	/* keepalives start here */

/* Global ("boot") clock: seconds since some epoch, monotonic. */
static uint64_t now;

struct kal_if {
	uint64_t	last_receive;	/* pp_last_receive poke (sppp_input) */
	uint32_t	alivecnt;	/* pp_alivecnt */
	uint32_t	alive_interval;	/* ticks between ECHO_REQ (SPPPSETKEEPALIVE) */
	uint32_t	maxalive;	/* max unanswered ECHO_REQ (SPPPSETKEEPALIVE) */
	uint32_t	max_noreceive;	/* sec silence before ECHO_REQs start */
	uint32_t	dev_flags;	/* PP_DEVF_KEEPALIVE */
	uint32_t	flags;		/* PP_IFDOWN */
	uint32_t	phase;		/* sppp phase */
	int		connecting;	/* pp_connecting (link running) */
	/* observable events the model counts: */
	int		echo_requests;	/* ECHO_REQs emitted */
	int		timeouts;	/* keepalive timeout fired */
	int		ifdown_works;	/* work_ifdown scheduled on timeout */
	int		closed;		/* LCP work_close scheduled */
	int		reopened;	/* LCP work_open scheduled */
	struct kal_if	*next;		/* pp_next on the per-vnet list */
};

/*
 * Per-vnet keepalive state (the model of V_spppq / V_keepalive_ch /
 * V_sppp_keepalive_cnt / V_sppp_keepalive_interval).
 */
struct kal_vnet {
	struct kal_if	*head;
	uint64_t	tick_cnt;	/* sppp_keepalive_cnt */
	uint32_t	interval;	/* sppp_keepalive_interval (per-vnet) */
	int		callout_armed;	/* callout_schedule / callout_stop */
};

/* ---- assertion harness ---- */
static int failures;

static void
check(int cond, const char *what)
{
	if (!cond) {
		printf("  ASSERTION FAILED: %s\n", what);
		failures++;
	} else {
		printf("  ok: %s\n", what);
	}
}

/*
 * One keepalive tick: the body of sppp_keepalive() (if_spppsubr.c:5588)
 * transcribed for a single per-vnet list, with sppp_detach()'s
 * callout_stop on empty list folded into the caller.
 */
static void
kal_tick(struct kal_vnet *v)
{
	struct kal_if *sp;

	if (!v->callout_armed)
		return;			/* callout stopped: no tick runs */
	for (sp = v->head; sp != NULL; sp = sp->next) {
		/* Keepalive mode disabled or channel down? */
		if (!(sp->dev_flags & PP_DEVF_KEEPALIVE) ||
		    !sp->connecting)
			continue;
		/* No keepalive in PPP mode if LCP not opened yet. */
		if (sp->phase < PPP_PHASE_AUTHENTICATE)
			continue;
		/* No echo reply, but maybe user data passed through? */
		if (sp->max_noreceive != 0 &&
		    (now - sp->last_receive) < sp->max_noreceive) {
			sp->alivecnt = 0;
			continue;
		}
		/* No echo request */
		if (sp->alive_interval == 0)
			continue;
		/* send a ECHO_REQ once in alive_interval ticks */
		if ((v->tick_cnt % sp->alive_interval) != 0)
			continue;
		if (sp->alivecnt >= sp->maxalive) {
			/* Timeout: restart the connection. */
			sp->alivecnt = 0;
			if (sp->flags & PP_IFDOWN)
				sp->ifdown_works++;
			sp->closed++;
			sp->reopened++;
			sp->timeouts++;
			continue;
		}
		if (sp->alivecnt < sp->maxalive)
			sp->alivecnt++;
		if (sp->phase >= PPP_PHASE_AUTHENTICATE)
			sp->echo_requests++;
	}
	v->tick_cnt++;
	if (v->head != NULL)
		v->callout_armed = 1;	/* re-arm, as :5686 does */
}

/* sppp_input's pp_last_receive poke (if_spppsubr.c:685), which now covers
 * payload frames too. */
static void
kal_receive(struct kal_if *sp)
{
	sp->last_receive = now;
}

/* sppp_attach's list insert + first-schedule (if_spppsubr.c:1247). */
static void
kal_attach(struct kal_vnet *v, struct kal_if *sp)
{
	sp->next = v->head;
	v->head = sp;
	if (v->head->next == NULL)	/* sppq was NULL: schedule */
		v->callout_armed = 1;
}

/* sppp_detach's list remove + last-out callout_stop (:1262). */
static void
kal_detach(struct kal_vnet *v, struct kal_if *sp)
{
	struct kal_if **q = &v->head, *p;

	while ((p = *q) != NULL) {
		if (p == sp) {
			*q = p->next;
			break;
		}
		q = &p->next;
	}
	if (v->head == NULL)
		v->callout_armed = 0;		/* callout_stop */
}

/* ---- scenario 1+2: dead-peer timeout and the max_noreceive freshness
 * gate (payload liveness poke keeps the peer "alive"). ---- */
static int
scenario_dead_peer(void)
{
	int prev = failures;
	struct kal_vnet v = { .interval = DEFAULT_KEEPALIVE_INTERVAL };
	struct kal_if sp = {
		.dev_flags = PP_DEVF_KEEPALIVE,
		.phase = PPP_PHASE_AUTHENTICATE,
		.alive_interval = DEFAULT_ALIVE_INTERVAL,
		.maxalive = DEFAULT_MAXALIVECNT,
		.max_noreceive = DEFAULT_NORECV_TIME,
		.connecting = 1,
	};
	int i;

	printf("--- Scenario 1: dead peer -> keepalive timeout (maxalive=%u, "
	    "alive_interval=%u, max_noreceive=%us) ---\n",
	    sp.maxalive, sp.alive_interval, sp.max_noreceive);

	kal_attach(&v, &sp);

	/* Peer healthy: keep receiving.  Even 30 ticks must never timeout. */
	for (i = 0; i < 30; i++) {
		kal_receive(&sp);	/* echo replies / payload keep flowing */
		kal_tick(&v);
	}
	check(sp.timeouts == 0,
	    "healthy peer: no timeout while last_receive stays fresh");
	check(sp.alivecnt == 0,
	    "freshness gate resets alivecnt every tick (no accumulation)");
	check(v.tick_cnt == 30, "per-vnet tick counter advanced 30 times");

	/* Peer dies at t=300 (no more receives).  15s grace must elapse
	 * before ECHO_REQs start; then one req per alive_interval tick and
	 * the maxalive threshold (3) goes unanswered -> timeout.  The
	 * timeout schedules close+open and resets alivecnt, so while the
	 * link stays down the cycle repeats (the in-kernel phase gate stops
	 * keepalives once LCP actually closes -- the live recipe observes
	 * the real phase dynamics). */
	now += DEFAULT_NORECV_TIME + 2;
	sp.timeouts = 0;
	sp.closed = sp.reopened = 0;
	for (i = 0; i < 20; i++)
		kal_tick(&v);
	check(sp.echo_requests > 0,
	    "ECHO_REQs emitted after the max_noreceive grace elapsed");
	check(sp.timeouts >= 1,
	    "maxalive unanswered ECHO_REQs -> LCP keepalive timeout fires");
	check(sp.closed == sp.timeouts && sp.reopened == sp.timeouts,
	    "every timeout schedules the close+open restart (link redial)");
	check(sp.alivecnt == 0, "alivecnt reset after the timeout");
	check(sp.ifdown_works == 0,
	    "PP_IFDOWN not set: no if_down work scheduled");

	kal_detach(&v, &sp);
	check(v.head == NULL && v.callout_armed == 0,
	    "detach empties the list and stops the callout");

	printf("--- Scenario 1 done ---\n");
	return failures - prev;
}

/* ---- scenario 3: alive_interval=0 disables keepalive. ---- */
static int
scenario_disabled(void)
{
	int prev = failures;
	struct kal_vnet v = { .interval = DEFAULT_KEEPALIVE_INTERVAL };
	struct kal_if sp = {
		.dev_flags = PP_DEVF_KEEPALIVE,
		.phase = PPP_PHASE_AUTHENTICATE,
		.alive_interval = 0,		/* SPPPSETKEEPALIVE -i 0 */
		.maxalive = 1,
		.max_noreceive = 0,
		.connecting = 1,
	};
	int i;

	printf("--- Scenario 2: alive_interval=0 disables keepalive ---\n");
	kal_attach(&v, &sp);
	now += 100;
	for (i = 0; i < 40; i++)
		kal_tick(&v);
	check(sp.echo_requests == 0,
	    "no ECHO_REQs when alive_interval=0 (even with a dead peer)");
	check(sp.timeouts == 0,
	    "no timeout when alive_interval=0 (the check is unreachable)");
	kal_detach(&v, &sp);
	printf("--- Scenario 2 done ---\n");
	return failures - prev;
}

/* ---- scenario 4: PP_IFDOWN schedules the if_down work on timeout. ---- */
static int
scenario_ifdown(void)
{
	int prev = failures;
	struct kal_vnet v = { .interval = DEFAULT_KEEPALIVE_INTERVAL };
	struct kal_if sp = {
		.dev_flags = PP_DEVF_KEEPALIVE,
		.phase = PPP_PHASE_AUTHENTICATE,
		.alive_interval = 1,
		.maxalive = 3,
		.max_noreceive = 0,
		.connecting = 1,
		.flags = PP_IFDOWN,
	};
	int i;

	printf("--- Scenario 3: PP_IFDOWN -> if_down work on timeout ---\n");
	kal_attach(&v, &sp);
	for (i = 0; i < 4; i++)
		kal_tick(&v);
	check(sp.timeouts == 1, "timeout fires (tick 4: 3 unanswered + 1)");
	check(sp.ifdown_works == 1,
	    "PP_IFDOWN set: work_ifdown scheduled together with close+open");
	kal_detach(&v, &sp);
	printf("--- Scenario 3 done ---\n");
	return failures - prev;
}

/* ---- scenario 5: per-vnet independence (the VNET_DEFINE change). ---- */
static int
scenario_per_vnet(void)
{
	int prev = failures;
	struct kal_vnet va = { .interval = 10 };
	struct kal_vnet vb = { .interval = 10 };
	struct kal_if a = {
		.dev_flags = PP_DEVF_KEEPALIVE,
		.phase = PPP_PHASE_AUTHENTICATE,
		.alive_interval = 1, .maxalive = 3,
		.max_noreceive = 15, .connecting = 1,
	};
	struct kal_if b = {
		.dev_flags = PP_DEVF_KEEPALIVE,
		.phase = PPP_PHASE_AUTHENTICATE,
		.alive_interval = 1, .maxalive = 3,
		.max_noreceive = 15, .connecting = 1,
	};
	int i;

	printf("--- Scenario 4: per-vnet keepalive state is independent ---\n");
	kal_attach(&va, &a);
	kal_attach(&vb, &b);

	/* vnet A's peer dies; vnet B's keeps answering (fresh receives). */
	now += 20;
	for (i = 0; i < 40; i++) {
		kal_receive(&b);		/* B keeps answering */
		kal_tick(&va);		/* A's tick counter advances alone */
		kal_tick(&vb);		/* B's tick counter advances alone */
	}
	check(a.timeouts >= 1, "vnet A: dead peer timed out");
	check(a.echo_requests > 0, "vnet A: ECHO_REQs flew once grace elapsed");
	check(b.timeouts == 0, "vnet B: healthy peer never times out");
	check(b.echo_requests == 0,
	    "vnet B: no ECHO_REQs while its peer stays fresh");
	check(va.tick_cnt == 40 && vb.tick_cnt == 40,
	    "tick counters are per-vnet (no shared modulo)");
	/* Interleaving A's ticks into B's list must be impossible by
	 * construction: each vnet owns its list head. */
	check(va.head == &a && vb.head == &b && va.head != vb.head,
	    "each vnet owns a distinct list head");

	kal_detach(&va, &a);
	kal_detach(&vb, &b);
	check(va.tick_cnt == 40 && vb.tick_cnt == 40,
	    "detach does not disturb the sibling vnet's counter");
	printf("--- Scenario 4 done ---\n");
	return failures - prev;
}

/* ---- scenario 6: clone destroy during a keepalive storm, x10 rounds. ---- */
static int
scenario_detach_storm(void)
{
	int prev = failures;
	struct kal_vnet v = { .interval = DEFAULT_KEEPALIVE_INTERVAL };
	struct kal_if ifs[10];
	int round, i;

	printf("--- Scenario 5: detach storm (10 ifaces under an echo "
	    "storm), repeated 10x ---\n");
	for (round = 0; round < 10; round++) {
		int live = 0;
		char msg[96];

		/* Storm: at every tick, every attached iface receives a
		 * reply AND sends echo requests (alive_interval=1,
		 * max_noreceive=0 -> keepalives every tick). */
		for (i = 0; i < 10; i++) {
			memset(&ifs[i], 0, sizeof(ifs[i]));
			ifs[i].dev_flags = PP_DEVF_KEEPALIVE;
			ifs[i].phase = PPP_PHASE_AUTHENTICATE;
			ifs[i].alive_interval = 1;
			ifs[i].maxalive = 3;
			ifs[i].max_noreceive = 0;
			ifs[i].connecting = 1;
			kal_attach(&v, &ifs[i]);
			live++;
		}
		for (i = 0; i < 12; i++) {
			int j;
			for (j = 0; j < 10; j++)
				if (ifs[j].connecting)
					kal_receive(&ifs[j]);
			kal_tick(&v);
		}
		/* Clone destroy storm: destroy half, then the rest. */
		for (i = 0; i < 10; i += 2) {
			kal_detach(&v, &ifs[i]);
			ifs[i].connecting = 0;
			live--;
		}
		kal_tick(&v);		/* keepalives keep firing mid-destroy */
		for (i = 1; i < 10; i += 2) {
			/* interleave a keepalive tick between destroys */
			if (i == 3)
				kal_tick(&v);
			kal_detach(&v, &ifs[i]);
			ifs[i].connecting = 0;
			live--;
		}
		check(live == 0, "round: every interface detached");
		check(v.head == NULL, "round: list empty after storm");
		check(v.callout_armed == 0,
		    "round: last detach stopped the callout");
		/* A tick on an empty, stopped list must be a no-op. */
		kal_tick(&v);
		check(v.callout_armed == 0 && v.tick_cnt > 0,
		    "round: no spurious re-arm after stop");
		snprintf(msg, sizeof(msg), "round %d of 10 complete", round);
		check(1, msg);
	}
	printf("--- Scenario 5 done ---\n");
	return failures - prev;
}

int
main(void)
{
	int rc;

	printf("sppp_keepalive: LCP keepalive FSM model (M002/S03/T2)\n");
	printf("model: maxalive=%d alive_interval=%d max_noreceive=%ds "
	    "per-vnet list/tick\n",
	    DEFAULT_MAXALIVECNT, DEFAULT_ALIVE_INTERVAL,
	    DEFAULT_NORECV_TIME);

	rc = scenario_dead_peer();
	rc += scenario_disabled();
	rc += scenario_ifdown();
	rc += scenario_per_vnet();
	rc += scenario_detach_storm();

	if (failures == 0)
		printf("\nALL ASSERTIONS PASSED -- harness exit 0\n");
	else
		printf("\n%d ASSERTION(S) FAILED\n", failures);
	exit(failures == 0 ? 0 : 1);
}