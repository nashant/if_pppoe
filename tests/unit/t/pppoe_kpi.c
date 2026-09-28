/* FreeBSD KPI hygiene: the bpf(4) link type against the bytes tapped, the
 * RX metadata reset when rcvif becomes pppoeN and the module taskqueue --
 * sys/net/if_pppoe.c.
 * Included after pppoe_session.c, whose sess_* fixtures it reuses. */
#include "ktest.h"
#include "frames.h"

/* DLT_PPP: address, control, then the protocol field (net/ppp_defs.h). */
static const uint8_t kpi_hdlc[2] = { PPP_ALLSTATIONS, PPP_UI };

static void
kpi_expect_tap(struct ifnet *ifp, const void *ppp, int n)
{
	uint8_t got[KSHIM_BPF_SNAP];
	int len;

	KT_ASSERT(kshim_bpf_last(got, &len) == ifp);
	KT_EQ(len, (int)sizeof(kpi_hdlc) + n);
	KT_MEMEQ(got, kpi_hdlc, sizeof(kpi_hdlc));
	KT_MEMEQ(got + sizeof(kpi_hdlc), ppp, n);
}

/* What the PADS arm does once the session is final (if_pppoe_disc.c). */
static void
kpi_publish_txsnap(struct pppoe_softc *sc)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	PPPOE_SC_LOCK(sc);
	pppoe_tx_snap_publish(sc, malloc_aligned(sizeof(struct pppoe_tx_snap),
	    CACHE_LINE_SIZE, M_PPPOE, M_WAITOK | M_ZERO));
	PPPOE_SC_UNLOCK(sc);
	NET_EPOCH_EXIT(et);
}

KTEST(pppoe_bpf, attached_as_dlt_ppp)
{
	struct pppoe_softc *sc = fx_pppoe_new();

	KT_EQ(sc->sc_ifp->kshim_dlt, DLT_PPP);
	KT_EQ(sc->sc_ifp->kshim_bpf_hdrlen, PPP_HDRLEN);
	fx_pppoe_free(sc);
}

KTEST(pppoe_bpf, rx_tap_is_hdlc_framed)
{
	struct epoch_tracker et;
	struct sess_fx x;
	struct fr f;
	/* IP while IPCP is closed: tapped, then dropped by sppp_input(). */
	uint8_t ppp[] = { 0x00, 0x21, 0x45, 0, 0, 20 };
	struct mbuf *m;

	sess_setup(&x, 0x1234);
	sess_frame(&f, 0x1234, ppp, sizeof(ppp));
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	m = kshim_netisr_pop();
	KT_ASSERT(m != NULL);
	kshim_bpf_reset();
	NET_EPOCH_ENTER(et);
	pppoe_data_input(m);
	NET_EPOCH_EXIT(et);
	KT_EQ(kshim_bpf_taps(), 1);
	kpi_expect_tap(x.sc->sc_ifp, ppp, sizeof(ppp));
	sess_teardown(&x);
}

KTEST(pppoe_bpf, tx_tap_is_hdlc_framed_on_both_paths)
{
	struct epoch_tracker et;
	struct sess_fx x;
	uint8_t ip[] = { 0x45, 0, 0, 20 };
	uint8_t lcp[] = { 0xc0, 0x21, 9, 1, 0, 8, 0, 0, 0, 0 };
	uint8_t want[2 + sizeof(ip)];
	uint16_t proto = htons(PPP_IP);
	struct ifnet *ifp;

	sess_setup(&x, 0x1234);
	kpi_publish_txsnap(x.sc);
	ifp = x.sc->sc_ifp;

	/* sppp_output()'s path: the protocol field comes separately. */
	kshim_bpf_reset();
	NET_EPOCH_ENTER(et);
	KT_EQ(pppoe_encap_output(x.sc, ifp, kshim_mbuf_from(ip, sizeof(ip)),
	    &proto), 0);
	NET_EPOCH_EXIT(et);
	memcpy(want, &proto, 2);
	memcpy(want + 2, ip, sizeof(ip));
	KT_EQ(kshim_bpf_taps(), 1);
	kpi_expect_tap(ifp, want, sizeof(want));

	/* if_transmit's path: the frame already carries it. */
	kshim_bpf_reset();
	KT_EQ(pppoe_transmit(ifp, kshim_mbuf_from(lcp, sizeof(lcp))), 0);
	KT_EQ(kshim_bpf_taps(), 1);
	kpi_expect_tap(ifp, lcp, sizeof(lcp));

	kshim_tx_flush(x.parent);
	sess_teardown(&x);
}

/* The parent's RX metadata describes the outer frame, not pppoeN's
 * payload: it all goes when rcvif is rewritten (if_gif.c/if_gre.c). */
KTEST(pppoe_sess_input, stale_rx_metadata_cleared)
{
	struct sess_fx x;
	struct fr f;
	uint8_t ppp[] = { 0x00, 0x21, 0x45, 0, 0, 20 };
	struct mbuf *m;

	sess_setup(&x, 0x1234);
	x.sc->sc_ifp->if_fib = 2;
	sess_frame(&f, 0x1234, ppp, sizeof(ppp));
	m = kshim_mbuf_chain(f.b, (int)f.len, 16);
	m->m_pkthdr.rcvif = x.parent;
	m->m_flags |= M_PROTO1 | M_PROTO5;
	m->m_next->m_flags |= M_PROTO2;
	m->m_pkthdr.csum_flags = CSUM_IP_CHECKED | CSUM_IP_VALID |
	    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
	m->m_pkthdr.fibnum = 7;
	m->m_flags |= M_VLANTAG;
	m->m_pkthdr.ether_vtag = EVL_MAKETAG(0, 5, 0);	/* priority-tagged, VID 0 */
	KT_EQ(fx_pfil_in(x.parent, &m), PFIL_CONSUMED);
	m = kshim_netisr_pop();
	KT_ASSERT(m != NULL);
	KT_ASSERT(m->m_pkthdr.rcvif == x.sc->sc_ifp);
	for (struct mbuf *n = m; n != NULL; n = n->m_next)
		KT_EQ(n->m_flags & M_PROTOFLAGS, 0);
	KT_EQ(m->m_pkthdr.csum_flags, 0);
	KT_EQ(m->m_pkthdr.fibnum, 2);
	KT_EQ(m->m_flags & M_VLANTAG, 0);
	m_freem(m);
	sess_teardown(&x);
}

/* Deferred work runs on the module's own single-threaded taskqueue, never
 * on the shared taskqueue_thread. */
KTEST(pppoe_taskq, deferred_work_stays_off_taskqueue_thread)
{
	struct sess_fx x;
	int shared0 = taskqueue_thread->tq_enqueued, own0;
	uint8_t confreq[] = { 0xc0, 0x21, 1, 1, 0, 4 };
	struct epoch_tracker et;
	struct fr f;

	KT_ASSERT(pppoe_taskq != NULL && pppoe_taskq != taskqueue_thread);
	KT_EQ(pppoe_taskq->tq_threads, 1);	/* one thread: FIFO order */
	own0 = pppoe_taskq->tq_enqueued;
	sess_setup(&x, 0x1234);	/* session task, pp_up()'s work */
	sess_frame(&f, 0x1234, confreq, sizeof(confreq));
	KT_EQ(sess_deliver(&x, &f, 0), PFIL_CONSUMED);
	NET_EPOCH_ENTER(et);
	pppoe_data_input(kshim_netisr_pop());	/* LCP: sppp work items */
	NET_EPOCH_EXIT(et);
	kshim_run_tasks();
	kshim_tx_flush(x.parent);
	sess_teardown(&x);
	KT_EQ(taskqueue_thread->tq_enqueued, shared0);
	KT_ASSERT(pppoe_taskq->tq_enqueued > own0 + 1);
}

/* A MOD_LOAD that fails is followed at once by MOD_UNLOAD
 * (kern_module.c:121-123), and linker_load_file() still runs the file's
 * other SYSINITs, pppoe_vnet_init() among them, before unloading it
 * (kern_linker.c:480, :488).  Neither may act on a module that never
 * finished loading: no NULL-tag deregister, no NULL taskqueue. */
KTEST(pppoe_taskq, failed_load_unwinds_nothing_it_did_not_do)
{
	struct taskqueue *tq = pppoe_taskq;
	eventhandler_tag dt = pppoe_ifdetach_tag, at = pppoe_ifattach_tag;
	jmp_buf jb, *saved = kshim_panic_jmp;
	int error;
	volatile int uerror = -1;
	volatile int panicked = 0;

	/* What a fresh load has before MOD_LOAD registers them. */
	pppoe_ifdetach_tag = pppoe_ifattach_tag = NULL;
	kshim_taskq_start_fail = ENOMEM;
	error = pppoe_modevent(NULL, MOD_LOAD, NULL);
	kshim_taskq_start_fail = 0;
	kshim_panic_jmp = &jb;
	if (setjmp(jb) == 0)
		uerror = pppoe_modevent(NULL, MOD_UNLOAD, NULL);
	else
		panicked = 1;
	kshim_panic_jmp = saved;
	pppoe_taskq = tq;
	pppoe_ifdetach_tag = dt;
	pppoe_ifattach_tag = at;
	KT_EQ(error, ENOMEM);
	KT_EQ(panicked, 0);
	KT_EQ(uerror, 0);
}

KTEST(pppoe_taskq, vnet_init_after_failed_load_does_nothing)
{
	struct taskqueue *tq = pppoe_taskq;
	struct if_clone *cloner = V_pppoe_cloner;
	pfil_hook_t hook = V_pppoe_pfil_hook;
	struct pppoe_stats stats = V_pppoe_stats;
	jmp_buf jb, *saved = kshim_panic_jmp;
	volatile int panicked = 0;
	bool touched;

	pppoe_taskq = NULL;
	kshim_panic_jmp = &jb;
	if (setjmp(jb) == 0)
		pppoe_vnet_init(NULL);
	else
		panicked = 1;
	kshim_panic_jmp = saved;
	pppoe_taskq = tq;
	touched = V_pppoe_cloner != cloner || V_pppoe_pfil_hook != hook ||
	    memcmp(&V_pppoe_stats, &stats, sizeof(stats)) != 0;
	V_pppoe_cloner = cloner;
	V_pppoe_pfil_hook = hook;
	V_pppoe_stats = stats;
	KT_EQ(panicked, 0);
	KT_ASSERT(!touched);
}

/* Where a SYSINIT sits: its (subsystem, order) key as one number. */
static uint64_t
kpi_si_key(int kind, const char *func)
{
	u_int sub, order;

	KT_EQ(kshim_sysinit_find(kind, func, &sub, &order), 0);
	return (((uint64_t)sub << 32) | order);
}

#define	KPI_KEY(sub, order)	((uint64_t)(sub) << 32 | (order))

/* vnet_ether_init() creates V_link_pfil_head at SI_SUB_PROTO_IF
 * (if_ethersubr.c:795); the hook cannot link to it any earlier. */
KTEST(pppoe_vnet, init_not_before_link_pfil_head)
{
	uint64_t pppoe = kpi_si_key(KSHIM_VNET_SYSINIT, "pppoe_vnet_init");

	KT_ASSERT(pppoe >= KPI_KEY(SI_SUB_PROTO_IF, SI_ORDER_ANY));
	/* sppp's per-vnet keepalive list is up before the cloner. */
	KT_ASSERT(pppoe >
	    kpi_si_key(KSHIM_VNET_SYSINIT, "sppp_keepalive_vnet_init"));
}

/* Destructors run largest key first (vnet.c:605, kern_linker.c:264-274):
 * clones and hook go while the link pfil head and sppp's keepalive list
 * still exist, and the taskqueue their destroys drain goes last. */
KTEST(pppoe_vnet, uninit_ordering)
{
	uint64_t pppoe = kpi_si_key(KSHIM_VNET_SYSUNINIT, "pppoe_vnet_uninit");
	uint64_t ka = kpi_si_key(KSHIM_VNET_SYSUNINIT,
	    "sppp_keepalive_vnet_uninit");

	KT_ASSERT(pppoe > KPI_KEY(SI_SUB_PROTO_PFIL, SI_ORDER_ANY));
	KT_ASSERT(pppoe > ka);
	KT_ASSERT(kpi_si_key(KSHIM_SYSUNINIT, "pppoe_taskq_fini") < ka);
}
