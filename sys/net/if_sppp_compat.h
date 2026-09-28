/*	$NetBSD$	*/

/*
 * FreeBSD port layer for the vendored NetBSD sppp(4) sources.
 *
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sys/net/{if_sppp.h,
 * if_spppvar.h, if_spppsubr.c}.
 *
 * Every row of the NetBSD KPI -> FreeBSD 14.3 KPI table in
 * docs/PORTING-sppp.md is implemented here unless the table's "How"
 * column says the call site is edited directly.  Rows stay at Status
 * `planned` until the S01 compile+link loop (T3) proves them; rows the
 * loop needs but this header does not map become new table rows there.
 *
 * This header is included TWICE from if_spppvar.h:
 *   1. at the top of if_spppvar.h  -> section A only: the KPI typedefs
 *      and macros that do not depend on the vendored structs.
 *   2. after struct sppp_work / struct sppp are defined -> section B:
 *      the sppp-dependent shim surface (struct workqueue with its single
 *      per-interface task on the module pppoe_taskq, the
 *      sppp_wq_* functions, sppp_from_ifp(), SPPPSUBR_MPSAFE).  Section A is single-evaluated so the second
 *      include only expands section B (which is gated on
 *      SPPP_COMPAT_STRUCTS_READY, defined by if_spppvar.h just before
 *      the second include).
 */

#ifndef _NET_IF_SPPP_COMPAT_H_
#define _NET_IF_SPPP_COMPAT_H_

/* ------------------------------------------------------------------ *
 * Section A: FreeBSD 14.3 KPI mapping (no struct sppp dependency).
 * ------------------------------------------------------------------ */

#ifdef _KERNEL

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/callout.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>
#include <sys/md5.h>
#include <sys/libkern.h>
#include <sys/priv.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/stdint.h>
#include <sys/_stdarg.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
/* sppp reads struct ifnet directly; 15.x if_var.h no longer includes it. */
#include <net/if_private.h>
#include <net/route.h>
#include <net/ppp_defs.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#ifdef INET
#include <netinet/tcp.h>
#endif
#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#endif

/*
 * One allocation zone for all sppp state (the softc-embed contract in
 * docs/PORTING-sppp.md).  if_pppoe.c holds the MALLOC_DEFINE; this
 * declaration makes M_PPPOE visible to the vendored sources.
 */
MALLOC_DECLARE(M_PPPOE);

struct sppp;
struct sppp_work;
struct workqueue;

/* NetBSD malloc(9) how-argument constants (NetBSD sys/sys/malloc.h). */
#define	KM_SLEEP	1	/* caller may block */
#define	KM_NOSLEEP	0	/* caller must not block */

/*
 * kmem_* -> malloc(9)/free(9) with M_PPPOE.
 *
 * NetBSD kmem_zalloc zeroes, kmem_alloc does not; KM_SLEEP -> M_WAITOK,
 * KM_NOSLEEP -> M_NOWAIT.  kmem_free/kmem_intr_free drop the size
 * argument (FreeBSD's free(9) tracks sizes in the zone).  All
 * sppp_input control-path allocations are M_NOWAIT (calling-context
 * rule 2, audited in T2 Step 4).
 */
#define	kmem_zalloc(_sz, _how)	malloc((_sz), M_PPPOE, M_WAITOK | M_ZERO)
#define	kmem_alloc(_sz, _how)	malloc((_sz), M_PPPOE, \
				((_how) == KM_NOSLEEP) ? M_NOWAIT : M_WAITOK)
#define	kmem_free(_p, _sz)	free((_p), M_PPPOE)
#define	kmem_intr_alloc(_sz, _how)	malloc((_sz), M_PPPOE, M_NOWAIT)
#define	kmem_intr_free(_p, _sz)	free((_p), M_PPPOE)

/*
 * callout_t -> struct callout.
 *
 * NetBSD's callout_init(c, CALLOUT_MPSAFE) + callout_setfunc(c, f, a) +
 * callout_schedule(c, ticks) collapses onto FreeBSD's callout_init(c, 1)
 * (MPSAFE) + callout_reset(c, on_ticks, f, a); c_func/c_arg carry the
 * handler between init and schedule.  (The pre-S02 mapping was
 * callout_init_mtx(c, NULL, 0), which is a softclock page fault -- see
 * the fix note under callout_init below.)  callout_halt/callout_destroy
 * both become callout_drain (embedded struct callout needs no
 * destructor; drain is the race-free teardown).
 */
typedef struct callout callout_t;

/*
 * NetBSD callout_init(c, CALLOUT_MPSAFE) -> FreeBSD callout_init(c, 1)
 * (the MPSAFE variant).  The pre-S02 spelling -- callout_init_mtx(c, NULL,
 * 0) -- was a latent page fault: it leaves c_lock == NULL with c_iflags == 0
 * (no CALLOUT_RETURNUNLOCKED), and softclock_call_cc()'s post-handler
 * unlock (kern_timeout.c:739) then dereferences class->lc_unlock(c_lock)
 * through a NULL class -- observed as 'Fatal trap 12' at virtual address
 * 0x30 in softclock on the very first live dial (S02/T1, 2026-09-20).  The
 * MPSAFE variant sets CALLOUT_RETURNUNLOCKED, which skips that unlock; the
 * handlers self-lock (sppp_keepalive takes SPPPQ_LOCK + SPPP_LOCK; the CP
 * timeout callbacks only enqueue work).  Self-reference below is fine: the
 * macro name is not re-expanded during its own expansion, so the inner
 * callout_init(...) resolves to the real function.
 */
#define	callout_init(_c, _flags)	callout_init((_c), 1)
#define	callout_setfunc(_c, _fn, _arg)	do {				\
	(_c)->c_func = (_fn);						\
	(_c)->c_arg = (_arg);						\
} while (0)
#define	callout_schedule(_c, _ticks)	callout_reset((_c), (_ticks),	\
				(_c)->c_func, (_c)->c_arg)
#define	callout_halt(_c, _lock)		callout_drain((_c))
#define	callout_destroy(_c)		callout_drain((_c))

/*
 * krwlock_t / kmutex_t -> struct mtx.
 *
 * The sppp lock is only held for control frames, ioctls and keepalive
 * bookkeeping (spec section 9, calling-context rule 2) — a mutex is the
 * right primitive: cheaper than sx, and callouts can share it.
 * RW_READER and RW_WRITER both map to mtx_lock.
 *
 * FreeBSD's rwlock.h (arriving via systm.h) already ships rw_init/
 * rw_destroy as macros and rw_enter/rw_exit as functions over its own
 * struct rwlock; those spellings are retired before ours take effect
 * (the KPI table row is still "macro per name").
 */
typedef struct mtx krwlock_t;
typedef struct mtx kmutex_t;

#ifdef rw_init
#undef rw_init
#endif
#ifdef rw_destroy
#undef rw_destroy
#endif
#ifdef rw_enter
#undef rw_enter
#endif
#ifdef rw_exit
#undef rw_exit
#endif
#ifdef rw_write_held
#undef rw_write_held
#endif
#ifdef rw_read_held
#undef rw_read_held
#endif
#define	rw_init(_l)		mtx_init((_l), "sppp", NULL, MTX_DEF)
#define	rw_destroy(_l)		mtx_destroy((_l))
#define	rw_enter(_l, _op)	mtx_lock((_l))
#define	rw_exit(_l)		mtx_unlock((_l))
#define	rw_write_held(_l)	mtx_owned((_l))
#define	rw_read_held(_l)	mtx_owned((_l))

#define	mutex_enter(_l)		mtx_lock((_l))
#define	mutex_exit(_l)		mtx_unlock((_l))
#define	mutex_obj_alloc(_type, _ipl)	sppp_mutex_obj_alloc()

static inline kmutex_t *
sppp_mutex_obj_alloc(void)
{
	kmutex_t *m = malloc(sizeof(*m), M_PPPOE, M_WAITOK | M_ZERO);

	mtx_init(m, "spppq", NULL, MTX_DEF);
	return (m);
}

/*
 * if_statinc / if_statadd -> if_inc_counter().  FreeBSD 14.3 removed
 * the per-counter ifnet fields, so the NetBSD names map to the
 * ift_counter enum values.
 */
#define	if_ibytes	IFCOUNTER_IBYTES
#define	if_obytes	IFCOUNTER_OBYTES
#define	if_ierrors	IFCOUNTER_IERRORS
#define	if_oerrors	IFCOUNTER_OERRORS
#define	if_iqdrops	IFCOUNTER_IQDROPS
#define	if_noproto	IFCOUNTER_NOPROTO
#define	if_statinc(_ifp, _nm)	if_inc_counter((_ifp), (_nm), 1)
#define	if_statadd(_ifp, _nm, _n) if_inc_counter((_ifp), (_nm), (_n))

/*
 * Byte counters are charged once, by the lower layer: pppoe_data_input()
 * counts IPACKETS/IBYTES and pppoe_encap_output() OPACKETS/OBYTES (the
 * PPPoE payload length, PPP protocol field included), for every frame
 * including those sppp never sees (the IPv6 poke-and-drop arm).  sppp's own
 * IBYTES/OBYTES adds (sppp_input, sppp_output, sppp_cp_send and the auth
 * send path) are compiled out under this define; left in, every byte was
 * counted twice (kern.features.if_pppoe_single_bytecount).
 */
#define	SPPP_LOWER_COUNTS_BYTES	1

/*
 * cprng_* -> arc4random(9) family (sys/sys/libkern.h).  The kernel
 * generator argument (kern_cprng) is dropped.
 */
#define	cprng_fast32()		arc4random()
#define	cprng_strong32()	arc4random()
#define	cprng_strong(_gen, _buf, _len, _flags)	\
	arc4random_buf((_buf), (_len))

/*
 * kauth_authorize_network() -> priv_check(curthread, PRIV_NET_SETIFPHYS).
 * Both SETPRIV and GETPRIV ioctl arms map to the same privilege (call
 * sites edited directly in if_spppsubr.c; the vendored code also used
 * `curlwp` for the l_cred argument which FreeBSD does not have).
 */

/*
 * KASSERT(cond) (1-arg, no message) -> SPPP_KASSERT(cond), which adds
 * the mandatory message argument.  if_spppsubr.c is swept so every
 * bare KASSERT() call becomes SPPP_KASSERT() (T2 Step 3).
 */
#define	SPPP_KASSERT(_cond)	KASSERT((_cond), ("%s", __func__))

/* NetBSD sys/sys/bitops.h helpers. */
#define	__BIT(_n)			(1 << (_n))
#define	ISSET(_x, _v)			((_x) & (_v))
#define	SET(_x, _v)			((_x) |= (_v))
#define	CLR(_x, _v)			((_x) &= ~(_v))

/*
 * __read_mostly: FreeBSD 14.3 systm.h already defines it as
 * __section(".data.read_mostly") — no compat redefinition (a bare
 * empty #define would collide with -Werror,-Wmacro-redefined).
 */

/*
 * NetBSD relaxed atomics.  FreeBSD 14.3 has no atomic_load_relaxed/
 * atomic_store_relaxed KPI, so the relaxed read/write is a plain
 * volatile access: exactly NetBSD's contract for these flags (no
 * ordering, just single-copy atomicity for word-sized aligned fields).
 * All targets here are bool/uint32 fields (pp_connecting, pp_ondemand,
 * pp_last_receive/activity) or the int-typed RPS global, so an aligned
 * 32-bit load/store is what the hardware performs anyway.
 * atomic_load_acquire and atomic_store_release are only used inside the
 * un-ported SPPP_FILTER blocks (compiled out) but are defined for
 * completeness.
 */
#define	atomic_load_relaxed(_x)		(*(_x))
#define	atomic_store_relaxed(_x, _v)	((*(_x)) = (_v))
#define	atomic_load_acquire(_x)		(*(_x))
#define	atomic_store_release(_x, _v)	((*(_x)) = (_v))

/*
 * __predict_true/__predict_false: defined by FreeBSD cdefs.h itself
 * (as __builtin_expect) — no compat redefinition needed.
 */

/* __UNCONST exists on FreeBSD cdefs.h; this is just belt-and-braces. */
#ifndef __UNCONST
#define	__UNCONST(_x)		((void *)(uintptr_t)(_x))
#endif

/*
 * IFF_RUNNING exists in FreeBSD net/if.h only under #ifndef _KERNEL (a
 * userland alias).  It is deliberately NOT aliased here: the value is
 * IFF_DRV_RUNNING, but that bit lives in if_drv_flags, and an alias let
 * the vendored `if_flags |= IFF_RUNNING` compile into a write of an unused
 * if_flags bit.  The call sites use if_setdrvflagbits()/if_getdrvflags()
 * directly, so any new IFF_RUNNING use is a compile error.
 */

/* NetBSD per-interface ifnet lock -> FreeBSD global ifnet sx lock
 * (the only ifnet lock FreeBSD 14.3 ships; the sites are MTU-adjust
 * arms that want the interface-wide lock). */
#ifndef IFNET_LOCK
#define	IFNET_LOCK(_ifp)	IFNET_WLOCK()
#define	IFNET_UNLOCK(_ifp)	IFNET_WUNLOCK()
#endif

/* NetBSD sys/once.h: ONCE_DECL + RUN_ONCE -> atomic cmpset guard. */
#define	ONCE_DECL(_o)	int _o = 0;
#define	RUN_ONCE(_o, _fn)	do {				\
	if (atomic_cmpset_int((_o), 0, 1))			\
		(_fn)();					\
} while (0)

/*
 * NetBSD log()/addlog() record assembly lives in if_spppsubr.c (its only
 * user): sppp_log()/sppp_addlog() and the addlog() spelling.  It needs
 * module-wide state and a lock, which a header cannot define once.
 */

/* NetBSD scheduler/workqueue constants used as real call arguments to
 * the sppp_wq_create() shim (FreeBSD has no equivalent enum). */
#ifndef PRI_SOFTNET
#define	PRI_SOFTNET	0
#endif
#ifndef IPL_SOFTNET
#define	IPL_SOFTNET	0
#endif
#ifndef WQ_MPSAFE
#define	WQ_MPSAFE	0
#endif

/* NetBSD-only ioctl the vendored ioctl switch still labels (no-op arm,
 * S03 owns route semantics).  Value matches NetBSD _IOW('i', 122,
 * struct ifreq) and cannot collide with the FreeBSD cases used here
 * (16, 49, 50, 51, 52). */
#ifndef SIOCINITIFADDR
#define	SIOCINITIFADDR	_IOW('i', 122, struct ifreq)
#endif

/* FreeBSD does not ship PRI* in kernel headers; amd64 uint64_t == ulong. */
#ifndef PRIu64
#define	PRIu64	"lu"
#endif

/*
 * The module's own taskqueue (if_pppoe.c: created at MOD_LOAD, drained
 * and freed after the last VNET_SYSUNINIT).  One thread, so it keeps the
 * FIFO order across tasks that the comments here and in if_spppsubr.c
 * rely on, without queueing behind -- or ahead of -- the rest of the
 * kernel's taskqueue_thread work.
 */
extern struct taskqueue *pppoe_taskq;

/*
 * Basic two-phase lock-free work queue types used by section B.  The
 * per-interface queue keeps ONE struct task on the module-level
 * pppoe_taskq plus a FIFO of pending sppp_work items chained by
 * wq_next (research amendment 4: no struct task embedded per work
 * item).  wq_mtx is a spin mutex: sppp_wq_add() may run from the netisr
 * RX path / callout context (never sleep), which mtx_lock() (the
 * sleep-mutex primitive) excludes -- under INVARIANTS it KASSERT-panics
 * on a spin mutex (MEM094, caught by the SMPW run).  All wq_mtx access
 * therefore uses mtx_lock_spin()/mtx_unlock_spin(), and the only
 * sleepable call in these paths -- taskqueue_enqueue(), which takes the
 * taskqueue's own MTX_DEF -- is issued OUTSIDE the spin mutex.
 */
#define	M_DONTWAIT	M_NOWAIT

#ifndef m_reset_rcvif
#define	m_reset_rcvif(_m)	do { (_m)->m_pkthdr.rcvif = NULL; } while (0)
#endif

/*
 * M_REGION_GET(p, T, m, off, len): pull the region contiguous and
 * return a typed pointer.  The vendored source has no callers at the
 * pin; defined for KPI-table completeness.
 */
#define	M_REGION_GET(_p, _T, _m, _off, _len)	do {			\
	(_m) = m_pullup((_m), (_off) + (_len));				\
	(_p) = (_T *)mtod((_m), uint8_t *) + (_off);			\
} while (0)

/* bpf_mtap(ifp, m, dir) — the direction argument is implicit in call. */
#define	bpf_mtap(_ifp, _m, _dir)	if_bpfmtap((_ifp), (_m))

/*
 * NetBSD pktqueue plumbing -> direct IP input.  NetBSD dispatches
 * payload IP frames through per-CP pktqueue objects (ip_pktq / ip6_pktq)
 * with an async RPS hash; FreeBSD has no equivalent, so sppp_input()
 * (the netisr path) hands PPP_IP / PPP_IPV6 straight to ip_input() /
 * ip6_input() with no second dispatch (spec section 6.5).  The pktq
 * selector struct preserves the vendored NULL/selector comparisons.
 * pktq_rps_hash_func_t is a pointer type so the vendored `func = NULL`
 * spellings type-check; the hash itself is always 0 (RPS not ported).
 */
struct sppp_pktq {
	int	proto;		/* AF_INET / AF_INET6 selector */
};
static struct sppp_pktq sppp_pktq_ip = { AF_INET };
#ifdef INET6
static struct sppp_pktq sppp_pktq_ip6 = { AF_INET6 };
#endif
typedef struct sppp_pktq pktqueue_t;
#define	ip_pktq		(&sppp_pktq_ip)
#ifdef INET6
#define	ip6_pktq	(&sppp_pktq_ip6)
#endif
#define	pktq_rps_hash_func_t	void *
#define	pktq_rps_hash(_fp, _m)	0

static inline bool
pktq_enqueue(pktqueue_t *pktq, struct mbuf *m, uint32_t hash __unused)
{
	if (pktq == ip_pktq) {
		ip_input(m);
		return true;
	}
#ifdef INET6
	if (pktq == ip6_pktq) {
		ip6_input(m);
		return true;
	}
#endif
	m_freem(m);
	return false;
}

/*
 * Legacy ifqueue macro names used by the vendored source that do not
 * exist in FreeBSD ifq.h.  if_snd is a struct ifaltq whose first five
 * fields match struct ifqueue, so FreeBSD's IFQ_* macros work on
 * &ifp->if_snd unchanged; the IF_* aliases below bridge the NetBSD
 * spellings.  IF_DROP drops one packet (NetBSD semantics).
 */
#ifndef IF_QFULL
#define	IF_QFULL(_ifq)		_IF_QFULL((_ifq))
#endif
#ifndef IF_IS_EMPTY
#define	IF_IS_EMPTY(_ifq)	IFQ_IS_EMPTY((_ifq))
#endif
#ifndef IF_PURGE
#define	IF_PURGE(_ifq)		IFQ_PURGE((_ifq))
#endif
#ifndef IF_DROP
#define	IF_DROP(_ifq)	do {					\
	struct mbuf *__m;					\
	IFQ_DEQUEUE((_ifq), __m);				\
	if (__m != NULL)					\
		m_freem(__m);					\
} while (0)
#endif

/* ALTQ-era classifier hook: a no-op on FreeBSD. */
#ifndef IFQ_CLASSIFY
#define	IFQ_CLASSIFY(_ifq, _m, _af)	do { (void)(_af); } while (0)
#endif

/* if_transmit_lock() was folded into if_transmit() on FreeBSD 14. */
#define	if_transmit_lock(_ifp, _m)	if_transmit((_ifp), (_m))

/* No cpu_softintr_p() on FreeBSD; the work handlers documented by
 * KASSERT(!cpu_softintr_p()) run on pppoe_taskq only, and this
 * tree has no software-interrupt-unsafe code path in sppp, so the
 * predicate is always false. */
static inline bool
cpu_softintr_p(void)
{
	return (false);
}

/* NetBSD seconds-since-boot counter. */
#define	time_uptime32	((uint32_t)time_uptime)

/* ppp_defs.h misses on FreeBSD's copy. */
#ifndef PPP_MINMRU
#define	PPP_MINMRU	128
#endif
#ifndef PPP_NOPROTO
#define	PPP_NOPROTO	0
#endif

#ifdef INET6
/* IN6_PRINT is not in FreeBSD; use inet_ntop() into the caller's buf. */
#ifndef IN6_PRINT
static inline const char *
sppp_in6_print(char *buf, const struct in6_addr *a)
{
	return (inet_ntop(AF_INET6, a, buf, INET6_ADDRSTRLEN));
}
#define	IN6_PRINT(_b, _a)	sppp_in6_print((_b), (_a))
#endif
#endif

#endif /* _KERNEL */
#endif /* _NET_IF_SPPP_COMPAT_H_ */

/*
 * Section B: sppp-dependent shim surface.  Expanded on the second
 * include from if_spppvar.h, after struct sppp_work / struct sppp.
 */
#ifdef SPPP_COMPAT_STRUCTS_READY
#ifndef SPPP_COMPAT_STRUCTS_DEFINED
#define	SPPP_COMPAT_STRUCTS_DEFINED

/* Compile the MPSAFE direct-transmit tail of sppp_output() in. */
#ifndef SPPPSUBR_MPSAFE
#define	SPPPSUBR_MPSAFE	1
#endif

struct workqueue {
	struct task	 wq_task;	/* one task on pppoe_taskq */
	struct sppp	*wq_sp;		/* owning interface */
	struct mtx	 wq_mtx;	/* spin lock for the FIFO */
	bool		 wq_pending;	/* task enqueued (hint) */
	struct sppp_work *wq_head;	/* FIFO head */
	struct sppp_work *wq_tail;	/* FIFO tail */
};

static void
sppp_wq_task(void *ctx, int pending)
{
	struct workqueue *wq = ctx;
	struct sppp_work *work;

	(void)pending;		/* task_fn_t carries a pending hint */

	mtx_lock_spin(&wq->wq_mtx);
	wq->wq_pending = false;
	mtx_unlock_spin(&wq->wq_mtx);

	for (;;) {
		mtx_lock_spin(&wq->wq_mtx);
		work = wq->wq_head;
		if (work != NULL) {
			wq->wq_head = work->wq_next;
			if (wq->wq_head == NULL)
				wq->wq_tail = NULL;
		}
		mtx_unlock_spin(&wq->wq_mtx);
		if (work == NULL)
			break;

		/*
		 * NetBSD ran the work dequeued from a per-CP workqueue under
		 * the sppp lock; the state-machine actions it invokes
		 * (sppp_wq_* -> sppp_*_event) expect SPPP_WLOCKED(sp).  Keep
		 * that contract.
		 *
		 * Clear BUSY before invoking (as NetBSD did): a handler that
		 * re-enqueues the same work item must not be dropped by a
		 * stale BUSY.
		 *
		 * curvnet: pppoe_taskq carries no vnet, but the handlers
		 * transmit through if_transmit() -> the driver's
		 * pppoe_transmit(), which reads per-vnet state (V_pppoe_stats,
		 * V_link_pfil_head via ether_output_frame) and -- from S03 --
		 * applies addresses via in_control_ioctl().  M001 ruling #3
		 * requires CURVNET_SET on every taskqueue path touching
		 * V_ state; the S2 spike proved this exact recipe.
		 */
		atomic_cmpset_int((int *)&work->state,
		    SPPP_WK_BUSY, SPPP_WK_FREE);
		CURVNET_SET(if_getvnet(wq->wq_sp->pp_if));
		mtx_lock(&wq->wq_sp->pp_lock);
		work->func(wq->wq_sp, work->arg);
		mtx_unlock(&wq->wq_sp->pp_lock);
		CURVNET_RESTORE();
	}
}

#define	SPPP_WQ_TASK_PRIO	0

static struct workqueue *
sppp_wq_create(struct sppp *sp, const char *name, int prio,
    int ipl __unused, int flags __unused)
{
	struct workqueue *wq = malloc(sizeof(*wq), M_PPPOE, M_WAITOK | M_ZERO);

	wq->wq_sp = sp;
	mtx_init(&wq->wq_mtx, "sppp_wq", NULL, MTX_SPIN);
	TASK_INIT(&wq->wq_task, SPPP_WQ_TASK_PRIO, sppp_wq_task, wq);
	(void)name;
	return (wq);
}

static void
sppp_wq_destroy(struct sppp *sp __unused, struct workqueue *wq)
{
	taskqueue_drain(pppoe_taskq, &wq->wq_task);
	mtx_destroy(&wq->wq_mtx);
	free(wq, M_PPPOE);
}

static void
sppp_wq_set(struct sppp_work *work,
    void (*func)(struct sppp *, void *), void *arg)
{
	work->func = func;
	work->arg = arg;
	work->wq_next = NULL;
}

/*
 * sppp_wq_add() is sleep-free and safe from any context (netisr RX,
 * callout, ioctl): it only CASes the item state and pushes a pointer.
 * State CAS: FREE -> BUSY; a second add of the same item is dropped.
 */
static void
sppp_wq_add(struct workqueue *wq, struct sppp_work *work)
{
	bool enqueue;

	KASSERT(work->func != NULL, ("%s: NULL func", __func__));

	if (!atomic_cmpset_int((int *)&work->state,
	    SPPP_WK_FREE, SPPP_WK_BUSY))
		return;			/* already queued / unavailable */

	mtx_lock_spin(&wq->wq_mtx);
	work->wq_next = NULL;
	if (wq->wq_tail != NULL)
		wq->wq_tail->wq_next = work;
	else
		wq->wq_head = work;
	wq->wq_tail = work;
	enqueue = !wq->wq_pending;
	wq->wq_pending = true;
	mtx_unlock_spin(&wq->wq_mtx);

	/*
	 * taskqueue_enqueue() takes the taskqueue's sleepable mutex, so it
	 * must not run under the spin mutex (WITNESS: sleepable-after-
	 * non-sleepable).  Deferring it is race-free: wq_pending was set
	 * under the lock, so a concurrent add cannot double-enqueue, and
	 * sppp_wq_task only clears wq_pending under the lock before
	 * draining the FIFO until empty -- an item appended while the task
	 * is queued or running is still picked up by its dequeue loop.  A
	 * late enqueue after the task already drained just runs the task
	 * once on an empty FIFO.
	 */
	if (enqueue)
		taskqueue_enqueue(pppoe_taskq, &wq->wq_task);
}

/*
 * Wait for a work item: mark it unavailable (blocks re-add) and, if it
 * is still queued or running, drain the task.  Callers (sppp_cp_fini at
 * detach) run outside the task thread, so blocking here is safe.
 */
static void
sppp_wq_wait(struct workqueue *wq, struct sppp_work *work)
{
	int old;
	bool enqueue;

	old = atomic_swap_int((int *)&work->state, SPPP_WK_UNAVAIL);
	if (old == SPPP_WK_FREE)
		return;

	mtx_lock_spin(&wq->wq_mtx);
	enqueue = (wq->wq_head != NULL && !wq->wq_pending);
	if (enqueue)
		wq->wq_pending = true;
	mtx_unlock_spin(&wq->wq_mtx);

	/* See sppp_wq_add(): enqueue stays outside the spin mutex. */
	if (enqueue)
		taskqueue_enqueue(pppoe_taskq, &wq->wq_task);

	taskqueue_drain(pppoe_taskq, &wq->wq_task);
}

/*
 * sppp_from_ifp() — the ONLY ifp -> struct sppp access path.  The
 * softc-embed contract (docs/PORTING-sppp.md, "Struct surgery"): the
 * driver embeds `struct sppp ppp` in struct pppoe_softc and hands the
 * embedded pointer to if_setllsoftc(ifp, &sc->ppp), so the link-layer
 * softc slot is the container-of (if_softc stays the driver's own
 * pppoe_softc, as in M001).  The pp_if back-pointer mirrors it for the
 * vendored `sp->pp_if` accesses.
 */
static inline struct sppp *
sppp_from_ifp(struct ifnet *ifp)
{
	return ((struct sppp *)if_getllsoftc(ifp));
}

/*
 * Liveness timestamp for every received frame (R2).  pp_last_receive has
 * one-second resolution (time_uptime), but every frame on every netisr CPU
 * stored it, bouncing its cache line between all of them at line rate.
 * Store only when the second has changed: the common case is a shared
 * read, and the value the keepalive reads is the same.
 */
static inline void
sppp_note_receive(struct sppp *sp)
{
	uint32_t now = time_uptime32;

	if (atomic_load_relaxed(&sp->pp_last_receive) != now)
		atomic_store_relaxed(&sp->pp_last_receive, now);
}

/*
 * p2p_rtrequest shim context.  NetBSD's sppp_ioctl SIOCINITIFADDR arm
 * attached p2p_rtrequest to ifa->ifa_rtrequest; FreeBSD 14.3 removed
 * ifa_rtrequest and has no ifnet->if_rtrequest hook either (see T2
 * field notes in docs/PORTING-sppp.md), so the arm is a no-op here —
 * FreeBSD's cloning route semantics for p2p ifaddrs are handled by
 * ifioctl/SIOCAIFADDR in S03's address application.
 */

#endif /* SPPP_COMPAT_STRUCTS_DEFINED */
#endif /* SPPP_COMPAT_STRUCTS_READY */