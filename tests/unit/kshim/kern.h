/*
 * kern.h -- userland stand-in for the FreeBSD 14.3 kernel KPI surface used
 * by sys/net/ *.c.  Force-included (-include) ahead of every unit-test and
 * fuzz translation unit; the headers under tests/unit/include are empty so
 * the kernel sources' own #include lines resolve here.
 *
 * Only what the sources under test need is modelled.  Behaviour that
 * matters to a test (mbuf chains, lock ownership, the taskqueue, callouts,
 * log records, transmitted frames) lives in kshim.c; the rest are no-ops or
 * trap via KSHIM_UNSTUBBED().  See docs/UNIT-TESTS.md.
 */
#ifndef _KSHIM_KERN_H_
#define _KSHIM_KERN_H_

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>

#define	_KERNEL		1
#define	INET		1
#define	INET6		1
#define	VIMAGE		1
#define	RSS		1
#define	INVARIANTS	1

/* ------------------------------------------------------------------ */
/* cdefs / param                                                        */
/* ------------------------------------------------------------------ */
#ifndef __unused
#define	__unused		__attribute__((__unused__))
#endif
#ifndef __packed
#define	__packed		__attribute__((__packed__))
#endif
#define	__aligned(x)		__attribute__((__aligned__(x)))
#define	CACHE_LINE_SIZE		64
#ifndef PAGE_SIZE
#define	PAGE_SIZE		4096
#endif
#define	__printflike(f, a)	__attribute__((__format__(__printf__, f, a)))
#define	__predict_true(e)	__builtin_expect(!!(e), 1)
#define	__predict_false(e)	__builtin_expect(!!(e), 0)
#define	__containerof(p, T, f)	((T *)(void *)((char *)(p) - offsetof(T, f)))
#define	__DECONST(T, v)		((T)(uintptr_t)(const void *)(v))
#define	__UNCONST(v)		((void *)(uintptr_t)(const void *)(v))
#define	__FBSDID(s)		struct __hack
#define	__read_mostly
#define	__exclusive_cache_line
#define	__noinline		__attribute__((__noinline__))
#define	__diagused		__unused
#define	__section(x)
#define	__result_use_check	__attribute__((__warn_unused_result__))
#define	__nonstring
#define	nitems(x)		(sizeof((x)) / sizeof((x)[0]))
#ifndef MIN
#define	MIN(a, b)		(((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define	MAX(a, b)		(((a) > (b)) ? (a) : (b))
#endif
#define	howmany(x, y)		(((x) + ((y) - 1)) / (y))
#define	roundup(x, y)		((((x) + ((y) - 1)) / (y)) * (y))
#define	roundup2(x, y)		(((x) + ((y) - 1)) & (~((__typeof(x))(y) - 1)))
#define	powerof2(x)		((((x) - 1) & (x)) == 0)
#define	MAXCOMLEN		19
#define	CTASSERT(x)		_Static_assert(x, "compile-time assertion failed")

typedef	int64_t			sbintime_t;
typedef	uint64_t		*counter_u64_t;
typedef	int			boolean_t;

/* ------------------------------------------------------------------ */
/* panic / KASSERT / printf / log(9)                                    */
/* ------------------------------------------------------------------ */
void	kshim_panic(const char *file, int line, const char *fmt, ...)
	    __printflike(3, 4) __attribute__((__noreturn__));
#define	panic(...)		kshim_panic(__FILE__, __LINE__, __VA_ARGS__)
#define	KASSERT(exp, msg)	do {					\
	if (__predict_false(!(exp)))					\
		kshim_panic(__FILE__, __LINE__, "KASSERT(%s) failed: %s", \
		    #exp, kshim_kassert_msg msg);			\
} while (0)
const char *kshim_kassert_msg(const char *fmt, ...) __printflike(1, 2);
#define	MPASS(e)		KASSERT((e), ("%s", #e))
#define	KSHIM_UNSTUBBED()	\
	kshim_panic(__FILE__, __LINE__, "unstubbed KPI %s()", __func__)

#define	LOG_EMERG	0
#define	LOG_ALERT	1
#define	LOG_CRIT	2
#define	LOG_ERR		3
#define	LOG_WARNING	4
#define	LOG_NOTICE	5
#define	LOG_INFO	6
#define	LOG_DEBUG	7
void	kshim_log(int pri, const char *fmt, ...) __printflike(2, 3);
#define	log		kshim_log
int	kshim_printf(const char *fmt, ...) __printflike(1, 2);
#define	printf		kshim_printf
#define	uprintf		kshim_printf

size_t	kshim_strlcpy(char *dst, const char *src, size_t sz);
size_t	kshim_strlcat(char *dst, const char *src, size_t sz);
#define	strlcpy		kshim_strlcpy
#define	strlcat		kshim_strlcat
#define	bcmp(a, b, n)	memcmp((a), (b), (n))

/* sys/hash.h: a stand-in, not the kernel's Toeplitz/one-at-a-time -- tests
 * assert what the driver does with the hash, never particular values. */
uint32_t	jenkins_hash32(const uint32_t *k, size_t length, uint32_t initval);

uint32_t kshim_arc4random(void);
void	kshim_arc4random_buf(void *, size_t);
#define	arc4random	kshim_arc4random
#define	arc4random_buf	kshim_arc4random_buf

/* sys/random.h: random(4)'s seeded state is a test knob (kshim_reset():
 * seeded); read_random() of an unseeded device panics, since the kernel's
 * would block or hand back zeroes. */
extern bool kshim_random_seeded;
bool	kshim_is_random_seeded(void);
void	kshim_read_random(void *, u_int);
#define	is_random_seeded	kshim_is_random_seeded
#define	read_random	kshim_read_random

/* ------------------------------------------------------------------ */
/* malloc(9)                                                            */
/* ------------------------------------------------------------------ */
struct malloc_type { const char *ks_shortdesc; long ks_inuse; };
#define	MALLOC_DEFINE(t, s, l)	struct malloc_type t[1] = { { s, 0 } }
#define	MALLOC_DECLARE(t)	extern struct malloc_type t[1]
MALLOC_DECLARE(M_DEVBUF);
MALLOC_DECLARE(M_TEMP);
#define	M_NOWAIT	0x0001
#define	M_WAITOK	0x0002
#define	M_ZERO		0x0100
void	*kshim_malloc(size_t, struct malloc_type *, int);
void	*kshim_malloc_aligned(size_t, size_t, struct malloc_type *, int);
void	 kshim_free(void *, struct malloc_type *);
void	 kshim_zfree(void *, struct malloc_type *);
#define	malloc(s, t, f)		kshim_malloc((s), (t), (f))
#define	malloc_aligned(s, a, t, f) kshim_malloc_aligned((s), (a), (t), (f))
#define	free(p, t)		kshim_free((p), (t))
#define	zfree(p, t)		kshim_zfree((p), (t))
#define	explicit_bzero(p, n)	memset((p), 0, (n))

/* ------------------------------------------------------------------ */
/* time                                                                 */
/* ------------------------------------------------------------------ */
extern volatile time_t	kshim_time_uptime;
extern int		kshim_ticks;
#define	time_uptime	kshim_time_uptime
#define	time_second	kshim_time_uptime
#define	ticks		kshim_ticks
#define	hz		1000
void	getmicrouptime(struct timeval *);
#define	microuptime	getmicrouptime
#define	microtime	getmicrouptime
#define	getmicrotime	getmicrouptime
int	ppsratecheck(struct timeval *, int *, int);
int	ratecheck(struct timeval *, const struct timeval *);
#define	SBT_1S		((sbintime_t)1 << 32)
#define	tick_sbt	(SBT_1S / hz)

/* ------------------------------------------------------------------ */
/* byte order                                                           */
/* ------------------------------------------------------------------ */
#include <endian.h>
#define	htons(x)	((uint16_t)htobe16((uint16_t)(x)))
#define	ntohs(x)	((uint16_t)be16toh((uint16_t)(x)))
#define	htonl(x)	((uint32_t)htobe32((uint32_t)(x)))
#define	ntohl(x)	((uint32_t)be32toh((uint32_t)(x)))
#define	be16dec(p)	((uint16_t)(((const uint8_t *)(p))[0] << 8 | ((const uint8_t *)(p))[1]))
#define	be16enc(p, v)	do {						\
	((uint8_t *)(p))[0] = (uint8_t)((uint16_t)(v) >> 8);		\
	((uint8_t *)(p))[1] = (uint8_t)(uint16_t)(v);			\
} while (0)

/* ------------------------------------------------------------------ */
/* atomics (single-threaded harness: plain accesses)                    */
/* ------------------------------------------------------------------ */
static inline int
atomic_cmpset_int(volatile int *p, int o, int n)
{
	if (*p != o)
		return (0);
	*p = n;
	return (1);
}
static inline int
atomic_swap_int(volatile int *p, int v)
{
	int o = *p;

	*p = v;
	return (o);
}
#define	atomic_load_ptr(p)		(*(p))
#define	atomic_store_ptr(p, v)		(*(p) = (v))
#define	atomic_load_acq_ptr(p)		(*(p))
#define	atomic_store_rel_ptr(p, v)	(*(p) = (v))
#define	atomic_load_int(p)		(*(p))
#define	atomic_store_int(p, v)		(*(p) = (v))
#define	atomic_load_acq_int(p)		(*(p))
#define	atomic_store_rel_int(p, v)	(*(p) = (v))
#define	atomic_add_int(p, v)		(*(p) += (v))
#define	atomic_subtract_int(p, v)	(*(p) -= (v))
#define	atomic_fetchadd_int(p, v)	({ __typeof(*(p)) __o = *(p); *(p) += (v); __o; })
#define	atomic_fetchadd_64(p, v)	atomic_fetchadd_int(p, v)
#define	atomic_set_int(p, v)		(*(p) |= (v))
#define	atomic_clear_int(p, v)		(*(p) &= ~(v))

/* refcount(9) */
#define	refcount_init(p, v)	(*(p) = (v))
#define	refcount_acquire(p)	((*(p))++)
#define	refcount_release(p)	(--(*(p)) == 0)
#define	refcount_load(p)	(*(p))

/* ------------------------------------------------------------------ */
/* locks: WITNESS-lite ownership tracking (kshim.c)                     */
/* ------------------------------------------------------------------ */
struct lock_object { const char *lo_name; int lo_flags; };
struct mtx {
	struct lock_object lock_object;
	int	mtx_owned;
	int	mtx_inited;
	int	mtx_spin;
};
#define	MTX_DEF		0x0000
#define	MTX_SPIN	0x0001
#define	MTX_RECURSE	0x0004
#define	MTX_NEW		0x0020
#define	MA_OWNED	0x01
#define	MA_NOTOWNED	0x02
void	kshim_mtx_init(struct mtx *, const char *, const char *, int);
void	kshim_mtx_destroy(struct mtx *);
void	kshim_mtx_lock(struct mtx *, const char *, int);
void	kshim_mtx_unlock(struct mtx *, const char *, int);
void	kshim_mtx_assert(struct mtx *, int, const char *, int);
#define	mtx_init(m, n, t, o)	kshim_mtx_init((m), (n), (t), (o))
#define	mtx_destroy(m)		kshim_mtx_destroy((m))
#define	mtx_lock(m)		kshim_mtx_lock((m), __FILE__, __LINE__)
#define	mtx_unlock(m)		kshim_mtx_unlock((m), __FILE__, __LINE__)
#define	mtx_lock_spin(m)	kshim_mtx_lock((m), __FILE__, __LINE__)
#define	mtx_unlock_spin(m)	kshim_mtx_unlock((m), __FILE__, __LINE__)
#define	mtx_owned(m)		((m)->mtx_owned != 0)
#define	mtx_initialized(m)	((m)->mtx_inited != 0)
#define	mtx_assert(m, w)	kshim_mtx_assert((m), (w), __FILE__, __LINE__)
/* Priority 101: before fx_module_load()'s constructor(102), which calls
 * pppoe_modevent(MOD_LOAD) and so may take a lock declared this way. */
#define	MTX_SYSINIT(n, m, d, o)	\
	static void __attribute__((constructor(101))) kshim_mtxinit_##n(void) \
	{ mtx_init((m), (d), NULL, (o)); }

struct sx { struct mtx sx_mtx; };
#define	sx_init(s, n)		mtx_init(&(s)->sx_mtx, (n), NULL, MTX_DEF)
#define	sx_destroy(s)		mtx_destroy(&(s)->sx_mtx)
#define	sx_xlock(s)		mtx_lock(&(s)->sx_mtx)
#define	sx_xunlock(s)		mtx_unlock(&(s)->sx_mtx)
#define	sx_slock(s)		mtx_lock(&(s)->sx_mtx)
#define	sx_sunlock(s)		mtx_unlock(&(s)->sx_mtx)
#define	sx_xlocked(s)		mtx_owned(&(s)->sx_mtx)
#define	SA_XLOCKED		MA_OWNED
#define	sx_assert(s, w)		mtx_assert(&(s)->sx_mtx, (w))
#define	SX_SYSINIT(n, s, d)	\
	static void __attribute__((constructor(101))) kshim_sxinit_##n(void) \
	{ sx_init((s), (d)); }

/* ------------------------------------------------------------------ */
/* taskqueue(9) / callout(9) -- deferred, run explicitly by tests       */
/* ------------------------------------------------------------------ */
typedef void task_fn_t(void *, int);
struct task {
	struct task	*ta_next;
	int		 ta_pending;
	int		 ta_priority;
	task_fn_t	*ta_func;
	void		*ta_context;
	struct taskqueue *ta_queue;	/* kshim: the last enqueue's queue */
};
/* One FIFO runs every queue's tasks (kshim_run_tasks()); each queue
 * counts what was enqueued on it so a test can tell which one was used. */
struct taskqueue {
	const char	*tq_name;
	int		 tq_enqueued;
	int		 tq_threads;
};
extern struct taskqueue *taskqueue_thread;
extern struct taskqueue *taskqueue_swi;
typedef void (*taskqueue_enqueue_fn)(void *);
void	taskqueue_thread_enqueue(void *);
struct taskqueue *taskqueue_create(const char *, int, taskqueue_enqueue_fn,
	    void *);
int	taskqueue_start_threads(struct taskqueue **, int, int, const char *,
	    ...);
void	taskqueue_drain_all(struct taskqueue *);
void	taskqueue_free(struct taskqueue *);
#define	PWAIT			76
#define	TASK_INIT(t, p, f, c)	do {					\
	(t)->ta_next = NULL; (t)->ta_pending = 0;			\
	(t)->ta_priority = (p); (t)->ta_func = (f);			\
	(t)->ta_context = (c);						\
} while (0)
int	taskqueue_enqueue(struct taskqueue *, struct task *);
void	taskqueue_drain(struct taskqueue *, struct task *);
int	taskqueue_cancel(struct taskqueue *, struct task *, u_int *);

struct callout {
	void	(*c_func)(void *);
	void	*c_arg;
	int	 c_time;
	int	 c_pending;
	int	 c_inited;
	struct mtx *c_lock;
};
#define	CALLOUT_MPSAFE		1
#define	CALLOUT_RETURNUNLOCKED	0x10
void	callout_init(struct callout *, int);
void	callout_init_mtx(struct callout *, struct mtx *, int);
int	callout_reset(struct callout *, int, void (*)(void *), void *);
int	callout_stop(struct callout *);
int	callout_drain(struct callout *);
#define	callout_pending(c)	((c)->c_pending)
#define	callout_active(c)	((c)->c_pending)
#define	callout_reset_sbt(c, s, p, f, a, fl)	callout_reset((c), 1, (f), (a))

/* ------------------------------------------------------------------ */
/* threads, privileges, copyin                                          */
/* ------------------------------------------------------------------ */
struct ucred { int cr_uid; };
struct thread { struct ucred *td_ucred; };
extern struct thread *curthread;
#define	PRIV_NET_SETIFPHYS	1
#define	PRIV_NET_SETIFMTU	2
#define	PRIV_NET_ADDIFADDR	3
#define	PRIV_NET_DELIFADDR	4
#define	PRIV_DRIVER		5
int	priv_check(struct thread *, int);
int	copyin(const void *, void *, size_t);
int	copyout(const void *, void *, size_t);
int	copyinstr(const void *, void *, size_t, size_t *);
#define	critical_enter()	do { } while (0)
#define	critical_exit()		do { } while (0)
#define	sched_pin()		do { } while (0)
#define	sched_unpin()		do { } while (0)
#define	pause(w, t)		do { (void)(w); (void)(t); } while (0)
#define	curcpu			0
#define	mp_ncpus		1
#define	mp_maxid		0
#define	MAXCPU			1
#define	CPU_FOREACH(i)		for ((i) = 0; (i) <= mp_maxid; (i)++)

/* sys/sys/cpuset.h; CPU_ABSENT() is defined below, against the netisr(9)
 * shim's configurable CPU count (kshim_netisr_ncpu). */
#define	CPU_SETSIZE		64
typedef struct { unsigned long __bits; } cpuset_t;
#define	CPU_ZERO(s)		((s)->__bits = 0)
#define	CPU_FILL(s)		((s)->__bits = ~0UL)
#define	CPU_SET(i, s)		((s)->__bits |= (1UL << (i)))
#define	CPU_CLR(i, s)		((s)->__bits &= ~(1UL << (i)))
#define	CPU_ISSET(i, s)		((((s)->__bits) >> (i)) & 1UL)

/* ------------------------------------------------------------------ */
/* counter(9)                                                           */
/* ------------------------------------------------------------------ */
counter_u64_t	counter_u64_alloc(int);
void		counter_u64_free(counter_u64_t);
#define	counter_u64_add(c, v)	do { if ((c) != NULL) *(c) += (v); } while (0)
#define	counter_u64_fetch(c)	((c) != NULL ? *(c) : 0)
#define	counter_u64_zero(c)	do { if ((c) != NULL) *(c) = 0; } while (0)

/* ------------------------------------------------------------------ */
/* SYSINIT / modules / sysctl / eventhandler: registration no-ops       */
/* ------------------------------------------------------------------ */
/* sys/sys/kernel.h values: the (subsystem, order) keys are recorded. */
#define	SI_SUB_PSEUDO		0x7000000
#define	SI_SUB_PROTO_PFIL	0x8100000
#define	SI_SUB_PROTO_IF		0x8400000
#define	SI_SUB_PROTO_DOMAIN	0x8800000
#define	SI_SUB_PROTO_IFATTACHDOMAIN 0x8808000
#define	SI_ORDER_FIRST		0x0000000
#define	SI_ORDER_SECOND		0x0000001
#define	SI_ORDER_MIDDLE		0x1000000
#define	SI_ORDER_ANY		0xfffffff
/* Nothing runs them; kshim_sysinit_find() reports where each one sits. */
enum { KSHIM_SYSUNINIT, KSHIM_VNET_SYSINIT, KSHIM_VNET_SYSUNINIT };
void	kshim_sysinit_register(int kind, const char *func, u_int sub,
	    u_int order);
#define	KSHIM_SI__(kind, tag, ident, sub, order, func)			\
	static void __attribute__((constructor))			\
	kshim_si_##tag##_##ident(void)					\
	{ kshim_sysinit_register((kind), #func, (sub), (order)); }	\
	struct __hack
#define	SYSINIT(...)		struct __hack
#define	SYSUNINIT(ident, sub, order, func, arg)				\
	KSHIM_SI__(KSHIM_SYSUNINIT, u, ident, sub, order, func)
#define	VNET_SYSINIT(ident, sub, order, func, arg)			\
	KSHIM_SI__(KSHIM_VNET_SYSINIT, vi, ident, sub, order, func)
#define	VNET_SYSUNINIT(ident, sub, order, func, arg)			\
	KSHIM_SI__(KSHIM_VNET_SYSUNINIT, vu, ident, sub, order, func)
typedef struct module *module_t;
typedef struct moduledata { const char *name; int (*evhand)(module_t, int, void *); void *priv; } moduledata_t;
enum { MOD_LOAD, MOD_UNLOAD, MOD_SHUTDOWN, MOD_QUIESCE };
#define	DECLARE_MODULE(...)	struct __hack
#define	DECLARE_MODULE_TIED(...)	struct __hack
#define	MODULE_VERSION(...)	struct __hack
#define	MODULE_DEPEND(...)	struct __hack
#define	FEATURE(...)		struct __hack

struct sysctl_oid;
struct sysctl_req { int dummy; void *newptr; };
#define	TUNABLE_STR(...)	struct __hack
#define	TUNABLE_INT(...)	struct __hack
#define	SYSCTL_HANDLER_ARGS	struct sysctl_oid *oidp, void *arg1, \
				intmax_t arg2, struct sysctl_req *req
#define	SYSCTL_DECL(n)		struct __hack
#define	SYSCTL_NODE(...)	struct __hack
#define	SYSCTL_INT(...)		struct __hack
#define	SYSCTL_UINT(...)	struct __hack
#define	SYSCTL_U64(...)		struct __hack
#define	SYSCTL_BOOL(...)	struct __hack
#define	SYSCTL_STRING(...)	struct __hack
#define	SYSCTL_PROC(...)	struct __hack
#define	SYSCTL_COUNTER_U64(...)	struct __hack
#define	SYSCTL_ADD_PROC(...)	NULL
#define	CTLFLAG_RW		0
#define	CTLFLAG_RD		0
#define	CTLFLAG_RWTUN		0
#define	CTLFLAG_RDTUN		0
#define	CTLFLAG_VNET		0
#define	CTLFLAG_MPSAFE		0
#define	CTLFLAG_NEEDGIANT	0
#define	CTLTYPE_INT		0
#define	CTLTYPE_UINT		0
#define	CTLTYPE_STRING		0
#define	CTLTYPE_U64		0
#define	CTLTYPE_OPAQUE		0
#define	OID_AUTO		(-1)
int	sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int	sysctl_handle_string(SYSCTL_HANDLER_ARGS);
int	sysctl_wire_old_buffer(struct sysctl_req *, size_t);
#define	SYSCTL_IN(r, p, l)	(EINVAL)
#define	SYSCTL_OUT(r, p, l)	(0)

typedef void *eventhandler_tag;
#define	EVENTHANDLER_PRI_ANY	10000
#define	EVENTHANDLER_PRI_FIRST	0
#define	EVENTHANDLER_PRI_LAST	20000
#define	EVENTHANDLER_REGISTER(n, f, a, p)	((eventhandler_tag)(uintptr_t)1)
/* A NULL tag makes _eventhandler_deregister() empty the whole system-wide
 * list (subr_eventhandler.c:204-212 in 14.3): never what a module means. */
#define	EVENTHANDLER_DEREGISTER(n, t)	do {				\
	if ((t) == NULL)						\
		kshim_panic(__FILE__, __LINE__,				\
		    "EVENTHANDLER_DEREGISTER(%s, NULL)", #n);		\
} while (0)
#define	EVENTHANDLER_DECLARE(n, t)		struct __hack

/* sbuf(9): only the handful the sysctl handlers use, backed by stdio. */
struct sbuf { char *s_buf; size_t s_len, s_size; };
struct sbuf *sbuf_new_for_sysctl(struct sbuf *, char *, int, struct sysctl_req *);
struct sbuf *sbuf_new(struct sbuf *, char *, int, int);
int	sbuf_printf(struct sbuf *, const char *, ...) __printflike(2, 3);
int	sbuf_cat(struct sbuf *, const char *);
int	sbuf_finish(struct sbuf *);
void	sbuf_delete(struct sbuf *);
char	*sbuf_data(struct sbuf *);
ssize_t	sbuf_len(struct sbuf *);
#define	SBUF_FIXEDLEN		0
#define	SBUF_INCLUDENUL		0

void	devctl_notify(const char *, const char *, const char *, const char *);

/* ------------------------------------------------------------------ */
/* ioctl encoding (FreeBSD sys/ioccom.h)                                */
/* ------------------------------------------------------------------ */
#define	IOCPARM_SHIFT	13
#define	IOCPARM_MASK	((1 << IOCPARM_SHIFT) - 1)
#define	IOCPARM_LEN(x)	(((x) >> 16) & IOCPARM_MASK)
#define	IOC_VOID	0x20000000UL
#define	IOC_OUT		0x40000000UL
#define	IOC_IN		0x80000000UL
#define	IOC_INOUT	(IOC_IN | IOC_OUT)
#define	_IOC(i, g, n, l) ((unsigned long)((i) | (((l) & IOCPARM_MASK) << 16) | ((g) << 8) | (n)))
#define	_IO(g, n)	_IOC(IOC_VOID, (g), (n), 0)
#define	_IOR(g, n, t)	_IOC(IOC_OUT, (g), (n), sizeof(t))
#define	_IOW(g, n, t)	_IOC(IOC_IN, (g), (n), sizeof(t))
#define	_IOWR(g, n, t)	_IOC(IOC_INOUT, (g), (n), sizeof(t))

/* ------------------------------------------------------------------ */
/* MD5 (sys/md5.h) -- real implementation in kshim.c for CHAP tests     */
/* ------------------------------------------------------------------ */
typedef struct MD5Context {
	uint32_t state[4];
	uint32_t count[2];
	unsigned char buffer[64];
} MD5_CTX;
void	MD5Init(MD5_CTX *);
void	MD5Update(MD5_CTX *, const void *, unsigned int);
void	MD5Final(void *, MD5_CTX *);

/* ------------------------------------------------------------------ */
/* queue(3) subset + ck_queue aliases                                   */
/* ------------------------------------------------------------------ */
#define	KSHIM_LIST_HEAD(name, type)	struct name { struct type *lh_first; }
#define	KSHIM_LIST_ENTRY(type)		struct { struct type *le_next; struct type **le_prev; }
#define	CK_LIST_HEAD(name, type)	KSHIM_LIST_HEAD(name, type)
#define	CK_LIST_ENTRY(type)		KSHIM_LIST_ENTRY(type)
#define	CK_LIST_HEAD_INITIALIZER(h)	{ NULL }
#define	CK_LIST_FIRST(h)		((h)->lh_first)
#define	CK_LIST_NEXT(e, f)		((e)->f.le_next)
#define	CK_LIST_EMPTY(h)		((h)->lh_first == NULL)
#define	CK_LIST_INIT(h)			((h)->lh_first = NULL)
#define	CK_LIST_FOREACH(v, h, f)	\
	for ((v) = (h)->lh_first; (v) != NULL; (v) = (v)->f.le_next)
#define	CK_LIST_FOREACH_SAFE(v, h, f, t) \
	for ((v) = (h)->lh_first; (v) != NULL && ((t) = (v)->f.le_next, 1); (v) = (t))
#define	CK_LIST_INSERT_HEAD(h, e, f)	do {				\
	if (((e)->f.le_next = (h)->lh_first) != NULL)			\
		(h)->lh_first->f.le_prev = &(e)->f.le_next;		\
	(h)->lh_first = (e);						\
	(e)->f.le_prev = &(h)->lh_first;				\
} while (0)
#define	CK_LIST_REMOVE(e, f)	do {					\
	if ((e)->f.le_next != NULL)					\
		(e)->f.le_next->f.le_prev = (e)->f.le_prev;		\
	*(e)->f.le_prev = (e)->f.le_next;				\
} while (0)
#define	CK_STAILQ_HEAD(name, type)	struct name { struct type *stqh_first; struct type **stqh_last; }
#define	CK_STAILQ_ENTRY(type)		struct { struct type *stqe_next; }
#define	CK_STAILQ_FIRST(h)		((h)->stqh_first)
#define	CK_STAILQ_NEXT(e, f)		((e)->f.stqe_next)
#define	CK_STAILQ_INIT(h)		do { (h)->stqh_first = NULL; (h)->stqh_last = &(h)->stqh_first; } while (0)
#define	CK_STAILQ_FOREACH(v, h, f)	\
	for ((v) = (h)->stqh_first; (v) != NULL; (v) = (v)->f.stqe_next)
#define	CK_STAILQ_INSERT_TAIL(h, e, f)	do {				\
	(e)->f.stqe_next = NULL;					\
	*(h)->stqh_last = (e);						\
	(h)->stqh_last = &(e)->f.stqe_next;				\
} while (0)

/* ------------------------------------------------------------------ */
/* epoch(9) / vnet(9)                                                   */
/* ------------------------------------------------------------------ */
struct epoch_tracker { int et_dummy; };
struct epoch_context { void *ec_dummy[2]; };
typedef struct epoch_context *epoch_context_t;
extern int kshim_net_epoch_depth;
#define	NET_EPOCH_ENTER(et)	do { (void)&(et); kshim_net_epoch_depth++; } while (0)
#define	NET_EPOCH_EXIT(et)	do { (void)&(et); kshim_net_epoch_depth--; } while (0)
#define	NET_EPOCH_ASSERT()	KASSERT(kshim_net_epoch_depth > 0, ("not in net epoch"))
#define	NET_EPOCH_WAIT()	do { } while (0)
#define	NET_EPOCH_DRAIN_CALLBACKS() do { } while (0)
#define	NET_EPOCH_CALL(f, c)	(f)((c))
#define	in_epoch(e)		(kshim_net_epoch_depth > 0)

struct vnet { int vnet_dummy; };
extern struct vnet *kshim_vnet0;
#define	curvnet			kshim_vnet0
#define	vnet0			kshim_vnet0
#define	VNET_DEFINE(t, n)	t n
#define	VNET_DEFINE_STATIC(t, n) static t n
#define	VNET_DECLARE(t, n)	extern t n
#define	VNET(n)			(n)
#define	V_NAME(n)		n
#define	VNET_NAME(n)		n
#define	CURVNET_SET(v)		((void)(v))
#define	CURVNET_SET_QUIET(v)	CURVNET_SET(v)
#define	CURVNET_RESTORE()	do { } while (0)
#define	VNET_ASSERT(e, m)	do { } while (0)
#define	VNET_ITERATOR_DECL(v)	struct vnet *v
#define	VNET_LIST_RLOCK()	do { } while (0)
#define	VNET_LIST_RUNLOCK()	do { } while (0)
#define	VNET_LIST_RLOCK_NOSLEEP() do { } while (0)
#define	VNET_LIST_RUNLOCK_NOSLEEP() do { } while (0)
#define	VNET_FOREACH(v)		for ((v) = kshim_vnet0; (v) != NULL; (v) = NULL)
#define	IS_DEFAULT_VNET(v)	((v) == kshim_vnet0)

/* ------------------------------------------------------------------ */
/* sockets / addresses                                                  */
/* ------------------------------------------------------------------ */
typedef uint8_t		sa_family_t;
typedef uint32_t	socklen_t;
typedef uint32_t	in_addr_t;
typedef uint16_t	in_port_t;
#define	AF_UNSPEC	0
#define	AF_LINK		18
#define	AF_INET		2
#define	AF_INET6	28
#define	SOCK_DGRAM	2
struct sockaddr {
	uint8_t		sa_len;
	sa_family_t	sa_family;
	char		sa_data[14];
};
struct sockaddr_storage { uint8_t ss_len; sa_family_t ss_family; char __ss_pad[126]; };
struct in_addr { in_addr_t s_addr; };
struct sockaddr_in {
	uint8_t		sin_len;
	sa_family_t	sin_family;
	in_port_t	sin_port;
	struct in_addr	sin_addr;
	char		sin_zero[8];
};
struct in6_addr {
	union {
		uint8_t		__u6_addr8[16];
		uint16_t	__u6_addr16[8];
		uint32_t	__u6_addr32[4];
	} __u6_addr;
};
#define	s6_addr		__u6_addr.__u6_addr8
#define	s6_addr8	__u6_addr.__u6_addr8
#define	s6_addr16	__u6_addr.__u6_addr16
#define	s6_addr32	__u6_addr.__u6_addr32
struct sockaddr_in6 {
	uint8_t		sin6_len;
	sa_family_t	sin6_family;
	in_port_t	sin6_port;
	uint32_t	sin6_flowinfo;
	struct in6_addr	sin6_addr;
	uint32_t	sin6_scope_id;
};
#define	INADDR_ANY		((in_addr_t)0x00000000)
#define	INADDR_BROADCAST	((in_addr_t)0xffffffff)
#define	INET_ADDRSTRLEN		16
#define	INET6_ADDRSTRLEN	46
#define	IN6_IS_ADDR_LINKLOCAL(a) \
	((a)->s6_addr[0] == 0xfe && ((a)->s6_addr[1] & 0xc0) == 0x80)
#define	IN6_IS_ADDR_UNSPECIFIED(a) \
	((a)->s6_addr32[0] == 0 && (a)->s6_addr32[1] == 0 && \
	 (a)->s6_addr32[2] == 0 && (a)->s6_addr32[3] == 0)
#define	IN6_ARE_ADDR_EQUAL(a, b)	(memcmp((a), (b), sizeof(struct in6_addr)) == 0)
#define	IN6_IS_SCOPE_EMBED(a)	IN6_IS_ADDR_LINKLOCAL(a)
#define	IN6_IFF_TENTATIVE	0x02
#define	IN6_IFF_DUPLICATED	0x04
#define	IN6_IFF_DETACHED	0x08
#define	IN6_IFF_NODAD		0x20
#define	IN6_IFF_AUTOCONF	0x40
#define	IN6_IFF_NOTREADY	(IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED)
#define	ND6_INFINITE_LIFETIME	0xffffffff
#define	IPPROTO_IP	0
#define	IPPROTO_ICMP	1
#define	IPPROTO_TCP	6
#define	IPPROTO_UDP	17
#define	IPPROTO_IPV6	41
const char *kshim_inet_ntop(int, const void *, char *, socklen_t);
#define	inet_ntop	kshim_inet_ntop
char	*inet_ntoa_r(struct in_addr, char *);
char	*ip6_sprintf(char *, const struct in6_addr *);

struct sockaddr_dl {
	uint8_t		sdl_len;
	uint8_t		sdl_family;
	uint16_t	sdl_index;
	uint8_t		sdl_type;
	uint8_t		sdl_nlen;
	uint8_t		sdl_alen;
	uint8_t		sdl_slen;
	char		sdl_data[46];
};
#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define	sintosa(sin)	((struct sockaddr *)(sin))
#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define	sin6tosa(sin6)	((struct sockaddr *)(sin6))
#define	LLADDR(s)	((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

struct ip {
	uint8_t		ip_hl:4, ip_v:4;	/* little-endian host */
	uint8_t		ip_tos;
	uint16_t	ip_len;
	uint16_t	ip_id;
	uint16_t	ip_off;
	uint8_t		ip_ttl;
	uint8_t		ip_p;
	uint16_t	ip_sum;
	struct in_addr	ip_src, ip_dst;
} __packed;
#define	IPVERSION	4
#define	IP_MF		0x2000
#define	IP_OFFMASK	0x1fff
struct ip6_hdr {
	uint32_t	ip6_flow;
	uint16_t	ip6_plen;
	uint8_t		ip6_nxt;
	uint8_t		ip6_hlim;
	struct in6_addr	ip6_src;
	struct in6_addr	ip6_dst;
} __packed;
#define	ip6_vfc		ip6_flow
#define	IPV6_VERSION		0x60
#define	IPV6_VERSION_MASK	0xf0
struct tcphdr {
	uint16_t th_sport, th_dport;
	uint32_t th_seq, th_ack;
	uint8_t	 th_x2_off, th_flags;
	uint16_t th_win, th_sum, th_urp;
} __packed;
struct udphdr { uint16_t uh_sport, uh_dport, uh_ulen, uh_sum; };

/* ------------------------------------------------------------------ */
/* mbuf(9) -- kshim.c keeps every buffer a separate heap block so ASan */
/* catches an overrun of any single mbuf                                */
/* ------------------------------------------------------------------ */
#define	MSIZE		256
#define	MLEN		224
#define	MHLEN		168	/* FreeBSD 14 amd64 order of magnitude; see UNIT-TESTS.md */
/* Real max_linkhdr_grow() (sys/net/if.c) raises the global link-header
 * headroom floor; the harness never allocates off it, so a no-op is enough
 * to satisfy the call at module load. */
static inline void max_linkhdr_grow(int new_size) { (void)new_size; }
#define	MINCLSIZE	(MHLEN + 1)
#define	MCLBYTES	2048
#define	MJUMPAGESIZE	4096
#define	MT_DATA		1
#define	MT_HEADER	MT_DATA
#define	M_EXT		0x00000001
#define	M_PKTHDR	0x00000002
#define	M_EOR		0x00000004
#define	M_RDONLY	0x00000008
#define	M_BCAST		0x00000010
#define	M_MCAST		0x00000020
#define	M_VLANTAG	0x00000080
#define	M_FLOWID	0x00400000
/* sys/sys/mbuf.h: protocol-specific flags, purged when crossing layers */
#define	M_PROTO1	0x00002000
#define	M_PROTO2	0x00004000
#define	M_PROTO3	0x00008000
#define	M_PROTO4	0x00010000
#define	M_PROTO5	0x00020000
#define	M_PROTO6	0x00040000
#define	M_PROTO7	0x00080000
#define	M_PROTO8	0x00100000
#define	M_PROTO9	0x00200000
#define	M_PROTO10	0x00400000
#define	M_PROTO11	0x00800000
#define	M_PROTOFLAGS							\
    (M_PROTO1|M_PROTO2|M_PROTO3|M_PROTO4|M_PROTO5|M_PROTO6|M_PROTO7|M_PROTO8|\
     M_PROTO9|M_PROTO10|M_PROTO11)
#define	M_DONTWAIT	M_NOWAIT
#define	M_COPYALL	1000000000
#define	M_HASHTYPE_NONE		0
#define	M_HASHTYPE_OPAQUE	1
#define	M_HASHTYPE_OPAQUE_HASH	2
#define	M_HASHTYPE_RSS_IPV4	3
#define	M_HASHTYPE_RSS_TCP_IPV4	4
#define	M_HASHTYPE_RSS_IPV6	5
#define	M_HASHTYPE_RSS_TCP_IPV6	6
#define	M_HASHTYPE_RSS_UDP_IPV4	7
#define	M_HASHTYPE_RSS_UDP_IPV6	8
#define	M_HASHTYPE_GET(m)	((m)->m_pkthdr.rsstype)
#define	M_HASHTYPE_SET(m, v)	((m)->m_pkthdr.rsstype = (v))
#define	M_HASHTYPE_ISHASH(m)	((m)->m_pkthdr.rsstype > M_HASHTYPE_OPAQUE)
#define	EVL_VLANOFTAG(t)	((t) & 0x0fff)
/* net/if_vlan_var.h */
#define	EVL_MAKETAG(vlid, pri, cfi)					\
    ((((pri) & 7) << 13) | (((cfi) & 1) << 12) | ((vlid) & 0x0fff))
#define	CSUM_DELAY_DATA		0x0001
#define	CSUM_DELAY_IP		0x0002
#define	CSUM_TCP		0x0004	/* FreeBSD CSUM_IP_TCP */
#define	CSUM_TCP_IPV6		0x0400	/* FreeBSD CSUM_IP6_TCP */
/* RX results, sys/sys/mbuf.h values */
#define	CSUM_L3_CALC		0x01000000
#define	CSUM_L3_VALID		0x02000000
#define	CSUM_L4_CALC		0x04000000
#define	CSUM_L4_VALID		0x08000000
#define	CSUM_IP_CHECKED		CSUM_L3_CALC
#define	CSUM_IP_VALID		CSUM_L3_VALID
#define	CSUM_DATA_VALID		CSUM_L4_VALID
#define	CSUM_PSEUDO_HDR		CSUM_L4_CALC
/* netinet/tcp.h (RFC 9293), for the MSS clamp */
#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define	TCPOLEN_MAXSEG		4
#define	TH_SYN			0x02
#define	bswap16(x)		__builtin_bswap16(x)	/* sys/endian.h */

struct ifnet;
struct pkthdr {
	struct ifnet	*rcvif;
	int32_t		 len;
	uint32_t	 flowid;
	uint8_t		 rsstype;
	uint16_t	 ether_vtag;
	uint32_t	 csum_flags;
	uint16_t	 fibnum;
};
struct mbuf {
	struct mbuf	*m_next;
	struct mbuf	*m_nextpkt;
	caddr_t		 m_data;
	int32_t		 m_len;
	uint32_t	 m_type;
	uint32_t	 m_flags;
	struct pkthdr	 m_pkthdr;
	caddr_t		 m_kbuf;	/* kshim: start of the storage */
	int32_t		 m_ksize;	/* kshim: size of the storage */
};
#define	mtod(m, t)	((t)((m)->m_data))
#define	mtodo(m, o)	((void *)(((m)->m_data) + (o)))
#define	M_LEADINGSPACE(m)	((int)((m)->m_data - (m)->m_kbuf))
#define	M_TRAILINGSPACE(m)	\
	((int)(((m)->m_kbuf + (m)->m_ksize) - ((m)->m_data + (m)->m_len)))
#define	M_WRITABLE(m)		1
#define	M_ALIGN(m, l)		do { (m)->m_data += (MLEN - (l)) & ~(sizeof(long) - 1); } while (0)
#define	MH_ALIGN(m, l)		do { (m)->m_data += (MHLEN - (l)) & ~(sizeof(long) - 1); } while (0)
struct mbuf	*m_get(int, short);
struct mbuf	*m_gethdr(int, short);
struct mbuf	*m_getcl(int, short, int);
struct mbuf	*m_get2(int, int, short, int);
bool		 kshim_m_clget(struct mbuf *, int);
#define	MCLGET(m, h)		kshim_m_clget((m), (h))
#define	MGETHDR(m, h, t)	((m) = m_gethdr((h), (t)))
#define	MGET(m, h, t)		((m) = m_get((h), (t)))
void		 m_freem(struct mbuf *);
struct mbuf	*m_free(struct mbuf *);
struct mbuf	*m_pullup(struct mbuf *, int);
void		 m_copydata(const struct mbuf *, int, int, caddr_t);
void		 m_copyback(struct mbuf *, int, int, const void *);
void		 m_adj(struct mbuf *, int);
struct mbuf	*m_prepend(struct mbuf *, int, int);
struct mbuf	*m_defrag(struct mbuf *, int);
struct mbuf	*m_dup(const struct mbuf *, int);
struct mbuf	*m_copym(struct mbuf *, int, int, int);
u_int		 m_length(struct mbuf *, struct mbuf **);
int		 m_append(struct mbuf *, int, const void *);
void		 m_cat(struct mbuf *, struct mbuf *);
void		 m_move_pkthdr(struct mbuf *, struct mbuf *);
void		 m_demote_pkthdr(struct mbuf *);
#define	M_PREPEND(m, plen, how)	do {					\
	struct mbuf **_mmp = &(m);					\
	struct mbuf *_mm = *_mmp;					\
	int _mplen = (plen);						\
	if (M_LEADINGSPACE(_mm) >= _mplen) {				\
		_mm->m_data -= _mplen;					\
		_mm->m_len += _mplen;					\
	} else								\
		_mm = m_prepend(_mm, _mplen, (how));			\
	if (_mm != NULL && (_mm->m_flags & M_PKTHDR))			\
		_mm->m_pkthdr.len += _mplen;				\
	*_mmp = _mm;							\
} while (0)
#define	m_rcvif(m)		((m)->m_pkthdr.rcvif)
#define	M_SETFIB(m, fib)	((m)->m_pkthdr.fibnum = (fib))
static inline void
m_clrprotoflags(struct mbuf *m)
{
	for (; m != NULL; m = m->m_next)
		m->m_flags &= ~M_PROTOFLAGS;
}

/* ------------------------------------------------------------------ */
/* net/ethernet.h, net/ppp_defs.h                                       */
/* ------------------------------------------------------------------ */
#define	ETHER_ADDR_LEN		6
#define	ETHER_TYPE_LEN		2
#define	ETHER_CRC_LEN		4
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define	ETHER_MIN_LEN		64
#define	ETHER_MAX_LEN		1518
#define	ETHERMTU		(ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define	ETHER_VLAN_ENCAP_LEN	4
#define	ETHERTYPE_IP		0x0800
#define	ETHERTYPE_IPV6		0x86dd
#define	ETHERTYPE_VLAN		0x8100
#define	ETHERTYPE_PPPOEDISC	0x8863
#define	ETHERTYPE_PPPOE		0x8864
struct ether_header {
	uint8_t		ether_dhost[ETHER_ADDR_LEN];
	uint8_t		ether_shost[ETHER_ADDR_LEN];
	uint16_t	ether_type;
} __packed;
struct ether_addr { uint8_t octet[ETHER_ADDR_LEN]; } __packed;

#define	PPP_ADDRESS(p)	(((const u_char *)(p))[0])
#define	PPP_HDRLEN	4
#define	PPP_FCSLEN	2
#define	PPP_MTU		1500
#define	PPP_MAXMRU	65000
#define	PPP_ALLSTATIONS	0xff
#define	PPP_UI		0x03
#define	PPP_IP		0x0021
#define	PPP_ISO		0x0023
#define	PPP_XNS		0x0025
#define	PPP_IPX		0x002b
#define	PPP_VJC_COMP	0x002d
#define	PPP_VJC_UNCOMP	0x002f
#define	PPP_IPV6	0x0057
#define	PPP_COMP	0x00fd
#define	PPP_IPCP	0x8021
#define	PPP_IPV6CP	0x8057
#define	PPP_CCP		0x80fd
#define	PPP_LCP		0xc021
#define	PPP_PAP		0xc023
#define	PPP_LQR		0xc025
#define	PPP_CHAP	0xc223
#define	PPP_CBCP	0xc029

/* ------------------------------------------------------------------ */
/* net/if.h, net/if_var.h                                               */
/* ------------------------------------------------------------------ */
#define	IFNAMSIZ	16
#define	IF_NAMESIZE	IFNAMSIZ
#define	IFF_UP		0x1
#define	IFF_BROADCAST	0x2
#define	IFF_DEBUG	0x4
#define	IFF_LOOPBACK	0x8
#define	IFF_POINTOPOINT	0x10
#define	IFF_NEEDSEPOCH	0x20
#define	IFF_DRV_RUNNING	0x40
#define	IFF_NOARP	0x80
#define	IFF_PROMISC	0x100
#define	IFF_ALLMULTI	0x200
#define	IFF_DRV_OACTIVE	0x400
#define	IFF_SIMPLEX	0x800
#define	IFF_LINK0	0x1000
#define	IFF_LINK1	0x2000
#define	IFF_LINK2	0x4000
#define	IFF_MULTICAST	0x8000
#define	IFF_CANTCONFIG	0x10000
#define	IFF_PPROMISC	0x20000
#define	IFF_MONITOR	0x40000
#define	IFF_STATICARP	0x80000
#define	IFF_STICKYARP	0x100000
#define	IFF_DYING	0x200000
#define	IFF_RENAMING	0x400000
#define	IFF_PASSIVE	IFF_LINK0
#define	IFF_AUTO	IFF_LINK1
#define	IFF_CISCO	IFF_LINK2
#define	IFF_OACTIVE	IFF_DRV_OACTIVE
#define	LINK_STATE_UNKNOWN	0
#define	LINK_STATE_DOWN		1
#define	LINK_STATE_UP		2
#define	IFT_ETHER	0x6
#define	IFT_PPP		0x17
#define	IFT_L2VLAN	0x87
#define	IFCAP_VLAN_HWTAGGING	0x00008
#define	IF_MINMTU	72
#define	IF_MAXMTU	65535

typedef enum {
	IFCOUNTER_IPACKETS = 0,
	IFCOUNTER_IERRORS,
	IFCOUNTER_OPACKETS,
	IFCOUNTER_OERRORS,
	IFCOUNTER_COLLISIONS,
	IFCOUNTER_IBYTES,
	IFCOUNTER_OBYTES,
	IFCOUNTER_IMCASTS,
	IFCOUNTER_OMCASTS,
	IFCOUNTER_IQDROPS,
	IFCOUNTER_OQDROPS,
	IFCOUNTER_NOPROTO,
	IFCOUNTERS
} ift_counter;

struct ifnet;
typedef struct ifnet *if_t;
struct route;
struct rtentry;
struct ifaddr {
	struct sockaddr	*ifa_addr;
	struct sockaddr	*ifa_dstaddr;
	struct sockaddr	*ifa_netmask;
	struct ifnet	*ifa_ifp;
	CK_STAILQ_ENTRY(ifaddr) ifa_link;
	u_int		 ifa_flags;
	u_int		 ifa_refcnt;
};
CK_STAILQ_HEAD(ifaddrhead, ifaddr);
struct ifaltq {
	struct mbuf	*ifq_head;
	struct mbuf	*ifq_tail;
	int		 ifq_len;
	int		 ifq_maxlen;
	struct mtx	 ifq_mtx;
	int		 altq_type;
	int		 altq_flags;
};
#define	ALTQF_ENABLED	0x02
#define	ALTQ_IS_ENABLED(ifq)	(((ifq)->altq_flags & ALTQF_ENABLED) != 0)
struct ifqueue {
	struct mbuf	*ifq_head;
	struct mbuf	*ifq_tail;
	int		 ifq_len;
	int		 ifq_maxlen;
	struct mtx	 ifq_mtx;
};
#define	_IF_QFULL(ifq)		((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define	IFQ_IS_EMPTY(ifq)	((ifq)->ifq_len == 0)
#define	IFQ_DEQUEUE(ifq, m)	do {					\
	(m) = (ifq)->ifq_head;						\
	if ((m) != NULL) {						\
		if (((ifq)->ifq_head = (m)->m_nextpkt) == NULL)		\
			(ifq)->ifq_tail = NULL;				\
		(m)->m_nextpkt = NULL;					\
		(ifq)->ifq_len--;					\
	}								\
} while (0)
#define	IFQ_PURGE(ifq)		do {					\
	struct mbuf *__pm;						\
	for (;;) {							\
		IFQ_DEQUEUE((ifq), __pm);				\
		if (__pm == NULL)					\
			break;						\
		m_freem(__pm);						\
	}								\
} while (0)
#define	IFQ_SET_MAXLEN(ifq, l)	((ifq)->ifq_maxlen = (l))
#define	IFQ_SET_READY(ifq)	do { } while (0)
#define	ifq_maxlen_default	50

struct ifreq {
	char	ifr_name[IFNAMSIZ];
	union {
		struct sockaddr	ifru_addr;
		struct sockaddr	ifru_dstaddr;
		short		ifru_flags[2];
		int		ifru_mtu;
		int		ifru_metric;
		caddr_t		ifru_data;
		uint32_t	ifru_fib;
	} ifr_ifru;
};
#define	ifr_addr	ifr_ifru.ifru_addr
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr
#define	ifr_flags	ifr_ifru.ifru_flags[0]
#define	ifr_mtu		ifr_ifru.ifru_mtu
#define	ifr_data	ifr_ifru.ifru_data
#define	ifr_metric	ifr_ifru.ifru_metric
struct in_aliasreq {
	char			ifra_name[IFNAMSIZ];
	struct sockaddr_in	ifra_addr;
	struct sockaddr_in	ifra_broadaddr;
#define	ifra_dstaddr	ifra_broadaddr
	struct sockaddr_in	ifra_mask;
	int			ifra_vhid;
};
struct in6_addrlifetime { time_t ia6t_expire, ia6t_preferred; uint32_t ia6t_vltime, ia6t_pltime; };
struct in6_aliasreq {
	char			ifra_name[IFNAMSIZ];
	struct sockaddr_in6	ifra_addr;
	struct sockaddr_in6	ifra_dstaddr;
	struct sockaddr_in6	ifra_prefixmask;
	int			ifra_flags;
	struct in6_addrlifetime	ifra_lifetime;
	int			ifra_vhid;
};
struct in6_ifreq {
	char	ifr_name[IFNAMSIZ];
	union { struct sockaddr_in6 ifru_addr; int ifru_flags6; } ifr_ifru;
};
struct in_ifaddr { struct ifaddr ia_ifa; struct sockaddr_in ia_addr; };
struct in6_ifaddr { struct ifaddr ia_ifa; struct sockaddr_in6 ia_addr; int ia6_flags; };

#define	SIOCSIFADDR	_IOW('i', 12, struct ifreq)
#define	SIOCSIFDSTADDR	_IOW('i', 14, struct ifreq)
#define	SIOCSIFFLAGS	_IOW('i', 16, struct ifreq)
#define	SIOCADDMULTI	_IOW('i', 49, struct ifreq)
#define	SIOCDELMULTI	_IOW('i', 50, struct ifreq)
#define	SIOCGIFMTU	_IOWR('i', 51, struct ifreq)
#define	SIOCSIFMTU	_IOW('i', 52, struct ifreq)
#define	SIOCDIFADDR	_IOW('i', 25, struct ifreq)
#define	SIOCAIFADDR	_IOW('i', 43, struct in_aliasreq)
#define	SIOCAIFADDR_IN6	_IOW('i', 27, struct in6_aliasreq)
#define	SIOCDIFADDR_IN6	_IOW('i', 25, struct in6_ifreq)
#define	SIOCSIFCAP	_IOW('i', 30, struct ifreq)
#define	SIOCGIFSTATUS	_IOWR('i', 59, struct ifreq)

typedef int	(*if_output_fn_t)(struct ifnet *, struct mbuf *, const struct sockaddr *, struct route *);
typedef int	(*if_transmit_fn_t)(struct ifnet *, struct mbuf *);
typedef int	(*if_ioctl_fn_t)(struct ifnet *, u_long, caddr_t);
typedef void	(*if_qflush_fn_t)(struct ifnet *);
typedef void	(*if_start_fn_t)(struct ifnet *);

struct ifnet {
	char		 if_xname[IFNAMSIZ];
	const char	*if_dname;
	int		 if_dunit;
	u_short		 if_index;
	int		 if_flags;
	int		 if_drv_flags;
	int		 if_capenable;
	int		 if_capabilities;
	uint64_t	 if_hwassist;
	u_char		 if_type;
	u_char		 if_addrlen;
	u_char		 if_link_state;
	uint32_t	 if_mtu;
	void		*if_softc;
	void		*if_llsoftc;
	void		*if_bpf;
	uint8_t		 if_pcp;
	u_int		 if_fib;
	struct vnet	*if_vnet;
	struct ifaddr	*if_addr;
	struct ifaddrhead if_addrhead;
	struct ifaltq	 if_snd;
	struct task	 if_linktask;
	if_output_fn_t	 if_output;
	if_transmit_fn_t if_transmit;
	if_ioctl_fn_t	 if_ioctl;
	if_qflush_fn_t	 if_qflush;
	if_start_fn_t	 if_start;
	void		*if_afdata[64];
	uint64_t	 if_counters[IFCOUNTERS];
	/* kshim bookkeeping: frames the stack transmitted on this ifnet */
	struct mbuf	*kshim_txq_head;
	struct mbuf	*kshim_txq_tail;
	int		 kshim_txq_len;
	int		 kshim_link_changes;
	int		 kshim_refs;
	int		 kshim_dlt;	/* bpfattach() link type, -1: none */
	u_int		 kshim_bpf_hdrlen;
};

void	if_inc_counter(struct ifnet *, ift_counter, int64_t);
uint64_t if_getcounter(struct ifnet *, ift_counter);
void	if_link_state_change(struct ifnet *, int);
int	if_transmit(struct ifnet *, struct mbuf *);
const char *if_name(struct ifnet *);
#define	if_getllsoftc(ifp)	((ifp)->if_llsoftc)
#define	if_setllsoftc(ifp, s)	((ifp)->if_llsoftc = (s))
#define	if_getsoftc(ifp)	((ifp)->if_softc)
#define	if_getfib(ifp)		((ifp)->if_fib)
#define	if_setsoftc(ifp, s)	((ifp)->if_softc = (s))
#define	if_getflags(ifp)	((ifp)->if_flags)
#define	if_setflags(ifp, f)	((ifp)->if_flags = (f))
#define	if_setflagbits(ifp, s, c) ((ifp)->if_flags = ((ifp)->if_flags | (s)) & ~(c))
#define	if_getdrvflags(ifp)	((ifp)->if_drv_flags)
#define	if_setdrvflags(ifp, f)	((ifp)->if_drv_flags = (f))
#define	if_setdrvflagbits(ifp, s, c) \
	((ifp)->if_drv_flags = ((ifp)->if_drv_flags | (s)) & ~(c))
#define	if_getmtu(ifp)		((ifp)->if_mtu)
#define	if_setmtu(ifp, v)	((ifp)->if_mtu = (v))
#define	if_gettype(ifp)		((ifp)->if_type)
#define	if_getvnet(ifp)		((ifp)->if_vnet)
#define	if_getindex(ifp)	((ifp)->if_index)
#define	if_getcapenable(ifp)	((ifp)->if_capenable)
#define	if_getlladdr(ifp)	(LLADDR((struct sockaddr_dl *)(ifp)->if_addr->ifa_addr))
#define	if_getafdata(ifp, af)	((ifp)->if_afdata[(af)])
#define	if_getlinkstate(ifp)	((ifp)->if_link_state)
#define	if_setoutputfn(ifp, f)	((ifp)->if_output = (f))
#define	if_settransmitfn(ifp, f) ((ifp)->if_transmit = (f))
#define	if_setioctlfn(ifp, f)	((ifp)->if_ioctl = (f))
#define	if_setqflushfn(ifp, f)	((ifp)->if_qflush = (f))
#define	if_setstartfn(ifp, f)	((ifp)->if_start = (f))
#define	if_setsendqlen(ifp, l)	do { } while (0)
#define	if_setsendqready(ifp)	do { } while (0)
#define	if_setifheaderlen(ifp, l) do { } while (0)
#define	if_setmtu_locked	if_setmtu
#define	if_ref(ifp)		((ifp)->kshim_refs++)
#define	if_rele(ifp)		((ifp)->kshim_refs--)
#define	if_altq_is_enabled(ifp)	ALTQ_IS_ENABLED(&(ifp)->if_snd)
#define	IFNET_WLOCK()		do { } while (0)
#define	IFNET_WUNLOCK()		do { } while (0)
#define	IFNET_RLOCK()		do { } while (0)
#define	IFNET_RUNLOCK()		do { } while (0)
#define	IF_ADDR_RLOCK(ifp)	do { } while (0)
#define	IF_ADDR_RUNLOCK(ifp)	do { } while (0)
#define	IF_ADDR_WLOCK(ifp)	do { } while (0)
#define	IF_ADDR_WUNLOCK(ifp)	do { } while (0)
#define	ifa_ref(ifa)		((ifa)->ifa_refcnt++)
#define	ifa_free(ifa)		((ifa)->ifa_refcnt--)
/* bpf(4) taps are recorded (kshim.h: kshim_bpf_*); data is not const,
 * exactly as bpf_mtap2_if() declares it (net/bpf.h). */
void	kshim_bpf_mtap2(struct ifnet *, void *, u_int, struct mbuf *);
#define	BPF_MTAP(ifp, m)	kshim_bpf_mtap2((ifp), NULL, 0, (m))
#define	BPF_MTAP2(ifp, d, l, m)	kshim_bpf_mtap2((ifp), (d), (l), (m))
#define	bpf_peers_present(b)	0
#define	if_bpfmtap(ifp, m)	do { (void)(ifp); (void)(m); } while (0)
#define	rt_ifmsg(ifp, f)	do { (void)(ifp); } while (0)
extern int kshim_notifymtu_calls;	/* if_notifymtu() calls, for tests */
#define	if_notifymtu(ifp)	do { (void)(ifp); kshim_notifymtu_calls++; } while (0)

struct bpf_insn { u_short code; u_char jt, jf; uint32_t k; };
struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; };
#define	BPF_MAXINSNS	512

/* Stubbed network-stack entry points (kshim.c records calls). */
void	ip_input(struct mbuf *);
void	ip6_input(struct mbuf *);
int	ether_output_frame(struct ifnet *, struct mbuf *);
extern int kshim_ip_input_calls, kshim_ip6_input_calls;
int	in_control_ioctl(u_long, void *, struct ifnet *, struct ucred *);
int	in6_control_ioctl(u_long, void *, struct ifnet *, struct ucred *);
int	in6_setscope(struct in6_addr *, struct ifnet *, uint32_t *);
struct in6_ifaddr *in6ifa_ifpforlinklocal(struct ifnet *, int);
void	if_up(struct ifnet *);
void	if_down(struct ifnet *);

/* netisr(9) / RSS */
typedef void netisr_handler_t(struct mbuf *);
typedef struct mbuf *netisr_m2cpuid_t(struct mbuf *, uintptr_t, u_int *);
typedef struct mbuf *netisr_m2flow_t(struct mbuf *, uintptr_t);
typedef void netisr_drainedcpu_t(u_int);
struct netisr_handler {
	const char	*nh_name;
	netisr_handler_t *nh_handler;
	netisr_m2flow_t	*nh_m2flow;
	netisr_m2cpuid_t *nh_m2cpuid;
	netisr_drainedcpu_t *nh_drainedcpu;
	u_int		 nh_proto;
	u_int		 nh_qlimit;
	u_int		 nh_policy;
	u_int		 nh_dispatch;
};
#define	NETISR_POLICY_SOURCE	1
#define	NETISR_POLICY_FLOW	2
#define	NETISR_POLICY_CPU	3
#define	NETISR_DISPATCH_DEFAULT	0
#define	NETISR_DISPATCH_DEFERRED 1
#define	NETISR_DISPATCH_HYBRID	2
#define	NETISR_DISPATCH_DIRECT	3
extern u_int kshim_netisr_ncpu;
extern const struct netisr_handler *kshim_netisr_registered;
#define	netisr_get_cpucount()	(kshim_netisr_ncpu)
#define	netisr_get_cpuid(i)	((i) % kshim_netisr_ncpu)
void	netisr_register(const struct netisr_handler *);
void	netisr_unregister(const struct netisr_handler *);
void	netisr_register_vnet(const struct netisr_handler *);
void	netisr_unregister_vnet(const struct netisr_handler *);
int	netisr_dispatch(u_int, struct mbuf *);
int	netisr_dispatch_src(u_int, uintptr_t, struct mbuf *);
int	netisr_setqlimit(const struct netisr_handler *, u_int);
#define	CPU_ABSENT(i)		((u_int)(i) >= kshim_netisr_ncpu)
#define	COUNTER_ARRAY_ALLOC(a, n, w)	do {				\
	for (int __i = 0; __i < (int)(n); __i++)			\
		(a)[__i] = counter_u64_alloc((w));			\
} while (0)
#define	COUNTER_ARRAY_FREE(a, n)	do {				\
	for (int __i = 0; __i < (int)(n); __i++)			\
		counter_u64_free((a)[__i]);				\
} while (0)
int	rss_proto_software_hash_v4(struct in_addr, struct in_addr, u_short,
	    u_short, int, uint32_t *, uint32_t *);
int	rss_proto_software_hash_v6(const struct in6_addr *,
	    const struct in6_addr *, u_short, u_short, int, uint32_t *,
	    uint32_t *);
u_int	rss_hash2cpuid(uint32_t, u_int);
u_int	rss_getnumbuckets(void);
u_int	rss_getnumcpus(void);

/* nd6 */
struct nd_ifinfo { uint32_t flags; };
#define	ND6_IFF_PERFORMNUD	0x1
#define	ND6_IFF_AUTO_LINKLOCAL	0x20
#define	ND6_IFF_IFDISABLED	0x8
#define	ND_IFINFO(ifp)		((struct nd_ifinfo *)if_getafdata((ifp), AF_INET6))

/* pfil(9) */
typedef enum { PFIL_PASS = 0, PFIL_DROPPED, PFIL_CONSUMED, PFIL_REALLOCED } pfil_return_t;
struct inpcb;
typedef pfil_return_t (*pfil_mbuf_chk_t)(struct mbuf **, struct ifnet *, int, void *, struct inpcb *);
typedef struct pfil_hook *pfil_hook_t;
typedef struct pfil_head *pfil_head_t;
#define	PFIL_VERSION		2
#define	PFIL_IN			0x00010000
#define	PFIL_OUT		0x00020000
#define	PFIL_HEADPTR		0x00100000
#define	PFIL_HOOKPTR		0x00200000
#define	PFIL_UNLINK		0x00400000
#define	PFIL_TYPE_ETHERNET	3
struct pfil_hook_args {
	int		 pa_version;
	int		 pa_flags;
	int		 pa_type;
	pfil_mbuf_chk_t	 pa_mbuf_chk;
	void		*pa_ruleset;
	const char	*pa_modname;
	const char	*pa_rulname;
};
struct pfil_link_args {
	int		 pa_version;
	int		 pa_flags;
	union { const char *pa_headname; pfil_head_t pa_head; };
	union { struct { const char *pa_modname, *pa_rulname; }; pfil_hook_t pa_hook; };
};
extern pfil_head_t kshim_link_pfil_head;
#define	V_link_pfil_head	kshim_link_pfil_head
pfil_hook_t pfil_add_hook(struct pfil_hook_args *);
void	pfil_remove_hook(pfil_hook_t);
int	pfil_link(struct pfil_link_args *);

/* if_clone(9) and ifnet lifecycle */
struct if_clone;
struct ifc_data { uint32_t flags; uint32_t unit; void *params; };
typedef int ifc_create_f(struct if_clone *, char *, size_t, struct ifc_data *, struct ifnet **);
typedef int ifc_destroy_f(struct if_clone *, struct ifnet *, uint32_t);
struct if_clone_addreq {
	uint16_t	 version;
	uint16_t	 spare;
	uint32_t	 flags;
	uint32_t	 maxunit;
	void		*match_f;
	ifc_create_f	*create_f;
	ifc_destroy_f	*destroy_f;
};
#define	IFC_F_AUTOUNIT		0x01
#define	IFC_F_FORCE		0x02
struct if_clone *ifc_attach_cloner(const char *, struct if_clone_addreq *);
void	ifc_detach_cloner(struct if_clone *);
int	if_clone_destroy(const char *);
struct ifnet *if_alloc(u_char);
void	if_free(struct ifnet *);
void	if_initname(struct ifnet *, const char *, int);
void	if_attach(struct ifnet *);
void	if_detach(struct ifnet *);
struct ifnet *ifunit_ref(const char *);
struct ifnet *ifunit(const char *);
#define	DLT_NULL		0
#define	DLT_PPP			9
#define	DLT_PPP_ETHER		51
void	kshim_bpfattach(struct ifnet *, u_int, u_int);
#define	bpfattach(ifp, d, h)	kshim_bpfattach((ifp), (d), (h))
#define	bpfdetach(ifp)		do { (void)(ifp); } while (0)

#endif /* _KSHIM_KERN_H_ */
