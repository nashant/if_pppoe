/*
 * kshim.c -- userland implementation of the KPIs declared in kern.h.
 * Single-threaded: locks track ownership only; tasks and callouts run when a
 * test asks; each mbuf's storage is its own heap block (exact ASan bounds).
 */
#include "kshim.h"

#undef malloc
#undef free
#undef printf
#undef log
#undef strlcpy
#undef strlcat
#undef arc4random
#undef arc4random_buf
#undef inet_ntop

/* ------------------------------------------------------------------ */
/* panic / KASSERT                                                      */
/* ------------------------------------------------------------------ */
jmp_buf	*kshim_panic_jmp;
char	 kshim_panic_msg[512];
int	 kshim_panics;

void
kshim_panic(const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	int n;

	n = snprintf(kshim_panic_msg, sizeof(kshim_panic_msg), "%s:%d: ",
	    file, line);
	va_start(ap, fmt);
	vsnprintf(kshim_panic_msg + n, sizeof(kshim_panic_msg) - n, fmt, ap);
	va_end(ap);
	kshim_panics++;
	if (kshim_panic_jmp != NULL)
		longjmp(*kshim_panic_jmp, 1);
	fprintf(stderr, "panic: %s\n", kshim_panic_msg);
	abort();
}

const char *
kshim_kassert_msg(const char *fmt, ...)
{
	static char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return (buf);
}

/* ------------------------------------------------------------------ */
/* log(9) / printf capture                                              */
/* ------------------------------------------------------------------ */
#define	KSHIM_LOG_MAX	256
struct klogrec { int pri; char *text; };
static struct klogrec klog[KSHIM_LOG_MAX];
static int klog_n;
int kshim_log_echo = -1;

static void
klog_add(int pri, const char *fmt, va_list ap)
{
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	if (kshim_log_echo < 0)
		kshim_log_echo = getenv("KSHIM_VERBOSE") != NULL;
	if (kshim_log_echo)
		fprintf(stderr, "[log %d] %s%s", pri, buf,
		    (buf[0] && buf[strlen(buf) - 1] == '\n') ? "" : "\n");
	if (klog_n == KSHIM_LOG_MAX) {
		free(klog[0].text);
		memmove(&klog[0], &klog[1], sizeof(klog[0]) * (KSHIM_LOG_MAX - 1));
		klog_n--;
	}
	klog[klog_n].pri = pri;
	klog[klog_n].text = strdup(buf);
	klog_n++;
}

void
kshim_log(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	klog_add(pri, fmt, ap);
	va_end(ap);
}

int
kshim_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	klog_add(KSHIM_LOG_PRINTF, fmt, ap);
	va_end(ap);
	return (0);
}

int kshim_log_count(void) { return (klog_n); }

const char *
kshim_log_get(int idx, int *pri)
{
	if (idx < 0 || idx >= klog_n)
		return (NULL);
	if (pri != NULL)
		*pri = klog[idx].pri;
	return (klog[idx].text);
}

int
kshim_log_find(const char *needle)
{
	for (int i = 0; i < klog_n; i++)
		if (strstr(klog[i].text, needle) != NULL)
			return (i);
	return (-1);
}

void
kshim_log_clear(void)
{
	for (int i = 0; i < klog_n; i++)
		free(klog[i].text);
	klog_n = 0;
}

void
devctl_notify(const char *sys, const char *subsys, const char *type,
    const char *data)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "devctl system=%s subsystem=%s type=%s %s",
	    sys, subsys, type, data != NULL ? data : "");
	kshim_log(KSHIM_LOG_DEVCTL, "%s", buf);
}

/* ------------------------------------------------------------------ */
/* libkern                                                              */
/* ------------------------------------------------------------------ */
size_t
kshim_strlcpy(char *dst, const char *src, size_t sz)
{
	size_t n = strlen(src);

	if (sz != 0) {
		size_t c = n >= sz ? sz - 1 : n;

		memcpy(dst, src, c);
		dst[c] = '\0';
	}
	return (n);
}

size_t
kshim_strlcat(char *dst, const char *src, size_t sz)
{
	size_t d = strnlen(dst, sz);

	if (d == sz)
		return (sz + strlen(src));
	return (d + kshim_strlcpy(dst + d, src, sz - d));
}

/* sys/hash.h: Bob Jenkins' one-at-a-time over 32-bit words -- a stand-in
 * for the kernel's Toeplitz hash, deterministic and good enough to spread
 * flows across CPUs in tests (see tests/unit/t/netisr_hash.c). */
uint32_t
jenkins_hash32(const uint32_t *k, size_t length, uint32_t initval)
{
	uint32_t hash = initval;

	for (size_t i = 0; i < length; i++) {
		hash += k[i];
		hash += hash << 10;
		hash ^= hash >> 6;
	}
	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;
	return (hash);
}

static uint64_t krand_state = 0x9e3779b97f4a7c15ULL;

uint32_t
kshim_arc4random(void)
{
	/* xorshift64*: deterministic so failures reproduce. */
	krand_state ^= krand_state >> 12;
	krand_state ^= krand_state << 25;
	krand_state ^= krand_state >> 27;
	return ((uint32_t)((krand_state * 0x2545f4914f6cdd1dULL) >> 32));
}

void
kshim_arc4random_seed(uint64_t seed)
{
	krand_state = seed != 0 ? seed : 0x9e3779b97f4a7c15ULL;
}

void
kshim_arc4random_buf(void *p, size_t n)
{
	uint8_t *b = p;

	while (n-- > 0)
		*b++ = (uint8_t)kshim_arc4random();
}

bool kshim_random_seeded = true;

bool
kshim_is_random_seeded(void)
{
	return (kshim_random_seeded);
}

void
kshim_read_random(void *p, u_int n)
{
	if (!kshim_random_seeded)
		kshim_panic(__FILE__, __LINE__, "read_random() while unseeded");
	kshim_arc4random_buf(p, n);
}

const char *
kshim_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
	const uint8_t *a = src;

	if (af == AF_INET)
		snprintf(dst, size, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	else if (af == AF_INET6)
		snprintf(dst, size, "%x:%x:%x:%x:%x:%x:%x:%x",
		    a[0] << 8 | a[1], a[2] << 8 | a[3], a[4] << 8 | a[5],
		    a[6] << 8 | a[7], a[8] << 8 | a[9], a[10] << 8 | a[11],
		    a[12] << 8 | a[13], a[14] << 8 | a[15]);
	else
		return (NULL);
	return (dst);
}

char *
inet_ntoa_r(struct in_addr in, char *buf)
{
	kshim_inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN);
	return (buf);
}

char *
ip6_sprintf(char *buf, const struct in6_addr *a)
{
	kshim_inet_ntop(AF_INET6, a, buf, INET6_ADDRSTRLEN);
	return (buf);
}

/* ------------------------------------------------------------------ */
/* malloc(9)                                                            */
/* ------------------------------------------------------------------ */
MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");
int kshim_malloc_nowait_fail;
int kshim_notifymtu_calls;

/*
 * Every malloc(9) block is carved at `hdr` bytes into a block aligned to
 * 2 * hdr, with the base pointer stored just below it: plain malloc() gets
 * hdr = KSHIM_MALLOC_ALIGN, so its result is aligned to exactly that (what
 * "suitably aligned for storage of any type of object" promises) and
 * deliberately never to anything more.  Code that needs more -- a
 * __aligned(CACHE_LINE_SIZE) struct -- must say so with malloc_aligned(9),
 * or UBSan's alignment check trips on every run, not only when glibc
 * happens to hand out a misaligned block.  The block ends exactly at the
 * caller's size, so ASan still catches an overrun.
 */
#define	KSHIM_MALLOC_ALIGN	16

static void *
kshim_malloc_at(size_t sz, size_t hdr, struct malloc_type *t, int flags)
{
	void *base;
	char *p;

	if ((flags & M_NOWAIT) && kshim_malloc_nowait_fail > 0 &&
	    --kshim_malloc_nowait_fail == 0)
		return (NULL);
	/* malloc(9) never returns NULL for a zero size; neither do we. */
	if (sz == 0)
		sz = 1;
	if (posix_memalign(&base, 2 * hdr, hdr + sz) != 0)
		kshim_panic(__FILE__, __LINE__, "out of memory");
	p = (char *)base + hdr;
	((void **)p)[-1] = base;
	if (flags & M_ZERO)
		memset(p, 0, sz);
	if (t != NULL)
		t->ks_inuse++;
	return (p);
}

void *
kshim_malloc(size_t sz, struct malloc_type *t, int flags)
{
	return (kshim_malloc_at(sz, KSHIM_MALLOC_ALIGN, t, flags));
}

/* sys/kern/kern_malloc.c malloc_domainset_aligned(): same KASSERTs. */
void *
kshim_malloc_aligned(size_t sz, size_t align, struct malloc_type *t,
    int flags)
{
	if (align == 0 || !powerof2(align) || align > PAGE_SIZE)
		kshim_panic(__FILE__, __LINE__, "malloc_aligned: bad align");
	return (kshim_malloc_at(sz, align < KSHIM_MALLOC_ALIGN ?
	    KSHIM_MALLOC_ALIGN : align, t, flags));
}

void
kshim_free(void *p, struct malloc_type *t)
{
	if (p == NULL)
		return;
	if (t != NULL)
		t->ks_inuse--;
	free(((void **)p)[-1]);
}

void
kshim_zfree(void *p, struct malloc_type *t)
{
	kshim_free(p, t);
}

long
kshim_malloc_inuse(struct malloc_type *t)
{
	return (t->ks_inuse);
}

/* ------------------------------------------------------------------ */
/* time                                                                 */
/* ------------------------------------------------------------------ */
volatile time_t	kshim_time_uptime = 1000;
int		kshim_ticks = 1;

void
getmicrouptime(struct timeval *tv)
{
	tv->tv_sec = kshim_time_uptime;
	tv->tv_usec = 0;
}

/* sys/kern/kern_time.c ppsratecheck() semantics, on kshim time. */
int
ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
	struct timeval now;

	getmicrouptime(&now);
	if (lasttime->tv_sec == 0 || now.tv_sec - lasttime->tv_sec >= 1) {
		*lasttime = now;
		*curpps = 1;
		return (maxpps != 0);
	}
	if (*curpps < INT_MAX)
		(*curpps)++;
	return (maxpps < 0 || *curpps <= maxpps);
}

int
ratecheck(struct timeval *last, const struct timeval *min)
{
	struct timeval now;

	getmicrouptime(&now);
	if (last->tv_sec == 0 || now.tv_sec - last->tv_sec >= min->tv_sec) {
		*last = now;
		return (1);
	}
	return (0);
}

/* ------------------------------------------------------------------ */
/* locks                                                                */
/* ------------------------------------------------------------------ */
static int klocks_held;

void
kshim_mtx_init(struct mtx *m, const char *name, const char *type, int opts)
{
	(void)type;
	memset(m, 0, sizeof(*m));
	m->lock_object.lo_name = name;
	m->lock_object.lo_flags = opts;
	m->mtx_inited = 1;
	m->mtx_spin = (opts & MTX_SPIN) != 0;
}

void
kshim_mtx_destroy(struct mtx *m)
{
	if (m->mtx_owned)
		kshim_panic(__FILE__, __LINE__, "destroying owned mutex %s",
		    m->lock_object.lo_name);
	m->mtx_inited = 0;
}

void
kshim_mtx_lock(struct mtx *m, const char *file, int line)
{
	if (!m->mtx_inited)
		kshim_panic(file, line, "lock of uninitialized mutex %p", m);
	if (m->mtx_owned && !(m->lock_object.lo_flags & MTX_RECURSE))
		kshim_panic(file, line, "recursed on non-recursive mutex %s",
		    m->lock_object.lo_name);
	m->mtx_owned++;
	klocks_held++;
}

void
kshim_mtx_unlock(struct mtx *m, const char *file, int line)
{
	if (!m->mtx_owned)
		kshim_panic(file, line, "unlock of unowned mutex %s",
		    m->lock_object.lo_name);
	m->mtx_owned--;
	klocks_held--;
}

void
kshim_mtx_assert(struct mtx *m, int what, const char *file, int line)
{
	if ((what & MA_OWNED) && !m->mtx_owned)
		kshim_panic(file, line, "mutex %s not owned",
		    m->lock_object.lo_name);
	if ((what & MA_NOTOWNED) && m->mtx_owned)
		kshim_panic(file, line, "mutex %s owned",
		    m->lock_object.lo_name);
}

int kshim_locks_held(void) { return (klocks_held); }
void kshim_locks_reset(void) { klocks_held = 0; }

/* ------------------------------------------------------------------ */
/* taskqueue / callout                                                  */
/* ------------------------------------------------------------------ */
static struct taskqueue ktq_thread = { "thread" }, ktq_swi = { "swi" };
struct taskqueue *taskqueue_thread = &ktq_thread;
struct taskqueue *taskqueue_swi = &ktq_swi;
static struct task *ktq_head, *ktq_tail;
int kshim_taskq_start_fail;

void taskqueue_thread_enqueue(void *ctx) { (void)ctx; }

struct taskqueue *
taskqueue_create(const char *name, int mflags, taskqueue_enqueue_fn fn,
    void *ctx)
{
	struct taskqueue *tq = calloc(1, sizeof(*tq));

	(void)mflags; (void)fn; (void)ctx;
	tq->tq_name = name;
	return (tq);
}

int
taskqueue_start_threads(struct taskqueue **tqp, int count, int pri,
    const char *name, ...)
{
	(void)pri; (void)name;
	if (kshim_taskq_start_fail != 0)
		return (kshim_taskq_start_fail);
	(*tqp)->tq_threads += count;
	return (0);
}

static bool ktq_queued_on(struct taskqueue *);

void
taskqueue_drain_all(struct taskqueue *tq)
{
	/* Runs everything: one FIFO backs every queue here. */
	if (ktq_queued_on(tq))
		kshim_run_tasks();
}

void
taskqueue_free(struct taskqueue *tq)
{
	if (tq == taskqueue_thread || tq == taskqueue_swi)
		kshim_panic(__FILE__, __LINE__, "taskqueue_free(%s)",
		    tq->tq_name);
	taskqueue_drain_all(tq);
	free(tq);
}

int
taskqueue_enqueue(struct taskqueue *tq, struct task *t)
{
	if (tq == NULL)
		kshim_panic(__FILE__, __LINE__, "taskqueue_enqueue(NULL)");
	tq->tq_enqueued++;
	t->ta_queue = tq;
	if (t->ta_pending) {
		t->ta_pending++;
		return (0);
	}
	t->ta_pending = 1;
	t->ta_next = NULL;
	if (ktq_tail != NULL)
		ktq_tail->ta_next = t;
	else
		ktq_head = t;
	ktq_tail = t;
	return (0);
}

static bool
ktq_unlink(struct task *t)
{
	struct task **pp, *prev = NULL;

	for (pp = &ktq_head; *pp != NULL; prev = *pp, pp = &(*pp)->ta_next) {
		if (*pp == t) {
			*pp = t->ta_next;
			if (ktq_tail == t)
				ktq_tail = prev;
			t->ta_next = NULL;
			return (true);
		}
	}
	return (false);
}

static void
ktq_run(struct task *t)
{
	int pending = t->ta_pending;

	/* taskqueue_thread runs handlers with no locks held. */
	if (klocks_held != 0)
		kshim_panic(__FILE__, __LINE__,
		    "task %p run with %d lock(s) held", (void *)t, klocks_held);
	t->ta_pending = 0;
	t->ta_func(t->ta_context, pending);
}

int
kshim_run_tasks(void)
{
	int n = 0;

	while (ktq_head != NULL) {
		struct task *t = ktq_head;

		ktq_unlink(t);
		ktq_run(t);
		if (++n > 100000)
			kshim_panic(__FILE__, __LINE__, "taskqueue livelock");
	}
	return (n);
}

static bool
ktq_queued_on(struct taskqueue *tq)
{
	for (struct task *t = ktq_head; t != NULL; t = t->ta_next)
		if (t->ta_queue == tq)
			return (true);
	return (false);
}

int
kshim_tasks_pending(void)
{
	int n = 0;

	for (struct task *t = ktq_head; t != NULL; t = t->ta_next)
		n++;
	return (n);
}

void
kshim_tasks_reset(void)
{
	while (ktq_head != NULL) {
		struct task *t = ktq_head;

		ktq_unlink(t);
		t->ta_pending = 0;
	}
}

void
taskqueue_drain(struct taskqueue *tq, struct task *t)
{
	/* The kernel's takes TQ_LOCK(queue) first (subr_taskqueue.c:617). */
	if (tq == NULL)
		kshim_panic(__FILE__, __LINE__, "taskqueue_drain(NULL)");
	if (ktq_unlink(t))
		ktq_run(t);
}

int
taskqueue_cancel(struct taskqueue *tq, struct task *t, u_int *pendp)
{
	(void)tq;
	if (pendp != NULL)
		*pendp = t->ta_pending;
	if (ktq_unlink(t))
		t->ta_pending = 0;
	return (0);
}

void
callout_init(struct callout *c, int mpsafe)
{
	(void)mpsafe;
	memset(c, 0, sizeof(*c));
	c->c_inited = 1;
}

void
callout_init_mtx(struct callout *c, struct mtx *m, int flags)
{
	(void)flags;
	callout_init(c, 0);
	c->c_lock = m;
}

int
callout_reset(struct callout *c, int t, void (*fn)(void *), void *arg)
{
	int was = c->c_pending;

	if (c->c_lock != NULL)
		mtx_assert(c->c_lock, MA_OWNED);
	c->c_func = fn;
	c->c_arg = arg;
	c->c_time = kshim_ticks + t;
	c->c_pending = 1;
	return (was);
}

int
callout_stop(struct callout *c)
{
	int was = c->c_pending;

	c->c_pending = 0;
	return (was);
}

int
callout_drain(struct callout *c)
{
	return (callout_stop(c));
}

int
kshim_callout_fire(struct callout *c)
{
	if (!c->c_pending)
		return (0);
	c->c_pending = 0;
	if (c->c_lock != NULL)
		mtx_lock(c->c_lock);
	c->c_func(c->c_arg);
	if (c->c_lock != NULL)
		mtx_unlock(c->c_lock);
	return (1);
}

/* ------------------------------------------------------------------ */
/* threads / privileges / copyin                                        */
/* ------------------------------------------------------------------ */
static struct ucred kcred;
static struct thread kthread0 = { &kcred };
struct thread *curthread = &kthread0;

int priv_check(struct thread *td, int priv) { (void)td; (void)priv; return (0); }

int
copyin(const void *u, void *k, size_t n)
{
	if (u == NULL && n != 0)
		return (EFAULT);
	memcpy(k, u, n);
	return (0);
}

int
copyout(const void *k, void *u, size_t n)
{
	if (u == NULL && n != 0)
		return (EFAULT);
	memcpy(u, k, n);
	return (0);
}

int
copyinstr(const void *u, void *k, size_t n, size_t *done)
{
	size_t l;

	if (u == NULL)
		return (EFAULT);
	l = strnlen(u, n);
	if (l == n)
		return (ENAMETOOLONG);
	memcpy(k, u, l + 1);
	if (done != NULL)
		*done = l + 1;
	return (0);
}

/* ------------------------------------------------------------------ */
/* counter / sysctl / sbuf                                              */
/* ------------------------------------------------------------------ */
counter_u64_t
counter_u64_alloc(int flags)
{
	(void)flags;
	return (calloc(1, sizeof(uint64_t)));
}

void counter_u64_free(counter_u64_t c) { free(c); }

int sysctl_handle_int(struct sysctl_oid *o, void *a1, intmax_t a2, struct sysctl_req *r)
{ (void)o; (void)a1; (void)a2; (void)r; return (0); }
int sysctl_handle_string(struct sysctl_oid *o, void *a1, intmax_t a2, struct sysctl_req *r)
{ (void)o; (void)a1; (void)a2; (void)r; return (0); }
int sysctl_wire_old_buffer(struct sysctl_req *r, size_t l) { (void)r; (void)l; return (0); }

struct sbuf *
sbuf_new(struct sbuf *s, char *buf, int len, int flags)
{
	(void)buf; (void)flags;
	s->s_size = len > 0 ? (size_t)len : 128;
	s->s_buf = calloc(1, s->s_size);
	s->s_len = 0;
	return (s);
}

struct sbuf *
sbuf_new_for_sysctl(struct sbuf *s, char *buf, int len, struct sysctl_req *r)
{
	(void)r;
	return (sbuf_new(s, buf, len, 0));
}

int
sbuf_printf(struct sbuf *s, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (s->s_len + n + 1 > s->s_size) {
		s->s_size = s->s_len + n + 1;
		s->s_buf = realloc(s->s_buf, s->s_size);
	}
	va_start(ap, fmt);
	vsnprintf(s->s_buf + s->s_len, n + 1, fmt, ap);
	va_end(ap);
	s->s_len += n;
	return (0);
}

int sbuf_cat(struct sbuf *s, const char *str) { return (sbuf_printf(s, "%s", str)); }
int sbuf_finish(struct sbuf *s) { (void)s; return (0); }
void sbuf_delete(struct sbuf *s) { free(s->s_buf); s->s_buf = NULL; }
char *sbuf_data(struct sbuf *s) { return (s->s_buf); }
ssize_t sbuf_len(struct sbuf *s) { return ((ssize_t)s->s_len); }

/* ------------------------------------------------------------------ */
/* epoch / vnet                                                         */
/* ------------------------------------------------------------------ */
int kshim_net_epoch_depth;
static struct vnet kvnet0;
struct vnet *kshim_vnet0 = &kvnet0;

/* ------------------------------------------------------------------ */
/* mbuf(9)                                                              */
/* ------------------------------------------------------------------ */
static int kmbufs;

static struct mbuf *
kmb_alloc(int size, bool pkthdr)
{
	struct mbuf *m = calloc(1, sizeof(*m));

	m->m_kbuf = malloc(size);
	m->m_ksize = size;
	m->m_data = m->m_kbuf;
	m->m_type = MT_DATA;
	if (pkthdr)
		m->m_flags |= M_PKTHDR;
	kmbufs++;
	return (m);
}

struct mbuf *
m_get(int how, short type)
{
	(void)how; (void)type;
	if (kshim_malloc_nowait_fail > 0 && (how & M_NOWAIT) &&
	    --kshim_malloc_nowait_fail == 0)
		return (NULL);
	return (kmb_alloc(MLEN, false));
}

struct mbuf *
m_gethdr(int how, short type)
{
	(void)type;
	if (kshim_malloc_nowait_fail > 0 && (how & M_NOWAIT) &&
	    --kshim_malloc_nowait_fail == 0)
		return (NULL);
	return (kmb_alloc(MHLEN, true));
}

bool
kshim_m_clget(struct mbuf *m, int how)
{
	(void)how;
	free(m->m_kbuf);
	m->m_kbuf = malloc(MCLBYTES);
	m->m_ksize = MCLBYTES;
	m->m_data = m->m_kbuf;
	m->m_flags |= M_EXT;
	return (true);
}

struct mbuf *
m_getcl(int how, short type, int flags)
{
	struct mbuf *m = (flags & M_PKTHDR) ? m_gethdr(how, type) :
	    m_get(how, type);

	if (m != NULL)
		kshim_m_clget(m, how);
	return (m);
}

struct mbuf *
m_get2(int size, int how, short type, int flags)
{
	if (size > MCLBYTES)
		return (NULL);
	if (size <= ((flags & M_PKTHDR) ? MHLEN : MLEN))
		return ((flags & M_PKTHDR) ? m_gethdr(how, type) :
		    m_get(how, type));
	return (m_getcl(how, type, flags));
}

struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n = m->m_next;

	free(m->m_kbuf);
	free(m);
	kmbufs--;
	return (n);
}

void
m_freem(struct mbuf *m)
{
	while (m != NULL)
		m = m_free(m);
}

int kshim_mbuf_count(void) { return (kmbufs); }

u_int
m_length(struct mbuf *m, struct mbuf **last)
{
	u_int len = 0;

	for (; m != NULL; m = m->m_next) {
		len += m->m_len;
		if (last != NULL)
			*last = m;
	}
	return (len);
}

void
m_move_pkthdr(struct mbuf *to, struct mbuf *from)
{
	to->m_flags = (from->m_flags & ~M_EXT) | (to->m_flags & M_EXT);
	to->m_pkthdr = from->m_pkthdr;
	from->m_flags &= ~M_PKTHDR;
}

void
m_demote_pkthdr(struct mbuf *m)
{
	m->m_flags &= ~M_PKTHDR;
}

/* FreeBSD m_copydata() KASSERTs these; keep the assertion live here. */
void
m_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	u_int count;

	KASSERT(off >= 0, ("m_copydata, negative off %d", off));
	KASSERT(len >= 0, ("m_copydata, negative len %d", len));
	while (off > 0) {
		KASSERT(m != NULL, ("m_copydata, offset > size of mbuf chain"));
		if (off < m->m_len)
			break;
		off -= m->m_len;
		m = m->m_next;
	}
	while (len > 0) {
		KASSERT(m != NULL, ("m_copydata, length > size of mbuf chain"));
		count = MIN(m->m_len - off, len);
		memcpy(cp, mtod(m, caddr_t) + off, count);
		len -= count;
		cp += count;
		off = 0;
		m = m->m_next;
	}
}

void
m_copyback(struct mbuf *m, int off, int len, const void *cp)
{
	const char *c = cp;

	while (m != NULL && off >= m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}
	while (m != NULL && len > 0) {
		int n = MIN(m->m_len - off, len);

		memcpy(mtod(m, char *) + off, c, n);
		c += n;
		len -= n;
		off = 0;
		m = m->m_next;
	}
	KASSERT(len == 0, ("m_copyback past end of chain"));
}

/*
 * FreeBSD m_pullup(): contiguous len bytes in the first mbuf or the chain is
 * freed and NULL returned.  Like the real one (sys/kern/uipc_mbuf.c) it
 * cannot produce more than MHLEN bytes in a fresh header mbuf.
 */
struct mbuf *
m_pullup(struct mbuf *n, int len)
{
	struct mbuf *m;
	int count, space;

	if (n->m_len >= len)
		return (n);
	if ((n->m_flags & M_EXT) == 0 &&
	    n->m_data + len <= n->m_kbuf + n->m_ksize && n->m_next != NULL) {
		m = n;
		n = n->m_next;
		len -= m->m_len;
	} else {
		if (len > MHLEN)
			goto bad;
		m = kmb_alloc(MHLEN, false);
		if (n->m_flags & M_PKTHDR)
			m_move_pkthdr(m, n);
	}
	space = (int)((m->m_kbuf + m->m_ksize) - (m->m_data + m->m_len));
	do {
		count = MIN(MIN(MAX(len, 0), space), n->m_len);
		memcpy(mtod(m, char *) + m->m_len, mtod(n, char *), count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len)
			n->m_data += count;
		else
			n = m_free(n);
	} while (len > 0 && n != NULL);
	if (len > 0) {
		m_freem(m);
		goto bad2;
	}
	m->m_next = n;
	return (m);
bad:
	m_freem(n);
	return (NULL);
bad2:
	m_freem(n);
	return (NULL);
}

void
m_adj(struct mbuf *mp, int req_len)
{
	int len = req_len;
	struct mbuf *m;
	int count;

	if ((m = mp) == NULL)
		return;
	if (len >= 0) {
		while (m != NULL && len > 0) {
			if (m->m_len <= len) {
				len -= m->m_len;
				m->m_len = 0;
				m = m->m_next;
			} else {
				m->m_len -= len;
				m->m_data += len;
				len = 0;
			}
		}
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len -= (req_len - len);
	} else {
		len = -len;
		count = 0;
		for (;;) {
			count += m->m_len;
			if (m->m_next == NULL)
				break;
			m = m->m_next;
		}
		if (m->m_len >= len) {
			m->m_len -= len;
			if (mp->m_flags & M_PKTHDR)
				mp->m_pkthdr.len -= len;
			return;
		}
		count -= len;
		if (count < 0)
			count = 0;
		m = mp;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len = count;
		for (; m; m = m->m_next) {
			if (m->m_len >= count) {
				m->m_len = count;
				if (m->m_next != NULL) {
					m_freem(m->m_next);
					m->m_next = NULL;
				}
				break;
			}
			count -= m->m_len;
		}
	}
}

struct mbuf *
m_prepend(struct mbuf *m, int len, int how)
{
	struct mbuf *mn;

	if (len > MHLEN) {
		m_freem(m);
		return (NULL);
	}
	mn = (m->m_flags & M_PKTHDR) ? m_gethdr(how, MT_DATA) :
	    m_get(how, MT_DATA);
	if (mn == NULL) {
		m_freem(m);
		return (NULL);
	}
	if (m->m_flags & M_PKTHDR)
		m_move_pkthdr(mn, m);
	mn->m_next = m;
	m = mn;
	m->m_data = m->m_kbuf + m->m_ksize - len;
	m->m_len = len;
	return (m);
}

struct mbuf *
m_defrag(struct mbuf *m0, int how)
{
	struct mbuf *m;
	int len = m0->m_pkthdr.len;

	if (len > MCLBYTES)
		return (NULL);
	m = (len > MHLEN) ? m_getcl(how, MT_DATA, M_PKTHDR) :
	    m_gethdr(how, MT_DATA);
	if (m == NULL)
		return (NULL);
	m_copydata(m0, 0, len, mtod(m, caddr_t));
	m->m_len = len;
	m->m_pkthdr = m0->m_pkthdr;
	m->m_flags |= (m0->m_flags & ~(M_EXT));
	m_freem(m0);
	return (m);
}

struct mbuf *
m_dup(const struct mbuf *m, int how)
{
	int len = m->m_pkthdr.len;
	struct mbuf *n = (len > MHLEN) ? m_getcl(how, MT_DATA, M_PKTHDR) :
	    m_gethdr(how, MT_DATA);

	if (n == NULL || len > MCLBYTES)
		return (NULL);
	m_copydata(m, 0, len, mtod(n, caddr_t));
	n->m_len = len;
	n->m_pkthdr = m->m_pkthdr;
	return (n);
}

struct mbuf *
m_copym(struct mbuf *m, int off, int len, int how)
{
	struct mbuf *n;
	int total = (int)m_length(m, NULL);

	if (len == M_COPYALL)
		len = total - off;
	if (off < 0 || len < 0 || off + len > total || len > MCLBYTES)
		return (NULL);
	n = (len > MHLEN) ? m_getcl(how, MT_DATA, M_PKTHDR) :
	    m_gethdr(how, MT_DATA);
	m_copydata(m, off, len, mtod(n, caddr_t));
	n->m_len = n->m_pkthdr.len = len;
	return (n);
}

int
m_append(struct mbuf *m0, int len, const void *cp)
{
	struct mbuf *m;

	for (m = m0; m->m_next != NULL; m = m->m_next)
		;
	if (M_TRAILINGSPACE(m) < len)
		return (0);
	memcpy(mtod(m, char *) + m->m_len, cp, len);
	m->m_len += len;
	if (m0->m_flags & M_PKTHDR)
		m0->m_pkthdr.len += len;
	return (1);
}

void
m_cat(struct mbuf *m, struct mbuf *n)
{
	while (m->m_next != NULL)
		m = m->m_next;
	m->m_next = n;
}

/* One contiguous packet-header mbuf (a cluster above MHLEN). */
struct mbuf *
kshim_mbuf_from(const void *buf, int len)
{
	struct mbuf *m;

	if (len > MCLBYTES)
		return (kshim_mbuf_chain(buf, len, MCLBYTES));
	m = (len > MHLEN) ? m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR) :
	    m_gethdr(M_NOWAIT, MT_DATA);
	memcpy(m->m_data, buf, len);
	m->m_len = m->m_pkthdr.len = len;
	/* Trim the storage to the data so ASan flags any overread. */
	if (len > 0 && len < m->m_ksize && !(m->m_flags & M_EXT)) {
		char *nb = malloc(len);

		memcpy(nb, buf, len);
		free(m->m_kbuf);
		m->m_kbuf = m->m_data = nb;
		m->m_ksize = len;
	}
	return (m);
}

/* A chain of seglen-byte mbufs, each exactly sized. */
struct mbuf *
kshim_mbuf_chain(const void *buf, int len, int seglen)
{
	struct mbuf *head = NULL, **tail = &head;
	const char *p = buf;
	int off = 0;

	if (seglen <= 0)
		seglen = 1;
	do {
		int n = MIN(seglen, len - off);
		struct mbuf *m = kmb_alloc(n > 0 ? n : 1, head == NULL);

		if (n > 0)
			memcpy(m->m_data, p + off, n);
		m->m_len = n;
		if (n > MHLEN)
			m->m_flags |= M_EXT;
		*tail = m;
		tail = &m->m_next;
		off += n;
	} while (off < len);
	head->m_pkthdr.len = len;
	return (head);
}

/* ------------------------------------------------------------------ */
/* ifnet                                                                */
/* ------------------------------------------------------------------ */
#define	KSHIM_MAX_IFNETS	32
static struct ifnet *kifnets[KSHIM_MAX_IFNETS];

struct ifnet *
if_alloc(u_char type)
{
	struct ifnet *ifp = calloc(1, sizeof(*ifp));

	ifp->if_type = type;
	ifp->if_vnet = kshim_vnet0;
	ifp->kshim_dlt = -1;
	ifp->if_link_state = LINK_STATE_UNKNOWN;
	CK_STAILQ_INIT(&ifp->if_addrhead);
	ifp->if_snd.ifq_maxlen = 50;
	for (int i = 0; i < KSHIM_MAX_IFNETS; i++) {
		if (kifnets[i] == NULL) {
			kifnets[i] = ifp;
			ifp->if_index = i + 1;
			break;
		}
	}
	return (ifp);
}

void
if_free(struct ifnet *ifp)
{
	if (ifp == NULL)
		return;
	for (int i = 0; i < KSHIM_MAX_IFNETS; i++)
		if (kifnets[i] == ifp)
			kifnets[i] = NULL;
	kshim_tx_flush(ifp);
	if (ifp->if_addr != NULL) {
		free(ifp->if_addr->ifa_addr);
		free(ifp->if_addr);
	}
	free(ifp);
}

void
if_initname(struct ifnet *ifp, const char *name, int unit)
{
	ifp->if_dname = name;
	ifp->if_dunit = unit;
	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "%s%d", name, unit);
}

void if_attach(struct ifnet *ifp) { (void)ifp; }
void if_detach(struct ifnet *ifp) { (void)ifp; }
void if_up(struct ifnet *ifp) { ifp->if_flags |= IFF_UP; }
void if_down(struct ifnet *ifp) { ifp->if_flags &= ~IFF_UP; }

struct ifnet *
ifunit(const char *name)
{
	for (int i = 0; i < KSHIM_MAX_IFNETS; i++)
		if (kifnets[i] != NULL && strcmp(kifnets[i]->if_xname, name) == 0)
			return (kifnets[i]);
	return (NULL);
}

struct ifnet *
ifunit_ref(const char *name)
{
	struct ifnet *ifp = ifunit(name);

	if (ifp != NULL)
		if_ref(ifp);
	return (ifp);
}

struct ifnet *
kshim_ifnet_new(const char *name, u_char type)
{
	struct ifnet *ifp = if_alloc(type);

	kshim_strlcpy(ifp->if_xname, name, sizeof(ifp->if_xname));
	ifp->if_transmit = kshim_tx_capture;
	ifp->if_mtu = type == IFT_ETHER ? ETHERMTU : PPP_MTU;
	return (ifp);
}

void kshim_ifnet_free(struct ifnet *ifp) { if_free(ifp); }

void
kshim_ifnet_set_lladdr(struct ifnet *ifp, const uint8_t mac[6])
{
	struct ifaddr *ifa = calloc(1, sizeof(*ifa));
	struct sockaddr_dl *sdl = calloc(1, sizeof(*sdl));

	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_family = AF_LINK;
	sdl->sdl_alen = ETHER_ADDR_LEN;
	memcpy(LLADDR(sdl), mac, ETHER_ADDR_LEN);
	ifa->ifa_addr = (struct sockaddr *)sdl;
	ifa->ifa_ifp = ifp;
	ifp->if_addr = ifa;
	ifp->if_addrlen = ETHER_ADDR_LEN;
}

void
if_inc_counter(struct ifnet *ifp, ift_counter c, int64_t v)
{
	KASSERT(c < IFCOUNTERS, ("bad counter %d", c));
	ifp->if_counters[c] += v;
}

uint64_t if_getcounter(struct ifnet *ifp, ift_counter c) { return (ifp->if_counters[c]); }

void
if_link_state_change(struct ifnet *ifp, int state)
{
	if (ifp->if_link_state == state)
		return;
	ifp->if_link_state = state;
	ifp->kshim_link_changes++;
}

const char *if_name(struct ifnet *ifp) { return (ifp->if_xname); }

int
if_transmit(struct ifnet *ifp, struct mbuf *m)
{
	if (ifp->if_transmit == NULL)
		return (kshim_tx_capture(ifp, m));
	return (ifp->if_transmit(ifp, m));
}

int
kshim_tx_capture(struct ifnet *ifp, struct mbuf *m)
{
	m->m_nextpkt = NULL;
	if (ifp->kshim_txq_tail != NULL)
		ifp->kshim_txq_tail->m_nextpkt = m;
	else
		ifp->kshim_txq_head = m;
	ifp->kshim_txq_tail = m;
	ifp->kshim_txq_len++;
	return (0);
}

struct mbuf *
kshim_tx_pop(struct ifnet *ifp)
{
	struct mbuf *m = ifp->kshim_txq_head;

	if (m == NULL)
		return (NULL);
	ifp->kshim_txq_head = m->m_nextpkt;
	if (ifp->kshim_txq_head == NULL)
		ifp->kshim_txq_tail = NULL;
	ifp->kshim_txq_len--;
	m->m_nextpkt = NULL;
	return (m);
}

void
kshim_tx_flush(struct ifnet *ifp)
{
	struct mbuf *m;

	while ((m = kshim_tx_pop(ifp)) != NULL)
		m_freem(m);
}

int
ether_output_frame(struct ifnet *ifp, struct mbuf *m)
{
	return (if_transmit(ifp, m));
}

/* bpf(4): record what a listener would see, header bytes first. */
static struct ifnet *kbpf_ifp;
static uint8_t kbpf_buf[KSHIM_BPF_SNAP];
static int kbpf_len, kbpf_taps;

void
kshim_bpfattach(struct ifnet *ifp, u_int dlt, u_int hdrlen)
{
	ifp->kshim_dlt = (int)dlt;
	ifp->kshim_bpf_hdrlen = hdrlen;
}

void
kshim_bpf_mtap2(struct ifnet *ifp, void *data, u_int dlen, struct mbuf *m)
{
	int n, mlen = m->m_pkthdr.len;

	if (ifp->kshim_dlt < 0)
		kshim_panic(__FILE__, __LINE__, "bpf tap on %s before bpfattach",
		    ifp->if_xname);
	kbpf_ifp = ifp;
	kbpf_taps++;
	kbpf_len = (int)dlen + mlen;
	n = (int)dlen < KSHIM_BPF_SNAP ? (int)dlen : KSHIM_BPF_SNAP;
	if (n > 0)
		memcpy(kbpf_buf, data, n);
	if (mlen > KSHIM_BPF_SNAP - n)
		mlen = KSHIM_BPF_SNAP - n;
	if (mlen > 0)
		m_copydata(m, 0, mlen, (caddr_t)kbpf_buf + n);
}

int kshim_bpf_taps(void) { return (kbpf_taps); }

struct ifnet *
kshim_bpf_last(uint8_t buf[KSHIM_BPF_SNAP], int *lenp)
{
	if (buf != NULL)
		memcpy(buf, kbpf_buf, KSHIM_BPF_SNAP);
	if (lenp != NULL)
		*lenp = kbpf_len;
	return (kbpf_ifp);
}

void
kshim_bpf_reset(void)
{
	kbpf_ifp = NULL;
	kbpf_len = kbpf_taps = 0;
	memset(kbpf_buf, 0, sizeof(kbpf_buf));
}

int kshim_ip_input_calls, kshim_ip6_input_calls;
void ip_input(struct mbuf *m) { kshim_ip_input_calls++; m_freem(m); }
void ip6_input(struct mbuf *m) { kshim_ip6_input_calls++; m_freem(m); }

int in_control_ioctl(u_long c, void *d, struct ifnet *i, struct ucred *u)
{ (void)c; (void)d; (void)i; (void)u; return (0); }
int in6_control_ioctl(u_long c, void *d, struct ifnet *i, struct ucred *u)
{ (void)c; (void)d; (void)i; (void)u; return (0); }
int in6_setscope(struct in6_addr *a, struct ifnet *i, uint32_t *r)
{ (void)a; (void)i; if (r) *r = 0; return (0); }
struct in6_ifaddr *in6ifa_ifpforlinklocal(struct ifnet *i, int f)
{ (void)i; (void)f; return (NULL); }

/* ------------------------------------------------------------------ */
/* netisr / RSS / pfil / if_clone                                       */
/* ------------------------------------------------------------------ */
u_int kshim_netisr_ncpu = 1;
const struct netisr_handler *kshim_netisr_registered;
static struct mbuf *knisr_head, *knisr_tail;

void netisr_register(const struct netisr_handler *nh) { kshim_netisr_registered = nh; }
void netisr_unregister(const struct netisr_handler *nh) { (void)nh; kshim_netisr_registered = NULL; }
void netisr_register_vnet(const struct netisr_handler *nh) { (void)nh; }
void netisr_unregister_vnet(const struct netisr_handler *nh) { (void)nh; }

/* net.isr.maxqlimit's real default (10240): the only bound callers rely on. */
int
netisr_setqlimit(const struct netisr_handler *nh, u_int qlimit)
{
	(void)nh;
	return (qlimit > 10240 ? EINVAL : 0);
}

int
netisr_dispatch_src(u_int proto, uintptr_t src, struct mbuf *m)
{
	(void)proto; (void)src;
	m->m_nextpkt = NULL;
	if (knisr_tail != NULL)
		knisr_tail->m_nextpkt = m;
	else
		knisr_head = m;
	knisr_tail = m;
	return (0);
}

int netisr_dispatch(u_int proto, struct mbuf *m) { return (netisr_dispatch_src(proto, 0, m)); }

struct mbuf *
kshim_netisr_pop(void)
{
	struct mbuf *m = knisr_head;

	if (m == NULL)
		return (NULL);
	knisr_head = m->m_nextpkt;
	if (knisr_head == NULL)
		knisr_tail = NULL;
	m->m_nextpkt = NULL;
	return (m);
}

void
kshim_netisr_flush(void)
{
	struct mbuf *m;

	while ((m = kshim_netisr_pop()) != NULL)
		m_freem(m);
}

/* Not Toeplitz: a stable mix that depends on every tuple field. */
static uint32_t
kmix(uint32_t h, uint32_t v)
{
	h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
	return (h);
}

int
rss_proto_software_hash_v4(struct in_addr s, struct in_addr d, u_short sp,
    u_short dp, int proto, uint32_t *hv, uint32_t *ht)
{
	uint32_t h = kmix(kmix(kmix(0, s.s_addr), d.s_addr), (uint32_t)sp << 16 | dp);

	*hv = kmix(h, proto);
	*ht = (sp || dp) ? (proto == IPPROTO_TCP ? M_HASHTYPE_RSS_TCP_IPV4 :
	    M_HASHTYPE_RSS_UDP_IPV4) : M_HASHTYPE_RSS_IPV4;
	return (0);
}

int
rss_proto_software_hash_v6(const struct in6_addr *s, const struct in6_addr *d,
    u_short sp, u_short dp, int proto, uint32_t *hv, uint32_t *ht)
{
	uint32_t h = 0, a, b;

	/* Byte copies: the caller's header sits 2 bytes into the mbuf. */
	for (int i = 0; i < 4; i++) {
		memcpy(&a, (const uint8_t *)s + 4 * i, 4);
		memcpy(&b, (const uint8_t *)d + 4 * i, 4);
		h = kmix(kmix(h, a), b);
	}
	*hv = kmix(kmix(h, (uint32_t)sp << 16 | dp), proto);
	*ht = (sp || dp) ? (proto == IPPROTO_TCP ? M_HASHTYPE_RSS_TCP_IPV6 :
	    M_HASHTYPE_RSS_UDP_IPV6) : M_HASHTYPE_RSS_IPV6;
	return (0);
}

u_int rss_hash2cpuid(uint32_t h, u_int t) { (void)t; return (h % kshim_netisr_ncpu); }
u_int rss_getnumbuckets(void) { return (kshim_netisr_ncpu); }
u_int rss_getnumcpus(void) { return (kshim_netisr_ncpu); }

static int kpfil_head_dummy, kpfil_hook_dummy;
pfil_head_t kshim_link_pfil_head = (pfil_head_t)&kpfil_head_dummy;
pfil_hook_t pfil_add_hook(struct pfil_hook_args *a) { (void)a; return ((pfil_hook_t)&kpfil_hook_dummy); }
void pfil_remove_hook(pfil_hook_t h) { (void)h; }
int pfil_link(struct pfil_link_args *a) { (void)a; return (0); }

static struct if_clone_addreq kclone_req;
static int kclone_dummy;

struct if_clone *
ifc_attach_cloner(const char *name, struct if_clone_addreq *req)
{
	(void)name;
	kclone_req = *req;
	return ((struct if_clone *)&kclone_dummy);
}

void ifc_detach_cloner(struct if_clone *ifc) { (void)ifc; memset(&kclone_req, 0, sizeof(kclone_req)); }
int if_clone_destroy(const char *name) { (void)name; return (0); }

int
kshim_clone_create(int unit, struct ifnet **ifpp)
{
	struct ifc_data ifd = { 0, (uint32_t)unit, NULL };
	char name[IFNAMSIZ];

	if (kclone_req.create_f == NULL)
		return (ENXIO);
	snprintf(name, sizeof(name), "pppoe%d", unit);
	return (kclone_req.create_f((struct if_clone *)&kclone_dummy, name,
	    sizeof(name), &ifd, ifpp));
}

int
kshim_clone_destroy(struct ifnet *ifp)
{
	if (kclone_req.destroy_f == NULL)
		return (ENXIO);
	return (kclone_req.destroy_f((struct if_clone *)&kclone_dummy, ifp, 0));
}

/* ------------------------------------------------------------------ */
/* MD5 (RFC 1321 reference algorithm, public-domain style rewrite)      */
/* ------------------------------------------------------------------ */
#define	F(x, y, z)	(((x) & (y)) | (~(x) & (z)))
#define	G(x, y, z)	(((x) & (z)) | ((y) & ~(z)))
#define	H(x, y, z)	((x) ^ (y) ^ (z))
#define	I(x, y, z)	((y) ^ ((x) | ~(z)))
#define	ROL(x, n)	(((x) << (n)) | ((x) >> (32 - (n))))

static void
md5_transform(uint32_t st[4], const unsigned char blk[64])
{
	uint32_t a = st[0], b = st[1], c = st[2], d = st[3], x[16];
	static const uint32_t T[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
		0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
		0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
		0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
		0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
		0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
		0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
		0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
		0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
		0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
	static const int S[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

	for (int i = 0; i < 16; i++)
		x[i] = (uint32_t)blk[i * 4] | (uint32_t)blk[i * 4 + 1] << 8 |
		    (uint32_t)blk[i * 4 + 2] << 16 | (uint32_t)blk[i * 4 + 3] << 24;
	for (int i = 0; i < 64; i++) {
		uint32_t f, t;
		int g;

		if (i < 16) { f = F(b, c, d); g = i; }
		else if (i < 32) { f = G(b, c, d); g = (5 * i + 1) % 16; }
		else if (i < 48) { f = H(b, c, d); g = (3 * i + 5) % 16; }
		else { f = I(b, c, d); g = (7 * i) % 16; }
		t = d;
		d = c;
		c = b;
		b = b + ROL(a + f + T[i] + x[g], S[i]);
		a = t;
	}
	st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

void
MD5Init(MD5_CTX *c)
{
	c->count[0] = c->count[1] = 0;
	c->state[0] = 0x67452301;
	c->state[1] = 0xefcdab89;
	c->state[2] = 0x98badcfe;
	c->state[3] = 0x10325476;
}

void
MD5Update(MD5_CTX *c, const void *in, unsigned int len)
{
	const unsigned char *p = in;
	unsigned int idx = (c->count[0] >> 3) & 0x3f;

	if ((c->count[0] += len << 3) < (len << 3))
		c->count[1]++;
	c->count[1] += len >> 29;
	while (len-- > 0) {
		c->buffer[idx++] = *p++;
		if (idx == 64) {
			md5_transform(c->state, c->buffer);
			idx = 0;
		}
	}
}

void
MD5Final(void *digest, MD5_CTX *c)
{
	unsigned char bits[8], pad = 0x80, zero = 0, *out = digest;
	unsigned int idx;

	for (int i = 0; i < 4; i++) {
		bits[i] = (unsigned char)(c->count[0] >> (8 * i));
		bits[i + 4] = (unsigned char)(c->count[1] >> (8 * i));
	}
	MD5Update(c, &pad, 1);
	idx = (c->count[0] >> 3) & 0x3f;
	while (idx != 56) {
		MD5Update(c, &zero, 1);
		idx = (c->count[0] >> 3) & 0x3f;
	}
	MD5Update(c, bits, 8);
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			out[i * 4 + j] = (unsigned char)(c->state[i] >> (8 * j));
	memset(c, 0, sizeof(*c));
}

/* ------------------------------------------------------------------ */
/* SYSINIT registrations (recorded at constructor time, never run)      */
/* ------------------------------------------------------------------ */
#define	KSHIM_MAX_SYSINITS	32
static struct {
	int		 kind;
	const char	*func;
	u_int		 sub, order;
} ksysinits[KSHIM_MAX_SYSINITS];
static int nksysinits;

void
kshim_sysinit_register(int kind, const char *func, u_int sub, u_int order)
{
	if (nksysinits == KSHIM_MAX_SYSINITS)
		abort();
	ksysinits[nksysinits].kind = kind;
	ksysinits[nksysinits].func = func;
	ksysinits[nksysinits].sub = sub;
	ksysinits[nksysinits].order = order;
	nksysinits++;
}

int
kshim_sysinit_find(int kind, const char *func, u_int *sub, u_int *order)
{
	for (int i = 0; i < nksysinits; i++) {
		if (ksysinits[i].kind != kind ||
		    strcmp(ksysinits[i].func, func) != 0)
			continue;
		*sub = ksysinits[i].sub;
		*order = ksysinits[i].order;
		return (0);
	}
	return (-1);
}

/* ------------------------------------------------------------------ */
void
kshim_reset(void)
{
	kshim_tasks_reset();
	kshim_locks_reset();
	kshim_log_clear();
	kshim_netisr_flush();
	kshim_bpf_reset();
	kshim_net_epoch_depth = 0;
	kshim_malloc_nowait_fail = 0;
	kshim_taskq_start_fail = 0;
	kshim_panic_jmp = NULL;
	kshim_ip_input_calls = kshim_ip6_input_calls = 0;
	kshim_netisr_ncpu = 1;
	krand_state = 0x9e3779b97f4a7c15ULL;
	kshim_random_seeded = true;
}
