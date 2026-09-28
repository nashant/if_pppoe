/*
 * ktest.h -- a tiny self-registering C test runner (no external deps).
 *
 *	KTEST(suite, name) { KT_EQ(1 + 1, 2); }
 *	KTEST_XFAIL(suite, name, "why") { ... }	known bug: must fail
 *
 * Each test runs with fresh shim state; a panic()/KASSERT, a failed
 * assertion, a lock still held, or a leaked mbuf/M_PPPOE allocation at the
 * end fails it.
 */
#ifndef _KTEST_H_
#define _KTEST_H_

#include "kshim.h"

struct ktest {
	const char	*suite;
	const char	*name;
	void		(*fn)(void);
	const char	*file;
	int		 line;
	const char	*xfail;		/* non-NULL: expected to fail, and why */
	struct ktest	*next;
};

void	ktest_register(struct ktest *);
void	ktest_fail(const char *file, int line, const char *fmt, ...)
	    __printflike(3, 4) __attribute__((__noreturn__));
void	ktest_allow_leaks(void);
void	ktest_note(const char *fmt, ...) __printflike(1, 2);

#define	KTEST__(suite, name, xf)					\
	static void kt_fn_##suite##__##name(void);			\
	static struct ktest kt_##suite##__##name = {			\
		#suite, #name, kt_fn_##suite##__##name, __FILE__,	\
		__LINE__, (xf), NULL };					\
	static void __attribute__((constructor))			\
	kt_reg_##suite##__##name(void)					\
	{ ktest_register(&kt_##suite##__##name); }			\
	static void kt_fn_##suite##__##name(void)
#define	KTEST(suite, name)		KTEST__(suite, name, NULL)
#define	KTEST_XFAIL(suite, name, why)	KTEST__(suite, name, (why))

#define	KT_ASSERT(c)	do {						\
	if (!(c))							\
		ktest_fail(__FILE__, __LINE__, "assertion failed: %s", #c); \
} while (0)
#define	KT_EQ(a, b)	do {						\
	intmax_t _a = (intmax_t)(a), _b = (intmax_t)(b);		\
	if (_a != _b)							\
		ktest_fail(__FILE__, __LINE__, "%s == %s: %jd != %jd",	\
		    #a, #b, _a, _b);					\
} while (0)
#define	KT_NE(a, b)	do {						\
	intmax_t _a = (intmax_t)(a), _b = (intmax_t)(b);		\
	if (_a == _b)							\
		ktest_fail(__FILE__, __LINE__, "%s != %s: both %jd",	\
		    #a, #b, _a);					\
} while (0)
#define	KT_MEMEQ(a, b, n)	do {					\
	if (memcmp((a), (b), (n)) != 0)					\
		ktest_fail(__FILE__, __LINE__, "memcmp(%s, %s, %s) != 0", \
		    #a, #b, #n);					\
} while (0)
#define	KT_STREQ(a, b)	do {						\
	const char *_a = (a), *_b = (b);				\
	if (_a == NULL || _b == NULL || strcmp(_a, _b) != 0)		\
		ktest_fail(__FILE__, __LINE__, "%s == %s: \"%s\" != \"%s\"", \
		    #a, #b, _a ? _a : "(null)", _b ? _b : "(null)");	\
} while (0)
#define	KT_LOGGED(needle)	do {					\
	if (kshim_log_find(needle) < 0)					\
		ktest_fail(__FILE__, __LINE__, "no log record contains \"%s\"", \
		    (needle));						\
} while (0)
#define	KT_NOT_LOGGED(needle)	do {					\
	if (kshim_log_find(needle) >= 0)				\
		ktest_fail(__FILE__, __LINE__, "unexpected log record \"%s\"", \
		    kshim_log_get(kshim_log_find(needle), NULL));	\
} while (0)

/* Run stmt; it must panic (KASSERT/panic) with msg containing substr. */
#define	KT_EXPECT_PANIC(stmt, substr)	do {				\
	jmp_buf _kjb, *_ksaved = kshim_panic_jmp;			\
	int _kp = 0;							\
	kshim_panic_jmp = &_kjb;					\
	if (setjmp(_kjb) == 0) {					\
		stmt;							\
	} else								\
		_kp = 1;						\
	kshim_panic_jmp = _ksaved;					\
	if (!_kp)							\
		ktest_fail(__FILE__, __LINE__, "%s did not panic", #stmt); \
	if (strstr(kshim_panic_msg, (substr)) == NULL)			\
		ktest_fail(__FILE__, __LINE__, "panic \"%s\" lacks \"%s\"", \
		    kshim_panic_msg, (substr));				\
	kshim_locks_reset();						\
} while (0)

#endif /* _KTEST_H_ */
