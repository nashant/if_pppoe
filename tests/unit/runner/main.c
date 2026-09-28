/* ktest runner: ./unit [-v] [-l] [substring-filter ...] */
#include "ktest.h"

#include <time.h>
#include <unistd.h>

MALLOC_DECLARE(M_PPPOE);

static struct ktest *kt_head, **kt_tail = &kt_head;
static jmp_buf kt_jb;
static char kt_why[1024];
static int kt_allow_leaks, kt_verbose;

void
ktest_register(struct ktest *t)
{
	*kt_tail = t;
	kt_tail = &t->next;
}

void
ktest_fail(const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	int n;

	n = snprintf(kt_why, sizeof(kt_why), "%s:%d: ", file, line);
	va_start(ap, fmt);
	vsnprintf(kt_why + n, sizeof(kt_why) - n, fmt, ap);
	va_end(ap);
	longjmp(kt_jb, 1);
}

void ktest_allow_leaks(void) { kt_allow_leaks = 1; }

void
ktest_note(const char *fmt, ...)
{
	va_list ap;

	if (!kt_verbose)
		return;
	va_start(ap, fmt);
	fputs("    # ", stdout);
	vfprintf(stdout, fmt, ap);
	fputc('\n', stdout);
	va_end(ap);
}

static bool
kt_match(const struct ktest *t, int argc, char **argv)
{
	char full[256];

	if (argc == 0)
		return (true);
	snprintf(full, sizeof(full), "%s.%s", t->suite, t->name);
	for (int i = 0; i < argc; i++)
		if (strstr(full, argv[i]) != NULL)
			return (true);
	return (false);
}

/* Returns true if the test body failed (for any reason). */
static bool
kt_run(struct ktest *t)
{
	long pppoe0 = kshim_malloc_inuse(M_PPPOE);
	int mbufs0 = kshim_mbuf_count();

	kshim_reset();
	kt_allow_leaks = 0;
	kt_why[0] = '\0';
	if (setjmp(kt_jb) != 0)
		goto failed;
	kshim_panic_jmp = &kt_jb;
	t->fn();
	kshim_panic_jmp = NULL;
	if (kshim_locks_held() != 0)
		snprintf(kt_why, sizeof(kt_why), "%d lock(s) still held",
		    kshim_locks_held());
	else if (kshim_tasks_pending() != 0 && !kt_allow_leaks)
		snprintf(kt_why, sizeof(kt_why), "%d task(s) left queued",
		    kshim_tasks_pending());
	else if (!kt_allow_leaks && kshim_mbuf_count() != mbufs0)
		snprintf(kt_why, sizeof(kt_why), "leaked %d mbuf(s)",
		    kshim_mbuf_count() - mbufs0);
	else if (!kt_allow_leaks && kshim_malloc_inuse(M_PPPOE) != pppoe0)
		snprintf(kt_why, sizeof(kt_why), "leaked %ld M_PPPOE block(s)",
		    kshim_malloc_inuse(M_PPPOE) - pppoe0);
	if (kt_why[0] != '\0')
		return (true);
	return (false);
failed:
	kshim_panic_jmp = NULL;
	if (kt_why[0] == '\0')
		snprintf(kt_why, sizeof(kt_why), "panic: %s", kshim_panic_msg);
	return (true);
}

int
main(int argc, char **argv)
{
	int pass = 0, fail = 0, xfail = 0, xpass = 0, list = 0;
	struct timespec t0, t1;

	while (argc > 1 && argv[1][0] == '-') {
		if (strcmp(argv[1], "-v") == 0)
			kt_verbose = 1;
		else if (strcmp(argv[1], "-l") == 0)
			list = 1;
		argc--;
		argv++;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (struct ktest *t = kt_head; t != NULL; t = t->next) {
		bool failed;

		if (!kt_match(t, argc - 1, argv + 1))
			continue;
		if (list) {
			fprintf(stdout, "%s.%s%s\n", t->suite, t->name,
			    t->xfail ? " (xfail)" : "");
			continue;
		}
		if (kt_verbose)
			fprintf(stdout, "... %s.%s\n", t->suite, t->name);
		failed = kt_run(t);
		if (t->xfail != NULL) {
			if (failed) {
				xfail++;
				fprintf(stdout, "xfail %s.%s -- %s\n    (%s)\n",
				    t->suite, t->name, t->xfail, kt_why);
			} else {
				xpass++;
				fprintf(stdout, "XPASS %s.%s -- known bug no "
				    "longer reproduces; drop the XFAIL\n",
				    t->suite, t->name);
			}
		} else if (failed) {
			fail++;
			fprintf(stdout, "FAIL  %s.%s\n    %s\n", t->suite,
			    t->name, kt_why);
		} else {
			pass++;
			if (kt_verbose)
				fprintf(stdout, "ok    %s.%s\n", t->suite,
				    t->name);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (!list)
		fprintf(stdout, "\n%d passed, %d failed, %d xfail, %d xpass "
		    "in %.2fs\n", pass, fail, xfail, xpass,
		    (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9);
	/* A failed test longjmp()ed past its teardown: skip LSan's exit scan. */
	if (fail + xpass != 0)
		_exit(1);
	return (0);
}
