/*	$NetBSD: pppoectl.c,v 1.32 2026/07/28 07:28:02 yamaguchi Exp $	*/

/*
 * Copyright (c) 1997 Joerg Wunsch
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE DEVELOPERS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE DEVELOPERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * From: spppcontrol.c,v 1.3 1998/01/07 07:55:26 charnier Exp
 * From: ispppcontrol
 */
/*
 * FreeBSD port notice
 * -------------------
 * Ported to FreeBSD 14.3 (OPNsense 25.7, kernel SMP) for the OPNsense
 * if_pppoe project.  Source: NetBSD/src commit
 * 5ee7eb6e8db7128264453921994932a2c2a5af70, sbin/pppoectl/pppoectl.c.
 * every FreeBSD accommodation is a compile-time flag in the Makefile
 * (the -D__NetBSD__ variant selection, __dead2, libutil fparseln) — see
 * sbin/pppoectl/Makefile.  The tool drives the SPPP* ioctl surface of
 * this port's if_pppoe(4) driver, including the always-disabled
 * SPPPGETIDLETO/SPPPSETIDLETO (125/126) idle-timeout stubs (spec section
 * 8 and PORTING-sppp.md) that its list mode calls unconditionally, and
 * the SPPP_FILTER dial filters (144-146) it only uses when built with
 * -DSPPP_FILTER (never defined in this port).
 *
 * No longer byte-identical to NetBSD (R005 dropped to "same ioctl ABI",
 * not "same bytes"): p3-ctl-abi hardened -f/-S, print_error()/strtonum/
 * strlcpy and set_ifname() argument handling.  docs/PORTING-sppp.md
 * "pppoectl.c hardening deltas" lists every local change from the pin.
 *
 * One addition, not in NetBSD: the `mssfix` / `nomssfix` keywords and the
 * list-mode "mssfix:" line drive this driver's PPPOESETMSSFIX/
 * PPPOEGETMSSFIX TCP MSS clamp.  They are compiled only when
 * <net/if_pppoe.h> defines PPPOESETMSSFIX.
 */
#include <sys/cdefs.h>

#ifndef lint
__RCSID("$NetBSD: pppoectl.c,v 1.32 2026/07/28 07:28:02 yamaguchi Exp $");
#endif


#include <sys/param.h>
#include <sys/callout.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#ifdef SPPP_FILTER
#include <pcap.h>
#endif

__dead static void usage(void);
__dead static void print_error(const char *ifname, int error, const char * str);
static void set_ifname(char *dst, size_t dstsize, const char *src);
static void scrub_stdin_secret(void);
static long long parse_num(const char *what, const char *str,
	long long minval, long long maxval);
static void print_vals(const char *ifname, int phase, struct spppauthcfg *sp,
	int lcp_timeout, time_t idle_timeout, int authfailures,
	int max_auth_failures, u_int maxalive, time_t max_noreceive,
	u_int alive_interval, int ncp_flags);
static void print_dns(const char *ifname, int dns1, int dns2, int s, int tabs);
static void print_stats(const char *ifname, int s, int dump);
static const char *phase_name(int phase);
static const char *proto_name(int proto);
static const char *authflags(int flags);
static const char *pppoe_state_name(int state);
static const char *ppp_state_name(int state);
static void pppoectl_argument(char *arg);
#ifdef SPPP_FILTER
static void set_spppfilter(struct spppfilter *, const char *, const char *);
#endif

#define	ISSET(x, a)	((x) & (a))
/* __err is errno, captured immediately after the ioctl() call: print_error()
 * needs the real reason (ENXIO, EPERM, ...), not ioctl()'s -1 return, which
 * every failure reports identically (see print_error()). */
#define PPPOECTL_IOCTL(_ifname, _s, _cmd, _st)	do {	\
	int __e, __err;					\
	memset((_st), 0, sizeof(*(_st)));		\
	set_ifname((_st)->ifname, sizeof((_st)->ifname), (_ifname)); \
	__e = ioctl((_s), (_cmd), (_st));		\
	__err = errno;					\
	if (__e != 0)					\
		print_error((_ifname), __err, #_cmd);	\
} while (0)

static int hz = 0;

static int set_auth, set_lcp, set_idle_to, set_auth_failure, set_dns,
    clear_auth_failure_count, set_keepalive;
/* -S: myauthsecret read verbatim from stdin. Visible to pppoectl_argument()
 * too, so a later myauthsecret=/myauthkey= (from -f or argv) can be
 * rejected instead of silently overriding it. */
static int secret_from_stdin;
static char *stdin_secret;
static u_int set_ncpflags, clr_ncpflags;
static int maxalive = -1;
#ifdef PPPOESETMSSFIX
static int set_mssfix = -1;	/* -1 unchanged, 0 nomssfix, 1 mssfix */
#endif
static int max_noreceive = -1;
static int alive_intval = -1;
static struct spppauthcfg spr;
static struct sppplcpcfg lcp;
static struct spppncpcfg ncp;
static struct spppstatus status;
static struct spppidletimeout timeout;
static struct spppauthfailurestats authfailstats;
static struct spppauthfailuresettings authfailset;
static struct spppdnssettings dnssettings;
static struct spppkeepalivesettings keepalivesettings;
#ifdef SPPP_FILTER
static struct spppfilter	 spppfilter;
static const char		*filter_dialing = NULL;
static const char		*filter_active_in = NULL;
static const char		*filter_active_out = NULL;
#endif

int
main(int argc, char **argv)
{
	FILE *fp;
	int s, c;
	int errs = 0, verbose = 0, dump = 0, dns1 = 0, dns2 = 0;
	size_t len;
	const char *eth_if_name, *access_concentrator, *service;
	const char *ifname, *configname;
	char *line;
	int mib[2];
	struct clockinfo clockinfo;
	setprogname(argv[0]);

	eth_if_name = NULL;
	access_concentrator = NULL;
	service = NULL;
	configname = NULL;
	while ((c = getopt(argc, argv, "vde:f:s:a:n:S")) != -1)
		switch (c) {
		case 'v':
			verbose++;
			break;

		case 'd':
			dump++;
			break;

		case 'e':
			eth_if_name = optarg;
			break;

		case 'f':
			configname = optarg;
			break;

		case 'S':
			secret_from_stdin = 1;
			break;

		case 's':
			service = optarg;
			break;

		case 'a':
			access_concentrator = optarg;
			break;

		case 'n':
			if (strcmp(optarg, "1") == 0)
				dns1 = 1;
			else if (strcmp(optarg, "2") == 0)
				dns2 = 1;
			else {
				fprintf(stderr, "bad argument \"%s\" to -n (only 1 or two allowed)\n",
					optarg);
				errs++;
			}
			break;

		default:
			errs++;
			break;
		}
	argv += optind;
	argc -= optind;

	if (errs || argc < 1)
		usage();

	/* -S conflicts: -e (PPPOESETPARMS) never even looks at spr.mysecret
	 * (it returns below before -S's stdin read would run), and -f
	 * /dev/stdin would race -S for the same stdin. Both used to be
	 * silently ignored/racy; reject them instead. */
	if (secret_from_stdin && eth_if_name)
		errx(EX_USAGE, "-S cannot be combined with -e");
	if (secret_from_stdin && configname != NULL &&
	    strcmp(configname, "/dev/stdin") == 0)
		errx(EX_USAGE, "-S cannot be combined with -f /dev/stdin "
		    "(both read the secret from stdin)");

	ifname = argv[0];

	/* use a random AF to create the socket */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(EX_UNAVAILABLE, "ifconfig: socket");

	argc--;
	argv++;

	if (eth_if_name) {
		struct pppoediscparms parms;
		int e;

		memset(&parms, 0, sizeof parms);
		set_ifname(parms.ifname, sizeof(parms.ifname), ifname);
		set_ifname(parms.eth_ifname, sizeof(parms.eth_ifname), eth_if_name);
		if (access_concentrator) {
			parms.ac_name = access_concentrator;
			parms.ac_name_len = strlen(access_concentrator);
		}
		if (service) {
			parms.service_name = service;
			parms.service_name_len = strlen(service);
		}

		e = ioctl(s, PPPOESETPARMS, &parms);
		if (e)
			print_error(ifname, errno, "PPPOESETPARMS");
		return 0;
	}

	if (dns1 || dns2) {
		print_dns(ifname, dns1, dns2, s, 0);
	}

	if (dump) {
		print_stats(ifname, s, dump);
		return 0;
	}

	memset(&spr, 0, sizeof spr);
	set_ifname(spr.ifname, sizeof spr.ifname, ifname);
	spr.myauth = SPPP_AUTHPROTO_NOCHG;
	spr.hisauth = SPPP_AUTHPROTO_NOCHG;
	memset(&lcp, 0, sizeof lcp);
	set_ifname(lcp.ifname, sizeof lcp.ifname, ifname);
	memset(&ncp, 0, sizeof ncp);
	set_ifname(ncp.ifname, sizeof ncp.ifname, ifname);
	memset(&status, 0, sizeof status);
	set_ifname(status.ifname, sizeof status.ifname, ifname);
	memset(&timeout, 0, sizeof timeout);
	set_ifname(timeout.ifname, sizeof timeout.ifname, ifname);
	memset(&authfailstats, 0, sizeof authfailstats);
	set_ifname(authfailstats.ifname, sizeof authfailstats.ifname, ifname);
	memset(&authfailset, 0, sizeof authfailset);
	set_ifname(authfailset.ifname, sizeof authfailset.ifname, ifname);
	memset(&dnssettings, 0, sizeof dnssettings);
	set_ifname(dnssettings.ifname, sizeof dnssettings.ifname, ifname);
	memset(&keepalivesettings, 0, sizeof keepalivesettings);
	set_ifname(keepalivesettings.ifname, sizeof keepalivesettings.ifname, ifname);
#ifdef SPPP_FILTER
	memset(&spppfilter, 0, sizeof spppfilter);
	strlcpy(spppfilter.ifname, ifname, sizeof spppfilter.ifname);
#endif

	/* -S: myauthsecret read verbatim (one line, no fparseln unescaping)
	 * from stdin, so a caller never has to put a secret on argv or risk
	 * fparseln's backslash/comment handling mangling it (spec item 3). */
	if (secret_from_stdin) {
		size_t n = 0;
		ssize_t slen = getline(&stdin_secret, &n, stdin);
		if (slen < 0)
			err(EX_NOINPUT, "-S: reading secret from stdin");
		if (slen > 0 && stdin_secret[slen - 1] == '\n')
			stdin_secret[--slen] = '\0';
		if (slen > 0 && stdin_secret[slen - 1] == '\r')
			stdin_secret[--slen] = '\0';
		atexit(scrub_stdin_secret);
		spr.mysecret = stdin_secret;
		spr.mysecret_length = (u_int)slen + 1;
		set_auth = 1;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_CLOCKRATE;
	len = sizeof(clockinfo);
	if(sysctl(mib, 2, &clockinfo, &len, NULL, 0) == -1)
	{
		fprintf(stderr, "error, cannot sysctl kern.clockrate!\n");
		exit(1);
	}

	hz = clockinfo.hz;
		
	if (argc == 0 && !(dns1||dns2) && !configname && !secret_from_stdin) {
		/* list only mode */

		/* first pass, get name lengths */
		if (ioctl(s, SPPPGETAUTHCFG, &spr) == -1)
			err(EX_OSERR, "SPPPGETAUTHCFG");
		/* now allocate buffers for strings */
		if (spr.myname_length)
			if ((spr.myname = malloc(spr.myname_length)) == NULL)
				err(1, NULL);
		if (spr.hisname_length)
			if ((spr.hisname = malloc(spr.hisname_length)) == NULL)
				err(1, NULL);
		/* second pass: get names too */
		if (ioctl(s, SPPPGETAUTHCFG, &spr) == -1)
			err(EX_OSERR, "SPPPGETAUTHCFG");

		if (ioctl(s, SPPPGETLCPCFG, &lcp) == -1)
			err(EX_OSERR, "SPPPGETLCPCFG");
		if (ioctl(s, SPPPGETNCPCFG, &ncp) == -1)
			err(EX_OSERR, "SPPPGETNCPCFG");
		if (ioctl(s, SPPPGETSTATUS, &status) == -1)
			err(EX_OSERR, "SPPPGETSTATUS");
		if (ioctl(s, SPPPGETIDLETO, &timeout) == -1)
			err(EX_OSERR, "SPPPGETIDLETO");
		if (ioctl(s, SPPPGETAUTHFAILURES, &authfailstats) == -1)
			err(EX_OSERR, "SPPPGETAUTHFAILURES");
		if (ioctl(s, SPPPGETKEEPALIVE, &keepalivesettings) == -1)
			err(EX_OSERR, "SPPPGETKEEPALIVE");

		print_vals(ifname, status.phase, &spr, lcp.lcp_timeout,
		    timeout.idle_seconds, authfailstats.auth_failures,
		    authfailstats.max_failures,
		    keepalivesettings.maxalive,
		    keepalivesettings.max_noreceive,
		    keepalivesettings.alive_interval,
		    ncp.ncp_flags);
#ifdef PPPOEGETMSSFIX
		{
			struct pppoemssfixparms mp;

			memset(&mp, 0, sizeof mp);
			set_ifname(mp.ifname, sizeof mp.ifname, ifname);
			if (ioctl(s, PPPOEGETMSSFIX, &mp) == 0)
				printf("\tmssfix: %s\n",
				    mp.enable ? "enable" : "disable");
		}
#endif

		if (spr.hisname) free(spr.hisname);
		if (spr.myname) free(spr.myname);
		return 0;
	}

	/* first load the config file, then parse command line args.
	 * "-f /dev/stdin" works via this same fopen() -- no special case
	 * needed -- so the secret never has to be passed on argv. */
	if (configname) {
		if ((fp = fopen(configname, "r")) == NULL)
			err(EX_NOINPUT, "%s", configname);
		while ((line = fparseln(fp, NULL, NULL, NULL,
		    FPARSELN_UNESCALL)) != NULL) {
			if (line[0] != '\0')
				pppoectl_argument(line);
			/*
			 * We do not free(line) here, because we
			 * still have references to parts of the
			 * string collected in the various ioctl
			 * argument structures (and need those).
			 * Yes, this is a memory leak.
			 * We could copy the partial strings instead,
			 * and free those later - but this is a one-shot
			 * program and memory will be freed at process
			 * exit time anyway.
			 */
		}
		fclose(fp);
	}

       
	while (argc > 0) {
		pppoectl_argument(argv[0]);

		argv++;
		argc--;
	}

	if (set_auth) {
		if (ioctl(s, SPPPSETAUTHCFG, &spr) == -1)
			err(EX_OSERR, "SPPPSETAUTHCFG");
	}
	if (set_lcp) {
		if (ioctl(s, SPPPSETLCPCFG, &lcp) == -1)
			err(EX_OSERR, "SPPPSETLCPCFG");
	}
	if (set_ncpflags != 0 || clr_ncpflags != 0) {
		if (ioctl(s, SPPPGETNCPCFG, &ncp) == -1)
			err(EX_OSERR, "SPPPGETNCPCFG");

		ncp.ncp_flags |= set_ncpflags;
		ncp.ncp_flags &= ~clr_ncpflags;

		if (ioctl(s, SPPPSETNCPCFG, &ncp) == -1)
			err(EX_OSERR, "SPPPSETNCPCFG");
	}
	if (set_idle_to) {
		if (ioctl(s, SPPPSETIDLETO, &timeout) == -1)
			err(EX_OSERR, "SPPPSETIDLETO");
	}
	if (set_auth_failure) {
		if (ioctl(s, SPPPSETAUTHFAILURE, &authfailset) == -1)
			err(EX_OSERR, "SPPPSETAUTHFAILURE");
	}
	if (clear_auth_failure_count && !(set_auth || set_auth_failure)) {
		/*
		 * We want to clear the auth failure count, but did not
		 * do that implicitly by setting authentication - so
		 * do a zero-effect auth setting change
		 */
		if (ioctl(s, SPPPGETAUTHFAILURES, &authfailstats) == -1)
			err(EX_OSERR, "SPPPGETAUTHFAILURES");
		authfailset.max_failures = authfailstats.max_failures;
		if (ioctl(s, SPPPSETAUTHFAILURE, &authfailset) == -1)
			err(EX_OSERR, "SPPPSETAUTHFAILURE");
	}
	if (set_dns) {
		if (ioctl(s, SPPPSETDNSOPTS, &dnssettings) == -1)
			err(EX_OSERR, "SPPPSETDNSOPTS");
	}
	if (set_keepalive) {
		if (ioctl(s, SPPPGETKEEPALIVE, &keepalivesettings) == -1)
			err(EX_OSERR, "SPPPGETKEEPALIVE");
		if (max_noreceive >= 0)
			keepalivesettings.max_noreceive = max_noreceive;
		if (maxalive >= 0)
			keepalivesettings.maxalive = maxalive;
		if (alive_intval >= 0)
			keepalivesettings.alive_interval = alive_intval;
		if (ioctl(s, SPPPSETKEEPALIVE, &keepalivesettings) == -1)
			err(EX_OSERR, "SPPPSETKEEPALIVE");
	}
#ifdef PPPOESETMSSFIX
	if (set_mssfix >= 0) {
		struct pppoemssfixparms mp;

		memset(&mp, 0, sizeof mp);
		set_ifname(mp.ifname, sizeof mp.ifname, ifname);
		mp.enable = set_mssfix;
		if (ioctl(s, PPPOESETMSSFIX, &mp) == -1)
			err(EX_OSERR, "PPPOESETMSSFIX");
	}
#endif

#ifdef SPPP_FILTER
	if (filter_dialing != NULL) {
		const char *cmdstr = "SPPPIOCSDIALFILT";
		set_spppfilter(&spppfilter, filter_dialing, cmdstr);
		if (ioctl(s, SPPPIOCSDIALFILT, &spppfilter) == -1)
			err(EX_OSERR, "%s", cmdstr);
	}
	if (filter_active_in != NULL) {
		const char *cmdstr = "SPPPIOCSIACTIVE";
		set_spppfilter(&spppfilter, filter_active_in, cmdstr);
		if (ioctl(s, SPPPIOCSIACTIVE, &spppfilter) == -1)
			err(EX_OSERR, "%s", cmdstr);
	}
	if (filter_active_out != NULL) {
		const char *cmdstr = "SPPPIOCSOACTIVE";
		set_spppfilter(&spppfilter, filter_active_out, cmdstr);
		if (ioctl(s, SPPPIOCSOACTIVE, &spppfilter) == -1)
			err(EX_OSERR, "%s", cmdstr);
	}
#endif

	if (verbose) {
		if (ioctl(s, SPPPGETAUTHFAILURES, &authfailstats) == -1)
			err(EX_OSERR, "SPPPGETAUTHFAILURES");
		if (ioctl(s, SPPPGETKEEPALIVE, &keepalivesettings) == -1)
			err(EX_OSERR, "SPPPGETKEEPALIVE");
		print_vals(ifname, status.phase, &spr, lcp.lcp_timeout,
		    timeout.idle_seconds, authfailstats.auth_failures,
		    authfailstats.max_failures,
		    keepalivesettings.maxalive,
		    keepalivesettings.max_noreceive,
		    keepalivesettings.alive_interval,
		    ncp.ncp_flags);
	}

	return 0;
}

static void
pppoectl_argument(char *arg)
{
	size_t off;
	const char *cp;

#define startswith(a,s) strncmp(a, s, (off = strlen(s))) == 0
	if (startswith(arg, "authproto=")) {
		cp = arg + off;
		if (strcmp(cp, "pap") == 0)
			spr.myauth =
				spr.hisauth = SPPP_AUTHPROTO_PAP;
		else if (strcmp(cp, "chap") == 0)
			spr.myauth = spr.hisauth = SPPP_AUTHPROTO_CHAP;
		else if (strcmp(cp, "none") == 0)
			spr.myauth = spr.hisauth = SPPP_AUTHPROTO_NONE;
		else
			errx(EX_DATAERR, "bad auth proto: %s", cp);
		set_auth = 1;
	} else if (startswith(arg, "myauthproto=")) {
		cp = arg + off;
		if (strcmp(cp, "pap") == 0)
			spr.myauth = SPPP_AUTHPROTO_PAP;
		else if (strcmp(cp, "chap") == 0)
			spr.myauth = SPPP_AUTHPROTO_CHAP;
		else if (strcmp(cp, "none") == 0)
			spr.myauth = SPPP_AUTHPROTO_NONE;
		else
			errx(EX_DATAERR, "bad auth proto: %s", cp);
		set_auth = 1;
	} else if (startswith(arg, "myauthname=")) {
		spr.myname = arg + off;
		spr.myname_length = strlen(spr.myname)+1;
		set_auth = 1;
	} else if (startswith(arg, "myauthsecret=") || startswith(arg, "myauthkey=")) {
		if (secret_from_stdin)
			errx(EX_USAGE, "myauthsecret/myauthkey given after "
			    "-S already set the secret");
		spr.mysecret = arg + off;
		spr.mysecret_length = strlen(spr.mysecret)+1;
		set_auth = 1;
	} else if (startswith(arg, "hisauthproto=")) {
		cp = arg + off;
		if (strcmp(cp, "pap") == 0)
			spr.hisauth = SPPP_AUTHPROTO_PAP;
		else if (strcmp(cp, "chap") == 0)
			spr.hisauth = SPPP_AUTHPROTO_CHAP;
		else if (strcmp(cp, "none") == 0)
			spr.hisauth = SPPP_AUTHPROTO_NONE;
		else
			errx(EX_DATAERR, "bad auth proto: %s", cp);
		set_auth = 1;
	} else if (startswith(arg, "hisauthname=")) {
		spr.hisname = arg + off;
		spr.hisname_length = strlen(spr.hisname)+1;
		set_auth = 1;
	} else if (startswith(arg, "hisauthsecret=") || startswith(arg, "hisauthkey=")) {
		spr.hissecret = arg + off;
		spr.hissecret_length = strlen(spr.hissecret)+1;
		set_auth = 1;
	} else if (startswith(arg, "max-noreceive=")) {
		max_noreceive = (int)parse_num("max-noreceive", arg+off, 0, INT_MAX);
		set_keepalive = 1;
	} else if (startswith(arg, "max-alive-missed=")) {
		maxalive = (int)parse_num("max-alive-missed", arg+off, 0, INT_MAX);
		set_keepalive = 1;
	} else if (startswith(arg, "alive-interval=")) {
		alive_intval = (int)parse_num("alive-interval", arg+off, 0, INT_MAX);
		set_keepalive = 1;
	} else if (strcmp(arg, "callin") == 0)
		spr.hisauthflags |= SPPP_AUTHFLAG_NOCALLOUT;
	else if (strcmp(arg, "always") == 0)
		spr.hisauthflags &= ~SPPP_AUTHFLAG_NOCALLOUT;
	else if (strcmp(arg, "norechallenge") == 0)
		spr.hisauthflags |= SPPP_AUTHFLAG_NORECHALLENGE;
	else if (strcmp(arg, "rechallenge") == 0)
		spr.hisauthflags &= ~SPPP_AUTHFLAG_NORECHALLENGE;
	else if (strcmp(arg, "passiveauthproto") == 0)
		spr.myauthflags |= SPPP_AUTHFLAG_PASSIVEAUTHPROTO;
#ifndef __NetBSD__
	else if (strcmp(arg, "enable-vj") == 0)
		spr.defs.enable_vj = 1;
	else if (strcmp(arg, "disable-vj") == 0)
		spr.defs.enable_vj = 0;
#endif
	else if (startswith(arg, "lcp-timeout=")) {
		int timeout_arg = (int)parse_num("lcp-timeout", arg+off, 1, 20000);
		lcp.lcp_timeout = timeout_arg * hz / 1000;
		set_lcp = 1;
	} else if (startswith(arg, "idle-timeout=")) {
		timeout.idle_seconds =
		    (time_t)parse_num("idle-timeout", arg+off, 0, LLONG_MAX);
		set_idle_to = 1;
	} else if (startswith(arg, "max-auth-failure=")) {
		authfailset.max_failures =
		    (int)parse_num("max-auth-failure", arg+off, 0, INT_MAX);
		set_auth_failure = 1;
	} else if (strcmp(arg, "clear-auth-failure") == 0) {
		clear_auth_failure_count = 1;
	} else if (startswith(arg, "query-dns=")) {
		dnssettings.query_dns = (int)parse_num("query-dns", arg+off, 0, 3);
		set_dns = 1;
	} else if (strcmp(arg, "ipcp") == 0) {
		set_ncpflags |= SPPP_NCP_IPCP;
		clr_ncpflags &= ~SPPP_NCP_IPCP;
	} else if (strcmp(arg, "noipcp") == 0) {
		set_ncpflags &= ~SPPP_NCP_IPCP;
		clr_ncpflags |= SPPP_NCP_IPCP;
	} else if (strcmp(arg, "ipv6cp") == 0) {
		set_ncpflags |= SPPP_NCP_IPV6CP;
		clr_ncpflags &= ~SPPP_NCP_IPV6CP;
	} else if (strcmp(arg, "noipv6cp") == 0) {
		set_ncpflags &= ~SPPP_NCP_IPV6CP;
		clr_ncpflags |= SPPP_NCP_IPV6CP;
#ifdef PPPOESETMSSFIX
	} else if (strcmp(arg, "mssfix") == 0) {
		set_mssfix = 1;
	} else if (strcmp(arg, "nomssfix") == 0) {
		set_mssfix = 0;
#endif
#ifdef SPPP_FILTER
	} else if (startswith(arg, "filter-dialing=")) {
		filter_dialing = arg + off;
	} else if (startswith(arg, "filter-active-in=")) {
		filter_active_in = arg + off;
	} else if (startswith(arg, "filter-active-out=")) {
		filter_active_out = arg + off;
#endif
	} else
		errx(EX_DATAERR, "bad parameter: \"%s\"", arg);
}

static void
usage(void)
{
	const char * prog = getprogname();
	fprintf(stderr,
	    "usage:\n"
	    "       %s [-f config] ifname [...]\n"
	    "       %s [-v] ifname [{my|his}auth{proto|name|secret}=...] \\\n"
            "                      [callin] [always] [{no}rechallenge]\n"
            "                      [query-dns=3] [{no}ipcp] [{no}ipv6cp]\n"
#ifdef PPPOESETMSSFIX
            "                      [{no}mssfix]\n"
#endif
	    "           to set authentication names, passwords\n"
	    "           and (optional) parameters\n"
	    "       %s [-v] ifname lcp-timeout=ms|idle-timeout=s|\n"
	    "                      max-noreceive=s|max-alive-missed=cnt|\n"
	    "                      max-auth-failure=count|clear-auth-failure\n"
#ifdef SPPP_FILTER
	    "                      filter-dialing=...|\n"
	    "                      filter-active-in=...|filter-active-out=...\n"
#endif
	    "           to set general parameters\n"
	    "   or\n"
	    "       %s -e ethernet-ifname ifname\n"
	    "           to connect an ethernet interface for PPPoE\n"
	    "       %s [-a access-concentrator-name] [-s service-name] ifname\n"
	    "           to specify (optional) data for PPPoE sessions\n"
	    "       %s -d ifname\n"
	    "           to dump the current PPPoE session state\n"
	    "       %s -n (1|2) ifname\n"
	    "           to print DNS addresses retrieved via query-dns\n"
	    , prog, prog, prog, prog, prog, prog, prog);
	exit(EX_USAGE);
}

static void
print_vals(const char *ifname, int phase, struct spppauthcfg *sp, int lcp_timeout,
	time_t idle_timeout, int authfailures, int max_auth_failures,
	u_int maxalive_cnt, time_t max_noreceive_time, u_int alive_interval,
	int ncp_flags)
{
#ifndef __NetBSD__
	time_t send, recv;
#endif

	printf("%s:\tphase=%s\n", ifname, phase_name(phase));
	if (sp->myauth) {
		printf("\tmyauthproto=%s myauthname=\"%s\"\n",
		       proto_name(sp->myauth),
		       sp->myname);
	}
	if (sp->hisauth) {
		printf("\thisauthproto=%s hisauthname=\"%s\"%s\n",
		       proto_name(sp->hisauth),
		       sp->hisname,
		       authflags(sp->hisauthflags));
	}
#ifndef __NetBSD__
	if (sp->defs.pp_phase > PHASE_DEAD) {
		send = time(NULL) - sp->defs.pp_last_sent;
		recv = time(NULL) - sp->defs.pp_last_recv;
		printf("\tidle_time=%ld\n", (send<recv)? send : recv);
	}
#endif

	printf("\tlcp timeout: %.3f s\n",
	       (double)lcp_timeout / hz);

	if (idle_timeout != 0)
		printf("\tidle timeout = %lu s\n", (unsigned long)idle_timeout);
	else
		printf("\tidle timeout = disabled\n");

	if (authfailures != 0)
		printf("\tauthentication failures = %d\n", authfailures);
	printf("\tmax-auth-failure = %d\n", max_auth_failures);

	printf("\tmax-noreceive = %ld seconds\n", (long)max_noreceive_time);
	printf("\tmax-alive-missed = %u unanswered echo requests\n", maxalive_cnt);
	printf("\talive-interval = %u\n", alive_interval);

#ifndef __NetBSD__
	printf("\tenable_vj: %s\n",
	       sp->defs.enable_vj ? "on" : "off");
#endif

	printf("\tipcp: %s\n",
	    ncp_flags & SPPP_NCP_IPCP ? "enable" : "disable");
	printf("\tipv6cp: %s\n",
	    ncp_flags & SPPP_NCP_IPV6CP ? "enable" : "disable");
}

static void
print_dns(const char *ifname, int dns1, int dns2, int s, int tabs)
{
	int i;
	struct spppdnsaddrs addrs;

	if (!dns1 && !dns2)
		return;

	PPPOECTL_IOCTL(ifname, s, SPPPGETDNSADDRS, &addrs);
	if (dns1) {
		for (i = 0; i < tabs; i++)
			printf("\t");
		if (tabs > 0)
			printf("primary dns address ");
		printf("%d.%d.%d.%d\n",
		       (addrs.dns[0] >> 24) & 0xff,
		       (addrs.dns[0] >> 16) & 0xff,
		       (addrs.dns[0] >> 8) & 0xff,
		       addrs.dns[0] & 0xff);
	}
	if (dns2) {
		for (i = 0; i < tabs; i++)
			printf("\t");
		if (tabs > 0)
			printf("secondary dns address ");
		printf("%d.%d.%d.%d\n",
		       (addrs.dns[1] >> 24) & 0xff,
		       (addrs.dns[1] >> 16) & 0xff,
		       (addrs.dns[1] >> 8) & 0xff,
		       addrs.dns[1] & 0xff);
	}
}

static void
print_stats(const char *ifname, int s, int dump)
{
	struct pppoeconnectionstate state;
	struct sppplcpstatus lcpst;
	struct spppipcpstatus ipcpst;
	struct spppipv6cpstatus ipv6cpst;
	struct in_addr addr;

	PPPOECTL_IOCTL(ifname, s, PPPOEGETSESSION, &state);

	/* dump PPPoE session state */
	printf("%s:\t%s %s\n", ifname,
	    dump > 1 ? "PPPoE state:" : "state =",
	    pppoe_state_name(state.state));
	printf("\tSession ID: 0x%x\n", state.session_id);
	printf("\tPADI retries: %d\n", state.padi_retry_no);
	printf("\tPADR retries: %d\n", state.padr_retry_no);

	if (dump > 1) {
		PPPOECTL_IOCTL(ifname, s, SPPPGETLCPSTATUS, &lcpst);
		PPPOECTL_IOCTL(ifname, s, SPPPGETIPCPSTATUS, &ipcpst);
		PPPOECTL_IOCTL(ifname, s, SPPPGETIPV6CPSTATUS, &ipv6cpst);

		printf("\tLCP state: %s\n",
		    ppp_state_name(lcpst.state));
		printf("\tIPCP state: %s\n",
		    ppp_state_name(ipcpst.state));
		printf("\tIPv6CP state: %s\n",
		    ppp_state_name(ipv6cpst.state));

		if (lcpst.state == SPPP_STATE_OPENED) {
			printf("\tLCP negotiated options:\n");
			printf("\t\tmru %lu\n", lcpst.mru);
			printf("\t\tmagic number 0x%lx\n",
			    lcpst.magic);
		}

		if (ipcpst.state == SPPP_STATE_OPENED) {
			addr.s_addr = ipcpst.myaddr;

			printf("\tIPCP negotiated options:\n");
			printf("\t\taddress %s\n", inet_ntoa(addr));
			print_dns(ifname,
			    ISSET(ipcpst.opts, SPPP_IPCP_OPT_PRIMDNS),
			    ISSET(ipcpst.opts, SPPP_IPCP_OPT_SECDNS),
			    s, 2);
		}

		if (ipv6cpst.state == SPPP_STATE_OPENED) {
			printf("\tIPv6CP negotiated options:\n");
			if (ISSET(ipv6cpst.opts, SPPP_IPV6CP_OPT_COMPRESSION))
				printf("\t\tcompression\n");
			if (ISSET(ipv6cpst.opts, SPPP_IPV6CP_OPT_IFID)) {
				printf("\t\tifid: "
				    "my_ifid=0x%02x%02x%02x%02x%02x%02x%02x%02x, "
				    "his_ifid=0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				ipv6cpst.my_ifid[0], ipv6cpst.my_ifid[1],
				ipv6cpst.my_ifid[2], ipv6cpst.my_ifid[3],
				ipv6cpst.my_ifid[4], ipv6cpst.my_ifid[5],
				ipv6cpst.my_ifid[6], ipv6cpst.my_ifid[7],
				ipv6cpst.his_ifid[0], ipv6cpst.his_ifid[1],
				ipv6cpst.his_ifid[2], ipv6cpst.his_ifid[3],
				ipv6cpst.his_ifid[4], ipv6cpst.his_ifid[5],
				ipv6cpst.his_ifid[6], ipv6cpst.his_ifid[7]);
			}
		}
	}
}

static const char *
phase_name(int phase)
{
	switch (phase) {
	case SPPP_PHASE_DEAD:		return "dead";
	case SPPP_PHASE_ESTABLISH:	return "establish";
	case SPPP_PHASE_TERMINATE:	return "terminate";
	case SPPP_PHASE_AUTHENTICATE:	return "authenticate";
	case SPPP_PHASE_NETWORK:	return "network";
	}
	return "illegal";
}

static const char *
proto_name(int proto)
{
	static char buf[12];
	switch (proto) {
	case SPPP_AUTHPROTO_PAP:	return "pap";
	case SPPP_AUTHPROTO_CHAP:	return "chap";
	case SPPP_AUTHPROTO_NONE:	return "none";
	}
	snprintf(buf, sizeof(buf), "0x%x", (unsigned)proto);
	return buf;
}

static const char *
authflags(int flags)
{
	static char buf[32];
	buf[0] = '\0';
	if (flags & SPPP_AUTHFLAG_NOCALLOUT)
		strlcat(buf, " callin", sizeof(buf));
	if (flags & SPPP_AUTHFLAG_NORECHALLENGE)
		strlcat(buf, " norechallenge", sizeof(buf));
	return buf;
}

static const char *
pppoe_state_name(int state)
{

	switch(state) {
	case PPPOE_STATE_INITIAL:
		return "initial";
	case PPPOE_STATE_PADI_SENT:
		return "PADI sent";
	case PPPOE_STATE_PADR_SENT:
		return "PADR sent";
	case PPPOE_STATE_SESSION:
		return "session";
	case PPPOE_STATE_CLOSING:
		return "closing";
	}

	return "unknown";
}
static const char *
ppp_state_name(int state)
{

	switch (state) {
	case SPPP_STATE_INITIAL:	return "initial";
	case SPPP_STATE_STARTING:	return "starting";
	case SPPP_STATE_CLOSED:		return "closed";
	case SPPP_STATE_STOPPED:	return "stopped";
	case SPPP_STATE_CLOSING:	return "closing";
	case SPPP_STATE_STOPPING:	return "stopping";
	case SPPP_STATE_REQ_SENT:	return "req-sent";
	case SPPP_STATE_ACK_RCVD:	return "ack-rcvd";
	case SPPP_STATE_ACK_SENT:	return "ack-sent";
	case SPPP_STATE_OPENED:		return "opened";
	}

	return "unknown";
}

/*
 * `error` is errno, not ioctl()'s -1 return (every failure returns -1, so
 * that value can never distinguish "no such interface" from anything
 * else). ifioctl()'s generic ifunit_ref() lookup on our struct's leading
 * ifname field returns ENXIO before the driver ever sees the ioctl.
 */
static void
print_error(const char *ifname, int error, const char * str)
{
	if (error == ENXIO)
		fprintf(stderr, "%s: interface not found\n", ifname);
	else
		fprintf(stderr, "%s: %s: %s\n", ifname, str, strerror(error));
	exit(EX_DATAERR);
}

/* Scrubs the -S secret from memory at exit (atexit(), so every err()/errx()
 * exit path is covered too, not just the normal return). */
static void
scrub_stdin_secret(void)
{
	if (stdin_secret != NULL) {
		explicit_bzero(stdin_secret, strlen(stdin_secret));
		free(stdin_secret);
		stdin_secret = NULL;
	}
}

/* strncpy(dst, src, sizeof(dst)) does not NUL-terminate when src doesn't
 * fit, silently handing the kernel a truncated (and possibly wrong)
 * interface name; strlcpy() always terminates, and a truncated result
 * here is itself an error worth stopping on rather than probing/setting
 * the wrong interface. */
static void
set_ifname(char *dst, size_t dstsize, const char *src)
{
	if (strlcpy(dst, src, dstsize) >= dstsize)
		errx(EX_USAGE, "interface name too long: %s", src);
}

/* atoi()/atol() return 0 on garbage input, indistinguishable from an
 * actual 0 -- strtonum(3) rejects non-numeric and out-of-range input
 * instead of silently accepting it. */
static long long
parse_num(const char *what, const char *str, long long minval, long long maxval)
{
	const char *errstr;
	long long v;

	v = strtonum(str, minval, maxval, &errstr);
	if (errstr != NULL)
		errx(EX_DATAERR, "%s: \"%s\" is %s (range %lld..%lld)",
		    what, str, errstr, minval, maxval);
	return v;
}

#ifdef SPPP_FILTER
static void
set_spppfilter(struct spppfilter *sf, const char *pcap_str,
    const char *cmdstr)
{

	if (strcmp(pcap_str, "none") == 0) {
		/* filter matches no packets */
		static const struct bpf_insn null_insns[] = {
			BPF_STMT(BPF_RET+BPF_K, (u_int)0)
		};
		const struct bpf_program null_bf = {
			.bf_len = __arraycount(null_insns),
			.bf_insns = __UNCONST(null_insns),
		};
		sf->bf = null_bf;
	} else if (strcmp(pcap_str, "all") == 0) {
		sf->bf.bf_len = 0;
		sf->bf.bf_insns = NULL;
	} else {
		pcap_t *pcap;
		/*
		 * bpf_filter() is called before PPP encapsulation in
		 * sppp_output and after PPP decapsulation in sppp_input.
		 * It therefore sees raw IP packets rather than PPP frames,
		 * so use DLT_RAW instead of DLT_PPP_ETHER.
		 */
		pcap = pcap_open_dead(DLT_RAW, 65535);
		if (pcap == NULL)
			err(EX_OSERR, "%s: pcap_open_dead failed", cmdstr);
		if (pcap_compile(pcap, &sf->bf, pcap_str, 1, 0))
			errx(EX_OSERR, "%s: filter compile error: %s",
			    cmdstr, pcap_geterr(pcap));

		pcap_close(pcap);
	}
}
#endif
