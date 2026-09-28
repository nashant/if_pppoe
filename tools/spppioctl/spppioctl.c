/*
 * spppioctl - probe the full SPPP* ioctl surface of an if_pppoe clone.
 *
 * M002/S04/T1 stopgap for pppoectl(8) (plan 2, S05): proves the complete
 * implemented SPPP ioctl set (120-124, 127-139) is answered by the
 * in-kernel driver, that 125/126 (idle timeout) are always-disabled
 * stubs (spec section 8, PORTING-sppp.md decision), and that the dial
 * filters 144-146 remain unimplemented.
 *
 *   spppioctl dnsopts IFACE MASK     # SPPPSETDNSOPTS then GET round-trip
 *   spppioctl dns IFACE              # SPPPGETDNSADDRS -> print negotiated DNS
 *   spppioctl idleget IFACE          # SPPPGETIDLETO -> print idle timeout
 *   spppioctl idleset IFACE SECS     # SPPPSETIDLETO  -> accept-and-ignore
 *   spppioctl sweep IFACE            # every 120-124/127-139 answered,
 *                                    # 125/126 stub semantics, 144-146 fail
 *
 * The struct and ioctl numbers come from the vendored sys/net/if_sppp.h
 * (ABI constraint R005) via -I${.CURDIR}/../../sys (see Makefile): a
 * private copy here could silently desync from the driver across a
 * renumbering (it did once -- the group-letter fix in if_sppp.h).
 * SPPP_FILTER's struct spppfilter (144-146) needs <net/bpf.h>'s
 * bpf_program; this tool never compiles or runs a filter, so a
 * zeroed/absent bf_insns is the correct "no filter" probe payload.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_sppp.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* One buffer large enough for every struct above. */
union spbuf {
	struct spppstatus		st;
	struct spppstatusncp		stncp;
	struct spppidletimeout		idle;
	struct spppauthcfg		auth;
	struct sppplcpcfg		lcp;
	struct spppauthfailurestats	afs;
	struct spppauthfailuresettings	afss;
	struct spppdnssettings		dnsopts;
	struct spppdnsaddrs		dns;
	struct spppkeepalivesettings	ka;
	struct sppplcpstatus		lcpst;
	struct spppipcpstatus		ipcpst;
	struct spppipv6cpstatus		ipv6st;
	struct spppncpcfg		ncp;
	struct spppfilter		filt;
	char				slack[256];
};

static unsigned long
iocnum(int n)
{
	switch (n) {
	case 120: return SPPPGETAUTHCFG;
	case 121: return SPPPSETAUTHCFG;
	case 122: return SPPPGETLCPCFG;
	case 123: return SPPPSETLCPCFG;
	case 124: return SPPPGETSTATUS;
	case 125: return SPPPGETIDLETO;
	case 126: return SPPPSETIDLETO;
	case 127: return SPPPGETAUTHFAILURES;
	case 128: return SPPPSETAUTHFAILURE;
	case 129: return SPPPSETDNSOPTS;
	case 130: return SPPPGETDNSOPTS;
	case 131: return SPPPGETDNSADDRS;
	case 132: return SPPPSETKEEPALIVE;
	case 133: return SPPPGETKEEPALIVE;
	case 134: return SPPPGETSTATUSNCP;
	case 135: return SPPPGETLCPSTATUS;
	case 136: return SPPPGETIPCPSTATUS;
	case 137: return SPPPGETIPV6CPSTATUS;
	case 138: return SPPPGETNCPCFG;
	case 139: return SPPPSETNCPCFG;
	case 144: return SPPPIOCSDIALFILT;
	case 145: return SPPPIOCSIACTIVE;
	case 146: return SPPPIOCSOACTIVE;
	default: errx(2, "no ioctl for number %d", n);
	}
}

static int
probe_fd(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(1, "socket");
	return fd;
}

/* Fill the buffer for ioctl number n.  ifname is written into every
 * struct's head (char ifname[IFNAMSIZ]) before any readback ioctl so
 * the interface is identified from the first call. */
static void
sweep_fill(int fd, int n, const char *ifname, union spbuf *b)
{
	memset(b, 0, sizeof(*b));
	strlcpy(b->st.ifname, ifname, sizeof(b->st.ifname));
	switch (n) {
	case 120:		/* SPPPGETAUTHCFG: zeroed struct is safe */
	case 122:		/* SPPPGETLCPCFG */
	case 124:		/* SPPPGETSTATUS */
	case 125:		/* SPPPGETIDLETO */
	case 127:		/* SPPPGETAUTHFAILURES */
	case 130:		/* SPPPGETDNSOPTS */
	case 131:		/* SPPPGETDNSADDRS */
	case 133:		/* SPPPGETKEEPALIVE */
	case 134:		/* SPPPGETSTATUSNCP */
	case 135:		/* SPPPGETLCPSTATUS */
	case 136:		/* SPPPGETIPCPSTATUS */
	case 137:		/* SPPPGETIPV6CPSTATUS */
	case 138:		/* SPPPGETNCPCFG */
		break;
	case 121:		/* SPPPSETAUTHCFG: NOCHG = no state change */
		b->auth.myauth = SPPP_AUTHPROTO_NOCHG;
		b->auth.hisauth = SPPP_AUTHPROTO_NOCHG;
		break;
	case 123:		/* SPPPSETLCPCFG: readback the GET value */
		if (ioctl(fd, SPPPGETLCPCFG, b) < 0)
			err(1, "SPPPGETLCPCFG (readback for 123)");
		break;
	case 126:		/* SPPPSETIDLETO: any value (accept-and-ignore) */
		b->idle.idle_seconds = 300;
		break;
	case 128:		/* SPPPSETAUTHFAILURE: benign max */
		b->afss.max_failures = 3;
		break;
	case 129:		/* SPPPSETDNSOPTS: readback the GET value */
		if (ioctl(fd, SPPPGETDNSOPTS, b) < 0)
			err(1, "SPPPGETDNSOPTS (readback for 129)");
		break;
	case 132:		/* SPPPSETKEEPALIVE: readback the GET value */
		if (ioctl(fd, SPPPGETKEEPALIVE, b) < 0)
			err(1, "SPPPGETKEEPALIVE (readback for 132)");
		break;
	case 139:		/* SPPPSETNCPCFG: readback the GET value */
		if (ioctl(fd, SPPPGETNCPCFG, b) < 0)
			err(1, "SPPPGETNCPCFG (readback for 139)");
		break;
	case 144:		/* SPPPIOCSDIALFILT: must NOT be answered */
	case 145:		/* SPPPIOCSIACTIVE */
	case 146:		/* SPPPIOCSOACTIVE */
		break;
	default:
		errx(2, "sweep: unhandled ioctl number %d", n);
	}
}

/*
 * sweep: prove that 120-139 (the full implemented set incl. the 125/126
 * stubs) are all answered, and that the dial filters 144-146 are not.
 * Exit 0 iff every required ioctl returned 0 AND every expected-fail
 * ioctl failed.  Prints one line per ioctl: "<n> ok" / "<n> fail(err=X)"
 * / "<n> EXPECTED-FAIL ok".
 */
static int
do_sweep(const char *ifname)
{
	int fd = probe_fd();
	int bad = 0;
	int required[] = {
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
		-1 };
	int unfiltered[] = { 144, 145, 146, -1 };
	int i, n;

	for (i = 0; required[i] != -1; i++) {
		union spbuf b;
		n = required[i];
		sweep_fill(fd, n, ifname, &b);
		errno = 0;
		if (ioctl(fd, iocnum(n), &b) < 0) {
			printf("%d fail(err=%d)\n", n, errno);
			bad = 1;
			continue;
		}
		/* stub semantics the caller relies on (also asserted via
		 * the idleget/idleset subcommands) */
		if (n == 125 && b.idle.idle_seconds != 0) {
			printf("%d fail(stub returned idle=%ld)\n", n,
			    (long)b.idle.idle_seconds);
			bad = 1;
			continue;
		}
		printf("%d ok\n", n);
	}
	for (i = 0; unfiltered[i] != -1; i++) {
		union spbuf b;
		n = unfiltered[i];
		sweep_fill(fd, n, ifname, &b);
		errno = 0;
		if (ioctl(fd, iocnum(n), &b) < 0) {
			printf("%d not-implemented(err=%d)\n", n, errno);
			continue;
		}
		printf("%d UNEXPECTED-ok\n", n);
		bad = 1;
	}
	close(fd);
	return bad ? 1 : 0;
}

static int
do_dnsopts(const char *ifname, int mask)
{
	int fd = probe_fd();
	union spbuf b;

	memset(&b, 0, sizeof(b));
	strlcpy(b.dnsopts.ifname, ifname, sizeof(b.dnsopts.ifname));
	b.dnsopts.query_dns = mask;
	if (ioctl(fd, SPPPSETDNSOPTS, &b) < 0)
		err(1, "SPPPSETDNSOPTS");
	if (ioctl(fd, SPPPGETDNSOPTS, &b) < 0)
		err(1, "SPPPGETDNSOPTS");
	printf("dnsopts=%d\n", b.dnsopts.query_dns);
	close(fd);
	return b.dnsopts.query_dns == (mask & 3) ? 0 : 1;
}

static int
do_dns(const char *ifname)
{
	int fd = probe_fd();
	union spbuf b;
	char ab[INET_ADDRSTRLEN], bb[INET_ADDRSTRLEN];

	memset(&b, 0, sizeof(b));
	strlcpy(b.dns.ifname, ifname, sizeof(b.dns.ifname));
	if (ioctl(fd, SPPPGETDNSADDRS, &b) < 0)
		err(1, "SPPPGETDNSADDRS");

	(void)inet_ntop(AF_INET, &b.dns.dns[0], ab, sizeof(ab));
	(void)inet_ntop(AF_INET, &b.dns.dns[1], bb, sizeof(bb));
	printf("dns=%s %s\n", ab, bb);
	close(fd);
	return 0;
}

static int
do_idleget(const char *ifname)
{
	int fd = probe_fd();
	union spbuf b;

	memset(&b, 0, sizeof(b));
	strlcpy(b.idle.ifname, ifname, sizeof(b.idle.ifname));
	if (ioctl(fd, SPPPGETIDLETO, &b) < 0)
		err(1, "SPPPGETIDLETO");
	printf("idle=%ld\n", (long)b.idle.idle_seconds);
	close(fd);
	return b.idle.idle_seconds == 0 ? 0 : 1;
}

static int
do_idleset(const char *ifname, long secs)
{
	int fd = probe_fd();
	union spbuf b;

	memset(&b, 0, sizeof(b));
	strlcpy(b.idle.ifname, ifname, sizeof(b.idle.ifname));
	b.idle.idle_seconds = secs;
	if (ioctl(fd, SPPPSETIDLETO, &b) < 0)
		err(1, "SPPPSETIDLETO");
	printf("idle=set\n");
	close(fd);
	return 0;
}

int
main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
		    "usage: %s dnsopts IFACE MASK | dns IFACE | "
		    "idleget IFACE | idleset IFACE SECS | sweep IFACE\n",
		    argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "dnsopts") == 0) {
		if (argc != 4)
			return 2;
		return do_dnsopts(argv[2], atoi(argv[3]));
	}
	if (strcmp(argv[1], "dns") == 0)
		return do_dns(argv[2]);
	if (strcmp(argv[1], "idleget") == 0)
		return do_idleget(argv[2]);
	if (strcmp(argv[1], "idleset") == 0)
		return do_idleset(argv[2], atol(argv[3]));
	if (strcmp(argv[1], "sweep") == 0)
		return do_sweep(argv[2]);
	fprintf(stderr, "%s: unknown subcommand %s\n", argv[0], argv[1]);
	return 2;
}