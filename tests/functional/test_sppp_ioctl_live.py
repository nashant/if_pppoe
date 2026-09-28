"""S04 T1: live verification of the full SPPP* ioctl surface.

Drives the in-kernel if_pppoe/sppp stack through a live dial against the
lab accel-ppp server and then probes every SPPP* ioctl from a host-side C
helper compiled on the client VM:

  - SPPPSETDNSOPTS/SPPPGETDNSOPTS round-trip enables the IPCP DNS options
    (the in-kernel default is query_dns=0, like pppoectl's absent
    dns-options setting), then after the dial:
  - SPPPGETDNSADDRS returns the accel-ppp-pushed primary DNS 10.99.0.1
    (R010) -- the mpd5-seam test only ever sees the option on the wire;
  - SPPPGETIDLETO returns a zeroed spppidletimeout and SPPPSETIDLETO is
    accept-and-ignore (research amendment 2, R005): the stubs exist so
    NetBSD pppoectl list mode does not die, and nothing is stored;
  - every ioctl in the implemented set 120-124, 125-139 answers (no
    ENOTTY) while the dial filters 144-146 remain unimplemented
    (spec section 8, PORTING-sppp.md).
"""
from __future__ import annotations

import time

import pytest

from lab import (
    ACCEL_GW,
    PPPOE_STATE_SESSION,
    _ssh_stdin,
    spppauth_cmd,
    push_vendored_sppp_headers,
)

# The auth helper from the PAP live test installs /usr/local/sbin/spppauth
# (SPPPSETAUTHCFG myauthproto=PAP); accel-ppp requires authentication, so
# the probe dial must program it before `up`, exactly like test_pap_live.
from test_pap_live import _install_spppauth

pytestmark = pytest.mark.datapath

# Minimal SPPPIOC* surface prober, byte-identical in behaviour to
# tools/spppioctl/spppioctl.c (keep the two in sync). Includes the real
# vendored <net/if_sppp.h> (pushed to the client VM by
# push_vendored_sppp_headers(), see _install_spppioctl()) instead of a
# private struct/ioctl-number copy, so a renumbering can't silently desync
# this probe from the driver (p3-ctl-abi).
_SPPPPIOCTL_C = r"""
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

union spbuf {
	struct spppstatus st;
	struct spppstatusncp stncp;
	struct spppidletimeout idle;
	struct spppauthcfg auth;
	struct sppplcpcfg lcp;
	struct spppauthfailurestats afs;
	struct spppauthfailuresettings afss;
	struct spppdnssettings dnsopts;
	struct spppdnsaddrs dns;
	struct spppkeepalivesettings ka;
	struct sppplcpstatus lcpst;
	struct spppipcpstatus ipcpst;
	struct spppipv6cpstatus ipv6st;
	struct spppncpcfg ncp;
	struct spppfilter filt;
	char slack[256];
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

static void
sweep_fill(int fd, int n, const char *ifname, union spbuf *b)
{
	memset(b, 0, sizeof(*b));
	strlcpy(b->st.ifname, ifname, sizeof(b->st.ifname));
	switch (n) {
	case 120: case 122: case 124: case 125: case 127:
	case 130: case 131: case 133: case 134: case 135:
	case 136: case 137: case 138:
		break;
	case 121:
		b->auth.myauth = SPPP_AUTHPROTO_NOCHG;
		b->auth.hisauth = SPPP_AUTHPROTO_NOCHG;
		break;
	case 123:
		if (ioctl(fd, SPPPGETLCPCFG, b) < 0)
			err(1, "SPPPGETLCPCFG");
		break;
	case 126:
		b->idle.idle_seconds = 300;
		break;
	case 128:
		b->afss.max_failures = 3;
		break;
	case 129:
		if (ioctl(fd, SPPPGETDNSOPTS, b) < 0)
			err(1, "SPPPGETDNSOPTS");
		break;
	case 132:
		if (ioctl(fd, SPPPGETKEEPALIVE, b) < 0)
			err(1, "SPPPGETKEEPALIVE");
		break;
	case 139:
		if (ioctl(fd, SPPPGETNCPCFG, b) < 0)
			err(1, "SPPPGETNCPCFG");
		break;
	case 144: case 145: case 146:
		break;
	default:
		errx(2, "sweep: unhandled ioctl number %d", n);
	}
}

static int
do_sweep(const char *ifname)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int bad = 0;
	int required[] = {
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131, 132, 133, 134, 135, 136, 137, 138, 139, -1 };
	int unfiltered[] = { 144, 145, 146, -1 };
	int i, n;

	if (fd < 0)
		err(1, "socket");
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
do_status(const char *ifname)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	union spbuf b;

	if (fd < 0)
		err(1, "socket");
	memset(&b, 0, sizeof(b));
	strlcpy(b.st.ifname, ifname, sizeof(b.st.ifname));
	if (ioctl(fd, SPPPGETSTATUS, &b) < 0)
		err(1, "SPPPGETSTATUS");
	printf("phase=%d\n", b.st.phase);
	close(fd);
	return 0;
}

static int
do_dnsopts(const char *ifname, int mask)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	union spbuf b;

	if (fd < 0)
		err(1, "socket");
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
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	union spbuf b;
	char ab[INET_ADDRSTRLEN], bb[INET_ADDRSTRLEN];

	if (fd < 0)
		err(1, "socket");
	memset(&b, 0, sizeof(b));
	strlcpy(b.dns.ifname, ifname, sizeof(b.dns.ifname));
	if (ioctl(fd, SPPPGETDNSADDRS, &b) < 0)
		err(1, "SPPPGETDNSADDRS");
	/* The driver stores the address as a host-order uint32; inet_ntop
	 * wants network order, so swap back before printing. */
	uint32_t a = htonl(b.dns.dns[0]), c = htonl(b.dns.dns[1]);
	(void)inet_ntop(AF_INET, &a, ab, sizeof(ab));
	(void)inet_ntop(AF_INET, &c, bb, sizeof(bb));
	printf("dns=%s %s\n", ab, bb);
	close(fd);
	return 0;
}

static int
do_idleget(const char *ifname)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	union spbuf b;

	if (fd < 0)
		err(1, "socket");
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
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	union spbuf b;

	if (fd < 0)
		err(1, "socket");
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
	if (argc < 3)
		return 2;
	if (strcmp(argv[1], "dnsopts") == 0)
		return do_dnsopts(argv[2], atoi(argv[3]));
	if (strcmp(argv[1], "dns") == 0)
		return do_dns(argv[2]);
	if (strcmp(argv[1], "idleget") == 0)
		return do_idleget(argv[2]);
	if (strcmp(argv[1], "idleset") == 0)
		return do_idleset(argv[2], atol(argv[3]));
	if (strcmp(argv[1], "sweep") == 0)
		return do_sweep(argv[2]);
	if (strcmp(argv[1], "status") == 0)
		return do_status(argv[2]);
	return 2;
}
"""


def _install_spppioctl(driver):
    """Compile the embedded SPPPIOC* prober on the client (root)."""
    hdr_dir = push_vendored_sppp_headers(driver)
    r = _ssh_stdin(
        driver.port,
        "cat > /tmp/spppioctl.c",
        _SPPPPIOCTL_C,
    )
    assert r.returncode == 0, f"uploading spppioctl.c failed: {r.stderr}"
    r = driver.run(
        f"cc -O2 -Wall -I{hdr_dir} -o /usr/local/sbin/spppioctl /tmp/spppioctl.c && "
        "rm -f /tmp/spppioctl.c",
        root=True,
    )
    assert r.returncode == 0, f"spppioctl compile failed: {r.stdout}\n{r.stderr}"
    # No-args run must print nothing and exit 2 (usage gate).
    r = driver.run("/usr/local/sbin/spppioctl", root=True)
    assert r.returncode == 2, (
        "spppioctl without args should exit 2: "
        f"{r.stdout}\n{r.stderr}"
    )


def _wait_inet(driver, timeout=25):
    """Poll until the live session has a negotiated IPv4 address."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = driver.iface_state()
        if last["inet"] is not None:
            return last
        time.sleep(0.5)
    return last


def test_sppp_ioctl_surface_live(driver, accel_server, sniffer):
    """Full live ioctl-surface proof on an up session (R005, R010, spec 8)."""
    _install_spppioctl(driver)
    _install_spppauth(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")

    # accel-ppp requires authentication; program PAP creds before dialling
    # (the same SPPPSETAUTHCFG path test_pap_live uses).
    cmd, secret = spppauth_cmd("pppoe0")
    r = driver.run(cmd, root=True, stdin=secret)
    assert r.returncode == 0, f"spppauth set failed: {r.stdout}\n{r.stderr}"

    # Enable the IPCP DNS options before dialling: the in-kernel default is
    # query_dns=0 (like pppoectl's default); SPPPSETDNSOPTS round-trips.
    r = driver.run("/usr/local/sbin/spppioctl dnsopts pppoe0 3", root=True)
    assert r.returncode == 0 and "dnsopts=3" in r.stdout, (
        f"dnsopts set/get round-trip failed: {r.stdout}\n{r.stderr}"
    )

    sniffer.start()
    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION)
    assert st["state"] == PPPOE_STATE_SESSION, (
        f"state stayed {st}: no live discovery\n"
        f"dmesg:\n{driver.run('dmesg | tail -25').stdout}\n"
        f"accel-log:\n{accel_server.log_tail(10)}"
    )
    up = _wait_inet(driver)
    assert up["inet"] is not None, (
        f"no negotiated IPv4 on the live session: {up['raw']}\n"
        f"accel-log:\n{accel_server.log_tail(15)}"
    )

    # SPPPGETDNSADDRS must return the accel-ppp-pushed primary DNS (R010).
    r = driver.run("/usr/local/sbin/spppioctl dns pppoe0", root=True)
    assert r.returncode == 0, f"spppioctl dns failed: {r.stdout}\n{r.stderr}"
    assert r.stdout.strip() == f"dns={ACCEL_GW} 0.0.0.0", (
        f"SPPPGETDNSADDRS did not return the negotiated DNS {ACCEL_GW}: "
        f"{r.stdout}"
    )

    # SPPPGETIDLETO: zeroed struct, no error (never dies; R005).
    r = driver.run("/usr/local/sbin/spppioctl idleget pppoe0", root=True)
    assert r.returncode == 0, f"idleget failed: {r.stdout}\n{r.stderr}"
    assert r.stdout.strip() == "idle=0", f"SPPPGETIDLETO not zeroed: {r.stdout}"

    # SPPPSETIDLETO: accept-and-ignore (spec 8 stub) -- a second GET still 0.
    r = driver.run("/usr/local/sbin/spppioctl idleset pppoe0 300", root=True)
    assert r.returncode == 0, f"idleset failed: {r.stdout}\n{r.stderr}"
    r = driver.run("/usr/local/sbin/spppioctl idleget pppoe0", root=True)
    assert r.returncode == 0 and r.stdout.strip() == "idle=0", (
        f"SPPPSETIDLETO stored a timeout instead of ignoring: {r.stdout}"
    )

    # The full sweep: 120-139 all answered (no ENOTTY), 144-146 absent.
    r = driver.run("/usr/local/sbin/spppioctl sweep pppoe0", root=True)
    assert r.returncode == 0, f"spppioctl sweep failed:\n{r.stdout}\n{r.stderr}"
    got = r.stdout.split()
    for n in range(120, 140):
        assert f"{n}:ok" in got or f"{n} ok" in r.stdout, (
            f"ioctl {n} not answered in sweep:\n{r.stdout}"
        )
    for n in range(144, 147):
        assert f"{n} not-implemented" in r.stdout, (
            f"dial filter ioctl {n} should not be implemented:\n{r.stdout}"
        )
    assert not any("UNEXPECTED-ok" in l for l in r.stdout.splitlines()), (
        f"a do-not-port ioctl was answered:\n{r.stdout}"
    )

    # The session survived the whole probe: IPCP still up, DNS intact.
    up2 = driver.iface_state()
    assert up2["inet"] is not None and up2["inet"] == up["inet"], (
        f"session dropped during ioctl sweep: {up2['raw']}"
    )
    r = driver.run("/usr/local/sbin/spppioctl dns pppoe0", root=True)
    assert r.stdout.strip() == f"dns={ACCEL_GW} 0.0.0.0", (
        f"DNS lost after sweep: {r.stdout}"
    )
    sniffer.stop()