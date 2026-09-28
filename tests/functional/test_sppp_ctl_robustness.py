"""sppp control-path robustness: auth ioctls, syslog records, control frames.

Three fixes in the vendored sppp layer, each proved live on the in-kernel
driver (CLIENT=if_pppoe, `datapath` marker -- the `driver` fixture owns the
clone):

  - SPPPSETAUTHCFG/SPPPGETAUTHCFG used to malloc(M_WAITOK)/copyin/copyout
    under the sppp mutex (a MTX_DEF mutex in this port): WITNESS on the SMPW
    kernel printed "uma_zalloc_debug ... non-sleepable locks held ... sppp"
    with a sppp_params backtrace for every set.  A set also freed the old
    credentials before validating the new ones, so a rejected set left the
    interface with no credentials at all.
  - SPPP_LOG() emitted its "<ifname>: " prefix and its text as two log(9)
    records at different priorities, so the text of an INFO/ERR record never
    reached syslog at the priority it was logged with.
  - pppoe_data_input() guaranteed only 2 contiguous bytes, but sppp's control
    input reads (and NAKs/REJs in place) the whole frame through mtod().
"""
from __future__ import annotations

import re
import time

import pytest
from scapy.all import Ether, PPPoED, Raw

from lab import (
    ETH_PPPOE_SESSION,
    PADO,
    PPPOE_STATE_SESSION,
    _ssh_stdin,
    active_creds,
    push_vendored_sppp_headers,
)
from test_pap_live import _serial_log

pytestmark = pytest.mark.datapath

# SPPPSETAUTHCFG/SPPPGETAUTHCFG driver. Includes the real vendored
# <net/if_sppp.h> (pushed to the client VM by push_vendored_sppp_headers(),
# see _install_spppauthcfg()) instead of a private copy, so a renumbering
# can't silently desync this probe from the driver (p3-ctl-abi). NEVER
# prints a secret value: `get` reports only whether the kernel wrote into
# the secret buffers it was handed (it must not).
_SPPPAUTHCFG_C = r"""
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_sppp.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
proto(const char *s)
{
	if (strcmp(s, "none") == 0) return 0;
	if (strcmp(s, "pap") == 0) return 1;
	if (strcmp(s, "chap") == 0) return 2;
	errx(2, "bad proto %s", s);
}

static void
str(const char *s, char **p, u_int *len)
{
	if (strcmp(s, "-") == 0) { *p = NULL; *len = 0; return; }
	*p = (char *)s;
	*len = strlen(s) + 1;
}

int
main(int argc, char **argv)
{
	struct spppauthcfg cfg;
	char myname[512], hisname[512], mysec[64], hissec[64];
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	u_int i;

	if (argc < 3)
		return 2;
	memset(&cfg, 0, sizeof(cfg));
	strlcpy(cfg.ifname, argv[2], sizeof(cfg.ifname));
	if (strcmp(argv[1], "set") == 0 && argc == 9) {
		/* set IF MYPROTO MYNAME MYSECRET HISPROTO HISNAME HISSECRET */
		cfg.myauth = proto(argv[3]);
		str(argv[4], &cfg.myname, &cfg.myname_length);
		str(argv[5], &cfg.mysecret, &cfg.mysecret_length);
		cfg.hisauth = proto(argv[6]);
		str(argv[7], &cfg.hisname, &cfg.hisname_length);
		str(argv[8], &cfg.hissecret, &cfg.hissecret_length);
		if (ioctl(s, SPPPSETAUTHCFG, &cfg) < 0)
			err(1, "SPPPSETAUTHCFG");
		printf("set ok\n");
		return 0;
	}
	if (strcmp(argv[1], "setbad") == 0 && argc == 5) {
		/* setbad IF toolong|efault NAMELEN: a PAP set whose myname is
		 * NAMELEN bytes long (toolong) or whose mysecret points at
		 * unmapped memory (efault); prints the errno. */
		static char big[8192];
		u_int n = (u_int)atoi(argv[4]);
		cfg.myauth = 1;
		if (strcmp(argv[3], "toolong") == 0) {
			if (n == 0 || n > sizeof(big))
				errx(2, "bad length");
			memset(big, 'x', n - 1);
			big[n - 1] = '\0';
			cfg.myname = big;
			cfg.myname_length = n;
			cfg.mysecret = "whatever";
			cfg.mysecret_length = 9;
		} else {
			cfg.myname = "newname";
			cfg.myname_length = 8;
			cfg.mysecret = (char *)8;	/* unmapped */
			cfg.mysecret_length = 16;
		}
		errno = 0;
		if (ioctl(s, SPPPSETAUTHCFG, &cfg) == 0)
			printf("setbad errno=0\n");
		else
			printf("setbad errno=%d\n", errno);
		return 0;
	}
	if (strcmp(argv[1], "get") == 0) {
		/* Pass 1: lengths only.  Pass 2: names into buffers, with
		 * sentinel-filled secret buffers that must come back
		 * untouched.  Pass 3: a too-short name buffer must fail with
		 * ENAMETOOLONG. */
		if (ioctl(s, SPPPGETAUTHCFG, &cfg) < 0)
			err(1, "SPPPGETAUTHCFG pass 1");
		printf("myauth=%u hisauth=%u mynamelen=%u hisnamelen=%u\n",
		    cfg.myauth, cfg.hisauth, cfg.myname_length,
		    cfg.hisname_length);
		memset(myname, 0, sizeof(myname));
		memset(hisname, 0, sizeof(hisname));
		memset(mysec, 0xa5, sizeof(mysec));
		memset(hissec, 0xa5, sizeof(hissec));
		cfg.myname = myname;
		cfg.hisname = hisname;
		cfg.mysecret = mysec;
		cfg.mysecret_length = sizeof(mysec);
		cfg.hissecret = hissec;
		cfg.hissecret_length = sizeof(hissec);
		if (cfg.myname_length == 0)
			cfg.myname_length = sizeof(myname);
		if (cfg.hisname_length == 0)
			cfg.hisname_length = sizeof(hisname);
		if (ioctl(s, SPPPGETAUTHCFG, &cfg) < 0)
			err(1, "SPPPGETAUTHCFG pass 2");
		printf("myname=<%s> hisname=<%s>\n", myname, hisname);
		for (i = 0; i < sizeof(mysec); i++)
			if ((u_char)mysec[i] != 0xa5 ||
			    (u_char)hissec[i] != 0xa5)
				break;
		printf("secrets_untouched=%d\n", i == sizeof(mysec));
		if (myname[0] != '\0') {
			memset(&cfg, 0, sizeof(cfg));
			strlcpy(cfg.ifname, argv[2], sizeof(cfg.ifname));
			cfg.myname = myname;
			cfg.myname_length = 1;
			errno = 0;
			(void)ioctl(s, SPPPGETAUTHCFG, &cfg);
			printf("short_errno=%d\n", errno);
		}
		return 0;
	}
	return 2;
}
"""

_HELPER = "/usr/local/sbin/spppauthcfg"
ENAMETOOLONG = 63
EFAULT = 14


def _install_spppauthcfg(driver):
    hdr_dir = push_vendored_sppp_headers(driver)
    r = _ssh_stdin(driver.port, "cat > /tmp/spppauthcfg.c", _SPPPAUTHCFG_C)
    assert r.returncode == 0, f"uploading spppauthcfg.c failed: {r.stderr}"
    r = driver.run(
        f"cc -O2 -Wall -I{hdr_dir} -o {_HELPER} /tmp/spppauthcfg.c && "
        "rm -f /tmp/spppauthcfg.c",
        root=True,
    )
    assert r.returncode == 0, f"spppauthcfg compile failed: {r.stdout}\n{r.stderr}"


def _get(driver, iface="pppoe0") -> dict:
    r = driver.run(f"{_HELPER} get {iface}", root=True)
    assert r.returncode == 0, f"spppauthcfg get failed: {r.stdout}\n{r.stderr}"
    out = {"raw": r.stdout}
    for k, v in re.findall(r"(\w+)=(<[^>]*>|\S+)", r.stdout):
        out[k] = v.strip("<>")
    return out


def _serial_mark() -> int:
    return len(_serial_log())


def _serial_since(mark: int) -> str:
    return _serial_log()[mark:]


def _wait_inet(driver, timeout=25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = driver.iface_state()
        if last["inet"] is not None:
            return last
        time.sleep(0.5)
    return last


def test_auth_cfg_set_repeatedly_is_witness_clean_and_reads_back(driver):
    """PAP and CHAP sets, 25 of each, then a GET round-trip.  No WITNESS
    sleep-under-mutex report may name sppp_params (the pre-fix SMPW suite
    logged 242 of them); the names read back are the last ones set; the
    secret buffers handed to GET are never written; a short name buffer is
    ENAMETOOLONG."""
    _install_spppauthcfg(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")

    mark = _serial_mark()
    # One remote loop: 75 separate ssh round trips would dominate the test.
    loop = (
        "for i in $(seq 0 24); do "
        f"{_HELPER} set pppoe0 pap user$i usersecret$i none - - || exit 1; "
        f"{_HELPER} set pppoe0 chap user$i usersecret$i "
        "chap peer$i peersecret$i || exit 2; "
        f"{_HELPER} get pppoe0 >/dev/null || exit 3; "
        "done"
    )
    r = driver.run(loop, root=True, timeout=120)
    assert r.returncode == 0, (
        f"set/get loop failed (rc {r.returncode}: 1=PAP set, 2=CHAP set, "
        f"3=get): {r.stdout}\n{r.stderr}"
    )

    got = _get(driver)
    assert got["myauth"] == "2" and got["hisauth"] == "2", got["raw"]
    assert got["myname"] == "user24" and got["hisname"] == "peer24", got["raw"]
    assert got["mynamelen"] == str(len("user24") + 1), got["raw"]
    assert got["hisnamelen"] == str(len("peer24") + 1), got["raw"]
    assert got["secrets_untouched"] == "1", (
        f"SPPPGETAUTHCFG wrote into the caller's secret buffers: {got['raw']}"
    )
    assert "secret" not in got["myname"] + got["hisname"], got["raw"]
    assert got["short_errno"] == str(ENAMETOOLONG), (
        f"a 1-byte name buffer did not fail ENAMETOOLONG: {got['raw']}"
    )

    time.sleep(2)  # let the serial console drain
    delta = _serial_since(mark)
    offending = [
        l for l in delta.splitlines()
        if "sppp_params" in l or "uma_zalloc_debug" in l
        or "sleeping with" in l.lower()
    ]
    assert not offending, (
        "WITNESS reported sleeping/allocating under a lock in the sppp auth "
        "ioctls:\n" + "\n".join(offending[:40])
    )


def test_rejected_auth_cfg_leaves_the_old_credentials_intact(driver, accel_server):
    """A set that fails validation (name too long, secret pointer faults)
    must not touch the stored credentials: GET still reads back the run's
    account name, and the session still authenticates with its secret."""
    _install_spppauthcfg(driver)
    # create() programs PAP with the run's account through pppoectl.
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")
    user = active_creds().user
    before = _get(driver)
    assert before["myauth"] == "1" and before["myname"] == user, before["raw"]

    # 3000 > MCLBYTES: rejected before and after the fix, but the pre-fix
    # code freed the old credentials first.  300: longer than the u_char
    # name_len can describe (the pre-fix code accepted it and stored a
    # wrapped length).
    for n in (3000, 300):
        r = driver.run(f"{_HELPER} setbad pppoe0 toolong {n}", root=True)
        assert r.returncode == 0 and f"setbad errno={ENAMETOOLONG}" in r.stdout, (
            f"a {n}-byte name was not rejected ENAMETOOLONG: {r.stdout}\n{r.stderr}"
        )
    r = driver.run(f"{_HELPER} setbad pppoe0 efault 0", root=True)
    assert r.returncode == 0 and f"setbad errno={EFAULT}" in r.stdout, (
        f"a faulting secret pointer was not rejected EFAULT: {r.stdout}\n{r.stderr}"
    )

    after = _get(driver)
    assert after["myauth"] == "1" and after["myname"] == user, (
        f"a rejected SPPPSETAUTHCFG changed the stored credentials:\n"
        f"before: {before['raw']}\nafter: {after['raw']}"
    )

    # The secret cannot be read back; authenticating with it is the proof.
    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION)
    assert st.get("state") == PPPOE_STATE_SESSION, st
    up = _wait_inet(driver)
    assert up["inet"] is not None, (
        "the session did not authenticate after the rejected sets -- the "
        f"stored secret was lost: {up['raw']}\n{accel_server.log_tail(20)}"
    )


_SYSLOG_CONF = "/etc/syslog.d/zz-sppp-prio-test.conf"
_INFO_LOG = "/var/log/sppp-prio-info.log"
_DEBUG_LOG = "/var/log/sppp-prio-debug.log"


def test_sppp_info_record_reaches_syslog_whole_at_info_priority(driver, accel_server):
    """"IPCP layer down" is an sppp LOG_INFO record.  It must reach syslog as
    one kern.info line carrying both the interface name and the text; the
    pre-fix SPPP_LOG() logged "pppoe0: " at INFO and the text separately at
    kern.debug."""
    r = driver.run("grep -Eq '^include[[:space:]]+/etc/syslog.d' /etc/syslog.conf")
    assert r.returncode == 0, "client syslog.conf does not include /etc/syslog.d"
    conf = f"kern.=info\t{_INFO_LOG}\nkern.=debug\t{_DEBUG_LOG}\n"
    r = _ssh_stdin(driver.port, "cat > /tmp/sppp-prio.conf", conf)
    assert r.returncode == 0, r.stderr
    r = driver.run(
        f"install -m 644 /tmp/sppp-prio.conf {_SYSLOG_CONF} && "
        f"rm -f /tmp/sppp-prio.conf && : > {_INFO_LOG} && : > {_DEBUG_LOG} && "
        "service syslogd reload",
        root=True,
    )
    assert r.returncode == 0, f"syslogd setup failed: {r.stdout}\n{r.stderr}"
    try:
        time.sleep(1)
        driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")
        driver.up("pppoe0")
        up = _wait_inet(driver)
        assert up["inet"] is not None, (
            f"no IPCP session to take down: {up['raw']}\n{accel_server.log_tail(20)}"
        )
        driver.down("pppoe0")

        want = re.compile(r"kernel: pppoe0: IPCP layer down$", re.M)
        deadline = time.time() + 15
        info = ""
        while time.time() < deadline:
            info = driver.run(f"cat {_INFO_LOG}", root=True).stdout
            if want.search(info):
                break
            time.sleep(1)
        debug = driver.run(f"cat {_DEBUG_LOG}", root=True).stdout
        assert want.search(info), (
            "no whole 'pppoe0: IPCP layer down' record at kern.info\n"
            f"kern.info:\n{info}\nkern.debug:\n{debug}"
        )
        assert not re.search(r"kernel: pppoe0:\s*$", info, re.M), (
            f"a prefix-only 'pppoe0:' record reached kern.info:\n{info}"
        )
        assert "IPCP layer down" not in debug, (
            f"the INFO record's text leaked to kern.debug:\n{debug}"
        )
    finally:
        driver.run(
            f"rm -f {_SYSLOG_CONF} {_INFO_LOG} {_DEBUG_LOG}; "
            "service syslogd reload",
            root=True,
        )


def test_large_lcp_confreq_is_parsed_whole(driver, accel_server, sniffer):
    """An LCP Configure-Request larger than MHLEN must be parsed to its end:
    MRU, then 50 Async-Control-Character-Map options (accepted by the
    reject pass), then ONE unknown option as the very last 8 bytes of a
    312-byte option list.  The client's Configure-Reject must carry exactly
    that last option -- only a parser that walked the whole frame finds it.
    (sppp_cp_send() clamps replies to MHLEN, so a reject echoing many
    options could not prove this; the single trailing option can.)

    The fix this guards makes a non-IP frame contiguous before sppp_input()
    (m_pullup up to MHLEN, m_defrag beyond).  The lab cannot force a chained
    RX mbuf -- vtnet receives a frame this size into one cluster -- so the
    chained-input arm is covered by code review; this test proves a
    beyond-MHLEN control frame still parses whole on the contiguous path.
    """
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"no session: {parms}\n{accel_server.log_tail(20)}"
    )
    session = parms["session"]
    pados = [
        p for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADO
    ]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    ac_mac = pados[0][Ether].src.lower()
    # Session publish is asynchronous; let LCP settle past its first
    # exchange too, so our Configure-Request is not raced by accel-ppp's.
    time.sleep(3)

    accm = bytes([2, 6, 0, 0, 0, 0]) * 50
    unknown = bytes([200, 8]) + b"TAILOPT"[:6]
    opts = bytes([1, 4, 0x05, 0xd4]) + accm + unknown
    ident = 0x7b
    lcp = bytes([1, ident]) + (4 + len(opts)).to_bytes(2, "big") + opts
    ppp = b"\xc0\x21" + lcp
    assert len(ppp) > 256, "the frame must exceed MHLEN"
    frame = Ether(dst=driver.mac, src=ac_mac, type=ETH_PPPOE_SESSION) / Raw(
        b"\x11\x00" + session.to_bytes(2, "big") + len(ppp).to_bytes(2, "big") + ppp
    )

    def _is_our_rej(p):
        if not p.haslayer(Ether) or p[Ether].type != ETH_PPPOE_SESSION:
            return False
        if p[Ether].src.lower() != driver.mac.lower():
            return False
        raw = bytes(p[Ether].payload)
        return (len(raw) >= 12 and raw[6:8] == b"\xc0\x21"
                and raw[8] == 4 and raw[9] == ident)

    sniffer.send([frame])
    rej = sniffer.wait_for(_is_our_rej, timeout=10)
    sniffer.stop()
    assert rej is not None, (
        f"no LCP Configure-Reject for our {len(lcp)}-byte Configure-Request "
        f"(id {ident:#x}); parms={driver.parms('pppoe0')}\n"
        f"{accel_server.log_tail(20)}"
    )
    raw = bytes(rej[Ether].payload)
    lcp_len = int.from_bytes(raw[10:12], "big")
    assert lcp_len == 4 + len(unknown) and raw[12:12 + len(unknown)] == unknown, (
        "Configure-Reject does not carry exactly the trailing unknown option: "
        f"len={lcp_len} data={raw[12:12 + max(lcp_len - 4, 0)].hex()}"
    )
