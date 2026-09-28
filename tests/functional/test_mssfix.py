"""In-kernel TCP MSS clamp (fix group p3-mss).

mpd5 enables `tcpmssfix` by default and OPNsense users expect it; the
in-kernel driver has to do the same or every PMTUD-blackholed path behind
the PPPoE link stalls on full-size segments.  The driver clamps the MSS
option of every TCP SYN / SYN-ACK crossing pppoeN, in both directions, to
the session MTU minus 40 (IPv4) or 60 (IPv6), and fixes the TCP checksum up
incrementally (RFC 1624).  Default on, per interface; off with
`pppoectl pppoeN nomssfix` (PPPOESETMSSFIX), advertised as
kern.features.if_pppoe_mssfix, and every clamp counts in
net.pppoe.mss_clamped.

How each direction is observed:

  TX  A raw-socket helper compiled on the client (`mssprobe syn4|syn6`)
      emits a SYN whose MSS option (9000) is larger than any PPPoE MTU --
      the shape of a LAN host's SYN forwarded through the router, which the
      client's own TCP stack never produces (it derives its MSS from the
      pppoe0 MTU already).  The frame is captured on br-isp as it leaves
      the client: MSS must read exactly mtu-40 (mtu-60 for IPv6) and scapy
      must find the TCP checksum valid.  The MSS option is placed both at
      an even and at an odd offset in the TCP header -- the odd one is the
      byte-swapped half of the RFC 1624 update, which only a checksum check
      on the wire can prove.
  RX  A SYN carrying MSS 9000 is injected into the LIVE session from the
      AC's MAC with the real session id (same technique as
      test_wire_safety.py), addressed to the client's pppoe0 address.  The
      client BPF tap on pppoe0 sits before the clamp, so the proof is
      indirect but strict: the counter moves, and the client's TCP stack
      ANSWERS (SYN-ACK or RST) -- tcp_input() drops a bad-checksum segment
      silently, and `netstat -s -p tcp`'s "discarded for bad checksums"
      must not move either.
  Real connections: nc/iperf3 to the AC's iperf3 server (10.99.0.1:5201);
      the client's SYN on the wire carries MSS <= mtu-40, both handshake
      segments have valid checksums, a server SYN-ACK above mtu-40 is
      counted by the RX clamp, and data flows.

pf on the client (lab/vm/router-mode.sh loads `scrub on pppoe0 max-mss
1452`) would clamp too and hide the driver, so every clamp test skips while
pf is enabled.

Driver-only (the `driver` fixture): needs the rebuilt if_pppoe.ko and, for
the keyword test, the rebuilt pppoectl from sbin/pppoectl installed as
/usr/local/sbin/pppoectl.
"""
from __future__ import annotations

import random
import re
import time

import pytest
from scapy.all import IP, TCP, Ether, IPv6, PPPoED, Raw

from lab import (
    ACCEL_GW,
    CLIENT_MAC,
    ETH_PPPOE_SESSION,
    PADS,
    PPPOE_STATE_SESSION,
    _ssh_stdin,
)

pytestmark = pytest.mark.datapath

PPP_IP, PPP_IPV6 = 0x0021, 0x0057
IPERF_PORT = 5201
BIG_MSS = 9000
PROBE = "/usr/local/sbin/mssprobe"
POCTL = "/usr/local/sbin/pppoectl"

# Test-only helper, compiled on the client VM like test_sppp_ioctl_live's
# spppioctl.  It includes no kernel header: the struct and ioctl numbers
# are reproduced from sys/net/if_pppoe.h (IFNAMSIZ 16 + u_int = 20 bytes;
# keep in sync).
_MSSPROBE_C = r"""
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct pppoemssfixparms {
	char	ifname[IFNAMSIZ];
	u_int	enable;
};
#define	PPPOESETMSSFIX	_IOW('i', 113, struct pppoemssfixparms)
#define	PPPOEGETMSSFIX	_IOWR('i', 114, struct pppoemssfixparms)

static void
usage(void)
{
	fprintf(stderr,
	    "usage: mssprobe get IFACE\n"
	    "       mssprobe set IFACE 0|1\n"
	    "       mssprobe syn4 SRC DST DPORT SPORT MSS even|odd\n"
	    "       mssprobe syn6 DST%%IFACE DPORT SPORT MSS even|odd\n");
	exit(2);
}

/* A 28-byte SYN: 20 header + 8 option bytes, MSS at an even or odd
 * offset (odd: one leading NOP). */
static int
build_syn(uint8_t *b, int sport, int dport, int mss, int odd)
{
	uint8_t *o = b + 20;

	memset(b, 0, 28);
	b[0] = sport >> 8; b[1] = sport & 0xff;
	b[2] = dport >> 8; b[3] = dport & 0xff;
	b[4] = 0x5a; b[5] = 0x17; b[6] = 0x00; b[7] = 0x01;	/* seq */
	b[12] = (28 / 4) << 4;
	b[13] = 0x02;						/* SYN */
	b[14] = 0xff; b[15] = 0xff;				/* window */
	if (odd) {
		o[0] = 1;
		o[1] = 2; o[2] = 4; o[3] = mss >> 8; o[4] = mss & 0xff;
		o[5] = 1; o[6] = 1; o[7] = 1;
	} else {
		o[0] = 2; o[1] = 4; o[2] = mss >> 8; o[3] = mss & 0xff;
		o[4] = 1; o[5] = 1; o[6] = 1; o[7] = 1;
	}
	return (28);
}

static uint32_t
sum16(uint32_t s, const uint8_t *p, int len)
{
	int i;

	for (i = 0; i + 1 < len; i += 2)
		s += (uint32_t)(p[i] << 8 | p[i + 1]);
	if (len & 1)
		s += (uint32_t)(p[len - 1] << 8);
	return (s);
}

static int
ifsock(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s < 0)
		err(1, "socket");
	return (s);
}

int
main(int argc, char **argv)
{
	struct pppoemssfixparms mp;
	uint8_t b[64];
	int s, len;

	if (argc < 3)
		usage();
	if (strcmp(argv[1], "get") == 0 && argc == 3) {
		memset(&mp, 0, sizeof(mp));
		strlcpy(mp.ifname, argv[2], sizeof(mp.ifname));
		if (ioctl(ifsock(), PPPOEGETMSSFIX, &mp) < 0)
			err(1, "PPPOEGETMSSFIX");
		printf("mssfix=%u\n", mp.enable);
		return (0);
	}
	if (strcmp(argv[1], "set") == 0 && argc == 4) {
		memset(&mp, 0, sizeof(mp));
		strlcpy(mp.ifname, argv[2], sizeof(mp.ifname));
		mp.enable = (u_int)strtoul(argv[3], NULL, 10);
		if (ioctl(ifsock(), PPPOESETMSSFIX, &mp) < 0)
			err(1, "PPPOESETMSSFIX");
		return (0);
	}
	if (strcmp(argv[1], "syn4") == 0 && argc == 8) {
		struct sockaddr_in src, dst;
		uint32_t cs;

		memset(&src, 0, sizeof(src));
		memset(&dst, 0, sizeof(dst));
		src.sin_len = dst.sin_len = sizeof(src);
		src.sin_family = dst.sin_family = AF_INET;
		if (inet_pton(AF_INET, argv[2], &src.sin_addr) != 1 ||
		    inet_pton(AF_INET, argv[3], &dst.sin_addr) != 1)
			usage();
		len = build_syn(b, atoi(argv[5]), atoi(argv[4]),
		    atoi(argv[6]), strcmp(argv[7], "odd") == 0);
		/* Full checksum: pseudo-header + segment, as a forwarded
		 * SYN from a LAN host would carry it. */
		cs = sum16(0, (uint8_t *)&src.sin_addr, 4);
		cs = sum16(cs, (uint8_t *)&dst.sin_addr, 4);
		cs += IPPROTO_TCP + len;
		cs = sum16(cs, b, len);
		cs = (cs & 0xffff) + (cs >> 16);
		cs = (cs & 0xffff) + (cs >> 16);
		cs = ~cs & 0xffff;
		b[16] = cs >> 8; b[17] = cs & 0xff;
		if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
			err(1, "raw socket");
		if (bind(s, (struct sockaddr *)&src, sizeof(src)) < 0)
			err(1, "bind");
		if (sendto(s, b, len, 0, (struct sockaddr *)&dst,
		    sizeof(dst)) != len)
			err(1, "sendto");
		printf("sent syn4 sport=%s mss=%s\n", argv[5], argv[6]);
		return (0);
	}
	if (strcmp(argv[1], "syn6") == 0 && argc == 7) {
		struct addrinfo hints, *ai;
		int off = 16, e;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if ((e = getaddrinfo(argv[2], NULL, &hints, &ai)) != 0)
			errx(1, "getaddrinfo %s: %s", argv[2], gai_strerror(e));
		len = build_syn(b, atoi(argv[4]), atoi(argv[3]),
		    atoi(argv[5]), strcmp(argv[6], "odd") == 0);
		if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0)
			err(1, "raw6 socket");
		/* The kernel fills the full checksum in (rip6_output). */
		if (setsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &off,
		    sizeof(off)) < 0)
			err(1, "IPV6_CHECKSUM");
		if (sendto(s, b, len, 0, ai->ai_addr, ai->ai_addrlen) != len)
			err(1, "sendto");
		printf("sent syn6 sport=%s mss=%s\n", argv[4], argv[5]);
		return (0);
	}
	usage();
	return (2);
}
"""


def _install_mssprobe(driver):
    r = _ssh_stdin(driver.port, "cat > /tmp/mssprobe.c", _MSSPROBE_C)
    assert r.returncode == 0, f"uploading mssprobe.c failed: {r.stderr}"
    r = driver.run(
        f"cc -O2 -Wall -Werror -o {PROBE} /tmp/mssprobe.c && rm -f /tmp/mssprobe.c",
        root=True,
    )
    assert r.returncode == 0, f"mssprobe compile failed: {r.stdout}\n{r.stderr}"


def _skip_if_pf_enabled(driver):
    r = driver.run("pfctl -si 2>/dev/null | grep -i '^Status:'", root=True)
    if "Enabled" in r.stdout:
        pytest.skip(
            "pf is enabled on the client (router-mode.sh scrubs max-mss on "
            "pppoe0), which would clamp too and mask the driver -- run "
            "`lab/vm/router-mode.sh disable` first"
        )


def _wait_inet(driver, timeout=30):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = driver.iface_state()
        if last["inet"] is not None:
            return last
        time.sleep(0.5)
    return last


def _session_up(driver, sniffer, service="lab"):
    """Create/bind/auth pppoe0 (driver.create), dial under capture, and wait
    for IPCP.  Returns (iface state, session id, AC MAC)."""
    driver.create(iface="pppoe0", parent="vtnet1", service=service)
    sniffer.start()
    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION, timeout=25)
    if st.get("state") != PPPOE_STATE_SESSION:
        # Dial-start race (see lab.IfPppoeDriver.create): re-drive once.
        driver.down("pppoe0")
        time.sleep(2)
        driver.up("pppoe0")
        st = driver.wait_state(PPPOE_STATE_SESSION, timeout=25)
    assert st.get("state") == PPPOE_STATE_SESSION, (
        f"no session: {st}\n{driver.run('dmesg | tail -20').stdout}"
    )
    state = _wait_inet(driver)
    assert state and state["inet"], f"IPCP never gave pppoe0 an address: {state}"
    session = st["session"]
    pads = [
        p for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADS
        and p[PPPoED].sessionid == session
    ]
    assert pads, f"no PADS for session {session} captured"
    return state, session, pads[-1][Ether].src.lower()


def _session_ip(sniffer, from_client: bool):
    """Every IPv4/IPv6 datagram carried in a captured PPPoE session frame,
    as a scapy IP/IPv6 packet, in one direction.  Parsed off the raw PPPoE
    bytes (plen-bounded, so Ethernet padding never leaks in)."""
    out = []
    for p in sniffer.packets:
        if not p.haslayer(Ether) or p[Ether].type != ETH_PPPOE_SESSION:
            continue
        if (p[Ether].src.lower() == CLIENT_MAC.lower()) != from_client:
            continue
        raw = bytes(p[Ether].payload)
        if len(raw) < 8:
            continue
        plen = int.from_bytes(raw[4:6], "big")
        ppp = raw[6:6 + plen]
        proto = int.from_bytes(ppp[:2], "big")
        if proto == PPP_IP:
            out.append(IP(ppp[2:]))
        elif proto == PPP_IPV6:
            out.append(IPv6(ppp[2:]))
    return out


def _mss(pkt):
    for kind, val in pkt[TCP].options:
        if kind == "MSS":
            return val
    return None


def _tcp_csum_ok(pkt) -> bool:
    """Recompute the TCP checksum with scapy and compare with the wire."""
    wire = pkt[TCP].chksum
    clone = pkt.copy()
    del clone[TCP].chksum
    return clone.__class__(bytes(clone))[TCP].chksum == wire


def _wait_syn(sniffer, from_client, sport=None, dport=None, synack=False,
              timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ip in _session_ip(sniffer, from_client):
            if not ip.haslayer(TCP):
                continue
            t = ip[TCP]
            flags = int(t.flags)
            if not flags & 0x02:
                continue
            if bool(flags & 0x10) != synack:
                continue
            if sport is not None and t.sport != sport:
                continue
            if dport is not None and t.dport != dport:
                continue
            return ip
        time.sleep(0.2)
    return None


def _sport():
    return random.randint(20000, 60000)


def _bad_cksum_count(driver) -> int:
    r = driver.run("netstat -s -p tcp")
    m = re.search(r"(\d+) discarded for bad checksums", r.stdout)
    return int(m.group(1)) if m else 0


# ---------------------------------------------------------------- control


def test_mssfix_feature_counter_and_default_on(driver):
    """kern.features.if_pppoe_mssfix advertises the clamp (the plugin gates
    eligibility on it, docs/plugin/risk-register.md C9), the counter exists,
    and a fresh clone clamps by default (mpd5 parity)."""
    _install_mssprobe(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    assert driver.sysctl("kern.features.if_pppoe_mssfix") == "1"
    assert driver.counter("mss_clamped") >= 0
    r = driver.run(f"{PROBE} get pppoe0")
    assert r.returncode == 0, f"PPPOEGETMSSFIX failed: {r.stdout}\n{r.stderr}"
    assert r.stdout.strip() == "mssfix=1", r.stdout


def test_mssfix_ioctl_toggle_is_root_only(driver):
    _install_mssprobe(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    r = driver.run(f"{PROBE} set pppoe0 0")  # not root
    assert r.returncode != 0, "an unprivileged PPPOESETMSSFIX succeeded"
    assert driver.run(f"{PROBE} get pppoe0").stdout.strip() == "mssfix=1"

    assert driver.run(f"{PROBE} set pppoe0 0", root=True).returncode == 0
    assert driver.run(f"{PROBE} get pppoe0").stdout.strip() == "mssfix=0"
    assert driver.run(f"{PROBE} set pppoe0 1", root=True).returncode == 0
    assert driver.run(f"{PROBE} get pppoe0").stdout.strip() == "mssfix=1"
    # Anything non-zero is "on"; a value > 1 is refused rather than
    # silently reinterpreted, so a future bitmask can reuse the field.
    r = driver.run(f"{PROBE} set pppoe0 7", root=True)
    assert r.returncode != 0 and "Invalid argument" in r.stderr, r.stderr


def test_pppoectl_mssfix_keywords(driver):
    """`pppoectl pppoe0 nomssfix|mssfix` drives PPPOESETMSSFIX and the list
    mode reports the setting."""
    _install_mssprobe(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    r = driver.run(f"{POCTL} pppoe0 nomssfix", root=True)
    assert r.returncode == 0, f"pppoectl nomssfix: {r.stdout}\n{r.stderr}"
    assert driver.run(f"{PROBE} get pppoe0").stdout.strip() == "mssfix=0"
    assert "mssfix: disable" in driver.run(f"{POCTL} pppoe0", root=True).stdout
    r = driver.run(f"{POCTL} pppoe0 mssfix", root=True)
    assert r.returncode == 0, f"pppoectl mssfix: {r.stdout}\n{r.stderr}"
    assert driver.run(f"{PROBE} get pppoe0").stdout.strip() == "mssfix=1"
    assert "mssfix: enable" in driver.run(f"{POCTL} pppoe0", root=True).stdout


# --------------------------------------------------------------------- TX


def _send_syn4(driver, state, sport, mss, layout):
    cmd = (f"{PROBE} syn4 {state['inet']} {state['inet_peer']} "
           f"{IPERF_PORT} {sport} {mss} {layout}")
    r = driver.run(cmd, root=True)
    assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"


@pytest.mark.parametrize("layout", ["even", "odd"])
def test_tx_syn_mss_clamped_to_mtu_minus_40(driver, sniffer, layout):
    _install_mssprobe(driver)
    _skip_if_pf_enabled(driver)
    state, _, _ = _session_up(driver, sniffer)
    mtu = state["mtu"]
    before = driver.counter("mss_clamped")
    sport = _sport()
    _send_syn4(driver, state, sport, BIG_MSS, layout)
    syn = _wait_syn(sniffer, from_client=True, sport=sport, dport=IPERF_PORT)
    assert syn is not None, "the probe SYN never reached the wire"
    assert _mss(syn) == mtu - 40, (
        f"MSS on the wire {_mss(syn)} != mtu {mtu} - 40 ({layout} offset)"
    )
    assert _tcp_csum_ok(syn), (
        f"TCP checksum broken by the clamp ({layout} offset): "
        f"{syn[TCP].chksum:#06x}"
    )
    assert driver.counter("mss_clamped") - before >= 1


def test_tx_syn_smaller_mss_left_alone(driver, sniffer):
    _install_mssprobe(driver)
    _skip_if_pf_enabled(driver)
    state, _, _ = _session_up(driver, sniffer)
    sport = _sport()
    _send_syn4(driver, state, sport, 536, "even")
    syn = _wait_syn(sniffer, from_client=True, sport=sport, dport=IPERF_PORT)
    assert syn is not None, "the probe SYN never reached the wire"
    assert _mss(syn) == 536
    assert _tcp_csum_ok(syn)


def test_tx_nomssfix_passes_mss_through(driver, sniffer):
    _install_mssprobe(driver)
    _skip_if_pf_enabled(driver)
    state, _, _ = _session_up(driver, sniffer)
    assert driver.run(f"{PROBE} set pppoe0 0", root=True).returncode == 0
    before = driver.counter("mss_clamped")
    sport = _sport()
    _send_syn4(driver, state, sport, BIG_MSS, "even")
    syn = _wait_syn(sniffer, from_client=True, sport=sport, dport=IPERF_PORT)
    assert syn is not None, "the probe SYN never reached the wire"
    assert _mss(syn) == BIG_MSS, "MSS clamped although nomssfix is set"
    assert _tcp_csum_ok(syn)
    assert driver.counter("mss_clamped") == before


# --------------------------------------------------------------------- RX


def _inject_syn(sniffer, ac_mac, session, state, sport, dport, mss):
    ip = (IP(src=state["inet_peer"], dst=state["inet"], ttl=64)
          / TCP(sport=sport, dport=dport, flags="S", seq=0x10203040,
                window=65535, options=[("MSS", mss), ("NOP", None),
                                       ("NOP", None), ("SAckOK", b"")]))
    ppp = PPP_IP.to_bytes(2, "big") + bytes(ip)
    pppoe = (b"\x11\x00" + session.to_bytes(2, "big")
             + len(ppp).to_bytes(2, "big") + ppp)
    sniffer.send([Ether(dst=CLIENT_MAC, src=ac_mac, type=ETH_PPPOE_SESSION)
                  / Raw(pppoe)])


def _client_answered(sniffer, sport, dport, timeout=8):
    """The client's TCP reply (SYN-ACK or RST) to our injected SYN."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ip in _session_ip(sniffer, from_client=True):
            if (ip.haslayer(TCP) and ip[TCP].dport == sport
                    and ip[TCP].sport == dport):
                return ip
        time.sleep(0.2)
    return None


@pytest.mark.parametrize("enabled", [True, False], ids=["mssfix", "nomssfix"])
def test_rx_syn_clamped_and_still_accepted(driver, sniffer, enabled):
    """An inbound SYN with MSS 9000 is clamped (counter) and the clamped
    segment still passes tcp_input()'s checksum check: the client answers
    it and no bad-checksum discard is counted.  nomssfix is the control."""
    _install_mssprobe(driver)
    _skip_if_pf_enabled(driver)
    state, session, ac_mac = _session_up(driver, sniffer)
    if not enabled:
        assert driver.run(f"{PROBE} set pppoe0 0", root=True).returncode == 0
    before = driver.counter("mss_clamped")
    bad_before = _bad_cksum_count(driver)
    # sshd on the client answers SYN-ACK (a closed port would do with a
    # RST, unless net.inet.tcp.blackhole is set -- hence sshd).
    sport, dport = _sport(), 22
    _inject_syn(sniffer, ac_mac, session, state, sport, dport, BIG_MSS)
    reply = _client_answered(sniffer, sport, dport)
    assert reply is not None, (
        "the client never answered the injected SYN -- a clamp that broke "
        "the TCP checksum is dropped silently by tcp_input()"
    )
    assert _bad_cksum_count(driver) == bad_before
    delta = driver.counter("mss_clamped") - before
    if enabled:
        assert delta >= 1, "inbound SYN not clamped"
    else:
        assert delta == 0, "inbound SYN clamped although nomssfix is set"


# ------------------------------------------------------ real connections


def test_real_tcp_connection_syn_and_synack_within_mtu(driver, sniffer):
    """A real connection to the AC's iperf3 server.  The client's SYN
    leaves with MSS <= mtu-40; the server's SYN-ACK is captured BEFORE the
    RX clamp (on br-isp), so its MSS is the server's choice -- if that is
    above mtu-40 the RX clamp must have counted it.  Both checksums are
    valid on the wire and data flows across the clamped session."""
    _skip_if_pf_enabled(driver)
    state, _, _ = _session_up(driver, sniffer)
    mtu = state["mtu"]
    before = driver.counter("mss_clamped")
    r = driver.run(f"iperf3 -c {ACCEL_GW} -t 2 -J >/dev/null", timeout=30)
    assert r.returncode == 0, f"iperf3 through pppoe0 failed: {r.stdout}\n{r.stderr}"
    syn = _wait_syn(sniffer, from_client=True, dport=IPERF_PORT)
    synack = _wait_syn(sniffer, from_client=False, sport=IPERF_PORT, synack=True)
    assert syn is not None and synack is not None, "handshake not captured"
    assert _mss(syn) is not None and _mss(syn) <= mtu - 40, (
        f"client SYN MSS {_mss(syn)} > mtu {mtu} - 40"
    )
    for what, p in (("SYN", syn), ("SYN-ACK", synack)):
        assert _tcp_csum_ok(p), f"{what} checksum invalid on the wire"
    if _mss(synack) is not None and _mss(synack) > mtu - 40:
        assert driver.counter("mss_clamped") > before, (
            f"server SYN-ACK MSS {_mss(synack)} > mtu {mtu} - 40 was not "
            "clamped on receive"
        )


# ------------------------------------------------------------------- IPv6


def _mpdsrv_tun_ll():
    from test_ipv6cp import _mpdsrv_tun_ll as ll
    return ll()


@pytest.mark.needs_mpdsrv
@pytest.mark.parametrize("layout", ["even", "odd"])
def test_tx_ipv6_syn_mss_clamped_to_mtu_minus_60(driver, sniffer, layout):
    """IPv6 variant against the mpdsrv VM (the only lab peer whose IPv6CP
    opens, see test_ipv6cp.py): a raw IPv6 SYN to the peer's link-local
    leaves with MSS = mtu - 60 and a valid checksum."""
    _install_mssprobe(driver)
    _skip_if_pf_enabled(driver)
    r = driver.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    assert r.returncode == 0
    state, _, _ = _session_up(driver, sniffer, service="mpdlab")
    deadline = time.time() + 45
    while time.time() < deadline:
        state = driver.iface_state()
        if state["inet6_ll"] and "tentative" not in state["raw"]:
            break
        time.sleep(1)
    if not state["inet6_ll"]:
        pytest.skip("IPv6CP did not open against mpdsrv; no link-local on pppoe0")
    peer = _mpdsrv_tun_ll()
    assert peer, "could not discover the mpdsrv tunnel link-local"
    mtu = state["mtu"]
    before = driver.counter("mss_clamped")
    sport = _sport()
    cmd = f"{PROBE} syn6 {peer}%pppoe0 {IPERF_PORT} {sport} {BIG_MSS} {layout}"
    # sendto can hit EADDRNOTAVAIL briefly after "tentative" clears (the race
    # test_ipv6cp.py retries ping6 around); that send never reaches the driver.
    deadline = time.time() + 30
    while True:
        r = driver.run(cmd, root=True)
        if r.returncode == 0:
            break
        if ("Can't assign requested address" not in r.stdout + r.stderr
                or time.time() >= deadline):
            break
        time.sleep(1)
    assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"
    syn = _wait_syn(sniffer, from_client=True, sport=sport, dport=IPERF_PORT)
    assert syn is not None and syn.haslayer(IPv6), "IPv6 probe SYN not on the wire"
    assert _mss(syn) == mtu - 60, f"IPv6 MSS {_mss(syn)} != mtu {mtu} - 60"
    assert _tcp_csum_ok(syn), f"IPv6 TCP checksum broken ({layout} offset)"
    assert driver.counter("mss_clamped") - before >= 1
