"""IPv6 payload RX delivery over the in-kernel PPPoE session (p3-ipv6rx).

Before this group, pppoe_data_input() poked the keepalive timestamp and
DROPPED every received PPP_IPV6 (0x0057) frame, even with IPv6CP Opened: the
client could send IPv6 but never receive a single datagram, so ping6, RA and
DHCPv6 were all dead on arrival.  The fix routes PPP_IPV6 through
sppp_input()'s IPv6CP-gated arm, which hands the datagram to ip6_input() with
rcvif = pppoe0.

Which peer
----------
accel-ppp (service "lab") never lets IPv6CP reach Opened
(test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only), so every IPv6 payload
case here dials the mpdsrv VM's mpd5 server (service "mpdlab",
needs_mpdsrv), against which IPv6CP negotiates and the driver's addr task
installs the negotiated fe80:: on pppoe0.

Two kinds of evidence, deliberately
-----------------------------------
* scapy-injected frames: an ICMPv6 Echo Request (and a Router Advertisement)
  built here, wrapped in a PPPoE session frame carrying the LIVE session id
  and the AC's MAC (both read off the PADS this test's own dial produced), so
  it passes the driver's (parent, session, peer MAC) lookup.  The source is a
  made-up link-local (INJECT_SRC) that can never be one of the client's own
  addresses, so an Echo Reply on the wire addressed to it can only have come
  from the client's ip6_input() -> icmp6 -> sppp_output() path: no loopback
  shortcut, whatever the two lab VMs' MACs are.
* real ping6 in both directions between the client and the mpdsrv tunnel
  link-local (the fe80:: on the session's ngN, read live: mpd5 cannot pin
  its IPv6CP interface identifier), with the wire capture proving the
  replies crossed the link.  The tunnel is
  found by lab.mpdsrv_tunnel(), which only accepts the ngN whose p2p peer is
  the client's session address: the old first-fe80::-in-`ifconfig -a` scrape
  (test_ipv6cp.py before this group) resolved to mpdsrv's vtnet link-local,
  so its ping6 "passed" at base 3708dfc -- when every PPP_IPV6 frame was
  still dropped -- only because the client answered that address itself.

ping6 runs at the default 1 s interval: FreeBSD ping6 refuses a sub-second
-i for non-root users (I haven't verified this against the 14.3 source;
test_soak.py runs its `ping -i 0.5` with root=True) and
both ends are reached over ssh as the unprivileged `freebsd` user.

The netisr spreading case needs no IPv6CP (cpu_hits counts before the sppp
gate) and runs against accel-ppp through the `driver` fixture, mirroring
test_datapath.py::test_decapsulated_frames_spread_across_cpus for PPP_IPV6.

DHCPv6: a DHCPv6 server's Advertise/Reply is UDP unicast to the client's
link-local (port 546), i.e. exactly the unicast-to-link-local RX path the
injected Echo Request proves; there is no DHCPv6 server in the lab to run a
full exchange against, so no separate DHCPv6 case exists.

Driver-only: CLIENT=if_pppoe.
"""
from __future__ import annotations

import ipaddress
import os
import re
import time

import pytest
from scapy.all import (
    UDP,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    IPv6,
    PPPoED,
    Raw,
)

from lab import (
    ETH_PPPOE_SESSION,
    MPDSRV_SSH_PORT,
    PADO,
    PADS,
    PPPOE_STATE_SESSION,
    _ssh,
    mpdsrv_tunnel,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("CLIENT", "mpd5") != "if_pppoe",
    reason="driver-specific: exercises the in-kernel PPP_IPV6 RX path "
    "(CLIENT=if_pppoe)",
)

PPP_IPV6 = 0x0057

# A link-local no lab host owns: its IID has the U/L bit clear and no ff:fe
# in the middle, so it is not the EUI-64 of any lab MAC (52:54:00:...), and
# it is never the client's own address.
INJECT_SRC = "fe80::6b:6b00:5eed:1"
ECHO_ID = 0x6B6B
# RFC 3849 documentation prefix; unique enough that a hit in `ndp -p` can only
# have come from the RA injected here.
RA_PREFIX = "2001:db8:6a:1::"


def _session_tunnel(client_ip: str, ll: str) -> tuple[str, str]:
    """(ngN, link-local) of the mpd5 server's tunnel for THIS session.

    Read off the ngN whose p2p peer is this session's address (mpd5 cannot
    pin its IPv6CP interface identifier, so there is no fixed value to
    expect).  It must differ from the client's own link-local, or a ping6
    would be answered locally and prove nothing."""
    ifname, peer = mpdsrv_tunnel(client_ip)
    assert ifname and peer, (
        f"no ngN on mpdsrv with p2p peer {client_ip} carrying an fe80::"
    )
    assert not _same(peer, ll), f"client and server share link-local {ll}"
    return ifname, peer


def _same(a: str, b: str) -> bool:
    """IPv6 address equality regardless of textual form."""
    return ipaddress.IPv6Address(a) == ipaddress.IPv6Address(b)


def _pppoe0_link_locals(client) -> list[tuple[str, str]]:
    """Every fe80:: on pppoe0 as (address, rest-of-line flags)."""
    out = client.run("ifconfig pppoe0").stdout
    return re.findall(r"inet6 (fe80::[0-9a-f:]+)%pppoe0 ([^\n]*)", out)


def _session_frame(dst_mac: str, src_mac: str, session: int, proto: int,
                   body: bytes):
    ppp = proto.to_bytes(2, "big") + body
    pppoe = (b"\x11\x00" + session.to_bytes(2, "big")
             + len(ppp).to_bytes(2, "big") + ppp)
    return Ether(dst=dst_mac, src=src_mac, type=ETH_PPPOE_SESSION) / Raw(pppoe)


def _ipv6_sent_by(sniffer, mac: str, session: int) -> list:
    """Every PPP_IPV6 datagram `mac` sent on `session`, parsed as scapy IPv6
    off the raw plen-bounded PPPoE payload (Ethernet padding never leaks)."""
    out = []
    for p in sniffer.packets:
        if not p.haslayer(Ether) or p[Ether].type != ETH_PPPOE_SESSION:
            continue
        if p[Ether].src.lower() != mac.lower():
            continue
        raw = bytes(p[Ether].payload)
        if len(raw) < 8 or int.from_bytes(raw[2:4], "big") != session:
            continue
        plen = int.from_bytes(raw[4:6], "big")
        ppp = raw[6:6 + plen]
        if len(ppp) < 2 + 40 or int.from_bytes(ppp[:2], "big") != PPP_IPV6:
            continue
        out.append(IPv6(ppp[2:]))
    return out


def _wait_ipv6(sniffer, mac, session, pred, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        hits = [p for p in _ipv6_sent_by(sniffer, mac, session) if pred(p)]
        if hits:
            return hits
        time.sleep(0.2)
    return []


def _mpdlab_ipv6_session(client, sniffer, wait_iface_up):
    """Dial the mpdsrv VM under capture and wait for IPv6CP to install a
    usable (non-tentative) fe80:: on pppoe0.

    Returns (session id, AC MAC, client link-local, client IPv4).  The sniffer is left
    running for the caller's own assertions.
    """
    # p2p DAD can never complete over PPPoE (no NA source); the standard
    # PPP-host sysctl, as test_ipv6cp.py sets it.
    r = client.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    assert r.returncode == 0, f"dad_count=0 failed: {r.stdout}\n{r.stderr}"

    sniffer.start()
    client.dial(service="mpdlab")
    state = wait_iface_up(client, timeout=30)
    assert state["up"] and state["inet"] and state["inet"].startswith("10.99.2."), (
        f"session did not come up from the mpdlab pool: {state}"
    )
    session = client.parms()["session"]
    assert session, f"no live PPPoE session id: {client.parms()}"
    pads = [
        p for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADS
        and p[PPPoED].sessionid == session
    ]
    assert pads, f"no PADS for live session {session} captured: AC MAC unknown"
    ac_mac = pads[-1][Ether].src.lower()
    assert ac_mac != client.mac.lower()

    deadline = time.time() + 45
    lls: list = []
    while time.time() < deadline:
        lls = _pppoe0_link_locals(client)
        if lls and all("tentative" not in flags for _, flags in lls):
            break
        time.sleep(1)
    assert lls, "IPv6CP never installed a link-local on pppoe0"
    assert all("tentative" not in f and "duplicated" not in f for _, f in lls), (
        f"pppoe0 link-local unusable: {lls}"
    )
    return session, ac_mac, lls[0][0], state["inet"]


def test_kern_feature_if_pppoe_ipv6_advertised(client):
    """FEATURE(if_pppoe_ipv6): the plugin gates IPv6 eligibility on
    kern.features.if_pppoe_ipv6 (docs/plugin/risk-register.md C9); a .ko
    without IPv6 RX must not advertise it, one with it must."""
    r = client.run("kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko", root=True)
    assert r.returncode == 0, f"if_pppoe not loadable: {r.stdout}\n{r.stderr}"
    r = client.run("sysctl -n kern.features.if_pppoe_ipv6")
    assert r.returncode == 0 and r.stdout.strip() == "1", (
        f"kern.features.if_pppoe_ipv6 missing or not 1: rc={r.returncode} "
        f"out={r.stdout!r} err={r.stderr!r}"
    )


@pytest.mark.needs_mpdsrv
def test_pppoe0_carries_exactly_the_ipv6cp_link_local(client, sniffer, wait_iface_up):
    """IPv6CP owns pppoe0's link-local: exactly one fe80:: after the session
    is up, not an extra random-IID one from in6_ifattach()'s auto-link-local
    (pppoe0 is IFT_PPP with no MAC, so in6_get_ifid() would fall back to a
    random IID on the first IFF_UP).  Two link-locals make source selection
    for link-local peers (RS, DHCPv6 Solicit) pick either, and the peer's
    replies to the wrong one outlive the session."""
    _session, _ac_mac, _ll, _ip = _mpdlab_ipv6_session(client, sniffer, wait_iface_up)
    sniffer.stop()
    lls = _pppoe0_link_locals(client)
    assert len(lls) == 1, f"pppoe0 carries {len(lls)} link-locals, want 1: {lls}"


@pytest.mark.needs_mpdsrv
def test_injected_icmpv6_echo_to_link_local_is_answered(client, sniffer, wait_iface_up):
    """The core RX proof.  An ICMPv6 Echo Request from INJECT_SRC to the
    client's IPv6CP link-local, injected as the AC on the live session, must
    reach ip6_input() with rcvif = pppoe0 (the link-local destination only
    matches with pppoe0's scope) and draw an Echo Reply back over the
    session (sppp_output AF_INET6 -> pppoe_transmit).  The pre-fix driver
    drops the request in pppoe_data_input(), so no reply ever appears."""
    session, ac_mac, ll, _ip = _mpdlab_ipv6_session(client, sniffer, wait_iface_up)
    # pppoe_session_task() publishes asynchronously; the session is long
    # since published once IPv6CP has opened, but keep the margin cheap.
    time.sleep(1)

    frames = [
        _session_frame(
            client.mac, ac_mac, session, PPP_IPV6,
            bytes(IPv6(src=INJECT_SRC, dst=ll, hlim=64)
                  / ICMPv6EchoRequest(id=ECHO_ID, seq=seq, data=b"ipv6rx" * 8)))
        for seq in (1, 2, 3)
    ]
    sniffer.send(frames)

    def is_reply(p):
        return (p.haslayer(ICMPv6EchoReply)
                and p[ICMPv6EchoReply].id == ECHO_ID
                and _same(p[IPv6].dst, INJECT_SRC))

    replies = _wait_ipv6(sniffer, client.mac, session, is_reply, timeout=10)
    sniffer.stop()
    assert replies, (
        f"no ICMPv6 Echo Reply to {INJECT_SRC} from the client after 3 "
        f"injected requests to {ll}: PPP_IPV6 is not being delivered to "
        "ip6_input() (or the reply is not getting out through sppp_output)"
    )
    seqs = {p[ICMPv6EchoReply].seq for p in replies}
    assert seqs <= {1, 2, 3} and len(seqs) >= 2, f"reply seqs {seqs}"
    assert all(_same(p[IPv6].src, ll) for p in replies), (
        f"replies not sourced from the IPv6CP link-local {ll}: "
        f"{[p[IPv6].src for p in replies]}"
    )


@pytest.mark.needs_mpdsrv
def test_ipv6_ping_client_to_ac(client, sniffer, wait_iface_up):
    """ping6 from the client to the mpd5 server's tunnel link-local: the
    requests go out through sppp_output, the server's replies must come back
    in through the PPP_IPV6 RX path.  The peer link-local must differ from
    the client's own, or the client would answer itself locally and the
    ping would prove nothing."""
    session, ac_mac, ll, ip = _mpdlab_ipv6_session(client, sniffer, wait_iface_up)
    _ifname, peer = _session_tunnel(ip, ll)

    r = client.run(f"ping6 -c 3 {peer}%pppoe0", timeout=25)
    out = r.stdout + r.stderr
    replies = _wait_ipv6(
        sniffer, ac_mac, session,
        lambda p: p.haslayer(ICMPv6EchoReply) and _same(p[IPv6].dst, ll),
        timeout=5)
    sniffer.stop()
    assert replies, (
        f"the server never put an ICMPv6 Echo Reply to {ll} on the wire:\n{out}"
    )
    m = re.search(r"(\d+) packets received", out)
    assert m and int(m.group(1)) >= 2, (
        f"ping6 {peer}%pppoe0: the server's replies were on the wire but the "
        f"client did not receive them:\n{out}"
    )


@pytest.mark.needs_mpdsrv
def test_ipv6_ping_ac_to_client(client, sniffer, wait_iface_up):
    """The reverse direction: the mpd5 server pings the client's IPv6CP
    link-local over its tunnel interface.  Needs RX (the request) and TX
    (the reply) on the client; the capture proves the client's replies left
    through the session."""
    session, _ac_mac, ll, ip = _mpdlab_ipv6_session(client, sniffer, wait_iface_up)
    ifname, _peer = _session_tunnel(ip, ll)

    r = _ssh(MPDSRV_SSH_PORT, f"ping6 -c 3 {ll}%{ifname}", timeout=25)
    out = r.stdout + r.stderr
    replies = _wait_ipv6(
        sniffer, client.mac, session,
        lambda p: p.haslayer(ICMPv6EchoReply) and _same(p[IPv6].src, ll),
        timeout=5)
    sniffer.stop()
    assert replies, (
        f"the client never sent an ICMPv6 Echo Reply from {ll}: the server's "
        f"requests were not delivered to ip6_input():\n{out}"
    )
    m = re.search(r"(\d+) packets received", out)
    assert m and int(m.group(1)) >= 2, f"ping6 from mpdsrv failed:\n{out}"


@pytest.mark.needs_mpdsrv
def test_router_advertisement_to_all_nodes_is_processed(client, sniffer, wait_iface_up):
    """An RA to ff02::1 (all-nodes multicast, the group in6_update_ifa()
    joins with the link-local -- which needs IFF_MULTICAST and a no-op
    SIOCADDMULTI on pppoe0) must reach nd6_ra_input(): its Prefix
    Information option shows up in `ndp -p` on pppoe0.  Router lifetime 0
    and A=0 so the RA installs neither a default router nor a SLAAC address
    in the client VM; the prefix goes with the clone on the next dial."""
    session, ac_mac, _ll, _ip = _mpdlab_ipv6_session(client, sniffer, wait_iface_up)
    fwd = client.run("sysctl -n net.inet6.ip6.forwarding").stdout.strip() or "0"
    try:
        r = client.run(
            "sysctl net.inet6.ip6.forwarding=0 && "
            "ifconfig pppoe0 inet6 accept_rtadv", root=True)
        assert r.returncode == 0, f"accept_rtadv setup failed: {r.stdout}\n{r.stderr}"

        ra = (IPv6(src=INJECT_SRC, dst="ff02::1", hlim=255)
              / ICMPv6ND_RA(routerlifetime=0)
              / ICMPv6NDOptPrefixInfo(prefix=RA_PREFIX, prefixlen=64, L=1, A=0,
                                      validlifetime=300, preferredlifetime=120))
        sniffer.send([_session_frame(client.mac, ac_mac, session, PPP_IPV6,
                                     bytes(ra))])
        deadline = time.time() + 10
        out = ""
        while time.time() < deadline:
            out = client.run("ndp -p").stdout
            if re.search(rf"{re.escape(RA_PREFIX)}/64 if=pppoe0", out):
                break
            time.sleep(0.5)
        sniffer.stop()
        assert re.search(rf"{re.escape(RA_PREFIX)}/64 if=pppoe0", out), (
            f"injected RA's prefix {RA_PREFIX}/64 never appeared on pppoe0: "
            f"the ff02::1 datagram was not delivered to nd6_ra_input():\n{out}"
        )
    finally:
        client.run("ifconfig pppoe0 inet6 -accept_rtadv", root=True)
        client.run(f"sysctl net.inet6.ip6.forwarding={fwd}", root=True)


@pytest.mark.datapath
def test_ipv6_frames_spread_across_cpus(driver, sniffer):
    """PPP_IPV6 frames are hashed on the inner IPv6 flow like IPv4
    (pppoe_hash_inner()'s PPP_IPV6 arm, RSS kernels): 2000 UDP/IPv6 frames
    over 200 (src, sport) flows on one session must land on >= 2 netisr
    workstreams with no CPU taking > 80%.  cpu_hits is counted before the
    sppp IPv6CP gate, so the accel session (IPv6CP never opens) is enough;
    the datagrams themselves are dropped there, by design."""
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]
    pados = [p for p in sniffer.packets
             if p.haslayer(PPPoED) and p[PPPoED].code == PADO]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    ac_mac = pados[0][Ether].src

    assert int(driver.sysctl("net.isr.numthreads")) >= 2, (
        "net.isr.numthreads < 2: one netisr workstream, nothing can spread "
        "(net.isr.maxthreads=4, net.isr.bindthreads=1 in loader.conf)"
    )
    time.sleep(2)

    frames = [
        _session_frame(
            driver.mac, ac_mac, session, PPP_IPV6,
            bytes(IPv6(src=f"2001:db8:6a:2::{(i % 200) + 1:x}", dst="2001:db8:6a:3::1")
                  / UDP(sport=1024 + (i % 200), dport=9) / Raw(b"z" * 64)))
        for i in range(2000)
    ]

    def hits():
        raw = driver.sysctl("net.pppoe.cpu_hits")
        return {k: int(v) for k, v in (t.split("=") for t in raw.split())}

    before = hits()
    sniffer.send(frames)
    time.sleep(3)
    after = hits()
    delta = {k: after[k] - before.get(k, 0) for k in after}
    total = sum(delta.values())
    busy = [k for k, v in delta.items() if v > 0]
    assert total >= 1500, f"only {total}/2000 reached the netisr handler: {delta}"
    assert len(busy) >= 2, f"IPv6 frames did not spread across CPUs: {delta}"
    assert max(delta.values()) <= 0.8 * total, (
        f"one CPU took > 80% of 200 IPv6 flows: {delta}"
    )
