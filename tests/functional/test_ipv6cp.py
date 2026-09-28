"""IPv6CP: interface-id negotiation and a link-local address on pppoe0.

Two servers, two behaviours, both asserted as passing tests (no xfails
remain in the M002 suite):

- **mpdsrv (mpd5 VM)**: IPv6CP negotiates to Opened and the negotiated
  fe80:: link-local is applied in-kernel on pppoe0 -- live-proven in S04
  and asserted here through both the `client` seam and the `driver`
  surface.
- **accel-ppp (isp VM, service "lab")**: IPv6CP never opens against it.  The
  pinned server-side limitation has held across two accel generations, but
  the observable shape changed on 2026-09-23 when the legacy lab-host
  isp-netns accel (kernel PPP without IPv6, which silently ignored IPv6CP
  and logged `warn: ppp: kernel doesn't support ipv6`) was replaced by the
  dedicated Debian isp VM running accel-ppp 1.14.0 (lab/vm/provision-isp.sh).
  That build **initiates** IPv6CP -- it sends its own Configure-Request
  (observed Interface-Id 01:00:00:00:00:00:00:00) as soon as the client's
  ConfReq arrives -- but it never ACKs the client's ConfReq: every client
  request is ConfNak'ed with a 02:00:00:00:00:00:00:00 proposal, so IPv6CP
  never reaches Opened and the client keeps its seeded-ifid link-local.  The
  pinned exception is therefore asserted **direction-aware** by
  test_ipv6cp_accel_stays_offer_only (server-sent frames only): the client
  offers (its ConfReq is on the wire) and the server never sends
  Configure-Ack.  A direction-blind codeset assertion here would false-fail
  on the client's own (mandatory, RFC 5072) ConfAck of accel's ConfReq.
  If a future accel-ppp ACKs the client's IPv6CP, this test fails loudly and
  the mpdsrv/accel distinction in this module's docstring needs revisiting.
"""
from __future__ import annotations

import ipaddress
import time

import pytest
from scapy.all import Ether, PPP

from lab import CLIENT_MAC, PPPOE_STATE_SESSION, mpdsrv_tunnel, spppauth_cmd

IPV6CP_PROTO = 0x8057


def _mpdsrv_tun_ll(client_ip: str | None = None):
    """The mpd5 server's tunnel link-local for the current session (fe80::...).

    Delegates to lab.mpdsrv_tunnel(), which only accepts the ngN whose p2p
    peer is `client_ip`.  The previous scrape here took the first fe80::/64
    in `ifconfig -a`, i.e. mpdsrv's vtnet link-local, so the ping6 below
    "passed" at 3708dfc -- when pppoe_data_input() still dropped every
    PPP_IPV6 frame -- only because the client answered that address itself
    (a local false pass).  mpd5 cannot pin its IPv6CP interface
    identifier, so the value is read live, never compared to a constant.
    """
    return mpdsrv_tunnel(client_ip)[1]


@pytest.mark.needs_mpdsrv
def test_ipv6cp_negotiated_and_link_local(client, sniffer, wait_iface_up):
    """IPv6CP negotiated to Opened with a link-local on pppoe0 -- against the
    mpdsrv VM (needs_mpdsrv): accel-ppp's kernel driver refuses IPv6
    outright (see test_ipv6cp_accel_stays_offer_only), so the negotiated
    link-local can only ever be proven against mpd5, where IPv6CP is
    enabled and was live-proven in S04.  This is the formerly-xfailed test
    flipped for M002 S05 T4: it now dials the mpdsrv service through the
    same `client` seam every other suite test uses.
    """
    # p2p DAD can never complete over the PPPoE link (no MAC, no NA
    # source); this is the standard PPP-host sysctl (an mpd5 client needs
    # the same) -- the driver's addr task applies the negotiated fe80::
    # without waiting for DAD.
    r = client.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    assert r.returncode == 0, f"dad_count=0 failed: {r.stdout}\n{r.stderr}"

    def _ipv6cp_opened(p) -> bool:
        if not (p.haslayer(PPP) and p[PPP].proto == IPV6CP_PROTO):
            return False
        return bytes(p[PPP].payload)[0] == 2  # Configure-Ack

    sniffer.start()
    client.dial(service="mpdlab")
    state = wait_iface_up(client, timeout=20)
    # Wait for the actual event (IPv6CP reaching Configure-Ack) instead of a
    # blind sleep(3); 20s is more generous than the old fixed window and
    # returns as soon as Opened is observed. A miss here just means the
    # assertions below fail with their own clear message.
    sniffer.wait_for(_ipv6cp_opened, timeout=20)
    sniffer.stop()

    # The session must be with the mpdsrv VM (mpdlab pool 10.99.2.x).
    assert state["inet"] and state["inet"].startswith("10.99.2."), (
        f"session did not come up from the mpdlab pool: {state}"
    )

    ipv6cp_frames = [p for p in sniffer.packets if p.haslayer(PPP) and p[PPP].proto == IPV6CP_PROTO]
    assert ipv6cp_frames, "client never sent an IPv6CP frame at all"
    # code 2 == Configure-Ack: IPv6CP actually reached Opened.
    codes = {bytes(p[PPP].payload)[0] for p in ipv6cp_frames}
    assert 2 in codes, f"IPv6CP never reached Configure-Ack, codes seen: {sorted(codes)}"

    state = client.iface_state()
    assert state["inet6_ll"] and state["inet6_ll"].startswith("fe80::"), (
        f"no fe80:: link-local address on pppoe0: {state}"
    )


def test_ipv6cp_accel_stays_offer_only(client, sniffer, wait_iface_up):
    """The accel-ppp IPv6CP exception, asserted positively and
    DIRECTION-AWARE (formerly an xfail): the client DOES offer IPv6CP
    (Configure-Requests go out on the wire) and the server never ACKs it
    (no server-sent Configure-Ack is ever seen), so the negotiation never
    completes.  The assertion is scoped to server-sent frames on purpose:
    since the 2026-09-23 isp-VM migration (see the module docstring),
    accel-ppp 1.14.0 sends its OWN IPv6CP ConfReq -- ifid 01:00:... --
    which the client correctly ConfAcks (RFC 5072: a non-colliding peer
    proposal must be accepted; frame-level evidence:
    tests/results/reconnect/s03-t5-diag-offer{,2,3}.py), and accel then
    ConfNaks every client request with a 02:00:... proposal instead of
    ACKing, so IPv6CP still never opens and the driver keeps its
    seeded-ifid link-local on pppoe0.  A direction-blind codeset
    assertion here false-fails on the client's own ConfAck (the
    deterministic full-suite failure of 2026-09-25); the loud-failure
    contract remains: a future accel-ppp that ACKs the client's IPv6CP
    (server-sent ConfAck) fails this test and the mpdsrv/accel
    distinction in this module's docstring needs revisiting.
    """
    sniffer.start()
    client.dial(service="lab")
    wait_iface_up(client, timeout=20)
    # Proving a negative (no server ConfAck) needs a bounded dwell, but
    # anchor it to the first observed IPv6CP frame -- not an arbitrary point
    # after iface-up -- so the settle window starts only once IPv6CP is
    # actually under way.
    first_ipv6cp = sniffer.wait_for(
        lambda p: p.haslayer(PPP) and p[PPP].proto == IPV6CP_PROTO, timeout=10
    )
    assert first_ipv6cp is not None, "client never sent an IPv6CP frame within 10s of iface-up"
    time.sleep(3)  # let the ConfReq/ConfNak volley play out before checking codes
    sniffer.stop()

    ipv6cp_frames = [p for p in sniffer.packets if p.haslayer(PPP) and p[PPP].proto == IPV6CP_PROTO]
    assert ipv6cp_frames, "client never sent an IPv6CP frame at all"
    client_sent = [p for p in ipv6cp_frames if p[Ether].src == CLIENT_MAC]
    server_sent = [p for p in ipv6cp_frames if p[Ether].src != CLIENT_MAC]
    client_codes = {bytes(p[PPP].payload)[0] for p in client_sent}
    server_codes = {bytes(p[PPP].payload)[0] for p in server_sent}
    assert 1 in client_codes, (
        f"no IPv6CP Configure-Request from the client, client codes: {sorted(client_codes)}"
    )
    assert 2 not in server_codes, (
        f"accel-ppp answered IPv6CP (server-sent Configure-Ack seen, server codes "
        f"{sorted(server_codes)}) -- the documented offer-only exception no longer holds"
    )


@pytest.mark.datapath
@pytest.mark.needs_mpdsrv
def test_ipv6cp_negotiates_link_local_with_mpdsrv(driver, sniffer):
    """IPv6CP against the mpd5 server VM (R007/R009, T2): the in-kernel
    client negotiates IPv6CP to Opened and the negotiated fe80:: is applied
    on pppoe0 by the driver's addr task (in6_control_ioctl(SIOCAIFADDR_IN6)
    on taskqueue_thread under CURVNET_SET) -- no userland ifconfig step.
    PAP + IPCP on this same session were proven live in S02/S03; this test
    adds the IPv6CP layer on top.
    """
    # p2p DAD can never complete over the PPPoE link (no MAC, no NA
    # source), and a tentative link-local is unbindable for ping6; this is
    # the standard PPP-host sysctl (an mpd5 client needs the same).
    r = driver.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    assert r.returncode == 0, f"dad_count=0 failed: {r.stdout}\n{r.stderr}"

    driver.create(iface="pppoe0", parent="vtnet1", service="mpdlab")
    cmd, secret = spppauth_cmd("pppoe0")
    r = driver.run(cmd, root=True, stdin=secret)
    assert r.returncode == 0, f"spppauth failed: {r.stdout}\n{r.stderr}"

    sniffer.start()
    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    if st["state"] != PPPOE_STATE_SESSION:
        # Dial-start race (observed with the harness flow, not manual):
        # re-drive the FSM once -- the interface is UP but discovery never
        # began; down/up re-enters SIOCSIFFLAGS and starts PADI.
        driver.down("pppoe0")
        time.sleep(2)
        driver.up("pppoe0")
        st = driver.wait_state(PPPOE_STATE_SESSION, timeout=25)
    if st["state"] != PPPOE_STATE_SESSION:
        dbg = driver.run("dmesg | tail -15")
        assert False, (
            f"state stayed {st['state']} (not SESSION): {st}\n"
            f"client dmesg:\n{dbg.stdout}\n{dbg.stderr}"
        )

    # Wait for IPv6CP Opened -> fe80:: applied in-kernel on pppoe0.
    deadline = time.time() + 45
    ll = ""
    while time.time() < deadline:
        st = driver.iface_state("pppoe0")
        if st["inet6_ll"]:
            ll = st["inet6_ll"]
            if "tentative" not in st["raw"]:
                break
        time.sleep(1)

    assert ll.startswith("fe80::"), (
        f"no fe80:: link-local applied in-kernel on pppoe0: {ll!r} {st['raw']}"
    )

    ipv6cp_frames = [
        p for p in sniffer.packets if p.haslayer(PPP) and p[PPP].proto == IPV6CP_PROTO
    ]
    assert ipv6cp_frames, "client never sent an IPv6CP frame at all"
    # code 2 == Configure-Ack: IPv6CP actually reached Opened.
    codes = {bytes(p[PPP].payload)[0] for p in ipv6cp_frames}
    assert 2 in codes, f"IPv6CP never reached Opened vs mpdsrv, codes: {sorted(codes)}"
    sniffer.stop()

    # ping6 the mpd5 server's tunnel link-local over the PPP link.
    client_ip = driver.iface_state("pppoe0")["inet"]
    peer = _mpdsrv_tun_ll(client_ip)
    assert peer, (
        f"could not discover the mpdsrv tunnel link-local (ngN --> {client_ip})"
    )
    assert ipaddress.IPv6Address(peer) != ipaddress.IPv6Address(ll), (
        f"mpdsrv tunnel and pppoe0 share link-local {ll}: a ping6 would be "
        "answered locally and prove nothing"
    )
    deadline = time.time() + 30
    ok = False
    ping_out = ""
    while time.time() < deadline:
        r = driver.run(f"ping6 -c 3 {peer}%pppoe0", timeout=25)
        ping_out = r.stdout + r.stderr
        if "0.0% packet loss" in ping_out and "packets received" in ping_out:
            ok = True
            break
        time.sleep(1)
    assert ok, f"ping6 {peer}%pppoe0 over the link failed:\n{ping_out}"
