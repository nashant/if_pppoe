"""Data-path scaling tests (branch p2/scaling, docs/PERF-DESIGN.md).

What each commit of the series changed that is observable from outside the
kernel:

  * R3 -- the inner-flow hash is always compiled (no `options RSS`
    dependency), hashes TCP/UDP on the 5-tuple and every IPv4 fragment on
    addresses + protocol only, and one flow key always lands on one netisr
    worker (per-flow ordering);
  * R4 -- net.pppoe.dispatch_cpus / net.pppoe.dispatch_map: flows are
    spread over the configured CPU set only, CPU 0 excluded by default;
  * qlimit -- net.pppoe.netisr_qlimit (4096) and the
    net.pppoe.netisr_enqueue_drop counter;
  * T1/T2/T4 -- IP leaves through the lock-free snapshot path in ONE
    22-byte prepend: the wire frame and the pppoe0 output counters must be
    exactly what the old two-prepend path produced;
  * T1/T2/R1 -- the lock-free paths survive redials (server PADT) and
    dispatch-map swaps under traffic in both directions, with M_PPPOE flat
    (a leaked session snapshot or dispatch map shows up there).

The spreading tests use net.pppoe.cpu_hits (per-CPU handler invocations),
as test_datapath.py::test_decapsulated_frames_spread_across_cpus does.  It
counts EVERY session frame the netisr handler runs for, not only the
injected ones: the real AC's LCP/CHAP/IPCP/IPv6CP negotiation and echoes
(unhashable, so on the session-id CPU) and its IPv6 RA/ND (hashed on their
own address pair, so on some other CPU).  _dial_as_ac() therefore waits for
the negotiation to finish and the counters to go quiet before a test
injects, and the "one CPU only" assertions allow only the handful of
periodic frames (an LCP echo, an RA) that can still land in the window.
All `datapath`: the conftest `driver` fixture hangs up the CLIENT seam
first and re-dials it afterwards.
"""
from __future__ import annotations

import json
import re
import time

import pytest
from scapy.all import ICMP, IP, UDP, Ether, IPv6, PPPoED, Raw, fragment

from hardening_probe import (
    _client_ssh_up,
    _dmesg_leak_count,
    _serial_offset,
    _vmstat_pppoe_row,
)
from lab import ACCEL_GW, ETH_PPPOE_SESSION, PADO, PPPOE_STATE_SESSION
from test_lifecycle import (
    _SessionFlood,
    _dial_capturing_pads,
    _no_panic_since,
    _start_load,
    _stop_load,
    _wait_inet,
    _wait_vmstat_row,
)

pytestmark = pytest.mark.datapath

# Stray handler hits a "single worker" assertion tolerates once the session
# is quiet (_wait_quiet): the AC's periodic LCP echoes (session-id fallback
# CPU) and RAs (their own hashed CPU) can still fall inside the window.
STRAY = 10
# _wait_quiet(): a window with no handler hit at all, within the deadline.
QUIET_WINDOW = 1.5
QUIET_TIMEOUT = 30
REDIAL_LOOPS = 8


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _cpu_hits(driver) -> dict:
    """`net.pppoe.cpu_hits` -> {"cpu0": n, ...}."""
    raw = driver.sysctl("net.pppoe.cpu_hits")
    return {k: int(v) for k, v in (tok.split("=") for tok in raw.split())}


def _dispatch_map(driver) -> list[str]:
    """`net.pppoe.dispatch_map` -> ["cpu1", "cpu2", ...]."""
    return re.findall(r"cpu\d+", driver.sysctl("net.pppoe.dispatch_map"))


def _set_dispatch(driver, spec: str):
    return driver.run(f"sysctl net.pppoe.dispatch_cpus={spec}", root=True)


def _need_workers(driver, n: int):
    assert int(driver.sysctl("net.isr.numthreads")) >= n, (
        f"net.isr.numthreads < {n}: not enough netisr workstreams to "
        "discriminate. Set net.isr.maxthreads=4 and net.isr.bindthreads=1 "
        "in the client VM's /boot/loader.conf and reboot (plan 1 Task 1 "
        "Step 5)")


def _dial_as_ac(driver, sniffer):
    """Create + dial pppoe0; return (session id, AC MAC)."""
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    pados = [p for p in sniffer.packets
             if p.haslayer(PPPoED) and p[PPPoED].code == PADO]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    # PPPOE_STATE_SESSION is only discovery (and the session publish,
    # pppoe_session_task, is asynchronous): LCP, auth, IPCP, IPv6CP and the
    # AC's first RAs follow over the next seconds, all through the handler.
    # Injected before they are done, 14-18 of them landed on other CPUs than
    # the one test flow and failed the reorder check although every one of
    # its 600 frames was on one CPU ({'cpu1': 14, 'cpu2': 4, 'cpu3': 600}).
    assert _wait_inet(driver.run), "IPCP never applied an address"
    _wait_quiet(driver)
    return parms["session"], pados[0][Ether].src


def _wait_quiet(driver):
    """Wait for a QUIET_WINDOW with no net.pppoe.cpu_hits increment at all,
    so the per-CPU deltas a test reads are its own frames' (plus at most a
    periodic LCP echo or RA)."""
    deadline = time.time() + QUIET_TIMEOUT
    last = _cpu_hits(driver)
    while time.time() < deadline:
        time.sleep(QUIET_WINDOW)
        now = _cpu_hits(driver)
        if now == last:
            return
        last = now
    pytest.fail(f"net.pppoe.cpu_hits never went quiet for {QUIET_WINDOW}s "
                f"within {QUIET_TIMEOUT}s: {last}")


def _frame(driver, ac_mac, session, ppp: bytes):
    return (Ether(dst=driver.mac, src=ac_mac, type=ETH_PPPOE_SESSION)
            / Raw(b"\x11\x00" + session.to_bytes(2, "big")
                  + len(ppp).to_bytes(2, "big") + ppp))


def _v4(pkt) -> bytes:
    return b"\x00\x21" + bytes(pkt)


def _v6(pkt) -> bytes:
    return b"\x00\x57" + bytes(pkt)


def _inject(driver, sniffer, frames, settle=3.0) -> dict:
    """Send `frames` as the AC; return the per-CPU handler-hit delta."""
    before = _cpu_hits(driver)
    sniffer.send(frames)
    time.sleep(settle)
    after = _cpu_hits(driver)
    return {k: after[k] - before.get(k, 0) for k in after}


# ---------------------------------------------------------------------------
# R3 + R4: spreading, per-flow pinning, fragments, IPv6, the dispatch set.
# ---------------------------------------------------------------------------
def test_flows_spread_only_over_the_dispatch_set(driver, server, sniffer):
    """200 IPv4/UDP flows on one session spread over >= 2 workers, and only
    over the CPUs net.pppoe.dispatch_map lists.  With the default "auto" the
    map must leave CPU 0 (the usual parent RX-queue CPU) out whenever there
    is another workstream to use.

    This spreads on ANY kernel: the hash no longer goes through
    rss_proto_software_hash_v4(), which compiled to "no hash" without
    `options RSS` and left every frame on sc_session % n (one CPU)."""
    _need_workers(driver, 3)
    session, ac_mac = _dial_as_ac(driver, sniffer)
    assert driver.sysctl("net.pppoe.dispatch_cpus") == "auto"
    allowed = _dispatch_map(driver)
    assert allowed and "cpu0" not in allowed, (
        f"dispatch_cpus=auto should exclude cpu0: map={allowed}")

    frames = [
        _frame(driver, ac_mac, session, _v4(
            IP(src=f"10.99.1.{(i % 200) + 1}", dst="10.99.0.1")
            / UDP(sport=1024 + (i % 200), dport=9) / Raw(b"z" * 64)))
        for i in range(2000)
    ]
    delta = _inject(driver, sniffer, frames)
    total = sum(delta.values())
    busy = [k for k, v in delta.items() if v > 0]
    assert total >= 1500, f"only {total}/2000 reached the handler: {delta}"
    assert set(busy) <= set(allowed), (
        f"frames were processed outside the dispatch set {allowed}: {delta}")
    assert len(busy) >= 2, f"200 flows did not spread: {delta}"
    assert max(delta.values()) <= 0.8 * total, (
        f"one CPU took > 80% of 200 flows -- the hash is not spreading: "
        f"{delta}")


def test_one_flow_stays_on_one_worker(driver, server, sniffer):
    """Per-flow ordering: 600 frames of ONE UDP 5-tuple (payload carries a
    sequence number, IP id varies) must all be handled on one worker --
    netisr keeps one workstream's frames in order, and nothing else can.
    A per-frame input to the hash (the IP id, say) or a per-frame CPU choice
    would scatter them."""
    _need_workers(driver, 2)
    session, ac_mac = _dial_as_ac(driver, sniffer)
    frames = [
        _frame(driver, ac_mac, session, _v4(
            IP(src="10.99.1.77", dst="10.99.0.1", id=i)
            / UDP(sport=40000, dport=9) / Raw(i.to_bytes(4, "big") * 16)))
        for i in range(600)
    ]
    delta = _inject(driver, sniffer, frames)
    top = max(delta, key=delta.get)
    rest = sum(v for k, v in delta.items() if k != top)
    assert delta[top] >= 500, f"the flow's frames went missing: {delta}"
    assert rest <= STRAY, (
        f"one flow was split across workers (reorder risk): {delta}")


def test_ip_fragments_of_one_host_pair_stay_on_one_worker(
        driver, server, sniffer):
    """200 UDP datagrams between one host pair, each with a DIFFERENT source
    port, each split into two IPv4 fragments.  Every fragment -- the first
    (MF set, ports present) as much as the rest (offset != 0, no ports) --
    must hash on addresses + protocol only, so all 400 frames land on one
    worker and a datagram's fragments cannot be reordered against each
    other.  The old hash only excluded offset != 0: first fragments hashed
    on their (varying) ports and scattered away from their tails."""
    _need_workers(driver, 2)
    session, ac_mac = _dial_as_ac(driver, sniffer)
    frames = []
    for i in range(200):
        dgram = (IP(src="10.99.1.88", dst="10.99.0.1", id=0x1000 + i)
                 / UDP(sport=2000 + i, dport=9) / Raw(b"f" * 1000))
        frags = fragment(dgram, fragsize=512)
        assert len(frags) == 2
        frames += [_frame(driver, ac_mac, session, _v4(f)) for f in frags]
    delta = _inject(driver, sniffer, frames)
    top = max(delta, key=delta.get)
    rest = sum(v for k, v in delta.items() if k != top)
    assert delta[top] >= 350, f"fragments went missing: {delta}"
    assert rest <= STRAY, (
        f"fragments of one host pair were split across workers: {delta}")


def test_ipv6_flows_spread(driver, server, sniffer):
    """The IPv6 arm of the hash: 200 IPv6/UDP flows spread over >= 2
    workers within the dispatch set (the frames are then dropped by the
    S03 IPv6 arm or delivered by p3-ipv6rx; the handler hit is counted
    first either way)."""
    _need_workers(driver, 3)
    session, ac_mac = _dial_as_ac(driver, sniffer)
    allowed = _dispatch_map(driver)
    frames = [
        _frame(driver, ac_mac, session, _v6(
            IPv6(src=f"2001:db8:1::{(i % 200) + 1:x}", dst="2001:db8::1")
            / UDP(sport=1024 + (i % 200), dport=9) / Raw(b"z" * 64)))
        for i in range(2000)
    ]
    delta = _inject(driver, sniffer, frames)
    busy = [k for k, v in delta.items() if v > 0]
    assert sum(delta.values()) >= 1500, f"IPv6 frames went missing: {delta}"
    assert set(busy) <= set(allowed), f"outside {allowed}: {delta}"
    assert len(busy) >= 2, f"200 IPv6 flows did not spread: {delta}"


def test_dispatch_cpus_sysctl_pins_and_validates(driver, server, sniffer):
    """net.pppoe.dispatch_cpus at run time: a one-CPU list puts every flow
    on that CPU; "all" brings CPU 0 back into the map; a malformed list is
    refused (EINVAL) and leaves the setting alone; "auto" restores the
    default."""
    _need_workers(driver, 3)
    session, ac_mac = _dial_as_ac(driver, sniffer)
    auto_map = _dispatch_map(driver)
    target = auto_map[-1]
    try:
        r = _set_dispatch(driver, target[len("cpu"):])
        assert r.returncode == 0, r.stderr
        assert _dispatch_map(driver) == [target]
        frames = [
            _frame(driver, ac_mac, session, _v4(
                IP(src=f"10.99.1.{(i % 100) + 1}", dst="10.99.0.1")
                / UDP(sport=3000 + (i % 100), dport=9) / Raw(b"p" * 64)))
            for i in range(1000)
        ]
        delta = _inject(driver, sniffer, frames)
        assert delta[target] >= 800, f"not pinned to {target}: {delta}"
        assert sum(v for k, v in delta.items() if k != target) == 0, (
            f"frames outside the one-CPU dispatch set {target}: {delta}")

        r = _set_dispatch(driver, "all")
        assert r.returncode == 0, r.stderr
        assert "cpu0" in _dispatch_map(driver), _dispatch_map(driver)

        for bad in ("x", "1-", "3-1", "1,,2x", "99999"):
            r = _set_dispatch(driver, bad)
            assert r.returncode != 0, f"dispatch_cpus accepted {bad!r}"
            assert driver.sysctl("net.pppoe.dispatch_cpus") == "all"
    finally:
        _set_dispatch(driver, "auto")
    assert _dispatch_map(driver) == auto_map


def test_netisr_qlimit_and_enqueue_drop_counter(driver):
    """The pppoe netisr protocol is registered with the 4096 default (it
    used to be a fixed 1000), visible both in the sysctl and in netstat -Q,
    and the enqueue-drop counter exists."""
    driver.kldload()
    assert driver.sysctl("net.pppoe.netisr_qlimit") == "4096"
    q = driver.run("netstat -Q").stdout
    m = re.search(r"^\s*pppoe\s+\d+\s+(\d+)", q, re.M)
    assert m and m.group(1) == "4096", f"netstat -Q:\n{q}"
    assert int(driver.sysctl("net.pppoe.netisr_enqueue_drop")) >= 0


# ---------------------------------------------------------------------------
# T1/T2/T4: the lock-free, one-prepend transmit path on the wire.
# ---------------------------------------------------------------------------
def test_ip_transmit_frame_and_counters_via_the_snapshot_path(
        driver, accel_server, sniffer):
    """IP from the stack now leaves through sppp_output() -> pp_xmit_proto
    -> pppoe_encap_output(): one 22-byte prepend built from the session
    snapshot instead of sppp's 2 bytes plus pppoe_transmit()'s 20.  The
    frame on the wire must be bit-for-bit what the old path produced -- AC
    MAC, parent MAC, 0x8864, VER/TYPE 1/1, code 0, the session id, the
    PPPoE length covering the protocol field, protocol 0x0021 -- and pppoe0's
    output counters must charge the PPPoE payload, once per packet."""
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    parms, pads = _dial_capturing_pads(
        sniffer, lambda: driver.up("pppoe0"),
        lambda t: driver.wait_state(PPPOE_STATE_SESSION, timeout=t))
    assert parms.get("state") == PPPOE_STATE_SESSION, parms
    assert pads is not None
    ac_mac = pads[Ether].src.lower()
    assert _wait_inet(driver.run), "IPCP never applied an address"

    def opkts():
        # libxo, as test_datapath.py::_datapath_snapshot reads it: the
        # IFT_PPP <Link#N> row has no address, so the text table's columns
        # do not sit at fixed offsets.
        r = driver.run("netstat --libxo json -I pppoe0 -bnW")
        assert r.returncode == 0, r.stderr
        rows = json.loads(r.stdout)["statistics"]["interface"]
        link = [x for x in rows if str(x.get("network", "")).startswith("<Link")]
        return link[0]["sent-packets"], link[0]["sent-bytes"]

    n, size = 20, 200
    tx0 = driver.counter("tx_frames")
    p0, b0 = opkts()
    sniffer.start()
    # An interval under 1 s is root-only in FreeBSD ping(8) ("-i interval
    # too short: Operation not permitted" otherwise).
    r = driver.run(f"ping -c {n} -i 0.2 -s {size} {ACCEL_GW}", root=True,
                   timeout=30)
    time.sleep(1)
    sniffer.stop()
    p1, b1 = opkts()
    tx1 = driver.counter("tx_frames")
    assert r.returncode == 0, f"ping through pppoe0 failed:\n{r.stdout}"

    ours = [p for p in sniffer.packets
            if p.haslayer(Ether) and p[Ether].type == ETH_PPPOE_SESSION
            and p[Ether].src.lower() == driver.mac.lower()
            and p.haslayer(ICMP) and p[ICMP].type == 8]
    assert len(ours) >= n, f"only {len(ours)} echo requests captured"
    ppp_len = 2 + 20 + 8 + size            # proto + IPv4 + ICMP + data
    for p in ours:
        raw = bytes(p)
        assert p[Ether].dst.lower() == ac_mac, p.summary()
        assert raw[14] == 0x11 and raw[15] == 0x00, raw[14:16].hex()
        assert int.from_bytes(raw[16:18], "big") == parms["session"]
        assert int.from_bytes(raw[18:20], "big") == ppp_len, raw[18:20].hex()
        assert raw[20:22] == b"\x00\x21", raw[20:22].hex()
    assert tx1 - tx0 >= n, f"tx_frames moved {tx1 - tx0} for {n} pings"
    # Other session frames leave during the window too (LCP echo, and since
    # IPv6CP opens on pppoe0 its RS/MLD/ND), so bound the counters by what
    # the sniffer saw us send rather than by a fixed allowance: each packet
    # counted exactly once can never exceed the wire (a double count shows
    # ~2x packets and bytes).  SLACK covers frames sent between the counter
    # reads and the sniffer start/stop.
    wire = [p for p in sniffer.packets
            if p.haslayer(Ether) and p[Ether].type == ETH_PPPOE_SESSION
            and p[Ether].src.lower() == driver.mac.lower()]
    wire_bytes = sum(int.from_bytes(bytes(p)[18:20], "big") for p in wire)
    SLACK = 2
    assert n <= p1 - p0 <= len(wire) + SLACK, (
        f"pppoe0 Opkts delta {p1 - p0} for {n} pings; {len(wire)} session "
        "frames from us on the wire")
    assert n * ppp_len <= b1 - b0 <= wire_bytes + SLACK * 64, (
        f"pppoe0 Obytes delta {b1 - b0}, expected >= {n * ppp_len} and <= "
        f"{wire_bytes} on the wire (PPPoE payload, protocol field included)")


# ---------------------------------------------------------------------------
# T1/T2/R1/R4 under churn: redial and dispatch-map swaps with traffic.
# ---------------------------------------------------------------------------
@pytest.mark.lifecycle
def test_redial_and_map_swaps_under_bidirectional_traffic(
        driver, accel_server, sniffer):
    """REDIAL_LOOPS times, with ping -f / a UDP blaster / ioctl loops on
    pppoe0 and a session-frame flood from the AC: the AC tears the session
    down (PADT), the driver redials by itself, and net.pppoe.dispatch_cpus
    flips between "auto" and "all".  Every teardown clears the transmit
    snapshot under transmitters that load it without a lock, every redial
    publishes a new one, and every flip swaps the dispatch map under
    m2cpuid readers.  No panic, the session always comes back, and M_PPPOE
    is flat once the clone is destroyed: a snapshot or map that was never
    freed (or freed twice) shows up there or on the console."""
    driver.kldload()
    driver.destroy()
    before = _vmstat_pppoe_row(driver)
    assert before is not None, "vmstat -m unreadable"
    leaks_before = _dmesg_leak_count(driver)
    offset = _serial_offset()

    driver.create(iface="pppoe0", parent="vtnet1", service="lab",
                  reload=False)
    try:
        for i in range(REDIAL_LOOPS):
            parms, pads = _dial_capturing_pads(
                sniffer,
                (lambda: driver.up("pppoe0")) if i == 0 else (lambda: None),
                lambda t: driver.wait_state(PPPOE_STATE_SESSION, timeout=t),
                timeout=40)
            assert parms.get("state") == PPPOE_STATE_SESSION, (
                f"iter {i}: no session after the redial: {parms}\n"
                f"{accel_server.log_tail(20)}")
            inet = _wait_inet(driver.run)
            assert inet, f"iter {i}: IPCP never applied an address"
            src = pads[Ether].src if pads is not None else None
            flood = (_SessionFlood(dst_mac=driver.mac, src_mac=src,
                                   session=parms["session"], dst_ip=inet)
                     if src else None)
            try:
                _start_load(driver)
                if flood:
                    flood.start()
                time.sleep(1.0)
                r = _set_dispatch(driver, "all" if i % 2 == 0 else "auto")
                assert r.returncode == 0, r.stderr
                time.sleep(0.5)
                accel_server.terminate_all()
                time.sleep(1.0)  # traffic keeps hitting the torn-down session
            finally:
                if flood:
                    flood.stop()
                _stop_load(driver)
            assert _client_ssh_up(), f"iter {i}: client VM stopped answering"
    finally:
        _set_dispatch(driver, "auto")
        driver.destroy()

    _no_panic_since(offset, f"during {REDIAL_LOOPS} redials under traffic")
    after = _wait_vmstat_row(driver, before)
    assert after == before, (
        f"M_PPPOE not flat across {REDIAL_LOOPS} redials: "
        f"before {before}, after {after}")
    assert _dmesg_leak_count(driver) == leaks_before, (
        "new 'leaked memory on destroy' line in dmesg")
