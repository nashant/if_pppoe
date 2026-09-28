"""In-kernel if_pppoe data-path tests (design spec sections 6 and 7).

These drive the driver through `IfPppoeDriver` rather than the `client`
fixture seam: plan 1 has no PPP layer yet, so there is no dial(). Select
with `-m datapath`.
"""
from __future__ import annotations

import json
import re
import shlex
import time

import pytest
import scapy.layers.ppp as ppp
from scapy.all import IP, UDP, Ether, PPPoED, Raw

from lab import (
    auth_cfg_cmd,
    ACCEL_GW,
    ACCEL_POOL_RE,
    ETH_PPPOE_SESSION,
    PADI,
    PADO,
    PADR,
    PADS,
    PADT,
    PPPOE_STATE_INITIAL,
    PPPOE_STATE_PADI_SENT,
    PPPOE_STATE_SESSION,
    TAG_AC_NAME,
    TAG_HOST_UNIQ,
    TAG_MAX_PAYLOAD,
    TAG_SERVICE_NAME,
    pppoe_tags,
    wait_until,
)

from test_sppp_ioctl_live import _install_spppioctl  # noqa: E402

pytestmark = pytest.mark.datapath


def test_ioctls_roundtrip_parent_service_and_acname(driver):
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")
    parms = driver.parms("pppoe0")
    assert parms["parent"] == "vtnet1", parms
    assert parms["service"] == "lab", parms
    assert parms["acname"] == "isp-lab", parms
    assert parms["state"] == PPPOE_STATE_INITIAL, (
        f"expected PPPOE_STATE_INITIAL before `ifconfig up`: {parms}"
    )
    assert parms["session"] == 0, parms


# Source MAC for every injected session frame below. It sits on br-isp's
# segment but is allocated to nothing: the lab's VMs take 52:54:00:aa:00:01 and
# :02 (lab/vm/common.sh:47, :58) and accel-ppp answers from the isp netns veth,
# whose MAC the kernel generates at random. Nothing relies on that reasoning
# though -- test_session_frames_from_an_unknown_peer_mac_are_not_delivered
# reads the AC's real MAC off its PADO and asserts the difference at run time.
FOREIGN_MAC = "52:54:00:aa:00:09"


def _session_frame(dst_mac, session=1, src="10.99.1.1", dst="10.99.0.1", payload=b"y" * 32):
    """A well-formed PPPoE session frame carrying PPP protocol 0x0021 (IPv4)."""
    ppp = b"\x00\x21" + bytes(IP(src=src, dst=dst) / UDP(dport=9) / Raw(payload))
    pppoe = b"\x11\x00" + session.to_bytes(2, "big") + len(ppp).to_bytes(2, "big") + ppp
    return Ether(dst=dst_mac, src=FOREIGN_MAC, type=0x8864) / Raw(pppoe)


def _taken(driver):
    """0x8864 frames the hook took off the wire, however they ended up.

    Deliberately the SUM of sess_in and sess_nosession rather than sess_in
    alone: this test's five frames name session 1 from a MAC that is not our
    AC, and there is no session at all here (no `up`), so the real demux counts
    every one of them as sess_nosession. Asserting on sess_in alone would only
    pass while pppoe_sess_input() was still the pre-Task-10 counting stub.
    """
    return driver.counter("sess_in") + driver.counter("sess_nosession")


def _wait_counter_delta(driver, name: str, before: int, delta: int, timeout=5, interval=0.1):
    """Poll until net.pppoe.<name> has advanced by at least `delta` from
    `before`, replacing a blind post-injection sleep with a wait on the
    actual counter increment (still bounded, so a driver bug that never
    counts the frames times out instead of hanging).
    """
    wait_until(
        lambda: driver.counter(name) - before >= delta,
        timeout=timeout, interval=interval,
        desc=f"net.pppoe.{name} to advance by {delta} from {before}",
    )


def test_hook_takes_only_pppoe_ethertypes(driver, sniffer):
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    seen_before = driver.counter("hook_seen")
    taken_before = _taken(driver)

    plain = (
        Ether(dst=driver.mac, src=FOREIGN_MAC)
        / IP(dst="10.99.0.9")
        / UDP(dport=9)
        / Raw(b"x" * 32)
    )
    sniffer.send([plain] * 5 + [_session_frame(driver.mac)] * 5)
    # Wait for the hook to actually take the frames instead of a blind
    # sleep(1.0); no session exists here (no `up`) so nothing else can move
    # this counter, and the exact-count assert below still catches an
    # overshoot the wait itself wouldn't (jumping past 5 in one step).
    wait_until(
        lambda: _taken(driver) - taken_before >= 5,
        timeout=5, interval=0.1,
        desc="the hook to take the five 0x8864 frames",
    )

    # Session 1 is not ours, so since p3-pfil-counters the five frames are
    # passed on (PFIL_PASS) rather than consumed -- but still counted.
    assert _taken(driver) - taken_before == 5, (
        "the hook did not inspect exactly the five 0x8864 frames"
    )
    assert driver.counter("hook_seen") - seen_before >= 5, (
        "hook_seen did not advance -- is vtnet1 in the parent set?"
    )


def _datapath_snapshot(driver, iface="pppoe0"):
    """(sess_lo, data_lo, Ipkts, Ibytes, sess_hi, data_hi) read in a SINGLE
    ssh round trip, with the module counters read BOTH before and after the
    interface-counter read.

    One round trip is the whole point. `driver.counter()` opens a fresh
    connection per call (`lab.py:378-381`; `_ssh_base_args()` at `lab.py:53-63`
    sets no ControlMaster, so each is a full TCP + key exchange + auth), and
    the test below runs while accel-ppp is sending keepalive/Configure-Request
    frames every second.  A frame landing between the module-counter read and
    the interface-counter read would skew them against each other and fail a
    naive equality assertion against perfectly correct code -- so both the
    module counter (net.pppoe.sess_in/data_in; since p2/scaling the
    interface's IPACKETS is charged next to data_in, in pppoe_data_input on
    the netisr worker, and data_in == sess_in) and the interface counter are
    read, with the netstat read bracketed by two sysctl reads.  The invariant
    is then sess_lo <= Ipkts <= sess_hi (a snapshot of a counter that follows
    the accepted-frame path must be squeezed between two snapshots of the
    counter it is charged with), which is immune to a frame landing in the
    inter-command gap.

    The interface counters come from libxo JSON rather than the plain-text
    table: an IFT_PPP interface has no link-layer address, so its `<Link#N>`
    row leaves the Address column empty and the numeric fields do not sit at
    fixed word offsets.
    """
    r = driver.run(
        f"sysctl -n net.pppoe.sess_in net.pppoe.data_in; "
        f"netstat --libxo json -I {iface} -bnW; "
        f"sysctl -n net.pppoe.sess_in net.pppoe.data_in"
    )
    assert r.returncode == 0, (
        f"datapath snapshot failed: {r.stdout}\n{r.stderr}"
    )
    lo1, lo2, netstat, hi1, hi2 = r.stdout.split("\n", 4)
    lo_sess, lo_data = int(lo1), int(lo2)
    hi_sess, hi_data = int(hi1), int(hi2)
    rows = json.loads(netstat)["statistics"]["interface"]
    link = [row for row in rows if str(row.get("network", "")).startswith("<Link")]
    assert link, f"no link-layer row for {iface}: {netstat}"
    return (lo_sess, lo_data, link[0]["received-packets"],
            link[0]["received-bytes"], hi_sess, hi_data)


def _module_counter_dump(driver):
    """All net.pppoe.* counters, so a bracket failure is self-diagnosing:
    the failing deltas alone cannot separate a lost frame from a stray
    charging path, but the full counter set (hook_seen, sess_nosession,
    sess_short, disc_in, cpu_hits) can."""
    r = driver.run("sysctl net.pppoe")
    return "\n".join("    " + line for line in r.stdout.strip().split("\n"))


def test_session_frames_are_decapsulated_and_counted(driver, accel_server):
    """accel-ppp sends LCP Configure-Requests as soon as the session is up.
    Plan 1 has no PPP layer, so each one is demuxed to the softc, stripped of
    its 20 bytes of Ethernet+PPPoE header, counted and dropped -- which is the
    whole of this task's receive path, asserted end to end with the server's
    own traffic rather than an injected frame.

    Every frame the demux accepts must reach pppoe_data_input() (data_in ==
    sess_in) and must be charged to the interface itself (Ipkts == sess_in),
    so a break anywhere between the lookup and the hand-off shows up here.
    """
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    b_lo, b_data_lo, b_ipkts, b_ibytes, b_hi, b_data_hi = _datapath_snapshot(driver)

    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    # Wait for the first accepted session frame instead of a blind
    # sleep(8): a poll to "sess_in moved" outlasts the async session-table
    # publish and a lost Configure-Request retransmit (3s) by construction.
    wait_until(
        lambda: driver.counter("sess_in") > b_hi,
        timeout=20, interval=0.3,
        desc="sess_in to advance past the baseline (first accepted session frame)",
    )

    a_lo, a_data_lo, a_ipkts, a_ibytes, a_hi, a_data_hi = _datapath_snapshot(driver)
    # Cross-paired sess bracket (see the long comment at the bracket assert
    # below): lower = a_lo - b_hi, upper = a_hi - b_lo.
    sess_lo = a_lo - b_hi
    sess_hi = a_hi - b_lo
    data_lo = a_data_lo - b_data_lo
    data_hi = a_data_hi - b_data_hi
    ipkts = a_ipkts - b_ipkts
    ibytes = a_ibytes - b_ibytes
    assert sess_hi > 0, (
        "the session demux accepted nothing at all -- accel-ppp should have "
        f"sent LCP Configure-Requests by now: {parms}\n{accel_server.log_tail(30)}"
    )
    # The module counters (sess_in/data_in, read atomically together by the
    # one sysctl) must agree exactly: the decapped frames cannot be lost
    # between the session demux and pppoe_data_input().
    assert data_lo == sess_lo and data_hi == sess_hi, (
        f"{sess_lo}/{sess_hi} session frames accepted but "
        f"{data_lo}/{data_hi} reached pppoe_data_input(); the decapsulated "
        "frames are being lost"
    )
    # The interface's Ipkts is charged next to data_in in pppoe_data_input()
    # (p2/scaling moved it off the serial RX stage), and data_in == sess_in
    # is asserted exactly above, so its delta over the window must be
    # bracketed by
    # the module-counter deltas. The bracket pairs must CROSS the snapshots:
    # each snapshot's sess_in is read twice (once either side of the netstat
    # read), and a frame landing in the BASELINE snapshot's own inter-command
    # gap (sess -> netstat -> sess, all one ssh exec but milliseconds wide)
    # is present in BOTH baseline sess reads -- so it cancels out of a_lo -
    # b_lo and of a_hi - b_hi -- while remaining in the Ipkts delta
    # (b's netstat read precedes it, a's follows it). Cross-pairing removes
    # the blind spot: the lower bound's window [b_hi, a_lo] is strictly
    # inside the Ipkts window [b_netstat, a_netstat] and the upper bound's
    # window [b_lo, a_hi] strictly contains it, so with sess_in and Ipkts
    # moving atomically, (a_lo - b_hi) <= Ipkts <= (a_hi - b_lo) can never
    # be violated by correct driver code, whichever gap a frame lands in.
    # (Observed live in M002 S05 T3 run watchdog-1: Ipkts delta 11 vs
    # [10, 10] -- one accel-ppp keepalive in the baseline gap.)
    #
    # UPPER-BOUND SKEW ALLOWANCE (+2): sess_in and Ipkts are incremented by
    # two SEPARATE per-CPU counter adds (now on two different CPUs) with
    # no barrier between them, so the reader can observe them non-atomically:
    # if the RX thread is preempted between the two adds while a snapshot
    # runs, the frame's Ipkts charge lands after the reader's netstat read
    # while its sess_in add landed before the baseline's first sysctl read --
    # leaving Ipkts permanently 1-2 frames above the bracket.  Observed live
    # in the M002 S05 T4 bracket-loop probe (1 of 3 trials): Ipkts 14 vs
    # [13, 13] with the module counters ending EXACTLY at sess_in ==
    # data_in == 13 -- the data path itself never loses or double-counts a
    # frame, so this is a reader/straddle artifact, not a driver defect.
    # Allow up to 2 frames of straddle on the upper bound only: a systematic
    # off-path charge (unknown sessions or nosession frames charged to
    # pppoe0) shows up as tens of frames, not two, and the exact
    # data_in == sess_in equality plus the lower bound below keep the
    # lost-frame and decap-loss teeth fully intact.
    assert sess_lo <= ipkts <= sess_hi + 2, (
        f"pppoe0 Ipkts delta {ipkts} is outside the bracketed session-frame "
        f"delta [{sess_lo}, {sess_hi}] (+2 straddle allowance) -- the "
        "per-interface counters do not follow the data path\n"
        f"module counters at failure: {_module_counter_dump(driver)}"
    )
    # IBYTES is charged the PPPoE payload length, not the frame length. These
    # are LCP Configure-Requests: 2 bytes of PPP protocol field plus an ~18-byte
    # LCP body, inside an Ethernet frame padded to the 60-byte minimum. The
    # upper bound is what has teeth -- charging m_pkthdr.len instead of plen
    # could not come in under 60 bytes a frame.
    assert 2 * ipkts <= ibytes < 60 * ipkts, (
        f"pppoe0 Ibytes ({ibytes}) over {ipkts} frames is not a PPPoE payload "
        "count; below 2 bytes a frame there is not even a PPP protocol field, "
        "and at or above the 60-byte Ethernet minimum it is the whole frame "
        "being charged rather than the payload"
    )


def test_session_frames_from_an_unknown_peer_mac_are_not_delivered(driver, sniffer):
    """Spec section 6.3 keys the session lookup on (parent ifp, session id,
    peer MAC). Frames naming the live session id but sourced from a MAC that is
    not our AC must miss that lookup outright.

    Asserting sess_nosession advances by exactly the number sent is what makes
    this a real test: drop the peer-MAC comparison from the lookup and all 20
    match the live session instead, leaving sess_nosession at 0.
    """
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]

    # FOREIGN_MAC is only "foreign" as long as the lab does not hand it to the
    # AC. Read the AC's real MAC off its own PADO and check, or this test could
    # one day assert the exact opposite of its name without anyone noticing.
    pados = [p for p in _disc(sniffer) if p[PPPoED].code == PADO]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    ac_mac = pados[0][Ether].src.lower()
    assert ac_mac != FOREIGN_MAC.lower(), (
        f"the lab has allocated {FOREIGN_MAC} to the AC itself, so the frames "
        "below are not from an unknown peer at all and this test would assert "
        "the opposite of what it claims"
    )
    # The publish is asynchronous; wait for it directly (sess_in actually
    # advancing) instead of a blind sleep(2), or the AC's own frames could
    # still land in sess_nosession and skew the exact count below.
    sess_in_baseline = driver.counter("sess_in")
    wait_until(
        lambda: driver.counter("sess_in") > sess_in_baseline,
        timeout=10, interval=0.2,
        desc="the session-table publish to complete (sess_in to advance)",
    )

    nosession_before = driver.counter("sess_nosession")
    sniffer.send([
        _session_frame(driver.mac, session=session, src=f"10.99.1.{i + 1}")
        for i in range(20)
    ])
    _wait_counter_delta(driver, "sess_nosession", nosession_before, 20)

    assert driver.counter("sess_nosession") - nosession_before == 20, (
        f"20 frames for live session {session} from a MAC that is not our AC "
        "were not all rejected as sess_nosession -- the session key must "
        "include the peer MAC (spec section 6.3)"
    )


def test_truncated_session_frame_is_counted_not_crashed(driver, sniffer):
    """A PPPoE header claiming 1400 bytes of payload on a frame carrying 4 must
    be counted and dropped, never walked past."""
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms

    short_before = driver.counter("sess_short")
    # PPPoE header claims 1400 bytes of payload but carries 4.
    bad = b"\x11\x00\x00\x01\x05\x78" + b"\x00\x21\x45\x00"
    sniffer.send(
        [Ether(dst=driver.mac, src=FOREIGN_MAC, type=0x8864) / Raw(bad)] * 10
    )
    _wait_counter_delta(driver, "sess_short", short_before, 10)

    assert driver.counter("sess_short") - short_before == 10, (
        "truncated session frames were not counted as sess_short"
    )
    assert driver.run("uptime").returncode == 0, "the client VM stopped responding"


def _disc(sniffer):
    return [p for p in sniffer.packets if p.haslayer(PPPoED)]


def test_padi_pado_padr_pads_against_accel(driver, accel_server, sniffer):
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()

    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"if_pppoe never reached PPPOE_STATE_SESSION: {parms}\n"
        f"accel-ppp log:\n{accel_server.log_tail(30)}"
    )
    assert parms["session"] != 0, parms

    codes = [p[PPPoED].code for p in _disc(sniffer)]
    for code in (PADI, PADO, PADR, PADS):
        assert code in codes, f"code {code:#x} missing: {[hex(c) for c in codes]}"
    first = {c: codes.index(c) for c in (PADI, PADO, PADR, PADS)}
    assert first[PADI] < first[PADO] < first[PADR] < first[PADS], (
        f"discovery frames out of order: {[hex(c) for c in codes]}"
    )


def test_host_uniq_and_service_name_in_padi(driver, sniffer):
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()

    frames = _disc(sniffer)
    padis = [p for p in frames if p[PPPoED].code == PADI]
    assert padis, "no PADI captured"
    tags = pppoe_tags(padis[0])
    assert tags.get(TAG_SERVICE_NAME) == b"lab", tags
    hu = tags.get(TAG_HOST_UNIQ)
    assert hu is not None and len(hu) == 8, f"Host-Uniq missing or wrong size: {tags}"

    pados = [p for p in frames if p[PPPoED].code == PADO]
    assert pados, "no PADO captured"
    assert pppoe_tags(pados[0]).get(TAG_HOST_UNIQ) == hu, "PADO did not echo Host-Uniq"
    padrs = [p for p in frames if p[PPPoED].code == PADR]
    assert padrs, "no PADR captured"
    assert pppoe_tags(padrs[0]).get(TAG_HOST_UNIQ) == hu, "PADR did not echo Host-Uniq"


def test_ac_name_is_offered_and_recorded(driver, sniffer):
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()

    pados = [p for p in _disc(sniffer) if p[PPPoED].code == PADO]
    assert pados, "no PADO captured"
    assert pppoe_tags(pados[0]).get(TAG_AC_NAME) == b"isp-lab", (
        f"unexpected AC-Name: {pppoe_tags(pados[0])}"
    )


def test_mismatched_service_name_never_reaches_session(driver, sniffer):
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="not-a-real-service")
    driver.up("pppoe0")
    first_padi = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADI, timeout=15
    )
    assert first_padi is not None, "if_pppoe did not even send a PADI within 15s"
    # Proving a negative (no PADS ever): anchor the settle window to the
    # first PADI actually observed rather than a blind sleep from up().
    time.sleep(8)
    sniffer.stop()

    codes = [p[PPPoED].code for p in _disc(sniffer)]
    assert PADI in codes, "if_pppoe did not even send a PADI"
    assert PADS not in codes, "accel-ppp sent a PADS for a mismatched Service-Name"
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_PADI_SENT, (
        f"expected to still be retrying PADI: {parms}"
    )


def test_client_sends_padt_on_ifconfig_down(driver, sniffer):
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]

    sniffer.start()
    driver.down("pppoe0")
    padt = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADT, timeout=10
    )
    sniffer.stop()

    assert padt is not None, "no PADT on the wire after `ifconfig pppoe0 down`"
    assert padt[PPPoED].sessionid == session, (
        f"PADT session id {padt[PPPoED].sessionid} != {session}"
    )
    assert driver.parms("pppoe0")["state"] == PPPOE_STATE_INITIAL


def test_server_padt_tears_the_session_down_and_redials(driver, accel_server, sniffer):
    """...and the data path follows the new session id.

    The final assertion is the only coverage of the session table across a
    session-id change: the softc has to leave the first session's hash bucket
    and be republished into the second's, and if it stayed in the old bucket
    every frame of the new session would miss `pppoe_session_lookup()` and land
    in sess_nosession instead. Note what it does NOT cover -- the coalescing
    case `sc_hashed_session` exists for. PPPOE_RECON_PADTRCVD puts 5s between
    the PADT's enqueue and the PADS's, so the taskqueue always drains in
    between and the two intents never merge into one run; nothing reachable
    from this harness makes them.
    """
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    first = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert first["state"] == PPPOE_STATE_SESSION, first

    padt_before = driver.counter("padt_rx")
    sniffer.start()
    accel_server.terminate_all("hard")
    # Wait for the actual event (padt_rx advancing) instead of a blind
    # sleep(3); 10s is more generous than the old fixed 3s.
    try:
        wait_until(
            lambda: driver.counter("padt_rx") > padt_before,
            timeout=10, interval=0.2, desc="padt_rx to advance past the baseline",
        )
    except TimeoutError:
        pass  # the assert below reports this with the accel-ppp log attached
    sniffer.stop()

    assert driver.counter("padt_rx") > padt_before, (
        f"if_pppoe did not count the server's PADT\n{accel_server.log_tail(30)}"
    )
    # The FSM must not sit idle: it re-dials within PPPOE_RECON_PADTRCVD (5s)
    # plus one PADI timeout.
    # padt_rx counts every PADT that reached the segment, INCLUDING ones
    # naming a session this softc does not own (the receive path counts
    # PADTs before the softc lookup, by design -- "an AC answering with
    # errors, or PADTing a session we had already torn down").  Under the
    # stale-session churn of repeated dials this test can therefore see
    # padt_rx advance on a stale-session PADT well before the PADT that
    # tears THIS session (M002 S05 T3 run final-1: state PADI_SENT with
    # padi_retries 0 at the old 25s deadline -- the re-dial had only just
    # been scheduled).  Wait for the FSM to actually leave SESSION -- the
    # real tear-down signal -- then allow the documented re-dial its 5s
    # plus generous PADI retransmit backoff.
    leave_deadline = time.time() + 20
    while time.time() < leave_deadline and (
        driver.parms().get("state") == PPPOE_STATE_SESSION
    ):
        time.sleep(0.5)
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=40)
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"if_pppoe did not re-dial after the server PADT: {parms}"
    )
    assert parms["session"] != first["session"], (
        f"accel-ppp re-used session id {parms['session']}, so the re-hash this "
        "test exists to cover was never exercised"
    )

    data_before = driver.counter("data_in")
    # Wait for the actual event (data_in advancing on the re-dialled
    # session) instead of a blind sleep(6); 15s (roughly two-and-a-half
    # accel-ppp LCP retransmit periods) is more generous than the old
    # fixed 6s.
    try:
        wait_until(
            lambda: driver.counter("data_in") > data_before,
            timeout=15, interval=0.3,
            desc="data_in to advance on the re-dialled session",
        )
    except TimeoutError:
        pass  # the assert below reports this with the accel-ppp log attached
    assert driver.counter("data_in") > data_before, (
        f"nothing was decapsulated on re-dialled session {parms['session']} -- "
        "the session table did not follow the new session id\n"
        f"{accel_server.log_tail(30)}"
    )


def test_padi_is_retransmitted_with_backoff_when_no_ac_answers(driver, sniffer):
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="no-such-service-xyz")
    driver.up("pppoe0")

    def _padi_count():
        return sum(1 for p in sniffer.packets if p.haslayer(PPPoED) and p[PPPoED].code == PADI)

    # The measurement is inherently time-based (proving the PADI backoff
    # actually widens), but wait for the 3rd PADI itself instead of a
    # blind sleep(20): 30s is more generous than the old fixed window.
    wait_until(
        lambda: _padi_count() >= 3, timeout=30, interval=0.5,
        desc="3rd PADI retransmit (backoff widening)",
    )
    sniffer.stop()

    padi_times = [
        p.time for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADI
    ]
    assert len(padi_times) >= 3, f"only {len(padi_times)} PADIs in 20s"
    gaps = [round(b - a, 1) for a, b in zip(padi_times, padi_times[1:])]
    assert gaps[-1] > gaps[0], f"PADI retransmits did not back off: {gaps}"
    assert driver.parms("pppoe0")["padi_retries"] >= 2, driver.parms("pppoe0")


SPOOFED_MAC = "52:54:00:aa:00:fe"   # on br-isp, but not the AC


def _padt_frame(dst_mac, session, src_mac, host_uniq=None):
    """A well-formed PADT (RFC 2516 section 5.5) naming `session`, optionally
    carrying a Host-Uniq tag (0x0103)."""
    tags = b""
    if host_uniq is not None:
        tags += b"\x01\x03" + len(host_uniq).to_bytes(2, "big") + host_uniq
    pppoe = (
        b"\x11\xa7"
        + session.to_bytes(2, "big")
        + len(tags).to_bytes(2, "big")
        + tags
    )
    return Ether(dst=dst_mac, src=src_mac, type=0x8863) / Raw(pppoe)


def _session_and_host_uniq(driver, sniffer):
    """Dial to SESSION with the sniffer running and read our Host-Uniq token off
    the PADI -- the only place it is visible from outside the kernel
    (`pppoeparms -d` does not report it)."""
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms

    padis = [p for p in _disc(sniffer) if p[PPPoED].code == PADI]
    assert padis, "no PADI captured, so our Host-Uniq is unknown"
    hu = pppoe_tags(padis[0]).get(TAG_HOST_UNIQ)
    assert hu is not None and len(hu) == 8, (
        f"Host-Uniq missing or wrong size: {pppoe_tags(padis[0])}"
    )
    return parms, hu


def test_tagless_padt_from_a_foreign_mac_misses_the_session_fallback(driver, sniffer):
    """A PADT carrying no Host-Uniq is resolved by the (parent, session id, peer
    MAC) fallback walk, so the wrong source MAC must miss that lookup outright.

    This covers the fallback walk's own filter only. The PADT arm's
    re-validation is never reached on this path -- see the Host-Uniq variant
    below, which is the test for that.
    """
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]

    padt_before = driver.counter("padt_rx")
    sniffer.send([_padt_frame(driver.mac, session, SPOOFED_MAC)])
    _wait_counter_delta(driver, "padt_rx", padt_before, 1)

    assert driver.counter("padt_rx") == padt_before + 1, (
        "the driver never parsed the spoofed PADT, so surviving it proves nothing"
    )
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"a tagless PADT from a MAC that is not our AC tore the session down: {parms}"
    )
    assert parms["session"] == session, parms


def test_padt_echoing_our_host_uniq_from_a_foreign_mac_does_not_tear_the_session_down(
    driver, sniffer
):
    """The real session-kill guard. A PADT that echoes our Host-Uniq resolves the
    softc through `pppoe_find_by_hunique()`, which checks neither parent nor
    session nor peer MAC -- so the PADT arm's own `sc_dest == peer`
    re-validation is the only thing between a spoofed frame from anything on the
    ISP segment and a torn-down session.

    Negative control run and recorded in the round-2 fix report: with that
    re-validation removed this test fails (the session goes to PADI_SENT).
    """
    parms, hu = _session_and_host_uniq(driver, sniffer)
    session = parms["session"]

    padt_before = driver.counter("padt_rx")
    sniffer.send([_padt_frame(driver.mac, session, SPOOFED_MAC, host_uniq=hu)])
    _wait_counter_delta(driver, "padt_rx", padt_before, 1)

    assert driver.counter("padt_rx") == padt_before + 1, (
        "the driver never parsed the spoofed PADT, so surviving it proves nothing"
    )
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"a PADT echoing our Host-Uniq from a MAC that is not our AC tore the "
        f"session down: {parms}"
    )
    assert parms["session"] == session, parms


def test_client_sends_padt_on_clone_destroy(driver, sniffer):
    """`ifconfig pppoe0 destroy` with a live session must PADT too, not just
    `down`: it is the teardown path, transmitting with sc_detaching set."""
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]

    tx_before = driver.counter("padt_tx")
    sniffer.start()
    driver.destroy("pppoe0")
    padt = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED)
        and p[PPPoED].code == PADT
        and p[PPPoED].sessionid == session,
        timeout=10,
    )
    sniffer.stop()

    assert padt is not None, (
        f"no PADT for session {session} on the wire after `ifconfig pppoe0 destroy`"
    )
    assert driver.counter("padt_tx") == tx_before + 1, (
        f"padt_tx did not advance by exactly one: {driver.counter('padt_tx')} "
        f"(was {tx_before})"
    )


@pytest.fixture
def parent_mtu(driver):
    """Set vtnet1's MTU for one test and always put it back.

    RFC 4638 is the only thing in this suite that touches the *parent*'s MTU,
    and a parent left at 1508 would follow every later test and mpd5's redial
    around. Restoring it belongs to the fixture, not to a manual step after
    the run: a test that fails between raising it and lowering it must still
    hand the lab back unchanged.
    """
    original = driver.iface_state("vtnet1")["mtu"]
    assert original is not None, "could not read vtnet1's MTU"

    def _set(mtu: int):
        r = driver.run(f"ifconfig vtnet1 mtu {mtu}", root=True)
        assert r.returncode == 0, (
            f"could not set vtnet1 MTU to {mtu}: {r.stdout}\n{r.stderr}"
        )

    yield _set
    r = driver.run(f"ifconfig vtnet1 mtu {original}", root=True)
    assert r.returncode == 0, (
        f"could not restore vtnet1 MTU to {original} -- every later test now "
        f"runs against a mutated parent: {r.stdout}\n{r.stderr}"
    )


def test_ppp_max_payload_is_offered_clamped_and_applied_to_the_mtu(
    driver, sniffer, parent_mtu
):
    """RFC 4638 end to end against accel-ppp, as far as this lab reaches.

    The client asks for 1500 in PADI; accel-ppp is configured `[ppp] mtu=1492`
    (lab/isp-netns/accel-ppp.conf:27) so its PADO offers 1492 and the PADR
    repeats that clamped value rather than the 1500 first asked for. Its PADS
    then carries no PPP-Max-Payload tag at all, which RFC 4638 section 5.1
    ("If (PPP-Max-Payload-Tag) AND (PPP-Max-Payload-Tag > 1492)") leaves at the
    1492 default -- so the 1500 set on pppoe0 before dialling must come back
    down to 1492 once the session is up. A conformant AC would echo 1492 in the
    PADS instead (section 4 says it MUST); both land on the same 1492, by the
    two different arms of the write-back, so the PADS assertion below accepts
    either rather than pinning accel-ppp's non-conformance as the requirement.

    Only the tag values and the resulting MTU are asserted: the lab's WAN
    uplink and `br-isp` are both 1500 (a known environment constraint), so no
    frame larger than 1492 can actually be pushed here. Plan 2 Task 13 does
    the payload end to end against mpdsrv.
    """
    parent_mtu(1508)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    r = driver.run("ifconfig pppoe0 mtu 1500", root=True)
    assert r.returncode == 0, f"could not raise pppoe0 MTU: {r.stdout}\n{r.stderr}"
    before = driver.iface_state("pppoe0")
    assert before["mtu"] == 1500, before["raw"]

    sniffer.start()
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms

    padis = [p for p in _disc(sniffer) if p[PPPoED].code == PADI]
    assert padis, "no PADI captured"
    assert pppoe_tags(padis[0]).get(TAG_MAX_PAYLOAD) == b"\x05\xdc", (
        f"PADI did not offer PPP-Max-Payload 1500: {pppoe_tags(padis[0])}"
    )

    pados = [p for p in _disc(sniffer) if p[PPPoED].code == PADO]
    assert pados, "no PADO captured"
    assert pppoe_tags(pados[0]).get(TAG_MAX_PAYLOAD) == b"\x05\xd4", (
        "this test assumes accel-ppp grants 1492 (accel-ppp.conf `[ppp] "
        f"mtu=1492`); it granted: {pppoe_tags(pados[0])}"
    )

    padrs = [p for p in _disc(sniffer) if p[PPPoED].code == PADR]
    assert padrs, "no PADR captured"
    assert pppoe_tags(padrs[0]).get(TAG_MAX_PAYLOAD) == b"\x05\xd4", (
        "PADR should repeat PPP-Max-Payload clamped to what the PADO granted "
        f"(1492), not the 1500 originally asked for: {pppoe_tags(padrs[0])}"
    )

    padss = [p for p in _disc(sniffer) if p[PPPoED].code == PADS]
    assert padss, "no PADS captured"
    assert pppoe_tags(padss[0]).get(TAG_MAX_PAYLOAD) in (None, b"\x05\xd4"), (
        "a PADS granting more than 1492 would make the 1492 assertion below "
        f"wrong rather than failing here: {pppoe_tags(padss[0])}"
    )
    state = driver.iface_state("pppoe0")
    assert state["mtu"] == 1492, (
        "the negotiated PPP-Max-Payload was not written back to the interface "
        f"MTU (still {state['mtu']}):\n{state['raw']}"
    )


def test_redial_still_offers_the_administrators_max_payload(
    driver, sniffer, parent_mtu
):
    """A second dial must re-offer 1500, not whatever the first one settled on.

    RFC 4638 negotiation is per session. The first session ends at 1492 -- the
    PADO clamps and the tagless PADS falls back -- and if the driver kept that
    in the same field it reads when building a PADI, the redial would quietly
    offer nothing at all and RFC 4638 would be off for the life of the
    interface. The administrator's request has to outlive the session that
    negotiated it down.
    """
    parent_mtu(1508)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    r = driver.run("ifconfig pppoe0 mtu 1500", root=True)
    assert r.returncode == 0, f"could not raise pppoe0 MTU: {r.stdout}\n{r.stderr}"

    sniffer.start()
    driver.up("pppoe0")
    first = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert first["state"] == PPPOE_STATE_SESSION, first
    assert driver.iface_state("pppoe0")["mtu"] == 1492, (
        "the first session should have negotiated down to 1492 -- without that "
        "this test proves nothing"
    )

    driver.down("pppoe0")
    back = driver.wait_state(PPPOE_STATE_INITIAL, timeout=10)
    assert back["state"] == PPPOE_STATE_INITIAL, back
    driver.up("pppoe0")
    second = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert second["state"] == PPPOE_STATE_SESSION, second

    padis = [p for p in _disc(sniffer) if p[PPPoED].code == PADI]
    assert len(padis) >= 2, f"expected a PADI per dial, captured {len(padis)}"
    offered = [pppoe_tags(p).get(TAG_MAX_PAYLOAD) for p in padis]
    assert offered == [b"\x05\xdc"] * len(padis), (
        "a PADI stopped offering the administrator's 1500 -- the negotiated "
        f"value leaked across sessions: {offered}"
    )


def test_ppp_max_payload_rejected_when_parent_mtu_too_small(driver, parent_mtu):
    """A parent at 1500 has no room for the 8 bytes of PPPoE+PPP header, so
    SIOCSIFMTU must refuse 1500 on pppoe0 and leave the MTU where it was."""
    parent_mtu(1500)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    before = driver.iface_state("pppoe0")["mtu"]

    r = driver.run("ifconfig pppoe0 mtu 1500", root=True)
    assert r.returncode != 0, (
        "pppoe0 accepted MTU 1500 with a 1500-MTU parent -- there is no room "
        f"for the 8-byte PPPoE+PPP overhead: {r.stdout}\n{r.stderr}"
    )
    assert driver.iface_state("pppoe0")["mtu"] == before, (
        f"the rejected SIOCSIFMTU still changed the MTU (was {before}): "
        f"{driver.iface_state('pppoe0')['raw']}"
    )


@pytest.fixture
def reflect(driver):
    """Turn `net.pppoe.reflect` on for one test and always turn it back off.

    The reflector bounces every decapsulated PPP frame straight back at the AC,
    so a test that failed between switching it on and switching it off would
    leave accel-ppp -- and then mpd5's own redial -- talking to an echo for the
    rest of the session. That makes the restore a fixture's job, not a step
    after the test body, exactly as `parent_mtu` above is for the parent's MTU.

    The knob is read back after the restore rather than the exit status being
    taken on trust: "it is back at 0" is the thing that actually has to be
    true for the next test, and it costs one more ssh round trip in teardown.
    """

    def _set(value: int):
        # Compiled in only with PPPOE_TEST_REFLECT (release builds leave it
        # out; lab/vm/build-module.sh defines it by default).  Checked here,
        # after the test's create() has loaded the module, and failed loudly
        # rather than skipped so a lab .ko built without it cannot hide.
        r = driver.run("sysctl -N net.pppoe.reflect")
        assert r.returncode == 0, (
            "net.pppoe.reflect is absent: the module was built without "
            "PPPOE_TEST_REFLECT=1 (lab/vm/build-module.sh sets it unless "
            f"PPPOE_TEST_HOOKS=0): {r.stdout}\n{r.stderr}"
        )
        r = driver.run(f"sysctl net.pppoe.reflect={value}", root=True)
        assert r.returncode == 0, (
            f"could not set net.pppoe.reflect={value}: {r.stdout}\n{r.stderr}"
        )

    yield _set
    r = driver.run("sysctl net.pppoe.reflect=0", root=True)
    assert r.returncode == 0, (
        "could not switch the reflector back off -- every later test now runs "
        f"against a driver that echoes PPP frames: {r.stdout}\n{r.stderr}"
    )
    assert driver.sysctl("net.pppoe.reflect") == "0", (
        "net.pppoe.reflect did not come back to 0: "
        f"{driver.sysctl('net.pppoe.reflect')}"
    )


def test_reflected_frame_comes_back_with_the_right_pppoe_header(
    driver, accel_server, sniffer, reflect
):
    """RX decap and TX encap, proved in one exchange.

    Plan 1 has no PPP layer to hand a decapsulated frame to, so `pppoe_transmit()`
    has nothing that would call it. `net.pppoe.reflect` is the hook that closes
    the loop: with it set, `pppoe_data_input()` hands the frame it would have
    dropped straight to `pppoe_transmit()`, which re-encapsulates it and sends
    it to the AC.

    A session frame carrying a marker goes in addressed to us from the AC's own
    MAC; the same PPP bytes must come back out addressed to the AC, under a
    PPPoE header carrying this session's id and the right length. That is the
    whole transmit path -- peer MAC, source MAC, ethertype, VER/TYPE, code 0,
    session id and length -- asserted against one frame.

    The reflector is switched on as late as possible and off as soon as the
    echo is in hand: while it is on, accel-ppp's own LCP Configure-Requests are
    echoed back to it, and an AC that sees its own magic number returned treats
    the link as looped and hangs the session up.
    """
    from scapy.all import PPPoE

    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"if_pppoe never reached PPPOE_STATE_SESSION: {parms}\n"
        f"accel-ppp log:\n{accel_server.log_tail(30)}"
    )
    session = parms["session"]

    # The AC's MAC, as the driver itself latched it from the PADO: the injected
    # frame has to come from that MAC or the session lookup rejects it
    # (spec section 6.3 keys on parent, session id and peer MAC together).
    pados = [p for p in _disc(sniffer) if p[PPPoED].code == PADO]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    ac_mac = pados[0][Ether].src.lower()

    # pppoe_session_task() publishes the session asynchronously; a frame that
    # beats it is counted sess_nosession and never reaches pppoe_data_input().
    # Wait for the publish directly (sess_in advancing) instead of a blind
    # sleep(2).
    sess_in_baseline = driver.counter("sess_in")
    wait_until(
        lambda: driver.counter("sess_in") > sess_in_baseline,
        timeout=10, interval=0.2,
        desc="the session-table publish to complete (sess_in to advance)",
    )

    marker = b"REFLECT-ME-0123456789"
    ppp = b"\x00\x21" + bytes(
        IP(src="10.99.1.7", dst="10.99.0.1") / UDP(dport=9) / Raw(marker)
    )
    frame = Ether(dst=driver.mac, src=ac_mac, type=ETH_PPPOE_SESSION) / Raw(
        b"\x11\x00" + session.to_bytes(2, "big") +
        len(ppp).to_bytes(2, "big") + ppp
    )

    # Both counters are read before the reflector goes on: each is its own ssh
    # round trip, and every one of them widens the window above.
    data_before = driver.counter("data_in")
    tx_before = driver.counter("tx_frames")

    reflect(1)
    sniffer.send([frame])
    echo = sniffer.wait_for(
        lambda p: p.haslayer(Ether) and
        p[Ether].type == ETH_PPPOE_SESSION and
        p[Ether].dst.lower() == ac_mac and bytes(p).find(marker) >= 0,
        timeout=10,
    )
    reflect(0)
    sniffer.stop()

    data_delta = driver.counter("data_in") - data_before
    tx_delta = driver.counter("tx_frames") - tx_before
    assert echo is not None, (
        f"nothing carrying the marker came back to the AC at {ac_mac}: "
        f"data_in delta={data_delta}, tx_frames delta={tx_delta}, "
        f"tx_errors={driver.counter('tx_errors')}, "
        f"parms={driver.parms('pppoe0')}\n"
        f"accel-ppp log:\n{accel_server.log_tail(30)}"
    )
    assert echo[Ether].src.lower() == driver.mac.lower(), (
        "the reflected frame did not come from the parent's own MAC: "
        f"{echo[Ether].src}"
    )
    assert echo[PPPoE].version == 1 and echo[PPPoE].type == 1, (
        f"reflected VER/TYPE is not 1/1: {echo[PPPoE].version}/"
        f"{echo[PPPoE].type}"
    )
    assert echo[PPPoE].code == 0, (
        f"reflected PPPoE code is {echo[PPPoE].code:#x}, not 0 (session data)"
    )
    assert echo[PPPoE].sessionid == session, (
        f"reflected frame carried session {echo[PPPoE].sessionid}, expected "
        f"{session}"
    )
    assert echo[PPPoE].len == len(ppp), (
        f"reflected PPPoE length {echo[PPPoE].len} != {len(ppp)}"
    )
    # Byte-for-byte, sliced to the PPPoE length: the PPP frame the driver put
    # back on the wire has to be the one it took off it, protocol field and all.
    assert bytes(echo[PPPoE].payload)[:echo[PPPoE].len] == ppp, (
        "the reflected PPP payload is not the one that went in: "
        f"{bytes(echo[PPPoE].payload)[:echo[PPPoE].len]!r}"
    )
    assert data_delta > 0, (
        f"pppoe_data_input() saw nothing at all: data_in delta={data_delta}"
    )
    assert tx_delta > 0, (
        f"the frame came back but tx_frames did not move: {tx_delta}"
    )


def _cpu_hits(driver) -> dict:
    """`net.pppoe.cpu_hits` -> {"cpu0": n, ...}."""
    raw = driver.sysctl("net.pppoe.cpu_hits")
    return {k: int(v) for k, v in (tok.split("=") for tok in raw.split())}


def test_decapsulated_frames_spread_across_cpus(driver, server, sniffer):
    """Spec section 6.4, and the reason the whole driver exists: decapsulated
    session frames go to a private netisr protocol (NETISR_POLICY_CPU +
    NETISR_DISPATCH_HYBRID) whose nh_m2cpuid hashes the *inner* IPv4/IPv6
    4-tuple, so one PPPoE session is processed on every CPU at once instead of
    on whichever core the parent NIC's receive queue happens to use.

    The 2000 injected frames carry 200 distinct (src IP, src port) pairs on one
    session id, which is the only thing that can spread them: the session id,
    the peer MAC and the outer PPPoE header are identical across all of them.
    So the test discriminates in both directions --

      * drop the hash (or return a constant from pppoe_m2cpuid()) and every
        frame falls back to `sc_session % cpucount`, one CPU, and the
        `len(busy) >= 2` assertion fails;
      * drop the netisr hand-off and call pppoe_data_input() inline again and
        net.pppoe.cpu_hits does not exist, so the test errors at `before`.

    It cannot discriminate on a kernel with one netisr workstream --
    netisr_select_cpuid() shortcuts before nh_m2cpuid is ever called
    (sys/net/netisr.c:811-814) -- hence the net.isr.numthreads guard, which
    names its own fix rather than letting the test pass vacuously.
    """
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    sniffer.stop()
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    session = parms["session"]

    # Inject as the AC: the session lookup keys on the peer MAC as well as the
    # session id, so frames from any other source would all miss it and be
    # counted sess_nosession instead of reaching the handler.
    pados = [p for p in _disc(sniffer) if p[PPPoED].code == PADO]
    assert pados, "no PADO captured, so the AC's source MAC is unknown"
    ac_mac = pados[0][Ether].src

    assert int(driver.sysctl("net.isr.numthreads")) >= 2, (
        "net.isr.numthreads < 2: there is only one netisr workstream, so "
        "nothing can spread. Set net.isr.maxthreads=4 and net.isr.bindthreads=1 "
        "in the client VM's /boot/loader.conf and reboot (plan 1 Task 1 Step 5)"
    )

    # The session publish is asynchronous (pppoe_session_task); without this
    # the first frames would miss the lookup entirely. Wait for it directly
    # (sess_in advancing) instead of a blind sleep(2).
    sess_in_baseline = driver.counter("sess_in")
    wait_until(
        lambda: driver.counter("sess_in") > sess_in_baseline,
        timeout=10, interval=0.2,
        desc="the session-table publish to complete (sess_in to advance)",
    )

    frames = []
    for i in range(2000):
        ppp = b"\x00\x21" + bytes(
            IP(src=f"10.99.1.{(i % 200) + 1}", dst="10.99.0.1")
            / UDP(sport=1024 + (i % 200), dport=9)
            / Raw(b"z" * 64)
        )
        frames.append(
            Ether(dst=driver.mac, src=ac_mac, type=ETH_PPPOE_SESSION)
            / Raw(
                b"\x11\x00"
                + session.to_bytes(2, "big")
                + len(ppp).to_bytes(2, "big")
                + ppp
            )
        )

    before = _cpu_hits(driver)
    before_total = sum(before.values())
    sniffer.send(frames)
    # Wait for cpu_hits to reach the 1500-of-2000 threshold instead of a
    # blind sleep(3); a timeout just means `after` is taken at 10s instead
    # of 3s -- the assertion below still reports the real shortfall.
    try:
        wait_until(
            lambda: sum(_cpu_hits(driver).values()) - before_total >= 1500,
            timeout=10, interval=0.2,
            desc="net.pppoe.cpu_hits total to reach 1500 of 2000 injected frames",
        )
    except TimeoutError:
        pass
    after = _cpu_hits(driver)

    delta = {k: after[k] - before.get(k, 0) for k in after}
    total = sum(delta.values())
    busy = [k for k, v in delta.items() if v > 0]
    assert total >= 1500, (
        f"only {total} of 2000 injected frames reached the netisr handler: "
        f"{delta}"
    )
    assert len(busy) >= 2, (
        f"decapsulated frames did not spread across CPUs: {delta} "
        "(`netstat -Q` on the client shows whether the pppoe workstreams "
        "exist and whether anything was queued to them)"
    )
    # len(busy) >= 2 alone would pass on 1999/1. A flow hash over 200 flows
    # cannot leave four fifths of them on one CPU; a broken one can.
    assert max(delta.values()) <= 0.8 * total, (
        f"one CPU took more than 80% of the frames, so the inner-flow hash is "
        f"not distinguishing the 200 injected flows: {delta}"
    )
    # p2/scaling R4: only the CPUs net.pppoe.dispatch_cpus resolved to (by
    # default every netisr CPU but cpu0, the usual parent RX-queue CPU) may
    # run the handler.  And this spreads on a kernel without `options RSS`:
    # the hash no longer depends on it (test_scaling.py has the rest).
    allowed = set(re.findall(r"cpu\d+", driver.sysctl("net.pppoe.dispatch_map")))
    assert set(busy) <= allowed, (
        f"frames were handled outside the dispatch set {sorted(allowed)}: "
        f"{delta}"
    )


@pytest.mark.soak
def test_padi_backoff_is_capped_at_the_slow_retry_interval(driver, sniffer):
    """After PPPOE_DISC_MAXPADI (4) retries the interval stops doubling and
    settles on PPPOE_SLOW_RETRY (60s), so PADIs land at t=0,5,15,35,75,135.

    Only the 5th gap tells the two policies apart: uncapped, the interval would
    stay at the MIN(n,3) ceiling of 40s and the 6th PADI would arrive at t=115.
    That makes this a >2min test, so it is marked `soak` and excluded from the
    default suite (`lab/Makefile` runs `-m "not soak"`). Run it on demand:

        ssh <LAB_HOST> 'cd if_pppoe-lab && sudo venv/bin/python3 -m pytest \
            tests-functional -m soak -k slow_retry -v'
    """
    sniffer.start()
    driver.create(iface="pppoe0", parent="vtnet1", service="no-such-service-xyz")
    driver.up("pppoe0")

    def _padi_count():
        return sum(1 for p in sniffer.packets if p.haslayer(PPPoED) and p[PPPoED].code == PADI)

    # Wait for the 6th PADI (proving the cap at t~135s) instead of a blind
    # sleep(160): stops as soon as it lands, saving ~20s per soak run.
    wait_until(
        lambda: _padi_count() >= 6, timeout=200, interval=1.0,
        desc="6th PADI retransmit (PPPOE_SLOW_RETRY cap)",
    )
    sniffer.stop()

    padi_times = [
        p.time for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADI
    ]
    assert len(padi_times) >= 6, f"only {len(padi_times)} PADIs observed"
    gaps = [round(b - a, 1) for a, b in zip(padi_times, padi_times[1:])]
    assert 50 <= gaps[4] <= 70, (
        f"the 5th PADI gap should be PPPOE_SLOW_RETRY (60s), not the uncapped "
        f"40s ceiling: {gaps}"
    )
    assert driver.parms("pppoe0")["padi_retries"] >= 5, driver.parms("pppoe0")


def _lcp_configure_frames(sniffer):
    """LCP Configure-* frames (code 1=Request, 2=Ack, 3=Nak, 4=Reject)."""
    from scapy.layers.ppp import PPP_LCP_Configure

    return [p for p in sniffer.packets if p.haslayer(PPP_LCP_Configure)]


def test_lcp_exchange_reaches_opened_via_sppp(driver, accel_server, sniffer):
    """S02 T1: the wired sppp state machine must run a live LCP handshake
    against accel-ppp instead of counting-and-dropping its Configure-Requests.

    Plan 1 deliberately had no PPP layer; `pppoe_data_input()` dispatched
    PPP frames to the reflect arm or the drop counter.  With sppp_attach() in
    the cloner, `pppoe_ioctl(SIOCSIFFLAGS)` -> sppp_ioctl() opens LCP, LCP's
    This-Layer-Up calls pppoe_tls() which starts discovery, and on PADS the
    session task fires pp_up() (LCP Up event) so our side sends a
    Configure-Request.  This test proves the whole chain on the wire: both
    sides send Configure-Request and both sides Configure-Ack -- the
    two-directional ack being what an OPENED LCP means -- and that the sppp
    debug log (IFF_DEBUG) recorded the exchange in the module log.

    It also proves the SPPPGETSTATUS ioctl falls through pppoe_ioctl to
    sppp_ioctl instead of the plan-1 default EINVAL: phase is returned out of
    the PPP state machine, and the ioctl number is the FreeBSD encoding of
    _IOWR('P', 124, struct spppstatus) == 0xC014507C (was 0xC014697C on group 'i', p3-ctl-abi).
    """
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    # IFF_DEBUG turns on sppp's per-protocol debug records (SPPP_DLOG /
    # SPPP_LOG -> log(9)); "module log shows the negotiation" means these.
    r = driver.run("ifconfig pppoe0 debug", root=True)
    assert r.returncode == 0, f"ifconfig pppoe0 debug failed: {r.stdout}\n{r.stderr}"
    data_before = driver.counter("data_in")

    sniffer.start()
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms

    deadline = time.time() + 15
    confs = []
    while time.time() < deadline:
        confs = _lcp_configure_frames(sniffer)
        codes = {ppp_code(p) for p in confs}
        if 1 in codes and 2 in codes:
            break
        time.sleep(1)
    sniffer.stop()

    assert confs, (
        "no LCP Configure frame captured on the wire -- sppp never started "
        f"negotiating\n{parms}\n{accel_server.log_tail(30)}"
    )
    codes = {ppp_code(p) for p in confs}
    assert 1 in codes, (
        f"no Configure-Request captured -- our side never sent one: {codes}"
    )
    assert 2 in codes, (
        f"no Configure-Ack captured -- accel-ppp never accepted our config: {codes}"
    )
    reqs = [p for p in confs if ppp_code(p) == 1]
    acks = [p for p in confs if ppp_code(p) == 2]
    assert len(reqs) >= 2, (
        f"expected a Configure-Request from each side (>=2), saw {len(reqs)}: "
        f"{codes}"
    )
    assert len(acks) >= 1, (
        "expected accel-ppp to Configure-Ack our request at least once, saw "
        f"{len(acks)}: {codes}"
    )

    # Module log evidence: the sppp debug records for the exchange.  Each is
    # its own log(9) line ("lcp output <conf-req id=..>", "lcp input(...)").
    # accel-ppp requires client authentication (chap-secrets fixture), so a
    # no-auth client sees its Auth-Protocol option rejected and eventually a
    # PADT -- that is T2's live PAP/CHAP work; this task gates the
    # negotiation machinery itself (Configure-Request/Ack exchange, ack-rcvd).
    r = driver.run("dmesg | grep -E 'lcp (output|input)' | tail -30")
    assert r.returncode == 0
    lcp_log = r.stdout
    assert "conf-req" in lcp_log, (
        "the module debug log never recorded an LCP Configure-Request "
        f"exchange -- IFF_DEBUG was on:\n{lcp_log}\n{dmesg_tail(driver)}"
    )

    # SPPPGETSTATUS must land in sppp_ioctl() (not EINVAL) and report the
    # PPP layer's phase while a session is (or was just) up.  The client VM
    # has no python3 (the harness has never shipped one), so this goes
    # through the compiled spppioctl helper (same SPPPGETSTATUS ioctl,
    # _IOWR('P', 124, struct spppstatus) == 0xC014507C (was 0xC014697C on group 'i', p3-ctl-abi)) like every other
    # live ioctl probe in this suite -- see test_sppp_ioctl_live.py.
    _install_spppioctl(driver)
    r = driver.run("/usr/local/sbin/spppioctl status pppoe0", root=True)
    assert r.returncode == 0, (
        "SPPPGETSTATUS did not reach sppp_ioctl -- still EINVAL? "
        f"{r.stdout}\n{r.stderr}"
    )
    m = re.search(r"phase=(\d+)", r.stdout)
    assert m, f"spppioctl status printed no phase: {r.stdout}"
    phase = int(m.group(1))
    assert 0 <= phase <= 4, f"SPPPGETSTATUS returned a nonsense phase: {phase}"

    # The PPP layer consumed the LCP frames rather than the reflect/drop arm.
    assert driver.counter("data_in") > data_before, (
        "no decapsulated frame reached pppoe_data_input() during the LCP "
        f"exchange\n{accel_server.log_tail(30)}"
    )


def ppp_code(p):
    from scapy.layers.ppp import PPP_LCP_Configure

    return p[PPP_LCP_Configure].code


def dmesg_tail(driver):
    return driver.run("dmesg | tail -40").stdout


# ---------------------------------------------------------------------------
# PPP-layer tests against the if_pppoe backend (S05 T2).  These drive the
# in-kernel client through pppoectl(8) -- the verbatim NetBSD tool ported in
# S05 T1 (R005) -- rather than the spppauth helper, so they double as the
# tool's live auth/keepalive/query-dns mode proof on an up session.
# ---------------------------------------------------------------------------


def _pppoectl_up(driver, auth="pap", service="lab", query_dns=True):
    """Create the clone, program the sppp auth/dns/keepalive config over
    pppoectl (SPPPSETAUTHCFG/SPPPSETDNSOPTS/SPPPSETKEEPALIVE) and bring the
    interface up, returning the driver after waiting for PPPOE_STATE_SESSION.

    accel-ppp requires client authentication (chap-secrets fixture), so a
    session cannot reach LCP-opened, let alone the network phase, without a
    myauthproto/myname/mysecret programmed first.  query_dns=3 enables the
    IPCP DNS options (mpd5's `set ipcp enable req-pri-dns`), which the IPCP
    test below asserts on the wire.
    """
    driver.create(iface="pppoe0", parent="vtnet1", service=service)
    extra = "max-noreceive=0 max-alive-missed=3 alive-interval=1"
    if query_dns:
        extra += " query-dns=3"
    cfg, secret = auth_cfg_cmd(proto=auth, extra=extra)
    r = driver.run(cfg, root=True, stdin=secret)
    assert r.returncode == 0, f"pppoectl config failed: {r.stdout}\n{r.stderr}"
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    return driver


def _wait_inet(driver, timeout=25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = driver.iface_state("pppoe0")
        if last["inet"] is not None:
            return last
        time.sleep(0.5)
    return last


def test_lcp_echo_requests_sent_at_keepalive_cadence(driver, accel_server, sniffer):
    """The in-kernel client's own LCP Echo-Requests (sppp_keepalive, the
    PP_DEVF_KEEPALIVE flag if_pppoe attach wires in) must hit the wire at the
    ~10s cadence the seam programs (mpd5's `set link keep-alive 10 60`),
    independent of accel-ppp's own echoes -- i.e. filtered to frames sourced
    from the client's own MAC, not the AC's.
    """
    def _is_client_echo_req(p) -> bool:
        return (
            p.haslayer(ppp.PPP_LCP_Echo)
            and p[ppp.PPP_LCP_Echo].code == 9
            and p[Ether].src.lower() == driver.mac.lower()
        )

    sniffer.start()
    _pppoectl_up(driver, auth="pap")

    # The measurement is inherently time-based (proving a ~10s echo
    # cadence), but anchor it to the first observed echo instead of a
    # blind sleep(3)+sleep(25): LCP-Opened timing (and so the first echo)
    # varies with negotiation speed, worse on the SMPW debug kernel.
    first = sniffer.wait_for(_is_client_echo_req, timeout=30)
    assert first is not None, "no client-sourced LCP echo-request observed within 30s"
    second = sniffer.wait_for(
        lambda p: _is_client_echo_req(p) and p.time > first.time, timeout=15
    )
    sniffer.stop()
    assert second is not None, (
        "only one client-sourced LCP echo-request observed within 15s of the first"
    )

    echoes = sorted(p.time for p in sniffer.packets if _is_client_echo_req(p))
    assert len(echoes) >= 2, (
        f"expected >=2 client-sourced LCP echo-requests, saw "
        f"{len(echoes)}: {[round(t, 1) for t in echoes]}"
    )
    deltas = [b - a for a, b in zip(echoes, echoes[1:])]
    assert all(8 <= d <= 13 for d in deltas), (
        f"client echo-request spacing not ~10s: {[round(d, 1) for d in deltas]}"
    )


def test_pap_auth_negotiated_through_pppoectl(driver, accel_server, sniffer):
    """myauthproto=pap (R005 pppoectl auth mode) must produce a live PAP
    Authenticate-Request from the client and an Authenticate-Ack from
    accel-ppp, then a NETWORK-phase session with a pool address -- the same
    live-PAP proof as test_pap_live, but through the ported tool."""
    sniffer.start()
    _pppoectl_up(driver, auth="pap")

    deadline = time.time() + 15
    acks = []
    while time.time() < deadline:
        acks = [
            p for p in sniffer.packets
            if p.haslayer(ppp.PPP_PAP_Response)
            and p[ppp.PPP_PAP_Response].code == 2
        ]
        if acks:
            break
        time.sleep(1)
    sniffer.stop()

    assert acks, (
        "no PAP Authenticate-Ack observed with myauthproto=pap\n"
        f"{accel_server.log_tail(20)}"
    )
    state = _wait_inet(driver)
    assert state["inet"] and ACCEL_POOL_RE.match(state["inet"]), (
        f"PAP succeeded on the wire but no pool address came up: {state}"
    )
    assert state["inet_peer"] == ACCEL_GW, state


def test_chap_auth_negotiated_through_pppoectl(driver, accel_server, sniffer):
    """myauthproto=chap must complete CHAP-MD5 live: a Challenge (code 1) and
    Response (code 2) exchange culminating in a CHAP Success (code 3) from
    accel-ppp, then a NETWORK-phase session."""
    sniffer.start()
    _pppoectl_up(driver, auth="chap")

    deadline = time.time() + 15
    success = []
    while time.time() < deadline:
        success = [
            p for p in sniffer.packets
            if p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 3
        ]
        if success:
            break
        time.sleep(1)
    sniffer.stop()

    assert success, (
        "no CHAP Success observed with myauthproto=chap\n"
        f"{accel_server.log_tail(20)}"
    )
    state = _wait_inet(driver)
    assert state["inet"] and ACCEL_POOL_RE.match(state["inet"]), (
        f"CHAP succeeded on the wire but no pool address came up: {state}"
    )
    assert state["inet_peer"] == ACCEL_GW, state


def test_bpf_on_pppoe0_is_dlt_ppp_and_filters_match_both_directions(
        driver, accel_server):
    """tcpdump on pppoe0 sees DLT_PPP, and a compiled filter matches the
    frames tapped on both RX and TX.

    libpcap compiles DLT_PPP filters with the network layer at offset 4,
    after address/control and the protocol field.  pppoeN used to attach as
    DLT_PPP_ETHER (offset 8, a PPPoE header assumed) while tapping from the
    protocol field on, so 'icmp' matched nothing in either direction."""
    _pppoectl_up(driver, auth="pap")
    state = _wait_inet(driver)
    assert state["inet_peer"] == ACCEL_GW, state
    script = (
        "rm -f /tmp/pppoe-bpf.txt; "
        f"timeout 20 tcpdump -n -l -i pppoe0 -c 2 'icmp and host {ACCEL_GW}' "
        "> /tmp/pppoe-bpf.txt 2>&1 & sleep 2; "
        f"ping -c 3 -i 0.5 {ACCEL_GW} > /dev/null; wait; "
        "cat /tmp/pppoe-bpf.txt")
    r = driver.run("sh -c " + shlex.quote(script), root=True, timeout=40)
    out = r.stdout
    assert "link-type PPP (PPP)" in out, out
    assert "ICMP echo request" in out and "ICMP echo reply" in out, out


def test_ipcp_negotiates_pool_address_and_dns_through_pppoectl(driver, server, sniffer):
    """With query-dns=3 the in-kernel IPCP (sppp_ipcp) must request the
    primary/secondary DNS options (129/130) and Configure-Ack the pool
    address; the iface must come up with the negotiated pool IP and the
    accel-ppp gateway as peer (R010)."""
    sniffer.start()
    _pppoectl_up(driver, auth="pap", query_dns=True)

    deadline = time.time() + 15
    dns_values = set()
    while time.time() < deadline:
        state = _wait_inet(driver, timeout=10)
        if state["inet"]:
            for p in sniffer.packets:
                if not p.haslayer(ppp.PPP_IPCP):
                    continue
                ipcp = p[ppp.PPP_IPCP]
                if ipcp.code != 2:  # Configure-Ack: an agreed value
                    continue
                for opt in ipcp.options:
                    if opt.type == 129 and getattr(opt, "data", "0.0.0.0") != "0.0.0.0":
                        dns_values.add(opt.data)
            if dns_values:
                break
        time.sleep(1)
    sniffer.stop()

    assert state["inet"] and ACCEL_POOL_RE.match(state["inet"]), (
        f"no pool address negotiated on the if_pppoe backend: {state}"
    )
    assert state["inet_peer"] == ACCEL_GW, state
    assert dns_values == {"10.99.0.1"}, (
        f"negotiated primary DNS != accel-ppp 10.99.0.1: {dns_values}"
    )


def _parent_up(driver, parent="vtnet1"):
    r = driver.run(f"ifconfig {parent} up", root=True)
    assert r.returncode == 0, f"ifconfig {parent} up: {r.stdout}\n{r.stderr}"


def test_parent_down_drops_discovery_and_session_frames(driver, accel_server):
    """Nothing may reach a parent that is not IFF_UP and IFF_DRV_RUNNING.

    vtnet_txq_mq_start() divides by its active queue-pair count, zero until
    vtnet_init() has run, so a PADI to a vtnet that was not running yet
    panicked the client ("Fatal trap 18: integer divide fault").
    pppoe_output_frame() and pppoe_encap_output() now drop such frames and
    count them in net.pppoe.tx_parent_down.

    Discovery: `ifconfig vtnet1 down`, then dial -- the PADIs are dropped
    and counted, the FSM stays at PADI_SENT, nothing panics, and once the
    parent is back up the PADI timer alone dials a session.  Session: with
    that session up, down the parent again and ping the AC -- the IP and LCP
    frames are dropped and counted, on pppoe0's Oerrs too."""
    from hardening_probe import _serial_offset
    from test_lifecycle import _no_panic_since

    offset = _serial_offset()
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    try:
        r = driver.run("ifconfig vtnet1 down", root=True)
        assert r.returncode == 0, f"ifconfig vtnet1 down: {r.stderr}"
        down0 = driver.counter("tx_parent_down")
        driver.up("pppoe0")
        assert wait_until(
            lambda: driver.counter("tx_parent_down") > down0, timeout=10,
            desc="a dropped PADI counted in tx_parent_down"), (
            f"tx_parent_down stayed at {down0} with vtnet1 down")
        parms = driver.parms()
        assert parms["state"] == PPPOE_STATE_PADI_SENT, parms
        _no_panic_since(offset, "dialling on a parent that is down")

        _parent_up(driver)
        # PADI back-off is 5s, 10s, 20s, ...: the timer must redial alone.
        parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=45)
        assert parms["state"] == PPPOE_STATE_SESSION, (
            f"no session after vtnet1 came back up: {parms}\n"
            f"accel-ppp log:\n{accel_server.log_tail(30)}")
        state = _wait_inet(driver)
        assert state["inet"], f"no IPCP address: {state}"

        r = driver.run("ifconfig vtnet1 down", root=True)
        assert r.returncode == 0, f"ifconfig vtnet1 down: {r.stderr}"
        down0 = driver.counter("tx_parent_down")
        oerr0 = _oerrs(driver)
        driver.run(f"ping -c 3 -i 0.2 -t 3 {ACCEL_GW}", root=True)
        # The driver has no link-event handler, so nothing closes the
        # session while vtnet1 is down; if something ever does, encap
        # returns ENETDOWN without counting and the check below would fail
        # for that reason instead.
        parms = driver.parms()
        assert parms["state"] == PPPOE_STATE_SESSION, (
            f"session closed while vtnet1 was down: {parms}")
        assert driver.counter("tx_parent_down") >= down0 + 3, (
            "session frames to a down parent were not counted in "
            "tx_parent_down")
        assert _oerrs(driver) >= oerr0 + 3, "pppoe0 Oerrs did not rise"
        _no_panic_since(offset, "sending session frames to a down parent")
    finally:
        _parent_up(driver)


def _oerrs(driver, iface="pppoe0"):
    """pppoe0's Oerrs column from `netstat -I <iface> -n` (Link row)."""
    out = driver.run(f"netstat -I {iface} -n").stdout.splitlines()
    hdr = out[0].split()
    # Counted from the right: pppoe0's Link row has an empty Address column.
    assert hdr[-2:] == ["Oerrs", "Coll"], f"netstat header: {out[0]}"
    row = next(l.split() for l in out[1:] if "<Link" in l)
    return int(row[-2])
