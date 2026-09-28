"""Malformed/stray PPPoE frame robustness tests.

Phase 0 (client-agnostic): inject 200 malformed PPPoE frames at the client
and assert its session survives: address unchanged, ping to the gateway
works, ssh still reachable.

Driver-specific (CLIENT=if_pppoe only, skipped otherwise): the in-kernel
driver's net.pppoe.term_unknown policy (S01 T01) -- a rate-limited PADT for
a stale session of ours, off by default, never for a session it cannot
attribute -- plus its malformed-discovery resilience
and still-dials-after guarantee.  These need driver sysctls/counters that
only exist behind the in-kernel kmod, so they skip cleanly under CLIENT=mpd5
(the Phase 0 test below runs for both backends).
"""
from __future__ import annotations

import os
import random
import time

import pytest
from scapy.all import Ether, PPPoED, RandMAC, Raw

from lab import CLIENT_MAC, ETH_PPPOE_DISCOVERY, ETH_PPPOE_SESSION, PADS, PADT

# Skip gate for the driver-specific cases: net.pppoe.term_unknown /
# net.pppoe.padt_unknown only exist when the client VM runs the in-kernel
# if_pppoe kmod.  Under CLIENT=mpd5 these tests skip (T03 expects the Phase
# 0 case green and these three skipped there).
_DRIVER_ONLY = pytest.mark.skipif(
    os.environ.get("CLIENT", "mpd5") != "if_pppoe",
    reason="driver-specific: needs the in-kernel if_pppoe client "
    "(net.pppoe.term_unknown / net.pppoe.padt_unknown)",
)

# Source MAC for frames we inject as a bogus third peer.  Locally
# administered, distinct from every MAC the lab allocates (client
# 52:54:00:aa:00:01, mpdsrv, accel, FOREIGN_MAC, sniffer probe src), so PADTs
# the driver sends in reply are recognisable by their destination and the
# AC's own (teardown) PADTs never collide with our assertions.
STRAY_MAC = "02:73:aa:bb:cc:01"


def _pppoe_header(code: int, session_id: int, payload: bytes, declared_len: int | None = None) -> bytes:
    length = len(payload) if declared_len is None else declared_len
    return bytes([0x11, code]) + session_id.to_bytes(2, "big") + length.to_bytes(2, "big") + payload


def _malformed_frames(dst_mac: str, count: int) -> list:
    frames = []
    per = count // 5

    # 1. Truncated tags: PPPoE header's declared length is larger than the
    #    tag data actually present.
    for _ in range(per):
        tag = bytes([0x01, 0x03, 0x00, 0x10]) + os.urandom(4)  # tag_len=16, only 4 bytes given
        hdr = _pppoe_header(0x09, 0, tag, declared_len=len(tag) + 12)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 2. Oversize PPPoE length field (claims far more payload than sent).
    for _ in range(per):
        payload = os.urandom(8)
        hdr = _pppoe_header(0x09, 0, payload, declared_len=1400)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 3. Unknown/reserved tag types.
    for _ in range(per):
        tag = (0x7FFF).to_bytes(2, "big") + (4).to_bytes(2, "big") + os.urandom(4)
        hdr = _pppoe_header(0x07, 0, tag)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 4. Session-stage data frame with a random/wrong session id.
    for _ in range(per):
        sess = random.randint(1, 0xFFFE)
        ppp_payload = bytes([0xC0, 0x21]) + os.urandom(6)
        hdr = _pppoe_header(0x00, sess, ppp_payload)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_SESSION) / Raw(load=hdr))

    # 5. PADS with a bogus session id, unsolicited.
    remaining = count - per * 4
    for _ in range(remaining):
        sess = random.randint(1, 0xFFFE)
        hdr = _pppoe_header(0x65, sess, b"")
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    random.shuffle(frames)
    return frames


@pytest.mark.fuzz
def test_client_survives_malformed_pppoe_frames(client, sniffer, wait_iface_up):
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client not up before fuzzing: {before}"

    frames = _malformed_frames(client.mac, 200)
    sniffer.send(frames)
    time.sleep(3)

    after = client.iface_state()
    assert after["up"] and after["inet"] == before["inet"], (
        f"client session did not survive fuzzing: before={before} after={after}"
    )

    ping = client.run(f"ping -c3 -t5 {before['inet_peer']}")
    assert ping.returncode == 0, f"ping to gateway failed after fuzzing: {ping.stdout}\n{ping.stderr}"

    ssh_check = client.run("echo alive")
    assert ssh_check.returncode == 0 and "alive" in ssh_check.stdout, (
        f"client VM not reachable over ssh after fuzzing: {ssh_check}"
    )


def _stray_session_frames(dst_mac: str, count: int) -> list:
    """Session-stage frames for session ids the driver cannot know.

    Unicast to the parent's lladdr (the driver's term_unknown gate answers
    only a frame addressed to the parent -- broadcast garbage is not a
    teardown request) with a fixed bogus source MAC (STRAY_MAC): any PADT
    the driver sends back is addressed to that MAC, so the reply is trivial
    to distinguish from every other PADT on the segment.
    """
    frames = []
    for _ in range(count):
        sess = random.randint(1, 0xFFFE)
        ppp_payload = bytes([0xC0, 0x21]) + os.urandom(6)
        hdr = _pppoe_header(0x00, sess, ppp_payload)
        frames.append(Ether(dst=dst_mac, src=STRAY_MAC, type=ETH_PPPOE_SESSION) / Raw(load=hdr))
    return frames


def _padts_to_stray(sniffer) -> list:
    """PADT frames captured on the segment addressed to our stray peer."""
    return [
        p
        for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADT and p.dst.lower() == STRAY_MAC
    ]


def _session_and_ac(client, sniffer) -> tuple[int, str]:
    """The live session id and the AC's MAC, read off that session's PADS."""
    session = client.parms()["session"]
    assert session, f"no live PPPoE session id: {client.parms()}"
    pads = [
        p for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADS
        and p[PPPoED].sessionid == session
    ]
    assert pads, f"no PADS for session {session} captured; AC MAC unknown"
    return session, pads[-1][Ether].src.lower()


def _stale_session_frames(dst_mac: str, ac_mac: str, session: int, count: int) -> list:
    """Session frames from our AC for a session of ours that has ended."""
    hdr = _pppoe_header(0x00, session, bytes([0xC0, 0x21]) + b"\x09" * 6)
    return [Ether(dst=dst_mac, src=ac_mac, type=ETH_PPPOE_SESSION) / Raw(load=hdr)] * count


@_DRIVER_ONLY
@pytest.mark.fuzz
def test_unknown_session_padt_is_rate_limited(client, sniffer, wait_iface_up):
    """term_unknown=1, term_unknown_pps=1: 200 frames from our AC for the
    session this interface just closed draw at least one PADT but at most
    ~5 (ppsratecheck's 1/s cap), and padt_unknown moves in step.  The frames
    arrive in batches spread over ~4s so the per-second budget is actually
    exercised.  The live (new) session is untouched.

    A stale session of ours is the only unknown session the driver may
    attribute: with pfil passing foreign frames (p3-pfil-counters) a session
    it cannot attribute may be a same-NIC mpd5's, and must never draw a PADT
    (test_unattributable_unknown_session_is_passed_without_padt).
    """
    # Start the capture before dialing: the readiness probe proves the BPF
    # attach beat the fast in-kernel dial, so both PADS are captured.
    sniffer.start()
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client not up before fuzzing: {before}"
    stale, ac_mac = _session_and_ac(client, sniffer)

    # accel-ppp's allocate_channel() advances its sid bitmap one word per
    # allocation, so a just-freed id returns only after a wrap: rare, so
    # redial rather than fail (test_reissued_stale_session_id_is_not_padted
    # covers the reissue itself).
    for _ in range(3):
        client.restart_link()
        before = wait_iface_up(client, timeout=30)
        assert before["up"] and before["inet"], f"client not back up: {before}"
        live, _ = _session_and_ac(client, sniffer)
        if live != stale:
            break
        stale = live  # this close recorded the reissued id as the stale one
    else:
        pytest.skip(
            f"the AC reissued session id {stale} on every redial; the stale id "
            "is live, so this run cannot exercise the stale-session path"
        )

    r = client.run("sysctl net.pppoe.term_unknown=1 net.pppoe.term_unknown_pps=1", root=True)
    assert r.returncode == 0, f"sysctl term_unknown setup failed: {r.stdout}\n{r.stderr}"
    try:
        unknown_before = client.counter("padt_unknown")
        mark = len(sniffer.packets)  # restart_link's own teardown PADT is before this

        for _ in range(10):
            sniffer.send(_stale_session_frames(client.mac, ac_mac, stale, 20))
            time.sleep(0.35)
        time.sleep(2)  # let the last rate-limit window drain

        padts = [
            p for p in sniffer.packets[mark:]
            if p.haslayer(PPPoED) and p[PPPoED].code == PADT
            and p.dst.lower() == ac_mac and p[PPPoED].sessionid == stale
            and p.src.lower() == client.mac.lower()
        ]
        delta = client.counter("padt_unknown") - unknown_before
        assert delta >= 1, (
            f"padt_unknown did not move under term_unknown=1 "
            f"(delta={delta}) -- the stale-session PADT path did not fire"
        )
        assert delta <= 5, (
            f"padt_unknown moved {delta} times in ~4s at term_unknown_pps=1 "
            "-- the rate limiter is not capping sends"
        )
        assert 1 <= len(padts) <= 5, (
            f"{len(padts)} PADTs for stale session {stale} on the wire for "
            "200 frames at term_unknown_pps=1 -- expected the rate-limited 1..5 window"
        )

        after = client.iface_state()
        assert after["up"] and after["inet"] == before["inet"], (
            f"live session did not survive the stale flood: before={before} after={after}"
        )
        assert client.parms()["session"] == live, client.parms()
    finally:
        r = client.run("sysctl net.pppoe.term_unknown=0", root=True)
        assert r.returncode == 0, (
            f"term_unknown restore failed -- later tests would see the "
            f"feature enabled: {r.stdout}\n{r.stderr}"
        )


@_DRIVER_ONLY
@pytest.mark.fuzz
def test_unattributable_unknown_session_is_passed_without_padt(client, sniffer, wait_iface_up):
    """term_unknown=1 must still never PADT a session the driver cannot
    attribute to itself (random ids from a peer that is not our AC): those
    frames are passed up the stack untouched -- they may belong to mpd5 on
    the same NIC -- and counted in passed_foreign."""
    sniffer.start()
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client not up before fuzzing: {before}"

    r = client.run("sysctl net.pppoe.term_unknown=1 net.pppoe.term_unknown_pps=100", root=True)
    assert r.returncode == 0, f"sysctl term_unknown setup failed: {r.stdout}\n{r.stderr}"
    try:
        unknown_before = client.counter("padt_unknown")
        passed_before = client.counter("passed_foreign")
        sniffer.send(_stray_session_frames(client.mac, 200))
        time.sleep(2)

        assert client.counter("padt_unknown") == unknown_before, (
            "padt_unknown moved for sessions the driver cannot attribute"
        )
        assert not _padts_to_stray(sniffer), (
            "PADTs reached a peer that is not our AC under term_unknown=1"
        )
        passed = client.counter("passed_foreign") - passed_before
        assert passed >= 200, f"passed_foreign moved {passed} for 200 stray frames"
        after = client.iface_state()
        assert after["up"] and after["inet"] == before["inet"], (
            f"live session did not survive the stray flood: before={before} after={after}"
        )
    finally:
        r = client.run(
            "sysctl net.pppoe.term_unknown=0 net.pppoe.term_unknown_pps=1", root=True
        )
        assert r.returncode == 0, (
            f"term_unknown restore failed: {r.stdout}\n{r.stderr}"
        )


@_DRIVER_ONLY
@pytest.mark.fuzz
def test_unknown_session_padt_is_off_by_default(client, sniffer, wait_iface_up):
    """term_unknown defaults to 0: a stray session frame flood draws NO PADT
    and the padt_unknown counter does not move.  Depends on the rate-limit
    test's finally-reset (pytest runs this file in definition order) so the
    readback here really is the module default, not a leftover from the
    enabled case.
    """
    assert client.sysctl("net.pppoe.term_unknown") == "0", (
        "net.pppoe.term_unknown is not the documented default 0 -- a prior "
        "test leaked the setting (its restore must not be skipped)"
    )

    # Same unstarted-capture caveat as the rate-limit test: without start()
    # the not-PADTs-to-stray assertion below would pass vacuously over an
    # empty capture.  Starting before the dial keeps the probe's attach
    # guarantee in force for the whole flood.
    sniffer.start()
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client not up before fuzzing: {before}"

    unknown_before = client.counter("padt_unknown")
    sniffer.send(_stray_session_frames(client.mac, 200))
    time.sleep(2)

    delta = client.counter("padt_unknown") - unknown_before
    assert delta == 0, (
        f"padt_unknown moved {delta} with term_unknown=0 -- the feature is "
        "not actually gated off by default"
    )
    assert not _padts_to_stray(sniffer), (
        "PADTs reached the stray peer with term_unknown=0 -- the sysctl "
        "gate is not honouring the default-off policy"
    )

    after = client.iface_state()
    assert after["up"] and after["inet"] == before["inet"], (
        f"live session did not survive the stray flood: before={before} after={after}"
    )


def _malformed_discovery_frames(dst_mac: str, count: int) -> list:
    """Discovery-stage frames whose defects sit in the tag/length parse:
    tag length past the end of the frame, an oversized plen, a zero-length
    body, and a wrong VERTYPE.  Distinct from the Phase 0 set, which has no
    zero-length or VERTYPE case.
    """
    frames = []
    per = count // 4

    # 1. Tag length past end: tag header declares 16 bytes of value, 4 given.
    for _ in range(per):
        tag = bytes([0x01, 0x03, 0x00, 0x10]) + os.urandom(4)
        hdr = _pppoe_header(0x09, 0, tag, declared_len=len(tag) + 12)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 2. Oversized plen: header claims 1400 bytes of payload, 8 sent.
    for _ in range(per):
        payload = os.urandom(8)
        hdr = _pppoe_header(0x09, 0, payload, declared_len=1400)
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 3. Zero-length body: valid VERTYPE/code, no tags at all, plen=0.
    for _ in range(per):
        hdr = _pppoe_header(0x09, 0, b"")
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    # 4. Wrong VERTYPE: first byte is not PPPOE_VERTYPE (0x11) -- version
    #    2 garbage the parsers must reject before touching any tag data.
    for _ in range(count - per * 3):
        payload = os.urandom(8)
        hdr = bytes([0x21, 0x09, 0, 0]) + (0).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
        frames.append(Ether(dst=dst_mac, src=RandMAC(), type=ETH_PPPOE_DISCOVERY) / Raw(load=hdr))

    random.shuffle(frames)
    return frames


@_DRIVER_ONLY
@pytest.mark.fuzz
def test_malformed_discovery_tags_do_not_wedge_the_driver(client, sniffer, wait_iface_up):
    """Tag-length-past-end / oversized-plen / zero-length-body / wrong-VERTYPE
    floods leave the VM responsive (ssh alive, gateway pingable) and the
    driver still able to dial a fresh session afterwards.
    """
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client not up before fuzzing: {before}"

    sniffer.send(_malformed_discovery_frames(client.mac, 200))
    time.sleep(3)

    after = client.iface_state()
    assert after["up"] and after["inet"] == before["inet"], (
        f"client session did not survive the malformed-tag flood: "
        f"before={before} after={after}"
    )

    ping = client.run(f"ping -c3 -t5 {before['inet_peer']}")
    assert ping.returncode == 0, (
        f"ping to gateway failed after malformed-tag flood: {ping.stdout}\n{ping.stderr}"
    )

    ssh_check = client.run("echo alive")
    assert ssh_check.returncode == 0 and "alive" in ssh_check.stdout, (
        f"client VM not reachable over ssh after malformed-tag flood: {ssh_check}"
    )

    # Still able to dial: tear the surviving session down and establish a
    # fresh one -- the parser floods must not have wedged the discovery FSM
    # or the clone lifecycle.
    client.hangup()
    client.dial(service="lab")
    redialed = wait_iface_up(client, timeout=30)
    assert redialed["up"] and redialed["inet"], (
        f"driver could not dial after the malformed-tag flood: {redialed}"
    )
