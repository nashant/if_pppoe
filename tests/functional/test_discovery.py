"""PPPoE discovery stage (PADI/PADO/PADR/PADS/PADT) against SERVER=accel.

Every assertion is on frames captured live on br-isp (or on client/server
state that only the discovery exchange could have produced) -- see
conftest.py's `sniffer` fixture and lab.py's `pppoe_tags`.
"""
from __future__ import annotations

import time

from scapy.all import PPPoED

from lab import ACCEL_AC_NAME, PADI, PADO, PADR, PADS, PADT, TAG_AC_NAME, TAG_HOST_UNIQ, active_creds, pppoe_tags


def _discovery_frames(sniffer):
    return [p for p in sniffer.packets if p.haslayer(PPPoED)]


def test_padi_pado_padr_pads_ordering_and_hostuniq(client, sniffer, wait_iface_up):
    sniffer.start()
    client.dial(service="lab")
    # Wait for the session instead of a blind sleep(2): dial() is six ssh
    # round-trips and the in-kernel discovery itself is sub-second once up()
    # fires, so the assertion below must not depend on how fast those ssh
    # calls return -- the datapath twin (test_padi_pado_padr_pads_against_accel)
    # likewise waits for PPPOE_STATE_SESSION before asserting on the codes.
    state = wait_iface_up(client, timeout=20)
    sniffer.stop()
    assert state["up"] and state["inet"], (
        "session never came up, so the discovery-exchange window cannot be "
        f"trusted: {state}; captured {len(sniffer.packets)} frames; driver FSM: "
        f"{client.parms()}"
    )

    frames = _discovery_frames(sniffer)
    codes = [p[PPPoED].code for p in frames]
    # The four discovery codes must all appear, each at least once, in the
    # canonical RFC 2516 order (later phases may repeat if mpd5 retries).
    # (The sniffer's own 0xFF readiness probe may appear in `codes`; see
    # lab.PPPoESniffer._wait_capture_live -- it matches none of these codes.)
    for code in (PADI, PADO, PADR, PADS):
        assert code in codes, (
            f"code {code:#x} missing from captured discovery frames: {codes} "
            f"({len(frames)} discovery / {len(sniffer.packets)} total frames)"
        )
    first_idx = {code: codes.index(code) for code in (PADI, PADO, PADR, PADS)}
    assert first_idx[PADI] < first_idx[PADO] < first_idx[PADR] < first_idx[PADS], (
        f"discovery frames out of order: {[(hex(c)) for c in codes]}"
    )

    padi = frames[codes.index(PADI)]
    pado = frames[codes.index(PADO)]
    padr = frames[codes.index(PADR)]
    host_uniq = pppoe_tags(padi).get(TAG_HOST_UNIQ)
    assert host_uniq, "PADI carried no Host-Uniq tag"
    assert pppoe_tags(pado).get(TAG_HOST_UNIQ) == host_uniq, "PADO did not echo PADI's Host-Uniq"
    assert pppoe_tags(padr).get(TAG_HOST_UNIQ) == host_uniq, "PADR did not echo PADI's Host-Uniq"


def test_empty_service_name_accepted(client, sniffer, wait_iface_up):
    sniffer.start()
    client.dial(service="")
    state = wait_iface_up(client, timeout=20)
    sniffer.stop()

    assert state["up"] and state["inet"], (
        f"blank Service-Name PADI was not accepted (accel accept-blank-service=1): {state}"
    )
    frames = _discovery_frames(sniffer)
    assert any(p[PPPoED].code == PADS for p in frames), "no PADS observed for blank Service-Name"


def test_mismatched_service_name_no_pads(client, sniffer):
    sniffer.start()
    client.dial(service="not-a-real-service")
    first_padi = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADI, timeout=15
    )
    assert first_padi is not None, (
        "client never sent a PADI at all for a mismatched Service-Name"
    )
    # Proving a negative (no PADS ever) needs a bounded dwell, but anchor it
    # to the first observed PADI -- not a blind sleep from dial() -- so the
    # settle window starts only once discovery is actually under way.
    time.sleep(5)
    sniffer.stop()

    frames = _discovery_frames(sniffer)
    assert not any(p[PPPoED].code == PADS for p in frames), (
        "accel-ppp sent a PADS for a mismatched Service-Name -- expected discard"
    )
    state = client.iface_state()
    # IFF_UP is administrative (set by `ifconfig pppoe0 up` in dial()) and
    # stays set even though no session ever established: with the in-kernel
    # client the session-state signal is the negotiated IPv4 address, which
    # the mismatched service name must never produce (no PADS -> no IPCP).
    assert state["inet"] is None, (
        f"pppoe0 negotiated an address despite mismatched service name: {state}"
    )


def test_ac_name_in_pado(client, sniffer):
    sniffer.start()
    client.dial(service="lab")
    # Wait for the PADO itself instead of a blind sleep(2).
    sniffer.wait_for(lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADO, timeout=15)
    sniffer.stop()

    frames = _discovery_frames(sniffer)
    pados = [p for p in frames if p[PPPoED].code == PADO]
    assert pados, "no PADO captured"
    ac_names = {pppoe_tags(p).get(TAG_AC_NAME) for p in pados}
    assert ac_names == {ACCEL_AC_NAME.encode()}, f"PADO AC-Name != {ACCEL_AC_NAME!r}: {ac_names}"


def test_server_initiated_terminate_padt_and_redial(client, accel_server, sniffer, wait_iface_up):
    client.dial(service="lab")
    before = wait_iface_up(client, timeout=20)
    assert before["up"] and before["inet"], f"client never came up before terminate test: {before}"

    # The account is generated per run (labcreds.lab_session), not a fixed "lab".
    user = active_creds().user
    sessions_before = accel_server.sessions()
    assert any(s.get("username") == user and s.get("state") == "active" for s in sessions_before), (
        f"no active {user!r} session on the server before terminate: {sessions_before}"
    )

    sniffer.start()
    accel_server.terminate_all("hard")
    padt = sniffer.wait_for(lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADT, timeout=15)
    assert padt is not None, "no PADT observed after server-initiated terminate"
    sniffer.stop()

    after = wait_iface_up(client, timeout=60)
    assert after["up"] and after["inet"], f"client did not re-dial within 60s after terminate: {after}"


def test_client_hangup_sends_padt(client, sniffer):
    client.dial(service="lab")
    client_mac = client.mac

    sniffer.start()
    client.hangup()
    padt = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADT and p.src.lower() == client_mac.lower(),
        timeout=15,
    )
    sniffer.stop()
    assert padt is not None, "no client-sourced PADT observed after client hangup"

    # restored to "lab" by the autouse fixture; mpd5 itself is stopped, so
    # bring it back explicitly here too (dial() implies a restart).
    client.dial(service="lab")
