"""LCP layer: MRU, echo keepalive, magic number, PAP/CHAP auth, bad-password backoff."""
from __future__ import annotations

import time

import pytest
import scapy.layers.ppp as ppp
from scapy.all import PPPoED, Ether

from lab import PADI, PADS, TAG_MAX_PAYLOAD, pppoe_tags


def test_mru_1492_with_accel(client, wait_iface_up):
    client.dial(service="lab")
    state = wait_iface_up(client, timeout=20)
    assert state["mtu"] == 1492, f"expected MRU/MTU 1492 with accel-ppp, got: {state}"


@pytest.mark.needs_mpdsrv
def test_mru_mtu_1500_with_mpdsrv(client, sniffer, wait_iface_up):
    """RFC 4638 max-payload against the mpdsrv VM with the in-kernel client.

    The old xfail described the *mpd5 client* never emitting the RFC 4638
    PPP-Max-Payload tag (0x0120) on the wire; the in-kernel client emits it
    whenever the administrator raises the MTU above 1492 (the datapath
    suite proves the same offer/clamp/write-back against accel-ppp).  mpd5
    5.9_19 as a *server*, however, is tag-silent on the reply side -- S04's
    live vector captured PADO/PADS carrying no tag even when the PADI
    offered 0x05dc, and the probe behind this flip re-proved it live -- so
    the driver's RFC 4638 section 5.1 PADS write-back must honestly hold
    pppoe0 at the standard 1492: never above the peer's grant.  The
    expected MTU is therefore computed from the wire (the PADS grant when
    the peer echoes one, else the 1492 default), so this test keeps
    asserting the driver's conformance verbatim if a later mpd5 ever
    grants 1500.  The full 1500-byte payload round-trip stays blocked on
    the tag-silent server (lab/vm/README.md "Known issue: mpd5 RFC4638
    max-payload does not reach 1500 on the wire"); raising br-isp/tap MTUs
    to >= 1508 is the other recorded prerequisite.
    """
    original_parent_mtu = client.iface_state("vtnet1")["mtu"]
    assert original_parent_mtu is not None, "could not read vtnet1's MTU"
    r = client.run("ifconfig vtnet1 mtu 1508", root=True)
    assert r.returncode == 0, (
        f"could not set vtnet1 MTU to 1508: {r.stdout}\n{r.stderr}"
    )
    try:
        sniffer.start()
        client.dial(service="mpdlab",
                    mtu=1500, max_payload=1500)
        state = wait_iface_up(client, timeout=20)
    finally:
        sniffer.stop()
        r = client.run(f"ifconfig vtnet1 mtu {original_parent_mtu}", root=True)
        assert r.returncode == 0, (
            f"could not restore vtnet1 MTU to {original_parent_mtu} -- every "
            f"later test now runs against a mutated parent: {r.stdout}\n{r.stderr}"
        )

    # The session must be with the mpdsrv VM (mpdlab pool 10.99.2.x).
    assert state["inet"] and state["inet"].startswith("10.99.2."), (
        f"session did not come up from the mpdlab pool: {state}"
    )

    # The client side of RFC 4638 is the part the mpd5 client never did:
    # the PADI must offer the administrator's 1500 as tag 0x0120.
    padis = [p for p in sniffer.packets
             if p.haslayer(PPPoED) and p[PPPoED].code == PADI]
    assert padis, "no PADI captured"
    offered = pppoe_tags(padis[0]).get(TAG_MAX_PAYLOAD)
    assert offered == b"\x05\xdc", (
        f"PADI did not offer PPP-Max-Payload 1500: {pppoe_tags(padis[0])}"
    )

    # The expected MTU is whatever the server granted on the wire (a PADS
    # tag above 1492), else the RFC 4638 5.1 default of 1492 -- never above
    # the peer's grant.  Today's mpd5 5.9_19 echoes nothing (tag-silent).
    padss = [p for p in sniffer.packets
             if p.haslayer(PPPoED) and p[PPPoED].code == PADS]
    assert padss, "no PADS captured"
    grant = pppoe_tags(padss[0]).get(TAG_MAX_PAYLOAD)
    if grant is not None and int.from_bytes(grant, "big") > 1492:
        expected = min(int.from_bytes(grant, "big"), 1500)
    else:
        expected = 1492
    assert state["mtu"] == expected, (
        f"pppoe0 MTU {state['mtu']} != the RFC 4638 5.1 value {expected} for "
        f"the captured PADS grant {grant!r}:\n{state['raw']}"
    )


def test_lcp_echo_interval(client, sniffer):
    def _is_client_echo_req(p) -> bool:
        return (
            p.haslayer(ppp.PPP_LCP_Echo)
            and p[ppp.PPP_LCP_Echo].code == 9
            and p[Ether].src.lower() == client.mac.lower()
        )

    sniffer.start()
    client.dial(service="lab")

    # The measurement is inherently time-based (proving a ~10s echo
    # cadence), but anchor it to the first observed echo instead of a
    # blind sleep from dial(): LCP-Opened timing (and so the first echo)
    # varies with negotiation speed, worse on the SMPW debug kernel.
    first = sniffer.wait_for(_is_client_echo_req, timeout=30)
    assert first is not None, "no LCP echo-request observed within 30s of dial"
    second = sniffer.wait_for(
        lambda p: _is_client_echo_req(p) and p.time > first.time, timeout=15
    )
    sniffer.stop()
    assert second is not None, "only one LCP echo-request observed within 15s of the first"

    echoes = sorted(p.time for p in sniffer.packets if _is_client_echo_req(p))
    assert len(echoes) >= 2, f"expected >=2 LCP echo-requests, saw {len(echoes)}"
    deltas = [b - a for a, b in zip(echoes, echoes[1:])]
    assert all(8 <= d <= 13 for d in deltas), f"echo-request spacing not ~10s: {deltas}"


def test_magic_number_present(client, sniffer):
    # Filter to CLIENT-sent Configure frames only: collecting both
    # directions let the server's own magic number satisfy this assertion
    # even if the driver never emitted one, which is what we're testing.
    def _client_lcp_configure(p) -> bool:
        return p.haslayer(ppp.PPP_LCP_Configure) and p[Ether].src.lower() == client.mac.lower()

    sniffer.start()
    client.dial(service="lab")
    first = sniffer.wait_for(_client_lcp_configure, timeout=20)
    sniffer.stop()
    assert first is not None, "no client-sent LCP Configure-Request/Ack captured within 20s"

    configs = [p[ppp.PPP_LCP_Configure] for p in sniffer.packets if _client_lcp_configure(p)]
    assert configs, "no client-sent LCP Configure-Request/Ack captured"
    magic_values = [
        opt.magic_number
        for cfg in configs
        for opt in cfg.options
        if hasattr(opt, "magic_number")
    ]
    assert magic_values, "no LCP Magic-Number option seen in any client-sent Configure frame"
    assert all(m not in (None, 0) for m in magic_values), f"magic number present but zero: {magic_values}"


def test_pap_success(client, sniffer, wait_iface_up):
    sniffer.start()
    client.dial(service="lab", accept=("pap",))
    wait_iface_up(client, timeout=20)
    # Wait for the Ack frame itself instead of a blind sleep(1) "buffer":
    # iface-up can be observed slightly before the sniffer's async capture
    # thread has appended the Ack it raced with.
    sniffer.wait_for(
        lambda p: p.haslayer(ppp.PPP_PAP_Response) and p[ppp.PPP_PAP_Response].code == 2,
        timeout=5,
    )
    sniffer.stop()

    # scapy's haslayer() is exact-class by default (no subclass match), and
    # PAP-Ack/-Nak dissect as PPP_PAP_Response (a PPP_PAP subclass), not
    # PPP_PAP itself -- verified live (`haslayer(PPP_PAP)` was 0 for a
    # captured PAP-Ack whose actual type was PPP_PAP_Response).
    acks = [p for p in sniffer.packets if p.haslayer(ppp.PPP_PAP_Response) and p[ppp.PPP_PAP_Response].code == 2]
    assert acks, "no PAP Authenticate-Ack observed with accept=('pap',)"
    state = client.iface_state()
    assert state["up"] and state["inet"], f"PAP succeeded on the wire but iface didn't come up: {state}"


def test_chap_md5_success(client, sniffer, wait_iface_up):
    sniffer.start()
    client.dial(service="lab", accept=("chap",))
    wait_iface_up(client, timeout=20)
    # See test_pap_success: wait for the Success frame itself, not a blind
    # sleep(1) buffer for the sniffer's capture thread to catch up.
    sniffer.wait_for(
        lambda p: p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 3,
        timeout=5,
    )
    sniffer.stop()

    chap_success = [p for p in sniffer.packets if p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 3]
    assert chap_success, "no CHAP Success observed with accept=('chap',)"
    state = client.iface_state()
    assert state["up"] and state["inet"], f"CHAP succeeded on the wire but iface didn't come up: {state}"


def test_default_auth_whichever_chosen_is_logged(client, sniffer, wait_iface_up):
    """accel-ppp/mpd5 negotiate whichever of pap/chap/eap both sides allow;
    the brief only requires we assert whichever it chose is logged."""
    sniffer.start()
    client.dial(service="lab")
    wait_iface_up(client, timeout=20)
    # See test_pap_success: wait for whichever success frame the
    # negotiation used, not a blind sleep(1) capture-catch-up buffer.
    sniffer.wait_for(
        lambda p: (p.haslayer(ppp.PPP_PAP_Response) and p[ppp.PPP_PAP_Response].code == 2)
        or (p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 3),
        timeout=5,
    )
    sniffer.stop()

    used = None
    for p in sniffer.packets:
        if p.haslayer(ppp.PPP_PAP_Response) and p[ppp.PPP_PAP_Response].code == 2:
            used = "pap"
        elif p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 3:
            used = "chap"
    assert used is not None, "no PAP-Ack or CHAP-Success observed for the default auth negotiation"
    state = client.iface_state()
    assert state["up"], f"negotiated auth ({used}) did not bring the link up: {state}"


def test_bad_password_no_ipcp_backoff(client, sniffer):
    sniffer.start()
    client.dial(service="lab", password="not-the-password")

    # Anchor the redial-cadence measurement below to the first observed
    # PADI (fail fast if the client never redials at all) rather than
    # counting from dial() itself, whose own duration varies with the
    # mpd5 restart speed (worse on the SMPW debug kernel).
    first_padi = sniffer.wait_for(
        lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADI, timeout=10
    )
    assert first_padi is not None, "no PADI observed at all after a bad-password dial"

    # The measurement itself is inherently time-based (proving a
    # >=2-redial-in-20s cadence, and that IPCP never starts across that
    # window), so a bounded dwell from the first PADI is unavoidable.
    time.sleep(20)
    sniffer.stop()

    state = client.iface_state()
    # IFF_UP stays set after `ifconfig pppoe0 up` even when authentication
    # fails (administrative state); the driver-side signal for "no session"
    # is the absence of a negotiated IPv4 address (no IPCP after failed
    # PAP/CHAP).  mpd5 leaves the interface down in the same situation, so
    # this assertion holds for both client backends.
    assert state["inet"] is None, (
        f"iface negotiated an address despite a bad password: {state}"
    )

    # Confirm the redials are actually failing auth (not silently refused
    # for some unrelated reason): a PAP-Nak or CHAP-Failure must appear.
    auth_failed = any(
        (p.haslayer(ppp.PPP_PAP_Response) and p[ppp.PPP_PAP_Response].code == 3)
        or (p.haslayer(ppp.PPP_CHAP) and p[ppp.PPP_CHAP].code == 4)
        for p in sniffer.packets
    )
    assert auth_failed, "no PAP Authenticate-Nak or CHAP Failure observed despite a bad password"

    padis = sorted(p.time for p in sniffer.packets if p.haslayer(PPPoED) and p[PPPoED].code == PADI)
    assert len(padis) >= 2, f"expected >=2 redial attempts (PADI) within 20s of bad-password, saw {len(padis)}"
    deltas = [b - a for a, b in zip(padis, padis[1:])]
    assert all(d >= 1.0 for d in deltas), f"client retried faster than 1/s: {deltas}"

    # Codes 1-4 (Configure-*) mean NCP is actually negotiating; 5/6
    # (Terminate-Request/Ack) are expected here -- confirmed live, they're
    # the *previous* session's IPCP being torn down by this dial()'s mpd5
    # restart, landing at the very start of this test's sniffer window.
    assert not any(
        p.haslayer(ppp.PPP_IPCP) and p[ppp.PPP_IPCP].code in (1, 2, 3, 4) for p in sniffer.packets
    ), "an IPCP Configure-* frame was observed despite a bad password -- NCP must not start before auth succeeds"
