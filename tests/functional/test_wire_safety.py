"""sppp wire-input memory safety (fix group g1-wire).

Every frame here is injected into a LIVE session: the real PPPoE session id
and the AC's real MAC (both read off the PADS of the dial the test itself
makes), unicast to the client's vtnet1.  That is what gets a frame past the
driver's (parent, session id, peer MAC) session lookup and into
sppp_input() -- a frame from any other MAC is counted as sess_nosession and
never reaches the PPP layer (test_datapath.py covers that half).

What each case pins, all inherited NetBSD sppp bugs in
sys/net/if_spppsubr.c:

  (a) an unknown PPP protocol (0x80FD, 0x8207) took sppp_input()'s
      `default:` arm straight to `reject_protocol:` WITHOUT the sppp lock,
      where the label asserts the lock and unlocks it -- a remote panic on
      the INVARIANTS/WITNESS kernel.  Fixed: the arm takes the lock, and a
      Protocol-Reject naming the protocol goes back while LCP is Opened.
  (b) a Configure-Request whose option list starts `00 00` made the
      LCP/IPCP/IPv6CP parsers `break` out of both passes and ACK, copying
      the whole option list into a buffer sized by a `u_char` -- 258 bytes
      of options into a 2-byte heap allocation.  Fixed: the buffer size is
      a size_t and an option length below 2 drops the packet, so no
      Configure-Ack echoing the malformed request ever leaves the client.
      Positive control: with IFF_DEBUG on, the parser's new drop exit logs
      "<cp> option 0x00 length 0, dropping" -- proof the frame reached the
      parser at all, rather than being dropped (or Protocol-Rejected)
      upstream of it, which would pass the no-ACK check vacuously.
  (b3) an option list with a lone trailing octet after the last option
      stopped both passes with len == 1 and was ACKed stray byte and all.
      Fixed: dropped (logged "<cp> trailing octet ..., dropping").
  (b2) a Configure-Request with an option longer than the list takes the
      parsers' CP_RCR_ERR exit, which never sets the buffer out-parameter
      -- and sppp_rcr_event() then freed its uninitialized `buf`.  Fixed:
      initialized; the ERR exit still restarts LCP, so the session must
      come back on its own.
  (c) a Protocol-Reject too short to carry the rejected-protocol field
      had p[0..1] read past the LCP length anyway.  Fixed: dropped (logged
      "lcp invalid proto-rej length 4").  A well-formed one (length 8)
      must still be parsed and logged as an RXJ for the protocol it names.

The unfixed kernel is expected to PANIC the client VM on (a) (and may on
(b), heap corruption being what it is), so every case asserts the VM is
still alive -- ssh answers within a bounded timeout and the client serial
log grew no panic signature -- before anything else.  A dead VM is a test
FAILURE, never a hang: every ssh here is bounded (lab._ssh timeout +
ConnectTimeout), and conftest's restore fixture swallows its own redial
failure.

Driver-only: the client must be the in-kernel sppp stack (CLIENT=if_pppoe).
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import time

import pytest
from scapy.all import Ether, PPPoED, Raw

from lab import ETH_PPPOE_SESSION, PADS
from unload_probe import SERIAL_LOG, _serial_offset, _serial_panic_hits, _serial_tail

pytestmark = [
    pytest.mark.fuzz,
    pytest.mark.skipif(
        os.environ.get("CLIENT", "mpd5") != "if_pppoe",
        reason="driver-specific: injects into the in-kernel sppp stack "
        "(CLIENT=if_pppoe)",
    ),
]

PPP_LCP, PPP_IPCP, PPP_IPV6CP = 0xC021, 0x8021, 0x8057
CONF_REQ, CONF_ACK, PROTO_REJ = 1, 2, 8
CP_NAME = {PPP_LCP: "lcp", PPP_IPCP: "ipcp", PPP_IPV6CP: "ipv6cp"}

# Ident for every injected control packet.  The Configure-Ack assertion in
# (b) also matches on the echoed length, so a real AC ConfReq that happens
# to reuse this ident can never be mistaken for our malformed one.
INJECT_IDENT = 0xA5


def _session_frame(dst_mac: str, src_mac: str, session: int, proto: int,
                   body: bytes):
    """A PPPoE session frame carrying PPP `proto` + `body`."""
    ppp = proto.to_bytes(2, "big") + body
    pppoe = (b"\x11\x00" + session.to_bytes(2, "big")
             + len(ppp).to_bytes(2, "big") + ppp)
    return Ether(dst=dst_mac, src=src_mac, type=ETH_PPPOE_SESSION) / Raw(pppoe)


def _cp_packet(code: int, ident: int, data: bytes,
               declared_len: int | None = None) -> bytes:
    """An LCP-style control packet (code, ident, length, data)."""
    length = 4 + len(data) if declared_len is None else declared_len
    return bytes([code, ident]) + length.to_bytes(2, "big") + data


def _client_ppp(sniffer, mac: str, session: int):
    """(protocol, payload) for every captured session frame the client sent
    on `session`.  Parsed off the raw PPPoE bytes (plen-bounded, so the
    Ethernet padding never leaks into a payload) rather than scapy's PPP
    layer binding."""
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
        if len(ppp) < 2:
            continue
        out.append((int.from_bytes(ppp[:2], "big"), ppp[2:]))
    return out


def _live_session(client, sniffer, wait_iface_up):
    """Dial service "lab" under capture; return (session id, AC MAC, state).

    The sniffer is left running so the caller sees the client's replies to
    whatever it injects next.
    """
    sniffer.start()
    client.dial(service="lab")
    state = wait_iface_up(client, timeout=30)
    assert state["up"] and state["inet"], f"client not up before injecting: {state}"
    session = client.parms()["session"]
    assert session, f"no live PPPoE session id: {client.parms()}"
    pads = [
        p for p in sniffer.packets
        if p.haslayer(PPPoED) and p[PPPoED].code == PADS
        and p[PPPoED].sessionid == session
    ]
    assert pads, (
        f"no PADS for live session {session} captured, so the AC's MAC is "
        "unknown and nothing injected could reach sppp_input()"
    )
    ac_mac = pads[-1][Ether].src.lower()
    assert ac_mac != client.mac.lower(), f"PADS source {ac_mac} is the client itself"
    return session, ac_mac, state


def _vm_alive(client) -> bool:
    try:
        r = client.run("echo wire-safety-alive", timeout=10)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 and "wire-safety-alive" in r.stdout


def _assert_survived(client, serial_offset: int, what: str):
    """The client VM is alive and its serial console shows no panic.

    Checked before any session assertion: after a panic the VM stops
    answering, and a bounded ssh probe is what turns that into a FAIL here
    instead of a hang or a confusing iface-state error further down.
    """
    alive = _vm_alive(client)
    tail = _serial_tail(serial_offset)
    hits = _serial_panic_hits(tail) if tail is not None else []
    assert alive and not hits, (
        f"client VM did not survive {what}: ssh alive={alive}, panic "
        f"signatures in {SERIAL_LOG}: {hits or '(none)'}"
        + ("" if tail is not None else " (serial log unreadable)")
    )


def _dmesg_count(client, needle: str) -> int:
    """Lines in the kernel message buffer containing `needle`.

    Callers compare a count taken before the injection with one taken
    after, never test for presence: the buffer may still hold lines from an
    earlier run.  (A ring wrap in the seconds between the two reads could
    only evict old lines; the injections below each add several new ones.)
    """
    r = client.run(f"dmesg | grep -Fci -- {needle!r} || true")
    out = r.stdout.strip()
    return int(out) if out.isdigit() else 0


@contextlib.contextmanager
def _sppp_debug(client):
    """IFF_DEBUG on pppoe0 for the duration: the SPPP_DLOG records the
    assertions below count only exist with it.  Turned back off only if the
    VM is still alive, so a panic stays a fast failure."""
    r = client.run("ifconfig pppoe0 debug", root=True)
    assert r.returncode == 0, f"ifconfig pppoe0 debug failed: {r.stdout}\n{r.stderr}"
    try:
        yield
    finally:
        if _vm_alive(client):
            client.run("ifconfig pppoe0 -debug", root=True)


def _protocol_rejected(sniffer, mac: str, session: int, proto: int) -> bool:
    """Did the client send an LCP Protocol-Reject naming `proto`?"""
    return any(
        pr == PPP_LCP and len(pl) >= 6 and pl[0] == PROTO_REJ
        and int.from_bytes(pl[4:6], "big") == proto
        for pr, pl in _client_ppp(sniffer, mac, session)
    )


def _assert_session_up(client, wait_iface_up, before: dict, what: str):
    """Still up with an address: either untouched or cleanly renegotiated."""
    after = wait_iface_up(client, timeout=40)
    assert after["up"] and after["inet"], (
        f"session did not survive (or renegotiate after) {what}: "
        f"before={before} after={after}"
    )


@pytest.mark.parametrize("proto", [0x80FD, 0x8207], ids=["0x80fd", "0x8207"])
def test_unknown_ppp_protocol_is_protocol_rejected(client, sniffer, wait_iface_up, proto):
    """(a) An unknown protocol on a live session draws a Protocol-Reject
    naming it (LCP is Opened) and leaves the VM and the session up."""
    session, ac_mac, before = _live_session(client, sniffer, wait_iface_up)
    offset = _serial_offset()

    body = _cp_packet(CONF_REQ, INJECT_IDENT, b"")
    sniffer.send([_session_frame(client.mac, ac_mac, session, proto, body)] * 3)
    time.sleep(2)

    _assert_survived(client, offset, f"PPP protocol 0x{proto:04x}")
    assert _protocol_rejected(sniffer, client.mac, session, proto), (
        f"no LCP Protocol-Reject for 0x{proto:04x} from the client while "
        "LCP was Opened (RFC 1661 5.7)"
    )
    _assert_session_up(client, wait_iface_up, before, f"PPP protocol 0x{proto:04x}")


def _assert_no_ack(sniffer, mac: str, session: int, proto: int, body: bytes,
                   why: str):
    acks = [
        pl for pr, pl in _client_ppp(sniffer, mac, session)
        if pr == proto and len(pl) >= 4 and pl[0] == CONF_ACK
        and pl[1] == INJECT_IDENT and int.from_bytes(pl[2:4], "big") == len(body)
    ]
    assert not acks, (
        f"the client Configure-Acked a 0x{proto:04x} Configure-Request {why}"
    )


def _inject_malformed_confreq(client, sniffer, wait_iface_up, proto: int,
                              options: bytes, needle: str, copies: int):
    """Inject `copies` Configure-Requests carrying `options` on a live
    session with IFF_DEBUG on; return (session, body, before-state, number
    of new `needle` log lines).  Skips when the client Protocol-Rejects the
    NCP instead: it is disabled there, so no parser is ever reached."""
    session, ac_mac, before = _live_session(client, sniffer, wait_iface_up)
    body = _cp_packet(CONF_REQ, INJECT_IDENT, options)
    with _sppp_debug(client):
        offset = _serial_offset()
        hits_before = _dmesg_count(client, needle)
        sniffer.send(
            [_session_frame(client.mac, ac_mac, session, proto, body)] * copies)
        time.sleep(3)
        _assert_survived(client, offset,
                         f"malformed 0x{proto:04x} Configure-Request")
        hits = _dmesg_count(client, needle) - hits_before
    if proto != PPP_LCP and _protocol_rejected(sniffer, client.mac, session,
                                               proto):
        pytest.skip(f"{CP_NAME[proto]} is disabled on this client (it "
                    f"Protocol-Rejected 0x{proto:04x}), so no parser runs")
    return session, body, before, hits


@pytest.mark.parametrize(
    "proto", [PPP_LCP, PPP_IPCP, PPP_IPV6CP], ids=["lcp", "ipcp", "ipv6cp"]
)
def test_confreq_with_zero_length_option_is_dropped(client, sniffer, wait_iface_up, proto):
    """(b) A Configure-Request carrying 258 bytes of options that start
    `00 00` (option length 0) is dropped, not ACKed.

    258 is the smallest option length whose u_char truncation (258 & 0xff
    == 2) turns the pre-fix ACK memcpy into a 256-byte heap overflow.  Sent
    several times to give the unfixed kernel's corruption a chance to land
    on something live.  The client must never send a Configure-Ack echoing
    this request, and the parser's drop exit must have logged -- the
    positive control that the frame reached sppp_*_confreq() at all.
    """
    needle = f"{CP_NAME[proto]} option 0x00 length 0, dropping"
    options = b"\x00\x00" + b"\x41" * 256
    session, body, before, hits = _inject_malformed_confreq(
        client, sniffer, wait_iface_up, proto, options, needle, copies=5)
    assert len(body) == 262

    _assert_no_ack(sniffer, client.mac, session, proto, body,
                   "whose first option has length 0 -- the parser accepted a "
                   "malformed option list (and the pre-fix ACK path "
                   "overflows its u_char-sized buffer)")
    assert hits > 0, (
        f"no new '{needle}' log line with IFF_DEBUG on: the malformed "
        f"0x{proto:04x} Configure-Request never reached the parser's drop "
        "exit, so the no-ACK check above proves nothing"
    )
    _assert_session_up(client, wait_iface_up, before,
                       f"malformed 0x{proto:04x} Configure-Request")


@pytest.mark.parametrize(
    "proto", [PPP_LCP, PPP_IPCP, PPP_IPV6CP], ids=["lcp", "ipcp", "ipv6cp"]
)
def test_confreq_with_trailing_octet_is_dropped(client, sniffer, wait_iface_up, proto):
    """(b3) A well-formed option followed by one stray octet is dropped.

    The stray octet is option type 1, which the log line names.  The
    leading option is one each CP would otherwise ACK or NAK (LCP MRU
    1492, IPCP IP-Address 0.0.0.0, IPv6CP a zero Interface-Identifier), so
    a pre-fix kernel parses it, stops at len == 1 and answers; the fixed
    one must not ACK and must log the drop.
    """
    first = {
        PPP_LCP: b"\x01\x04\x05\xd4",
        PPP_IPCP: b"\x03\x06\x00\x00\x00\x00",
        PPP_IPV6CP: b"\x01\x0a" + b"\x00" * 8,
    }[proto]
    needle = f"{CP_NAME[proto]} trailing octet 0x01, dropping"
    session, body, before, hits = _inject_malformed_confreq(
        client, sniffer, wait_iface_up, proto, first + b"\x01", needle,
        copies=3)

    _assert_no_ack(sniffer, client.mac, session, proto, body,
                   "that ends in a lone trailing octet")
    assert hits > 0, (
        f"no new '{needle}' log line with IFF_DEBUG on: the 0x{proto:04x} "
        "Configure-Request with a trailing octet was not dropped by the "
        "parser"
    )
    _assert_session_up(client, wait_iface_up, before,
                       f"0x{proto:04x} Configure-Request with a trailing octet")


@pytest.mark.parametrize("proto", [PPP_LCP, PPP_IPCP], ids=["lcp", "ipcp"])
def test_confreq_with_overlong_option_is_not_fatal(client, sniffer, wait_iface_up, proto):
    """(b2) Option type 1 (LCP MRU / IPCP IP-Addresses) claiming 16 bytes in a
    4-byte list is the parsers' CP_RCR_ERR exit (restart LCP).  The VM must
    live through it -- the pre-fix sppp_rcr_event() freed an uninitialized
    pointer on that exit -- and the session must renegotiate."""
    session, ac_mac, before = _live_session(client, sniffer, wait_iface_up)
    offset = _serial_offset()

    body = _cp_packet(CONF_REQ, INJECT_IDENT, b"\x01\x10\x05\xdc")
    sniffer.send([_session_frame(client.mac, ac_mac, session, proto, body)] * 3)
    time.sleep(3)

    _assert_survived(client, offset, f"an overlong 0x{proto:04x} option")
    after = wait_iface_up(client, timeout=60)
    assert after["up"] and after["inet"], (
        f"session did not renegotiate after an overlong 0x{proto:04x} "
        f"option: before={before} after={after}"
    )


def test_short_protocol_reject_is_dropped(client, sniffer, wait_iface_up):
    """(c) A Protocol-Reject whose LCP length (4) leaves no room for the
    rejected-protocol field is dropped before the field is read.

    Two bytes (0xc0de) ride in the PPPoE payload just past the LCP length:
    the pre-fix handler reads them as the rejected protocol and, with
    IFF_DEBUG on, logs "for proto 0xc0de".  The fixed one must not, and
    must log its own drop instead.
    """
    session, ac_mac, before = _live_session(client, sniffer, wait_iface_up)
    body = _cp_packet(PROTO_REJ, INJECT_IDENT, b"") + b"\xc0\xde"
    drop_needle = "lcp invalid proto-rej length 4"
    with _sppp_debug(client):
        offset = _serial_offset()
        rxj_before = _dmesg_count(client, "proto 0xc0de")
        drop_before = _dmesg_count(client, drop_needle)
        sniffer.send(
            [_session_frame(client.mac, ac_mac, session, PPP_LCP, body)] * 3)
        time.sleep(2)
        _assert_survived(client, offset, "a 4-byte Protocol-Reject")
        rxj = _dmesg_count(client, "proto 0xc0de") - rxj_before
        drops = _dmesg_count(client, drop_needle) - drop_before

    assert rxj <= 0, (
        "the Protocol-Reject handler read the rejected-protocol field past "
        f"the 4-byte LCP length ({rxj} new 'proto 0xc0de' log lines)"
    )
    assert drops > 0, (
        f"no new '{drop_needle}' log line with IFF_DEBUG on: the short "
        "Protocol-Reject never reached the length check"
    )
    _assert_session_up(client, wait_iface_up, before, "a 4-byte Protocol-Reject")


def test_protocol_reject_with_body_is_parsed(client, sniffer, wait_iface_up):
    """(c2) The positive side of (c): a Protocol-Reject with LCP length 8
    (a 4-byte body: rejected protocol 0xc0de plus 2 octets of the rejected
    packet) passes the length check and is logged as an RXJ naming 0xc0de.
    An unknown protocol is an RXJ-, which LCP ignores while Opened, so the
    session stays up."""
    session, ac_mac, before = _live_session(client, sniffer, wait_iface_up)
    body = _cp_packet(PROTO_REJ, INJECT_IDENT, b"\xc0\xde\x01\x02")
    assert len(body) == 8
    with _sppp_debug(client):
        offset = _serial_offset()
        rxj_before = _dmesg_count(client, "proto 0xc0de")
        sniffer.send(
            [_session_frame(client.mac, ac_mac, session, PPP_LCP, body)] * 3)
        time.sleep(2)
        _assert_survived(client, offset, "an 8-byte Protocol-Reject")
        rxj = _dmesg_count(client, "proto 0xc0de") - rxj_before

    assert rxj > 0, (
        "a well-formed 8-byte Protocol-Reject for 0xc0de was not logged as "
        "an RXJ with IFF_DEBUG on -- the length check drops valid packets"
    )
    _assert_session_up(client, wait_iface_up, before, "an 8-byte Protocol-Reject")
