"""pfil coexistence, single byte count, observability counters, sysctl clamps
(fix group p3-pfil-counters).

What each case pins, against sys/net/if_pppoe.c / if_pppoe_disc.c:

  * Foreign PPPoE frames pass the pfil hook untouched.  The hook used to
    return PFIL_CONSUMED for EVERY 0x8863 frame on a bound parent and for
    every 0x8864 frame whose session missed the table, so mpd5 on the same
    NIC -- ng_ether's `orphans` hook, which ether_demux() only reaches after
    the link pfil chain -- never saw its own PADO/PADS/session traffic.  A
    discovery frame that names no softc of ours (Host-Uniq miss, or a PADT
    whose session/peer is not our live session) and a session frame for a
    session we do not own are now PFIL_PASS, counted in
    net.pppoe.passed_foreign.  Advertised as kern.features.
    if_pppoe_pfil_pass_foreign (docs/plugin/risk-register.md C9).
  * Each byte is counted once.  IBYTES/OBYTES were charged both by the PPPoE
    layer (pppoe_sess_input / pppoe_transmit) and again by sppp (sppp_input,
    sppp_output, sppp_cp_send), so `netstat -I pppoe0 -b` read ~2x the real
    traffic.  Advertised as kern.features.if_pppoe_single_bytecount.
  * net.pppoe.nomem / netisr_enqueue_drop / passed_foreign exist.
  * net.pppoe.term_unknown only ever PADTs the session a softc last closed,
    never that id once the AC has handed it back to us (its first frames
    can beat the session-table publish), and only within
    net.pppoe.term_unknown_window seconds of the close.
  * Signed knobs reject negative values: ppsratecheck() treats a negative
    maxpps as "unlimited", so term_unknown_pps=-1 turned the rate-limited
    PADT into an amplifier.

Every case drives the driver through the `driver` fixture (datapath style,
test_datapath.py) so it runs whatever CLIENT says.
"""
from __future__ import annotations

import json
import re
import time

import pytest
from scapy.all import Ether, Raw

from lab import (
    ETH_PPPOE_DISCOVERY,
    ETH_PPPOE_SESSION,
    PADI,
    PADO,
    PADR,
    PADS,
    PADT,
    PPPOE_STATE_SESSION,
    TAG_AC_NAME,
    TAG_HOST_UNIQ,
    TAG_SERVICE_NAME,
    PPPoESniffer,
    pppoe_tags,
)

pytestmark = pytest.mark.datapath

# Unallocated on br-isp (see test_datapath.FOREIGN_MAC for the reasoning);
# a different value so a failure here is attributable at a glance.
FOREIGN_MAC = "52:54:00:aa:00:0b"

# A Host-Uniq no softc of ours can carry: the driver's tokens are a small
# per-module counter (pppoe_clone_create(): atomic_fetchadd_64 from 1), and
# this is far outside any count of clones a test run creates.
FOREIGN_HUNIQ = bytes.fromhex("f0f1f2f3f4f5f6f7")


def _tlv(tag: int, value: bytes) -> bytes:
    return tag.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _disc_frame(dst: str, code: int, session: int = 0,
                hunique: bytes | None = FOREIGN_HUNIQ) -> Ether:
    tags = _tlv(TAG_SERVICE_NAME, b"not-ours")
    if hunique is not None:
        tags += _tlv(TAG_HOST_UNIQ, hunique)
    hdr = (bytes([0x11, code]) + session.to_bytes(2, "big")
           + len(tags).to_bytes(2, "big"))
    return Ether(dst=dst, src=FOREIGN_MAC, type=ETH_PPPOE_DISCOVERY) / Raw(hdr + tags)


def _sess_frame(dst: str, session: int, payload: bytes = b"\xc0\x21" + b"\x09" * 10,
                src: str = FOREIGN_MAC) -> Ether:
    hdr = (b"\x11\x00" + session.to_bytes(2, "big")
           + len(payload).to_bytes(2, "big"))
    return Ether(dst=dst, src=src, type=ETH_PPPOE_SESSION) / Raw(hdr + payload)


def _counters(driver, *names: str) -> dict:
    """Several net.pppoe.* counters in ONE ssh round trip, one line each."""
    r = driver.run("sysctl -n " + " ".join(f"net.pppoe.{n}" for n in names))
    assert r.returncode == 0, f"sysctl {names} failed: {r.stdout}\n{r.stderr}"
    vals = r.stdout.split()
    assert len(vals) == len(names), f"expected {len(names)} values: {r.stdout!r}"
    return dict(zip(names, (int(v) for v in vals)))


def _live_session(driver) -> int:
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms["state"] == PPPOE_STATE_SESSION, parms
    # The session-table publish is asynchronous (pppoe_session_task()); let
    # it land so the AC's own frames are not counted as foreign below.
    time.sleep(2)
    return parms["session"]


# ---------------------------------------------------------------------------
# Feature flags, counters and sysctl clamps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("feature", [
    "if_pppoe_pfil_pass_foreign",
    "if_pppoe_single_bytecount",
])
def test_kern_feature_is_advertised(driver, feature):
    """The OPNsense plugin gates eligibility on these (risk-register C9); a
    missing sysctl reads as "old .ko", so it must exist and read 1."""
    driver.kldload()
    r = driver.run(f"sysctl -n kern.features.{feature}")
    assert r.returncode == 0 and r.stdout.strip() == "1", (
        f"kern.features.{feature} is not advertised by the loaded module: "
        f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    )


@pytest.mark.parametrize("counter", ["nomem", "netisr_enqueue_drop", "passed_foreign"])
def test_observability_counter_exists(driver, counter):
    driver.kldload()
    val = driver.counter(counter)
    assert val >= 0, f"net.pppoe.{counter} = {val}"


@pytest.mark.parametrize("knob,bad", [
    ("term_unknown_pps", -1),
    ("term_unknown_pps", -2147483648),
    ("term_unknown", -1),
    ("term_unknown", 2),
])
def test_signed_sysctl_rejects_out_of_range(driver, knob, bad):
    """ppsratecheck(9) treats maxpps < 0 as unlimited, so a negative
    term_unknown_pps would lift the PADT rate limit entirely; term_unknown
    is a boolean.  The write must fail and leave the value untouched."""
    driver.kldload()
    before = driver.sysctl(f"net.pppoe.{knob}")
    r = driver.run(f"sysctl net.pppoe.{knob}={bad}", root=True)
    after = driver.sysctl(f"net.pppoe.{knob}")
    assert r.returncode != 0, (
        f"sysctl net.pppoe.{knob}={bad} was accepted: {r.stdout}{r.stderr}"
    )
    assert after == before, f"net.pppoe.{knob} moved {before} -> {after}"


def test_term_unknown_pps_accepts_zero_and_restores(driver):
    """0 is a legal budget (ppsratecheck never fires); the clamp must not
    refuse it."""
    driver.kldload()
    before = driver.sysctl("net.pppoe.term_unknown_pps")
    try:
        r = driver.run("sysctl net.pppoe.term_unknown_pps=0", root=True)
        assert r.returncode == 0, f"{r.stdout}{r.stderr}"
        assert driver.sysctl("net.pppoe.term_unknown_pps") == "0"
    finally:
        driver.run(f"sysctl net.pppoe.term_unknown_pps={before}", root=True)


# ---------------------------------------------------------------------------
# Foreign frames pass the hook
# ---------------------------------------------------------------------------

def test_foreign_discovery_frames_are_passed_not_consumed(driver, sniffer):
    """PADI/PADO/PADS naming a Host-Uniq that is not ours, and PADTs that do
    not match our live session (wrong session id, or right id from the wrong
    peer), are another client's business: counted passed_foreign, never
    disc_in, and the live session is untouched."""
    session = _live_session(driver)
    other = (session + 64) & 0xFFFF or 1
    frames = (
        [_disc_frame("ff:ff:ff:ff:ff:ff", PADI)] * 5
        + [_disc_frame(driver.mac, PADO)] * 5
        + [_disc_frame(driver.mac, PADS, session=other)] * 5
        + [_disc_frame(driver.mac, PADT, session=other, hunique=None)] * 5
        # Our live session id, but FOREIGN_MAC is not our AC: not ours.
        + [_disc_frame(driver.mac, PADT, session=session, hunique=None)] * 5
    )
    before = _counters(driver, "passed_foreign", "disc_in")
    sniffer.send(frames)
    time.sleep(1.0)
    after = _counters(driver, "passed_foreign", "disc_in")

    assert after["passed_foreign"] - before["passed_foreign"] == len(frames), (
        f"{len(frames)} foreign discovery frames, passed_foreign moved "
        f"{after['passed_foreign'] - before['passed_foreign']} -- the hook is "
        "still consuming discovery frames that name no softc of ours"
    )
    assert after["disc_in"] == before["disc_in"], (
        f"disc_in moved {after['disc_in'] - before['disc_in']}: foreign "
        "discovery frames were consumed"
    )
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_SESSION and parms["session"] == session, (
        f"the live session did not survive foreign discovery traffic: {parms}"
    )


def test_unknown_session_frames_are_passed_not_consumed(driver, sniffer):
    """0x8864 frames for a session we do not own are passed (still counted
    sess_nosession, plus passed_foreign); ours keep flowing."""
    session = _live_session(driver)
    other = (session + 128) & 0xFFFF or 1
    frames = [_sess_frame(driver.mac, other)] * 20
    before = _counters(driver, "passed_foreign", "sess_nosession")
    sniffer.send(frames)
    time.sleep(1.0)
    after = _counters(driver, "passed_foreign", "sess_nosession")

    assert after["passed_foreign"] - before["passed_foreign"] == 20, (
        f"passed_foreign moved {after['passed_foreign'] - before['passed_foreign']} "
        "for 20 unknown-session frames"
    )
    assert after["sess_nosession"] - before["sess_nosession"] == 20, (
        "sess_nosession must keep counting passed unknown-session frames"
    )
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_SESSION and parms["session"] == session, parms


_NG_HOLE = "pppoe_orph"


def _hole_frames(driver) -> int:
    """Frames the ng_hole node on vtnet1:orphans has swallowed on hook "in".

    ng_hole's getstats reply is `Args: { frames=N octets=M }`; ngctl's ASCII
    form omits zero-valued fields, so an absent `frames=` means 0.
    """
    r = driver.run(f"ngctl msg {_NG_HOLE}: getstats '\"in\"'", root=True)
    assert r.returncode == 0, f"ng_hole getstats failed: {r.stdout}\n{r.stderr}"
    m = re.search(r"frames=(\d+)", r.stdout)
    return int(m.group(1)) if m else 0


def _orphans_peer_type(driver) -> str | None:
    """ng type of whatever sits on vtnet1:orphans, or None if it is free.

    `ngctl show vtnet1:` lists one row per connected hook:
    `  orphans  <peer name>  <peer type>  <peer ID>  <peer hook>`.
    """
    r = driver.run("ngctl show vtnet1:", root=True)
    assert r.returncode == 0, f"ngctl show vtnet1: {r.stdout}\n{r.stderr}"
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) == 5 and f[0] == "orphans":
            return f[2]
    return None


@pytest.fixture
def orphans_hole(driver):
    """An ng_hole node on vtnet1's ng_ether `orphans` hook -- where mpd5's
    PPPoE node sits -- for one test, always shut down afterwards.

    Stopping mpd5 (conftest mpd5_quiesced) does NOT free the hook: mpd5
    leaves its ng_pppoe node attached to vtnet1:orphans when it exits and
    re-uses it on the next start (on the lab client that node is the one
    the boot-time mpd5 made, surviving every later mpd5 stop/start).  So
    an ng_pppoe found there while mpd5 is down is that leftover: detach it
    for the test and put an equivalent one back afterwards, so the
    session-end mpd5 restart finds the VM exactly as it left it.  A live
    mpd5 owns the node (CLIENT=mpd5), and yanking it would kill its
    session -- skip instead.
    """
    if driver.run("service mpd5 onestatus").returncode == 0:
        pytest.skip("mpd5 is running and owns vtnet1:orphans")
    r = driver.run("kldload -n ng_ether ng_hole", root=True)
    assert r.returncode == 0, f"kldload ng_ether ng_hole: {r.stdout}\n{r.stderr}"
    driver.run(f"ngctl shutdown {_NG_HOLE}:", root=True)  # stale from a crash
    peer = _orphans_peer_type(driver)
    restore_pppoe = peer == "pppoe"
    if restore_pppoe:
        r = driver.run("ngctl shutdown vtnet1:orphans", root=True)
        assert r.returncode == 0, (
            f"could not detach mpd5's leftover ng_pppoe: {r.stdout}\n{r.stderr}"
        )
    elif peer is not None:
        pytest.fail(f"vtnet1:orphans is held by an unexpected ng_{peer} node")
    r = driver.run("ngctl mkpeer vtnet1: hole orphans in", root=True)
    assert r.returncode == 0, (
        f"could not attach ng_hole to vtnet1:orphans: {r.stdout}\n{r.stderr}"
    )
    try:
        r = driver.run(f"ngctl name vtnet1:orphans {_NG_HOLE}", root=True)
        assert r.returncode == 0, f"ngctl name: {r.stdout}\n{r.stderr}"
        yield
    finally:
        driver.run(f"ngctl shutdown {_NG_HOLE}:", root=True)
        if restore_pppoe:
            r = driver.run("ngctl mkpeer vtnet1: pppoe orphans ethernet", root=True)
            assert r.returncode == 0, (
                f"could not re-attach ng_pppoe to vtnet1:orphans: {r.stdout}\n{r.stderr}"
            )


def test_passed_foreign_frames_reach_ng_ether_orphans(driver, sniffer, orphans_hole):
    """End to end: what mpd5 needs is for the frames to come OUT of pfil and
    reach ng_ether's orphans hook (ether_demux()'s discard arm, after the
    link pfil chain).  Foreign discovery and session frames must arrive
    there; before the fix the hook consumed them and the hole saw nothing."""
    session = _live_session(driver)
    other = (session + 192) & 0xFFFF or 1
    frames = [_disc_frame(driver.mac, PADO)] * 10 + [_sess_frame(driver.mac, other)] * 10
    before = _hole_frames(driver)
    sniffer.send(frames)
    time.sleep(1.0)
    got = _hole_frames(driver) - before
    assert got == len(frames), (
        f"{len(frames)} foreign PPPoE frames injected, {got} reached "
        "vtnet1:orphans -- a same-NIC mpd5 would not see its own traffic"
    )
    parms = driver.parms("pppoe0")
    assert parms["state"] == PPPOE_STATE_SESSION and parms["session"] == session, parms


# ---------------------------------------------------------------------------
# Byte counters: each byte once
# ---------------------------------------------------------------------------

# Per-packet bytes charged on top of iperf3's TCP payload: PPP protocol field +
# IPv4 + TCP + RFC 7323 timestamps (without timestamps the error is 0.8%).
_PER_PKT = 2 + 20 + 20 + 12
_MSS_PAYLOAD = 1492 - 20 - 20 - 12  # full-sized segment's payload at MTU 1492
_TOLERANCE = 0.02


def _iface_counters(driver, iface: str = "pppoe0") -> dict:
    r = driver.run(f"netstat --libxo json -I {iface} -bnW")
    assert r.returncode == 0, f"netstat -I {iface}: {r.stdout}\n{r.stderr}"
    rows = json.loads(r.stdout)["statistics"]["interface"]
    link = [row for row in rows if str(row.get("network", "")).startswith("<Link")]
    assert link, f"no link-layer row for {iface}: {r.stdout}"
    row = link[0]
    return {
        "ipkts": int(row["received-packets"]),
        "ibytes": int(row["received-bytes"]),
        "opkts": int(row["sent-packets"]),
        "obytes": int(row["sent-bytes"]),
    }


def _wait_inet(driver, timeout: float = 30.0) -> dict:
    """SESSION only means discovery finished; iperf needs IPCP's address (and
    with it the 10.99.0.1 host route), or its SYN leaves via vtnet0."""
    deadline = time.time() + timeout
    while True:
        st = driver.iface_state("pppoe0")
        if st["inet"] or time.time() >= deadline:
            return st
        time.sleep(1.0)


def _iperf(driver, reverse: bool) -> dict:
    cmd = "iperf3 -c 10.99.0.1 -t 5 -J" + (" -R" if reverse else "")
    r = driver.run(cmd, root=True, timeout=60)
    assert r.returncode == 0, f"{cmd} failed: {r.stdout[-2000:]}\n{r.stderr}"
    return json.loads(r.stdout)["end"]


@pytest.mark.parametrize("direction", ["tx", "rx"])
def test_byte_counters_match_iperf_within_2pct(driver, direction):
    """`netstat -I pppoe0 -b` must agree with the traffic iperf3 actually
    moved: payload bytes + per-packet PPP/IP/TCP headers, within 2%.
    Counting each byte in both the PPPoE layer and sppp read ~2x."""
    _live_session(driver)
    up = _wait_inet(driver)
    assert up["inet"], f"no IPCP address on pppoe0 before iperf: {up['raw']}"

    before = _iface_counters(driver)
    end = _iperf(driver, reverse=(direction == "rx"))
    after = _iface_counters(driver)

    if direction == "tx":
        sent = end["sum_sent"]
        # Retransmitted segments cross the wire again but are not in
        # sum_sent.bytes (application bytes).
        payload = int(sent["bytes"]) + int(sent.get("retransmits", 0)) * _MSS_PAYLOAD
        pkts = after["opkts"] - before["opkts"]
        counted = after["obytes"] - before["obytes"]
    else:
        payload = int(end["sum_received"]["bytes"])
        pkts = after["ipkts"] - before["ipkts"]
        counted = after["ibytes"] - before["ibytes"]
    assert payload > 1_000_000, f"iperf3 moved almost nothing: {end}"
    expected = payload + pkts * _PER_PKT
    err = abs(counted - expected) / expected
    assert err <= _TOLERANCE, (
        f"{direction}: pppoe0 counted {counted} bytes over {pkts} packets, "
        f"iperf3 payload {payload} (+{_PER_PKT}/pkt = {expected}); off by "
        f"{err:.1%} (> {_TOLERANCE:.0%}) -- ratio {counted / payload:.3f}; "
        "~2.0 means each byte is still counted twice"
    )


# ---------------------------------------------------------------------------
# term_unknown attribution: the stale session of ours, and nothing else
# ---------------------------------------------------------------------------

# A scripted AC on br-isp.  accel-ppp discards a PADI whose Service-Name it
# does not serve (test_discovery.test_mismatched_service_name_discarded), so
# with this Service-Name only the scripted AC answers, and it hands out the
# session id the test chooses -- which accel-ppp cannot be made to do.
SCRIPT_AC_MAC = "52:54:00:aa:00:0c"
SCRIPT_AC_SERVICE = b"p3-script-ac"
SCRIPT_AC_SESSION = 0x2a40

# LCP Configure-Request, MRU 1492: what an AC sends right after its PADS.
_LCP_CONFREQ = b"\xc0\x21" + b"\x01\x01\x00\x08" + b"\x01\x04\x05\xd4"


class ScriptedAC:
    """Answers our PADI with a PADO and our PADR with a PADS for `session`,
    followed in the SAME sendp() burst by `burst` LCP Configure-Requests on
    that session.  Back to back on the wire they land in one vtnet RX batch,
    ahead of pppoe_session_task()'s table insert: exactly when the reviewed
    bug made the RX hook treat our new session as the stale one and PADT
    it.  Every PPPoE frame on br-isp is kept in `packets`."""

    def __init__(self, session: int, burst: int = 16):
        self.session = session
        self.burst = burst
        self.packets: list = []
        self._sniffer = None

    def _reply(self, code: int, pkt, session: int = 0) -> Ether:
        tags = pppoe_tags(pkt)
        body = (_tlv(TAG_SERVICE_NAME, SCRIPT_AC_SERVICE)
                + _tlv(TAG_AC_NAME, b"p3-script-ac"))
        if TAG_HOST_UNIQ in tags:
            body += _tlv(TAG_HOST_UNIQ, tags[TAG_HOST_UNIQ])
        hdr = (bytes([0x11, code]) + session.to_bytes(2, "big")
               + len(body).to_bytes(2, "big"))
        return Ether(dst=pkt[Ether].src, src=SCRIPT_AC_MAC,
                     type=ETH_PPPOE_DISCOVERY) / Raw(hdr + body)

    def _on_frame(self, pkt):
        from scapy.all import PPPoED, sendp

        self.packets.append(pkt)
        if not pkt.haslayer(PPPoED) or pkt[Ether].src.lower() == SCRIPT_AC_MAC:
            return
        if pppoe_tags(pkt).get(TAG_SERVICE_NAME) != SCRIPT_AC_SERVICE:
            return
        code = pkt[PPPoED].code
        if code == PADI:
            sendp([self._reply(PADO, pkt)], iface=PPPoESniffer.IFACE, verbose=False)
        elif code == PADR and pkt[Ether].dst.lower() == SCRIPT_AC_MAC:
            frames = [self._reply(PADS, pkt, self.session)]
            frames += [_sess_frame(pkt[Ether].src, self.session, _LCP_CONFREQ,
                                   src=SCRIPT_AC_MAC)] * self.burst
            sendp(frames, iface=PPPoESniffer.IFACE, verbose=False)

    def start(self):
        from scapy.all import AsyncSniffer

        self._sniffer = AsyncSniffer(iface=PPPoESniffer.IFACE,
                                     filter="pppoed or pppoes",
                                     prn=self._on_frame, store=False)
        self._sniffer.start()
        time.sleep(1.0)  # no readiness probe: the first PADI is retried anyway

    def stop(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def padts_from(self, mac: str, session: int, since: int = 0) -> list:
        from scapy.all import PPPoED

        return [
            p for p in self.packets[since:]
            if p.haslayer(PPPoED) and p[PPPoED].code == PADT
            and p[Ether].src.lower() == mac.lower()
            and p[PPPoED].sessionid == session
        ]


@pytest.fixture
def scripted_ac():
    ac = ScriptedAC(SCRIPT_AC_SESSION)
    ac.start()
    try:
        yield ac
    finally:
        ac.stop()


def _scripted_session(driver, knobs: str) -> None:
    """Bind pppoe0 to the scripted AC's service with the given net.pppoe
    knobs (set after create()'s module reload), and dial it."""
    driver.create(iface="pppoe0", parent="vtnet1",
                  service=SCRIPT_AC_SERVICE.decode())
    r = driver.run(f"sysctl {knobs}", root=True)
    assert r.returncode == 0, f"sysctl {knobs}: {r.stdout}\n{r.stderr}"
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms.get("state") == PPPOE_STATE_SESSION, (
        f"no session from the scripted AC: {parms}"
    )
    assert parms["session"] == SCRIPT_AC_SESSION, parms


def test_reissued_stale_session_id_is_not_padted(driver, scripted_ac):
    """Close session X, redial, and the AC hands out X again with its first
    LCP frames right behind the PADS.  Those frames can miss the session
    table (the insert is deferred to pppoe_session_task()) while (X, AC)
    still equals the softc's last-closed record; with term_unknown=1 the
    driver used to drop them and PADT its own brand-new session, and the AC
    re-issuing X on the redial made that a loop.  padt_unknown must not
    move, no PADT for X may leave after the second PADS, and the session
    must still be X."""
    _scripted_session(driver, "net.pppoe.term_unknown=1 net.pppoe.term_unknown_pps=100")

    driver.down("pppoe0")  # records X as the last-closed session (and PADTs it)
    time.sleep(1.0)
    mark = len(scripted_ac.packets)
    before = driver.counter("padt_unknown")
    driver.up("pppoe0")
    parms = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert parms.get("state") == PPPOE_STATE_SESSION, parms
    time.sleep(2.0)  # the AC would react to a PADT well within this

    assert driver.counter("padt_unknown") == before, (
        "padt_unknown moved: the driver treated the AC's frames for our new "
        f"session {SCRIPT_AC_SESSION} as the stale one"
    )
    padts = scripted_ac.padts_from(driver.mac, SCRIPT_AC_SESSION, since=mark)
    assert not padts, (
        f"{len(padts)} PADT(s) for our own live session {SCRIPT_AC_SESSION} "
        "after the AC reissued it"
    )
    parms = driver.parms("pppoe0")
    assert (parms["state"] == PPPOE_STATE_SESSION
            and parms["session"] == SCRIPT_AC_SESSION), parms


def test_stale_session_attribution_expires(driver, sniffer, scripted_ac):
    """The last-closed record is honoured for net.pppoe.term_unknown_window
    seconds only: past it the AC may have given the id to another client on
    the parent (a same-NIC mpd5 shares our MAC, so shares the RFC 2516 key),
    and its frames must be passed, not PADTed.  Within the window the same
    frames do draw a PADT, so the negative half is not vacuous."""
    _scripted_session(
        driver,
        "net.pppoe.term_unknown=1 net.pppoe.term_unknown_pps=100 "
        "net.pppoe.term_unknown_window=2",
    )
    driver.down("pppoe0")  # closes X; the record is now 0s old
    time.sleep(4.0)        # > term_unknown_window

    stale = [_sess_frame(driver.mac, SCRIPT_AC_SESSION, _LCP_CONFREQ,
                         src=SCRIPT_AC_MAC)] * 10
    mark = len(scripted_ac.packets)
    before = _counters(driver, "padt_unknown", "passed_foreign")
    sniffer.send(stale)
    time.sleep(1.0)
    after = _counters(driver, "padt_unknown", "passed_foreign")
    assert after["padt_unknown"] == before["padt_unknown"], (
        "padt_unknown moved for a session closed longer ago than "
        "term_unknown_window"
    )
    assert after["passed_foreign"] - before["passed_foreign"] == len(stale), (
        "expired-stale session frames were not passed up the stack"
    )
    assert not scripted_ac.padts_from(driver.mac, SCRIPT_AC_SESSION, since=mark)

    r = driver.run("sysctl net.pppoe.term_unknown_window=180", root=True)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    before = driver.counter("padt_unknown")
    sniffer.send(stale)
    time.sleep(1.0)
    assert driver.counter("padt_unknown") > before, (
        "inside term_unknown_window the stale session drew no PADT: the "
        "attribution itself is broken, so the expiry check above proves nothing"
    )
