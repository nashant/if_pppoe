"""Reconnect trigger tests (M003 S03 T3).

The S03 acceptance contract is the kernel-side trigger OPNsense's
devd-driven dhcp6c consumes: at least two RTM_IFINFO messages for pppoe0
(a LINK_DOWN / LINK_UP pair) on every reconnect, PADT on clone destroy,
and an IPv6 link-local that is rebuilt across the outage -- not stale.

Oracle 1 -- routing-socket route monitor.  `route -n monitor` on the
client VM writes every routing-socket message to a file.  The monitor is
started AFTER the session is up and only then is the trigger fired:
starting it before the dial counts first-dial messages and passes
vacuously, and start() must not return until the capture PROVES it is
attached -- pid-alive does not (run2 lost a whole teardown DOWN burst to
the attach window, transitions ['UP']).

Oracle 2 -- dmesg.  dmesg is a rotating ring, so once the ring is full a
snapshot diff of identical-text lines is blind to them (a new `link state
changed to DOWN` replaces an older identical line and changes no counts --
probe-verified).  Each test therefore CLEARS the ring with
`sysctl kern.msgbuf_clear=1` (dmesg(8) here has no -C) right before the
trigger and reads `dmesg` after: the read-back is exactly
the trigger window.  `pppoe0: link state changed to DOWN` then `UP` gives
the interface-named DOWN-before-UP ordering.

Route-monitor format (verified live, FreeBSD 14.x route(8) compact style):
one line per routing-socket message, e.g.

    06:19:09.486 PID    0 add/repl iface iface#5 pppoe0 admin UP oper UP mtu 1492
    06:19:12.504 PID    0 add/repl addr 10.99.0.189/32 -> 10.99.0.1 iface pppoe0

RTM_IFINFO lines literally name the interface.  The routing socket
re-broadcasts RTM_IFINFO on every flag/address event, so the raw message
count is a weak oracle -- and the capture itself is LOSSY: even with
attachment proven (lo0 probe), diag3's terminate capture held the
tear-down's addr delete and UP re-broadcasts but ZERO DOWN lines while
the cleared-ring dmesg window showed the DOWN.  The monitor is therefore
AUXILIARY evidence (>=2 RTM_IFINFO messages for pppoe0 in the window);
the AUTHORITATIVE DOWN/UP oracle is the cleared-ring dmesg window
(kern.msgbuf_clear=1), which names the interface and orders the states
exactly.  The plan's "exactly two messages" premise does not hold on
this tree either: one restart_link legitimately visits DOWN and UP twice
in the dmesg window (diag3: PADT/local-shutdown close, DOWN, UP,
re-dial, DOWN, UP, IPCP layer up) because sppp closes, re-opens and
re-negotiates through its phases -- dedup only forbids duplicate
CONSECUTIVE states, so the honest assertions are the pair's existence
and ordering, never an exact count.
"""
from __future__ import annotations

import random
import re
import threading
import time

import pytest
from scapy.all import Ether, PPPoED

from lab import (
    CLIENT_SSH_PORT,
    MPDSRV_SSH_PORT,
    PADT,
    IfPppoeClient,
    _ssh_stdin,
)

pytestmark = pytest.mark.reconnect

RTMON_PID = "/tmp/rtmon-reconnect.pid"
RTMON_OUT = "/tmp/rtmon-reconnect.out"

# S03 T4: pfctl-driven ALTQ state on the parent (vtnet1).  ALTQ on an
# interface is only reachable through pf -- `ifconfig -altq` is not a
# thing -- so this file's ALTQ proof loads a cbq ruleset with pfctl and
# drives the T2 detection points (parent bind / session start) with a
# plain re-dial.
ALTQ_PF_CONF = "/tmp/pf-altq-m003-s03t4.conf"
_ALTQ_RULESET = (
    "altq on vtnet1 cbq bandwidth 100Mb queue { def }\n"
    "queue def bandwidth 95% cbq(default)\n"
    "pass all\n"
)
_CLEAN_RULESET = "pass all\n"
_ALTQ_WARN_MARK = "has ALTQ enabled"



@pytest.fixture
def pppoe_client(client):
    """The in-kernel client only: the reconnect oracles (pppoeparms session
    state, pppoectl-driven link restarts) do not exist on Mpd5Client."""
    if not isinstance(client, IfPppoeClient):
        pytest.skip("reconnect tests drive the in-kernel if_pppoe client (CLIENT=if_pppoe)")
    return client


class _RouteMonitor:
    """`route -n monitor` collector on the client VM (plan T3 recipe):
    daemon(8) backgrounds it with a pid file, the monitor's output goes to
    RTMON_OUT, and stop() kills it and returns everything captured.

    start() does not return until the capture PROVES it is attached: a lo0
    alias is injected and the monitor must show it (the scapy sniffer's
    readiness-probe pattern, MEM114).  The pid being alive does not prove
    attachment -- run2's terminate case lost the whole DOWN burst to the
    attach window and saw transitions ['UP']."""

    def __init__(self, client):
        self.client = client
        self._probe_alias = None

    def start(self):
        c = self.client
        # A monitor left behind by a previously crashed run would double-
        # count every message below -- kill any stale one first.
        c.run(f"kill -9 $(cat {RTMON_PID} 2>/dev/null) 2>/dev/null", root=True)
        r = c.run(f": > {RTMON_OUT}", root=True)
        assert r.returncode == 0, f"could not truncate {RTMON_OUT}: {r.stdout}\n{r.stderr}"
        r = c.run(
            f"daemon -f -p {RTMON_PID} sh -c 'route -n monitor > {RTMON_OUT} 2>&1'",
            root=True, timeout=10,
        )
        assert r.returncode == 0, (
            f"daemon route monitor failed: rc={r.returncode} {r.stdout}\n{r.stderr}"
        )
        # Attach-proof probe: an lo0 alias ADD must appear in the capture
        # before the trigger is fired.  The alias is removed immediately,
        # so the VM is unchanged (the remove is itself captured -- it names
        # lo0, not pppoe0, and is filtered out by the parser).
        self._probe_alias = f"192.0.2.{random.randint(200, 254)}"
        c.run(f"ifconfig lo0 alias {self._probe_alias}/32", root=True)
        deadline = time.time() + 5
        while time.time() < deadline:
            raw = c.run(f"cat {RTMON_OUT}", root=True).stdout
            if "lo0" in raw:
                c.run(f"ifconfig lo0 -alias {self._probe_alias}/32", root=True)
                self._probe_alias = None
                return
            time.sleep(0.3)
        c.run(f"ifconfig lo0 -alias {self._probe_alias}/32", root=True)
        self._probe_alias = None
        raise RuntimeError(
            "route monitor never attached to the routing socket -- the lo0 "
            "probe alias was never captured, so trigger-window assertions "
            "would silently miss the teardown"
        )

    def stop(self) -> str:
        c = self.client
        if self._probe_alias is not None:
            c.run(f"ifconfig lo0 -alias {self._probe_alias}/32", root=True)
            self._probe_alias = None
        c.run(f"kill -9 $(cat {RTMON_PID} 2>/dev/null) 2>/dev/null", root=True)
        r = c.run(f"cat {RTMON_OUT}", root=True)
        return r.stdout


def _dmesg_clear(client):
    """Clear the client VM's msgbuf ring so the post-trigger `dmesg` read is
    exactly the trigger window (MEM064: never trust a full rotating ring).
    dmesg(8) on this client kernel has no -C flag (usage shows only
    [-ac] [-M core [-N system]]); kern.msgbuf_clear=1 is the supported
    equivalent (diag2 verified live: the ring drops to 0 lines)."""
    r = client.run("sysctl kern.msgbuf_clear=1", root=True)
    assert r.returncode == 0, (
        f"kern.msgbuf_clear failed: {r.stdout}\n{r.stderr}"
    )


def _dmesg_window(client):
    return client.run("dmesg").stdout.splitlines()


_IFINFO_RE = re.compile(
    r"\badd/repl iface\s+iface#(?P<idx>\d+)\s+(?P<name>\S+)\s+"
    r"admin\s+(?P<admin>\S+)\s+oper\s+(?P<oper>\S+)\b"
)


def _ifinfo_msgs(raw):
    """All parsed RTM_IFINFO lines, in message order:
    [(idx, name, admin, oper)].  Format per the live probe (tests/results/
    reconnect/ evidence for exec 7ed0b7a6)."""
    return [
        (int(m.group("idx")), m.group("name"), m.group("admin"), m.group("oper"))
        for m in _IFINFO_RE.finditer(raw)
    ]


def _ifinfo_pppoe0(raw):
    """RTM_IFINFO (admin, oper) states for pppoe0, in message order."""
    return [(a, o) for _, name, a, o in _ifinfo_msgs(raw) if name == "pppoe0"]


def _oper_transitions(states):
    """Distinct consecutive oper states -- the level if_link_state_change()
    actually dedups.  A route monitor sees a dozen repeated RTM_IFINFO
    broadcasts per reconnect (flag/addr events re-broadcast ifinfo); the
    dedup contract is only visible here."""
    seq = []
    for _, oper in states:
        if not seq or seq[-1] != oper:
            seq.append(oper)
    return seq


def _link_changes(dmesg_lines):
    downs = [i for i, l in enumerate(dmesg_lines)
             if "pppoe0: link state changed to DOWN" in l]
    ups = [i for i, l in enumerate(dmesg_lines)
           if "pppoe0: link state changed to UP" in l]
    return downs, ups


def _rtmon_evidence(raw):
    """Bounded raw-monitor excerpt for failure messages."""
    return "\n".join(raw.splitlines()[-60:])


# ---------------------------------------------------------------------------
# Accel-marked trigger cases (service "lab", accel-ppp peer).
# ---------------------------------------------------------------------------


def test_server_terminate_produces_link_down_then_link_up_rtm_ifinfo_pair(
    pppoe_client, accel_server, wait_iface_up
):
    """Server-side hard terminate -> PADT -> the client tears and re-dials:
    at least two RTM_IFINFO messages for pppoe0 in the post-trigger window,
    DOWN before UP.  The route monitor starts only AFTER the dial -- before
    it would count the first dial's own pair and pass vacuously.

    Up to ~180s is allowed for the re-dial: accel-ppp holds the dead
    session's pool lease ~60s and NAK/TERMs the reconnecting client's IPCP
    meanwhile (MEM064), so the trigger window may contain more than one
    DOWN/UP cycle -- hence at-least-2, not exactly-2.
    """
    c = pppoe_client
    c.dial(service="lab")
    st = _wait_up(c, wait_iface_up, timeout=30)
    assert st["up"] and st["inet"], f"initial dial did not complete: {st['raw']}"
    base_inet = st["inet"]

    _dmesg_clear(c)
    mon = _RouteMonitor(c)
    mon.start()
    try:
        accel_server.terminate_all("hard")
        st = _wait_up(c, wait_iface_up, timeout=180)
    finally:
        raw = mon.stop()
        window = _dmesg_window(c)

    assert st["up"] and st["inet"], (
        f"re-dial did not complete within 180s of the server terminate:\n{st['raw']}"
        f"\naccel log:\n{accel_server.log_tail(30)}"
    )
    states = _ifinfo_pppoe0(raw)
    assert len(states) >= 2, (
        f"expected >=2 RTM_IFINFO messages naming pppoe0 in the window after "
        f"accel terminate_all(hard), saw {len(states)}\n"
        f"route monitor:\n{_rtmon_evidence(raw)}"
    )
    # Authoritative DOWN/UP oracle: the cleared-ring dmesg window.  (The
    # routing-socket capture is lossy even when attachment is proven --
    # diag3 flow A held the teardown's addr delete and UP re-broadcasts
    # but zero DOWN lines while dmesg showed DOWN -- so ordering is not
    # asserted against the monitor.)  diag3's window: PADT close, DOWN,
    # UP, re-dial, DOWN, UP, IPCP layer up.
    downs, ups = _link_changes(window)
    assert downs and ups and downs[0] < ups[-1], (
        "the cleared-ring dmesg window does not show pppoe0 going DOWN then "
        f"UP (DOWN lines: {len(downs)}, UP lines: {len(ups)})\n"
        "dmesg window:\n" + "\n".join(window[-40:])
    )
    # No vacuous pass: the PADT-triggered close and the fresh IPCP
    # convergence must both be in the window -- the terminate actually
    # reached THIS client and the redial completed at the PPP layer.
    assert any("closed: received PADT" in l for l in window), (
        "no PADT-triggered session close in the cleared-ring dmesg window -- "
        "the terminate_all did not actually tear this client's session\n"
        "dmesg window:\n" + "\n".join(window[-40:])
    )
    assert any("IPCP layer up" in l for l in window), (
        "no IPCP layer up in the cleared-ring dmesg window -- the redial "
        "did not converge at the PPP layer"
    )


def test_restart_link_produces_the_rtm_ifinfo_pair(pppoe_client, accel_server, wait_iface_up):
    """IfPppoeClient.restart_link() (the milestone decision's seam) tears and
    re-dials administratively: the RTM_IFINFO stream for pppoe0 must show a
    DOWN state before an UP state, and the redial must renegotiate a fresh
    address (the MEM068 oracle).  The kernel dedups unchanged consecutive
    link states, but one restart_link legitimately visits DOWN and UP more
    than once (sppp closes, re-opens, re-negotiates through its phases;
    diag2's cleared-ring window shows DOWN,UP,DOWN,UP) -- so ordering and
    existence are asserted, never an exact message count.
    """
    c = pppoe_client
    c.dial(service="lab")
    st = _wait_up(c, wait_iface_up, timeout=30)
    assert st["up"] and st["inet"], f"initial dial did not complete: {st['raw']}"
    base_inet = st["inet"]

    _dmesg_clear(c)
    mon = _RouteMonitor(c)
    mon.start()
    try:
        c.restart_link()
        st = _wait_up(c, wait_iface_up, timeout=60)
        # Let the session's own LCP/keepalive settle so no late flap lands
        # after the monitor is stopped and hides a real third state.
        time.sleep(3)
    finally:
        raw = mon.stop()
        window = _dmesg_window(c)

    assert st["up"] and st["inet"], (
        f"restart_link redial did not complete: {st['raw']}\n{accel_server.log_tail(30)}"
    )
    states = _ifinfo_pppoe0(raw)
    assert len(states) >= 2, (
        f"expected >=2 RTM_IFINFO messages naming pppoe0 across restart_link, "
        f"saw {len(states)}\nroute monitor:\n{_rtmon_evidence(raw)}"
    )
    # The kernel dedups unchanged consecutive link states -- a DOWN state
    # must precede an UP state.  Exact counts are NOT asserted: the routing
    # socket re-broadcasts ifinfo on every flag/address event (probe:
    # ~13 messages for one restart_link), and sppp's close/re-open/re-
    # negotiate cycle legitimately visits DOWN and UP more than once
    # (diag2 dmesg window: DOWN,UP,DOWN,UP).
    seq = _oper_transitions(states)
    assert "DOWN" in seq and "UP" in seq and seq.index("DOWN") < seq.index("UP"), (
        f"restart_link oper-state transitions for pppoe0 do not show DOWN "
        f"then UP: {seq} from {len(states)} messages\n"
        f"route monitor:\n{_rtmon_evidence(raw)}"
    )
    downs, ups = _link_changes(window)
    assert downs and ups and downs[0] < ups[-1], (
        "restart_link must show pppoe0 DOWN before UP in the cleared-ring "
        f"dmesg window (DOWN x{len(downs)}, UP x{len(ups)})\n"
        "dmesg window:\n" + "\n".join(window[-60:])
    )
    # The redial must actually renegotiate, not keep the old address applied:
    # the fresh session is what makes the RTM pair a reconnect, not a no-op.
    assert st["inet"] != base_inet, (
        f"restart_link redial kept the same negotiated address "
        f"({base_inet}) -- MEM068 would look exactly like this"
    )


def test_padt_on_clone_destroy(pppoe_client, sniffer, accel_server, wait_iface_up):
    """`ifconfig pppoe0 destroy` on a live session must PADT naming the live
    session id -- the gap S03 closes.  The conftest sniffer fixture yields an
    UNSTARTED sniffer: sniffer.start() MUST happen before the tear or the
    capture is empty and the assert passes vacuously (MEM114)."""
    c = pppoe_client
    c.dial(service="lab")
    st = _wait_up(c, wait_iface_up, timeout=30)
    assert st["up"] and st["inet"], f"initial dial did not complete: {st['raw']}"
    session = c.parms()["session"]
    assert session, f"no session id on the live session: {c.parms()}"

    sniffer.start()  # BEFORE the tear (MEM114)
    try:
        c.hangup()  # ifconfig pppoe0 destroy
        padt = sniffer.wait_for(
            lambda p: p.haslayer(PPPoED)
            and p[PPPoED].code == PADT
            and p[PPPoED].sessionid == session,
            timeout=10,
        )
    finally:
        sniffer.stop()

    assert padt is not None, (
        f"no PADT for live session {session} captured after `ifconfig pppoe0 "
        "destroy` -- the clone-destroy teardown is not sending PADT "
        "(frames seen: "
        f"{[(p[Ether].type, getattr(p.getlayer(PPPoED), 'code', None))
            for p in sniffer.packets[:20]]})"
    )
    assert padt[PPPoED].sessionid == session


# ---------------------------------------------------------------------------
# IPv6 link-local rebuild (needs_mpdsrv: only mpd5 completes IPv6CP).
# ---------------------------------------------------------------------------


def _wait_ll(client, timeout=45, poll=1.0):
    """The pppoe0 fe80:: link-local once present on the interface, or None.
    (The 'tentative' flag flip-flops on this kernel even with dad_count=0 --
    diag2 baseline -- so it is not a reliable readiness gate; this test's
    teeth are absence-during-outage and presence-after, not DAD state.)"""
    deadline = time.time() + timeout
    st = client.iface_state()
    while time.time() < deadline:
        st = client.iface_state()
        if st["inet6_ll"]:
            return st["inet6_ll"]
        time.sleep(poll)
    return None


def _wait_ll_gone(client, timeout=30, poll=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not client.iface_state()["inet6_ll"]:
            return True
        time.sleep(poll)
    return False


@pytest.mark.needs_mpdsrv
def test_ipv6_link_local_is_rebuilt_not_stale(pppoe_client, wait_iface_up):
    """The DHCPv6-restart contract on the IPv6 side: the fe80:: link-local
    exists after the dial, is ABSENT during the outage window, and a FRESH
    one appears after the re-dial -- it must not survive the tear verbatim.

    Shape mirrors test_ipv6cp.py (dad_count=0, mpdlab, generous ll wait).
    The outage is driven client-side with restart_link(): the plan's
    sanctioned alternative to a server-side tear, because
    MpdsrvServer.terminate_all raises NotImplementedError -- and restart_link
    drives the identical kernel teardown (LCP close -> IPCP tld -> address
    clear, T1-proven) deterministically, keeping the case flake-free
    (MEM083).

    The kernel's auto link-local (net.inet6.ip6.auto_linklocal=1) instantly
    re-creates ANY deleted fe80:: on the interface: diag3 proves the
    driver's clear DOES fire (RTM_DELADDR for the negotiated fe80:: on the
    wire) while ifconfig never shows absence, because the kernel re-seeds
    the ll within milliseconds of the delete.  For the duration of this
    test auto_linklocal is disabled (restored in the finally), leaving the
    driver-negotiated link-local the ONLY fe80:: on pppoe0 -- which makes
    the absence window observable.
    """
    c = pppoe_client
    # p2p DAD can never complete over the PPPoE link; the standard PPP-host
    # sysctl so the negotiated fe80:: applies without waiting for DAD.
    r = c.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    assert r.returncode == 0, f"dad_count=0 failed: {r.stdout}\n{r.stderr}"
    # Disable the kernel's auto link-local so the ONLY fe80:: on pppoe0 is
    # the driver-negotiated one; restored below so later tests are
    # unaffected.
    r = c.run("sysctl -n net.inet6.ip6.auto_linklocal", root=True)
    assert r.returncode == 0, f"auto_linklocal read failed: {r.stdout}\n{r.stderr}"
    saved_all = r.stdout.strip()
    r = c.run("sysctl net.inet6.ip6.auto_linklocal=0", root=True)
    assert r.returncode == 0, (
        f"auto_linklocal=0 failed: {r.stdout}\n{r.stderr}"
    )
    try:
        c.dial(service="mpdlab")
        st = _wait_up(c, wait_iface_up, timeout=30)
        assert st["inet"] and st["inet"].startswith("10.99.2."), (
            f"session did not come up from the mpdlab pool: {st['raw']}"
        )
        ll1 = _wait_ll(c, timeout=45)
        assert ll1 and ll1.startswith("fe80::"), (
            f"no fe80:: link-local on pppoe0 after the mpdlab dial:\n{st['raw']}"
        )

        # Outage: tear the link; the link-local must actually go AWAY (the
        # T1 clear arm), not survive as a stale address.  diag3 measured
        # the observable window: the clear task deletes the ll ~0.5s into
        # restart_link (during its internal down/sleep/up) and the re-dial
        # re-applies ~1.3s later -- the absence window OPENS AND CLOSES
        # WHILE restart_link() IS STILL RUNNING, so a watcher started after
        # it returns only ever samples the tail and misses (run4).  Watch
        # concurrently.
        watcher = {}

        def _watch_absence():
            watcher["gone"] = _wait_ll_gone(c, timeout=40, poll=0.2)

        wt = threading.Thread(target=_watch_absence, daemon=True)
        wt.start()
        c.restart_link()
        wt.join(timeout=60)
        gone = watcher.get("gone", False)
        assert gone, (
            "the fe80:: link-local was never removed during the outage "
            "window -- a stale link-local survived the session tear"
        )

        # Re-dial: a fresh link-local must appear.  Whether the negotiated
        # interface-id repeats is up to the negotiation (mpd5's tunnel ifid
        # is stable), so ll2 may legitimately equal ll1; the absence-
        # during-outage assertion above is the rebuild proof.  Values are
        # recorded for the run log.
        st = _wait_up(c, wait_iface_up, timeout=30)
        assert st["inet"] and st["inet"].startswith("10.99.2."), (
            f"re-dial did not complete: {st['raw']}"
        )
        ll2 = _wait_ll(c, timeout=45)
        assert ll2 and ll2.startswith("fe80::"), (
            f"no fresh fe80:: link-local after the re-dial:\n{st['raw']}"
        )
        print(f"ll rebuild: {ll1} -> {ll2} (re-applied identical: {ll1 == ll2})")
    finally:
        r = c.run(f"sysctl net.inet6.ip6.auto_linklocal={saved_all}", root=True)
        if r.returncode != 0:
            print(f"WARNING: could not restore net.inet6.ip6.auto_linklocal "
                  f"to {saved_all}: {r.stderr}")


def _wait_up(client, wait_iface_up, timeout):
    """wait_iface_up with the driver-client INITIAL-stall watchdog the
    conftest helper already carries; returns the last state."""
    st = wait_iface_up(client, timeout=timeout)
    return st if st else client.iface_state()

# ---------------------------------------------------------------------------
# ALTQ detection on the parent (S03 T4): net.pppoe.parent_altq flip driven
# by pfctl, with the one-shot dmesg warning oracle.  Both terminal states
# of this test are honest outcomes: the full 0 -> 1 -> 0 flip (kernel with
# a working pf/ALTQ) or a pytest.skip whose reason names exactly why the
# kernel cannot attach ALTQ (the functional check then belongs to S06 on
# the real box).  A skip is never a silent pass: the reason string lands
# verbatim in the run log.
# ---------------------------------------------------------------------------


def test_altq_on_the_parent_is_detected_and_warned_about(
    pppoe_client, accel_server, wait_iface_up
):
    """The roadmap demo line: net.pppoe.parent_altq flips with a dmesg
    warning when the parent has ALTQ enabled, and does not warn twice.

    ALTQ on an interface is only reachable through pf (`ifconfig -altq`
    does not exist), so the flip is driven with `pfctl -f` of a cbq
    ruleset on vtnet1, and the T2 detection points (parent bind at
    pppoectl -e, session start at discovery connect) are driven with a
    plain re-dial -- dial() recreates the clone, so every dial is a fresh
    softc and the sysctl tracks the live parent state.

    Oracle: the cleared-ring dmesg window (MEM064) for the one-shot
    warning, and `sysctl -n net.pppoe.parent_altq` for the indicator.
    The one-shot latch is per-softc (sc_parent_altq_warned), so the
    no-repeat assertion uses restart_link() -- the SAME softc re-runs the
    session-start detection point without recreating the clone.
    """
    c = pppoe_client

    # pf pre-state: needed both for the skip decision and for the
    # finally-restore (pfctl -d also detaches any ALTQ discipline).
    r = c.run("pfctl -s info", root=True)
    if r.returncode != 0:
        pytest.skip(
            "pf is not available on this kernel: "
            f"{(r.stderr or r.stdout).strip()}"
        )
    was_enabled = "Status: Enabled" in r.stdout
    conf_written = False

    try:
        # (1) Baseline: with no ALTQ anywhere the indicator is 0 and the
        # detection points do not warn (negative control for the oracle).
        _dmesg_clear(c)
        c.dial(service="lab")
        st = _wait_up(c, wait_iface_up, timeout=60)
        assert st["up"] and st["inet"], (
            f"baseline dial did not complete: {st['raw']}"
        )
        assert c.counter("parent_altq") == 0, (
            "baseline net.pppoe.parent_altq != 0 -- ALTQ is already enabled "
            "on vtnet1 from earlier state (pf was "
            f"{'enabled' if was_enabled else 'disabled'} at test start); "
            "clean the pf state and re-run"
        )
        baseline_warns = [l for l in _dmesg_window(c) if _ALTQ_WARN_MARK in l]
        assert not baseline_warns, (
            "the driver warned about ALTQ on an ALTQ-free parent:\n"
            + "\n".join(baseline_warns)
        )

        # pf must be ENABLED for the cbq discipline to attach and queue.
        r = c.run("pfctl -e", root=True)
        if r.returncode != 0:
            pytest.skip(
                "pf could not be enabled on this kernel: "
                f"{(r.stderr or r.stdout).strip()}"
            )

        # (2) Load the ALTQ ruleset.  A kernel without ALTQ support (or
        # without the cbq discipline) fails right here -- that is the
        # recorded skip.
        r = _ssh_stdin(CLIENT_SSH_PORT, f"cat > {ALTQ_PF_CONF}", _ALTQ_RULESET)
        assert r.returncode == 0, f"could not write {ALTQ_PF_CONF}: {r.stderr}"
        conf_written = True
        r = c.run(f"pfctl -f {ALTQ_PF_CONF}", root=True, timeout=30)
        if r.returncode != 0:
            reason = (r.stderr or r.stdout).strip() or "pfctl -f returned a failure"
            # Drop ssh transport noise (host-key warnings) from the reason.
            reason = "\n".join(
                l for l in reason.splitlines() if not l.startswith("Warning:")
            ).strip()
            # Enrich the recorded skip reason with the kernel's own ALTQ
            # feature flag: kern.features.altq is absent on a kernel built
            # without ALTQ (the OPNsense SMP lab kernel's confirmed state).
            feat = c.run("sysctl -n kern.features.altq 2>&1")
            feat_txt = feat.stdout.strip() or feat.stderr.strip() or "read failed"
            pytest.skip(
                "pfctl could not attach the cbq ALTQ discipline to vtnet1 on "
                "this kernel (kernel lacks ALTQ / discipline support): "
                f"{reason} [kern.features.altq: {feat_txt}]"
            )
        # Advisory proof the discipline really attached (not load-bearing:
        # the sysctl flip below is the contract).
        q = c.run("pfctl -s queue", root=True)
        print(f"pfctl -s queue after ALTQ load: {(q.stdout or q.stderr).strip()[:200]}")

        # (3) Re-bind with ALTQ on: the fresh clone's bind + session start
        # run the detection points -> indicator 1 and exactly ONE warning
        # (the per-softc latch collapses the two detection points of one
        # dial into a single log line).
        _dmesg_clear(c)
        c.dial(service="lab")
        st = _wait_up(c, wait_iface_up, timeout=60)
        assert st["up"] and st["inet"], (
            f"session did not come up with ALTQ enabled on the parent: {st['raw']}"
        )
        assert c.counter("parent_altq") == 1, (
            "net.pppoe.parent_altq did not flip to 1 with ALTQ enabled on "
            "vtnet1\ndmesg window:\n" + "\n".join(_dmesg_window(c)[-40:])
        )
        warns = [l for l in _dmesg_window(c) if _ALTQ_WARN_MARK in l]
        assert len(warns) == 1, (
            f"expected exactly one one-shot ALTQ warning in the window, got "
            f"{len(warns)}:\n" + "\n".join(warns)
        )
        print(f"ALTQ warning observed: {warns[0]}")

        # One-shot latch: the SAME softc (restart_link does not recreate
        # the clone) re-runs the session-start detection point -- the
        # warning must NOT repeat, while the indicator stays 1.
        _dmesg_clear(c)
        c.restart_link()
        st = _wait_up(c, wait_iface_up, timeout=60)
        assert st["up"] and st["inet"], (
            f"restart under ALTQ did not complete: {st['raw']}"
        )
        assert c.counter("parent_altq") == 1
        latch_warns = [l for l in _dmesg_window(c) if _ALTQ_WARN_MARK in l]
        assert not latch_warns, (
            "the ALTQ warning repeated on a second session start of the same "
            "softc -- the one-shot latch (sc_parent_altq_warned) is broken:\n"
            + "\n".join(latch_warns)
        )

        # (4) Remove ALTQ (pass-all keeps the lab reachable), re-bind, and
        # the indicator must follow the live parent state back to 0.
        r = _ssh_stdin(CLIENT_SSH_PORT, f"cat > {ALTQ_PF_CONF}", _CLEAN_RULESET)
        assert r.returncode == 0, f"could not write the clean ruleset: {r.stderr}"
        r = c.run(f"pfctl -f {ALTQ_PF_CONF}", root=True, timeout=30)
        assert r.returncode == 0, (
            f"pfctl -f (clean ruleset) failed: {r.stdout}\n{r.stderr}"
        )
        # Reachability around the ruleset change (the ssh round-trip IS the
        # probe; assert on its marker so a silent timeout cannot pass).
        r = c.run("echo reach-probe-ok")
        assert "reach-probe-ok" in r.stdout, "lab unreachable after removing ALTQ"
        _dmesg_clear(c)
        c.dial(service="lab")
        st = _wait_up(c, wait_iface_up, timeout=60)
        assert st["up"] and st["inet"], (
            f"session did not come up after removing ALTQ: {st['raw']}"
        )
        r = c.run("echo reach-probe-ok")
        assert "reach-probe-ok" in r.stdout, "lab unreachable after the final re-bind"
        assert c.counter("parent_altq") == 0, (
            "net.pppoe.parent_altq did not drop back to 0 after the ALTQ "
            "ruleset was removed and the parent re-bound"
        )
        final_warns = [l for l in _dmesg_window(c) if _ALTQ_WARN_MARK in l]
        assert not final_warns, (
            "the driver warned about ALTQ after the ALTQ ruleset was "
            "removed:\n" + "\n".join(final_warns)
        )
        print("ALTQ flip cycle complete: 0 -> 1 (warn once) -> 0")
    finally:
        # Restore the lab's pf state: always leave the pass-all ruleset
        # loaded (keeps the lab reachable even on an assert-aborted path),
        # and put pf back to its pre-test enabled state -- pfctl -d also
        # detaches any leftover ALTQ discipline.  Best-effort: the
        # assertions above have already spoken.
        if conf_written:
            c.run(f"pfctl -f {ALTQ_PF_CONF}", root=True)
        if not was_enabled:
            c.run("pfctl -d", root=True)
        c.run(f"rm -f {ALTQ_PF_CONF}", root=True)
