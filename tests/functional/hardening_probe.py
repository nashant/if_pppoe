#!/usr/bin/env python3
"""S02 hardening probe: kldunload under traffic, vnet jail cycles, M_PPPOE
accounting.

Standalone script -- deliberately NOT a pytest test. It has no test_ prefix
anywhere and only a top-level main(), so pytest's default
python_files=test_*.py / *_test.py never collects it; the suite count stays
pinned (MEM008) and this probe must never become a counted test.

Run like the suite, ON <LAB_HOST>, under sudo (scapy needs raw sockets on
br-isp for the PADT sniffer):

    sudo env CLIENT=if_pppoe SERVER=accel venv/bin/python3 \
        tests-functional/hardening_probe.py

CLIENT seam: only CLIENT=if_pppoe is legal -- this probe kldunload's the
if_pppoe kernel module, which the mpd5 backend cannot do; any other CLIENT
value hard-fails with an explanation instead of silently probing nothing.

What it does:
  1. Snapshot the byte offset of run/client.serial.log (the client VM's
     console; the panic oracle -- it accumulates across cycles, the loop
     never restarts the VM) and the vmstat -m pppoe row (M_PPPOE inuse /
     memuse) plus the dmesg 'leaked memory on destroy' count as the
     phase-C before-snapshot.
  2. Quiesce mpd5 (the driver shares vtnet1's MAC and the pppoe0 name --
     MEM055) and destroy any stale pppoe0 clone.
  3. Phase A -- 10 traffic cycles: kldload -> create/up pppoe0 on vtnet1 ->
     wait PPPOE_STATE_SESSION -> log the netstat -Q pppoe workstream
     depth as INFORMATIONAL ONLY (depth-0 is only stable when idle; M001
     finding I1 -- it is NEVER asserted here) -> iperf3 -c 10.99.0.1 -t 5
     over the live session (iperf3 -s -D runs on the isp VM and
     provision-client.sh installs iperf3 on the client) -> kldunload
     PROMPTLY with the live session still up (in-flight frames still race
     teardown; the queue-depth precondition is not stable under traffic)
     -> kldstat shows if_pppoe gone -> the sniffer caught the PADT naming
     the live session -> serial log tail has no panic signature -> the
     client VM still answers ssh -> next cycle reloads the module.
  4. Phase B -- 5 vnet jail create/destroy cycles with the session up:
     jail -c name=hN host.hostname=hN vnet persist -> jail -r -> assert no
     panic signature, ssh alive, session still up. After the 5 cycles
     assert the module still dials.
  5. Phase C -- M_PPPOE accounting: the vmstat -m pppoe row after all
     phases must equal the before-snapshot (count and bytes flat) and
     dmesg must not have gained a 'leaked memory on destroy' line during
     the run. Both are asserted. Both vmstat rows are taken LIKE-FOR-LIKE
     (module resident, no clone: the module is force-loaded right after
     the quiesce, and the after row is re-taken after the live clone is
     destroyed) -- a session-live row would structurally differ from the
     quiesced before-row (softc/strings/cookie/wq are session-owned) and
     make "flat" meaningless. Note the dmesg 'leaked memory on destroy'
     count is the real MEM093 leak oracle: an allocation leaked at
     kldunload dies with its malloc-type instance, so vmstat can never
     see it in the current instance's row.
  6. finally: destroy any clone and re-dial via IfPppoeClient, restoring
     exactly what conftest's `driver` fixture leaves behind (the driver
     fixture leaves mpd5 stopped; conftest restarts it at session end --
     the probe likewise leaves mpd5 stopped).

Every assertion miss is printed as a FAIL line and turns the exit code
non-zero, so a teardown that cannot survive traffic makes this probe's
exit status the operational FAIL the milestone gate needs.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lab import (  # noqa: E402
    CLIENT_SERIAL_REL,
    CLIENT_SSH_PORT,
    IfPppoeClient,
    IfPppoeDriver,
    PPPoESniffer,
    PPPOE_STATE_SESSION,
    PADT,
    _ssh,
    exempt_from_rc_autoconf,
)
from scapy.all import PPPoED  # noqa: E402

LAB_SERVICE = "lab"

# Panic signatures grep'd from the serial-log tail -- the generic FreeBSD
# crash texts (the kernel's own "panic:" banner, the "Fatal trap" banner,
# the bare "trap 12", and the naked "page fault" wording).
PANIC_PATTERNS = (
    re.compile(r"\bpanic\b"),
    re.compile(r"Fatal trap"),
    re.compile(r"trap 12"),
    re.compile(r"page fault"),
)


def _netisr_pppoe_queue_len(d) -> int:
    """netstat -Q parse: the pppoe workstream's current queue depth.

    Mirrors unload_probe.py's I1 tripwire parser. Here the depth is
    INFORMATIONAL only: under traffic the depth is NOT stable at 0 (frames
    are legitimately in flight/queued), so the precondition must never be
    asserted -- the value is logged so the run log still shows the
    in-flight window the unload races. Returns -1 when unparseable (a
    changed netstat format stays visible, never silent).
    """
    try:
        r = d.run("netstat -Q")
    except Exception:
        return -1
    if r.returncode != 0:
        return -1
    total = 0
    found = False
    for m in re.finditer(r"^\s*\d+\s+\d+\s+pppoe\s+(\d+)\s", r.stdout, re.M):
        total += int(m.group(1))
        found = True
    return total if found else -1


# ---------------------------------------------------------------------------
# Serial log plumbing (the panic oracle).  The probe runs under sudo, so
# $HOME is root's; recover the invoking user like lab.py's _default_ssh_key().
# ---------------------------------------------------------------------------
def _sudo_home() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    return os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")


SERIAL_LOG = os.environ.get("LAB_SERIAL_LOG") or os.path.join(
    _sudo_home(), CLIENT_SERIAL_REL
)


def _serial_offset() -> int:
    try:
        return os.path.getsize(SERIAL_LOG)
    except OSError:
        return 0


def _serial_tail(offset: int) -> str | None:
    """Serial-log bytes after `offset`; None when the oracle is unreadable.

    The serial log IS the panic oracle -- a probe that passed because the
    file was missing would be faking a clean log.  An unreadable oracle
    therefore returns None and the caller FAILs the panic-signature check.
    """
    try:
        with open(SERIAL_LOG, "rb") as fh:
            fh.seek(offset)
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return None


def _serial_panic_hits(tail: str, limit: int = 5) -> list[str]:
    """Lines of `tail` matching a panic signature, de-duplicated, capped."""
    hits: list[str] = []
    for ln in tail.splitlines():
        stripped = ln.strip()
        if not stripped or stripped in hits:
            continue
        if any(pat.search(stripped) for pat in PANIC_PATTERNS):
            hits.append(stripped)
            if len(hits) >= limit:
                break
    return hits


# ---------------------------------------------------------------------------
# SSH liveness + iface helpers (re-implemented inline; this script must NOT
# import conftest, and the suite needs no new fixtures).
# ---------------------------------------------------------------------------
def _client_ssh_up() -> bool:
    try:
        r = _ssh(CLIENT_SSH_PORT, "echo pppoe-probe-alive", timeout=10)
        return r.returncode == 0 and "pppoe-probe-alive" in r.stdout
    except Exception:
        return False


def _wait_iface_up(client, timeout: float = 30.0, poll: float = 1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.iface_state()
        if last["up"] and last["inet"]:
            return last
        time.sleep(poll)
    return last


def _wait_iface_gone(client, iface: str = "pppoe0", timeout: float = 30.0, poll: float = 0.5):
    """True once `iface` has disappeared from `ifconfig -l` on the client VM."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if iface not in client.run("ifconfig -l").stdout.split():
            return True
        time.sleep(poll)
    return False


# ---------------------------------------------------------------------------
# Check accounting: one printed line per assertion, FAIL anywhere -> exit 1.
# ---------------------------------------------------------------------------
_results: list[tuple[str, bool, str]] = []


def _check(name: str, cond: bool, detail: str = "") -> bool:
    _results.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}: {name}" + (f"  [{detail}]" if detail else ""))
    return bool(cond)


def _info(msg: str) -> None:
    """Informational line: observed, logged, never asserted."""
    print(f"INFO: {msg}")


# ---------------------------------------------------------------------------
# M_PPPOE accounting helpers (phase C).
# ---------------------------------------------------------------------------
def _vmstat_pppoe_row(d) -> tuple[int, str] | None:
    """(inuse, memuse) of the vmstat -m 'pppoe' row; (0, '0K') when absent.

    vmstat -m prints one row per malloc type:
    "pppoe   <InUse> <MemUse> <HighUse> <Requests> <Size(s)>".  InUse and
    MemUse are the leak accounting; the row is genuinely absent (all-zero)
    before the first M_PPPOE allocation, which is the same as flat-zero.
    Returns None when vmstat itself fails so a broken harness cannot fake
    a flat type.
    """
    try:
        r = d.run("vmstat -m")
    except Exception:
        return None
    if r.returncode != 0:
        return None
    for ln in r.stdout.splitlines():
        f = ln.split()
        if f and f[0] == "pppoe" and len(f) >= 3:
            try:
                return (int(f[1]), f[2])
            except ValueError:
                return None
    return (0, "0K")


def _dmesg_leak_count(d) -> int | None:
    """Number of 'leaked memory on destroy' lines in dmesg; None on failure."""
    try:
        r = d.run("dmesg")
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.count("leaked memory on destroy")


# ---------------------------------------------------------------------------
# iperf3 bitrate parse: any summary row's "N.MUbits/sec sender/receiver".
# ---------------------------------------------------------------------------
_IPERF_ROW_RE = re.compile(
    r"([\d.]+)\s+([KMGT]?)bits/sec\s+(sender|receiver)", re.I
)
_IPERF_MULT = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}


def _iperf_max_bits(out: str) -> float:
    best = 0.0
    for m in _IPERF_ROW_RE.finditer(out):
        try:
            val = float(m.group(1)) * _IPERF_MULT[m.group(2).upper()]
        except (ValueError, KeyError):
            continue
        best = max(best, val)
    return best


def _run_traffic(d, i: int) -> bool:
    """Push iperf3 -c 10.99.0.1 -t 5 over the live session; True on success."""
    # PPPOE_STATE_SESSION only means discovery finished: sppp's IPCP can
    # still be negotiating, and until pppoe0 holds its negotiated inet the
    # 10.99.0.1 host route does not exist -- iperf3's SYN then follows the
    # default route (vtnet0) and blackholes until iperf3's own 60s connect
    # timeout, i.e. the ssh timeout fires first and every cycle fails
    # (live-run finding: all 10 pre-fix cycles timed out at 30s; with the
    # IPCP wait, the same manual iperf3 flows at ~2.7Gbit/s).  Wait for the
    # IPCP address before starting traffic.
    up = _wait_iface_up(d, timeout=15)
    if not (up and up["inet"]):
        _check(f"iter {i}: iperf3 traffic over the live session", False,
               f"no IPCP address on pppoe0 before iperf: {up}")
        return False
    try:
        r = d.run("iperf3 -c 10.99.0.1 -t 5", root=True, timeout=45)
    except Exception as exc:
        _check(f"iter {i}: iperf3 traffic over the live session", False,
               f"{type(exc).__name__}: {exc}")
        return False
    bits = _iperf_max_bits(r.stdout)
    ok = r.returncode == 0 and bits > 0
    _check(f"iter {i}: iperf3 traffic over the live session", ok,
           f"rc={r.returncode} max_bits/sec={bits:.0f}"
           + ("" if ok else f" stderr={r.stderr.strip()[:200]}"))
    return ok


# ---------------------------------------------------------------------------
# Phase A: one traffic-under-unload cycle.
# ---------------------------------------------------------------------------
def _establish_session(d: IfPppoeDriver, label: str, timeout: int = 45) -> dict:
    """Dial a fresh pppoe0 session, hardened for the slower debug kernel.

    create() already embeds the MEM112 force-reload (unload-if-present +
    load), destroys any stale pppoe0 clone, and pre-downs the fresh clone
    so every up() is a real SIOCSIFFLAGS transition.  Two SMPW findings
    shape the rest of this helper: (1) the WITNESS/INVARIANTS kernel runs
    discovery noticeably slower than the release kernel, so the
    wait_state timeout is raised from the release-kernel 20s to `timeout`
    (45s); (2) immediately after the 10th unload-under-traffic cycle the
    phase-B re-dial stalled for the whole window with state=0
    padi_retries=0 on BOTH prior SMPW runs (deterministic, while the
    identical dial path succeeded at every traffic cycle).  A stalled
    dial therefore gets the same one bounded down->up remedy the traffic
    cycles and conftest's dial watchdog encode: re-entering SIOCSIFFLAGS
    re-opens LCP and restarts discovery.
    """
    d.create(iface="pppoe0", parent="vtnet1", service=LAB_SERVICE)
    d.up("pppoe0")
    state = d.wait_state(PPPOE_STATE_SESSION, timeout=timeout)
    if state.get("state") != PPPOE_STATE_SESSION:
        _info(f"{label}: dial stalled at state={state.get('state')} "
              f"padi_retries={state.get('padi_retries')} -- applying the "
              "bounded down->up discovery restart")
        d.down("pppoe0")
        time.sleep(1)
        d.up("pppoe0")
        state = d.wait_state(PPPOE_STATE_SESSION, timeout=timeout)
    return state


def _run_traffic_cycle(d: IfPppoeDriver, sniffer: PPPoESniffer, i: int) -> None:
    offset = _serial_offset()

    parms = _establish_session(d, f"iter {i}", timeout=20)
    session = parms.get("session")
    _check(f"iter {i}: session established", parms.get("state") == PPPOE_STATE_SESSION,
           f"{parms}")
    if parms.get("state") != PPPOE_STATE_SESSION:
        return  # nothing was up, so there is no unload-with-live-session to probe

    _info(f"iter {i}: netstat -Q pppoe workstream depth "
          f"{_netisr_pppoe_queue_len(d)} (informational only: not stable under traffic)")

    sniffer.start()
    try:
        _run_traffic(d, i)
        d.kldunload()  # module goes away with the live session still up, promptly
        padt = sniffer.wait_for(
            lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADT, timeout=10
        )
    finally:
        sniffer.stop()

    r = d.run("kldstat -q -n if_pppoe")
    _check(f"iter {i}: if_pppoe gone from kldstat after kldunload",
           r.returncode != 0, f"kldstat -q -n exit {r.returncode}")
    _check(f"iter {i}: PADT on the wire for session {session}",
           padt is not None and padt[PPPoED].sessionid == session,
           f"sniffed sessionid={padt[PPPoED].sessionid if padt is not None else 'none'}")
    _check(f"iter {i}: client VM answers ssh (no panic/reboot)", _client_ssh_up())

    tail = _serial_tail(offset)
    if tail is None:
        _check(f"iter {i}: serial log readable (panic oracle present)", False,
               f"cannot read {SERIAL_LOG}")
        return
    hits = _serial_panic_hits(tail)
    _check(f"iter {i}: serial log tail has no panic signature",
           not hits,
           "; ".join(hits) if hits else f"{len(tail)} bytes since cycle start")


# ---------------------------------------------------------------------------
# Phase B: one vnet jail create/destroy cycle with the session up.
# ---------------------------------------------------------------------------
def _run_jail_cycle(d: IfPppoeDriver, i: int, offset: int) -> None:
    r = d.run(f"jail -c name=h{i} host.hostname=h{i} vnet persist", root=True)
    _check(f"jail {i}: created", r.returncode == 0, f"rc={r.returncode} {r.stderr.strip()[:120]}")
    time.sleep(1.0)
    d.run(f"jail -r h{i}", root=True)
    time.sleep(0.5)

    tail = _serial_tail(offset)
    if tail is None:
        _check(f"jail {i}: serial log readable (panic oracle present)", False,
               f"cannot read {SERIAL_LOG}")
    else:
        hits = _serial_panic_hits(tail)
        _check(f"jail {i}: no panic signature", not hits,
               "; ".join(hits) if hits else f"{len(tail)} bytes since jail phase start")
    _check(f"jail {i}: client VM answers ssh", _client_ssh_up())
    state = d.wait_state(PPPOE_STATE_SESSION, timeout=10)
    _check(f"jail {i}: session still up after destroy", state.get("state") == PPPOE_STATE_SESSION,
           f"state={state.get('state')}")


# ---------------------------------------------------------------------------
# Setup: quiesce mpd5 (MEM055) and clear any stale clone.
# ---------------------------------------------------------------------------
def _setup_quiesce(d: IfPppoeDriver) -> bool:
    try:
        r = d.run("service mpd5 onestatus")
    except Exception as exc:
        _check("setup: mpd5 quiesce probe", False, f"{type(exc).__name__}: {exc}")
        return False
    if r.returncode == 0 and "mpd5 is running" in r.stdout:
        st = d.run("service mpd5 stop", root=True)
        _check("setup: mpd5 stopped (driver owns vtnet1's MAC, MEM055)", st.returncode == 0,
               f"rc={st.returncode}")
        time.sleep(2.0)
    else:
        _info("mpd5 not running -- nothing to quiesce")
    client = IfPppoeClient()
    client.hangup()
    gone = _wait_iface_gone(client, "pppoe0", timeout=30)
    _check("setup: pppoe0 clone gone", gone)
    return gone


def main() -> int:
    ap = argparse.ArgumentParser(description="M003/S02 hardening probe")
    ap.add_argument("--traffic-cycles", type=int, default=10,
                    help="kldunload-under-traffic cycles (default 10)")
    ap.add_argument("--jail-cycles", type=int, default=5,
                    help="vnet jail create/destroy cycles (default 5)")
    args = ap.parse_args()

    client_key = os.environ.get("CLIENT", "if_pppoe")
    if client_key != "if_pppoe":
        print(
            f"FAIL: CLIENT={client_key!r} is not supported by this probe: "
            "the hardening contract kldunload's the if_pppoe kernel module, "
            "which only the CLIENT=if_pppoe seam can drive (mpd5 cannot "
            "kldunload the module). Re-run with CLIENT=if_pppoe.",
            file=sys.stderr,
        )
        return 1

    d = IfPppoeDriver()
    sniffer = PPPoESniffer()

    print(f"serial log: {SERIAL_LOG}")
    print(f"traffic cycles: {args.traffic_cycles}, jail cycles: {args.jail_cycles}")
    start = time.time()
    try:
        # devd's `pccard_ether pppoe0 stop` on the DETACH each kldunload's
        # clone destroy posts would otherwise autoload if_pppoe straight
        # back (lab.RC_AUTOCONF_EXEMPT) -- the "gone from kldstat" misses.
        exempt_from_rc_autoconf(d.run)
        if not _setup_quiesce(d):
            return 1
        # Force-load the freshly-deployed module before the before-snapshot:
        # both phase-C vmstat rows must be taken in the same state (module
        # resident, no clone), and a stale resident .ko must never survive
        # into the run (kldload() unloads first -- MEM112 discipline).
        d.kldload()

        before_row = _vmstat_pppoe_row(d)
        before_leaks = _dmesg_leak_count(d)
        if before_row is None:
            _check("phase C: vmstat -m pppoe row readable (before)", False,
                   "vmstat failed or row unparseable")
        else:
            _info(f"before: vmstat -m pppoe row inuse={before_row[0]} memuse={before_row[1]}")
            _check("phase C: vmstat -m pppoe row readable (before)", True)
        if before_leaks is None:
            _check("phase C: dmesg readable (before)", False, "dmesg failed")
        else:
            _info(f"before: dmesg 'leaked memory on destroy' count {before_leaks}")
            _check("phase C: dmesg readable (before)", True)

        print("--- phase A: traffic-under-unload cycles ---")
        for i in range(1, args.traffic_cycles + 1):
            print(f"--- traffic cycle {i}/{args.traffic_cycles} ---")
            try:
                _run_traffic_cycle(d, sniffer, i)
            except Exception as exc:
                _check(f"iter {i}: completed without exception", False,
                       f"{type(exc).__name__}: {exc}")

        print("--- phase B: vnet jail create/destroy cycles ---")
        # Settle after the 10th PADT before re-dialing: the accel peer tears
        # its per-session state down asynchronously, and on the slower
        # WITNESS/INVARIANTS kernel the phase-B re-dial raced that teardown
        # in both prior SMPW runs (state=0, padi_retries=0 for the whole
        # window).  The setup-quiesce discipline (destroy any stale clone
        # first) is embedded in create(); the timeout is the debug kernel's
        # 45s; a stalled dial gets the bounded down->up restart.
        time.sleep(3.0)
        state = _establish_session(d, "phase B")
        _check("phase B: session re-established before jail cycles",
               state.get("state") == PPPOE_STATE_SESSION, f"{state}")
        offset = _serial_offset()
        for i in range(1, args.jail_cycles + 1):
            print(f"--- jail cycle {i}/{args.jail_cycles} ---")
            try:
                _run_jail_cycle(d, i, offset)
            except Exception as exc:
                _check(f"jail {i}: completed without exception", False,
                       f"{type(exc).__name__}: {exc}")
        # After the 5 cycles the module must still dial.
        try:
            state = _establish_session(d, "phase B post-jail")
            _check("phase B: module still dials after jail cycles",
                   state.get("state") == PPPOE_STATE_SESSION, f"{state}")
        except Exception as exc:
            _check("phase B: module still dials after jail cycles", False,
                   f"{type(exc).__name__}: {exc}")

        print("--- phase C: M_PPPOE accounting ---")
        after_row_live = _vmstat_pppoe_row(d)
        if after_row_live is not None:
            _info(f"after (session live): vmstat -m pppoe row "
                  f"inuse={after_row_live[0]} memuse={after_row_live[1]}")
        # Like-for-like with the before-snapshot (module resident, no
        # clone): destroy the live clone and let the epoch-deferred softc
        # free land before taking the row the flat check compares.
        d.destroy()
        gone = _wait_iface_gone(d, "pppoe0", timeout=30)
        _check("phase C: session clone destroyed for accounting", gone)
        time.sleep(2.0)  # NET_EPOCH_CALL softc free lands
        after_row = _vmstat_pppoe_row(d)
        if after_row is None or before_row is None:
            _check("phase C: vmstat -m pppoe row readable (after)", False,
                   "vmstat failed or row unparseable")
        else:
            _info(f"after: vmstat -m pppoe row inuse={after_row[0]} memuse={after_row[1]}")
            _check("phase C: M_PPPOE flat (inuse and memuse unchanged)",
                   after_row == before_row,
                   f"before inuse={before_row[0]} memuse={before_row[1]}, "
                   f"after inuse={after_row[0]} memuse={after_row[1]}"
                   + ("" if after_row == before_row else " (MEM093 pre-T3)"))
        after_leaks = _dmesg_leak_count(d)
        if after_leaks is None or before_leaks is None:
            _check("phase C: dmesg leak-line count readable (after)", False,
                   "dmesg failed or unreadable")
        else:
            _info(f"after: dmesg 'leaked memory on destroy' count {after_leaks}")
            _check("phase C: no new 'leaked memory on destroy' in dmesg",
                   after_leaks == before_leaks,
                   f"count {before_leaks} -> {after_leaks}"
                   + ("" if after_leaks == before_leaks else " (MEM093 pre-T3)"))
    finally:
        # Restore the driver fixture's end state: clone destroyed, module
        # loaded (load-if-absent), client re-dialed to service 'lab'.
        try:
            d.destroy()
            client = IfPppoeClient()
            client.dial(service=LAB_SERVICE)
            restored = _wait_iface_up(client, timeout=30)
            _check("restore: client re-dialed to service 'lab'",
                   bool(restored and restored["up"] and restored["inet"]), f"{restored}")
        except Exception as exc:
            _check("restore: client re-dialed to service 'lab'", False,
                   f"{type(exc).__name__}: {exc}")

    elapsed = time.time() - start
    failed = [name for name, ok, _ in _results if not ok]
    print()
    print(f"RESULT: {len(_results) - len(failed)}/{len(_results)} checks passed"
          + (f", {len(failed)} FAILED" if failed else "") + f", in {elapsed:.0f}s")
    for name, ok, detail in _results:
        if not ok:
            print(f"  still failing: {name} [{detail}]")
    return 1 if failed else 0


if __name__ == "__main__":
    # The run's PPPoE account is generated, installed on the servers' tmpfs
    # and removed again around main() (labcreds.py) -- no fixed account.
    from labcreds import lab_session

    with lab_session():
        rc = main()
    sys.exit(rc)
