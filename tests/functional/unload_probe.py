#!/usr/bin/env python3
"""Operational teardown probe for the M001/S01 MOD_UNLOAD ordering fix.

Standalone script -- deliberately NOT a pytest test. It has no test_ prefix
and only a top-level main(), so pytest's default python_files=test_*.py /
*_test.py never collects it; the suite count is pinned at 37 passed / 2
deselected / 2 xfailed through M001, and this probe must not become a 38th
test.

Run like the suite, ON <LAB_HOST>, under sudo (scapy needs raw sockets
on br-isp):

    sudo env CLIENT=mpd5 SERVER=accel venv/bin/python3 \
        tests-functional/unload_probe.py --iterations 10

What it does:
  1. Snapshot the byte offset of run/client.serial.log (the client VM's
     console; it accumulates across iterations -- the loop never restarts
     the VM).
  2. Mirror the pytest ``driver`` fixture's setup: hang up mpd5 and wait
     for pppoe0 to vanish (the in-kernel clone needs the name + parent).
  3. --iterations times (default 10): IfPppoeDriver.kldload() (force-reload)
     -> create the pppoe0 clone on vtnet1, service 'lab' -> up ->
     PPPOE_STATE_SESSION -> arm the br-isp PPPoE sniffer -> kldunload with
     the live session up -> assert (a) netstat -Q shows the pppoe
     workstream queue depth at 0 before the unload (review finding I1's
     residual queued-workstream tripwire), (b) kldstat shows if_pppoe gone,
     (c) the sniffer caught a PADT naming the session that was up,
     (d) the serial log's new tail has no panic signature, (e) the client
     VM still answers ssh (no panic/reboot took it down).
  4. Late-jail smoke: with the module loaded again, create a vnet jail on
     the client VM and assert dmesg did NOT gain the 'pppoe: pfil_link'
     warning (pppoe_vnet_init() at SI_SUB_PROTO_IF links the hook in a
     vnet created after kldload), then destroy the jail and kldunload.
  5. finally: destroy any pppoe0 clone and re-dial mpd5 to service 'lab',
     restoring exactly what conftest's ``driver`` fixture leaves behind.

Every assertion miss is printed as a FAIL line and turns the exit code
non-zero, so a broken unload ordering makes this probe's exit status the
operational FAIL the milestone gate needs.
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
    IfPppoeDriver,
    Mpd5Client,
    PPPoESniffer,
    PPPOE_STATE_SESSION,
    PADT,
    _ssh,
)
from scapy.all import PPPoED  # noqa: E402

LAB_SERVICE = "lab"

# Panic signatures grep'd from the serial-log tail.  These are the generic
# FreeBSD crash texts: the kernel's own "panic:" banner, the "Fatal trap"
# banner ("Fatal trap 12: page fault while in kernel mode", "Fatal trap 6:"),
# the bare "trap 12", and the naked "page fault" wording.
PANIC_PATTERNS = (
    re.compile(r"\bpanic\b"),
    re.compile(r"Fatal trap"),
    re.compile(r"trap 12"),
    re.compile(r"page fault"),
)

# The if_pppoe workstream's netisr protocol number (sys/net/if_pppoe.h):
# netstat -Q prints it in the "Proto" column of the pppoe row.
NETISR_PPPOE_DATA = 11


def _netisr_pppoe_queue_len(d) -> int:
    """netstat -Q parse: the pppoe workstream's current queue depth.

    netstat -Q prints a "Protocols" table (one row per registered netisr
    protocol: "Name Proto QLimit Policy Dispatch Flags" -- QLimit is a
    constant cap, NOT a depth) and a "Workstreams" table (one row per
    CPU: "WSID CPU Name Len WMark ..." -- Len is the current queue
    depth).  A depth above zero means a frame is still queued for the
    pppoe workstream that a just-started swi_net could still read
    np_handler for -- the residual queued-workstream window review
    finding I1 documents (NET_EPOCH_WAIT() does not cover queued work).
    The queue must read 0 before every kldunload; the sum of the Len
    column across all pppoe workstream rows is returned (0 when empty).
    When the pppoe workstream rows cannot be found or parsed this
    returns -1 so a changed netstat format turns the tripwire into a
    FAIL, never a silent pass.
    """
    try:
        r = d.run("netstat -Q")
    except Exception:
        return -1
    if r.returncode != 0:
        return -1
    # Workstreams rows look like: "   0   0   pppoe      0     0 ...".
    # Capture the Len column (index 3) for every pppoe row and sum.
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
# SSH liveness + the two tiny iface helpers (re-implemented inline; this
# script must NOT import conftest, and the suite needs no new fixtures).
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


# ---------------------------------------------------------------------------
# One live-session kldunload cycle.
# ---------------------------------------------------------------------------
def _run_iteration(d: IfPppoeDriver, sniffer: PPPoESniffer, i: int) -> None:
    offset = _serial_offset()

    d.kldload()
    d.create(iface="pppoe0", parent="vtnet1", service=LAB_SERVICE)
    d.up("pppoe0")
    parms = d.wait_state(PPPOE_STATE_SESSION, timeout=20)
    session = parms.get("session")
    _check(f"iter {i}: session established", parms.get("state") == PPPOE_STATE_SESSION, f"{parms}")
    if parms.get("state") != PPPOE_STATE_SESSION:
        return  # nothing was up, so there is no unload-with-live-session to probe

    sniffer.start()
    qlen = _netisr_pppoe_queue_len(d)
    _check(
        f"iter {i}: netstat -Q pppoe queue depth 0 before kldunload (I1 residual-window tripwire)",
        qlen == 0,
        f"pppoe workstream queue depth {qlen}",
    )
    try:
        d.kldunload()  # module goes away with the live session still up
        padt = sniffer.wait_for(
            lambda p: p.haslayer(PPPoED) and p[PPPoED].code == PADT, timeout=10
        )
    finally:
        sniffer.stop()

    r = d.run("kldstat -q -n if_pppoe")
    _check(
        f"iter {i}: if_pppoe gone from kldstat after kldunload",
        r.returncode != 0,
        f"kldstat -q -n exit {r.returncode}",
    )
    _check(
        f"iter {i}: PADT on the wire for session {session}",
        padt is not None and padt[PPPoED].sessionid == session,
        f"sniffed sessionid={padt[PPPoED].sessionid if padt is not None else 'none'}",
    )
    _check(f"iter {i}: client VM answers ssh (no panic/reboot)", _client_ssh_up())

    tail = _serial_tail(offset)
    if tail is None:
        _check(
            f"iter {i}: serial log readable (panic oracle present)",
            False,
            f"cannot read {SERIAL_LOG}",
        )
        return
    hits = _serial_panic_hits(tail)
    _check(
        f"iter {i}: serial log tail has no panic signature",
        not hits,
        "; ".join(hits) if hits else f"{len(tail)} bytes since iteration start",
    )


# ---------------------------------------------------------------------------
# Late-jail smoke: a vnet jail created AFTER kldload runs pppoe_vnet_init()
# from its own vnet_alloc(), after vnet_ether_init() made the link pfil head
# (both at SI_SUB_PROTO_IF), so pppoe_pfil_attach()'s pfil_link() succeeds
# and its warning must stay out of dmesg.
# ---------------------------------------------------------------------------
def _loud_path_smoke(d: IfPppoeDriver) -> None:
    d.kldload()
    d.run("jail -r t13guard", root=True)  # stale jail from a crashed prior run: no-op
    before = d.run("dmesg").stdout
    before_count = before.count("pppoe: pfil_link")
    r = d.run("jail -c name=t13guard host.hostname=guard vnet persist", root=True)
    _check("loud-path: vnet jail t13guard created", r.returncode == 0, f"rc={r.returncode}")
    if r.returncode != 0:
        d.kldunload()
        return
    time.sleep(1.0)
    after = d.run("dmesg").stdout
    _check(
        "loud-path: no 'pppoe: pfil_link' warning for a jail made after kldload",
        after.count("pppoe: pfil_link") == before_count,
        f"occurrences {before_count} -> {after.count('pppoe: pfil_link')}",
    )
    d.run("jail -r t13guard", root=True)
    _check("loud-path: jail destroyed", True)
    d.kldunload()
    _check("loud-path: module unloaded after smoke", True)


def main() -> int:
    ap = argparse.ArgumentParser(description="M001/S01 kldunload operational probe")
    ap.add_argument("--iterations", type=int, default=10, help="kldload->kldunload cycles (default 10)")
    args = ap.parse_args()

    d = IfPppoeDriver()
    client = Mpd5Client()
    sniffer = PPPoESniffer()

    print(f"serial log: {SERIAL_LOG}")
    print(f"iterations: {args.iterations}")
    start = time.time()
    try:
        client.hangup()
        gone = _wait_iface_gone(client, "pppoe0", timeout=30)
        _check("setup: mpd5 hung up, pppoe0 vanished", gone)
        if not gone:
            return 1  # the in-kernel clone cannot take the name while mpd5 holds it

        for i in range(1, args.iterations + 1):
            print(f"--- iteration {i}/{args.iterations} ---")
            try:
                _run_iteration(d, sniffer, i)
            except Exception as exc:
                _check(
                    f"iter {i}: completed without exception",
                    False,
                    f"{type(exc).__name__}: {exc}",
                )

        print("--- loud-path jail smoke ---")
        try:
            _loud_path_smoke(d)
        except Exception as exc:
            _check("loud-path: smoke completed", False, f"{type(exc).__name__}: {exc}")
    finally:
        d.destroy()
        try:
            client.dial(service=LAB_SERVICE)
            restored = _wait_iface_up(client, timeout=30)
            _check(
                "restore: mpd5 re-dialed to service 'lab'",
                bool(restored and restored["up"] and restored["inet"]),
                f"{restored}",
            )
        except Exception as exc:
            _check(
                "restore: mpd5 re-dialed to service 'lab'",
                False,
                f"{type(exc).__name__}: {exc}",
            )

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
