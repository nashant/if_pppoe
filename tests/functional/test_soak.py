"""24h soaks. Marked `soak`, excluded by the default `-m "not soak"` run
(see lab/Makefile's test-func target) -- select explicitly with `-m soak`
when you actually want to run them (they take 24 hours).

Two cases:
  * test_redial_every_10_minutes_for_24_hours -- the mpd5 redial loop,
    written and reviewed in the S02-era harness work (run it under
    CLIENT=mpd5).
  * test_if_pppoe_24h_soak_no_leak_no_drop -- the in-kernel driver's 24h
    session soak (S04 T1, M003): one live session, continuous ping traffic,
    hourly leak/drop checks.  The hourly assertions live in the module-level
    soak_hourly_check() helper so S05's sustained multi-flow run can import
    them.  Launch the driver soak detached on <LAB_HOST>:

        ssh <LAB_HOST> 'cd if_pppoe-lab && nohup sudo env CLIENT=if_pppoe \\
            SERVER=accel venv/bin/python3 -m pytest tests-functional \\
            -m soak -k no_leak_no_drop -v > /tmp/soak.log 2>&1 &'

    (-k no_leak_no_drop on purpose: under CLIENT=if_pppoe a bare `-m soak`
    would also collect the mpd5 redial loop and the datapath PADI-backoff
    case, running three soaks back to back instead of the one 24h clock.)
"""
from __future__ import annotations

import os
import time

import pytest

from lab import ACCEL_GW, IfPppoeDriver

LAB_SERVICE = "lab"

# Driver-only gate (S01's _DRIVER_ONLY pattern): the leak/drop assertions
# read if_pppoe's own surfaces -- the M_PPPOE vmstat row, the pppoe row of
# `netstat -Q`, and net.pppoe.* counters -- which only exist when the client
# VM runs the in-kernel kmod.  Under CLIENT=mpd5 the case skips.
_DRIVER_ONLY = pytest.mark.skipif(
    os.environ.get("CLIENT", "mpd5") != "if_pppoe",
    reason="reads if_pppoe's own counters (M_PPPOE vmstat row, netstat -Q "
    "pppoe row, net.pppoe.*) (CLIENT=if_pppoe only)",
)


def _malloc_inuse(client) -> int:
    """M_PPPOE InUse count: `vmstat -m` row of the pppoe malloc type.

    Row shape: `pppoe <inuse> <memuse> <...>` -- field 1 is InUse.
    """
    r = client.run("vmstat -m | grep -w pppoe")
    return int(r.stdout.split()[1]) if r.stdout.strip() else 0


def _qdrops(client) -> int:
    """netisr QDrops for the pppoe protocol row of `netstat -Q`."""
    r = client.run("netstat -Q")
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 9 and parts[2] == "pppoe":
            return int(parts[7])
    return 0


def soak_baselines(client, d: IfPppoeDriver) -> dict:
    """Capture the soak's zero-drift baselines right after the dial settles."""
    return {
        "inuse": _malloc_inuse(client),
        "qdrops": _qdrops(client),
        "tx_errors": int(d.sysctl("net.pppoe.tx_errors")),
    }


def soak_hourly_check(client, d: IfPppoeDriver, base: dict, hour: int = 0,
                      server=None) -> dict:
    """One hourly soak check, shared by the 24h soak loop (S04 T1) and S05's
    sustained multi-flow run.

    Asserts (a) the session is up with an address, (b) M_PPPOE InUse growth
    <= 4 since `base` (the known 32-byte MEM093 item is 1 item; 4 gives the
    assertion slack without hiding a leak), (c) netstat -Q QDrops flat on
    the pppoe row, (d) net.pppoe.tx_errors flat.  The session-down failure
    message embeds the accel-ppp log tail when `server` is supplied.
    Returns the observed counters so callers can summarise the run.
    """
    st = client.iface_state()
    if not (st["up"] and st["inet"]):
        accel = f"\naccel-ppp log:\n{server.log_tail(30)}" if server is not None else ""
        raise AssertionError(f"hour {hour}: session down: {st}{accel}")
    inuse = _malloc_inuse(client)
    assert inuse <= base["inuse"] + 4, (
        f"hour {hour}: M_PPPOE allocations grew {base['inuse']} -> {inuse}"
    )
    drops = _qdrops(client)
    assert drops == base["qdrops"], (
        f"hour {hour}: netisr QDrops for pppoe grew {base['qdrops']} -> {drops}"
    )
    tx_err = int(d.sysctl("net.pppoe.tx_errors"))
    assert tx_err == base["tx_errors"], (
        f"hour {hour}: tx_errors grew {base['tx_errors']} -> {tx_err}"
    )
    return {"hour": hour, "inuse": inuse, "qdrops": drops, "tx_errors": tx_err}


@pytest.mark.soak
@_DRIVER_ONLY
def test_if_pppoe_24h_soak_no_leak_no_drop(client, server):
    """24 hours of a live driver session with continuous traffic and hourly
    checks (S04 T1).

    Fails on: a session that is down without an address at any hourly
    check, a growing M_PPPOE allocation count (InUse growth > 4), any
    netisr QDrops for the pppoe protocol, or a non-zero tx_errors delta.
    Continuous ping traffic to the accel gateway runs as a `daemon`
    (pid file /tmp/soak.pid on the client VM) and is killed in the finally
    block.  On a session-down failure the accel-ppp log tail is embedded in
    the assertion message.
    """
    d = IfPppoeDriver()
    client.dial(service=LAB_SERVICE)
    deadline0 = time.time() + 60
    state = {}
    while time.time() < deadline0:
        state = client.iface_state()
        if state["up"] and state["inet"]:
            break
        time.sleep(1)
    assert state["inet"], f"soak could not start: {state}"

    base = soak_baselines(client, d)

    client.run(
        f"daemon -f -p /tmp/soak.pid ping -i 0.5 -q {ACCEL_GW}", root=True
    )
    try:
        end = time.time() + 24 * 3600
        hour = 0
        while time.time() < end:
            time.sleep(3600)
            hour += 1
            soak_hourly_check(client, d, base, hour=hour, server=server)
    finally:
        client.run(
            "kill $(cat /tmp/soak.pid) 2>/dev/null; rm -f /tmp/soak.pid",
            root=True,
        )

    st = client.iface_state()
    assert st["up"] and st["inet"], f"the session did not survive 24h: {st}"


@pytest.mark.soak
def test_redial_every_10_minutes_for_24_hours(client, wait_iface_up):
    interval_s = 10 * 60
    total_s = 24 * 60 * 60
    cycles = total_s // interval_s

    failures = []
    for i in range(cycles):
        client.restart_link()
        state = wait_iface_up(client, timeout=60)
        if not (state["up"] and state["inet"]):
            failures.append((i, state))
        remaining = interval_s - 60
        if remaining > 0:
            time.sleep(remaining)

    assert not failures, f"{len(failures)}/{cycles} redial cycles failed to come back up: {failures[:5]}"
