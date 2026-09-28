#!/usr/bin/env python3
"""S06 T1 helper: switch the lab client VM to the in-kernel if_pppoe backend.

Runs ON the lab host (like the functional suite): stops mpd5 (freeing the
accel-ppp session and its ng0 interface) and dials if_pppoe via the S05
IfPppoeClient seam -- the exact command sequence pinned byte-for-byte by
test_client_seam.py -- then waits for the pppoe0 session to carry its IPCP
address. Idempotent: dial() recreates the clone each call.

Usage (on the lab host):
    ~/if_pppoe-lab/venv/bin/python3 if_pppoe-dial.py
Exit 0 on a live session (prints SESSION_UP <ip> <mtu>), 1 on timeout.

LAB_DIR overrides where tests/functional's lab.py is found relative to
the invoking user's home (default: if_pppoe-lab, matching lab.py's own
LAB_HOME_DIR and the test-func rsync target).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

_lab_dir = os.environ.get("LAB_DIR", "if_pppoe-lab")
sys.path.insert(0, os.path.join(os.path.expanduser("~"), _lab_dir, "tests-functional"))
from lab import IfPppoeClient  # noqa: E402


def main() -> int:
    client = IfPppoeClient()
    stop = client.run("service mpd5 stop", root=True, timeout=30)
    if stop.returncode != 0:
        print(f"WARN: service mpd5 stop rc={stop.returncode}: "
              f"{stop.stdout.strip()} {stop.stderr.strip()}", file=sys.stderr)
    client.dial(service="lab")

    for attempt in range(40):
        st = client.iface_state()
        if st["up"] and st["inet"]:
            print(f"SESSION_UP {st['inet']} mtu={st['mtu']}")
            return 0
        time.sleep(1)
    print(f"SESSION_TIMEOUT; pppoe0 state: {st['raw']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())