"""Dry-run check for lab/vm/perf-target.sh: the per-BACKEND data-plane IP
`iperf3 -c` must target (lab/Makefile's test-perf-fwd sources this same
script, so it can't drift from what's tested here -- final-review blocker,
"the one-command harness can never measure forwarded traffic").
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "lab" / "vm" / "perf-target.sh"


@pytest.mark.parametrize(
    "backend,expected_ip",
    [
        ("if_pppoe", "10.99.0.1"),   # accel-ppp gw, provision-isp.sh
        ("mpd5", "10.99.0.1"),       # same accel-ppp gw
        ("raw", "192.168.99.1"),     # provision-isp-raw.sh
    ],
)
def test_perf_target_is_the_data_plane_ip_not_an_ssh_alias(backend, expected_ip):
    proc = subprocess.run(
        ["bash", str(SCRIPT), backend], capture_output=True, text=True, timeout=10
    )
    assert proc.returncode == 0, proc.stderr
    target = proc.stdout.strip()
    assert target == expected_ip
    # The bug this guards against: an ssh-config.sh `lab-<name>` alias is
    # never a valid iperf3 -c target (the lan VM can't resolve it at all).
    assert not target.startswith("lab-")


def test_perf_target_rejects_unknown_backend():
    proc = subprocess.run(
        ["bash", str(SCRIPT), "plain"], capture_output=True, text=True, timeout=10
    )
    assert proc.returncode != 0
    assert "BACKEND must be" in proc.stderr
