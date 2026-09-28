"""Fixtures for tests/plugin/'s round-trip harness. Local-logic tests
(test_config_diff.py, test_repo_registration.py, lab/vm/test_console_driver.py)
need none of this and always run. Only test_roundtrip.py needs a live DUT,
gated on environment variables so `pytest tests/plugin` is safe to run with
no lab access (that whole test skips; everything else still runs and
proves the logic that doesn't need a box).

`opnsense_api` (and its `requests` import) is imported lazily, inside the
fixture, after the env-var skip check -- a module-level import would make
collecting this file (hence any `pytest tests/plugin` run) require
`requests` installed even when nothing needs it.
"""
from __future__ import annotations

import os
import subprocess

import pytest

REQUIRED_ENV = ("IFPPPOE_DUT_HOST", "IFPPPOE_DUT_API_KEY", "IFPPPOE_DUT_API_SECRET")


def pytest_configure(config):
    # Registered defensively so `@pytest.mark.timeout(...)` never warns as an
    # unknown marker when pytest-timeout isn't installed (it's optional --
    # see requirements.txt); pytest-timeout re-registers (and enforces) the
    # same marker name when it is.
    config.addinivalue_line(
        "markers", "timeout(seconds): wall-clock test timeout (enforced only if pytest-timeout is installed)"
    )


def _missing_env() -> list[str]:
    return [v for v in REQUIRED_ENV if not os.environ.get(v)]


@pytest.fixture(scope="session")
def dut_api():
    # Per-run credentials: lab/vm/plugin-roundtrip.sh generates them and sets
    # these env vars for this pytest process only; nothing is read from disk.
    missing = _missing_env()
    if missing:
        pytest.skip(f"no live DUT configured (missing env: {', '.join(missing)}); see tests/plugin/README.md")
    from opnsense_api import OpnsenseApiClient  # lazy: see module docstring
    # IFPPPOE_DUT_API_HOST (host[:port]): where the API is reached when that
    # differs from the ssh target, e.g. plugin-roundtrip.sh's local tunnel
    # to dut's LAN address, which only the lab host can route to.
    return OpnsenseApiClient(
        host=os.environ.get("IFPPPOE_DUT_API_HOST") or os.environ["IFPPPOE_DUT_HOST"],
        api_key=os.environ["IFPPPOE_DUT_API_KEY"],
        api_secret=os.environ["IFPPPOE_DUT_API_SECRET"],
    )


@pytest.fixture(scope="session")
def dut_ssh_target() -> str:
    """host[:jump] for the ssh-based steps the API has no surface for (pkg
    repo registration -- see opnsense_api.py's register_repo docstring).
    Defaults to root@<IFPPPOE_DUT_HOST>; set IFPPPOE_DUT_SSH_JUMP to reach it
    via a jump host (e.g. the lab host, for the lab's br-dut-lan address)."""
    missing = _missing_env()
    if missing:
        pytest.skip(f"no live DUT configured (missing env: {', '.join(missing)}); see tests/plugin/README.md")
    return os.environ["IFPPPOE_DUT_HOST"]


def dut_ssh_run(dut_ssh_target: str, remote_cmd: str, input_text: str | None = None,
                 timeout: float = 30) -> subprocess.CompletedProcess:
    cmd = dut_ssh_cmd(dut_ssh_target, remote_cmd)
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)


def dut_ssh_cmd(dut_ssh_target: str, remote_cmd: str, environ=os.environ) -> list[str]:
    """IFPPPOE_DUT_SSH_KEY is the run's ephemeral root key (a tmpfs path set
    by lab/vm/plugin-roundtrip.sh; root has no password). IdentitiesOnly
    keeps ssh from offering the operator's own keys to the DUT; -i and
    IdentitiesOnly apply to the destination, not the -J jump host."""
    jump = environ.get("IFPPPOE_DUT_SSH_JUMP")
    key = environ.get("IFPPPOE_DUT_SSH_KEY")
    # BatchMode=yes: a login that would otherwise prompt fails fast instead
    # of hanging on stdin -- root has key auth only, never a password.
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=8", "-o", "BatchMode=yes"]
    if key:
        cmd += ["-i", key, "-o", "IdentitiesOnly=yes"]
    if jump:
        cmd += ["-J", jump]
    cmd += [f"root@{dut_ssh_target}", remote_cmd]
    return cmd


def dut_live_config(dut_ssh_target: str) -> str:
    """The live /conf/config.xml, over ssh -- NOT
    OpnsenseApiClient.download_config_backup(), which returns the newest
    /conf/backup/config-*.xml (Api/BackupController.php downloadAction).
    That file can be empty/absent on a freshly seeded box that was never
    write_config()'d, and is a snapshot from whenever the last backup was
    taken, not necessarily now."""
    r = dut_ssh_run(dut_ssh_target, "cat /conf/config.xml")
    if r.returncode != 0:
        raise RuntimeError(f"reading /conf/config.xml over ssh failed: {r.stderr}")
    return r.stdout
