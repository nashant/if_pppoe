"""p3-ctl-abi: live proof that pppoectl(8) actually works against a real
session now that SPPP*/PPPOE* ioctls stay on group 'i' (the blocker this
branch fixed: a private group would never have reached this driver at all
-- see docs/PORTING-sppp.md "ioctl number collision").

Three of these are the spec's own acceptance tests:

  * pppoectl -d -d on an up session shows the real negotiated IPCP state
    ("opened"), not "unknown" (tests/results/pppoectl-t1.txt:25 was the
    original bug report for this).
  * pppoectl -f /nonexistent exits non-zero with the path in stderr.
  * pppoectl -f /dev/stdin applies myauthname=/myauthsecret= piped on
    stdin (the plugin's no-secret-on-argv path).

The fourth is the review's major finding #2's own suggested live test:
print_error()'s ENXIO "interface not found" sentinel only fires because
group 'i' routes through ifioctl()'s ifunit_ref() lookup; a bad group
would print "Can't assign requested address" (EADDRNOTAVAIL) instead.
"""
from __future__ import annotations

import shlex
import time

import pytest

from lab import PPPOE_STATE_SESSION, _ssh_stdin, active_creds, auth_cfg_cmd

pytestmark = pytest.mark.datapath

POCTL = "/usr/local/sbin/pppoectl"


def _run_root_stdin(driver, cmd: str, data: str, timeout: int = 20):
    """Like driver.run(cmd, root=True) (IfPppoeDriver.run(), lab.py) but
    also feeds `data` to the root-run command's own stdin -- needed for
    `pppoectl -f /dev/stdin`.

    `data` is CMD's stdin as is (lab._run_guest): su(1) on the lab guests
    reads no line from a non-tty stdin, so no leading blank line is sent
    for it -- one would reach CMD as its first line.
    """
    wrapped = "su -m root -c " + shlex.quote(cmd)
    return _ssh_stdin(driver.port, wrapped, data, timeout=timeout)


def _wait_inet(driver, timeout=25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = driver.iface_state("pppoe0")
        if last["inet"] is not None:
            return last
        time.sleep(0.5)
    return last


def test_pppoectl_dash_d_dash_d_shows_real_ipcp_state_on_a_live_session(
    driver, server
):
    """The blocker this branch fixes: with SPPPGETIPCPSTATUS on a
    colliding group/number, ifhwioctl() (SIOCGIFGROUP) answered before
    pppoe_ioctl() ever ran, so `pppoectl -d -d` always printed "IPCP
    state: unknown" even on a fully negotiated session. Fixed, it must
    show "opened"."""
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    cfg, secret = auth_cfg_cmd(
        proto="pap", extra="max-noreceive=0 max-alive-missed=3 alive-interval=1",
        poctl=POCTL)
    r = driver.run(cfg, root=True, stdin=secret)
    assert r.returncode == 0, f"pppoectl config failed: {r.stdout}\n{r.stderr}"
    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert st["state"] == PPPOE_STATE_SESSION, st
    up = _wait_inet(driver)
    assert up["inet"] is not None, f"no negotiated IPv4: {up}"

    r = driver.run(f"{POCTL} -d -d pppoe0", root=True)
    assert r.returncode == 0, f"pppoectl -d -d failed: {r.stdout}\n{r.stderr}"
    assert "IPCP state: opened" in r.stdout, (
        "SPPPGETIPCPSTATUS did not reach the driver -- expected "
        f"'IPCP state: opened', got:\n{r.stdout}"
    )
    assert "IPCP state: unknown" not in r.stdout, (
        f"IPCP state still 'unknown' -- the group/number collision is "
        f"not actually fixed:\n{r.stdout}"
    )
    assert "LCP state: opened" in r.stdout, r.stdout


def test_pppoectl_dash_f_nonexistent_file_exits_nonzero(driver):
    """Spec acceptance test: a missing -f config file must be a hard
    error, not a silent no-op (pppoectl.c ~349). fopen() fails before any
    ioctl is attempted, so this never needs to create pppoe0 itself --
    the `driver` fixture is requested only because every `datapath` test
    in this module must (conftest.py's `_restore_client_to_lab`)."""
    r = driver.run(f"{POCTL} -f /nonexistent pppoe0", root=True)
    assert r.returncode != 0, (
        f"pppoectl -f /nonexistent must exit non-zero: rc={r.returncode} "
        f"stdout={r.stdout!r}"
    )
    assert "/nonexistent" in r.stderr, (
        f"expected the missing path in stderr: {r.stderr!r}"
    )


def test_pppoectl_dash_f_dev_stdin_applies_auth_config_from_stdin(
    driver, server
):
    """Spec acceptance test: `-f /dev/stdin` must let the plugin pipe
    myauthname=/myauthsecret= without ever putting a secret on argv, and
    the session must actually authenticate with it (PAP against the lab
    AC's per-run generated account (lab.active_creds()), the one
    test_pap_live.py and
    _pppoectl_up() use).

    driver.create() already programs valid PAP creds itself (lab.py), so
    a wrong secret is set first here -- reaching a real session can then
    only be explained by the -f /dev/stdin config actually being applied,
    not by leftover state from create().
    """
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    r = driver.run(f"{POCTL} pppoe0 myauthsecret=not-the-real-secret", root=True)
    assert r.returncode == 0, f"breaking the secret failed: {r.stdout}\n{r.stderr}"

    creds = active_creds()
    cfg = (
        "myauthproto=pap\n"
        f"myauthname={creds.user}\n"
        f"myauthsecret={creds.password}\n"
        "max-noreceive=0\n"
        "max-alive-missed=3\n"
        "alive-interval=1\n"
    )
    r = _run_root_stdin(driver, f"{POCTL} -f /dev/stdin pppoe0", cfg)
    assert r.returncode == 0, (
        f"pppoectl -f /dev/stdin failed: {r.stdout}\n{r.stderr}"
    )

    driver.up("pppoe0")
    st = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert st["state"] == PPPOE_STATE_SESSION, (
        f"session did not reach PPPOE_STATE_SESSION with -f /dev/stdin "
        f"auth config: {st}"
    )
    up = _wait_inet(driver)
    assert up["inet"] is not None, (
        f"PAP with a stdin-piped secret did not negotiate an address: {up}"
    )


def test_pppoectl_dash_d_dash_d_nonexistent_iface_prints_interface_not_found(driver):
    """Review finding (major #2): print_error()'s ENXIO sentinel only
    works because group 'i' routes through ifioctl()'s ifunit_ref()
    lookup, which returns ENXIO for an unknown name before the driver
    ever sees the ioctl. A wrong group would print
    "Can't assign requested address" (EADDRNOTAVAIL) instead.
    The name must fit IFNAMSIZ, or pppoectl's own length check rejects it
    before any ioctl (test_pppoectl_ifname_longer_than_ifnamsiz_...)."""
    r = driver.run(f"{POCTL} -d -d nxiface0", root=True)
    assert r.returncode != 0
    assert "interface not found" in r.stderr, (
        f"expected 'interface not found' (ENXIO via ifioctl()), got: "
        f"{r.stderr!r}"
    )
    assert "Can't assign requested address" not in r.stderr, (
        "got EADDRNOTAVAIL instead of ENXIO -- SPPPGETIPCPSTATUS/"
        f"PPPOEGETSESSION did not route through ifioctl(): {r.stderr!r}"
    )


def test_pppoectl_ifname_longer_than_ifnamsiz_is_rejected_before_ioctl(driver):
    """An ifname that cannot fit IFNAMSIZ (16, incl. NUL) is refused by
    pppoectl itself instead of being silently truncated to a different
    interface's name."""
    r = driver.run(f"{POCTL} -d -d nonexistentiface0", root=True)
    assert r.returncode != 0
    assert "interface name too long" in r.stderr, r.stderr
