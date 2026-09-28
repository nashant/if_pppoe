"""The plugin install/enable/reboot/disable/reboot/uninstall round-trip,
against a live `dut` VM (see lab/vm/README.md "dut (plugin-test DUT)").

Needs IFPPPOE_DUT_HOST/_API_KEY/_API_SECRET (conftest.py's dut_api fixture),
which only lab/vm/plugin-roundtrip.sh sets, per run; skips entirely otherwise, so `pytest tests/plugin` is safe with no lab
access. Steps and their assertions are exactly the ones the p4-opnvm
component spec lists. Status assertions use the service/status payload of
Support::mergeStatus() (checked offline by test_plugin_contract.py and by
plugin/net/if-pppoe/tests/engine/test_integration.php).

Steps run as one ordered sequence (not independent tests) because each
depends on the DUT state the previous step left it in. A failure partway
through leaves nothing behind: plugin-roundtrip.sh boots every run from a
fresh tmpfs overlay of the never-provisioned image.
"""
from __future__ import annotations

import os
import time

import pytest

from conftest import dut_live_config, dut_ssh_run
from config_diff import diff
from repo_registration import fingerprint_ucl, repo_conf

PKG_NAME = "os-if-pppoe"
REPO_NAME = "IfPppoe"
REPO_URL = os.environ.get("IFPPPOE_REPO_URL", "http://lab-host.example:8080/if-pppoe")
REPO_FINGERPRINTS_DIR = f"/usr/local/etc/pkg/fingerprints/{REPO_NAME}"
# Step 4's connectivity targets. Defaults assume a WAN with internet; the
# lab's accel-ppp has no upstream and never opens IPv6CP (tests/functional/
# test_ipv6cp.py), so plugin-roundtrip.sh points v4 at the PPPoE peer and
# sets v6 empty, which skips that check (printed, not silent).
PING4_TARGET = os.environ.get("IFPPPOE_DUT_PING4", "8.8.8.8")
PING6_TARGET = os.environ.get("IFPPPOE_DUT_PING6", "2001:4860:4860::8888")


@pytest.mark.timeout(3600)  # requires pytest-timeout; harmless no-op marker otherwise (conftest registers it)
def test_plugin_install_enable_disable_uninstall_roundtrip(dut_api, dut_ssh_target):
    # -- 0. baseline: WAN is up on stock mpd5 BEFORE the plugin touches
    # anything -- a failure later must not be confused with a lab/seed
    # problem that was there from the start. -----------------------------
    r = dut_ssh_run(dut_ssh_target, "netstat -rn | grep -q '^default.*pppoe0'")
    assert r.returncode == 0, "baseline failed: no default route via pppoe0 before the plugin is even installed"

    # -- 1. register the repo (filesystem, over ssh -- no API surface; see
    # opnsense_api.py's register_repo docstring) -------------------------
    signing_pubkey = os.environ.get("IFPPPOE_REPO_SIGNING_PUBKEY_PATH")
    if not signing_pubkey:
        pytest.skip("IFPPPOE_REPO_SIGNING_PUBKEY_PATH not set (the signing key is kept outside the repo)")
    pubkey_bytes = open(signing_pubkey, "rb").read()

    conf_text = repo_conf(REPO_NAME, REPO_URL, REPO_FINGERPRINTS_DIR)
    fp_text = fingerprint_ucl(pubkey_bytes)

    r = dut_ssh_run(dut_ssh_target, f"mkdir -p /usr/local/etc/pkg/repos {REPO_FINGERPRINTS_DIR}/trusted")
    assert r.returncode == 0, r.stderr
    r = dut_ssh_run(dut_ssh_target, f"cat > /usr/local/etc/pkg/repos/{REPO_NAME}.conf", input_text=conf_text)
    assert r.returncode == 0, r.stderr
    r = dut_ssh_run(dut_ssh_target, f"cat > {REPO_FINGERPRINTS_DIR}/trusted/{REPO_NAME}.pub", input_text=fp_text)
    assert r.returncode == 0, r.stderr

    # dut_live_config, not download_config_backup: the latter is the newest
    # /conf/backup/*.xml, which can be empty/absent on a freshly seeded box
    # that was never write_config()'d -- see conftest.py's docstring.
    config_before = dut_live_config(dut_ssh_target)

    # -- 2. install from Firmware API -------------------------------------
    install_log = dut_api.firmware_install(PKG_NAME)
    assert "***DONE***" in install_log or PKG_NAME in install_log, install_log

    # -- 3. enable + apply (reboot-to-apply: Api/ServiceController) -------
    dut_api.ifpppoe_set_settings(enabled=True)
    dut_api.ifpppoe_reconfigure()
    # Keys: Support::mergeStatus() (the payload of service/status), fed by
    # `engine status --json`; test_plugin_contract.py checks they exist.
    status = dut_api.ifpppoe_status()
    assert status["engine_available"] is True, status
    assert status["persisted"] == "enabled", status
    assert status["apply_pending"] is False, status
    assert status["reboot_required"] is True, f"enable+apply must ask for a reboot: {status}"

    # Reboot-to-apply means BEFORE the reboot, the box must still be running
    # mpd5 -- reconfigure() alone must not have live-switched the backend.
    r = dut_ssh_run(dut_ssh_target, "netstat -rn | grep -q '^default.*pppoe0'")
    assert r.returncode == 0, "WAN dropped before reboot -- enable+reconfigure must not touch the running backend"
    assert _backend(status, "wan") == "mpd5", f"expected mpd5 still active before the reboot-to-apply: {status}"

    dut_api.reboot()
    dut_api.wait_until_unreachable(timeout=60)
    dut_api.wait_until_reachable(timeout=300)

    # -- 4. assert kernel backend + connectivity --------------------------
    status = dut_api.ifpppoe_status()
    assert status["hook_status"] == "applied", status
    assert status["boot"]["result"] == "enabled", status
    assert status["reboot_required"] is False, status
    assert _backend(status, "wan") == "kernel", f"expected the kernel backend on wan: {status}"
    assert status["notices"] == [], status

    # The API answers before the kernel session has finished IPCP (seen
    # live: "ping: sendto: No route to host", then fine seconds later), so
    # wait for the WAN before probing it.
    assert _wait_for_wan(dut_ssh_target, timeout=120), "no default route via pppoe0 within 120s of the reboot"
    r = dut_ssh_run(dut_ssh_target, f"ping -c2 -t5 {PING4_TARGET}")
    assert r.returncode == 0, f"IPv4 connectivity check ({PING4_TARGET}) failed: {r.stdout}\n{r.stderr}"
    if PING6_TARGET:
        r = dut_ssh_run(dut_ssh_target, f"ping6 -c2 -X5 {PING6_TARGET}")
        assert r.returncode == 0, f"IPv6 connectivity check ({PING6_TARGET}) failed: {r.stdout}\n{r.stderr}"
    else:
        print("IPv6 connectivity check NOT RUN: IFPPPOE_DUT_PING6 is empty")

    gw = dut_api.gateway_status()
    assert any(
        "WAN_PPPOE" in str(v) for v in _flatten(gw)
    ), f"expected a WAN_PPPOE gateway in gateway/status: {gw}"

    # -- 5. disable + reboot -> assert mpd5 -------------------------------
    dut_api.ifpppoe_set_settings(enabled=False)
    dut_api.ifpppoe_reconfigure()
    dut_api.reboot()
    dut_api.wait_until_unreachable(timeout=60)
    dut_api.wait_until_reachable(timeout=300)

    status = dut_api.ifpppoe_status()
    assert status["hook_status"] == "reverted", status
    assert status["reboot_required"] is False, status
    assert _backend(status, "wan") == "mpd5", f"expected mpd5 on wan after disabling: {status}"

    # -- 6. uninstall + assert clean --------------------------------------
    remove_log = dut_api.firmware_remove(PKG_NAME)
    assert "***DONE***" in remove_log or PKG_NAME in remove_log, remove_log

    health = dut_api.firmware_health()
    assert "interfaces.inc" not in health["log"], f"hook left interfaces.inc checksum-dirty: {health['log']}"

    # if-pppoe-kmod is a PLUGIN_DEPENDS of os-if-pppoe, not reverse-removed
    # by pkg (pkg remove never cascades to a dependency's own dependents): a
    # DOCUMENTED leftover, not asserted as a bug.
    r = dut_ssh_run(dut_ssh_target, "pkg info -e if-pppoe-kmod")
    kmod_left_over = r.returncode == 0
    # uninstall.sh removes /conf/if_pppoe once hookctl revert succeeded, and the
    # health check above proved interfaces.inc is pristine again.
    r = dut_ssh_run(dut_ssh_target, "test -d /conf/if_pppoe")
    assert r.returncode != 0, "/conf/if_pppoe left behind although the hook revert succeeded"

    config_after = dut_live_config(dut_ssh_target)
    mismatches = diff(config_before, config_after)
    assert mismatches == [], f"config.xml changed across the round-trip: {mismatches}"

    print(f"post-uninstall leftover (documented, not asserted as a bug): if-pppoe-kmod still installed={kmod_left_over}")


def _flatten(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj


def _backend(status: dict, friendly: str) -> str | None:
    """backend of one interface in the service/status payload's interfaces list"""
    for iface in status.get("interfaces", []):
        if iface.get("friendly") == friendly:
            return iface.get("backend")
    return None


def _wait_for_wan(dut_ssh_target: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        r = dut_ssh_run(dut_ssh_target, "netstat -rn | grep -q '^default.*pppoe0'")
        if r.returncode == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(3)
