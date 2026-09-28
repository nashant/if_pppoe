"""Offline checks that this harness talks to the plugin the way the plugin's
own sources say it must (no DUT needed)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import opnsense_api
from config_diff import VOLATILE_SUBTREES

PLUGIN = Path(__file__).resolve().parents[2] / "plugin/net/if-pppoe/src/opnsense/mvc/app"


def test_settings_payload_uses_the_controller_model_name():
    ctrl = (PLUGIN / "controllers/OPNsense/IfPppoe/Api/SettingsController.php").read_text()
    m = re.search(r"\$internalModelName\s*=\s*'([^']+)'", ctrl)
    assert m and m.group(1) == opnsense_api.IFPPPOE_MODEL_NAME

    sent = {}

    class Fake(opnsense_api.OpnsenseApiClient):
        def post(self, path, json=None, **kwargs):
            sent["path"], sent["json"] = path, json
            return {"result": "saved"}

    Fake("dut", "k", "s").ifpppoe_set_settings(enabled=True, exclude=["opt1"])
    assert sent["path"] == opnsense_api.IFPPPOE_SETTINGS_SET
    assert sent["json"] == {"ifpppoe": {"general": {"enabled": "1", "exclude": "opt1"}}}


def test_config_diff_excludes_the_model_mount():
    mount = ET.parse(PLUGIN / "models/OPNsense/IfPppoe/IfPppoe.xml").getroot().findtext("mount")
    assert tuple(mount.strip("/").split("/")) in VOLATILE_SUBTREES


def test_roundtrip_status_keys_exist_in_the_service_payload():
    support = (PLUGIN / "library/OPNsense/IfPppoe/Support.php").read_text()
    body = support[support.index("public static function mergeStatus"):]
    keys = set(re.findall(r"^\s+'([a-z_]+)' =>", body[: body.index("if ($engine === null)")], re.M))
    used = set(re.findall(r'status\["([a-z_]+)"\]', (Path(__file__).parent / "test_roundtrip.py").read_text()))
    assert used, "test_roundtrip.py no longer reads status keys?"
    assert used <= keys, f"test_roundtrip.py reads keys Support::mergeStatus() never returns: {used - keys}"
    assert {"friendly", "backend"} <= set(re.findall(r"'([a-z_]+)' =>", body))


def test_services_page_reads_the_kernel_coverage_keys_mergestatus_returns():
    support = (PLUGIN / "library/OPNsense/IfPppoe/Support.php").read_text()
    body = support[support.index("public static function mergeStatus"):]
    keys = set(re.findall(r"^\s+'([a-z_]+)' =>", body[: body.index("if ($engine === null)")], re.M))
    kernel_keys = {"supported_kernels", "running_kernel", "installed_kernel", "kernel_upgrade"}
    assert kernel_keys <= keys
    view = (PLUGIN / "views/OPNsense/IfPppoe/settings.volt").read_text()
    assert kernel_keys <= set(re.findall(r"data\.([a-z_]+)", view))
    # Engine::kernelCoverage() emits the members Support::mergeKernels() reads
    engine = (PLUGIN.parents[1] / "scripts/if_pppoe/lib/Engine.php").read_text()
    cov = engine[engine.index("public function kernelCoverage"):]
    cov = cov[: cov.index("private static function kernelLabel")]
    for k in ("supported", "running", "installed", "upgrade", "pending_reboot", "covered", "version", "build_id"):
        assert f"'{k}' =>" in cov, k
