"""Offline checks for lab/vm/make-dut-seed.py and the ssh command the
round trip uses: per-run credentials in, nothing standing baked into the
seed, root locked (key-only). Values here are throwaway test strings.
"""
from __future__ import annotations

import base64
import importlib.util
import secrets
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import dut_ssh_cmd

LAB_VM = Path(__file__).resolve().parents[2] / "lab" / "vm"

_spec = importlib.util.spec_from_file_location("make_dut_seed", LAB_VM / "make-dut-seed.py")
make_dut_seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_dut_seed)

PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Rvbmx5dGVzdG9ubHl0ZXN0b25seXRlc3Q test-only"


def _creds() -> dict:
    return {
        "DUT_API_KEY": secrets.token_urlsafe(40),
        "DUT_API_SECRET": secrets.token_urlsafe(40),
        "DUT_PPPOE_PASSWORD": secrets.token_hex(24),
    }


def _render(creds: dict) -> str:
    values = make_dut_seed.build_values(creds, PUBKEY, "plugintest", "if-pppoe-plugin")
    return make_dut_seed.render((LAB_VM / "dut-config.xml.tmpl").read_text(), values)


def test_seed_renders_well_formed_and_locked_root():
    creds = _creds()
    root = ET.fromstring(_render(creds))
    user = root.find("system/user")
    assert user.findtext("name") == "root"
    # '*' (locked, never matches), not empty: auth.inc local_user_set()
    # skips a user with an empty <password> entirely.
    assert user.findtext("password") == "*"
    assert base64.b64decode(user.findtext("authorizedkeys")).decode() == PUBKEY + "\n"
    assert root.find("system/ssh/passwordauth") is None
    assert root.findtext("system/ssh/permitrootlogin") == "1"


def test_seed_embeds_only_api_secret_hash():
    creds = _creds()
    out = _render(creds)
    assert creds["DUT_API_SECRET"] not in out
    item = ET.fromstring(out).find("system/user/apikeys/item")
    assert item.findtext("key") == creds["DUT_API_KEY"]
    assert item.findtext("secret").startswith("$6$")


def test_seed_pppoe_account_from_run_values():
    creds = _creds()
    ppp = ET.fromstring(_render(creds)).find("ppps/ppp")
    assert ppp.findtext("username") == "plugintest"
    assert base64.b64decode(ppp.findtext("password")).decode() == creds["DUT_PPPOE_PASSWORD"]


def test_each_render_salts_differently():
    creds = _creds()
    a = ET.fromstring(_render(creds)).findtext("system/user/apikeys/item/secret")
    b = ET.fromstring(_render(creds)).findtext("system/user/apikeys/item/secret")
    assert a != b


def test_missing_env_refuses():
    with pytest.raises(SystemExit):
        make_dut_seed.read_env({"DUT_API_KEY": "x"})


def test_rejects_non_pubkey():
    with pytest.raises(SystemExit):
        make_dut_seed.build_values(_creds(), "-----BEGIN OPENSSH PRIVATE KEY-----", "u", "s")


def test_ssh_cmd_uses_ephemeral_key_only():
    env = {"IFPPPOE_DUT_SSH_KEY": "/run/user/0/if_pppoe-dut.X/id_ed25519", "IFPPPOE_DUT_SSH_JUMP": "lab-host.example"}
    cmd = dut_ssh_cmd("192.168.90.2", "true", environ=env)
    i = cmd.index("-i")
    assert cmd[i + 1] == env["IFPPPOE_DUT_SSH_KEY"]
    assert "IdentitiesOnly=yes" in cmd
    assert "BatchMode=yes" in cmd
    assert cmd[-2:] == ["root@192.168.90.2", "true"]


def test_ssh_cmd_without_key_has_no_identity_flags():
    cmd = dut_ssh_cmd("192.168.90.2", "true", environ={})
    assert "-i" not in cmd and "-J" not in cmd
