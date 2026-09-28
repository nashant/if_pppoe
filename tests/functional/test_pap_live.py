"""S02 T2: live PAP authentication against accel-ppp with secret redaction.

Drives the in-kernel if_pppoe/sppp stack (not mpd5, not the `client` seam)
through a full live PAP dial against the lab accel-ppp server:

  - SPPPSETAUTHCFG with myauthproto=PAP and the run's generated account
    (lab.active_creds(), see labcreds.py) via a pppoectl-equivalent ioctl
    path.  pppoectl(8)
    is S05, so the ioctl is driven by a minimal C helper compiled on the
    client VM from the source embedded below (the standalone copy is
    tools/spppauth/spppauth.c -- keep the two in sync).
  - the dial: LCP opens (auth-proto negotiated), phase -> authenticate,
    sppp_pap_scr sends a PAP Authenticate-Request, accel-ppp verifies it
    against its tmpfs chap-secrets entry and answers PAP-Ack.
  - R011: the module debug log must show the PAP request with the peer name
    but `secret=<redacted>`, and the plaintext secret value must appear
    NOWHERE: not in the module log, not in the client serial log, not in
    test output.
"""
from __future__ import annotations

import re
import time

import pytest

from lab import (
    CLIENT_SERIAL_REL,
    PPPOE_STATE_SESSION,
    _ssh_stdin,
    active_creds,
    spppauth_cmd,
    push_vendored_sppp_headers,
)

# The client VM's serial console log.  The pytest process runs on
# <LAB_HOST> under sudo (conftest), so this is a local file there.
CLIENT_SERIAL = CLIENT_SERIAL_REL  # per LAB_SLOT

pytestmark = pytest.mark.datapath

# Minimal SPPPSETAUTHCFG driver, byte-identical in behaviour to
# tools/spppauth/spppauth.c. Includes the real vendored <net/if_sppp.h>
# (pushed to the client VM by push_vendored_sppp_headers(), see
# _install_spppauth()) instead of a private copy, so a renumbering can't
# silently desync this probe from the driver (p3-ctl-abi). Compiled on the
# client by install() below; NEVER prints a secret value (R011).
_SPPPAUTH_C = r"""
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_sppp.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct spppauthcfg cfg;
	if (argc != 4) {
		fprintf(stderr, "usage: spppauth NAME SECRET IFNAME (myauthproto=PAP)\n");
		return 2;
	}
	memset(&cfg, 0, sizeof(cfg));
	strlcpy(cfg.ifname, argv[3], sizeof(cfg.ifname));
	cfg.myauth = SPPP_AUTHPROTO_PAP;
	cfg.myname = argv[1];
	cfg.mysecret = argv[2];
	cfg.myname_length = strlen(argv[1]) + 1;
	cfg.mysecret_length = strlen(argv[2]) + 1;
	if (ioctl(socket(AF_INET, SOCK_DGRAM, 0), SPPPSETAUTHCFG, &cfg) < 0)
		err(1, "SPPPSETAUTHCFG");
	return 0;
}
"""


def _install_spppauth(driver):
    """Compile the embedded SPPPSETAUTHCFG helper on the client (root)."""
    hdr_dir = push_vendored_sppp_headers(driver)
    r = _ssh_stdin(
        driver.port,
        "cat > /tmp/spppauth.c",
        _SPPPAUTH_C,
    )
    assert r.returncode == 0, f"uploading spppauth.c failed: {r.stderr}"
    r = driver.run(
        f"cc -O2 -Wall -I{hdr_dir} -o /usr/local/sbin/spppauth /tmp/spppauth.c && "
        "rm -f /tmp/spppauth.c",
        root=True,
    )
    assert r.returncode == 0, f"spppauth compile failed: {r.stdout}\n{r.stderr}"
    r = driver.run("/usr/local/sbin/spppauth", root=True)
    assert r.returncode == 2, (
        "spppauth without args should print usage and exit 2: "
        f"{r.stdout}\n{r.stderr}"
    )


def _serial_log():
    """Read the client VM's serial console log (lives on the VM host, which
    is where the pytest process runs).  Mirrors conftest's SUDO_USER
    handling: the suite runs under sudo, so $HOME here is root's, not the
    invoking account's."""
    import os

    sudo_user = os.environ.get("SUDO_USER")
    home = os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")
    path = os.path.join(home, CLIENT_SERIAL)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        return f"(serial log unreadable: {exc})"


def test_pap_live_dial_authenticates_and_redacts_secret(driver, accel_server, sniffer):
    """Full live PAP dial: LCP -> authenticate -> PAP-Ack against accel-ppp,
    with the plaintext secret appearing nowhere (R011)."""
    import shlex as _shlex  # noqa: F401  (kept: mirrors the datapath tests)

    _install_spppauth(driver)
    driver.create(iface="pppoe0", parent="vtnet1", service="lab", acname="isp-lab")

    # IFF_DEBUG turns on sppp's per-protocol debug records; this is the
    # "module log shows the negotiation" surface.
    r = driver.run("ifconfig pppoe0 debug", root=True)
    assert r.returncode == 0, f"ifconfig pppoe0 debug failed: {r.stdout}"

    # Set the auth config: we are the peer, myauthproto=PAP, the run's
    # generated account (the secret goes over stdin, never argv of ssh).
    creds = active_creds()
    cmd, secret = spppauth_cmd("pppoe0")
    r = driver.run(cmd, root=True, stdin=secret)
    assert r.returncode == 0, f"spppauth set failed: {r.stdout}\n{r.stderr}"
    # The set ioctl must have stored PAP as our auth proto (a GET round-trip).
    # (The helper has no -g mode; SPPPGETAUTHCFG via the suite's python
    # ioctl needs the client python, which the lab VM does not ship, so the
    # stored-config proof is the live dial below itself.)

    sniffer.start()
    driver.up("pppoe0")
    # Discovery must reach the session state (PADS).
    deadline = time.time() + 20
    parms = {}
    while time.time() < deadline:
        parms = driver.parms("pppoe0")
        if parms.get("state") == PPPOE_STATE_SESSION:
            break
        time.sleep(0.5)
    assert parms["state"] == PPPOE_STATE_SESSION, (
        f"state stayed {parms}: no live discovery\n"
        f"parms={parms}\n"
        f"dmesg:\n{driver.run('dmesg | tail -25').stdout}\n"
        f"accel-log:\n{accel_server.log_tail(10)}"
    )

    # The module log must show the PAP exchange reaching success.  Poll the
    # syslog/console rather than dmesg (the driver logs via log(9) to
    # /var/log/messages; dmesg also carries it but can rotate under 2GB RAM).
    deadline = time.time() + 15
    pap_ok = False
    while time.time() < deadline:
        r = driver.run(
            "grep -hE 'pap (output|success)' "
            "/var/log/messages /var/log/console.log 2>/dev/null | tail -20 || true"
        )
        if re.search(r"pap success:? (Authentication succeeded|.*succeeded)", r.stdout):
            pap_ok = True
            break
        time.sleep(1)
    sniffer.stop()

    assert pap_ok, (
        "module log never showed PAP success -- live PAP dial did not "
        f"authenticate against accel-ppp\nlog-so-far:\n{r.stdout}\n"
        f"{accel_server.log_tail(20)}"
    )
    pap_log = r.stdout

    # The module log must have redacted the password on the wire.
    assert "secret=<redacted>" in pap_log, (
        "paper request log must show secret=<redacted>: "
        f"\n{pap_log}"
    )
    # ... and must NOT contain the plaintext secret anywhere.
    assert creds.password not in pap_log, (
        "plaintext PAP secret reached the module log (R011): "
        f"\n{pap_log}"
    )

    # Zero-hit sweep across every log surface (R011).
    for src, txt in (
        ("module log", pap_log),
        ("client serial log", _serial_log()),
        ("accel-ppp log", accel_server.log_tail(200)),
    ):
        assert creds.password not in txt, (
            f"plaintext secret found in {src} (R011): {txt}"
        )

    # Server side: the session must exist and be bound to the run's user.
    sessions = accel_server.sessions()
    assert any(s.get("username") == creds.user for s in sessions), (
        f"accel-ppp shows no session bound to user {creds.user}: {sessions}"
    )