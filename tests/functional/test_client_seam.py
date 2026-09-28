"""Unit tests for the IfPppoeClient command-invocation seam (S05 T2).

Pure Python -- no VM, no scapy raw sockets, no root.  Runs on any host
(conftest.py exempts this file from the off-lab collection gate) and on
<LAB_HOST> alongside the live suite.

The seam: `IfPppoeClient(runner=...)` accepts an injectable callable that
replaces the real ssh executor for EVERY pppoectl(8)/ifconfig PPPoE-control
command the client issues -- the parent bind (`pppoectl -e vtnet1 [-s
service] pppoe0`), the SPPPSETAUTHCFG/SPPPSETDNSOPTS/SPPPSETKEEPALIVE
config (one `pppoectl -S pppoe0 myauthproto=... myauthname=...
query-dns=... max-noreceive=... max-alive-missed=... alive-interval=...`
call, the secret on its stdin), `ifconfig pppoe0 mtu N`, up/down, the pppoe0 clone create/destroy
and the module-load guard.  With runner=None the pre-seam path is kept
byte-for-byte: the `echo | su -m root -c '<cmd>'` root wrap and the ssh
hostfwd call are untouched (verified against a monkeypatched `_ssh`).

These tests pin the exact command strings the client builds so later
hardening/soak/fuzz work can drive the client through the seam without
live VMs.
"""
from __future__ import annotations

import inspect
import shlex
import subprocess
import types

import pytest

import lab

# The live-suite autouse `_restore_client_to_lab` fixture (conftest.py)
# skips these tests: every command here goes to an injected fake runner or
# a monkeypatched `_ssh`, so the real VM must never be dialed.
pytestmark = pytest.mark.seam_unit

# ---------------------------------------------------------------------------
# Pinned command strings.  These literals are byte-for-byte the strings
# IfPppoeClient.dial/hangup/restart_link built before the seam refactor
# (verified against the recorded _ssh argv in the default-runner test).
# ---------------------------------------------------------------------------

# A stand-in for the run's generated account (labcreds.lab_session): these
# tests never reach a server, so a fixed obviously-fake value is fine here.
SEAM_CREDS = lab.LabCreds("seam-user", "seam-not-a-real-secret")
SEAM_STDIN = SEAM_CREDS.password + "\n"

BIND_LAB = "/usr/local/sbin/pppoectl -e vtnet1 -s lab pppoe0"
BIND_NO_SERVICE = "/usr/local/sbin/pppoectl -e vtnet1 pppoe0"
# The secret is NOT in these strings: `pppoectl -S` reads it from stdin.
CFG_DEFAULT = (
    "/usr/local/sbin/pppoectl -S pppoe0 myauthproto=pap "
    "myauthname=seam-user passiveauthproto "
    "query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1"
)
CFG_CHAP = (
    "/usr/local/sbin/pppoectl -S pppoe0 myauthproto=chap "
    "myauthname=seam-user "
    "query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1"
)


@pytest.fixture(autouse=True)
def _seam_creds(monkeypatch):
    """dial() defaults to lab.active_creds(); register the fake account.

    monkeypatch restores the previous value afterwards, so on a live lab
    run the session's real generated account (conftest's lab_creds) is
    back in place for every later test file."""
    monkeypatch.setattr(lab, "_ACTIVE_CREDS", SEAM_CREDS)

# The exact full dial() sequence for the default arguments, in order.
# The `ifconfig pppoe0 down` after create is S05 T3's dial-start-race fix:
# after a module (re)load the fresh clone can be born with IFF_UP already
# set, silently no-op'ing the first `up`; forcing the clone DOWN guarantees
# dial()'s final up() is a real down->up transition (the "pre-down before
# up" prereq the S04 live vector and the ipv6cp test both encode).
EXPECTED_DIAL_RAW = [
    "kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko",
    "ifconfig pppoe0 destroy",
    "ifconfig pppoe0 create",
    "ifconfig pppoe0 down",
    BIND_LAB,
    CFG_DEFAULT,
    "ifconfig pppoe0 up",
]


def _ok(stdout: str = "", stderr: str = ""):
    return types.SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)


def _fail(stderr: str = "pppoectl: Operation not permitted"):
    return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr)


class FakeRunner:
    """Records every (cmd, root, timeout) handed to the seam and returns a
    canned CompletedProcess-like result (default: rc=0, empty output).
    `stdins` maps each command that was given a stdin to that stdin.

    `results` maps an exact command string to a result object (used to
    script failures or canned stdout per command); anything not listed
    gets the rc=0 default.
    """

    def __init__(self, results=None):
        self.calls: list[tuple[str, bool, int]] = []
        self.stdins: dict[str, str] = {}
        self.results = dict(results or {})

    def __call__(self, cmd, root=False, timeout=20, stdin=None):
        self.calls.append((cmd, root, timeout))
        if stdin is not None:
            self.stdins[cmd] = stdin
        return self.results.get(cmd, _ok())


# --- (a) exact built command strings reach the runner unchanged ----------


def test_dial_routes_exact_command_strings_to_runner():
    fake = FakeRunner()
    lab.IfPppoeClient(runner=fake).dial(service="lab")

    assert [cmd for cmd, _, _ in fake.calls] == EXPECTED_DIAL_RAW
    # The secret reaches only the auth command, and only on its stdin.
    assert fake.stdins == {CFG_DEFAULT: SEAM_STDIN}
    assert not any(SEAM_CREDS.password in cmd for cmd, _, _ in fake.calls)
    # Every live command is root (the real executor wraps each with
    # `echo | su -m root -c ...`); the default timeout is preserved.
    assert all(root is True and timeout == 20 for _, root, timeout in fake.calls)


def test_dial_mtu_command_inserted_in_position():
    fake = FakeRunner()
    lab.IfPppoeClient(runner=fake).dial(
        service="lab", mtu=1500
    )
    assert [cmd for cmd, _, _ in fake.calls] == [
        "kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko",
        "ifconfig pppoe0 destroy",
        "ifconfig pppoe0 create",
        "ifconfig pppoe0 down",
        BIND_LAB,
        "ifconfig pppoe0 mtu 1500",
        CFG_DEFAULT,
        "ifconfig pppoe0 up",
    ]


def test_dial_max_payload_mtu_override():
    """max_payload=1500 (RFC 4638 offer) raises the effective mtu to 1500
    exactly as with an explicit mtu -- same command string, same place."""
    for kwargs in ({"mtu": 1492, "max_payload": 1500}, {"max_payload": 1500}):
        fake = FakeRunner()
        lab.IfPppoeClient(runner=fake).dial(
            service="lab", **kwargs
        )
        assert [cmd for cmd, _, _ in fake.calls] == [
            "kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko",
            "ifconfig pppoe0 destroy",
            "ifconfig pppoe0 create",
            "ifconfig pppoe0 down",
            BIND_LAB,
            "ifconfig pppoe0 mtu 1500",
            CFG_DEFAULT,
            "ifconfig pppoe0 up",
        ]


def test_dial_empty_service_and_chap_proto_variant():
    """service="" omits the Service-Name tag; accept=("chap",) selects
    myauthproto=chap with no passiveauthproto."""
    fake = FakeRunner()
    lab.IfPppoeClient(runner=fake).dial(
        service="", accept=("chap",)
    )
    assert [cmd for cmd, _, _ in fake.calls] == [
        "kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko",
        "ifconfig pppoe0 destroy",
        "ifconfig pppoe0 create",
        "ifconfig pppoe0 down",
        BIND_NO_SERVICE,
        CFG_CHAP,
        "ifconfig pppoe0 up",
    ]


def test_hangup_and_restart_link_route_through_seam():
    fake = FakeRunner()
    client = lab.IfPppoeClient(runner=fake)

    client.hangup()
    assert fake.calls == [("ifconfig pppoe0 destroy", True, 20)]

    # restart_link() waits for the FSM to reach PPPOE_STATE_INITIAL between
    # down and up (a state wait, not a sleep): answer that poll at once.
    parms_cmd = f"{lab.IfPppoeClient.PARMS} -d pppoe0"
    fake.results[parms_cmd] = _ok(stdout=f"state={lab.PPPOE_STATE_INITIAL}\n")
    fake.calls.clear()
    client.restart_link()
    assert [cmd for cmd, _, _ in fake.calls] == [
        "ifconfig pppoe0 down",
        parms_cmd,
        "ifconfig pppoe0 up",
    ]
    assert all(root is True and timeout == 20
               for cmd, root, timeout in fake.calls if cmd.startswith("ifconfig"))


def test_direct_run_calls_route_through_seam():
    """Caller-driven `client.run(...)` (e.g. conftest's `_wait_iface_gone`
    `ifconfig -l` probe) also funnels through the seam untouched."""
    fake = FakeRunner()
    lab.IfPppoeClient(runner=fake).run("ifconfig -l", root=False, timeout=5)
    assert fake.calls == [("ifconfig -l", False, 5)]


# --- (b) captured output / returncode flow back to the caller ------------


def test_runner_output_flows_back_to_caller():
    """iface_state parses the fake's canned stdout exactly as it would the
    real executor's -- stdout flows back through the seam untouched."""
    fake = FakeRunner(
        results={
            "ifconfig pppoe0": _ok(
                stdout=(
                    "pppoe0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,"
                    "MULTICAST> metric 0 mtu 1492\n"
                    "\tether 52:54:00:aa:00:01\n"
                    "\tinet6 fe80::5054:ff:feaa:1%pppoe0 prefixlen 64 "
                    "scopeid 0x4\n"
                    "\tinet 10.99.0.101 --> 10.99.0.1 netmask 0xffffffff\n"
                )
            )
        }
    )
    state = lab.IfPppoeClient(runner=fake).iface_state()
    assert state["mtu"] == 1492
    assert state["inet"] == "10.99.0.101"
    assert state["inet_peer"] == "10.99.0.1"
    assert state["inet6_ll"] == "fe80::5054:ff:feaa:1"
    assert state["up"] is True
    assert state["flags"] == ["UP", "BROADCAST", "RUNNING", "SIMPLEX", "MULTICAST"]


def test_runner_returncode_drives_dial_assertions():
    """rc=0 on every command -> dial completes without error (the same
    returncode checks the live executor satisfies)."""
    fake = FakeRunner()
    lab.IfPppoeClient(runner=fake).dial(service="lab")
    assert len(fake.calls) == len(EXPECTED_DIAL_RAW)


# --- (c) failure / exit-code handling identical to the real executor -----


def test_runner_failure_becomes_same_assertion_as_live_executor():
    """A nonzero returncode from the seam surfaces exactly as it does with
    the real executor: dial's own assert fires, naming the command and the
    captured stderr."""
    fake = FakeRunner(results={BIND_LAB: _fail(stderr="pppoectl: Permission denied")})
    with pytest.raises(AssertionError) as excinfo:
        lab.IfPppoeClient(runner=fake).dial(service="lab")
    msg = str(excinfo.value)
    assert BIND_LAB in msg
    assert "pppoectl: Permission denied" in msg


def test_runner_timeout_propagates_like_real_executor():
    """The real executor raises subprocess.TimeoutExpired on ssh timeout;
    the same exception raised by the runner propagates unchanged."""

    def runner(cmd, root=False, timeout=20):
        if "kldstat" in cmd:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)
        return _ok()

    with pytest.raises(subprocess.TimeoutExpired):
        lab.IfPppoeClient(runner=runner).dial(service="lab")


def test_runner_exception_propagates_unchanged():
    class Boom(RuntimeError):
        pass

    def runner(cmd, root=False, timeout=20):
        raise Boom("transport exploded")

    with pytest.raises(Boom, match="transport exploded"):
        lab.IfPppoeClient(runner=runner).dial(service="lab")


def test_invalid_accept_rejected_before_any_command():
    """Pre-command validation still fires before the seam sees anything:
    no command reaches the runner for a bad auth set."""
    fake = FakeRunner()
    with pytest.raises(ValueError, match="unknown auth method"):
        lab.IfPppoeClient(runner=fake).dial(accept=("ntlm",))
    with pytest.raises(RuntimeError, match="no EAP"):
        lab.IfPppoeClient(runner=fake).dial(accept=("eap",))
    assert fake.calls == []


# --- default runner: byte-for-byte the pre-seam ssh executor -------------


def test_default_runner_keeps_real_ssh_executor_path(monkeypatch):
    """runner=None must be behaviourally invisible: the seam falls through
    to IfPppoeDriver.run, which root-wraps and delivers the identical
    argv to `_ssh` (the same hostfwd subprocess the pre-seam dial used)."""
    calls: list[tuple[int, str, int]] = []
    stdin_calls: list[tuple[int, str, str, int]] = []

    def fake_ssh(port, cmd, timeout=20):
        calls.append((port, cmd, timeout))
        return _ok()

    def fake_ssh_stdin(port, cmd, data, timeout=20):
        calls.append((port, cmd, timeout))
        stdin_calls.append((port, cmd, data, timeout))
        return _ok()

    monkeypatch.setattr(lab, "_ssh", fake_ssh)
    monkeypatch.setattr(lab, "_ssh_stdin", fake_ssh_stdin)
    lab.IfPppoeClient().dial(service="lab")

    # Commands without stdin keep the `echo | su` wrap; the secret-bearing
    # one feeds the secret, and nothing else, as the command's stdin (su
    # reads no prompt line from a non-tty stdin: lab._run_guest).
    assert [cmd for _, cmd, _ in calls] == [
        ("su -m root -c " if c == CFG_DEFAULT else "echo | su -m root -c ")
        + shlex.quote(c) for c in EXPECTED_DIAL_RAW
    ]
    assert [(cmd, data) for _, cmd, data, _ in stdin_calls] == [
        ("su -m root -c " + shlex.quote(CFG_DEFAULT), SEAM_STDIN)
    ]
    assert all(port == lab.CLIENT_SSH_PORT for port, _, _ in calls)
    assert all(timeout == 20 for _, _, timeout in calls)


def test_dial_without_an_active_account_fails_before_any_command(monkeypatch):
    """No generated account registered -> dial() refuses up front instead
    of dialing with some fallback credential."""
    monkeypatch.setattr(lab, "_ACTIVE_CREDS", None)
    fake = FakeRunner()
    with pytest.raises(RuntimeError, match="no lab PPPoE account is active"):
        lab.IfPppoeClient(runner=fake).dial(service="lab")
    assert fake.calls == []


def test_mpd5_dial_writes_conf_only_to_the_tmpfs_guarded_dir(monkeypatch):
    """Mpd5Client.dial feeds the password-bearing mpd.conf on stdin to a
    root command that first proves MPD5_CONF_DIR is a tmpfs mount."""
    seen = []

    def fake_ssh_stdin(port, cmd, data, timeout=20):
        seen.append((cmd, data))
        return _ok()

    monkeypatch.setattr(lab, "_ssh_stdin", fake_ssh_stdin)
    monkeypatch.setattr(lab.Mpd5Client, "_wait_running", lambda self: None)
    lab.Mpd5Client().dial(service="lab")
    (cmd, data), = seen
    assert SEAM_CREDS.password not in cmd
    assert f"\tset auth password {SEAM_CREDS.password}\n" in data
    assert f"\tset auth authname {SEAM_CREDS.user}\n" in data
    assert cmd.startswith("su -m root -c ")
    assert "mount -p" in cmd and "tmpfs" in cmd and lab.MPD5_CONF_DIR in cmd
    assert "/tmp/" not in cmd


def test_root_stdin_reaches_the_command_verbatim(monkeypatch):
    """_run_guest(root=True, stdin=...) hands `stdin` to su's command
    unchanged.  su(1) on the lab guests reads no prompt line from a non-tty
    stdin, so the old leading blank line became the command's first line:
    `pppoectl -S` took an empty secret, mpdsrv an empty mpd.secret line."""
    seen = []

    def fake_ssh_stdin(port, cmd, data, timeout=20):
        seen.append((cmd, data))
        return _ok()

    monkeypatch.setattr(lab, "_ssh_stdin", fake_ssh_stdin)
    lab._run_guest(lab.CLIENT_SSH_PORT, "cat", True, 20, SEAM_STDIN)
    assert seen == [("su -m root -c cat", SEAM_STDIN)]


def test_generated_account_is_slot_scoped():
    import labcreds
    user, password = labcreds.generate()
    assert user.startswith(f"labrun-s{lab.LAB_SLOT}-")
    assert len(user) == len(labcreds.slot_prefix()) + 8
    assert len(password) == 32 and password.isalnum()


def test_account_file_filter_matches_exact_user_or_slot_prefix(tmp_path):
    """The accel chap-secrets / mpdsrv mpd.secret rewrite keeps every line
    but this run's user (exact), or but one slot's accounts (prefix, the
    explicit purge): other slots' and other runs' accounts survive."""
    import labcreds
    f = tmp_path / "accounts"
    f.write_text("# comment\n"
                 "labrun-s1-aaaaaaaa * x *\n"
                 "labrun-s1-bbbbbbbb * x *\n"
                 "labrun-s2-aaaaaaaa * x *\n"
                 "dutrun-cccccccc * x *\n")

    def keep(u, mode):
        r = subprocess.run(["sh", "-c", f'u=$1; mode=$2; f=$3; {labcreds._KEEP_OTHERS}',
                            "sh", u, mode, str(f)],
                           capture_output=True, text=True, check=True)
        return [ln.split()[0] for ln in r.stdout.splitlines()]

    assert keep("labrun-s1-aaaaaaaa", "exact") == [
        "#", "labrun-s1-bbbbbbbb", "labrun-s2-aaaaaaaa", "dutrun-cccccccc"]
    assert keep("labrun-s1-", "exact") == [
        "#", "labrun-s1-aaaaaaaa", "labrun-s1-bbbbbbbb", "labrun-s2-aaaaaaaa",
        "dutrun-cccccccc"]
    assert keep("labrun-s1-", "prefix") == ["#", "labrun-s2-aaaaaaaa", "dutrun-cccccccc"]


def test_default_construction_has_no_runner():
    assert lab.IfPppoeClient()._runner is None


# --- public surface regression guard --------------------------------------


def test_public_signatures_unchanged():
    """The seam must not alter IfPppoeClient's public surface: run()'s
    signature matches the driver's, and the client's methods keep the
    exact signatures real callers rely on."""
    driver_sig = inspect.signature(lab.IfPppoeDriver.dial) if hasattr(lab.IfPppoeDriver, "dial") else None
    for meth in ("run", "up", "down", "create", "destroy", "parms",
                 "wait_state", "sysctl", "counter", "iface_state"):
        client_sig = inspect.signature(getattr(lab.IfPppoeClient, meth))
        driver_sig = inspect.signature(getattr(lab.IfPppoeDriver, meth))
        assert str(client_sig) == str(driver_sig), f"IfPppoeClient.{meth} drifted from the driver surface"

    dial_sig = inspect.signature(lab.IfPppoeClient.dial)
    assert list(dial_sig.parameters) == [
        "self", "service", "user", "password", "mtu", "max_payload", "accept"
    ]
    assert dial_sig.parameters["service"].default == "lab"
    # No fixed account: user/password default to lab.active_creds().
    assert dial_sig.parameters["user"].default is None
    assert dial_sig.parameters["password"].default is None

    run_sig = inspect.signature(lab.IfPppoeClient.run)
    assert list(run_sig.parameters) == ["self", "cmd", "root", "timeout", "stdin"]
    assert run_sig.parameters["stdin"].default is None
    assert run_sig.parameters["root"].default is False
    assert run_sig.parameters["timeout"].default == 20

    init_sig = inspect.signature(lab.IfPppoeClient.__init__)
    assert list(init_sig.parameters) == ["self", "runner"]
    assert init_sig.parameters["runner"].default is None