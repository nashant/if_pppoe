"""Lab-object implementations for the functional PPPoE test harness.

Runs ON the lab host (see README.md): VM operations go over a direct ssh to
the guest's user-mode-NIC hostfwd (127.0.0.1:<port>, no jump host needed
since we're already on the host); accel-ppp/netns/bridge operations are
local subprocess calls (this process needs root -- run pytest under sudo).

Fixed lab facts this module hardcodes (see lab/vm/README.md, lab/vm/common.sh,
lab/isp-netns/README.md -- not guesses):
  - client VM ssh port 2223, user "freebsd", vtnet1 MAC 52:54:00:aa:00:01
    (lab/vm/common.sh vm_config), PPPoE iface name vtnet1, bundle iface pppoe0.
  - mpdsrv VM ssh port 2224, service "mpdlab", pool 10.99.2.x.
  - accel-ppp: netns "isp", ac-name "isp-lab", service "lab", pool
    10.99.0.100-199, gw 10.99.0.1, cli at 127.0.0.1:2001 (accel-cmd default
    port, accel-cmd -h), log /tmp/accel-ppp.log.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from typing import NamedTuple


def _default_ssh_key() -> str:
    """~$SUDO_USER/.ssh/id_rsa (falling back to id_ed25519) -- the Makefile's
    test-func target runs pytest under sudo (scapy needs raw sockets on
    br-isp), so $HOME here is root's, not the invoking user's; SUDO_USER
    recovers the account whose key is actually authorized on the VMs.
    Mirrors run.sh's SSH_PUBKEY_FILE discovery (id_rsa.pub first, then
    id_ed25519.pub) so both sides agree on which key pair is in play.
    """
    sudo_user = os.environ.get("SUDO_USER")
    home = os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")
    for name in ("id_rsa", "id_ed25519"):
        candidate = os.path.join(home, ".ssh", name)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(home, ".ssh", "id_rsa")


SSH_KEY = os.environ.get("LAB_SSH_KEY") or _default_ssh_key()

# Lab slot (lab/vm/common.sh vm_config; lab/vm/README.md "Slots and leases"):
# slot 1 is the original lab; slot N>1 offsets every ssh port by 10*(N-1),
# bridges its VMs on br-isp<N> and names them client<N>/isp<N>/mpdsrv<N>.
# MACs are identical in every slot (each slot is its own L2 segment).
LAB_SLOT = int(os.environ.get("LAB_SLOT", "1"))
if not 1 <= LAB_SLOT <= 9:
    raise ValueError(f"LAB_SLOT must be 1..9, got {LAB_SLOT}")
_SLOT_OFF = 10 * (LAB_SLOT - 1)
_SLOT_SFX = "" if LAB_SLOT == 1 else str(LAB_SLOT)
LAB_HOME_DIR = "if_pppoe-lab"  # lab/vm's $LAB_DIR, under the invoking user's home
_RUN_DIR = "run" if LAB_SLOT == 1 else f"run-slot{LAB_SLOT}"


def invoking_home() -> str:
    """Home of the account that ran sudo (pytest runs as root)."""
    sudo_user = os.environ.get("SUDO_USER")
    return os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")


CLIENT_SSH_PORT = 2223 + _SLOT_OFF
MPDSRV_SSH_PORT = 2224 + _SLOT_OFF
ISP_SSH_PORT = 2225 + _SLOT_OFF
BR_ISP = "br-isp" + _SLOT_SFX
# The client VM's serial console log, relative to invoking_home().
CLIENT_SERIAL_REL = os.path.join(LAB_HOME_DIR, _RUN_DIR, f"client{_SLOT_SFX}.serial.log")
CLIENT_MAC = "52:54:00:aa:00:01"
ACCEL_AC_NAME = "isp-lab"
ACCEL_GW = "10.99.0.1"
ACCEL_POOL_RE = re.compile(r"^10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99)$")
MPDSRV_GW = "10.99.2.1"
POCTL = "/usr/local/sbin/pppoectl"
# mpd5's config directory (mpd.conf + mpd.secret) on the client and mpdsrv
# VMs -- the default that `mpd5 -d dir` overrides (mpd5 manual, "Invoking
# mpd": https://mpd.sourceforge.net/doc5/mpd10.html).  labcreds mounts a
# tmpfs over it for the run so password-bearing files never touch disk.
MPD5_CONF_DIR = "/usr/local/etc/mpd5"


def tmpfs_guard(path: str) -> str:
    """FreeBSD sh test: true iff `path` is currently a tmpfs mountpoint
    (`mount -p` prints fstab-format lines: device, mountpoint, fstype)."""
    return (f"mount -p | awk -v d={shlex.quote(path)} "
            "'$2 == d && $3 == \"tmpfs\" { f = 1 } END { exit !f }'")


class LabCreds(NamedTuple):
    """One PPPoE account for the lab servers (accel-ppp and mpdsrv).

    There is no fixed lab account: labcreds.lab_session() generates one per
    run (user LABCREDS_USER_PREFIX + random hex, random password), installs
    it on the servers' tmpfs credential files, registers it here and removes
    it all at teardown.  Nothing here is ever written to disk locally."""

    user: str
    password: str


_ACTIVE_CREDS: LabCreds | None = None


def set_active_creds(creds: LabCreds | None) -> None:
    global _ACTIVE_CREDS
    _ACTIVE_CREDS = creds


def active_creds() -> LabCreds:
    """The current run's generated account (see labcreds.lab_session)."""
    if _ACTIVE_CREDS is None:
        raise RuntimeError(
            "no lab PPPoE account is active: the per-run credentials are "
            "installed by labcreds.lab_session() (conftest's session-scoped "
            "lab_creds fixture, or the probe scripts' __main__)")
    return _ACTIVE_CREDS


def auth_cfg_cmd(iface: str = "pppoe0", proto: str = "pap", extra: str = "",
                 creds: LabCreds | None = None, poctl: str = POCTL) -> tuple[str, str]:
    """(command, stdin) programming SPPPSETAUTHCFG with the run's account.

    The secret never goes on argv: `pppoectl -S` reads it, one raw line,
    from stdin (sbin/pppoectl/pppoectl.c, the secret_from_stdin getline
    path).  Pass the pair to run(cmd, root=True, stdin=...)."""
    c = creds or active_creds()
    cmd = f"{poctl} -S {iface} myauthproto={proto} myauthname={shlex.quote(c.user)}"
    if extra:
        cmd += f" {extra}"
    return cmd, c.password + "\n"


def spppauth_cmd(iface: str = "pppoe0", creds: LabCreds | None = None) -> tuple[str, str]:
    """(command, stdin) for the positional `spppauth NAME SECRET IFNAME`
    test helper (tools/spppauth).  The secret travels on stdin and is read
    by the guest's sh, so it is in no ssh command line and no local argv;
    only the short-lived spppauth process on the guest holds it in argv,
    as that tool's interface requires."""
    c = creds or active_creds()
    cmd = (f"IFS= read -r s; exec /usr/local/sbin/spppauth "
           f"{shlex.quote(c.user)} \"$s\" {shlex.quote(iface)}")
    return cmd, c.password + "\n"


def _ssh_base_args(port: int) -> list[str]:
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        "-i", SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-p", str(port),
        "freebsd@127.0.0.1",
    ]


def _ssh(port: int, *args: str, timeout: int = 20) -> subprocess.CompletedProcess:
    cmd = _ssh_base_args(port) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def mpdsrv_tunnel(client_ip: str | None = None) -> tuple[str | None, str | None]:
    """(ngN, link-local) of the mpd5 server's tunnel interface, or
    (None, None).

    Only ng* interfaces count: `ifconfig -a` lists interfaces in if_index
    order, so vtnet0/vtnet1/lo0 (which carry their own fe80::) come first and
    a scrape that takes the first fe80::/64 lands on a non-tunnel address.
    With `client_ip`, only the ngN whose point-to-point peer is that address
    (the live session, not a stale one) is accepted -- the same
    `inet A --> B` shape iface_state() reads.

    The address itself is not predictable: mpd5's IPv6CP layer has no
    configuration options (mpd5 manual, IPv6CP chapter: "there is no
    additional configuration options present at this layer"), so the
    interface identifier cannot be pinned and is read off the live ngN.
    """
    out = _ssh(MPDSRV_SSH_PORT, "ifconfig -a").stdout
    for block in re.split(r"(?m)^(?=\S)", out):
        m = re.match(r"(ng\d+):", block)
        if not m:
            continue
        ifname = m.group(1)
        if client_ip and not re.search(
                rf"^\tinet \S+ --> {re.escape(client_ip)}\b", block, re.M):
            continue
        ll = re.search(rf"inet6 (fe80::[0-9a-f:]+)%{ifname}\b", block)
        if ll:
            return ifname, ll.group(1)
    return None, None


def _ssh_stdin(port: int, remote_cmd: str, data: str, timeout: int = 20) -> subprocess.CompletedProcess:
    cmd = _ssh_base_args(port) + [remote_cmd]
    return subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)


def _ssh_stdin_bytes(port: int, remote_cmd: str, data: bytes, timeout: int = 20) -> subprocess.CompletedProcess:
    """Like _ssh_stdin, but locale-independent: some ctl-contract fixtures carry
    a unicode secret or exact tab/space bytes, and a text-mode pipe would
    re-encode them through the invoking process's locale."""
    cmd = _ssh_base_args(port) + [remote_cmd]
    return subprocess.run(cmd, input=data, capture_output=True, timeout=timeout)


def _run_guest(port: int, cmd: str, root: bool, timeout: int,
               stdin: str | None) -> subprocess.CompletedProcess:
    """The FreeBSD guests' run(): `echo | su -m root -c CMD` for root=True.

    With `stdin` (secrets: never argv), `stdin` is CMD's own stdin, as is:
    su(1) on the lab guests reads NO line from a non-tty stdin (it asks for
    no password there), so a leading blank line "for su's prompt" reaches
    CMD as its first line -- pppoectl -S then took an empty secret and the
    mpdsrv install an empty mpd.secret line (probe on slot 1:
    printf '\\nABCDEFG\\n' | ssh client "su -m root -c 'read s; read t; ...'"
    gave len(s)=0, len(t)=7).  `pppoectl -f /dev/stdin` only passed with the
    blank line because its -f loop skips empty lines (sbin/pppoectl/
    pppoectl.c: `if (line[0] != '\\0') pppoectl_argument(line)`)."""
    if stdin is None:
        if root:
            cmd = "echo | su -m root -c " + shlex.quote(cmd)
        return _ssh(port, cmd, timeout=timeout)
    if root:
        return _ssh_stdin(port, "su -m root -c " + shlex.quote(cmd), stdin,
                          timeout=timeout)
    return _ssh_stdin(port, cmd, stdin, timeout=timeout)


def _sppp_header_source_dir() -> str:
    """Where this checkout's own net/if_sppp.h + net/if_pppoe.h live: tried
    alongside this file first (lab/Makefile's test-func rsyncs them into
    tests-functional/vendor-headers/net/ for the normal lab-host deploy,
    since only tests/functional/ itself is otherwise synced there), then
    the full checkout's own sys/net/ (pytest run directly from a full
    clone)."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "vendor-headers", "net"),
        os.path.normpath(os.path.join(here, "..", "..", "sys", "net")),
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "if_sppp.h")):
            return c
    raise FileNotFoundError(
        "vendored net/if_sppp.h not found in any of: " + ", ".join(candidates)
    )


def push_vendored_sppp_headers(driver, remote_dir: str = "/tmp/pppoe-sppp-hdrs") -> str:
    """Upload the real net/if_sppp.h + net/if_pppoe.h to the client VM so an
    embedded C probe can #include them instead of a private copy that can
    silently desync from the driver (p3-ctl-abi; see
    docs/PORTING-sppp.md). Returns the remote -I directory."""
    src = _sppp_header_source_dir()
    # Created as the ssh user that then writes into it (the uploads below are
    # not root); a stale root-owned copy from an older harness is removed first.
    r = driver.run(f"rm -rf {remote_dir}", root=True)
    assert r.returncode == 0, f"rm -rf {remote_dir} on client failed: {r.stderr}"
    r = driver.run(f"mkdir -p {remote_dir}/net")
    assert r.returncode == 0, f"mkdir {remote_dir}/net on client failed: {r.stderr}"
    for name in ("if_sppp.h", "if_pppoe.h"):
        with open(os.path.join(src, name)) as fh:
            content = fh.read()
        r = _ssh_stdin(driver.port, f"cat > {remote_dir}/net/{name}", content)
        assert r.returncode == 0, f"uploading {name} to client VM failed: {r.stderr}"
    return remote_dir


def _ctl_contract_source_dir_and_replay() -> tuple[str, str]:
    """Where the ctl-contract fixtures dir + replay script live: tried
    alongside this file first (lab/Makefile's test-func rsyncs them into
    tests-functional/vendor-ctl-contract/ for the normal lab-host deploy,
    since only tests/functional/ itself is otherwise synced there -- same
    reasoning as _sppp_header_source_dir()), then the full checkout's own
    plugin/net/if-pppoe/tests/ (pytest run directly from a full clone)."""
    here = os.path.dirname(os.path.abspath(__file__))
    vendored = os.path.join(here, "vendor-ctl-contract")
    full_checkout = os.path.normpath(os.path.join(here, "..", "..", "plugin", "net", "if-pppoe", "tests"))
    candidates = (
        (os.path.join(vendored, "fixtures"), os.path.join(vendored, "ctl-contract-replay.sh")),
        (os.path.join(full_checkout, "fixtures", "ctl-contract"), os.path.join(full_checkout, "engine", "ctl-contract-replay.sh")),
    )
    for fixtures, replay in candidates:
        if os.path.isdir(fixtures) and os.path.isfile(replay):
            return fixtures, replay
    raise FileNotFoundError(
        "ctl-contract fixtures/replay script not found in any of: "
        + ", ".join(f"({f}, {r})" for f, r in candidates)
    )


def push_ctl_contract(driver, remote_dir: str = "/tmp/ctl-contract") -> tuple[str, str]:
    """Upload the ctl-contract fixtures (plugin/net/if-pppoe/tests/fixtures/
    ctl-contract/, one argv-token-per-line / raw-bytes file per scenario --
    see gen_ctl_contract.php) and the POSIX sh replay script that consumes
    them (plugin/net/if-pppoe/tests/engine/ctl-contract-replay.sh) to the
    client VM. Returns (remote fixtures dir, remote replay script path)."""
    fixtures_src, replay_src = _ctl_contract_source_dir_and_replay()

    # Created as the ssh user that then writes into it, same as
    # push_vendored_sppp_headers: a stale root-owned copy (fixtures dir and
    # the replay script uploaded alongside it) is removed first.
    r = driver.run(f"rm -rf {remote_dir} {remote_dir}.replay.sh", root=True)
    assert r.returncode == 0, f"rm -rf {remote_dir}* on client failed: {r.stderr}"
    r = driver.run(f"mkdir -p {remote_dir}")
    assert r.returncode == 0, f"mkdir {remote_dir} on client failed: {r.stderr}"

    # Binary, not text mode: fixture bytes (a unicode secret, exact tabs/spaces)
    # must reach the client verbatim, not re-encoded through this process's locale.
    for dirpath, _dirnames, filenames in os.walk(fixtures_src):
        rel = os.path.relpath(dirpath, fixtures_src)
        remote_sub = remote_dir if rel == "." else f"{remote_dir}/{rel}"
        if remote_sub != remote_dir:
            r = driver.run(f"mkdir -p {remote_sub}")
            assert r.returncode == 0, f"mkdir {remote_sub} on client failed: {r.stderr}"
        for name in filenames:
            with open(os.path.join(dirpath, name), "rb") as fh:
                content = fh.read()
            r = _ssh_stdin_bytes(driver.port, f"cat > {remote_sub}/{name}", content)
            assert r.returncode == 0, f"uploading {name} to client VM failed: {r.stderr}"

    replay_remote = f"{remote_dir}.replay.sh"
    with open(replay_src, "rb") as fh:
        content = fh.read()
    r = _ssh_stdin_bytes(driver.port, f"cat > {replay_remote}", content)
    assert r.returncode == 0, f"uploading ctl-contract-replay.sh to client VM failed: {r.stderr}"
    r = driver.run(f"chmod +x {replay_remote}")
    assert r.returncode == 0, f"chmod +x {replay_remote} on client failed: {r.stderr}"
    return remote_dir, replay_remote


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.2, desc: str = "condition"):
    """Poll `predicate()` until it returns truthy, or raise TimeoutError.

    Replaces a fixed `time.sleep(N)` guessing how long some lab-side state
    change takes with an actual wait on that state: returns as soon as
    `predicate()` is truthy (returning its value), and never waits longer
    than `timeout` -- which should be set at least as generous as whatever
    fixed sleep it replaces, since the SMPW debug kernel is slower than a
    normal build.  A `predicate` that itself raises (a transient ssh/parse
    hiccup mid-poll) is treated as "not yet" rather than failing the wait.
    """
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            result = predicate()
        except Exception as exc:  # noqa: BLE001 -- transient, retried below
            last_exc = exc
            result = None
        if result:
            return result
        time.sleep(interval)
    if last_exc is not None:
        raise TimeoutError(
            f"wait_until: timed out after {timeout}s waiting for {desc} "
            f"(last error: {last_exc!r})"
        )
    raise TimeoutError(f"wait_until: timed out after {timeout}s waiting for {desc}")


class Mpd5Client:
    """The known-good mpd5 PPPoE client on the "client" VM (CLIENT=mpd5)."""

    port = CLIENT_SSH_PORT
    mac = CLIENT_MAC

    def run(self, cmd: str, root: bool = False, timeout: int = 20,
            stdin: str | None = None) -> subprocess.CompletedProcess:
        return _run_guest(self.port, cmd, root, timeout, stdin)

    ALL_AUTH = ("pap", "chap", "eap")

    def dial(self, service, user=None, password=None, mtu=None, max_payload=None, accept=ALL_AUTH):
        """(Re)writes mpd.conf to a single "harness" label and restarts mpd5.

        user/password default to the run's generated account
        (active_creds()).  The conf carries that password, so it is only
        ever written into the tmpfs labcreds mounts over MPD5_CONF_DIR for
        the run (the guard below refuses anything else), fed over ssh
        stdin -- never argv, never a /tmp staging file on the guest's disk.

        max_redial 0 (infinite redial, mpd default is -1 "never" -- see
        mpd13.html "set link max-redial") so the redial-after-terminate test
        in test_discovery.py is testing real behavior, not a harness fluke.

        `accept`: which auth methods mpd will allow being asked for (mpd20.html
        "Link layer" chapter: pap/chap/eap each default to "disable and
        accept" independently, so restricting to e.g. accept=("chap",) also
        requires an explicit `deny` for the others -- accept alone does not
        undo their default-accept state).
        """
        if user is None or password is None:
            c = active_creds()
            user = c.user if user is None else user
            password = c.password if password is None else password
        effective_mtu = 1492 if mtu is None else mtu
        mru = None
        if max_payload is not None:
            effective_mtu = max(effective_mtu, max_payload)
            mru = max_payload + 1

        lines = [
            "startup:",
            "",
            "default:",
            "\tload harness",
            "",
            "harness:",
            "\tcreate bundle static wan",
            "\tset bundle enable ipv6cp",
            "\tset iface name pppoe0",
            "\tset ipcp ranges 0.0.0.0/0 0.0.0.0/0",
            "\tset ipcp enable req-pri-dns",
            "",
            "\tcreate link static wan pppoe",
            "\tset link action bundle wan",
            "\tset link keep-alive 10 60",
            "\tset link max-redial 0",
            "\tset link redial-delay 3",
            "\tset link disable chap pap",
            "\tset link accept " + " ".join(accept),
        ]
        deny = [m for m in self.ALL_AUTH if m not in accept]
        if deny:
            lines.append("\tset link deny " + " ".join(deny))
        lines += [
            f"\tset link mtu {effective_mtu}",
        ]
        if mru is not None:
            lines.append(f"\tset link mru {mru}")
        lines += [
            f"\tset auth authname {user}",
            f"\tset auth password {password}",
            "\tset pppoe iface vtnet1",
            f'\tset pppoe service "{service}"',
        ]
        if max_payload is not None:
            lines.append(f"\tset pppoe max-payload {max_payload}")
        lines.append("\topen")
        conf = "\n".join(lines) + "\n"

        r = self.run(
            f"{tmpfs_guard(MPD5_CONF_DIR)} || exit 3; umask 077; "
            f"cat > {MPD5_CONF_DIR}/mpd.conf && service mpd5 restart",
            root=True, stdin=conf,
        )
        assert r.returncode != 3, (
            f"{MPD5_CONF_DIR} is not the run's tmpfs mount (labcreds."
            "lab_session); refusing to write a password-bearing mpd.conf to disk")
        assert r.returncode == 0, f"mpd.conf write / mpd5 restart failed: {r.stdout}\n{r.stderr}"
        self._wait_running()

    def restart_link(self):
        r = self.run("service mpd5 restart", root=True)
        assert r.returncode == 0, f"mpd5 restart failed: {r.stdout}\n{r.stderr}"
        self._wait_running()

    def _wait_running(self, timeout: float = 10.0):
        """Wait for mpd5 to report itself running after a restart, instead
        of a blind sleep(2) guessing how long the daemon takes to fork and
        bind -- more generous than the old fixed 2s, and returns as soon as
        `service mpd5 onestatus` succeeds.
        """
        wait_until(
            lambda: self.run("service mpd5 onestatus").returncode == 0,
            timeout=timeout, interval=0.2,
            desc="mpd5 to report running (service mpd5 onestatus)",
        )

    def hangup(self):
        r = self.run("service mpd5 stop", root=True)
        assert r.returncode == 0, f"mpd5 stop failed: {r.stdout}\n{r.stderr}"

    def iface_state(self, iface="pppoe0") -> dict:
        r = self.run(f"ifconfig {iface}")
        out = r.stdout
        m_mtu = re.search(r"\bmtu (\d+)", out)
        m_inet = re.search(r"inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)", out)
        m_inet6 = re.search(r"inet6 (fe80::[0-9a-f:]+)", out)
        m_flags = re.search(r"flags=[0-9a-fA-F]+<([^>]*)>", out)
        flags = m_flags.group(1).split(",") if m_flags else []
        return {
            "raw": out,
            "mtu": int(m_mtu.group(1)) if m_mtu else None,
            "inet": m_inet.group(1) if m_inet else None,
            "inet_peer": m_inet.group(2) if m_inet else None,
            "inet6_ll": m_inet6.group(1) if m_inet6 else None,
            "flags": flags,
            "up": "UP" in flags,
        }


class AccelServer:
    """The lab's accel-ppp server (SERVER=accel).

    Two server implementations share this API:
    - the isp VM (a dedicated Linux VM running accel-pppd; accel-cmd runs
      inside the VM over ssh, since accel's CLI TCP socket binds guest
      loopback only and slirp host-forwarding cannot reach it), and
    - the legacy isp-netns server (accel-pppd inside the `isp` netns).
    _cli() tries the VM path first and falls back to the netns-wrapped
    invocation, so both stay runnable with zero test changes.
    """

    CLI = ["ip", "netns", "exec", "isp", "accel-cmd", "-H", "127.0.0.1", "-P", "2001"]
    CLI_VM = [
        "ssh", "-p", str(ISP_SSH_PORT),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
        "-i", SSH_KEY,
        "debian@127.0.0.1",
        "/usr/local/bin/accel-cmd", "-H", "127.0.0.1", "-P", "2001",
    ]
    # Slot 1: the /tmp symlink into isp-share; slot N: the isp<N> 9p share.
    LOG = os.environ.get("LAB_ACCEL_LOG") or (
        "/tmp/accel-ppp.log" if LAB_SLOT == 1 else
        os.path.join(invoking_home(), LAB_HOME_DIR, f"isp-share-slot{LAB_SLOT}", "accel-ppp.log")
    )

    def _cli(self, *args: str, timeout: int = 10) -> str:
        errors: list[str] = []
        cmds = [("isp VM", self.CLI_VM + list(args))]
        if LAB_SLOT == 1:  # the legacy isp netns exists for slot 1 only
            cmds.append(("isp netns", ["sudo"] + self.CLI + list(args)))
        for where, cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return r.stdout
            # If accel-cmd can't reach the CLI socket, a swallowed nonzero
            # exit here would make sessions() silently return [] --
            # indistinguishable from "no sessions" -- and terminate_all()
            # a silent no-op. Raise instead, mirroring ssh_collectors.run_ssh.
            # Every attempt is reported: the VM is the primary server, so
            # its error must not be hidden behind the netns fallback's.
            errors.append(
                f"{where}: accel-cmd {' '.join(args)} exited {r.returncode}: "
                f"stderr={r.stderr.strip()!r} stdout={r.stdout.strip()!r}"
            )
        raise RuntimeError("; ".join(errors))

    @staticmethod
    def _parse_table(out: str) -> list[dict]:
        lines = [ln for ln in out.splitlines() if "|" in ln and "---" not in ln]
        if not lines:
            return []
        header = [c.strip() for c in lines[0].split("|")]
        rows = []
        for ln in lines[1:]:
            cells = [c.strip() for c in ln.split("|")]
            if len(cells) != len(header):
                continue
            rows.append(dict(zip(header, cells)))
        return rows

    def sessions(self) -> list[dict]:
        return self._parse_table(self._cli("show", "sessions"))

    def terminate_all(self, mode: str = "hard"):
        return self._cli("terminate", "all", mode)

    def set_option(self, name: str, value: str):
        """Live (no-restart) accel-cmd options -- see `accel-cmd help`."""
        live = {"service-name": "Service-Name", "ac-name": "AC-Name"}
        if name not in live:
            raise NotImplementedError(f"set_option({name!r}): not a live accel-cmd 'pppoe set' option")
        return self._cli("pppoe", "set", live[name], value)

    def log_tail(self, n: int = 50) -> str:
        r = subprocess.run(["sudo", "tail", "-n", str(n), self.LOG], capture_output=True, text=True)
        return r.stdout


class MpdsrvServer:
    """The mpdsrv VM's mpd5 PPPoE server (SERVER=mpdsrv).

    Minimal: mpd5 has no accel-cmd-equivalent CLI wired up in this lab, so
    sessions()/log_tail() scrape ssh output instead of a control-socket API.
    No suite test requests the SERVER-selected `server` fixture today (the
    service-"lab" tests pin the accel peer via conftest's accel_server;
    the needs_mpdsrv tests reach the mpdsrv VM directly over ssh), but the
    fixture stays wired for genuinely server-parameterized tests.
    """

    port = MPDSRV_SSH_PORT

    def _run(self, cmd: str, root: bool = False, timeout: int = 20):
        if root:
            cmd = "echo | su -m root -c " + shlex.quote(cmd)
        r = _ssh(self.port, cmd, timeout=timeout)
        if r.returncode != 0:
            # Same silent-failure shape as AccelServer._cli: an unraised
            # nonzero exit here would make sessions() return [] --
            # indistinguishable from "no sessions".
            raise RuntimeError(
                f"ssh mpdsrv {cmd!r} exited {r.returncode}: "
                f"stderr={r.stderr.strip()!r} stdout={r.stdout.strip()!r}"
            )
        return r

    def sessions(self) -> list[dict]:
        r = self._run("ifconfig -a")
        rows = []
        for m in re.finditer(r"^(\S+):.*?\n(?:\t.*\n)*?\tinet (10\.99\.2\.\d+)", r.stdout, re.M):
            rows.append({"ifname": m.group(1), "ip": m.group(2)})
        return rows

    def terminate_all(self, mode: str = "hard"):
        raise NotImplementedError("MpdsrvServer.terminate_all: no control API wired up in this lab")

    def set_option(self, name: str, value: str):
        raise NotImplementedError("MpdsrvServer.set_option: no live control API wired up in this lab")

    def log_tail(self, n: int = 50) -> str:
        r = self._run(f"echo | su -m root -c 'tail -n {n} /var/log/daemon.log'")
        return r.stdout


class PPPoESniffer:
    """scapy AsyncSniffer on br-isp, filtered to PPPoE discovery+session frames."""

    IFACE = BR_ISP

    # Readiness probe (see _wait_capture_live): a PPPoED code the driver and
    # accel-ppp both ignore, unicasted to the client VM's MAC so the AC's tap
    # port never even sees it.  Locally-administered source MAC, distinct
    # from every MAC the lab allocates (client 52:54:00:aa:00:01, mpdsrv,
    # accel, FOREIGN_MAC 52:54:00:aa:00:fe).
    PROBE_CODE = 0xFF
    PROBE_DST = CLIENT_MAC
    PROBE_SRC = "02:73:6e:69:66:66"
    PROBE_HOST_UNIQ = b"sniff-ready"

    def __init__(self):
        self._sniffer = None
        self._packets: list = []

    def start(self):
        from scapy.all import AsyncSniffer

        self._packets = []
        # `.results` stays None until the capture thread stops (verified
        # against scapy's source); use `prn` for live access while running.
        self._sniffer = AsyncSniffer(
            iface=self.IFACE, filter="pppoed or pppoes", prn=self._packets.append, store=False
        )
        self._sniffer.start()
        self._wait_capture_live()

    def _wait_capture_live(self, timeout: float = 5.0, poll: float = 0.2):
        """Block until the capture is PROVABLY attached to br-isp.

        AsyncSniffer.start() only spawns the capture thread; the packet
        socket (and its BPF filter) attach asynchronously, and the 0.3s
        sleep this used to rely on lost whole discovery exchanges when the
        fast in-kernel dial beat the attach (S05 T3 baseline failure:
        test_padi_pado_padr_pads_ordering_and_hostuniq captured exactly two
        PADT frames and none of the PADI/PADO/PADR/PADS that must follow
        them on the wire).  Instead of guessing how long the attach takes,
        inject a one-frame readiness probe and require the capture to prove
        it saw one before start() returns.

        The probe is a PPPoED frame with an unused code (0xFF, collides with
        no asserted discovery code), unicasted to the client VM's MAC so the
        AC never sees it.  The client kernel's discovery input path drops it
        harmlessly: pppoe_find_by_hunique() finds no softc for the probe's
        Host-Uniq (sys/net/if_pppoe_disc.c), the code is not PADT, and no
        error tag is present, so the hook passes it up the stack untouched
        -- net.pppoe.passed_foreign moves by one per probe, nothing else --
        and the live session is untouched.  Tests asserting an exact
        passed_foreign delta take their baseline after start().  The probe frames stay in sniffer.packets;
        every consumer filters by layer/code and 0xFF matches none.

        The probe is re-sent every poll until seen: a single frame sent
        before the attach would itself be missed and turn the race into a
        spurious RuntimeError instead.
        """
        from scapy.all import Ether, PPPoED, Raw

        probe = (
            Ether(dst=self.PROBE_DST, src=self.PROBE_SRC, type=0x8863)
            / PPPoED(code=self.PROBE_CODE, sessionid=0)
            / Raw(
                # Host-Uniq TLV (type 259) by hand -- scapy does not
                # auto-chain PPPoETag layers (see pppoe_tags below).
                bytes([(259 >> 8) & 0xFF, 259 & 0xFF, 0, len(self.PROBE_HOST_UNIQ)])
                + self.PROBE_HOST_UNIQ
            )
        )
        deadline = time.time() + timeout
        while True:
            self.send([probe])
            for p in self.packets:
                if (
                    p.haslayer(PPPoED)
                    and p[PPPoED].code == self.PROBE_CODE
                    and pppoe_tags(p).get(TAG_HOST_UNIQ) == self.PROBE_HOST_UNIQ
                ):
                    return
            if time.time() >= deadline:
                break
            time.sleep(poll)
        raise RuntimeError(
            f"PPPoESniffer on {self.IFACE}: readiness probe not captured in "
            f"{timeout}s -- the capture socket is not seeing injected frames, "
            "so discovery/session assertions would silently race the attach"
        )

    def stop(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def restart(self):
        self.stop()
        self.start()

    @property
    def packets(self) -> list:
        return list(self._packets)

    def wait_for(self, predicate, timeout=10, poll=0.2):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for p in self.packets:
                if predicate(p):
                    return p
            time.sleep(poll)
        return None

    def send(self, frames):
        from scapy.all import sendp

        sendp(frames, iface=self.IFACE, verbose=False)


# PPPoE discovery-stage codes (RFC 2516), for filtering sniffed packets.
PADI, PADO, PADR, PADS, PADT = 0x09, 0x07, 0x19, 0x65, 0xA7
ETH_PPPOE_DISCOVERY = 0x8863
ETH_PPPOE_SESSION = 0x8864

# PPPoE tag types (scapy PPPoETag.tag_type ShortEnumField -- verified live,
# `PPPoETag().get_field('tag_type').i2s`): 257 Service-Name, 258 AC-Name,
# 259 Host-Uniq, 288 PPP-Max-Payload (RFC 4638).
TAG_SERVICE_NAME, TAG_AC_NAME, TAG_HOST_UNIQ, TAG_MAX_PAYLOAD = 257, 258, 259, 288


def pppoe_tags(pkt) -> dict:
    """Parse the TLV tag list after a PPPoED header into {tag_type: value}.

    scapy (2.7.0, verified live) does not auto-dissect PPPoED's payload into
    chained PPPoETag layers -- `bytes(pkt[PPPoED].payload)` comes back as
    raw TLV bytes (confirmed against a live PADI capture: `01 03 00 08 <8
    bytes Host-Uniq> 01 01 00 03 "lab"`), so the tag list is parsed by hand
    here instead of relying on layer auto-binding.
    """
    from scapy.all import PPPoED

    if not pkt.haslayer(PPPoED):
        return {}
    data = bytes(pkt[PPPoED].payload)
    tags = {}
    i = 0
    while i + 4 <= len(data):
        ttype = int.from_bytes(data[i:i + 2], "big")
        tlen = int.from_bytes(data[i + 2:i + 4], "big")
        tags[ttype] = data[i + 4:i + 4 + tlen]
        i += 4 + tlen
    return tags


# Interface names the functional suite and the hardening probe create on the
# client VM.  The VM's rc.conf DHCPs any interface it has no ifconfig_<if>
# for (inferred, not read: every new pppoe0 gets a dhclient -- the serial
# log's "dhclient: pppoe0: not found" -- and ACCEPT_RTADV, which is what the
# stock VM image's ifconfig_DEFAULT="DHCP inet6 accept_rtadv" does), and
# devd(8)'s IFNET ATTACH rule runs
# `/etc/pccard_ether <if> start` for every interface that appears -- which
# via rc.d/netif does `ifconfig <if> up` and starts dhclient on it -- and its
# DETACH rule runs `pccard_ether <if> stop`, i.e. more ifconfig(8) calls.
# All of that is asynchronous and lands whenever devd gets to it:
#   - a fresh pppoe0 clone was brought UP behind the test's forced down(),
#     dialled a session, and the test then read state=3 (SESSION) before its
#     own `ifconfig up`, saw the negotiated 1492 overwrite the MTU it had
#     just set, or saw a late `up` redial after its own `down` (the SMPW
#     baseline's four test_datapath failures; the serial log shows a
#     dhclient started on every pppoe0: "dhclient: pppoe0: not found");
#   - an ifconfig(8) run for a pppoe0 that the kldunload had just destroyed
#     autoloads if_pppoe from the module path (ifconfig's ifmaybeload()),
#     so the module was resident again right after a successful kldunload
#     (the hardening probe's 2/90 and test_pap_live's "already loaded").
# The NOAUTO keyword makes pccard_ether's checkauto() exit before any of it
# (network.subr autoif()).  Unit numbers are fixed wherever the suite creates
# interfaces precisely so they can be listed here ahead of time.
RC_AUTOCONF_EXEMPT = (
    "pppoe0", "pppoe1", "pppoe2", "pppoe3",
    # test_lifecycle.py: vnet-jail plumbing, the vlan-parent loop and the
    # AC-less parent of the discovery-time EBUSY check.
    "epair76a", "epair76b", "bridge76",
    "epair77a", "epair77b", "bridge77", "vlan77", "vlan78",
    "epair79a", "epair79b",
)


def exempt_from_rc_autoconf(run) -> None:
    """Mark RC_AUTOCONF_EXEMPT NOAUTO in the client VM's rc.conf (idempotent).

    `run` is an IfPppoeDriver-style run(cmd, root=...) callable."""
    args = " ".join(f"ifconfig_{name}=NOAUTO" for name in RC_AUTOCONF_EXEMPT)
    r = run(f"sysrc {args}", root=True)
    assert r.returncode == 0, f"sysrc NOAUTO failed: {r.stdout}\n{r.stderr}"


class IfPppoeDriver:
    """Low-level control surface for the in-kernel if_pppoe driver on the
    `client` VM, used by the `datapath` tests (plan 1).

    This is NOT the `client` fixture seam: `IfPppoeClient` (plan 2) wraps
    this class and adds dial/hangup/restart_link once sppp and pppoectl
    exist. Everything here goes over the same ssh hostfwd Mpd5Client uses.
    """

    port = CLIENT_SSH_PORT
    mac = CLIENT_MAC
    KO = "/tmp/if_pppoe.ko"
    PARMS = "/usr/local/sbin/pppoeparms"

    def run(self, cmd: str, root: bool = False, timeout: int = 20,
            stdin: str | None = None) -> subprocess.CompletedProcess:
        return _run_guest(self.port, cmd, root, timeout, stdin)

    def kldload(self):
        """Force a reload rather than load-if-absent: an `if_pppoe` left loaded
        from an earlier run is a stale .ko, and `kldstat || kldload` silently
        keeps it across a redeploy (it did, twice, during Task 5).

        The unload is verified before the load.  An if_pppoe that is still
        resident here was either never unloaded or was loaded again behind
        our back -- ifconfig(8) kldloads `if_<name>` from the module path for
        any interface name it does not know, which is exactly what devd's
        `pccard_ether pppoe0 stop` did on the DETACH that the unload's own
        clone destroy posts (SMPW baseline: "module already loaded or in
        kernel").  RC_AUTOCONF_EXEMPT closes that; if it ever reopens, fail
        here naming the resident file instead of testing whatever it is."""
        r = self.kldunload()
        assert self.run("kldstat -q -n if_pppoe").returncode != 0, (
            "if_pppoe still resident after kldunload "
            f"(rc={r.returncode} {r.stderr.strip()}): "
            + self.run("kldstat -v -n if_pppoe").stdout
        )
        r = self.run(f"kldload {self.KO}", root=True)
        assert r.returncode == 0, f"kldload if_pppoe failed: {r.stdout}\n{r.stderr}"

    def kldunload(self) -> subprocess.CompletedProcess:
        """Unload if loaded; the result is kldunload's (rc 0 when absent)."""
        return self.run("! kldstat -q -n if_pppoe || kldunload if_pppoe",
                        root=True)

    def create(self, iface: str = "pppoe0", parent: str = "vtnet1",
               service: str | None = None, acname: str | None = None,
               reload: bool = True):
        """Create the clone, bind it to `parent`, set the discovery parms.

        reload=False keeps the resident module (and so its M_PPPOE malloc
        type's counters) -- for tests that loop create/destroy."""
        if reload:
            self.kldload()
        self.run(f"ifconfig {iface} destroy", root=True)
        r = self.run(f"ifconfig {iface} create", root=True)
        assert r.returncode == 0, f"ifconfig {iface} create failed: {r.stdout}\n{r.stderr}"
        # Dial-start race (documented in S04, worked around by the ipv6cp
        # test): after a module (re)load the fresh clone can be born with
        # IFF_UP already set, so the caller's first `ifconfig up` sees no
        # down->up transition, sppp never opens LCP, and discovery never
        # begins (state stuck at INITIAL, no PADI).  Force the clone DOWN
        # here so every subsequent up() is a real transition (the
        # "pre-down before up" prereq the S04 live vector encodes).  The
        # "born UP" was devd's `pccard_ether pppoe0 start` (see
        # RC_AUTOCONF_EXEMPT, which now keeps devd off the clone).
        self.down(iface)
        cmd = f"{self.PARMS} -e {parent}"
        if service is not None:
            cmd += f" -s {shlex.quote(service)}"
        if acname is not None:
            cmd += f" -a {shlex.quote(acname)}"
        cmd += f" {iface}"
        r = self.run(cmd, root=True)
        assert r.returncode == 0, f"{cmd} failed: {r.stdout}\n{r.stderr}"
        # accel-ppp requires client authentication (chap-secrets fixture): a
        # no-auth client sees its LCP Auth-Protocol option rejected and gets
        # PADT'd within ~100ms of PADS, so the caller's session never reaches
        # a pollable SESSION state (the datapath/discovery tests' assumption).
        # Program the lab PAP credentials now -- the same SPPPSETAUTHCFG
        # surface pppoectl auth mode drives (R005; T1 proved the secret is
        # never echoed) -- making every create()+up() session stable, exactly
        # as the S04 live vector's mandatory spppauth step did.  The account
        # is the run's generated one; its secret goes over stdin (-S).
        cfg, secret = auth_cfg_cmd(iface=iface, proto="pap")
        r = self.run(cfg, root=True, stdin=secret)
        assert r.returncode == 0, f"{cfg} failed: {r.stdout}\n{r.stderr}"

    def destroy(self, iface: str = "pppoe0"):
        self.run(f"ifconfig {iface} destroy", root=True)

    def up(self, iface: str = "pppoe0"):
        r = self.run(f"ifconfig {iface} up", root=True)
        assert r.returncode == 0, f"ifconfig {iface} up failed: {r.stdout}\n{r.stderr}"

    def down(self, iface: str = "pppoe0"):
        self.run(f"ifconfig {iface} down", root=True)

    def parms(self, iface: str = "pppoe0") -> dict:
        """Parse `pppoeparms -d` into {key: str|int}."""
        r = self.run(f"{self.PARMS} -d {iface}")
        assert r.returncode == 0, f"pppoeparms -d failed: {r.stdout}\n{r.stderr}"
        out = {}
        for token in r.stdout.split():
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            out[k] = int(v) if v.isdigit() else v
        return out

    def wait_state(self, want: int, iface: str = "pppoe0", timeout: int = 20) -> dict:
        deadline = time.time() + timeout
        last = {}
        while time.time() < deadline:
            last = self.parms(iface)
            if last.get("state") == want:
                return last
            time.sleep(0.5)
        return last

    def sysctl(self, name: str) -> str:
        r = self.run(f"sysctl -n {name}")
        assert r.returncode == 0, f"sysctl {name} failed: {r.stdout}\n{r.stderr}"
        return r.stdout.strip()

    def counter(self, name: str) -> int:
        return int(self.sysctl(f"net.pppoe.{name}"))

    def iface_state(self, iface: str = "pppoe0") -> dict:
        r = self.run(f"ifconfig {iface}")
        out = r.stdout
        m_mtu = re.search(r"\bmtu (\d+)", out)
        m_inet = re.search(r"inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)", out)
        m_inet6 = re.search(r"inet6 (fe80::[0-9a-f:]+)", out)
        m_flags = re.search(r"flags=[0-9a-fA-F]+<([^>]*)>", out)
        flags = m_flags.group(1).split(",") if m_flags else []
        return {
            "raw": out,
            "mtu": int(m_mtu.group(1)) if m_mtu else None,
            "inet": m_inet.group(1) if m_inet else None,
            "inet_peer": m_inet.group(2) if m_inet else None,
            "inet6_ll": m_inet6.group(1) if m_inet6 else None,
            "flags": flags,
            "up": "UP" in flags,
        }


class IfPppoeClient(IfPppoeDriver):
    """The `client` fixture seam over the in-kernel if_pppoe/sppp driver
    (CLIENT=if_pppoe).

    dial/hangup/restart_link/iface_state/run implement the same surface as
    Mpd5Client, but drive the in-kernel client (S02/S03) through pppoectl(8)
    -- the verbatim NetBSD tool ported in S05 T1 (R005) -- over the SPPP*
    ioctl surface, plus `ifconfig` for the clone lifecycle:

      * create the pppoe0 clone, then `pppoectl -e vtnet1 [-s service] \
        pppoe0` (PPPOESETPARMS: parent bind + optional Service-Name), and
        `ifconfig pppoe0 mtu N` when mtu/max_payload is requested (RFC 4638
        PPP-Max-Payload offer, as test_ppp_max_payload_* do),
      * `pppoectl -S pppoe0 myauthproto=<pap|chap> [passiveauthproto] \
        myauthname=...` with the secret on stdin (SPPPSETAUTHCFG; the
        secret never goes on argv and is never echoed -- R011),
      * `pppoectl pppoe0 query-dns=3 max-noreceive=0 max-alive-missed=3 \
        alive-interval=1` (SPPPSETDNSOPTS + SPPPSETKEEPALIVE: the IPCP DNS
        options mpd5's `set ipcp enable req-pri-dns` enables, and the
        ~10s LCP echo cadence of mpd5's `set link keep-alive 10 60`),
      * `ifconfig pppoe0 up` -- SIOCSIFFLAGS opens sppp LCP, whose
        This-Layer-Up starts PPPoE discovery (pppoe_tls).

    There is no mpd5 config file and no /usr/local/etc/mpd5/mpd.conf
    rewrite; conftest's mpd.conf restore in pytest_sessionfinish only acts
    for CLIENT=mpd5.

    Command-invocation seam (S05 T2): `__init__(runner=None)` accepts an
    injectable callable replacing the real ssh executor for EVERY
    pppoectl(8)/ifconfig PPPoE-control command this client issues.  The
    overridden `run()` below is that single seam: with a runner injected
    the built command string/root/timeout go to it unchanged; with
    runner=None behaviour is byte-for-byte identical to
    IfPppoeDriver.run (root wrap + `_ssh` hostfwd call).
    """

    POCTL = "/usr/local/sbin/pppoectl"

    def __init__(self, runner=None):
        """IfPppoeClient(runner=None).

        `runner` is an injectable command-invocation callable used in
        place of the real ssh executor for every pppoectl(8)/ifconfig
        PPPoE-control command this client issues.  Contract:

            runner(cmd: str, root: bool = False, timeout: int = 20,
                   stdin: str | None = None)
                -> subprocess.CompletedProcess-like

        `cmd` is the exact command string built by dial/hangup/
        restart_link (pre-root-wrap); `root`/`timeout` are passed through
        unchanged.  `stdin` (the auth secret for `pppoectl -S`) is passed
        as a keyword only when a command has one, so a runner that never
        sees a secret-bearing command may keep the three-argument form.  Whatever the runner returns (a CompletedProcess-like
        object) -- or raises -- flows straight back to the caller, so a
        fake controls returncode/stdout and can exercise every failure
        path the real executor can hit.  runner=None keeps the pre-seam
        executor: `echo | su -m root -c '<cmd>'` for root=True, then the
        ssh hostfwd call via `_ssh`.
        """
        self._runner = runner

    def run(self, cmd: str, root: bool = False, timeout: int = 20,
            stdin: str | None = None) -> subprocess.CompletedProcess:
        """Single command-invocation seam for IfPppoeClient.

        Routes through the injected runner when one was given;
        otherwise this is byte-for-byte IfPppoeDriver.run (root-wraps the
        command and sends it over the ssh hostfwd, with `stdin` on the
        command's own stdin).  The signature matches the driver's, so
        real callers are unaffected.
        """
        if self._runner is not None:
            if stdin is None:
                return self._runner(cmd, root=root, timeout=timeout)
            return self._runner(cmd, root=root, timeout=timeout, stdin=stdin)
        return super().run(cmd, root=root, timeout=timeout, stdin=stdin)

    def _ensure_clone(self, iface: str = "pppoe0"):
        """Create the clone, loading the module first if absent.

        Unlike IfPppoeDriver.create(), this is load-if-absent rather than a
        force reload: the seam is used mid-suite by every test's restore, so
        a live session's counters/state must not be reset on each dial.
        """
        r = self.run(
            "kldstat -q -n if_pppoe || kldload /tmp/if_pppoe.ko", root=True
        )
        assert r.returncode == 0, (
            f"if_pppoe module not loadable: {r.stdout}\n{r.stderr}"
        )
        self.run(f"ifconfig {iface} destroy", root=True)  # no-op if absent
        r = self.run(f"ifconfig {iface} create", root=True)
        assert r.returncode == 0, (
            f"ifconfig {iface} create failed: {r.stdout}\n{r.stderr}"
        )
        # Dial-start race, same as IfPppoeDriver.create(): the clone can be
        # born already-UP after a module reload, silently no-op'ing the
        # first `up` in dial().  Guarantee a down->up transition for it.
        self.down(iface)

    def dial(self, service: str = "lab", user: str | None = None,
             password: str | None = None, mtu: int | None = None,
             max_payload: int | None = None,
             accept=("pap", "chap", "eap")):
        """(Re)create the pppoe0 clone and bring the in-kernel PPP session up.

        Mirrors Mpd5Client.dial's contract: `accept` selects which auth
        methods we are willing to be asked for (SPPPSETAUTHCFG myauthproto;
        several allowed -> passiveauthproto lets the server's LCP
        Auth-Protocol choice win).  EAP alone is rejected: sppp has no EAP
        (spec section 2 non-goal, if_spppsubr.c header comment).

        user/password default to the run's generated account
        (active_creds()); the password reaches pppoectl on stdin (-S).
        """
        effective_mtu = 1492 if mtu is None else mtu
        if max_payload is not None:
            effective_mtu = max(effective_mtu, max_payload)

        if accept is None:
            accept = ("pap", "chap", "eap")
        proto = None
        allowed = {"pap", "chap", "eap"}
        unknown = set(accept) - allowed
        if unknown:
            raise ValueError(f"accept={sorted(unknown)!r}: unknown auth method")
        if set(accept) == {"chap"}:
            proto = "chap"
        elif set(accept) == {"pap"}:
            proto = "pap"
        elif "eap" in accept and not (set(accept) & {"pap", "chap"}):
            raise RuntimeError(
                "if_pppoe has no EAP support (spec section 2 non-goal); "
                "accept=('eap',) is not dialable"
            )
        # More than one of pap/chap (or the full default set): advertise pap
        # and let the server's LCP Auth-Protocol choice win (passiveauthproto).

        if user is None or password is None:
            c = active_creds()
            user = c.user if user is None else user
            password = c.password if password is None else password

        self._ensure_clone()

        # Parent bind + Service-Name via pppoectl -e (PPPOESETPARMS, R005).
        # service == "" (test_empty_service_name_accepted) emits no
        # Service-Name tag, which accel-ppp's accept-blank-service=1 accepts.
        bind = f"{self.POCTL} -e vtnet1"
        if service:
            bind += " -s " + shlex.quote(service)
        bind += " pppoe0"
        r = self.run(bind, root=True)
        assert r.returncode == 0, f"{bind} failed: {r.stdout}\n{r.stderr}"

        if effective_mtu != 1492:
            r = self.run(f"ifconfig pppoe0 mtu {effective_mtu}", root=True)
            assert r.returncode == 0, (
                f"ifconfig pppoe0 mtu {effective_mtu} failed: "
                f"{r.stdout}\n{r.stderr}"
            )

        # SPPPSETAUTHCFG + SPPPSETDNSOPTS + SPPPSETKEEPALIVE in one
        # pppoectl call.  The secret is NOT in the command string: -S reads
        # it verbatim from stdin, so it never reaches argv or any log.
        extra = "passiveauthproto " if proto is None else ""
        extra += "query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1"
        cfg, secret = auth_cfg_cmd(proto=proto or "pap", extra=extra,
                                   creds=LabCreds(user, password),
                                   poctl=self.POCTL)
        r = self.run(cfg, root=True, stdin=secret)
        assert r.returncode == 0, (
            f"pppoectl auth/dns/keepalive config failed: {r.stdout}\n{r.stderr}"
        )

        self.up("pppoe0")
        # NOTE: dial() deliberately ends here.  A dial-start stall watchdog
        # (the S04 born-UP race can leave sppp's LCP unopened with the FSM
        # pinned at PPPOE_STATE_INITIAL) lives in conftest's
        # _wait_iface_up instead: adding any post-up() command here would
        # change the command sequence the S05 T2 runner-seam contract pins
        # byte-for-byte in test_client_seam.py's EXPECTED_DIAL_RAW.

    def hangup(self):
        """Stop the in-kernel client: destroy the pppoe0 clone (sends PADT if
        a session is up).  The `driver` fixture needs the name free for its
        own `ifconfig pppoe0 create`."""
        self.run("ifconfig pppoe0 destroy", root=True)

    def restart_link(self):
        """Restart the PPP session (down/up re-enters SIOCSIFFLAGS, which
        restarts LCP and PPPoE discovery) without touching the clone or its
        pppoectl-programmed parms/auth/dns/keepalive settings.

        Waits for the FSM to actually settle at PPPOE_STATE_INITIAL after
        `down` instead of a blind sleep(1): `up` right on top of a
        still-tearing-down FSM is exactly the born-UP-style race this
        method exists to recover from (see conftest's dial-stall
        watchdog), so re-entering SIOCSIFFLAGS needs the down to have
        actually landed first.
        """
        self.down("pppoe0")
        self.wait_state(PPPOE_STATE_INITIAL, iface="pppoe0", timeout=5)
        self.up("pppoe0")


# PPPoE discovery FSM states, mirroring sys/net/if_pppoe.h.
PPPOE_STATE_INITIAL = 0
PPPOE_STATE_PADI_SENT = 1
PPPOE_STATE_PADR_SENT = 2
PPPOE_STATE_SESSION = 3
PPPOE_STATE_CLOSING = 4
