"""Per-run PPPoE lab accounts: generated, installed on tmpfs, removed.

There is no fixed lab account and no secrets file in the repo.  Each run
(one pytest session, or one probe-script invocation) calls lab_session(),
which:

  1. generates a random account with `secrets` (user slot_prefix() --
     labrun-s<LAB_SLOT>- -- + 8 hex digits, a 32-character alphanumeric
     password), held only in this process's memory;
  2. installs it on the servers, always over ssh STDIN (never argv), into
     tmpfs only:
       - accel-ppp (the isp VM, or the legacy slot-1 isp netns on the lab
         host): one line in ACCEL_SECRETS (/run/accel-ppp/chap-secrets,
         dir 0700, file 0600; /run is tmpfs on Debian and on the lab host).
         lab/isp-netns/accel-ppp.conf's [chap-secrets] chap-secrets= points
         there.  No accel-cmd reload is needed: accel-ppp's chap-secrets
         module fopen()s and reads the file on every authentication
         (create_pd(), called from get_passwd()/check_passwd(), in
         https://github.com/accel-ppp/accel-ppp/blob/1.14.0/accel-pppd/extra/chap-secrets.c;
         its EV_CONFIG_RELOAD handler only re-reads the conf options).
         Other entries in that file are kept: only this run's exact user
         is replaced or removed, so another slot's or another run's
         account is never touched.
       - mpdsrv (mpd5 server): a tmpfs is mounted over MPD5_CONF_DIR, the
         on-disk mpd.conf (no secrets) is copied into it, this user's line
         is added to mpd.secret there (0600) and mpd5 restarted.
  3. on the client VM mounts the same kind of tmpfs over MPD5_CONF_DIR, so
     Mpd5Client.dial's password-bearing mpd.conf only ever lives in RAM
     (Mpd5Client.dial refuses to write it anywhere else);
  4. registers the account as lab.active_creds() -- the default user/
     password of every dial() and of IfPppoeDriver.create();
  5. at teardown (a finally: also on failure or Ctrl-C) removes exactly
     that user from accel-ppp and mpdsrv (mpdsrv's tmpfs is unmounted once
     no account is left on it), unmounts the client tmpfs (mpd5 then runs
     from its on-disk conf, which has no secrets), and forgets the account.

One pytest session or probe run = one account, installed once and removed
once.  The shell harness (lab/vm/job-common.sh, batch-suite.sh,
verify-branch.sh) generates none of its own; lab/vm/lab-creds.sh is only for
the standalone scripts (verify-lab.sh, perf-backend.sh), and follows the same
exact-user rules.

Nothing is written on the lab host outside /run, and nothing under $HOME.
"""
from __future__ import annotations

import contextlib
import secrets
import shlex
import string
import subprocess
from typing import Iterator

import lab
from lab import (
    CLIENT_SSH_PORT,
    ISP_SSH_PORT,
    LAB_SLOT,
    MPD5_CONF_DIR,
    MPDSRV_SSH_PORT,
    SSH_KEY,
    LabCreds,
    _run_guest,
    tmpfs_guard,
)

LABCREDS_USER_PREFIX = "labrun-"
ACCEL_SECRETS_DIR = "/run/accel-ppp"
ACCEL_SECRETS = f"{ACCEL_SECRETS_DIR}/chap-secrets"
# The isp VM's rendered accel-ppp.conf and the pre-tmpfs credential file
# provision-isp.sh used to install (removed on sight).
ISP_VM_ACCEL_CONF = "/etc/accel-ppp.conf"
ISP_VM_LEGACY_SECRETS = "/etc/accel-ppp/chap-secrets"
MPDSRV_ADDR = "10.99.2.100/24"  # mpd.secret's optional ip/mask column

_ALNUM = string.ascii_letters + string.digits


def slot_prefix(slot: int = LAB_SLOT) -> str:
    """User-name prefix of every account generated for lab slot `slot`
    (labrun-s<N>-).  Installs and removals match the exact user; only the
    explicit purge (lab-creds.sh teardown) matches this prefix, so no run
    ever touches another slot's -- or another run's -- account."""
    return f"{LABCREDS_USER_PREFIX}s{slot}-"


def generate() -> LabCreds:
    """A fresh random account.  Alphanumeric only, so it needs no quoting in
    chap-secrets, mpd.secret, mpd.conf or pppoectl's -S line."""
    user = slot_prefix() + secrets.token_hex(4)
    password = "".join(secrets.choice(_ALNUM) for _ in range(32))
    return LabCreds(user, password)


# Keep every line of file $f whose first field is not $u (exact user) or,
# with $mode = prefix, does not start with $u.  Shared by accel and mpdsrv.
_KEEP_OTHERS = ('awk -v u="$u" -v m="$mode" '
                '\'m == "prefix" ? index($1, u) != 1 : $1 != u\' "$f"')


# --- accel-ppp -------------------------------------------------------------
# $1: accel-ppp.conf to check points chap-secrets= at the tmpfs file ("" to
# skip); $2: stale on-disk secrets file to delete ("" to skip); $3: the exact
# user (any earlier line for it is replaced; every other line is kept).
# stdin: the one chap-secrets line ("client server secret ip", pppd format).
_ACCEL_ADD = f"""set -eu
umask 077
d={ACCEL_SECRETS_DIR}; f={ACCEL_SECRETS}; u=$3; mode=exact
IFS= read -r line
if [ -n "$1" ] && ! grep -qx "chap-secrets=$f" "$1"; then
    echo "$1: [chap-secrets] chap-secrets= is not $f (re-run lab/vm/provision-isp.sh)" >&2
    exit 4
fi
[ -z "$2" ] || rm -f "$2"
mkdir -p "$d"; chmod 700 "$d"
exec 9>"$d/.lock"; flock 9
{{ if [ -f "$f" ]; then {_KEEP_OTHERS}; fi
   printf '%s\\n' "$line"; }} > "$f.tmp"
chmod 600 "$f.tmp"; mv "$f.tmp" "$f"
"""

# $1: the user (mode exact) or user prefix (mode prefix); $2: exact|prefix.
_ACCEL_DEL = f"""set -eu
d={ACCEL_SECRETS_DIR}; f={ACCEL_SECRETS}; u=$1; mode=$2
[ -f "$f" ] || exit 0
exec 9>"$d/.lock"; flock 9
{_KEEP_OTHERS} > "$f.tmp" || true
if [ -s "$f.tmp" ]; then chmod 600 "$f.tmp"; mv "$f.tmp" "$f"; else rm -f "$f.tmp" "$f"; fi
"""


def _isp_ssh_args() -> list[str]:
    # Same transport as lab.AccelServer.CLI_VM.
    return [
        "ssh", "-p", str(ISP_SSH_PORT),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
        "-i", SSH_KEY,
        "debian@127.0.0.1",
    ]


def _accel_run(script: str, vm_args: tuple[str, ...], host_args: tuple[str, ...],
               data: str) -> None:
    """Run `script` as root on the accel host: the isp VM, falling back to
    the legacy slot-1 isp netns host (this lab host) when the VM's ssh
    transport is down -- the same order lab.AccelServer._cli uses."""
    remote = shlex.join(["sudo", "sh", "-c", script, "sh", *vm_args])
    r = subprocess.run(_isp_ssh_args() + [remote], input=data,
                       capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        return
    if r.returncode == 255 and LAB_SLOT == 1:
        r = subprocess.run(["sudo", "sh", "-c", script, "sh", *host_args], input=data,
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return
    raise RuntimeError(
        f"accel-ppp credential update failed (rc={r.returncode}): {r.stderr.strip()}")


def install_accel(creds: LabCreds) -> None:
    _accel_run(_ACCEL_ADD, (ISP_VM_ACCEL_CONF, ISP_VM_LEGACY_SECRETS, creds.user),
               ("", "", creds.user), f"{creds.user} * {creds.password} *\n")


def remove_accel(user: str, mode: str = "exact") -> None:
    _accel_run(_ACCEL_DEL, (user, mode), (user, mode), "")


# --- mpd5 (mpdsrv server, client VM) ----------------------------------------
_GUARD = tmpfs_guard(MPD5_CONF_DIR)
_D = shlex.quote(MPD5_CONF_DIR)

# Mount a tmpfs over the mpd5 conf dir, carrying the on-disk mpd.conf (no
# secrets) across.  A stale on-disk mpd.secret is deleted first.
_MPD5_MOUNT = f"""d={_D}
if ! {_GUARD}; then
    rm -f "$d/mpd.secret"
    conf=$(cat "$d/mpd.conf" 2>/dev/null || true)
    mount -t tmpfs -o mode=0700 tmpfs "$d"
    printf '%s\\n' "$conf" > "$d/mpd.conf"
    chmod 600 "$d/mpd.conf"
fi
"""

# Unmount (mpd5 stopped around it, then back to its prior state).  The
# on-disk conf underneath carries no secrets.
_MPD5_UNMOUNT_BODY = f"""if {_GUARD}; then
    running=0
    service mpd5 onestatus >/dev/null 2>&1 && running=1
    [ "$running" = 0 ] || service mpd5 onestop >/dev/null 2>&1 || true
    umount "$d" 2>/dev/null || umount -f "$d"
    [ "$running" = 0 ] || service mpd5 onestart >/dev/null 2>&1 || true
fi
rm -f "$d/mpd.secret"
"""
_MPD5_UNMOUNT = f"set -u\nd={_D}\n{_MPD5_UNMOUNT_BODY}exit 0\n"


def _mpdsrv_add(user: str) -> str:
    """stdin: the one mpd.secret line (login password ip/mask).  Replaces
    only `user`'s line; mpd5 is restarted to pick the file up."""
    return f"""set -eu
IFS= read -r line
u={shlex.quote(user)}; mode=exact
{_MPD5_MOUNT}umask 077
f="$d/mpd.secret"
{{ if [ -f "$f" ]; then {_KEEP_OTHERS}; fi
   printf '%s\\n' "$line"; }} > "$f.tmp"
mv "$f.tmp" "$f"
service mpd5 restart >/dev/null 2>&1 || service mpd5 start >/dev/null
"""


def _mpdsrv_del(user: str, mode: str = "exact") -> str:
    """Drop `user`'s mpd.secret line (or, mode prefix, every line under that
    prefix); the tmpfs is unmounted once no account is left on it."""
    return f"""set -u
u={shlex.quote(user)}; mode={shlex.quote(mode)}
d={_D}; f="$d/mpd.secret"
if {_GUARD} && [ -f "$f" ]; then
    umask 077
    {_KEEP_OTHERS} > "$f.tmp" || true
    if [ -s "$f.tmp" ]; then mv "$f.tmp" "$f"; exit 0; fi
    rm -f "$f.tmp"
fi
{_MPD5_UNMOUNT_BODY}exit 0
"""


def _guest(port: int, script: str, what: str, stdin: str | None = None) -> None:
    r = _run_guest(port, script, True, 60, stdin)
    if r.returncode != 0:
        raise RuntimeError(f"{what} failed (rc={r.returncode}): {r.stderr.strip()}")


def install_mpdsrv(creds: LabCreds) -> None:
    _guest(MPDSRV_SSH_PORT, _mpdsrv_add(creds.user), "mpdsrv mpd.secret install",
           stdin=f"{creds.user}\t{creds.password}\t{MPDSRV_ADDR}\n")


def remove_mpdsrv(user: str, mode: str = "exact") -> None:
    _guest(MPDSRV_SSH_PORT, _mpdsrv_del(user, mode), "mpdsrv account removal")


def mount_client_mpd5() -> None:
    _guest(CLIENT_SSH_PORT, "set -eu\n" + _MPD5_MOUNT, "client mpd5 tmpfs mount")


def unmount_client_mpd5() -> None:
    _guest(CLIENT_SSH_PORT, _MPD5_UNMOUNT, "client mpd5 tmpfs unmount")


@contextlib.contextmanager
def lab_session(*, mpdsrv: bool = True, client: bool = True) -> Iterator[LabCreds]:
    """Generate, install and register one run's account; undo it all on exit.

    accel-ppp is mandatory (every service-"lab" dial needs it).  mpdsrv is
    best-effort: a run without the mpdsrv VM keeps going and only its
    mpdlab dials fail.  Each undo step is queued before its install runs, so
    a half-done install is still cleaned up."""
    creds = generate()
    undo: list[tuple[str, callable]] = []
    try:
        undo.append(("accel", lambda: remove_accel(creds.user)))
        install_accel(creds)
        if mpdsrv:
            undo.append(("mpdsrv", lambda: remove_mpdsrv(creds.user)))
            try:
                install_mpdsrv(creds)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                print(f"labcreds: WARNING: mpdsrv account not installed ({exc}); "
                      "mpdlab dials will fail this run")
        if client:
            undo.append(("client", unmount_client_mpd5))
            mount_client_mpd5()
        lab.set_active_creds(creds)
        yield creds
    finally:
        lab.set_active_creds(None)
        for name, fn in reversed(undo):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 -- keep undoing the rest
                print(f"labcreds: WARNING: {name} teardown failed: {exc}")
