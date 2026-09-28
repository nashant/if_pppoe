#!/usr/bin/env bash
# shellcheck disable=SC2016  # the remote scripts below are single-quoted on purpose
# lab-creds.sh -- per-run PPPoE lab account (shell twin of
# tests/functional/labcreds.py; design, doc citations: lab/isp-netns/README.md
# "Lab accounts").  Source after common.sh; `LAB_SLOT=N ./lab-creds.sh teardown` cleans
# up after an interrupted run.  Secrets go over ssh stdin, never argv.

LAB_CREDS_USER_PREFIX=labrun-
# Every account of lab slot N is labrun-sN-<hex>: installs and removals match
# the exact user; only `teardown` (the interrupted-run cleanup) matches this
# slot prefix, so a run never touches another slot's or another run's account.
LAB_CREDS_SLOT_PREFIX="${LAB_CREDS_USER_PREFIX}s${LAB_SLOT:-1}-"
LAB_CREDS_ACCEL_DIR=/run/accel-ppp
LAB_CREDS_MPD5_DIR=/usr/local/etc/mpd5

# POSIX single-quoting for a remote command string (the FreeBSD guests'
# login shell is sh, the isp VM's is bash; both parse this).
_lab_creds_sq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

lab_creds_generate() {
    LAB_PPPOE_USER="${LAB_CREDS_SLOT_PREFIX}$(openssl rand -hex 4)"
    LAB_PPPOE_PASSWORD="$(openssl rand -hex 16)"
}

# Every line of $f except user $u's (mode exact) or except those starting
# with $u (mode prefix).  Same filter as labcreds.py's _KEEP_OTHERS.
_LAB_CREDS_KEEP_OTHERS='awk -v u="$u" -v m="$mode" '"'"'m == "prefix" ? index($1, u) != 1 : $1 != u'"'"' "$f"'

# $1: accel-ppp.conf to check, $2: stale on-disk secrets file to delete,
# $3: the exact user.  stdin: the chap-secrets line.
_LAB_CREDS_ACCEL_ADD='set -eu
umask 077
d='"$LAB_CREDS_ACCEL_DIR"'; f=$d/chap-secrets; u=$3; mode=exact
IFS= read -r line
if [ -n "$1" ] && ! grep -qx "chap-secrets=$f" "$1"; then
    echo "$1: [chap-secrets] chap-secrets= is not $f (re-run lab/vm/provision-isp.sh)" >&2
    exit 4
fi
[ -z "$2" ] || rm -f "$2"
mkdir -p "$d"; chmod 700 "$d"
exec 9>"$d/.lock"; flock 9
{ if [ -f "$f" ]; then '"$_LAB_CREDS_KEEP_OTHERS"'; fi
  printf "%s\n" "$line"; } > "$f.tmp"
chmod 600 "$f.tmp"; mv "$f.tmp" "$f"'

# $1: user (exact) or slot prefix (prefix); $2: exact|prefix.
_LAB_CREDS_ACCEL_DEL='set -eu
d='"$LAB_CREDS_ACCEL_DIR"'; f=$d/chap-secrets; u=$1; mode=$2
[ -f "$f" ] || exit 0
exec 9>"$d/.lock"; flock 9
'"$_LAB_CREDS_KEEP_OTHERS"' > "$f.tmp" || true
if [ -s "$f.tmp" ]; then chmod 600 "$f.tmp"; mv "$f.tmp" "$f"; else rm -f "$f.tmp" "$f"; fi'

_LAB_CREDS_GUARD="mount -p | awk -v d=$LAB_CREDS_MPD5_DIR '\$2 == d && \$3 == \"tmpfs\" { f = 1 } END { exit !f }'"

_LAB_CREDS_MPD5_MOUNT='d='"$LAB_CREDS_MPD5_DIR"'
if ! '"$_LAB_CREDS_GUARD"'; then
    rm -f "$d/mpd.secret"
    conf=$(cat "$d/mpd.conf" 2>/dev/null || true)
    mount -t tmpfs -o mode=0700 tmpfs "$d"
    printf "%s\n" "$conf" > "$d/mpd.conf"
    chmod 600 "$d/mpd.conf"
fi
'

# $1 (as u=): the exact user.  stdin: its mpd.secret line.
_LAB_CREDS_MPDSRV_ADD='set -eu
IFS= read -r line
'"$_LAB_CREDS_MPD5_MOUNT"'umask 077
mode=exact; f="$d/mpd.secret"
{ if [ -f "$f" ]; then '"$_LAB_CREDS_KEEP_OTHERS"'; fi
  printf "%s\n" "$line"; } > "$f.tmp"
mv "$f.tmp" "$f"
service mpd5 restart >/dev/null 2>&1 || service mpd5 start >/dev/null'

_LAB_CREDS_MPD5_UNMOUNT_BODY='if '"$_LAB_CREDS_GUARD"'; then
    running=0
    service mpd5 onestatus >/dev/null 2>&1 && running=1
    [ "$running" = 0 ] || service mpd5 onestop >/dev/null 2>&1 || true
    umount "$d" 2>/dev/null || umount -f "$d"
    [ "$running" = 0 ] || service mpd5 onestart >/dev/null 2>&1 || true
fi
rm -f "$d/mpd.secret"
exit 0'

_LAB_CREDS_MPD5_UNMOUNT='set -u
d='"$LAB_CREDS_MPD5_DIR"'
'"$_LAB_CREDS_MPD5_UNMOUNT_BODY"

# u=, mode= set by the caller: drop that account; unmount once none is left.
_LAB_CREDS_MPDSRV_DEL='set -u
d='"$LAB_CREDS_MPD5_DIR"'; f="$d/mpd.secret"
if '"$_LAB_CREDS_GUARD"' && [ -f "$f" ]; then
    umask 077
    '"$_LAB_CREDS_KEEP_OTHERS"' > "$f.tmp" || true
    if [ -s "$f.tmp" ]; then mv "$f.tmp" "$f"; exit 0; fi
    rm -f "$f.tmp"
fi
'"$_LAB_CREDS_MPD5_UNMOUNT_BODY"

# Write stdin (a password-bearing mpd.conf) into the client's tmpfs conf
# dir -- refused unless it IS the tmpfs mount.  The caller restarts mpd5.
_LAB_CREDS_CLIENT_CONF='set -eu
'"$_LAB_CREDS_GUARD"' || { echo "'"$LAB_CREDS_MPD5_DIR"' is not tmpfs: refusing to write mpd.conf" >&2; exit 3; }
umask 077
cat > '"$LAB_CREDS_MPD5_DIR"'/mpd.conf'

# FreeBSD guest as root.  stdin goes to the script as is: su(1) on the lab
# guests reads no prompt line from a non-tty stdin (a leading blank line
# would become the script's first line -- tests/functional/lab.py _run_guest).
_lab_creds_guest_root() {  # $1 vm name, $2 script; stdin passed through
    vm_ssh "$1" "su -m root -c $(_lab_creds_sq "$2")"
}

lab_creds_install_accel() {
    printf '%s * %s *\n' "$LAB_PPPOE_USER" "$LAB_PPPOE_PASSWORD" |
        vm_ssh isp "sudo sh -c $(_lab_creds_sq "$_LAB_CREDS_ACCEL_ADD") sh /etc/accel-ppp.conf /etc/accel-ppp/chap-secrets $LAB_PPPOE_USER"
}

# $1: user (default this run's), $2: exact|prefix (default exact).
lab_creds_remove_accel() {
    local u="${1:-${LAB_PPPOE_USER:-}}" mode="${2:-exact}"
    [ -n "$u" ] || return 0
    vm_ssh isp "sudo sh -c $(_lab_creds_sq "$_LAB_CREDS_ACCEL_DEL") sh $u $mode" </dev/null
}

lab_creds_install_mpdsrv() {
    printf '%s\t%s\t10.99.2.100/24\n' "$LAB_PPPOE_USER" "$LAB_PPPOE_PASSWORD" |
        _lab_creds_guest_root mpdsrv "u=$LAB_PPPOE_USER
$_LAB_CREDS_MPDSRV_ADD"
}

lab_creds_remove_mpdsrv() {
    local u="${1:-${LAB_PPPOE_USER:-}}" mode="${2:-exact}"
    [ -n "$u" ] || return 0
    _lab_creds_guest_root mpdsrv "u=$u; mode=$mode
$_LAB_CREDS_MPDSRV_DEL" </dev/null
}

lab_creds_mount_client() {
    _lab_creds_guest_root client "set -eu
$_LAB_CREDS_MPD5_MOUNT" </dev/null
}

lab_creds_unmount_client() {
    _lab_creds_guest_root client "$_LAB_CREDS_MPD5_UNMOUNT" </dev/null
}

# Unmount the client tmpfs WITHOUT stopping mpd5 (perf-backend.sh: its
# session must outlive the account).  mpd5 has parsed mpd.conf by then; if
# the mount is still busy it is left in place with a warning.
_LAB_CREDS_MPD5_UNMOUNT_LIVE='d='"$LAB_CREDS_MPD5_DIR"'
if '"$_LAB_CREDS_GUARD"'; then
    umount "$d" || { echo "lab-creds: $d busy, left mounted (lab-creds.sh teardown)" >&2; exit 1; }
fi
exit 0'

lab_creds_unmount_client_live() {
    _lab_creds_guest_root client "$_LAB_CREDS_MPD5_UNMOUNT_LIVE" </dev/null
}

lab_creds_client_mpd5_conf() {
    _lab_creds_guest_root client "$_LAB_CREDS_CLIENT_CONF"
}

# This run's account only (the scripts' EXIT trap).
lab_creds_teardown() {
    lab_creds_remove_accel || echo "lab-creds: WARNING: accel-ppp account removal failed" >&2
    lab_creds_remove_mpdsrv || echo "lab-creds: WARNING: mpdsrv account removal failed" >&2
    lab_creds_unmount_client || echo "lab-creds: WARNING: client tmpfs unmount failed" >&2
    unset LAB_PPPOE_USER LAB_PPPOE_PASSWORD
}

# Interrupted-run cleanup: every account of this LAB_SLOT (never another's).
lab_creds_purge_slot() {
    lab_creds_remove_accel "$LAB_CREDS_SLOT_PREFIX" prefix || echo "lab-creds: WARNING: accel-ppp purge failed" >&2
    lab_creds_remove_mpdsrv "$LAB_CREDS_SLOT_PREFIX" prefix || echo "lab-creds: WARNING: mpdsrv purge failed" >&2
    lab_creds_unmount_client || echo "lab-creds: WARNING: client tmpfs unmount failed" >&2
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    cd "$(dirname "${BASH_SOURCE[0]}")"
    # shellcheck source=common.sh
    source ./common.sh
    case "${1:-}" in
        teardown) lab_creds_purge_slot ;;
        *) echo "usage: LAB_SLOT=N $0 teardown   (remove slot N's accounts after an interrupted run)" >&2; exit 2 ;;
    esac
fi
