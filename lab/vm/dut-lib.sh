#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # single-quoted remote scripts; DUT_*/R_* are for the sourcing scripts
# dut-lib.sh -- `dut` run machinery shared by plugin-roundtrip.sh and plugin-upgrade.sh
# (README.md "dut"); source after common.sh + lab-creds.sh. The caller owns RUNDIR, the
# creds, R_*_DIR state and teardown. Invariant: no secret on argv or outside tmpfs.

DUT_ME="${0##*/}"

vm_config dut
# vm_ssh re-runs vm_config for its target, so keep dut's values apart.
DUT_VM_NAME="$VM_NAME"
DUT_PIDFILE="\$HOME/$LAB_DIR/$VM_RUN_DIR/$VM_NAME.pid"
DUT_BASE="\$HOME/$LAB_DIR/images/$VM_BASE_IMAGE"
DUT_SOCK_PATH="$LAB_DIR/$VM_RUN_DIR/$VM_CONSOLE_SOCK"   # relative to $VMHOST's $HOME
DUT_LAN_IP="192.168.90.2"   # dut-config.xml.tmpl's <lan><ipaddr> -- keep in sync
DUT_REPO_HOST_IP="192.168.90.1"   # run.sh's VM_BRIDGE2_HOST_IP for dut -- keep in sync
IFPPPOE_REPO_PORT="${IFPPPOE_REPO_PORT:-8090}"
# $VMHOST tmpfs dirs holding a run's overlay / kernel set / served repo: <prefix>.XXXXXX
R_OVL_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-run"
R_KSET_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-kset"
R_REPO_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-repo"
ISP_VM=isp1   # slot 1's isp, explicitly: dut is not slotted
# The lab isp has no upstream (no DNS/internet) and never opens IPv6CP
# (tests/functional/test_ipv6cp.py): connectivity checks ping its PPPoE peer,
# accel-ppp.conf's [ip-pool] gw-ip-address, and skip the v6 ping.
LAB_ISP_PPP_GW="10.99.0.1"

# Exact-user accel-ppp add/del. `dutrun-` is not lab-creds.sh's `labrun-`
# prefix, so neither side's rewrite can remove the other's account.
_DUT_ACCEL_ADD='set -eu
umask 077
d='"$LAB_CREDS_ACCEL_DIR"'; f=$d/chap-secrets; u=$2
IFS= read -r line
if ! grep -qx "chap-secrets=$f" "$1"; then
    echo "$1: [chap-secrets] chap-secrets= is not $f (re-run lab/vm/provision-isp.sh)" >&2
    exit 4
fi
mkdir -p "$d"; chmod 700 "$d"
exec 9>"$d/.lock"; flock 9
{ if [ -f "$f" ]; then grep -v "^$u " "$f" || true; fi
  printf "%s\n" "$line"; } > "$f.tmp"
chmod 600 "$f.tmp"; mv "$f.tmp" "$f"'

# $1: user.
_DUT_ACCEL_DEL='set -eu
d='"$LAB_CREDS_ACCEL_DIR"'; f=$d/chap-secrets; u=$1
[ -f "$f" ] || exit 0
exec 9>"$d/.lock"; flock 9
grep -v "^$u " "$f" > "$f.tmp" || true
if [ -s "$f.tmp" ]; then chmod 600 "$f.tmp"; mv "$f.tmp" "$f"; else rm -f "$f.tmp" "$f"; fi'

# dut_account_add [<ip>]: chap-secrets "user server secret ip"; <ip> pins the
# peer address (accel-pppd/extra/chap-secrets.c, 1.14.0: a dotted quad in
# the 4th field becomes the session's peer_addr), default `*` = the pool.
dut_account_add() {
    printf '%s * %s %s\n' "$DUT_PPPOE_USERNAME" "$DUT_PPPOE_PASSWORD" "${1:-*}" |
        vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_DUT_ACCEL_ADD") sh /etc/accel-ppp.conf $DUT_PPPOE_USERNAME"
}

# shellcheck disable=SC2329  # called from the callers' teardown (a trap)
dut_account_del() {
    vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_DUT_ACCEL_DEL") sh $DUT_PPPOE_USERNAME" </dev/null
}

# dut_ssh <cmd>: root@dut over br-dut-lan via $VMHOST, the run's ephemeral key.
# Root's login shell is opnsense-shell, which runs <cmd> under /bin/csh:
# send anything beyond a simple command as a script to `/bin/sh -s`.
dut_ssh() {
    ssh -J "$VMHOST" -i "$RUNDIR/id_ed25519" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=5 -o BatchMode=yes "root@$DUT_LAN_IP" "$@"
}

# dut_is_running: dut's qemu (by pidfile) is alive on $VMHOST.
dut_is_running() {
    host_ssh "test -f \"$DUT_PIDFILE\" && sudo kill -0 \"\$(sudo cat \"$DUT_PIDFILE\")\"" 2>/dev/null
}

# dut_make_overlay <backing image on $VMHOST> [<virtual size>]: sets R_OVL_DIR
# to a fresh tmpfs dir holding $DUT_VM_NAME-run.qcow2, a qcow2 overlay of the
# never-provisioned base. Overlays a SIGKILLed run left are removed first
# (dut is known stopped, so none is in use).
dut_make_overlay() {
    local base="$1" size="${2:-}"
    R_OVL_DIR="$(host_ssh bash -s <<EOF
set -euo pipefail
[ "\$(stat -f -c %T /dev/shm)" = tmpfs ] || { echo "/dev/shm on $VMHOST is not tmpfs" >&2; exit 1; }
[ -f "$base" ] || { echo "$base missing (./fetch-image.sh dut)" >&2; exit 1; }
rm -rf "$R_OVL_PREFIX".*
d="\$(mktemp -d "$R_OVL_PREFIX.XXXXXX")"
chmod 700 "\$d"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "\$d/$DUT_VM_NAME-run.qcow2" $size
echo "\$d"
EOF
)"
    case "$R_OVL_DIR" in
        "$R_OVL_PREFIX".*) ;;
        *) echo "$DUT_ME: unexpected overlay dir '$R_OVL_DIR'" >&2; R_OVL_DIR=""; exit 1 ;;
    esac
}

# dut_repo_serve <repo.tar.gz>: untar a flat repo (./meta.conf,
# ./packagesite.pkg, ./*.pkg) on $VMHOST tmpfs and serve it to dut over
# br-dut-lan for the run's lifetime; exports IFPPPOE_REPO_URL. Flat matches
# a repo .conf url used verbatim -- see README.md "dut".
dut_repo_serve() {
    local tarball="$1"
    [ -f "$tarball" ] || { echo "$DUT_ME: IFPPPOE_REPO_TARBALL '$tarball' not found" >&2; exit 1; }

    R_REPO_DIR="$(host_ssh bash -s <<EOF
set -euo pipefail
[ "\$(stat -f -c %T /dev/shm)" = tmpfs ] || { echo "/dev/shm on $VMHOST is not tmpfs" >&2; exit 1; }
rm -rf "$R_REPO_PREFIX".*
d="\$(mktemp -d "$R_REPO_PREFIX.XXXXXX")"
chmod 700 "\$d"
mkdir -m 755 "\$d/www"
echo "\$d"
EOF
)"
    case "$R_REPO_DIR" in
        "$R_REPO_PREFIX".*) ;;
        *) echo "$DUT_ME: unexpected repo dir '$R_REPO_DIR'" >&2; R_REPO_DIR=""; exit 1 ;;
    esac

    echo "== copying IFPPPOE_REPO_TARBALL to $VMHOST =="
    scp -o ConnectTimeout=8 "$tarball" "$VMHOST:$R_REPO_DIR/repo.tar.gz"
    host_ssh "tar -C '$R_REPO_DIR/www' -xzf '$R_REPO_DIR/repo.tar.gz'"
    host_ssh "test -f '$R_REPO_DIR/www/meta.conf' && test -f '$R_REPO_DIR/www/packagesite.pkg'" \
        || { echo "$DUT_ME: IFPPPOE_REPO_TARBALL is missing meta.conf/packagesite.pkg at its root" >&2; exit 1; }

    echo "== serving the repo on $DUT_REPO_HOST_IP:$IFPPPOE_REPO_PORT (br-dut-lan) =="
    # One simple backgrounded command, not `cd x && setsid ...`: with &&,
    # $! is bash's wrapper subshell, not the server (tested both forms) --
    # --directory avoids needing the cd; fds redirected so ssh can return.
    host_ssh "setsid python3 -m http.server --directory '$R_REPO_DIR/www' --bind $DUT_REPO_HOST_IP $IFPPPOE_REPO_PORT </dev/null >'$R_REPO_DIR/http.log' 2>&1 & echo \$! > '$R_REPO_DIR/http.pid'"
    REPO_SERVER_STARTED=1
    sleep 1
    host_ssh "kill -0 \"\$(cat '$R_REPO_DIR/http.pid')\"" \
        || { echo "$DUT_ME: repo http.server did not stay up; log:" >&2; host_ssh "cat '$R_REPO_DIR/http.log'" >&2; exit 1; }

    export IFPPPOE_REPO_URL="http://$DUT_REPO_HOST_IP:$IFPPPOE_REPO_PORT"
    echo "IFPPPOE_REPO_URL=$IFPPPOE_REPO_URL"
}

# shellcheck disable=SC2329  # called from the callers' teardown (a trap)
dut_repo_stop() {
    if [ "${REPO_SERVER_STARTED:-0}" = 1 ]; then
        host_ssh "test -f '$R_REPO_DIR/http.pid' && kill \"\$(cat '$R_REPO_DIR/http.pid')\" 2>/dev/null" \
            || echo "$DUT_ME: WARNING: could not stop the IFPPPOE_REPO_TARBALL http.server on $VMHOST" >&2
    fi
    if [ -n "${R_REPO_DIR:-}" ]; then
        host_ssh "rm -rf '$R_REPO_DIR'" \
            || echo "$DUT_ME: WARNING: could not remove $VMHOST:$R_REPO_DIR (tmpfs)" >&2
    fi
}

# shellcheck disable=SC2329  # called from the callers' teardown (a trap)
dut_overlay_remove() {
    [ -n "${R_OVL_DIR:-}" ] || return 0
    # If qemu somehow survived `down`, unlinking still works: the data
    # lives only in tmpfs pages, freed when that process exits.
    host_ssh "if test -f \"$DUT_PIDFILE\" && sudo kill -0 \"\$(sudo cat \"$DUT_PIDFILE\")\" 2>/dev/null; then echo '$DUT_ME: WARNING: dut still running; its overlay is unlinked but held in RAM until qemu exits' >&2; fi; rm -rf '$R_OVL_DIR'" \
        || echo "$DUT_ME: WARNING: could not remove $VMHOST:$R_OVL_DIR (tmpfs)" >&2
}
