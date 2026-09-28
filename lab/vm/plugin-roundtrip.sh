#!/usr/bin/env bash
# shellcheck disable=SC2016  # the remote scripts below are single-quoted on purpose
# plugin-roundtrip.sh [pytest args...] -- the one entry point for tests/plugin's
# live round trip on `dut` (design: lab/vm/README.md "dut (plugin-test DUT)").
# Invariant: no secret is persisted or put on argv. dut boots from a per-run
# qcow2 overlay on $VMHOST tmpfs, so images/dut.qcow2 is only ever read.
# Optional DUT_KERNEL_SET / IFPPPOE_REPO_TARBALL: see README.md "dut".
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
# shellcheck source=lab-creds.sh
source ./lab-creds.sh   # _lab_creds_sq, LAB_CREDS_ACCEL_DIR

for t in openssl ssh-keygen python3 shred; do
    command -v "$t" >/dev/null || { echo "plugin-roundtrip.sh: need $t" >&2; exit 2; }
done

vm_config dut
# vm_ssh re-runs vm_config for its target, so keep dut's values apart.
DUT_VM_NAME="$VM_NAME"
DUT_PIDFILE="\$HOME/$LAB_DIR/$VM_RUN_DIR/$VM_NAME.pid"
DUT_BASE="\$HOME/$LAB_DIR/images/$VM_BASE_IMAGE"
DUT_LAN_IP="192.168.90.2"   # dut-config.xml.tmpl's <lan><ipaddr> -- keep in sync
DUT_REPO_HOST_IP="192.168.90.1"   # run.sh's VM_BRIDGE2_HOST_IP for dut -- keep in sync
IFPPPOE_REPO_PORT="${IFPPPOE_REPO_PORT:-8090}"
# $VMHOST tmpfs dirs holding a run's overlay / kernel set / served repo: <prefix>.XXXXXX
R_OVL_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-run"
R_KSET_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-kset"
R_REPO_PREFIX="/dev/shm/${LAB_DIR//\//_}-dut-repo"
ISP_VM=isp1   # slot 1's isp, explicitly (see header)
# The lab isp has no upstream (no DNS/internet) and never opens IPv6CP
# (tests/functional/test_ipv6cp.py): step 4 pings its PPPoE peer instead,
# accel-ppp.conf's [ip-pool] gw-ip-address, and skips the v6 ping.
LAB_ISP_PPP_GW="10.99.0.1"

# Refuse up front if dut is up: teardown's `run.sh dut down` must only stop
# a dut this run booted, and a running dut may still hold an old overlay.
if host_ssh "test -f \"$DUT_PIDFILE\" && sudo kill -0 \"\$(sudo cat \"$DUT_PIDFILE\")\"" 2>/dev/null; then
    echo "plugin-roundtrip.sh: dut is already running -- run './run.sh dut down' first." >&2
    exit 1
fi

RUNDIR="$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/if_pppoe-dut.XXXXXX")"
chmod 700 "$RUNDIR"
R_OVL_DIR=""
ACCOUNT_ADDED=0
PROVISIONED=0
DUT_PPPOE_USERNAME=""
R_KSET_DIR=""     # DUT_KERNEL_SET's tmpfs dir on $VMHOST (install_dut_kernel_set)
R_REPO_DIR=""     # IFPPPOE_REPO_TARBALL's tmpfs dir on $VMHOST (start_ifpppoe_repo)
REPO_SERVER_STARTED=0
PYTEST_RAN=0
API_TUNNEL_PID=""   # local ssh -L to dut's web GUI/API (open_api_tunnel)

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

dut_account_add() {
    printf '%s * %s *\n' "$DUT_PPPOE_USERNAME" "$DUT_PPPOE_PASSWORD" |
        vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_DUT_ACCEL_ADD") sh /etc/accel-ppp.conf $DUT_PPPOE_USERNAME"
}

# shellcheck disable=SC2329  # called from teardown (a trap)
dut_account_del() {
    vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_DUT_ACCEL_DEL") sh $DUT_PPPOE_USERNAME" </dev/null
}

# Fetch/copy DUT_KERNEL_SET to $VMHOST tmpfs, install it on dut like
# opnsense-update -k's install_kernel(), reboot, assert kern.build_id.
# See README.md "dut" for the sources this mirrors.
# dut_ssh <cmd>: root@dut over br-dut-lan via $VMHOST, the run's ephemeral key.
dut_ssh() {
    ssh -J "$VMHOST" -i "$RUNDIR/id_ed25519" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=5 -o BatchMode=yes "root@$DUT_LAN_IP" "$@"
}

install_dut_kernel_set() {
    R_KSET_DIR="$(host_ssh bash -s <<EOF
set -euo pipefail
[ "\$(stat -f -c %T /dev/shm)" = tmpfs ] || { echo "/dev/shm on $VMHOST is not tmpfs" >&2; exit 1; }
rm -rf "$R_KSET_PREFIX".*
d="\$(mktemp -d "$R_KSET_PREFIX.XXXXXX")"
chmod 700 "\$d"
echo "\$d"
EOF
)"
    case "$R_KSET_DIR" in
        "$R_KSET_PREFIX".*) ;;
        *) echo "plugin-roundtrip.sh: unexpected kset dir '$R_KSET_DIR'" >&2; R_KSET_DIR=""; exit 1 ;;
    esac

    echo "== fetching DUT_KERNEL_SET ($DUT_KERNEL_SET) onto $VMHOST =="
    case "$DUT_KERNEL_SET" in
        http://*|https://*)
            host_ssh "curl -fSL --connect-timeout 10 -o '$R_KSET_DIR/kernel.txz' '$DUT_KERNEL_SET'"
            ;;
        *)
            [ -f "$DUT_KERNEL_SET" ] || { echo "plugin-roundtrip.sh: DUT_KERNEL_SET '$DUT_KERNEL_SET' not found" >&2; exit 1; }
            scp -o ConnectTimeout=8 "$DUT_KERNEL_SET" "$VMHOST:$R_KSET_DIR/kernel.txz"
            ;;
    esac

    KSET_SHA256="$(host_ssh "sha256sum '$R_KSET_DIR/kernel.txz'" | awk '{print $1}')"
    echo "DUT_KERNEL_SET sha256: $KSET_SHA256"
    case "$DUT_KERNEL_SET" in
        http://*|https://*)
            # Sets are .sig-signed (RSA, opnsense-verify), not sha256-summed;
            # honor a "<set>.sha256" if one exists anyway, else log-only.
            if host_ssh "curl -fsSL --connect-timeout 8 -o '$R_KSET_DIR/kernel.txz.sha256' '$DUT_KERNEL_SET.sha256'" 2>/dev/null; then
                WANT_SHA256="$(host_ssh "awk '{print \$1}' '$R_KSET_DIR/kernel.txz.sha256'")"
                [ "$WANT_SHA256" = "$KSET_SHA256" ] \
                    || { echo "plugin-roundtrip.sh: sha256 mismatch for DUT_KERNEL_SET: want $WANT_SHA256 got $KSET_SHA256" >&2; exit 1; }
                echo "sha256 verified against ${DUT_KERNEL_SET}.sha256"
            else
                echo "no published sha256 next to $DUT_KERNEL_SET; sha256 above is log-only"
            fi
            ;;
    esac

    if [ -n "${DUT_EXPECT_BUILD_ID:-}" ]; then
        EXPECT_BUILD_ID="$DUT_EXPECT_BUILD_ID"
    else
        # `|| true` throughout: grep/readelf/file finding nothing is not
        # fatal here by itself -- the explicit checks below give the actual
        # error (pipefail would otherwise abort via set -e before they run).
        KERNEL_MEMBER="$(host_ssh "tar -tf '$R_KSET_DIR/kernel.txz'" | grep -E '(^|/)boot/kernel/kernel$' | head -n1)" || true
        [ -n "$KERNEL_MEMBER" ] || { echo "plugin-roundtrip.sh: no boot/kernel/kernel member in DUT_KERNEL_SET" >&2; exit 1; }
        host_ssh "tar -xf '$R_KSET_DIR/kernel.txz' -O '$KERNEL_MEMBER' > '$R_KSET_DIR/kernel-bin'"
        # readelf -n's "Build ID: <hex>" line, falling back to file(1)'s
        # "BuildID[sha1]=<hex>" if readelf isn't installed on $VMHOST.
        EXPECT_BUILD_ID="$(host_ssh "readelf -n '$R_KSET_DIR/kernel-bin' 2>/dev/null" | sed -n 's/^ *Build ID: *//p' | head -n1)" || true
        if [ -z "$EXPECT_BUILD_ID" ]; then
            EXPECT_BUILD_ID="$(host_ssh "file -b '$R_KSET_DIR/kernel-bin' 2>/dev/null" | grep -oE 'BuildID\[[a-z0-9]+\]=[0-9a-f]+' | sed -E 's/.*=//')" || true
        fi
        host_ssh "rm -f '$R_KSET_DIR/kernel-bin'"
        [ -n "$EXPECT_BUILD_ID" ] \
            || { echo "plugin-roundtrip.sh: could not read a build id via readelf -n or file(1) from DUT_KERNEL_SET's kernel binary; pass DUT_EXPECT_BUILD_ID=<hex> instead" >&2; exit 1; }
    fi
    echo "expected kern.build_id: $EXPECT_BUILD_ID"

    # The ephemeral key is copied to $VMHOST tmpfs only transiently, to scp
    # the set the same way the script already reaches dut (root@$DUT_LAN_IP,
    # key auth only) but from $VMHOST directly -- it shares br-dut-lan with
    # dut, so no -J jump is needed for this leg. Shredded right after use.
    host_ssh "umask 077 && cat > '$R_KSET_DIR/dut_key'" < "$RUNDIR/id_ed25519"
    host_ssh "chmod 600 '$R_KSET_DIR/dut_key'"
    KSET_SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -o BatchMode=yes -i '$R_KSET_DIR/dut_key' -o IdentitiesOnly=yes root@$DUT_LAN_IP"

    echo "== copying kernel.txz to dut =="
    host_ssh "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -i '$R_KSET_DIR/dut_key' -o IdentitiesOnly=yes '$R_KSET_DIR/kernel.txz' root@$DUT_LAN_IP:/tmp/kernel.txz"

    # Root's login shell is opnsense-shell, which hands `-c <cmd>` to
    # /bin/csh: send the install as a /bin/sh script on stdin, not as a
    # remote command string (csh can't parse it and installed nothing).
    echo "== installing the kernel set on dut (opnsense-update -k's install_kernel(), minimal mirror) =="
    host_ssh "$KSET_SSH /bin/sh -s" <<'EOF'
set -e
KERNELDIR=/boot/kernel
DEBUGDIR=/usr/lib/debug$KERNELDIR
for DIR in $KERNELDIR $DEBUGDIR; do
    if [ -d "$DIR.old" ]; then rm -r "$DIR.old"; fi
    if [ -d "$DIR" ]; then mv "$DIR" "$DIR.old"; fi
done
tar -C / -xpf /tmp/kernel.txz --exclude="^.abi_hint"
kldxref $KERNELDIR
rm -f /tmp/kernel.txz
echo "kernel set installed"
EOF

    # A NEW kern.boottime proves the reboot happened: otherwise the wait
    # can reach the old kernel's sshd before shutdown takes it down.
    BOOT_BEFORE="$(dut_ssh "sysctl -n kern.boottime")"

    echo "== rebooting dut into the new kernel set =="
    host_ssh "$KSET_SSH 'shutdown -r now'" || true
    host_ssh "shred -u '$R_KSET_DIR/dut_key' 2>/dev/null || rm -f '$R_KSET_DIR/dut_key'"

    echo "== waiting for sshd after the kernel-set reboot =="
    tries=0
    until boot_now="$(dut_ssh "sysctl -n kern.boottime" 2>/dev/null)" \
            && [ -n "$boot_now" ] && [ "$boot_now" != "$BOOT_BEFORE" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 90 ]; then
            echo "plugin-roundtrip.sh: timed out waiting for a new kern.boottime after the DUT_KERNEL_SET reboot" >&2
            exit 1
        fi
        sleep 2
    done

    GOT_BUILD_ID="$(dut_ssh "sysctl -n kern.build_id")"
    if [ "$GOT_BUILD_ID" != "$EXPECT_BUILD_ID" ]; then
        echo "plugin-roundtrip.sh: kern.build_id mismatch after installing DUT_KERNEL_SET: want $EXPECT_BUILD_ID got $GOT_BUILD_ID" >&2
        exit 1
    fi
    echo "kern.build_id confirmed: $GOT_BUILD_ID"
}

# Untar IFPPPOE_REPO_TARBALL (flat: ./meta.conf, ./packagesite.pkg, ./*.pkg)
# on $VMHOST tmpfs and serve it to dut over br-dut-lan for the run's
# lifetime. Flat matches repo_conf()'s url verbatim -- see README.md "dut".
start_ifpppoe_repo() {
    [ -f "$IFPPPOE_REPO_TARBALL" ] || { echo "plugin-roundtrip.sh: IFPPPOE_REPO_TARBALL '$IFPPPOE_REPO_TARBALL' not found" >&2; exit 1; }

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
        *) echo "plugin-roundtrip.sh: unexpected repo dir '$R_REPO_DIR'" >&2; R_REPO_DIR=""; exit 1 ;;
    esac

    echo "== copying IFPPPOE_REPO_TARBALL to $VMHOST =="
    scp -o ConnectTimeout=8 "$IFPPPOE_REPO_TARBALL" "$VMHOST:$R_REPO_DIR/repo.tar.gz"
    host_ssh "tar -C '$R_REPO_DIR/www' -xzf '$R_REPO_DIR/repo.tar.gz'"
    host_ssh "test -f '$R_REPO_DIR/www/meta.conf' && test -f '$R_REPO_DIR/www/packagesite.pkg'" \
        || { echo "plugin-roundtrip.sh: IFPPPOE_REPO_TARBALL is missing meta.conf/packagesite.pkg at its root" >&2; exit 1; }

    echo "== serving the repo on $DUT_REPO_HOST_IP:$IFPPPOE_REPO_PORT (br-dut-lan) =="
    # One simple backgrounded command, not `cd x && setsid ...`: with &&,
    # $! is bash's wrapper subshell, not the server (tested both forms) --
    # --directory avoids needing the cd; fds redirected so ssh can return.
    host_ssh "setsid python3 -m http.server --directory '$R_REPO_DIR/www' --bind $DUT_REPO_HOST_IP $IFPPPOE_REPO_PORT </dev/null >'$R_REPO_DIR/http.log' 2>&1 & echo \$! > '$R_REPO_DIR/http.pid'"
    REPO_SERVER_STARTED=1
    sleep 1
    host_ssh "kill -0 \"\$(cat '$R_REPO_DIR/http.pid')\"" \
        || { echo "plugin-roundtrip.sh: repo http.server did not stay up; log:" >&2; host_ssh "cat '$R_REPO_DIR/http.log'" >&2; exit 1; }

    export IFPPPOE_REPO_URL="http://$DUT_REPO_HOST_IP:$IFPPPOE_REPO_PORT"
    echo "IFPPPOE_REPO_URL=$IFPPPOE_REPO_URL"

    # dut's WAN is the offline lab isp (no DNS, no internet), so the stock
    # OPNsense mirror can't update, and pkg install aborts when any enabled
    # repo fails its auto-update (freebsd/pkg src/install.c pkgcli_update).
    # Disable it with an override file that sorts after OPNsense.conf.
    echo "== disabling the unreachable OPNsense pkg mirror on dut (offline lab WAN) =="
    dut_ssh /bin/sh -s <<'EOF'
set -e
mkdir -p /usr/local/etc/pkg/repos
echo 'OPNsense: { enabled: no }' > /usr/local/etc/pkg/repos/zz-lab-offline.conf
EOF
}

# shellcheck disable=SC2329  # invoked via trap
teardown() {
    local rc=$?
    set +e
    # Nothing may interrupt the cleanup (a second Ctrl-C is common while
    # the VM shuts down): ignore INT/TERM from here on.
    trap '' INT TERM
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ -s "$RUNDIR/dut-console.log" ]; then
        echo "== last console lines ($RUNDIR/dut-console.log, removed now) ==" >&2
        tail -n 40 "$RUNDIR/dut-console.log" >&2
    fi
    if [ -n "$API_TUNNEL_PID" ]; then
        kill "$API_TUNNEL_PID" 2>/dev/null
    fi
    # A failed pytest leaves dut up until the shutdown below: capture the
    # plugin-side state first (no secrets: packages, repos, firmware log).
    if [ "$rc" -ne 0 ] && [ "$PYTEST_RAN" = 1 ]; then
        echo "== dut-side state after the failed run ==" >&2
        dut_ssh /bin/sh -s >&2 <<'EOF' || true
echo "-- pkg info (pppoe)"; pkg info -x pppoe
echo "-- pkg repos"; pkg -vv 2>/dev/null | sed -n '/^Repositories:/,$p'
echo "-- /tmp/pkg_upgrade.progress (tail)"; tail -n 40 /tmp/pkg_upgrade.progress 2>/dev/null
echo "-- IfPppoe MVC controllers"; ls -R /usr/local/opnsense/mvc/app/controllers/OPNsense/IfPppoe 2>&1
echo "-- engine status"; /usr/local/opnsense/scripts/if_pppoe/engine status --json 2>&1
echo "-- WAN"; kldstat | grep -i pppoe; ifconfig pppoe0 2>&1; netstat -rn -f inet | grep default
echo "-- routes (inet)"; netstat -rn -f inet
echo "-- route get 10.99.0.1"; route -n get 10.99.0.1 2>&1
echo "-- ping the PPPoE peer"; ping -c2 -t5 10.99.0.1 2>&1
echo "-- pf rules naming pppoe0"; pfctl -sr 2>/dev/null | grep pppoe0
EOF
    fi
    # Credentials first, the slow VM shutdown last.
    if [ "$ACCOUNT_ADDED" = 1 ]; then
        dut_account_del \
            || echo "plugin-roundtrip.sh: WARNING: removing accel-ppp account $DUT_PPPOE_USERNAME from $ISP_VM failed; its line is in $ISP_VM:$LAB_CREDS_ACCEL_DIR/chap-secrets (tmpfs)" >&2
    fi
    if [ "$PROVISIONED" = 1 ]; then
        ./provision-dut.sh --scrub-seed >/dev/null
    fi
    find "$RUNDIR" -type f -exec shred -u {} + 2>/dev/null
    rm -rf "$RUNDIR"
    unset DUT_API_KEY DUT_API_SECRET DUT_PPPOE_PASSWORD
    if [ "$REPO_SERVER_STARTED" = 1 ]; then
        host_ssh "test -f '$R_REPO_DIR/http.pid' && kill \"\$(cat '$R_REPO_DIR/http.pid')\" 2>/dev/null" \
            || echo "plugin-roundtrip.sh: WARNING: could not stop the IFPPPOE_REPO_TARBALL http.server on $VMHOST" >&2
    fi
    if [ -n "$R_REPO_DIR" ]; then
        host_ssh "rm -rf '$R_REPO_DIR'" \
            || echo "plugin-roundtrip.sh: WARNING: could not remove $VMHOST:$R_REPO_DIR (tmpfs)" >&2
    fi
    if [ -n "$R_KSET_DIR" ]; then
        # dut_key (if the DUT_KERNEL_SET install left it behind) is the only
        # secret here -- kernel.txz itself is not.
        host_ssh "shred -u '$R_KSET_DIR/dut_key' 2>/dev/null; rm -rf '$R_KSET_DIR'" \
            || echo "plugin-roundtrip.sh: WARNING: could not remove $VMHOST:$R_KSET_DIR (tmpfs)" >&2
    fi
    if [ "$PROVISIONED" = 1 ]; then
        ./run.sh dut down
    fi
    if [ -n "$R_OVL_DIR" ]; then
        # If qemu somehow survived `down`, unlinking still works: the data
        # lives only in tmpfs pages, freed when that process exits.
        host_ssh "if test -f \"$DUT_PIDFILE\" && sudo kill -0 \"\$(sudo cat \"$DUT_PIDFILE\")\" 2>/dev/null; then echo 'plugin-roundtrip.sh: WARNING: dut still running; its overlay is unlinked but held in RAM until qemu exits' >&2; fi; rm -rf '$R_OVL_DIR'" \
            || echo "plugin-roundtrip.sh: WARNING: could not remove $VMHOST:$R_OVL_DIR (tmpfs)" >&2
    fi
    exit "$rc"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$(stat -f -c %T "$RUNDIR")" != "tmpfs" ]; then
    echo "plugin-roundtrip.sh: $RUNDIR is not tmpfs; refusing to put run credentials on disk" >&2
    exit 2
fi

# -- generate this run's credentials (command substitution / builtins only:
# nothing secret appears on any argv) --------------------------------------
ssh-keygen -q -t ed25519 -N '' -C "if_pppoe-dut-ephemeral" -f "$RUNDIR/id_ed25519"
DUT_API_KEY="$(openssl rand -base64 60 | tr -d '\n')"
DUT_API_SECRET="$(openssl rand -base64 60 | tr -d '\n')"
DUT_PPPOE_USERNAME="dutrun-$(openssl rand -hex 4)"   # not secret; hex-safe for grep ^user
DUT_PPPOE_PASSWORD="$(openssl rand -hex 24)"   # hex: no whitespace/quoting issues in chap-secrets
case "$DUT_PPPOE_USERNAME" in
    dutrun-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) echo "plugin-roundtrip.sh: bad generated username" >&2; exit 2 ;;
esac

# -- this run's throwaway overlay of the never-provisioned base, on tmpfs.
# Overlays left by a run that was SIGKILLed are removed first (dut is known
# stopped, so none is in use).
R_OVL_DIR="$(host_ssh bash -s <<EOF
set -euo pipefail
[ "\$(stat -f -c %T /dev/shm)" = tmpfs ] || { echo "/dev/shm on $VMHOST is not tmpfs" >&2; exit 1; }
[ -f "$DUT_BASE" ] || { echo "$DUT_BASE missing (./fetch-image.sh dut)" >&2; exit 1; }
rm -rf "$R_OVL_PREFIX".*
d="\$(mktemp -d "$R_OVL_PREFIX.XXXXXX")"
chmod 700 "\$d"
qemu-img create -q -f qcow2 -F qcow2 -b "$DUT_BASE" "\$d/$DUT_VM_NAME-run.qcow2"
echo "\$d"
EOF
)"
case "$R_OVL_DIR" in
    "$R_OVL_PREFIX".*) ;;
    *) echo "plugin-roundtrip.sh: unexpected overlay dir '$R_OVL_DIR'" >&2; R_OVL_DIR=""; exit 1 ;;
esac

ACCOUNT_ADDED=1   # before `add`: a half-done add is still removed at exit
dut_account_add

PROVISIONED=1
LAB_RUN_DRIVE="$R_OVL_DIR/$DUT_VM_NAME-run.qcow2" \
DUT_SSH_KEY="$RUNDIR/id_ed25519" DUT_CONSOLE_LOG="$RUNDIR/dut-console.log" \
DUT_API_KEY="$DUT_API_KEY" DUT_API_SECRET="$DUT_API_SECRET" \
DUT_PPPOE_PASSWORD="$DUT_PPPOE_PASSWORD" DUT_PPPOE_USERNAME="$DUT_PPPOE_USERNAME" \
    ./provision-dut.sh

if [ -n "${DUT_KERNEL_SET:-}" ]; then
    install_dut_kernel_set
fi
if [ -n "${IFPPPOE_REPO_TARBALL:-}" ]; then
    start_ifpppoe_repo
fi

# sshd comes up before mpd5 has dialed: wait for the WAN the test's
# baseline asserts, so a slow dial isn't reported as a plugin failure.
echo "== waiting for dut's PPPoE WAN (default route via pppoe0) =="
tries=0
until dut_ssh "netstat -rn | grep -q '^default.*pppoe0'" 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then
        echo "plugin-roundtrip.sh: no default route via pppoe0 after ${tries}x3s; dut-side state:" >&2
        dut_ssh "ifconfig pppoe0; netstat -rn -f inet; tail -n 30 /var/log/ppps/latest.log" >&2 || true
        exit 1
    fi
    sleep 3
done
echo "WAN up: default route via pppoe0"
# Informational baseline for step 4's peer ping, on stock mpd5.
echo "-- baseline (mpd5): ping the PPPoE peer $LAB_ISP_PPP_GW"
dut_ssh "ping -c2 -t5 $LAB_ISP_PPP_GW; route -n get $LAB_ISP_PPP_GW" || true

# dut's API is on br-dut-lan, which only $VMHOST routes to (ssh gets there
# with -J). Forward a local port through $VMHOST for the API client.
if [ -z "${IFPPPOE_DUT_API_HOST:-}" ]; then
    API_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
    ssh -N -o ExitOnForwardFailure=yes -o ConnectTimeout=8 -o ServerAliveInterval=15 \
        -L "127.0.0.1:$API_PORT:$DUT_LAN_IP:443" "$VMHOST" </dev/null &
    API_TUNNEL_PID=$!
    tries=0
    until python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', $API_PORT), 2)" 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 15 ] || ! kill -0 "$API_TUNNEL_PID" 2>/dev/null; then
            echo "plugin-roundtrip.sh: API tunnel 127.0.0.1:$API_PORT -> $DUT_LAN_IP:443 via $VMHOST did not come up" >&2
            exit 1
        fi
        sleep 1
    done
    export IFPPPOE_DUT_API_HOST="127.0.0.1:$API_PORT"
    echo "API via tunnel: https://$IFPPPOE_DUT_API_HOST -> $DUT_LAN_IP:443"
fi

REPO_ROOT="$(cd ../.. && pwd)"
# Only the plugins tests/plugin uses (requirements.txt): an operator's
# globally installed ones can break the live run (pytest-homeassistant-
# custom-component turns pytest-socket on and blocks the API client).
PYTEST_PLUGINS_ARGS=()
if python3 -c 'import pytest_timeout' 2>/dev/null; then PYTEST_PLUGINS_ARGS=(-p pytest_timeout); fi
rc=0
PYTEST_RAN=1
(
    cd "$REPO_ROOT"
    export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
    IFPPPOE_DUT_HOST="${IFPPPOE_DUT_HOST:-$DUT_LAN_IP}" \
    IFPPPOE_DUT_SSH_JUMP="${IFPPPOE_DUT_SSH_JUMP:-$VMHOST}" \
    IFPPPOE_DUT_SSH_KEY="$RUNDIR/id_ed25519" \
    IFPPPOE_DUT_PING4="${IFPPPOE_DUT_PING4-$LAB_ISP_PPP_GW}" \
    IFPPPOE_DUT_PING6="${IFPPPOE_DUT_PING6-}" \
    IFPPPOE_DUT_API_KEY="$DUT_API_KEY" IFPPPOE_DUT_API_SECRET="$DUT_API_SECRET" \
        python3 -m pytest "${PYTEST_PLUGINS_ARGS[@]}" tests/plugin "$@"
) || rc=$?
exit "$rc"
