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

# shellcheck source=dut-lib.sh
source ./dut-lib.sh   # vm_config dut, DUT_*/R_*_PREFIX/ISP_VM, dut_ssh, dut_account_*, dut_repo_*

# Refuse up front if dut is up: teardown's `run.sh dut down` must only stop
# a dut this run booted, and a running dut may still hold an old overlay.
if dut_is_running; then
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

# Fetch/copy DUT_KERNEL_SET to $VMHOST tmpfs, install it on dut like
# opnsense-update -k's install_kernel(), reboot, assert kern.build_id.
# See README.md "dut" for the sources this mirrors.
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

# Serve IFPPPOE_REPO_TARBALL to dut (dut_repo_serve) and disable the
# OPNsense mirror the offline lab WAN can't reach -- see README.md "dut".
start_ifpppoe_repo() {
    dut_repo_serve "$IFPPPOE_REPO_TARBALL"

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
    dut_repo_stop
    if [ -n "$R_KSET_DIR" ]; then
        # dut_key (if the DUT_KERNEL_SET install left it behind) is the only
        # secret here -- kernel.txz itself is not.
        host_ssh "shred -u '$R_KSET_DIR/dut_key' 2>/dev/null; rm -rf '$R_KSET_DIR'" \
            || echo "plugin-roundtrip.sh: WARNING: could not remove $VMHOST:$R_KSET_DIR (tmpfs)" >&2
    fi
    if [ "$PROVISIONED" = 1 ]; then
        ./run.sh dut down
    fi
    dut_overlay_remove
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
dut_make_overlay "$DUT_BASE"

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
