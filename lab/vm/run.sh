#!/usr/bin/env bash
# run.sh <name> <action> [args] — manage a lab VM on $VMHOST.
# VM specs live in common.sh's vm_config(); new names are new case branches
# there. <name> resolves through LAB_SLOT (client == client2 under LAB_SLOT=2).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

usage() {
    cat >&2 <<'U'
usage: run.sh <name> <action> [args]
  up | down | status | ssh [-- cmd...]
  shutdown                           like down, but never quits/kills: fails if the guest
                                     will not power off by itself (ssh, then ACPI)
  console-cmd '<text>' [wait-secs]   type <text>+CR on the serial console, print the output
  reset-clean                        reboot a wedged guest from its console (db> 'reset',
                                     or root login + 'shutdown -r now'); FORCE=1 falls back
                                     to a monitor system_reset
  monitor '<hmp command>'            send one QEMU HMP command (e.g. 'info status')
  snapshot-save                      (client VMs) clean shutdown, fold the run overlay into
                                     the base disk = new known-good, boot on a fresh overlay
  snapshot-revert                    (client VMs) monitor 'quit', discard the run overlay,
                                     recreate it from the known-good base, boot, wait for ssh
U
    exit 1
}

[ $# -ge 2 ] || usage
NAME_ARG="$1"; ACTION="$2"; shift 2 || true
if [ "${1:-}" = "--" ]; then shift; fi

vm_config "$NAME_ARG"
NAME="$VM_NAME"
# Remote-side paths (expanded on $VMHOST: keep the backslash-dollar).
R_RUN="\$HOME/$LAB_DIR/$VM_RUN_DIR"
R_IMG="\$HOME/$LAB_DIR/images"
# Snapshot layout (VM_SNAPSHOT=1 only): the known-good disk is
# $VM_BASE_IMAGE; once $NAME.golden exists the VM always boots from the
# throwaway overlay $NAME-run.qcow2 backed by it. Never boot the base image
# directly (e.g. with an older run.sh) while the overlay exists — that
# silently corrupts the overlay.
OVL="$NAME-run.qcow2"
MARK="$NAME.golden"

pubkey_file() {
    if [ -n "${SSH_PUBKEY_FILE:-}" ]; then echo "$SSH_PUBKEY_FILE"
    elif [ -f "$HOME/.ssh/id_rsa.pub" ]; then echo "$HOME/.ssh/id_rsa.pub"
    elif [ -f "$HOME/.ssh/id_ed25519.pub" ]; then echo "$HOME/.ssh/id_ed25519.pub"
    else
        echo "no ssh pubkey found (\$HOME/.ssh/id_rsa.pub or id_ed25519.pub); set SSH_PUBKEY_FILE" >&2
        return 1
    fi
}

is_running() {
    # NB: heredoc-to-stdin, not `bash -c "<string>"` — ssh joins trailing argv
    # words with spaces and hands them to the remote shell to reparse, which
    # mangles quoting; stdin heredocs are transported verbatim.
    host_ssh bash -s <<EOF
if [ -f "$R_RUN/$NAME.quota" ]; then
    # quota-launched VM: systemd unit owns the qemu process (no pidfile)
    sudo systemctl is-active --quiet lab-qemu-$NAME.service
    exit \$?
fi
f="$R_RUN/$NAME.pid"
[ -f "\$f" ] && sudo kill -0 "\$(sudo cat "\$f")" 2>/dev/null
EOF
}

wait_ssh() {
    echo -n "Waiting for ssh on $NAME (127.0.0.1:$VM_SSH_PORT via $VMHOST) "
    local tries=0
    # 480s budget: first boot on the stock cloud image runs a one-time
    # freebsd-update p0->pN pass + reboot, observed to take ~2m45s (task 4).
    until vm_ssh "$NAME" true 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 240 ]; then
            echo
            echo "Timed out waiting for ssh after ${tries}x2s. Check serial log:" >&2
            echo "  $VMHOST:~/$LAB_DIR/$VM_RUN_DIR/$NAME.serial.log" >&2
            return 1
        fi
        if [ $((tries % 15)) -eq 0 ]; then echo -n " [$((tries * 2))s] "; else echo -n "."; fi
        sleep 2
    done
    echo " up."
}

# bridged_nic <netdev-id> <tap> <mac> <bridge>: create bridge (if missing) and
# tap on the host; print the qemu -netdev/-device args. Opt-in, default off:
# LAB_VHOST=1 = vhost-net datapath (qemu's main-loop virtio caps a NIC near
# 1 Gbit/s whatever the guest's CPUs); LAB_NET_QUEUES=N>1 = N queue pairs on
# a multi_queue tap (RSS-style spread, like the production igc NICs).
bridged_nic() {
    local id="$1" tap="$2" mac="$3" bridge="$4"
    local q="${LAB_NET_QUEUES:-1}" tapmode="" nd_opts="" dev_opts=""
    if [ "$q" -gt 1 ]; then
        tapmode="multi_queue"
        nd_opts=",queues=$q"
        dev_opts=",mq=on,vectors=$((2 * q + 2))"
    fi
    if [ "${LAB_VHOST:-0}" = 1 ]; then nd_opts="$nd_opts,vhost=on"; fi
    host_ssh bash -s >&2 <<EOF
set -euo pipefail
sudo ip link add $bridge type bridge 2>/dev/null || true   # concurrent ups race here
sudo ip link show $bridge >/dev/null
sudo ip link set $bridge up
# cmd_up only gets here with the VM down, so recreating its tap is safe.
# Recreate whenever the tap's multi_queue flag differs from what's wanted,
# in either direction, or qemu's -netdev fails with "could not configure
# /dev/net/tun ... Invalid argument" against the stale tap.
cur_tapmode=""
tapinfo="\$(ip -d link show $tap 2>/dev/null || true)"
case "\$tapinfo" in *multi_queue*) cur_tapmode="multi_queue" ;; esac
if [ "\$cur_tapmode" != "$tapmode" ]; then
    sudo ip link delete $tap 2>/dev/null || true
fi
sudo ip tuntap add dev $tap mode tap $tapmode 2>/dev/null || true
sudo ip link set $tap master $bridge up
EOF
    echo "-netdev tap,id=$id,ifname=$tap,script=no,downscript=no$nd_opts -device virtio-net-pci,netdev=$id,mac=$mac$dev_opts"
}

cmd_up() {
    if is_running; then
        echo "$NAME already running (pidfile present)."
        return 0
    fi

    # VM_BR_TAP: bridged NIC for lab traffic, in addition to the always-present
    # user-mode ssh NIC (n0). Created/attached here (not left to qemu's own
    # tap-script hooks, hence script=no/downscript=no) so cmd_down can
    # detach+delete it explicitly. The bridge itself is created if missing
    # (slot 1's br-isp normally comes from isp-netns/up.sh; br-isp<N> from here).
    local extra_netdev=""
    if [ -n "$VM_BR_TAP" ]; then
        extra_netdev="$(bridged_nic n1 "$VM_BR_TAP" "$VM_BR_MAC" "$VM_BRIDGE")"
    fi

    # VM_VIRTFS_DIR: expose $LAB_DIR/<dir> on the host into the guest as a
    # virtio-9p share (tag hostshare) — used by the isp VM so accel-pppd can
    # write its log straight onto the lab host's disk (see provision-isp.sh).
    local extra_virtfs=""
    if [ -n "$VM_VIRTFS_DIR" ]; then
        host_ssh "mkdir -p \"\$HOME/$LAB_DIR/$VM_VIRTFS_DIR\""
        extra_virtfs="-virtfs local,path=\$HOME/$LAB_DIR/$VM_VIRTFS_DIR,mount_tag=hostshare,security_model=none,id=hostshare"
    fi

    # VM_BR_TAP2: second bridged NIC (n2) onto VM_BRIDGE2 (br-lan, or
    # br-lan<N> in slot N; `dut` uses its own br-dut-lan so plugin-test
    # API/ssh traffic never crosses the router-mode path; created here if
    # missing) — the router-mode LAN port of the DUT.
    local extra_netdev2=""
    if [ -n "${VM_BR_TAP2:-}" ]; then
        extra_netdev2="$(bridged_nic n2 "$VM_BR_TAP2" "$VM_BR_MAC2" "$VM_BRIDGE2")"
        if [ -n "${VM_BRIDGE2_HOST_IP:-}" ]; then
            host_ssh bash -s <<EOF
set -euo pipefail
ip addr show dev $VM_BRIDGE2 | grep -q " ${VM_BRIDGE2_HOST_IP} " || \
    sudo ip addr add $VM_BRIDGE2_HOST_IP dev $VM_BRIDGE2
EOF
        fi
    fi

    # VM_FWD_CLI: host-forward 127.0.0.1:<port> to the guest's accel-ppp CLI
    # (guest port 2001) — AccelServer._cli (tests/functional/lab.py).
    local cli_fwd=""
    if [ -n "${VM_FWD_CLI:-}" ]; then
        cli_fwd=",hostfwd=tcp:127.0.0.1:${VM_FWD_CLI}-:2001"
    fi

    # Resolve the throttle branch LOCALLY: the heredoc interpolates the value,
    # so the remote script branches on a literal, not on a (never-forwarded)
    # env var. NB: a remote string tail expands with its quote characters
    # intact when used unquoted — use an array instead.
    local quota_val="${LAB_THROTTLE_QUOTA:-}"
    # Same for LAB_RUN_DRIVE (a path, never a secret): resolved locally.
    local run_drive="${LAB_RUN_DRIVE:-}"

    # VM_IMG_TYPE=opnsense ships no cloud-init agent (it's not a cloud
    # image), so there is no cidata seed to build — first boot is
    # unattended-configured over the serial console instead, by
    # make-dut-seed.py + provision-dut.sh (see README's "dut" section).
    local extra_cdrom=""
    if [ "$VM_IMG_TYPE" != "opnsense" ]; then
        local pubkey
        pubkey="$(cat "$(pubkey_file)")"
        host_ssh bash -s <<EOF
set -euo pipefail
mkdir -p "$R_IMG"
cd "$R_IMG"

# Per-VM cloud-init scratch dir: two slots booting at once must not race on
# a shared user-data/meta-data pair.
ci="\$(mktemp -d)"
cat > "\$ci/user-data" <<CI
#cloud-config
hostname: $VM_HOSTNAME
users:
  - name: $VM_SSH_USER
    groups: $VM_SSH_GROUPS
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    ssh_authorized_keys:
      - $pubkey
ssh_pwauth: false
growpart:
  mode: auto
  devices: ['/']
CI
cat > "\$ci/meta-data" <<CI
instance-id: $NAME
local-hostname: $VM_HOSTNAME
CI
genisoimage -output "$VM_SEED_ISO" -volid cidata -joliet -rock "\$ci/user-data" "\$ci/meta-data" >/dev/null 2>&1 \
    || { echo "genisoimage failed for $VM_SEED_ISO" >&2; exit 1; }
rm -rf "\$ci"
EOF
        extra_cdrom="-drive file=\"\$PWD/$VM_SEED_ISO\",if=virtio,media=cdrom"
    fi
    # VM_CONFIG_ISO: a pre-built config.xml seed disk (make-dut-seed.py,
    # copied into images/ by provision-dut.sh) as an extra cdrom.
    if [ -n "${VM_CONFIG_ISO:-}" ]; then
        extra_cdrom="$extra_cdrom -drive file=\"\$PWD/$VM_CONFIG_ISO\",if=virtio,media=cdrom"
    fi

    host_ssh bash -s <<EOF
set -euo pipefail
RUN="$R_RUN"
mkdir -p "\$RUN" "$R_IMG"
cd "$R_IMG"

# Disk: the known-good base, or (after snapshot-save) its throwaway overlay,
# or LAB_RUN_DRIVE (an absolute path on this host, e.g. plugin-roundtrip.sh's
# per-run tmpfs overlay of dut's base) which wins over both.
DRIVE="\$PWD/$VM_BASE_IMAGE"
RUN_DRIVE="$run_drive"
if [ -n "\$RUN_DRIVE" ]; then
    case "\$RUN_DRIVE" in /*) ;; *) echo "LAB_RUN_DRIVE must be absolute (got \$RUN_DRIVE)" >&2; exit 1 ;; esac
    [ -f "\$RUN_DRIVE" ] || { echo "LAB_RUN_DRIVE \$RUN_DRIVE does not exist" >&2; exit 1; }
    DRIVE="\$RUN_DRIVE"
    echo "$NAME: booting from LAB_RUN_DRIVE \$DRIVE"
elif [ -f "$MARK" ]; then
    if [ ! -f "$OVL" ]; then
        qemu-img create -q -f qcow2 -F qcow2 -b "\$PWD/$VM_BASE_IMAGE" "$OVL"
    fi
    DRIVE="\$PWD/$OVL"
    echo "$NAME: booting from run overlay $OVL (known-good base $VM_BASE_IMAGE)"
fi

pidfile="\$RUN/$NAME.pid"
serial="\$RUN/$NAME.serial.log"
# Serial console: a unix-socket chardev (type into it with console-cmd /
# reset-clean / provision-dut.sh's console_driver.py) that also appends
# everything to the serial log, which is never truncated — the WITNESS/panic
# delta workflow snapshots its line count before a run. A boot marker
# separates launches.
sudo rm -f "\$RUN/$VM_CONSOLE_SOCK" "\$RUN/$VM_MONITOR_SOCK"
echo "=== run.sh: $NAME launched \$(date -u +%FT%TZ) drive=\$DRIVE ===" | sudo tee -a "\$serial" >/dev/null

# LAB_THROTTLE_QUOTA (e.g. 180): launch qemu inside a systemd CPUQuota
# service — the DUT's aggregate CPU is capped from boot, with NO process
# migration (migrating qemu into a CPUQuota cgroup post-boot killed this
# FreeBSD guest repeatedly). systemd-run returns immediately; the unit runs
# until qemu exits. Width-limiting (taskset) is still applied post-boot via
# throttle.sh — that is migration-free and safe.
sudo systemctl reset-failed "lab-qemu-$NAME.service" 2>/dev/null || true
QUOTA="$quota_val"
if [ -n "\$QUOTA" ]; then
    # SAFETY: never systemctl-stop this unit while qemu is alive inside it —
    # stopping a unit SIGTERMs its whole cgroup and power-cuts the guest;
    # the guest must be shut down first (cmd_down already does this).
    LAUNCH_PREFIX="sudo systemd-run --unit=lab-qemu-$NAME --property=CPUQuota=\${QUOTA}% --collect --quiet"
    LAUNCH_ARGS=( -pidfile "\$pidfile" )
    echo "\$QUOTA" > "\$RUN/$NAME.quota"
    echo "throttle: launching $NAME inside lab-qemu-$NAME.service with CPUQuota=\${QUOTA}%"
else
    LAUNCH_PREFIX="sudo"
    LAUNCH_ARGS=( -daemonize -pidfile "\$pidfile" )
fi

\${LAUNCH_PREFIX} qemu-system-x86_64 \
    -name $NAME \
    -machine accel=kvm \
    -cpu host \
    -smp $VM_VCPUS \
    -m ${VM_MEM_MB}M \
    -drive file="\$DRIVE",if=virtio,format=qcow2 \
    $extra_cdrom \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${VM_SSH_PORT}-:22$cli_fwd \
    -device virtio-net-pci,netdev=n0 \
    $extra_netdev \
    $extra_netdev2 \
    $extra_virtfs \
    -chardev socket,id=ser0,path="\$RUN/$VM_CONSOLE_SOCK",server=on,wait=off,logfile="\$serial",logappend=on \
    -serial chardev:ser0 \
    -monitor unix:"\$RUN/$VM_MONITOR_SOCK",server=on,wait=off \
    -display none \
    "\${LAUNCH_ARGS[@]}"
EOF

    if [ "$VM_IMG_TYPE" = "opnsense" ]; then
        # No cloud-init user/key, so no ssh yet -- first boot is console-menu
        # only until provision-dut.sh seeds config.xml and reboots.
        echo "$NAME booted (console socket: ~/$LAB_DIR/$VM_RUN_DIR/$VM_CONSOLE_SOCK on $VMHOST)."
        echo "Run provision-dut.sh to seed config.xml and enable ssh."
        return 0
    fi

    wait_ssh
}

# stop_vm <mode>
#   down  — ssh shutdown, wait 30s; then monitor system_powerdown (ACPI) + 60s,
#           then monitor 'quit'. VMs without a monitor socket (launched by an
#           older run.sh or by hand) keep the old SIGTERM/SIGKILL fallback.
#   clean — ssh shutdown, then ACPI powerdown; FAILS instead of quitting/killing
#           (snapshot-save: the base must only ever get a cleanly unmounted fs).
#   quit  — monitor 'quit' straight away (snapshot-revert: the overlay is
#           discarded anyway). Never SIGKILLs.
stop_vm() {
    local mode="$1"
    if [ "$mode" != quit ] && [ "$VM_IMG_TYPE" = "opnsense" ]; then
        # vm_ssh's n0/user-mode route is unused for this VM (unassigned in
        # the seed) and root has no password, so vm_ssh can never reach it --
        # try the LAN bridge IP (key auth, once seeded). If that fails (pre-
        # seed, or the LAN broken -- states plugin tests can leave it in),
        # the ladder below falls back to the monitor's ACPI system_powerdown.
        if [ -n "${VM_LAN_IP:-}" ]; then
            ssh -J "$VMHOST" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=5 -o BatchMode=yes "root@$VM_LAN_IP" \
                'sync; sync; shutdown -p now' >/dev/null 2>&1 || true
        fi
    elif [ "$mode" != quit ]; then
        # Graceful guest shutdown first (ACPI poweroff via ssh) so UFS buffers
        # flush to the virtual disk. `echo |` feeds the blank-password prompt
        # (root has no password, no sudo/doas) — same as build-kernel.sh's
        # asroot(); without it, a run with stdin closed can hang.
        echo | vm_ssh "$NAME" "$VM_SHUTDOWN_CMD" >/dev/null 2>&1 || true
    fi

    host_ssh bash -s <<EOF
set -uo pipefail
RUN="$R_RUN"
f="\$RUN/$NAME.pid"; mon="\$RUN/$VM_MONITOR_SOCK"; mode="$mode"
pid=""; [ -f "\$f" ] && pid="\$(sudo cat "\$f")"
alive() { [ -n "\$pid" ] && sudo kill -0 "\$pid" 2>/dev/null; }
waitdead() { local i; for i in \$(seq 1 "\$1"); do alive || return 0; sleep 1; done; ! alive; }
moncmd() { [ -S "\$mon" ] && printf '%s\n' "\$1" | sudo timeout 10 nc -U -q 1 "\$mon" >/dev/null 2>&1; }
cleanup() {
    sudo rm -f "\$f" "\$RUN/$NAME.quota" "\$RUN/$VM_CONSOLE_SOCK" "\$mon"
    sudo systemctl stop lab-qemu-$NAME.service 2>/dev/null || true
}

if [ -z "\$pid" ]; then
    # quota-launched VM without pidfile: stop the systemd unit (graceful
    # guest shutdown already attempted above)
    sudo systemctl stop lab-qemu-$NAME.service 2>/dev/null || true
    sudo rm -f "\$RUN/$NAME.quota"
    echo "$NAME stopped (no pidfile)."
    exit 0
fi

case "\$mode" in
    quit)
        if alive; then
            moncmd quit || { echo "$NAME: monitor socket \$mon unusable; refusing to kill" >&2; exit 1; }
            waitdead 20 || { echo "$NAME: still alive after monitor quit" >&2; exit 1; }
        fi
        cleanup; echo "$NAME stopped (monitor quit)."; exit 0 ;;
esac

grace=30; [ "\$mode" = clean ] && grace=90
waitdead "\$grace" && { cleanup; echo "$NAME stopped."; exit 0; }
if [ -S "\$mon" ]; then
    echo "$NAME: guest still up after ssh shutdown; sending ACPI system_powerdown"
    moncmd system_powerdown
    waitdead 60 && { cleanup; echo "$NAME stopped (ACPI powerdown)."; exit 0; }
    if [ "\$mode" = clean ]; then
        echo "$NAME: did not power off cleanly; left running (no quit/kill in clean mode)" >&2
        exit 1
    fi
    echo "$NAME: still up after ACPI powerdown; monitor quit"
    moncmd quit; waitdead 20
    alive && { echo "$NAME: still alive after monitor quit" >&2; exit 1; }
    cleanup; echo "$NAME stopped (monitor quit)."; exit 0
fi
if [ "\$mode" = clean ]; then
    echo "$NAME: no monitor socket and guest ignored ssh shutdown; left running" >&2
    exit 1
fi
# Legacy launch (no monitor socket): the pre-slots SIGTERM/SIGKILL path.
sudo kill "\$pid"; sleep 2
alive && sudo kill -9 "\$pid" || true
cleanup; echo "$NAME stopped (signal)."
EOF
}

cmd_down() {
    stop_vm "${1:-down}"
    if [ -n "$VM_BR_TAP" ]; then
        host_ssh bash -s <<EOF
sudo ip link set $VM_BR_TAP nomaster 2>/dev/null || true
sudo ip link delete $VM_BR_TAP 2>/dev/null || true
EOF
    fi
}

cmd_status() {
    if is_running; then echo "$NAME: running"; else echo "$NAME: stopped"; fi
    host_ssh bash -s <<EOF
cd "$R_IMG" 2>/dev/null || exit 0
ls -1 "$R_RUN"/$NAME.* 2>/dev/null | sed 's/^/  /'
[ -f "$MARK" ] && echo "  snapshot: \$(cat "$MARK")" || echo "  snapshot: none"
EOF
}

# console_send <text> <wait>: type text+CR into the serial console socket and
# print what the guest wrote to the serial log meanwhile. The lab host has no
# socat — OpenBSD nc -U does the job; -q <wait> lingers for the reply after stdin EOF.
# The text travels base64-encoded so no layer of quoting can mangle it.
console_send() {
    local text="$1" wait="${2:-3}" b64
    b64="$(printf '%s\r' "$text" | base64 -w0)"
    host_ssh bash -s <<EOF
set -euo pipefail
RUN="$R_RUN"
sock="\$RUN/$VM_CONSOLE_SOCK"
# hand-launched legacy instance (client-repair.md) used <name>.console.sock
[ -S "\$sock" ] || sock="\$RUN/$NAME.console.sock"
[ -S "\$sock" ] || { echo "$NAME: no console socket in \$RUN (VM not launched by this run.sh?)" >&2; exit 1; }
log="\$RUN/$NAME.serial.log"
before=\$(sudo stat -c %s "\$log" 2>/dev/null || echo 0)
echo "$b64" | base64 -d | sudo timeout $((wait + 10)) nc -U -q $wait "\$sock" >/dev/null || true
sudo tail -c +\$((before + 1)) "\$log"
EOF
}

cmd_monitor() {
    local c="$1" b64
    b64="$(printf '%s\n' "$c" | base64 -w0)"
    host_ssh bash -s <<EOF
set -euo pipefail
mon="$R_RUN/$VM_MONITOR_SOCK"
[ -S "\$mon" ] || { echo "$NAME: no monitor socket \$mon" >&2; exit 1; }
echo "$b64" | base64 -d | sudo timeout 10 nc -U -q 1 "\$mon" | tr -d '\r' \
    | sed -e 's/\x1b\[[0-9]*[A-Za-z]//g' | grep -v -e '^QEMU .* monitor' -e '^(qemu)' || true
EOF
}

cmd_reset_clean() {
    local out tail
    out="$(console_send "" 2)"
    tail="$(printf '%s' "$out" | tr -d '\r' | tail -c 300)"
    case "$tail" in
        *"db>"*)
            echo "$NAME: guest is in the kernel debugger; sending ddb 'reset'"
            console_send "reset" 2 >/dev/null ;;
        *"login:"*)
            echo "$NAME: guest at login prompt; logging in as root and rebooting"
            out="$(console_send "root" 3)"
            case "$out" in *Password:*) console_send "" 3 >/dev/null ;; esac
            console_send "shutdown -r now" 3 >/dev/null ;;
        *"# ")
            echo "$NAME: guest at a root shell; rebooting"
            console_send "shutdown -r now" 3 >/dev/null ;;
        *)
            if [ -n "${FORCE:-}" ]; then
                echo "$NAME: console state unrecognised; FORCE=1 -> monitor system_reset"
                cmd_monitor system_reset
            else
                echo "$NAME: console state unrecognised (last output below); rerun with FORCE=1 for a monitor system_reset" >&2
                printf '%s\n' "$tail" >&2
                return 1
            fi ;;
    esac
    sleep 10   # let the old guest drop off the network before probing ssh
    wait_ssh
}

need_snapshot_vm() {
    [ "$VM_SNAPSHOT" = 1 ] || { echo "$NAME: snapshots are only supported on client VMs" >&2; exit 1; }
}

cmd_snapshot_save() {
    need_snapshot_vm
    if is_running; then
        stop_vm clean || { echo "snapshot-save: $NAME did not stop cleanly; nothing saved" >&2; exit 1; }
    fi
    host_ssh bash -s <<EOF
set -euo pipefail
cd "$R_IMG"
if [ -f "$MARK" ] && [ -f "$OVL" ]; then
    echo "snapshot-save: folding $OVL into $VM_BASE_IMAGE"
    qemu-img commit -q "$OVL"
fi
rm -f "$OVL"
echo "saved \$(date -u +%FT%TZ) by \${SUDO_USER:-\$USER}" > "$MARK"
qemu-img create -q -f qcow2 -F qcow2 -b "\$PWD/$VM_BASE_IMAGE" "$OVL"
echo "snapshot-save: $NAME known-good = $VM_BASE_IMAGE (\$(cat "$MARK")); fresh overlay $OVL"
EOF
    cmd_up
}

cmd_snapshot_revert() {
    need_snapshot_vm
    host_ssh "test -f \"$R_IMG/$MARK\"" || { echo "snapshot-revert: $NAME has no snapshot (run snapshot-save first)" >&2; exit 1; }
    local t0; t0=$(date +%s)
    if is_running; then
        stop_vm quit || stop_vm clean || { echo "snapshot-revert: could not stop $NAME" >&2; exit 1; }
    fi
    host_ssh bash -s <<EOF
set -euo pipefail
cd "$R_IMG"
rm -f "$OVL"
qemu-img create -q -f qcow2 -F qcow2 -b "\$PWD/$VM_BASE_IMAGE" "$OVL"
EOF
    cmd_up
    echo "snapshot-revert: $NAME back at its known-good snapshot in $(( $(date +%s) - t0 ))s"
}

case "$ACTION" in
    up)              cmd_up ;;
    down)            cmd_down ;;
    shutdown)        cmd_down clean ;;
    status)          cmd_status ;;
    ssh)             vm_ssh "$NAME" "$@" ;;
    console-cmd)     [ $# -ge 1 ] || usage; console_send "$1" "${2:-3}" ;;
    monitor)         [ $# -eq 1 ] || usage; cmd_monitor "$1" ;;
    reset-clean)     cmd_reset_clean ;;
    snapshot-save)   cmd_snapshot_save ;;
    snapshot-revert) cmd_snapshot_revert ;;
    *)               usage ;;
esac
