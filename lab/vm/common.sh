#!/usr/bin/env bash
# Shared config, sourced by fetch-image.sh, run.sh, build-kernel.sh.
# Invoked from any host with ssh access to VMHOST; state lives under
# $VMHOST:$LAB_DIR, not locally.

set -euo pipefail

# Gitignored per-checkout overrides (see lab/local.env.example); sourced
# before VMHOST's own check below so it can supply the value.
_LOCAL_ENV="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/local.env"
if [ -f "$_LOCAL_ENV" ]; then
    # shellcheck source=/dev/null
    . "$_LOCAL_ENV"
fi
unset _LOCAL_ENV

VMHOST="${VMHOST:?set VMHOST in lab/local.env (see lab/local.env.example) or export it}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"   # relative to $VMHOST's $HOME

# LAB_SLOT: independent copy of client/isp/mpdsrv/lan (slot 1 = the original
# names/ports, unchanged; scheme in README.md "Slots and leases").
# tests/functional/lab.py mirrors the port/bridge arithmetic -- keep in sync.
LAB_SLOT="${LAB_SLOT:-1}"
case "$LAB_SLOT" in
    [1-9]) ;;
    *) echo "common.sh: LAB_SLOT must be 1..9 (got '$LAB_SLOT')" >&2; exit 1 ;;
esac
export LAB_SLOT

# slot_suffix <slot> -> "" for slot 1, "-slot<N>" otherwise (dir/log names).
slot_suffix() { if [ "$1" = 1 ]; then echo ""; else echo "-slot$1"; fi; }

# vm_resolve <name> -> sets VM_ROLE, VM_SLOT, VM_NAME (the real VM name).
vm_resolve() {
    local name="$1"
    if [[ "$name" =~ ^(client|mpdsrv|isp|lan)([1-9])$ ]]; then
        VM_ROLE="${BASH_REMATCH[1]}"; VM_SLOT="${BASH_REMATCH[2]}"
    else
        VM_ROLE="$name"
        case "$name" in
            build|build15) VM_SLOT=1 ;;   # one build VM per FreeBSD release, shared by every slot
            dut)   VM_SLOT=1 ;;           # one plugin-test DUT: fixed br-dut-lan
                                          # + 192.168.90.0/24, not slotted
            *)     VM_SLOT="$LAB_SLOT" ;;
        esac
    fi
    if [ "$VM_SLOT" = 1 ]; then VM_NAME="$VM_ROLE"; else VM_NAME="$VM_ROLE$VM_SLOT"; fi
}

# --- Per-VM-name configuration -------------------------------------------
# Adding a new VM (client, mpdsrv, ...) is a new case branch here. Every VM
# gets the ssh-reachable user-mode NIC (n0, hostfwd to VM_SSH_PORT) — that
# part of cmd_up/vm_ssh never changes per-name. VM_BR_TAP, when non-empty,
# additionally attaches a tap device (name = VM_BR_TAP) to br-isp and gives
# the guest a second NIC (n1) on it, so the VM can also reach the isp-netns
# lab network directly (bridged L2, not user-mode NAT).
vm_config() {
    vm_resolve "$1"
    local name="$VM_ROLE"
    VM_SNAPSHOT=""  # 1: supports run.sh snapshot-save/-revert (qcow2 run overlay)
    VM_RUN_DIR="run$(slot_suffix "$VM_SLOT")"   # under $LAB_DIR
    VM_FWD_CLI=""   # non-empty: host port forwarded to the guest's accel CLI 2001
    VM_BR_TAP=""   # default: no bridged NIC; set per-name below to opt in.
    VM_BR_MAC=""   # explicit MAC for the bridged NIC — qemu's auto-assigned
    VM_BRIDGE="br-isp"  # which host bridge the first bridged NIC joins
    VM_BR_TAP2=""  # optional SECOND bridged NIC (n2) — router-mode LAN port
    VM_BR_MAC2=""
    VM_BRIDGE2="br-lan"  # which host bridge the second bridged NIC joins
    VM_BRIDGE2_HOST_IP=""      # non-empty CIDR: give the HOST's port on the
                               # 2nd bridge this address (idempotent), so
                               # the lab host itself can reach that bridge's
                               # VMs directly (e.g. dut's br-dut-lan, for
                               # ssh/API -- no VM plays "lan client" there).
    VM_SSH_USER="freebsd"      # cloud-init user + ssh login (Linux VMs differ)
    VM_SSH_GROUPS="wheel"      # cloud-init groups for that user
    VM_SHUTDOWN_CMD='su -m root -c "sync; sync; shutdown -p now"'  # cmd_down
    VM_IMG_TYPE="freebsd"      # fetch-image.sh base-image flavour
    VM_FREEBSD_REL="14.3"      # VM_IMG_TYPE=freebsd: fetch-image.sh's -RELEASE image
    VM_VIRTFS_DIR=""           # non-empty: qemu -virtfs share of $LAB_DIR/<dir>
                               # mounted in the guest as 9p tag hostshare
    VM_CONFIG_ISO=""           # non-empty: 2nd cdrom (id=cd1) — a pre-built
                               # config.xml seed disk (make-dut-seed.py),
                               # unlike VM_SEED_ISO which run.sh rebuilds
                               # fresh every cmd_up as cloud-init cidata.
    # Every VM gets a serial-console unix socket (VM_CONSOLE_SOCK, a qemu
    # chardev that also appends to <name>.serial.log) and an HMP monitor
    # socket (VM_MONITOR_SOCK), both in $LAB_DIR/$VM_RUN_DIR on $VMHOST --
    # set after the case below, once VM_NAME/VM_RUN_DIR are final. run.sh's
    # console-cmd/reset-clean and provision-dut.sh's console_driver.py type
    # into the former; stop_vm's ACPI system_powerdown fallback uses the latter.
    VM_LAN_IP=""               # non-empty: a 2nd-bridge static IP stop_vm
                               # ssh's a `shutdown -p now` to, in place of
                               # vm_ssh (VM_IMG_TYPE=opnsense: n0 unassigned),
                               # before the monitor's ACPI powerdown fallback.
    # default MAC for a VM's 2nd NIC is deterministic from the
                   # command line shape, so two same-shaped VMs (client,
                   # mpdsrv) collide on br-isp without one (confirmed: both
                   # got 52:54:00:12:34:57, and PPPoE discovery frames were
                   # silently dropped, per the FDB flip-flop mechanism
                   # isp-netns's README already documented for the same root
                   # cause). Must be set whenever VM_BR_TAP is.
    case "$name" in
        build)
            VM_MEM_MB=12288
            VM_VCPUS=6
            VM_SSH_PORT=2222
            VM_BASE_IMAGE="build.qcow2"   # under $LAB_DIR/images/
            VM_SEED_ISO="build-seed.iso"  # under $LAB_DIR/images/
            VM_HOSTNAME="build"
            VM_OVERLAY_SIZE="60G"   # fetch-image.sh: size of $VM_BASE_IMAGE's overlay
            ;;
        build15)
            # FreeBSD 15.1 twin of `build` for the OPNsense 26.7 kernel/objdir
            # (build-kernel.sh with LAB_SERIES=26.7). Same guest layout
            # ($HOME/if_pppoe-lab/...), so build-check.sh runs unchanged.
            VM_MEM_MB=12288
            VM_VCPUS=6
            VM_SSH_PORT=2228
            VM_BASE_IMAGE="build15.qcow2"
            VM_SEED_ISO="build15-seed.iso"
            VM_HOSTNAME="build15"
            VM_OVERLAY_SIZE="60G"
            VM_FREEBSD_REL="15.1"
            ;;
        client)
            VM_MEM_MB=2048
            VM_VCPUS=4
            VM_SSH_PORT=2223
            VM_BASE_IMAGE="client.qcow2"
            VM_SEED_ISO="client-seed.iso"
            VM_HOSTNAME="client"
            VM_BR_TAP="tap-client"
            VM_BR_MAC="52:54:00:aa:00:01"
            VM_OVERLAY_SIZE="20G"
            # Router-mode (S06): vtnet2 bridged onto br-lan as the DUT's LAN
            # port — traffic is then measured THROUGH the VM's pf+NAT path
            # (192.168.77.0/24 LAN), like production's igc LAN port.
            VM_BR_TAP2="tap-lan"
            VM_BR_MAC2="52:54:00:aa:00:04"
            VM_SNAPSHOT=1
            ;;
        lan)
            # Linux LAN-side VM (S06 router mode): runs `iperf3 -c` as the
            # client BEHIND the router VM's pf+NAT — the run_matrix --client.
            # Static 192.168.77.10/24, default route via the router (192.168.77.2)
            # so traffic traverses the DUT's pf+NAT+pppoe path exactly like a
            # production LAN host.
            VM_MEM_MB=1024
            VM_VCPUS=2
            VM_SSH_PORT=2226
            VM_BASE_IMAGE="lan.qcow2"
            VM_SEED_ISO="lan-seed.iso"
            VM_HOSTNAME="lan"
            VM_BR_TAP="tap-lan-vm"
            VM_BR_MAC="52:54:00:aa:00:05"
            VM_BRIDGE="br-lan"
            VM_OVERLAY_SIZE="6G"
            VM_SSH_USER="debian"
            VM_SSH_GROUPS="sudo"
            VM_SHUTDOWN_CMD='sudo poweroff'
            VM_IMG_TYPE="debian"
            ;;
        mpdsrv)
            VM_MEM_MB=2048
            VM_VCPUS=2
            VM_SSH_PORT=2224
            VM_BASE_IMAGE="mpdsrv.qcow2"
            VM_SEED_ISO="mpdsrv-seed.iso"
            VM_HOSTNAME="mpdsrv"
            VM_BR_TAP="tap-mpdsrv"
            VM_BR_MAC="52:54:00:aa:00:02"
            VM_OVERLAY_SIZE="20G"
            ;;
        isp)
            # Linux ISP-side VM: accel-ppp PPPoE server + iperf3, replacing the
            # isp-netns accel as the lab's ISP. Same accel config shape as the
            # netns (service-name lab, 10.99.0.x pool, gw 10.99.0.1) so dials
            # and the functional suite are unchanged; its accel log reaches the
            # host through the virtio-9p share (VM_VIRTFS_DIR) so the suite's
            # /tmp/accel-ppp.log reads keep working (provision-isp.sh wires it).
            VM_MEM_MB=2048
            VM_VCPUS=4
            VM_SSH_PORT=2225
            VM_BASE_IMAGE="isp.qcow2"
            VM_SEED_ISO="isp-seed.iso"
            VM_HOSTNAME="isp"
            VM_BR_TAP="tap-isp"
            VM_BR_MAC="52:54:00:aa:00:03"
            VM_OVERLAY_SIZE="10G"
            VM_SSH_USER="debian"
            VM_SSH_GROUPS="sudo"
            VM_SHUTDOWN_CMD='sudo poweroff'
            VM_IMG_TYPE="debian"
            VM_VIRTFS_DIR="isp-share"
            VM_FWD_CLI=2001
            ;;
        dut)
            # Plugin-test DUT (tests/plugin/): separate from `client` so
            # plugin tests never touch its accel-ppp account/session. No
            # cloud-init -- see README's "dut (plugin-test DUT)" section.
            VM_MEM_MB=2048
            VM_VCPUS=2
            VM_SSH_PORT=2227
            VM_BASE_IMAGE="dut.qcow2"
            VM_HOSTNAME="dut"
            VM_IMG_TYPE="opnsense"
            VM_OVERLAY_SIZE="12G"
            # n1 = WAN: bridged onto br-isp, same broadcast domain as the
            # isp-netns/isp-VM accel-ppp server and the `client`/`mpdsrv` VMs
            # -- see README's "shares br-isp" note.
            VM_BR_TAP="tap-dut-wan"
            VM_BR_MAC="52:54:00:aa:00:06"
            # n2 = LAN: its own bridge (not br-lan, which `client`/`lan`
            # already use for router-mode) so plugin-test API/ssh traffic
            # never crosses the router-mode measurement path.
            VM_BR_TAP2="tap-dut-lan"
            VM_BR_MAC2="52:54:00:aa:00:07"
            VM_BRIDGE2="br-dut-lan"
            VM_BRIDGE2_HOST_IP="192.168.90.1/24"  # dut's LAN static is .2 (see dut-config.xml.tmpl)
            VM_CONFIG_ISO="dut-seed.iso"
            # dut's n0 is unassigned (no route, no password), so the other
            # VMs' vm_ssh shutdown can never reach it: stop_vm ssh's to this
            # LAN IP instead, then falls back to the monitor socket's ACPI
            # system_powerdown (works pre-seed / with the LAN broken).
            VM_LAN_IP="192.168.90.2"        # dut-config.xml.tmpl's <lan><ipaddr> -- keep in sync
            ;;
        *)
            echo "vm_config: unknown VM name '$name' (known: build, build15, client, mpdsrv, isp, lan, dut; client/mpdsrv/isp/lan take a slot suffix, e.g. client2)" >&2
            return 1
            ;;
    esac

    # Slot N>1: own name, ports, taps, bridge, share dir (see top of file).
    if [ "$VM_SLOT" != 1 ]; then
        local off=$(( 10 * (VM_SLOT - 1) ))
        VM_SSH_PORT=$(( VM_SSH_PORT + off ))
        VM_BASE_IMAGE="$VM_NAME.qcow2"
        VM_SEED_ISO="$VM_NAME-seed.iso"
        VM_HOSTNAME="$VM_NAME"
        if [ -n "$VM_BR_TAP" ]; then VM_BR_TAP="$VM_BR_TAP$VM_SLOT"; fi
        # Router-mode LAN segment (perf S06 / p2 forwarded harness): lan<N> and
        # client<N>'s vtnet2 share br-lan<N>, a separate L2 from every other
        # slot's, so addressing (192.168.77.0/24) is identical per slot.
        if [ "$name" = lan ]; then
            VM_BRIDGE="br-lan$VM_SLOT"
        else
            VM_BRIDGE="br-isp$VM_SLOT"
        fi
        if [ -n "$VM_BR_TAP2" ]; then
            VM_BR_TAP2="$VM_BR_TAP2$VM_SLOT"
            VM_BRIDGE2="br-lan$VM_SLOT"
        fi
        if [ -n "$VM_VIRTFS_DIR" ]; then VM_VIRTFS_DIR="$VM_VIRTFS_DIR-slot$VM_SLOT"; fi
        if [ -n "$VM_FWD_CLI" ]; then VM_FWD_CLI=$(( VM_FWD_CLI + off )); fi
    fi
    # VM_DISK_ID: stem of the VM's own disk files (base image, seed ISO, and
    # run.sh's snapshot overlay/marker). Same as VM_NAME unless a disk
    # variant below swaps the disk while keeping everything else.
    VM_DISK_ID="$VM_NAME"
    # LAB_CLIENT_IMAGE=15.1: the client boots its own FreeBSD 15.1 disk
    # (<name>-fbsd15.qcow2) instead of the 14.3 one; everything else (port,
    # MACs, pidfile, serial log) is shared -- README "FreeBSD 15.1 client".
    case "${LAB_CLIENT_IMAGE:-}" in
        ""|14.3) ;;
        15.1)
            if [ "$name" = client ]; then
                VM_FREEBSD_REL="15.1"
                VM_DISK_ID="$VM_NAME-fbsd15"
                VM_BASE_IMAGE="$VM_DISK_ID.qcow2"
                VM_SEED_ISO="$VM_DISK_ID-seed.iso"
            fi
            ;;
        *) echo "vm_config: LAB_CLIENT_IMAGE must be empty, 14.3 or 15.1 (got '$LAB_CLIENT_IMAGE')" >&2; return 1 ;;
    esac
    # Socket basenames, relative to $LAB_DIR/$VM_RUN_DIR on $VMHOST.
    VM_CONSOLE_SOCK="$VM_NAME.serial.sock"
    VM_MONITOR_SOCK="$VM_NAME.monitor.sock"
    return 0
}

# ssh to the VM's guest OS via $VMHOST as a jump host, since the
# user-mode-net ssh port-forward (127.0.0.1:$VM_SSH_PORT) is only reachable
# from $VMHOST itself. This is unchanged regardless of whether the VM also
# has a bridged NIC (VM_BR_TAP) — ssh always goes over the user-mode NIC.
vm_ssh() {
    local name="$1"; shift
    vm_config "$name"
    ssh -J "$VMHOST" -p "$VM_SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=8 \
        "$VM_SSH_USER@127.0.0.1" "$@"
}

# Run a command on $VMHOST itself (for qemu lifecycle, image fetch, etc).
host_ssh() {
    ssh -o ConnectTimeout=8 "$VMHOST" "$@"
}
