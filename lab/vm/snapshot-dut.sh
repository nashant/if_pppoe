#!/usr/bin/env bash
# snapshot-dut.sh save|list|revert|delete [tag] -- qemu-img internal
# snapshots of dut's overlay qcow2. `dut` must be stopped (./run.sh dut
# down) for save/revert/delete: qemu-img can't safely touch a qcow2 file a
# running qemu still has open.
# plugin-roundtrip.sh does not need this: it boots dut from a per-run tmpfs
# overlay and never writes the base. Never snapshot a provisioned disk.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

vm_config dut
IMG="\$HOME/$LAB_DIR/images/$VM_BASE_IMAGE"

usage() {
    echo "usage: $0 save|list|revert|delete TAG" >&2
    echo "       $0 list" >&2
    exit 1
}

[ $# -ge 1 ] || usage
ACTION="$1"; TAG="${2:-}"
if [ "$ACTION" != "list" ] && [ -z "$TAG" ]; then usage; fi

case "$ACTION" in
    save)
        host_ssh "qemu-img snapshot -c \"$TAG\" $IMG"
        echo "saved snapshot '$TAG'"
        ;;
    list)
        host_ssh "qemu-img snapshot -l $IMG"
        ;;
    revert)
        host_ssh "qemu-img snapshot -a \"$TAG\" $IMG"
        echo "reverted to snapshot '$TAG'"
        ;;
    delete)
        host_ssh "qemu-img snapshot -d \"$TAG\" $IMG"
        echo "deleted snapshot '$TAG'"
        ;;
    *) usage ;;
esac
