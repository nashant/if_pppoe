#!/usr/bin/env bash
# Downloads the FreeBSD <VM_FREEBSD_REL>-RELEASE amd64 BASIC-CLOUDINIT qcow2
# (14.3; 15.1 for build15 and LAB_CLIENT_IMAGE=15.1 clients) to the lab
# host (once), verifies its checksum, and creates each VM name's own overlay qcow2 backed by it (size from
# vm_config's VM_OVERLAY_SIZE). Args: VM names to create overlays for
# (default: build client mpdsrv).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

freebsd_img_vars() {
    # EOL releases move from download.freebsd.org to archive.freebsd.org's
    # old-releases (as .github/scripts/smoke-vm.sh fetch_image does); the
    # remote side below picks the first that serves CHECKSUM.SHA256.
    IMG_REL_PATH="VM-IMAGES/$1-RELEASE/amd64/Latest"
    IMG_BASE_URLS="https://download.freebsd.org/releases/$IMG_REL_PATH https://archive.freebsd.org/old-releases/$IMG_REL_PATH"
    IMG_XZ="FreeBSD-$1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
    IMG_QCOW2="${IMG_XZ%.xz}"
    # 14.3 keeps its original checksum file name; other releases get their own.
    if [ "$1" = 14.3 ]; then IMG_SUMS="CHECKSUM.SHA256"; else IMG_SUMS="CHECKSUM-$1.SHA256"; fi
}
# Linux base for the isp VM (cloud-init enabled, like the FreeBSD
# BASIC-CLOUDINIT image; seeded by the same run.sh genisoimage cidata ISO).
DEB_BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"
DEB_QCOW2="debian-12-genericcloud-amd64.qcow2"
# OPNsense "dut" VM base image (nano, not cloud-init -- see provision-dut.sh).
# Must be "nano" (preinstalled, boots straight to console menu), not the
# same-version "serial" image (an installer/live image needing an
# install-to-disk step provision-dut.sh doesn't do) -- see README "dut".
OPNSENSE_VERSION="${OPNSENSE_VERSION:-25.7}"
OPNSENSE_IMG_BASE_URL="${OPNSENSE_IMG_BASE_URL:-https://pkg.opnsense.org/releases/${OPNSENSE_VERSION}}"
OPNSENSE_IMG_BZ2="OPNsense-${OPNSENSE_VERSION}-nano-amd64.img.bz2"
OPNSENSE_IMG_RAW="${OPNSENSE_IMG_BZ2%.bz2}"
# One combined checksum file per version, not co-located per-image (BSD-style
# "SHA256 (file) = hash" lines, like the FreeBSD CHECKSUM.SHA256 above).
OPNSENSE_IMG_SUMS="OPNsense-${OPNSENSE_VERSION}-checksums-amd64.sha256"
NAMES=("$@")
[ ${#NAMES[@]} -gt 0 ] || NAMES=(build client mpdsrv)

# 14.3 is always fetched (as before), plus any other release a named VM uses.
RELS="14.3"
for NAME in "${NAMES[@]}"; do
    vm_config "$NAME"
    if [ "$VM_IMG_TYPE" = freebsd ] && [[ " $RELS " != *" $VM_FREEBSD_REL "* ]]; then
        RELS="$RELS $VM_FREEBSD_REL"
    fi
done

for REL in $RELS; do
freebsd_img_vars "$REL"
host_ssh bash -s <<EOF
set -euo pipefail
mkdir -p "\$HOME/$LAB_DIR/images"
cd "\$HOME/$LAB_DIR/images"

if [ ! -f "$IMG_QCOW2" ]; then
    IMG_BASE_URL=""
    for u in $IMG_BASE_URLS; do
        if curl -fsSL --retry 3 -o /dev/null -r 0-0 "\$u/CHECKSUM.SHA256"; then IMG_BASE_URL="\$u"; break; fi
    done
    [ -n "\$IMG_BASE_URL" ] || { echo "no mirror serves $IMG_REL_PATH (tried: $IMG_BASE_URLS)" >&2; exit 1; }
    echo "Using \$IMG_BASE_URL"
    if [ ! -f "$IMG_XZ" ]; then
        echo "Fetching $IMG_XZ ..."
        curl -fSL -o "$IMG_XZ.part" "\$IMG_BASE_URL/$IMG_XZ"
        mv "$IMG_XZ.part" "$IMG_XZ"
    fi
    echo "Fetching $IMG_SUMS ..."
    curl -fSL -o "$IMG_SUMS.new" "\$IMG_BASE_URL/CHECKSUM.SHA256"
    mv "$IMG_SUMS.new" "$IMG_SUMS"

    want=\$(grep -F "($IMG_XZ)" "$IMG_SUMS" | awk '{print \$NF}')
    if [ -z "\$want" ]; then
        echo "checksum for $IMG_XZ not found in $IMG_SUMS" >&2
        exit 1
    fi
    got=\$(sha256sum "$IMG_XZ" | awk '{print \$1}')
    if [ "\$want" != "\$got" ]; then
        echo "SHA256 mismatch for $IMG_XZ: want \$want got \$got" >&2
        exit 1
    fi
    echo "Checksum OK: \$got"

    echo "Decompressing ..."
    unxz -k -f "$IMG_XZ"
else
    echo "$IMG_QCOW2 already present, skipping download."
fi

EOF
done

# Debian base image, downloaded only when one of the requested VMs needs it
# (currently: isp). Checksum verified against cloud.debian.org's SHA512SUMS.
# NB: verification runs even when the image already exists — a prior run that
# downloaded the image but died before/during checksumming must not leave an
# unverified base image silently trusted (this actually happened once: the
# SHA512SUMS fetch raced the checksum grep and the retry skipped the check).
NEED_DEB=""
for NAME in "${NAMES[@]}"; do
    vm_config "$NAME"
    if [ "$VM_IMG_TYPE" = debian ]; then NEED_DEB=1; fi
done
if [ -n "$NEED_DEB" ]; then
    host_ssh bash -s <<EOF
set -euo pipefail
cd "\$HOME/$LAB_DIR/images"
if [ ! -f "$DEB_QCOW2" ]; then
    echo "Fetching $DEB_QCOW2 ..."
    curl -fSL -o "$DEB_QCOW2.part" "$DEB_BASE_URL/$DEB_QCOW2"
    mv "$DEB_QCOW2.part" "$DEB_QCOW2"
fi
# "latest" moves: once an image is verified its hash is pinned in
# <image>.sha512 and later runs check the pin, not today's SHA512SUMS (other
# VMs' overlays are backed by this exact file — it must never be replaced).
got=\$(sha512sum "$DEB_QCOW2" | awk '{print \$1}')
if [ -f "$DEB_QCOW2.sha512" ]; then
    want=\$(cat "$DEB_QCOW2.sha512")
    [ "\$want" = "\$got" ] || { echo "SHA512 mismatch for $DEB_QCOW2 against its pin: want \$want got \$got" >&2; exit 1; }
    echo "Checksum OK (pinned): \$got"
    exit 0
fi
curl -fSL -o SHA512SUMS.new "$DEB_BASE_URL/SHA512SUMS"
mv SHA512SUMS.new SHA512SUMS
want=\$(awk -v f="$DEB_QCOW2" '\$NF == f {print \$1}' SHA512SUMS)
if [ -z "\$want" ]; then
    echo "checksum for $DEB_QCOW2 not found in SHA512SUMS" >&2
    exit 1
fi
if [ "\$want" != "\$got" ]; then
    echo "SHA512 mismatch for $DEB_QCOW2: want \$want got \$got" >&2
    exit 1
fi
echo "\$got" > "$DEB_QCOW2.sha512"
echo "Checksum OK: \$got (pinned)"
EOF
fi

# OPNsense base image: ships as a raw .img (bz2-compressed), not qcow2, so it
# needs converting before it can back a qcow2 overlay. One checksums file per
# version covers all its images (BSD-style "SHA256 (file) = hash" lines), not
# a co-located per-image "<img>.sha256".
if printf '%s\n' "${NAMES[@]}" | grep -qx dut; then
    host_ssh bash -s <<EOF
set -euo pipefail
cd "\$HOME/$LAB_DIR/images"
if [ ! -f "${OPNSENSE_IMG_RAW}.qcow2" ]; then
    if [ ! -f "$OPNSENSE_IMG_BZ2" ]; then
        echo "Fetching $OPNSENSE_IMG_BZ2 ..."
        curl -fSL -o "$OPNSENSE_IMG_BZ2.part" "$OPNSENSE_IMG_BASE_URL/$OPNSENSE_IMG_BZ2"
        mv "$OPNSENSE_IMG_BZ2.part" "$OPNSENSE_IMG_BZ2"
    fi
    echo "Fetching $OPNSENSE_IMG_SUMS ..."
    curl -fSL -o "$OPNSENSE_IMG_SUMS.new" "$OPNSENSE_IMG_BASE_URL/$OPNSENSE_IMG_SUMS"
    mv "$OPNSENSE_IMG_SUMS.new" "$OPNSENSE_IMG_SUMS"
    want=\$(grep -F "($OPNSENSE_IMG_BZ2)" "$OPNSENSE_IMG_SUMS" | awk '{print \$NF}')
    if [ -z "\$want" ]; then
        echo "checksum for $OPNSENSE_IMG_BZ2 not found in $OPNSENSE_IMG_SUMS" >&2
        exit 1
    fi
    got=\$(sha256sum "$OPNSENSE_IMG_BZ2" | awk '{print \$1}')
    if [ "\$want" != "\$got" ]; then
        echo "SHA256 mismatch for $OPNSENSE_IMG_BZ2: want \$want got \$got" >&2
        exit 1
    fi
    echo "Checksum OK: \$got"
    echo "Decompressing + converting to qcow2 ..."
    bzip2 -dk -f "$OPNSENSE_IMG_BZ2"
    qemu-img convert -f raw -O qcow2 "$OPNSENSE_IMG_RAW" "${OPNSENSE_IMG_RAW}.qcow2"
    rm -f "$OPNSENSE_IMG_RAW"
else
    echo "${OPNSENSE_IMG_RAW}.qcow2 already present, skipping download."
fi
EOF
fi

for NAME in "${NAMES[@]}"; do
    vm_config "$NAME"
    case "$VM_IMG_TYPE" in
        freebsd)  freebsd_img_vars "$VM_FREEBSD_REL"; BACKING="$IMG_QCOW2" ;;
        debian)   BACKING="$DEB_QCOW2" ;;
        opnsense) BACKING="${OPNSENSE_IMG_RAW}.qcow2" ;;
        *) echo "fetch-image.sh: unknown VM_IMG_TYPE '$VM_IMG_TYPE' for $NAME" >&2; exit 1 ;;
    esac
    host_ssh bash -s <<EOF
set -euo pipefail
cd "\$HOME/$LAB_DIR/images"
if [ ! -f "$VM_BASE_IMAGE" ]; then
    echo "Creating $VM_OVERLAY_SIZE overlay $VM_BASE_IMAGE (for $NAME) backed by $BACKING ..."
    qemu-img create -f qcow2 -F qcow2 -b "\$PWD/$BACKING" "$VM_BASE_IMAGE"
    qemu-img resize "$VM_BASE_IMAGE" $VM_OVERLAY_SIZE
else
    echo "$VM_BASE_IMAGE already present, skipping overlay creation."
fi
    qemu-img info --force-share "$VM_BASE_IMAGE"
EOF
done
