#!/usr/bin/env bash
# provision-dut.sh [--scrub-seed] -- first-boot config for the `dut` OPNsense
# VM; boots it (refuses if already running). Normally called by
# plugin-roundtrip.sh with per-run credentials in the ENVIRONMENT, never argv:
#   DUT_SSH_KEY (ephemeral private key on tmpfs; .pub is root's only key),
#   DUT_API_KEY, DUT_API_SECRET, DUT_PPPOE_PASSWORD, DUT_PPPOE_USERNAME,
#   and LAB_RUN_DRIVE (the run's throwaway qcow2 overlay of images/dut.qcow2
#   on $VMHOST tmpfs, which run.sh boots instead of the base: the seeded
#   config.xml lands only there); optional DUT_CONSOLE_LOG (default: next
#   to DUT_SSH_KEY).
# Invariant: no secret is printed or lands on any disk. config.xml goes
# make-dut-seed.py stdout -> ssh -> $VMHOST /dev/shm; images/$VM_CONFIG_ISO
# is only a symlink to that tmpfs ISO until the console step consumes it,
# then the seed is shredded and the path becomes an empty placeholder ISO
# (volid DUTSPENT) so a later `run.sh dut up` still has its cdrom.
# --scrub-seed runs only that scrub (plugin-roundtrip.sh's teardown).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

vm_config dut

# $VMHOST-side paths. /dev/shm is tmpfs on Linux; checked before use.
R_SEED_DIR="/dev/shm/${LAB_DIR//\//_}-dut-seed"
R_SEED_LINK="\$HOME/$LAB_DIR/images/$VM_CONFIG_ISO"

SEED_SCRUBBED=0
scrub_seed() {
    [ "$SEED_SCRUBBED" = 1 ] && return 0
    # Shred the tmpfs seed (config.xml + ISO), then replace the images/ path
    # with an empty placeholder ISO. A regular file there (a placeholder, or a
    # seed ISO from before this scheme) is shredded too, never trusted.
    host_ssh bash -s <<EOF
set -u
d="$R_SEED_DIR"
img="$R_SEED_LINK"
if [ -d "\$d" ]; then
    find "\$d" -type f -exec shred -u {} + 2>/dev/null
    rm -rf "\$d"
fi
mkdir -p "\$(dirname "\$img")"
if [ -L "\$img" ]; then rm -f "\$img"
elif [ -f "\$img" ]; then shred -u "\$img" 2>/dev/null || rm -f "\$img"
fi
e="\$(mktemp -d)"
genisoimage -output "\$img" -volid DUTSPENT -joliet -rock "\$e" >/dev/null 2>&1 \
    || echo "provision-dut.sh: placeholder ISO build failed (run.sh dut up will miss its cdrom)" >&2
rmdir "\$e"
EOF
    SEED_SCRUBBED=1
}

if [ "${1:-}" = "--scrub-seed" ]; then
    scrub_seed
    echo "seed scrubbed on $VMHOST"
    exit 0
fi

missing=()
for v in DUT_SSH_KEY DUT_API_KEY DUT_API_SECRET DUT_PPPOE_PASSWORD DUT_PPPOE_USERNAME LAB_RUN_DRIVE; do
    [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "provision-dut.sh: missing env ${missing[*]} -- run ./plugin-roundtrip.sh, which generates them per run" >&2
    exit 2
fi
[ -f "$DUT_SSH_KEY" ] && [ -f "$DUT_SSH_KEY.pub" ] || { echo "provision-dut.sh: DUT_SSH_KEY / .pub not found" >&2; exit 2; }
KEY_DIR="$(dirname "$DUT_SSH_KEY")"
if [ "$(stat -f -c %T "$KEY_DIR")" != "tmpfs" ]; then
    echo "provision-dut.sh: $KEY_DIR is not tmpfs; the ephemeral key must never touch disk" >&2
    exit 2
fi
# The seeded config.xml must never reach the base image's persistent disk:
# refuse unless the drive run.sh will boot is a tmpfs file on $VMHOST.
case "$LAB_RUN_DRIVE" in
    /*) ;;
    *) echo "provision-dut.sh: LAB_RUN_DRIVE must be an absolute path on $VMHOST" >&2; exit 2 ;;
esac
if ! host_ssh "test -f '$LAB_RUN_DRIVE' && [ \"\$(stat -f -c %T '$(dirname "$LAB_RUN_DRIVE")')\" = tmpfs ]"; then
    echo "provision-dut.sh: LAB_RUN_DRIVE $LAB_RUN_DRIVE is missing or not on tmpfs on $VMHOST" >&2
    exit 2
fi
export LAB_RUN_DRIVE   # a path, not a secret: run.sh below boots it
CONSOLE_LOG="${DUT_CONSOLE_LOG:-$KEY_DIR/dut-console.log}"

if host_ssh "test -f \"\$HOME/$LAB_DIR/$VM_RUN_DIR/$VM_NAME.pid\" && sudo kill -0 \"\$(sudo cat \"\$HOME/$LAB_DIR/$VM_RUN_DIR/$VM_NAME.pid\")\"" 2>/dev/null; then
    echo "provision-dut.sh: dut is already running -- run './run.sh dut down' first." >&2
    echo "(re-seeding a running VM's disk doesn't reach it)" >&2
    exit 1
fi

trap scrub_seed EXIT

echo "== building seed ISO on $VMHOST tmpfs ($R_SEED_DIR) =="
host_ssh bash -s <<EOF
set -euo pipefail
[ "\$(stat -f -c %T /dev/shm)" = tmpfs ] || { echo "/dev/shm on $VMHOST is not tmpfs" >&2; exit 1; }
rm -rf "$R_SEED_DIR"
mkdir -m 700 "$R_SEED_DIR"
EOF
# config.xml travels make-dut-seed.py stdout -> ssh stdin -> tmpfs file.
python3 make-dut-seed.py --pubkey-file "$DUT_SSH_KEY.pub" --pppoe-username "$DUT_PPPOE_USERNAME" \
    | host_ssh "umask 077 && cat > '$R_SEED_DIR/config.xml'"
host_ssh bash -s <<EOF
set -euo pipefail
umask 077
d="$R_SEED_DIR"
img="$R_SEED_LINK"
grep -q '</opnsense>' "\$d/config.xml" || { echo "seed config.xml truncated" >&2; exit 1; }
# provision's console step mounts this by GEOM's iso9660 LABEL class
# (/dev/iso9660/DUTSEED) -- the volid must keep matching that mount.
(cd "\$d" && genisoimage -output dut-seed.iso -volid DUTSEED -joliet -rock config.xml >/dev/null 2>&1)
shred -u "\$d/config.xml"
mkdir -p "\$(dirname "\$img")"
if [ -f "\$img" ] && [ ! -L "\$img" ]; then shred -u "\$img"; fi
ln -sfn "\$d/dut-seed.iso" "\$img"
EOF

echo "== booting dut =="
./run.sh dut up

: > "$CONSOLE_LOG"
SOCK_PATH="$LAB_DIR/$VM_RUN_DIR/$VM_CONSOLE_SOCK"   # relative to $VMHOST's $HOME, per run.sh

echo "== driving the console: root login -> opnsense-shell -> 8) Shell (log: $CONSOLE_LOG) =="
# The nano image boots to getty's `login:` on ttyu0, not to the menu: root's
# login shell is opnsense-shell, so log in with the FACTORY DEFAULT password
# `opnsense` (public, documented; not a secret -- the seeded config.xml
# replaces it with a locked '*' and key-only ssh). Then, per opnsense/core
# 25.7.11 src/sbin/opnsense-shell: "Enter an option: " -> 8 = Shell
# (/bin/csh). `exec /bin/sh` so the commands below are sh, not csh. Each
# shell's root prompt ends in "# "; wait for it so no typeahead is lost.
#
# The NIC check asserts qemu's order (run.sh: n0 user-mode, n1 = WAN,
# n2 = LAN) is the vtnetN order dut-config.xml.tmpl assigns, by MAC.
# Mounts by GEOM's iso9660 LABEL, not a /dev/cdN guess: the seed disk is
# attached if=virtio (run.sh), which FreeBSD enumerates as vtbd, not cdN.
# Markers are split (printf '%s' A B): the tty echoes what we SEND before
# the shell runs it, so a marker spelled out whole in the command would
# match on that echo alone, before the copy even ran.
# Reboot is core's own /usr/local/etc/rc.reboot (what menu 6's reboot.php
# runs after its y/N prompt); its first ">>> Invoking stop script" line
# proves the reboot actually started (the echo of the command can't match).
NIC_CHECK="m1=\$(ifconfig vtnet1 ether | awk '/ether/{print \$2}'); m2=\$(ifconfig vtnet2 ether | awk '/ether/{print \$2}'); echo vtnet1=\$m1 vtnet2=\$m2; if [ \"\$m1\" = $VM_BR_MAC ] && [ \"\$m2\" = $VM_BR_MAC2 ]; then printf 'DUTSEED_%s\\n' NICS_OK; else printf 'DUTSEED_%s\\n' NICS_MISMATCH; fi"
python3 console_driver.py \
    --vmhost "$VMHOST" --sock "$SOCK_PATH" --log "$CONSOLE_LOG" --connect-timeout 300 \
    --boot-timeout 300 --boot-nudge-after 20 \
    --fail-marker "Login incorrect" --fail-marker "DUTSEED_NICS_MISMATCH" \
    --fail-marker "DUTSEED_COPY_FAILED" \
    "login:" "root" \
    "Password:" "opnsense" \
    "Enter an option:" "8" \
    "# " "exec /bin/sh" \
    "# " "printf 'DUTSEED_%s\n' SHELL_READY" \
    "DUTSEED_SHELL_READY" "$NIC_CHECK" \
    "DUTSEED_NICS_OK" \
    "mount -t cd9660 -o ro /dev/iso9660/DUTSEED /mnt && cp /mnt/config.xml /conf/config.xml && umount /mnt && printf 'DUTSEED_%s\n' COPY_DONE || printf 'DUTSEED_%s\n' COPY_FAILED" \
    "DUTSEED_COPY_DONE" "/usr/local/etc/rc.reboot" \
    "Invoking stop script" ""

# The first boot has consumed the seed: remove it from $VMHOST now, not at
# the end of the run. qemu keeps its already-open fd; the guest no longer
# needs it (config.xml is on /conf).
echo "== seed consumed; shredding it on $VMHOST =="
scrub_seed

DUT_LAN_IP="192.168.90.2"   # dut-config.xml.tmpl's <lan><ipaddr> -- keep in sync
echo "== waiting for sshd on the seeded config (LAN bridge, root@$DUT_LAN_IP) =="
tries=0
until ssh -J "$VMHOST" -i "$DUT_SSH_KEY" -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o BatchMode=yes "root@$DUT_LAN_IP" true 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -ge 90 ]; then
        echo "Timed out waiting for ssh on $DUT_LAN_IP after ${tries}x2s." >&2
        echo "Check the console transcript: $CONSOLE_LOG" >&2
        exit 1
    fi
    sleep 2
done

echo
echo "dut is up: root@$DUT_LAN_IP, ephemeral-key auth only (no root password)."
