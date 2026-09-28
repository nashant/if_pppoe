#!/usr/bin/env bash
# migrate-slot1.sh — ONE-TIME: move slot 1's `client` VM onto the slots-era
# run.sh launch (serial console socket + QEMU monitor + snapshot overlay).
# Never kills the guest (aborts if it won't power off), backs up client.qcow2
# first, and holds a slot-1 lease while it runs. Afterwards never boot slot
# 1's client with a pre-slots run.sh: it would write to the base image
# underneath the snapshot overlay. The loaded if_pppoe.ko does not survive.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export LAB_SLOT=1
source ./common.sh
vm_config client

TS="$(date -u +%Y%m%dT%H%M%SZ)"
say() { echo "=== migrate-slot1: $* ==="; }

say "[1/7] preflight"
host_ssh "test -f \"\$HOME/$LAB_DIR/images/client.golden\"" && {
    echo "client.golden already exists: slot 1 is already migrated (use run.sh client snapshot-save/-revert)." >&2
    exit 1; }
if host_ssh 'pgrep -af "pytest tests-functional([ /]|$)|tests-functional/(hardening|unload)_probe" | grep -v pgrep'; then
    echo "a slot-1 functional run is still going (above); wait for it to finish." >&2
    exit 1
fi
./slot.sh status
./slot.sh hold 1 "migrate-slot1.sh $TS" || {
    echo "slot 1 is leased by someone else (see status above); release it first when they are done." >&2
    exit 1; }
trap './slot.sh release 1' EXIT

say "[2/7] current guest state"
./run.sh client ssh -- 'uname -v; sysctl -n kern.ident net.isr.maxthreads net.isr.bindthreads; kldstat; cat /etc/rc.conf /boot/loader.conf'

say "[3/7] clean shutdown of the running client"
./run.sh client shutdown

say "[4/7] backup copy of client.qcow2"
host_ssh bash -s <<EOF
set -euo pipefail
cd "\$HOME/$LAB_DIR/images"
qemu-img check -q client.qcow2
cp --sparse=always client.qcow2 client.qcow2.pre-slots-$TS
ls -la client.qcow2 client.qcow2.pre-slots-$TS
sudo rm -f "\$HOME/$LAB_DIR/run/client.console.sock"   # hand-launch leftover
EOF

say "[5/7] boot with the new run.sh (console socket + monitor)"
./run.sh client up
./run.sh client ssh -- 'sysctl -n kern.ident net.isr.maxthreads net.isr.bindthreads'
./run.sh client monitor 'info status'

say "[6/7] snapshot-save (known-good = this disk)"
./run.sh client snapshot-save

say "[7/7] verify"
./run.sh client status
./run.sh client console-cmd '' 2 | tail -n 3
./run.sh client ssh -- 'uname -a; sysctl -n kern.ident'
echo
echo "migrate-slot1: done. Backup: $VMHOST:~/$LAB_DIR/images/client.qcow2.pre-slots-$TS (delete once happy)."
echo "Reload the module before testing: ./build-module.sh sync && ./build-module.sh deploy sys/modules/if_pppoe if_pppoe.ko && ./build-module.sh load if_pppoe.ko"
