#!/usr/bin/env bash
# provision-isp-raw.sh — add 192.168.99.1/24 (isp side of the "raw" no-PPPoE
# baseline; pairs with router-mode.sh enable raw) to the isp VM's bridged NIC.
# accel-pppd binds by interface name not address, so this is harmless to it.
# Requires ./provision-isp.sh already run. Idempotent. See docs/PERF-FWD-DESIGN.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

BR_MAC_ISP=52:54:00:aa:00:03

NIC="$(vm_ssh isp "grep -il '$BR_MAC_ISP' /sys/class/net/*/address 2>/dev/null | cut -d/ -f5 | head -1")"
[ -n "$NIC" ] || { echo "provision-isp-raw.sh: no NIC with MAC $BR_MAC_ISP found on the VM" >&2; exit 1; }
echo "bridged NIC: $NIC"

vm_ssh isp bash -s <<EOF
set -euo pipefail
sudo ip addr replace 192.168.99.1/24 dev $NIC
sudo ip link set $NIC up
ip -4 -o addr show $NIC
EOF
echo "provision-isp-raw.sh: done (192.168.99.1/24 on $NIC, alongside accel-ppp)"
