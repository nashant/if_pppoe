#!/usr/bin/env bash
# provision-lan.sh — turn the `lan` VM into the router-mode iperf3 client:
# install iperf3 and configure the bridged NIC (MAC 52:54:00:aa:00:05) with
# 192.168.77.10/24, default route via the router VM (192.168.77.2), so its
# traffic traverses the DUT's pf+NAT+pppoe path like a production LAN host.
# Requires: `./run.sh lan up`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

apt_retry() {
    local attempt
    for attempt in 1 2 3 4 5 6; do
        if "$@"; then return 0; fi
        echo "provision-lan.sh: apt failed (attempt $attempt), retrying in 30s..." >&2
        sleep 30
    done
    echo "provision-lan.sh: apt failed after retries" >&2
    return 1
}

echo "== install iperf3 =="
apt_retry vm_ssh lan 'sudo apt-get update -q'
apt_retry vm_ssh lan 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3'

echo "== static LAN config (bridged NIC by MAC) =="
NIC="$(vm_ssh lan "grep -il '52:54:00:aa:00:05' /sys/class/net/*/address 2>/dev/null | cut -d/ -f5 | head -1")"
[ -n "$NIC" ] || { echo "provision-lan.sh: no LAN NIC with MAC 52:54:00:aa:00:05" >&2; exit 1; }
echo "LAN NIC: $NIC"
vm_ssh lan bash -s <<EOF
set -euo pipefail
sudo ip link set $NIC up
sudo ip addr replace 192.168.77.10/24 dev $NIC
# default route via the router VM's LAN port — this is what puts iperf
# traffic through the DUT's pf+NAT+pppoe path
sudo ip route replace default via 192.168.77.2
# persist for reboots (systemd-networkd drop-in; genericcloud image)
printf '[Match]\nMACAddress=52:54:00:aa:00:05\n\n[Network]\nAddress=192.168.77.10/24\nGateway=192.168.77.2\n' | sudo tee /etc/systemd/network/10-lan.network >/dev/null
ip -4 -o addr show $NIC | head -1
ip route | head -3
EOF
echo "provision-lan.sh: done"