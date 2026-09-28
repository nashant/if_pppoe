#!/usr/bin/env bash
# provision-isp.sh — turn the Linux `isp` VM into the lab's ISP side:
# accel-ppp PPPoE server (same config as the isp-netns server) + iperf3.
#
# This replaces the lab host's isp-netns accel-pppd with a dedicated Linux VM
# so the server side has no pppoe threading/namespace entanglement with the
# test harness host. Session semantics are unchanged: same service-name "lab",
# ac-name "isp-lab", 10.99.0.x pool with gw 10.99.0.1, MTU/MRU 1492 — so
# dialling code and the functional suite are untouched.  No account is
# provisioned: chap-secrets= points at tmpfs (/run/accel-ppp/chap-secrets),
# where each run installs and removes its own generated one
# (tests/functional/labcreds.py, lab/vm/lab-creds.sh).
#
# Log-path compatibility: the functional suite reads the accel log at
# /tmp/accel-ppp.log on the lab host (tests/functional/lab.py:189). The VM's
# accel-pppd writes its log through the run.sh virtio-9p share onto
# $VMHOST:$LAB_DIR/isp-share/accel-ppp.log, and a symlink /tmp/accel-ppp.log
# -> that file keeps every suite log read working unchanged (see switch-isp).
#
# Usage (from anywhere with ssh to VMHOST): ./provision-isp.sh
# Requires: `./run.sh isp up` already succeeded.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

CONF_TEMPLATE=../isp-netns/accel-ppp.conf
ACCEL_TAG=1.14.0
BR_MAC_ISP=52:54:00:aa:00:03

apt_retry() {  # $@ = apt args; dpkg lock is shared with any other agent on the VM
    local attempt
    for attempt in 1 2 3 4 5 6; do
        if "$@"; then return 0; fi
        echo "provision-isp.sh: apt failed (attempt $attempt), retrying in 30s..." >&2
        sleep 30
    done
    echo "provision-isp.sh: apt failed after retries" >&2
    return 1
}

echo "== install build deps + iperf3 =="
apt_retry vm_ssh isp 'sudo apt-get update -q'
apt_retry vm_ssh isp 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    build-essential cmake libpcre2-dev libssl-dev git iperf3'

echo "== Debian generic kernel (the cloud kernel has no 9p module) =="
if ! vm_ssh isp 'uname -r' | grep -qv cloud; then
    apt_retry vm_ssh isp 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q linux-image-amd64'
    # Purge the (running) cloud kernel so grub can only boot the generic one;
    # preseed "don't abort removing the running kernel" or the purge fails.
    vm_ssh isp 'echo "linux-base linux-base/removing-running-kernel boolean false" | sudo debconf-set-selections'
    vm_ssh isp 'sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "linux-image-*cloud*"'
    vm_ssh isp 'sudo systemctl reboot' || true
    sleep 10
    tries=0
    until vm_ssh isp true 2>/dev/null; do
        tries=$((tries + 1)); [ "$tries" -lt 90 ] || { echo "isp did not come back after reboot" >&2; exit 1; }
        sleep 2
    done
    echo "booted $(vm_ssh isp 'uname -r')"
fi

echo "== build accel-ppp $ACCEL_TAG (same recipe as isp-netns/install-accel-ppp.sh) =="
vm_ssh isp bash -s <<EOF
set -euo pipefail
if [ ! -d "\$HOME/accel-ppp-src/.git" ]; then
    git clone -q https://github.com/accel-ppp/accel-ppp "\$HOME/accel-ppp-src"
fi
cd "\$HOME/accel-ppp-src"
git fetch -q --tags origin
git checkout -q "$ACCEL_TAG"
echo "accel-ppp commit: \$(git rev-parse HEAD)"
mkdir -p build && cd build
cmake -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE \
      -DRADIUS=FALSE -DSHAPER=FALSE -DCMAKE_INSTALL_PREFIX=/usr/local .. >/dev/null
make -j"\$(nproc)" >/dev/null
sudo make install >/dev/null
sudo ldconfig
EOF

echo "== mount virtio-9p host share =="
vm_ssh isp bash -s <<EOF
set -euo pipefail
sudo modprobe 9pnet_virtio 9p 9pnet 2>/dev/null || true
sudo mkdir -p /mnt/host
if ! mountpoint -q /mnt/host; then
    sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
fi
grep -q hostshare /etc/fstab 2>/dev/null || \
    echo 'hostshare /mnt/host 9p trans=virtio,version=9p2000.L,_netdev,nofail 0 0' | sudo tee -a /etc/fstab >/dev/null
touch /mnt/host/.isp-write-test && rm -f /mnt/host/.isp-write-test
echo "9p share mounted at /mnt/host (backed by $VMHOST:\$HOME/$LAB_DIR/$VM_VIRTFS_DIR)"
EOF

echo "== render + install accel-ppp.conf (accounts: per run, on tmpfs) =="
# Bridged NIC discovery: Debian names virtio NICs predictably; find the one
# carrying the reserved br-isp MAC rather than guessing ens3/ens4.
NIC="$(vm_ssh isp "grep -il '$BR_MAC_ISP' /sys/class/net/*/address 2>/dev/null | cut -d/ -f5 | head -1")"
[ -n "$NIC" ] || { echo "provision-isp.sh: no NIC with MAC $BR_MAC_ISP found on the VM" >&2; exit 1; }
echo "bridged NIC: $NIC"

RENDERED="$(mktemp)"
sed -e "s#@LABDIR@#/etc/accel-ppp#g" \
    -e "s#^interface=eth0#interface=$NIC#" \
    -e "s#^log-file=/tmp/accel-ppp.log#log-file=/mnt/host/accel-ppp.log#" \
    "$CONF_TEMPLATE" > "$RENDERED"
grep -E "^(interface|log-file)" "$RENDERED"

vm_ssh isp 'sudo mkdir -p /etc/accel-ppp'
vm_ssh isp 'sudo tee /etc/accel-ppp.conf >/dev/null' < "$RENDERED"
grep -qx 'chap-secrets=/run/accel-ppp/chap-secrets' "$RENDERED" || {
    echo "provision-isp.sh: accel-ppp.conf chap-secrets= must be the tmpfs path" >&2; exit 1; }
# The pre-tmpfs on-disk account file, if an older provision left one.
vm_ssh isp 'sudo rm -f /etc/accel-ppp/chap-secrets'
rm -f "$RENDERED"

echo "== start accel-pppd + iperf3 =="
vm_ssh isp bash -s <<EOF
set -euo pipefail
sudo ip link set $NIC up
# Old accel-pppd must exit first: while it holds 2001 the new one's CLI bind
# fails silently (cli/tcp.c) and its exit unlinks our pidfile (main.c).
# -x, not -f: -f also matches the "sudo pkill -f accel-pppd" parent.
sudo pkill -x accel-pppd 2>/dev/null || true
for _ in \$(seq 1 50); do pgrep -x accel-pppd >/dev/null || break; sleep 0.2; done
if pgrep -x accel-pppd >/dev/null; then
    echo "provision-isp.sh: old accel-pppd did not exit after SIGTERM" >&2; exit 1
fi
sudo rm -f /run/accel-pppd.pid
sudo /usr/local/sbin/accel-pppd -c /etc/accel-ppp.conf -p /run/accel-pppd.pid -d
pgrep -a -x accel-pppd
# The suite drives the server through this CLI: fail the provision, not a
# later test, if it is not answering.
for _ in \$(seq 1 25); do
    /usr/local/bin/accel-cmd -H 127.0.0.1 -P 2001 show version >/dev/null 2>&1 && break
    sleep 0.2
done
/usr/local/bin/accel-cmd -H 127.0.0.1 -P 2001 show version >/dev/null ||
    { echo "provision-isp.sh: accel-pppd CLI (127.0.0.1:2001) not answering" >&2; exit 1; }
echo "accel-pppd CLI answering on 127.0.0.1:2001"
pgrep -x iperf3 >/dev/null || sudo iperf3 -s -D
sleep 1
ss -ltn | grep 5201 && echo "iperf3 -s listening"
EOF

echo "provision-isp.sh: done. Session log lands on the host via 9p:"
echo "  $VMHOST:\$HOME/$LAB_DIR/$VM_VIRTFS_DIR/accel-ppp.log"