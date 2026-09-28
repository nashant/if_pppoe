#!/usr/bin/env bash
# router-mode.sh — client VM into router mode: LAN IP + forwarding + pf NAT on
# WAN=ng0/pppoe0/raw (raw = no-PPPoE baseline, vtnet1; see docs/PERF-FWD-DESIGN.md).
# Usage (from anywhere with ssh to VMHOST):
#   ./router-mode.sh enable ng0      # mpd5 WAN
#   ./router-mode.sh enable pppoe0   # if_pppoe WAN
#   ./router-mode.sh enable raw      # no-PPPoE baseline WAN (vtnet1)
#   ./router-mode.sh disable         # pf off, forwarding on (harmless)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

ACTION="${1:-}"; WAN_IF="${2:-}"
[ -n "$ACTION" ] || { echo "usage: $0 enable <ng0|pppoe0|raw> | disable" >&2; exit 1; }

if [ "$ACTION" = "disable" ]; then
    vm_ssh client 'echo | su -m root -c "pfctl -d" 2>/dev/null; true'
    echo "router-mode: pf disabled"
    exit 0
fi

[ "$ACTION" = "enable" ] || { echo "router-mode: unknown action '$ACTION'" >&2; exit 1; }
RAW_WAN=0
case "$WAN_IF" in
    ng0|pppoe0) ;;
    raw) RAW_WAN=1; WAN_IF="vtnet1" ;;
    *) echo "router-mode: WAN_IF must be ng0, pppoe0, or raw" >&2; exit 1 ;;
esac
# The PPPoE MSS clamp (1492 MTU - 40) would unfairly cap the no-PPPoE raw
# baseline's segment size below its real ceiling and bias the pppoe/raw
# throughput ratio favourably -- raw gets plain scrub, no clamp.
if [ "$RAW_WAN" -eq 1 ]; then
    SCRUB_LINE="scrub on $WAN_IF"
else
    SCRUB_LINE="scrub on $WAN_IF max-mss 1452"
fi

vm_ssh client sh -s <<EOF
set -euo pipefail
echo | su -m root -c "sysctl net.inet.ip.forwarding=1"
grep -q 'net.inet.ip.forwarding=1' /etc/sysctl.conf 2>/dev/null || \
    echo 'net.inet.ip.forwarding=1' | su -m root -c "tee -a /etc/sysctl.conf" >/dev/null
echo | su -m root -c "ifconfig vtnet2 192.168.77.2/24 up"
ifconfig vtnet2 | head -2
if [ $RAW_WAN -eq 1 ]; then
    echo | su -m root -c "ifconfig vtnet1 192.168.99.2/24 up"
    ifconfig vtnet1 | head -2
else
    # Drop a leftover raw-baseline alias from an earlier "enable raw" pass --
    # it would otherwise persist across backend passes (ifconfig aliases are
    # sticky until removed or reboot) and confuse a later raw-vs-pppoe compare.
    echo | su -m root -c "ifconfig vtnet1 192.168.99.2/24 -alias" 2>/dev/null || true
fi
echo | su -m root -c "kldload pf" 2>/dev/null || true
su -m root -c "kldstat -q -m pf" </dev/null || su -m root -c "kldstat -m pf" </dev/null || true
cat <<'PF' | su -m root -c "cat > /etc/pf.conf"
# lab router-mode pf.conf — mirrors production: NAT the LAN out the active
# WAN, clamp TCP MSS to the pppoe payload for a PPPoE WAN (pf scrub, as
# OPNsense/pfSense do), default pass.
set skip on lo
$SCRUB_LINE
nat on $WAN_IF from vtnet2:network to any -> ($WAN_IF)
pass all
PF
echo | su -m root -c "sysrc pf_enable=YES >/dev/null"
echo | su -m root -c "pfctl -f /etc/pf.conf"
echo | su -m root -c "pfctl -e" 2>/dev/null | head -1 || true   # rc 1 when already enabled (re-run)
su -m root -c "pfctl -si" </dev/null 2>/dev/null | head -2
EOF
echo "router-mode: enabled (WAN=$WAN_IF)"