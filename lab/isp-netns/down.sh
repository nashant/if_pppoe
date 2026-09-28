#!/usr/bin/env bash
# Tears down everything up.sh created: accel-pppd, iperf3, netns `isp`,
# veth pair, br-isp bridge. Never touches the host's own production trunk
# interface (PEER_TRUNK, default bond0) or any other existing host
# interface. Safe to run when some/all pieces are already gone.
# Kills are scoped via `ip netns pids`, not `pkill` -- see README.md
# "Deviations from brief".
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETNS=isp
BRIDGE=br-isp
VETH_HOST=isp0
PIDFILE=/run/accel-pppd-isp.pid
CONF_RENDERED="$SCRIPT_DIR/accel-ppp.rendered.conf"
PEER_VLAN="${PEER_VLAN:-}"
PEER_TRUNK="${PEER_TRUNK:-bond0}"

kill_netns_pids() {
	local ns="$1" pids
	pids="$(sudo ip netns pids "$ns" 2>/dev/null || true)"
	[ -z "$pids" ] && return 0
	echo "$pids" | xargs -r sudo kill 2>/dev/null || true
	local i
	for i in 1 2 3 4 5; do
		pids="$(sudo ip netns pids "$ns" 2>/dev/null || true)"
		[ -z "$pids" ] && return 0
		sleep 1
	done
	pids="$(sudo ip netns pids "$ns" 2>/dev/null || true)"
	if [ -n "$pids" ]; then
		echo "down.sh: SIGKILL stragglers in netns $ns: $pids" >&2
		echo "$pids" | xargs -r sudo kill -9 2>/dev/null || true
	fi
}

echo "== PEER_VLAN ${PEER_VLAN:-<unset>} on trunk $PEER_TRUNK =="
if [ -n "$PEER_VLAN" ]; then
	VLAN_IF="${PEER_TRUNK}.${PEER_VLAN}"
	if ip link show "$VLAN_IF" >/dev/null 2>&1; then
		sudo ip link del "$VLAN_IF"
		echo "removed $VLAN_IF (also detaches it from $BRIDGE)"
	else
		echo "$VLAN_IF not present, nothing to do"
	fi
fi

echo "== stopping processes in netns $NETNS (accel-pppd, iperf3) =="
kill_netns_pids "$NETNS"

echo "== removing netns $NETNS (also removes eth0 + its veth peer isp0) =="
sudo ip netns del "$NETNS" 2>/dev/null || true

echo "== removing veth $VETH_HOST (in case it survived) =="
sudo ip link del "$VETH_HOST" 2>/dev/null || true

echo "== removing bridge $BRIDGE =="
sudo ip link del "$BRIDGE" 2>/dev/null || true

echo "== removing stale pidfile + rendered conf + tmpfs accounts =="
sudo rm -f "$PIDFILE" "$CONF_RENDERED"
sudo rm -rf /run/accel-ppp

echo "down.sh: done"
