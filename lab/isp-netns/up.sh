#!/usr/bin/env bash
# Idempotent: creates br-isp bridge, netns `isp`, veth pair isp0(host)/eth0(ns),
# renders accel-ppp.conf, creates its tmpfs account dir /run/accel-ppp
# (empty: each run adds its own account), starts accel-pppd + iperf3 -s
# inside the netns. Never touches the host's own production trunk interface
# (PEER_TRUNK, default bond0) or any other existing host interface.
# Run on the lab host (see README.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETNS=isp
BRIDGE=br-isp
VETH_HOST=isp0
VETH_NS=eth0
NS_ADDR=10.99.0.1/24
PEER_VLAN="${PEER_VLAN:-}"
PEER_TRUNK="${PEER_TRUNK:-bond0}"
LABDIR="$SCRIPT_DIR"
CONF_TEMPLATE="$SCRIPT_DIR/accel-ppp.conf"
CONF_RENDERED="$SCRIPT_DIR/accel-ppp.rendered.conf"
PIDFILE=/run/accel-pppd-isp.pid
ACCEL_PPPD=/usr/local/sbin/accel-pppd

# `ip netns exec NS pgrep -x NAME` is NOT scoped to NS: it shares the host PID
# namespace, so it false-positives on a same-named process running anywhere
# else on the host. Scope by netns membership instead (`ip netns pids`).
netns_has_proc() {
	local ns="$1" comm="$2" pid
	for pid in $(sudo ip netns pids "$ns" 2>/dev/null); do
		[ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "$comm" ] && return 0
	done
	return 1
}

echo "== pppoe kernel module =="
sudo modprobe pppoe

echo "== bridge $BRIDGE =="
if ip link show "$BRIDGE" >/dev/null 2>&1; then
	echo "$BRIDGE already present"
else
	sudo ip link add "$BRIDGE" type bridge
	echo "created $BRIDGE"
fi
sudo ip link set "$BRIDGE" up

echo "== PEER_VLAN ${PEER_VLAN:-<unset>} on trunk $PEER_TRUNK =="
if [ -n "$PEER_VLAN" ]; then
	VLAN_IF="${PEER_TRUNK}.${PEER_VLAN}"

	if ! ip link show "$PEER_TRUNK" >/dev/null 2>&1; then
		echo "up.sh: PEER_TRUNK=$PEER_TRUNK does not exist" >&2
		exit 1
	fi

	if ip link show "$VLAN_IF" >/dev/null 2>&1; then
		echo "$VLAN_IF already present"
	else
		sudo ip link add link "$PEER_TRUNK" name "$VLAN_IF" type vlan id "$PEER_VLAN"
		echo "created $VLAN_IF"
	fi

	# A VLAN subinterface's MTU can never exceed its parent's (kernel-enforced);
	# this task must not raise $PEER_TRUNK's own MTU, so 1508 only if it's
	# already there -- see README.md's RFC 4638 caveat otherwise.
	TRUNK_MTU="$(cat "/sys/class/net/$PEER_TRUNK/mtu")"
	if [ "$TRUNK_MTU" -ge 1508 ]; then
		sudo ip link set dev "$VLAN_IF" mtu 1508
		echo "$VLAN_IF: MTU 1508 ($PEER_TRUNK MTU is $TRUNK_MTU)"
	else
		sudo ip link set dev "$VLAN_IF" mtu 1500
		echo "$VLAN_IF: MTU 1500 ($PEER_TRUNK MTU is $TRUNK_MTU, too small for 1508 -- no RFC 4638 headroom)"
	fi

	if ip -o link show "$VLAN_IF" | grep -q "master $BRIDGE"; then
		echo "$VLAN_IF already attached to $BRIDGE"
	else
		sudo ip link set dev "$VLAN_IF" master "$BRIDGE"
		echo "attached $VLAN_IF to $BRIDGE"
	fi
	sudo ip link set dev "$VLAN_IF" up
else
	echo "PEER_VLAN unset, skipping (behaviour identical to before Task 11)"
fi

echo "== netns $NETNS =="
if sudo ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
	echo "netns $NETNS already present"
else
	sudo ip netns add "$NETNS"
	echo "created netns $NETNS"
fi

echo "== veth pair $VETH_HOST/$VETH_NS =="
if ip link show "$VETH_HOST" >/dev/null 2>&1; then
	echo "$VETH_HOST already present"
else
	sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
	sudo ip link set "$VETH_HOST" master "$BRIDGE"
	sudo ip link set "$VETH_NS" netns "$NETNS"
	echo "created veth pair $VETH_HOST/$VETH_NS"
fi
sudo ip link set "$VETH_HOST" up
sudo ip netns exec "$NETNS" ip link set lo up
sudo ip netns exec "$NETNS" ip link set "$VETH_NS" up

if sudo ip netns exec "$NETNS" ip -4 -o addr show dev "$VETH_NS" | grep -q "${NS_ADDR}"; then
	echo "$VETH_NS already has $NS_ADDR"
else
	sudo ip netns exec "$NETNS" ip addr add "$NS_ADDR" dev "$VETH_NS"
	echo "assigned $NS_ADDR to $VETH_NS"
fi

echo "== rendering accel-ppp.conf (@LABDIR@ -> $LABDIR) =="
sed "s#@LABDIR@#$LABDIR#g" "$CONF_TEMPLATE" >"$CONF_RENDERED"

echo "== account dir /run/accel-ppp (tmpfs, filled per run) =="
sudo install -d -m 0700 /run/accel-ppp

echo "== accel-pppd =="
if netns_has_proc "$NETNS" accel-pppd; then
	echo "accel-pppd already running"
else
	sudo ip netns exec "$NETNS" "$ACCEL_PPPD" -c "$CONF_RENDERED" -p "$PIDFILE" -d
	sleep 1
	if netns_has_proc "$NETNS" accel-pppd; then
		echo "accel-pppd started"
	else
		echo "up.sh: accel-pppd failed to start, check the log-file set in accel-ppp.conf (/tmp/accel-ppp.log)" >&2
		exit 1
	fi
fi

echo "== iperf3 -s =="
if netns_has_proc "$NETNS" iperf3; then
	echo "iperf3 already running"
else
	sudo ip netns exec "$NETNS" iperf3 -s -D
	echo "iperf3 -s started"
fi

echo "up.sh: done"
