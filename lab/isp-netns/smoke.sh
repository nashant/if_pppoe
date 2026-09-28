#!/usr/bin/env bash
# Smoke test: brings up a temporary netns `cli` with a veth pair into br-isp,
# runs a PPPoE client (pppd + pppoe.so plugin) against the `isp` accel-pppd
# server for ~10s, confirms IPCP assigned an address from the 10.99.0.100-199
# pool, then tears the `cli` netns down. Leaves `isp` running.
# The account is generated for this run, added to accel-ppp's tmpfs
# chap-secrets and handed to pppd via a tmpfs `file` (pppd(8): "file name --
# Read options from file name"), never argv; cleanup removes both.
set -uo pipefail

BRIDGE=br-isp
CLI_NS=cli
CLI_VETH_HOST=cli0
# Not "eth0": collides with isp's eth0 MAC (persistent-MAC-by-name udev
# policy) -- see README.md "Deviations from brief".
CLI_VETH_NS=cli-eth0
LOGFILE=/tmp/smoke-pppd.log
PPPD_PLUGIN=pppoe.so
SECRETS=/run/accel-ppp/chap-secrets
LAB_USER="labrun-s1-$(openssl rand -hex 4)"  # the netns is slot 1's accel
LAB_PASS="$(openssl rand -hex 16)"
OPTS=""

cleanup() {
	echo "== cleanup: tearing down $CLI_NS =="
	# Scoped via `ip netns pids`, not `pkill -x pppd`: `ip netns exec` shares
	# the host PID namespace, so a name-matching pkill here could also hit an
	# unrelated pppd elsewhere on the host -- see README.md "Deviations from brief".
	local pids
	pids="$(sudo ip netns pids "$CLI_NS" 2>/dev/null || true)"
	if [ -n "$pids" ]; then
		echo "$pids" | xargs -r sudo kill 2>/dev/null || true
		sleep 1
		pids="$(sudo ip netns pids "$CLI_NS" 2>/dev/null || true)"
		[ -n "$pids" ] && echo "$pids" | xargs -r sudo kill -9 2>/dev/null || true
	fi
	sudo ip netns del "$CLI_NS" 2>/dev/null || true
	sudo ip link del "$CLI_VETH_HOST" 2>/dev/null || true
	[ -z "$OPTS" ] || sudo rm -f "$OPTS"
	if sudo test -f "$SECRETS"; then
		sudo sh -c 'grep -v "^$1[[:space:]]" "$2" > "$2.tmp" || true; mv "$2.tmp" "$2"' sh "$LAB_USER" "$SECRETS"
	fi
}
trap cleanup EXIT

echo "== creating $CLI_NS netns + veth into $BRIDGE =="
sudo ip netns add "$CLI_NS"
sudo ip link add "$CLI_VETH_HOST" type veth peer name "$CLI_VETH_NS"
sudo ip link set "$CLI_VETH_HOST" master "$BRIDGE"
sudo ip link set "$CLI_VETH_HOST" up
sudo ip link set "$CLI_VETH_NS" netns "$CLI_NS"
sudo ip netns exec "$CLI_NS" ip link set lo up
sudo ip netns exec "$CLI_NS" ip link set "$CLI_VETH_NS" up

echo "== this run's account: accel-ppp tmpfs chap-secrets + pppd tmpfs options file =="
sudo install -d -m 0700 /run/accel-ppp
printf '%s * %s *\n' "$LAB_USER" "$LAB_PASS" |
	sudo sh -c 'umask 077; cat >> "$1"' sh "$SECRETS"
OPTS="$(sudo mktemp /run/smoke-pppd.XXXXXX)"
printf 'user %s\npassword %s\n' "$LAB_USER" "$LAB_PASS" | sudo sh -c 'cat > "$1"' sh "$OPTS"

echo "== running pppd client (~10s) =="
sudo rm -f "$LOGFILE"
sudo ip netns exec "$CLI_NS" timeout 12 pppd \
	plugin "$PPPD_PLUGIN" "$CLI_VETH_NS" \
	file "$OPTS" noauth nodetach debug \
	>"$LOGFILE" 2>&1
STATUS=$?

echo "== pppd log ($LOGFILE) =="
sudo cat "$LOGFILE" || true

if sudo grep -qE "local[[:space:]]+IP address 10\.99\.0\.1[0-9][0-9]" "$LOGFILE" 2>/dev/null; then
	echo "SMOKE TEST: PASS -- IPCP assigned an address from the 10.99.0.100-199 pool"
	exit 0
else
	echo "SMOKE TEST: FAIL -- no IPCP address from pool found in $LOGFILE (pppd exit=$STATUS)"
	exit 1
fi
