#!/bin/sh
# smoke-guest.sh install-kernel|verify-kernel|module|dial|ctl-contract BUILD_ID
# -- runs as root INSIDE the smoke-test FreeBSD guest (driven by
# smoke-vm.sh), once per OPNsense kernel. smoke-vm.sh pushes
# /tmp/ci/{sets/<bid>.txz,ko/<bid>/if_pppoe.ko,bin/*}. On a failure the
# last "smoke-guest: DETAIL=<code>" line names the step for compat.json.
set -eu

CI=/tmp/ci
PPPOECTL="$CI/bin/pppoectl"
# kern.features the plugin's boot hook requires (plugin lib.sh
# IF_PPPOE_FEATURES). Enforced by default: a kernel whose .ko does not
# declare them is refused at boot anyway. REQUIRE_FEATURES=0 only warns.
FEATURES="linkevents ipv6 mssfix pfil_pass_foreign single_bytecount"

log() { echo "smoke-guest: $*"; }
fail() { # DETAIL MESSAGE
	echo "smoke-guest: DETAIL=$1"
	echo "smoke-guest: FAIL: $2" >&2
	dmesg | tail -n 30 >&2 || true
	exit 1
}

bid_arg() { # BUILD_ID -> sets BID and KO
	BID=${1:?BUILD_ID}
	printf '%s' "$BID" | grep -Eqx '[0-9a-f]{40}' || fail usage "not a build_id: $BID"
	KO="$CI/ko/$BID/if_pppoe.ko"
}

cmd_install_kernel() {
	# Official OPNsense kernel as an alternate kernel next to the stock one
	# (same approach as the lab client VM, lab/vm/provision-client.sh);
	# nextboot makes it one-shot so a kernel that panics or hangs falls back
	# to GENERIC on the next (reset) boot.
	set_file=$CI/sets/$BID.txz
	[ -f "$set_file" ] || fail install "no kernel set $set_file"
	# Keep the disk small: drop every earlier per-bid kernel dir except the
	# one we are running from.
	running=$(dirname "$(sysctl -n kern.bootfile)")
	for d in /boot/kernel.*; do
		[ -d "$d" ] || continue
		case "${d#/boot/kernel.}" in *[!0-9a-f]* | '') continue ;; esac
		[ "$d" = "$running" ] || rm -rf "$d"
	done
	rm -rf "$CI/kset" "/boot/kernel.$BID"
	mkdir -p "$CI/kset"
	tar -xf "$set_file" -C "$CI/kset" || fail install "extract $set_file"
	mv "$CI/kset/boot/kernel" "/boot/kernel.$BID"
	rm -rf "$CI/kset" "$set_file"
	nextboot -k "kernel.$BID" || fail install "nextboot -k kernel.$BID"
	log "kernel.$BID installed; nextboot set"
}

cmd_verify_kernel() {
	have=$(sysctl -n kern.build_id)
	log "uname: $(uname -v)"
	log "kern.bootfile=$(sysctl -n kern.bootfile) kern.build_id=$have"
	[ "$have" = "$BID" ] || fail boot "running kernel build_id $have != $BID"
}

cmd_module() {
	[ "$(sysctl -n kern.build_id)" = "$BID" ] || fail boot "not running kernel $BID"
	[ -f "$KO" ] || fail usage "no $KO"
	kldstat -q -m if_pppoe && fail kldload "if_pppoe already loaded before test"
	kldload -v "$KO" || fail kldload "kldload $KO"
	kldstat -q -n if_pppoe.ko || fail kldload "kldstat does not show if_pppoe.ko"
	log "loaded: $(kldstat -v -n if_pppoe.ko | head -n 1)"

	missing=""
	for f in $FEATURES; do
		v=$(sysctl -n "kern.features.if_pppoe_$f" 2>/dev/null || echo absent)
		log "kern.features.if_pppoe_$f=$v"
		[ "$v" = 1 ] || missing="$missing $f"
	done
	if [ -n "$missing" ]; then
		if [ "${REQUIRE_FEATURES:-1}" = 1 ]; then
			fail "feature-$(printf '%s' "${missing# }" | tr ' ' ',')" "missing kern.features:$missing"
		fi
		echo "::warning::if_pppoe kern.features not declared:$missing"
	fi

	ifconfig pppoe0 create || fail clone "ifconfig pppoe0 create"
	ifconfig pppoe0 || fail clone "ifconfig pppoe0"
	"$PPPOECTL" pppoe0 || fail pppoectl "pppoectl pppoe0 (SPPP ioctl ABI)"
	ifconfig pppoe0 destroy || fail clone "ifconfig pppoe0 destroy"
	ifconfig pppoe0 >/dev/null 2>&1 && fail clone "pppoe0 still present after destroy"

	cmd_ctl_contract

	kldunload if_pppoe || fail kldunload "kldunload if_pppoe"
	kldstat -q -m if_pppoe && fail kldunload "if_pppoe still loaded after kldunload"
	log "module load/clone/destroy/unload OK"
}

# ctl-contract: replays the engine-vs-real-pppoectl fixtures (see
# plugin/net/if-pppoe/tests/engine/{ctl_contract_fixtures.php,
# ctl-contract-replay.sh}) against this guest's own pppoectl. smoke-vm.sh
# does not push $CI/ctl-contract/ + $CI/ctl-contract-replay.sh yet, so
# until it does this is a documented no-op, not a hard smoke requirement.
cmd_ctl_contract() {
	if [ ! -d "$CI/ctl-contract" ] || [ ! -f "$CI/ctl-contract-replay.sh" ]; then
		log "ctl-contract fixtures not staged under $CI, skipping"
		return 0
	fi
	# This guest has only one NIC (vtnet0, smoke-vm.sh's -netdev/-device pair, and
	# it carries the ssh session): an epair stands in for a parent, as cmd_dial's
	# jailed mpd5 test does, rather than PPPOESETPARMS-ing a nonexistent vtnet1
	# (ENXIO) or the live ssh interface.
	epair=$(ifconfig epair create)
	ifconfig "$epair" up
	rc=0
	sh "$CI/ctl-contract-replay.sh" "$CI/ctl-contract" "$epair" pppoe8 "$PPPOECTL" ifconfig || rc=1
	ifconfig "$epair" destroy
	[ "$rc" = 0 ] || fail ctl-contract "ctl-contract replay"
}

cmd_dial() {
	# One PAP dial against mpd5 in a VNET jail across an epair; mirrors the
	# lab's mpdsrv config (lab/vm/provision-mpdsrv.sh), minus IPv6CP.
	export ASSUME_ALWAYS_YES=yes
	pkg install -q -y mpd5 >/dev/null || fail dial "pkg install mpd5"
	kldstat -q -m if_pppoe || kldload "$KO"
	epair=$(ifconfig epair create)
	peer="${epair%a}b"
	ifconfig "$epair" up
	jail -c name=pppsrv path=/ vnet vnet.interface="$peer" persist host.hostname=pppsrv
	trap 'cleanup_dial "$epair"' EXIT
	jexec pppsrv ifconfig "$peer" up
	# The PAP secret is generated per run and only ever lives in memory and
	# on a tmpfs mounted over $CI/mpd (mpd5 reads mpd.secret from its -d
	# config dir); cleanup_dial unmounts it, so it never reaches the disk.
	secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
	[ "${#secret}" -eq 32 ] || fail dial "could not generate a PAP secret"
	mkdir -p "$CI/mpd"
	mount -t tmpfs -o mode=0700 tmpfs "$CI/mpd" || fail dial "mount tmpfs on $CI/mpd"
	cat > "$CI/mpd/mpd.conf" <<EOF
startup:

default:
	load ci

ci:
	create bundle template B
	set ipcp ranges 10.99.2.1/32 10.99.2.100/24

	create link template L1 pppoe
	set link action bundle B
	set link disable eap chap
	set link enable pap
	set link keep-alive 10 60
	set link mtu 1492
	set link mru 1492
	set auth enable internal
	set pppoe iface $peer
	set pppoe service "ci"
	set link enable incoming
EOF
	(umask 077 && printf 'ci\t%s\t10.99.2.100/24\n' "$secret" > "$CI/mpd/mpd.secret")
	jexec pppsrv /usr/local/sbin/mpd5 -b -d "$CI/mpd" -p "$CI/mpd/mpd.pid" \
		|| fail dial "mpd5 did not start"
	sleep 2

	ifconfig pppoe0 create
	"$PPPOECTL" -e "$epair" -s ci pppoe0
	# -S: the secret goes in on stdin, never on argv.
	printf '%s\n' "$secret" | "$PPPOECTL" -S pppoe0 myauthproto=pap myauthname=ci \
		|| fail dial "pppoectl -S (PAP credentials)"
	unset secret
	ifconfig pppoe0 down
	ifconfig pppoe0 up
	i=0
	until ifconfig pppoe0 | grep -q 'inet 10\.99\.2\.'; do
		i=$((i + 1))
		[ "$i" -le 45 ] || { ifconfig pppoe0; "$PPPOECTL" pppoe0 || true; fail dial "no IPCP address after 45s"; }
		sleep 1
	done
	ifconfig pppoe0
	ping -c 3 -t 10 10.99.2.1 || fail dial "ping across the PPPoE session"
	log "PPPoE dial OK"
}

cleanup_dial() {
	ifconfig pppoe0 destroy 2>/dev/null || true
	if [ -f "$CI/mpd/mpd.pid" ]; then
		jexec pppsrv kill "$(cat "$CI/mpd/mpd.pid")" 2>/dev/null || true
	fi
	jail -r pppsrv 2>/dev/null || true
	umount -f "$CI/mpd" 2>/dev/null || true
	ifconfig "$1" destroy 2>/dev/null || true
}

cmd=${1:-}
case "$cmd" in
install-kernel | verify-kernel | module | dial | ctl-contract) bid_arg "${2:-}" ;;
*) echo "usage: $0 install-kernel|verify-kernel|module|dial|ctl-contract BUILD_ID" >&2; exit 1 ;;
esac
case "$cmd" in
install-kernel) cmd_install_kernel ;;
verify-kernel) cmd_verify_kernel ;;
module) cmd_module ;;
dial) cmd_dial ;;
ctl-contract) kldstat -q -m if_pppoe || kldload "$KO"; cmd_ctl_contract ;;
esac
