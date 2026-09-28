#!/usr/bin/env bash
# smoke-vm.sh up|cycle BID|dial BID|down|report -- boot-smoke the built
# modules on an ubuntu KVM runner: one FreeBSD BASIC-CLOUDINIT guest per
# shard, then per build_id: install that OPNsense kernel set as
# /boot/kernel.<bid>, nextboot into it, run smoke-guest.sh module, record
# pass/fail. See docs/CI.md "Smoke". Each kernel's set and .ko are staged
# on their own: one that cannot be staged is left out of the shard (no
# result, or set-gone.txt when the mirror no longer has the set) and the
# rest still run.
# Env: FREEBSD_VERSION KERNELS_JSON ARTIFACT_DIR (kmods artifact:
#      ko/<bid>/if_pppoe.ko, bin/*) BUILD_IDS (up) KMOD_SRC_ID (cycle)
#      [SMOKE_RUN_URL] [REQUIRE_FEATURES] [IMAGE_CACHE] [SMOKE_DIR]
#      [BOOT_TIMEOUT] [MODULE_TIMEOUT]
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SMOKE_DIR=${SMOKE_DIR:-${RUNNER_TEMP:-/tmp}/if_pppoe-smoke}
IMAGE_CACHE=${IMAGE_CACHE:-$SMOKE_DIR/images}
SSH_PORT=${SSH_PORT:-2222}
SSH_USER=ci
BOOT_TIMEOUT=${BOOT_TIMEOUT:-300}
MODULE_TIMEOUT=${MODULE_TIMEOUT:-300}
RESULTS="$SMOKE_DIR/results.ndjson"
# The build_ids `up` staged (set + .ko pushed); `cycle` skips the others.
STAGED="$SMOKE_DIR/staged.txt"
LOGS="$SMOKE_DIR/logs"
# "bid version http-status" per kernel whose set the mirror answered 404/410
# for: compat.sh's GONE list (dropped with reason set-gone, not no-result).
GONE="$LOGS/set-gone.txt"
mkdir -p "$SMOKE_DIR" "$IMAGE_CACHE" "$LOGS"

common_opts=(-i "$SMOKE_DIR/id_ed25519" -o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5
	-o ServerAliveInterval=10 -o ServerAliveCountMax=3)
gssh() { ssh "${common_opts[@]}" -p "$SSH_PORT" "$SSH_USER@127.0.0.1" "$@"; }
# FreeBSD cloud images ship no sudo; root has no password, so su from a
# wheel member is the privileged path (same as lab/vm/build-kernel.sh).
groot() { gssh "echo | su -m root -c '$*'"; }
# groot with a wall-clock limit; rc 124 = timed out (hang), 255 = ssh lost.
groot_t() { # SECONDS CMD...
	local t=$1
	shift
	timeout "$t" ssh "${common_opts[@]}" -p "$SSH_PORT" "$SSH_USER@127.0.0.1" "echo | su -m root -c '$*'"
}
gput() { scp "${common_opts[@]}" -P "$SSH_PORT" -q "$@"; }

wait_ssh_rc() { # timeout_s -> 0 when ssh answers, 1 on timeout
	local deadline=$((SECONDS + $1))
	until gssh true 2>/dev/null; do
		[ "$SECONDS" -lt "$deadline" ] || return 1
		sleep 3
	done
}

wait_ssh() { # timeout_s; guest must come up or the shard is an infra failure
	wait_ssh_rc "$1" && return 0
	echo "smoke-vm: no ssh after $1s" >&2
	tail -n 50 "$SMOKE_DIR/serial.log" >&2 || true
	exit 1
}

wait_ssh_down_rc() { # timeout_s
	local deadline=$((SECONDS + $1))
	while gssh true 2>/dev/null; do
		[ "$SECONDS" -lt "$deadline" ] || return 1
		sleep 2
	done
}

# QEMU monitor (unix socket): hard reset a panicked/hung guest. nextboot is
# one-shot, so the reset boot comes back on GENERIC.
qmon() { # COMMAND
	python3 - "$SMOKE_DIR/mon" "$1" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sys.argv[1])
time.sleep(0.3)
try:
    s.recv(4096)
except OSError:
    pass
s.sendall((sys.argv[2] + "\n").encode())
time.sleep(0.5)
s.close()
EOF
}

reset_guest() { # why
	echo "::warning::smoke-vm: $1; resetting the guest"
	qmon system_reset
	wait_ssh 600
	echo "smoke-vm: back on $(gssh 'sysctl -n kern.bootfile') after reset"
}

kjson() { # BID FIELD
	jq -er --arg b "$1" --arg f "$2" 'first(.[] | select(.build_id == $b)) | .[$f]' "$KERNELS_JSON"
}

fetch_image() {
	local base="https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_VERSION}-RELEASE/amd64/Latest"
	local xz="FreeBSD-${FREEBSD_VERSION}-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
	IMG="$SMOKE_DIR/${xz%.xz}"
	# IMAGE_CACHE keeps only the .xz (actions/cache); re-verified every run.
	if [ ! -f "$IMAGE_CACHE/$xz" ]; then
		curl -fsSL --retry 3 -o "$IMAGE_CACHE/$xz.part" "$base/$xz"
		mv "$IMAGE_CACHE/$xz.part" "$IMAGE_CACHE/$xz"
	fi
	curl -fsSL --retry 3 -o "$IMAGE_CACHE/CHECKSUM.SHA256" "$base/CHECKSUM.SHA256"
	local want got
	want=$(grep -F "($xz)" "$IMAGE_CACHE/CHECKSUM.SHA256" | awk '{print $NF}')
	got=$(sha256sum "$IMAGE_CACHE/$xz" | awk '{print $1}')
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		echo "smoke-vm: checksum mismatch for $xz ($want vs $got)" >&2
		exit 1
	fi
	xz -dc "$IMAGE_CACHE/$xz" > "$IMG"
}

# One kernel set, fetched on the runner and checked against the sha256
# that discovery recorded in kernels.json. 0 = staged; 1 = not staged, no
# result (infra: network, checksum, missing .ko -- the merge fails a
# supported ABI on it); 2 = the mirror no longer has the set (404/410), so
# the kernel cannot be smoked and is dropped (a set kept by discovery's
# --union). A cached pass for this kmod_src is never re-planned, so this
# only hits kernels whose .ko is untested: they are not shipped untested.
fetch_set() { # BID
	local bid=$1 url want got code rc=0 ver dst
	url=$(kjson "$bid" url)
	want=$(kjson "$bid" sha256)
	ver=$(kjson "$bid" version)
	dst="$SMOKE_DIR/sets/$bid.txz"
	if [ ! -f "$ARTIFACT_DIR/ko/$bid/if_pppoe.ko" ]; then
		echo "::error::smoke-vm: kmods artifact has no ko/$bid/if_pppoe.ko ($ver); not smoked"
		return 1
	fi
	# No -f: the status is needed to tell "gone" from a transient failure.
	code=$(curl -sSL --retry 3 -o "$dst" -w '%{http_code}' "$url") || rc=$?
	case "$rc:$code" in
	0:200) ;;
	0:404 | 0:410)
		rm -f "$dst"
		echo "::warning::smoke-vm: $ver ($bid): $url is gone (HTTP $code); dropped, not smoked"
		echo "$bid $ver $code" >> "$GONE"
		return 2
		;;
	*)
		rm -f "$dst"
		echo "::error::smoke-vm: $ver ($bid): fetching $url failed (curl rc $rc, HTTP ${code:-none}); not smoked"
		return 1
		;;
	esac
	got=$(sha256sum "$dst" | awk '{print $1}')
	if [ "$want" != "$got" ]; then
		rm -f "$dst"
		echo "::error::smoke-vm: $ver ($bid): $url sha256 $got != kernels.json $want; not smoked"
		return 1
	fi
	echo "smoke-vm: $ver $bid <- $url"
}

fetch_sets() {
	local bid
	mkdir -p "$SMOKE_DIR/sets"
	: > "$STAGED"
	for bid in $BUILD_IDS; do
		if fetch_set "$bid"; then echo "$bid" >> "$STAGED"; fi
	done
}

staged() { grep -qxF "$1" "$STAGED" 2>/dev/null; }

cmd_up() {
	: "${FREEBSD_VERSION:?}" "${KERNELS_JSON:?}" "${ARTIFACT_DIR:?}" "${BUILD_IDS:?}"
	rm -f "$RESULTS" "$GONE"
	fetch_sets
	if [ ! -s "$STAGED" ]; then
		echo "::warning::smoke-vm: no kernel of this shard could be staged; guest not booted"
		return 0
	fi
	fetch_image
	qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" "$SMOKE_DIR/disk.qcow2" 12G

	rm -f "$SMOKE_DIR/id_ed25519"*
	ssh-keygen -q -t ed25519 -N '' -f "$SMOKE_DIR/id_ed25519"
	mkdir -p "$SMOKE_DIR/seed"
	cat > "$SMOKE_DIR/seed/user-data" <<EOF
#cloud-config
hostname: smoke
users:
  - name: $SSH_USER
    groups: wheel
    shell: /bin/sh
    ssh_authorized_keys:
      - $(cat "$SMOKE_DIR/id_ed25519.pub")
ssh_pwauth: false
EOF
	printf 'instance-id: smoke\nlocal-hostname: smoke\n' > "$SMOKE_DIR/seed/meta-data"
	genisoimage -quiet -output "$SMOKE_DIR/seed.iso" -volid cidata -joliet -rock \
		"$SMOKE_DIR/seed/user-data" "$SMOKE_DIR/seed/meta-data"

	local accel=kvm cpu=host
	[ -w /dev/kvm ] || { echo "::warning::/dev/kvm not writable; falling back to TCG (slow)"; accel=tcg; cpu=max; }
	rm -f "$SMOKE_DIR/mon"
	qemu-system-x86_64 -name smoke -machine q35,accel="$accel" -cpu "$cpu" -smp 2 -m 2048 \
		-drive file="$SMOKE_DIR/disk.qcow2",if=virtio,format=qcow2 \
		-drive file="$SMOKE_DIR/seed.iso",if=virtio,media=cdrom \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 \
		-device virtio-net-pci,netdev=n0 \
		-serial file:"$SMOKE_DIR/serial.log" -display none \
		-monitor unix:"$SMOKE_DIR/mon",server,nowait \
		-daemonize -pidfile "$SMOKE_DIR/qemu.pid"
	wait_ssh 600
	echo "smoke-vm: first boot: $(gssh uname -a)"

	local bid
	gssh 'mkdir -p /tmp/ci/bin /tmp/ci/sets'
	gput "$HERE/smoke-guest.sh" "$SSH_USER@127.0.0.1:/tmp/ci/"
	gput "$ARTIFACT_DIR"/bin/* "$SSH_USER@127.0.0.1:/tmp/ci/bin/"
	gput "$SMOKE_DIR"/sets/*.txz "$SSH_USER@127.0.0.1:/tmp/ci/sets/"
	while read -r bid; do
		gssh "mkdir -p /tmp/ci/ko/$bid"
		gput "$ARTIFACT_DIR/ko/$bid/if_pppoe.ko" "$SSH_USER@127.0.0.1:/tmp/ci/ko/$bid/"
	done < "$STAGED"
	gssh 'chmod +x /tmp/ci/bin/*'
	rm -rf "$SMOKE_DIR/sets"
}

record() { # BID RESULT DETAIL
	local ko_sha
	ko_sha=$(sha256sum "$ARTIFACT_DIR/ko/$1/if_pppoe.ko" | awk '{print $1}')
	jq -nc --arg b "$1" --arg r "$2" --arg d "$3" --arg v "$(kjson "$1" version)" \
		--arg abi "$(kjson "$1" abi)" --arg k "$KMOD_SRC_ID" --arg ko "$ko_sha" \
		--arg run "${SMOKE_RUN_URL:-}" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{build_id: $b, kmod_src: $k, version: $v, abi: $abi, result: $r, detail: $d,
		  ko_sha256: $ko, run: $run, at: $at}' >> "$RESULTS"
	if [ "$2" = pass ]; then
		echo "smoke-vm: PASS $1 ($(kjson "$1" version))"
	else
		echo "::warning::smoke-vm: FAIL $1 ($(kjson "$1" version)): $3"
	fi
}

detail_of() { # LOGFILE DEFAULT
	local d
	d=$(sed -n 's/^smoke-guest: DETAIL=//p' "$1" | tail -n 1)
	echo "${d:-$2}"
}

# One kernel: install, nextboot, reboot, verify, module check. A kernel or
# module failure is recorded and the cycle returns 0 (the next bid runs); a
# guest that does not come back even on GENERIC exits non-zero (infra).
cycle_one() { # BID LOG
	local bid=$1 log=$2 rc=0 d
	groot_t 120 sh /tmp/ci/smoke-guest.sh install-kernel "$bid" 2>&1 | tee "$log" || rc=$?
	[ "$rc" = 0 ] || { record "$bid" fail "$(detail_of "$log" install)"; return 0; }

	groot shutdown -r now || true
	wait_ssh_down_rc 120 || reset_guest "guest did not go down for reboot"
	if ! wait_ssh_rc "$BOOT_TIMEOUT"; then
		reset_guest "kernel $bid did not boot within ${BOOT_TIMEOUT}s"
		record "$bid" fail boot
		return 0
	fi
	groot_t 60 sh /tmp/ci/smoke-guest.sh verify-kernel "$bid" 2>&1 | tee -a "$log" || rc=$?
	[ "$rc" = 0 ] || { record "$bid" fail "$(detail_of "$log" boot)"; return 0; }

	groot_t "$MODULE_TIMEOUT" "REQUIRE_FEATURES=${REQUIRE_FEATURES:-1} sh /tmp/ci/smoke-guest.sh module $bid" \
		2>&1 | tee -a "$log" || rc=$?
	case "$rc" in 124 | 255) ;; *) gssh dmesg > "$LOGS/dmesg-$bid.txt" 2>/dev/null || true ;; esac
	case "$rc" in
	0) record "$bid" pass "" ;;
	124 | 255)
		# Timed out (124) or lost ssh (255). Still up on the same kernel
		# after a lost session: the session died, not the kernel.
		if [ "$rc" = 255 ] && wait_ssh_rc 20 \
			&& [ "$(gssh 'sysctl -n kern.build_id' 2>/dev/null)" = "$bid" ]; then
			record "$bid" fail "$(detail_of "$log" ssh)"
			return 0
		fi
		[ "$rc" = 124 ] && d=hang || d=panic
		# A panic that auto-reboots comes back on GENERIC by itself.
		wait_ssh_rc 60 || reset_guest "kernel $bid: module step $d"
		record "$bid" fail "$d"
		;;
	*) record "$bid" fail "$(detail_of "$log" module)" ;;
	esac
}

cmd_cycle() {
	local bid=${1:?cycle BUILD_ID} off
	: "${KERNELS_JSON:?}" "${ARTIFACT_DIR:?}" "${KMOD_SRC_ID:?}"
	if ! staged "$bid"; then
		echo "::notice::smoke-vm: $bid was not staged by up; no cycle"
		return 0
	fi
	off=$(stat -c %s "$SMOKE_DIR/serial.log" 2>/dev/null || echo 0)
	echo "::group::smoke $(kjson "$bid" version) ($bid)"
	cycle_one "$bid" "$LOGS/cycle-$bid.log"
	echo "::endgroup::"
	tail -c +$((off + 1)) "$SMOKE_DIR/serial.log" > "$LOGS/serial-$bid.log" 2>/dev/null || true
}

# Best effort, on the shard's newest kernel when its cycle passed and the
# guest is still running it (it is the last cycle, see smoke-plan.sh).
cmd_dial() {
	local bid=${1:?dial BUILD_ID}
	jq -e --arg b "$bid" 'select(.build_id == $b and .result == "pass")' "$RESULTS" > /dev/null 2>&1 \
		|| { echo "::notice::smoke-vm: $bid did not pass its cycle; dial skipped"; return 0; }
	[ "$(gssh 'sysctl -n kern.build_id')" = "$bid" ] \
		|| { echo "::notice::smoke-vm: guest is not running $bid; dial skipped"; return 0; }
	groot sh /tmp/ci/smoke-guest.sh dial "$bid"
}

cmd_down() {
	gssh 'dmesg' > "$LOGS/dmesg.txt" 2>/dev/null || true
	groot shutdown -p now 2>/dev/null || true
	local pid
	pid=$(cat "$SMOKE_DIR/qemu.pid" 2>/dev/null || true)
	if [ -n "$pid" ]; then
		for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
		kill "$pid" 2>/dev/null || true
	fi
	cp "$SMOKE_DIR/serial.log" "$LOGS/serial.log" 2>/dev/null || true
	rm -rf "$SMOKE_DIR"/*.qcow2 "$SMOKE_DIR/id_ed25519" "$SMOKE_DIR/sets" "$SMOKE_DIR/mon"
}

# compat-part.json (compat.json schema 1) from this shard's results; bids
# that never reached record() are absent, i.e. "missing" to compat.sh.
cmd_report() {
	local out=${1:-$LOGS/compat-part.json}
	if [ -s "$RESULTS" ]; then
		jq -s '{schema: 1, results: .}' "$RESULTS" > "$out"
	else
		echo '{"schema":1,"results":[]}' > "$out"
	fi
	jq -r '.results[] | "| \(.version) | `\(.build_id)` | \(.result) | \(.detail) |"' "$out"
}

case "${1:-}" in
up) cmd_up ;;
cycle) cmd_cycle "${2:-}" ;;
dial) cmd_dial "${2:-}" ;;
down) cmd_down ;;
report) cmd_report "${2:-}" ;;
*) echo "usage: $0 up|cycle BUILD_ID|dial BUILD_ID|down|report [OUT]" >&2; exit 1 ;;
esac
