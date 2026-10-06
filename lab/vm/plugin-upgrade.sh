#!/usr/bin/env bash
# shellcheck disable=SC2016  # the remote scripts below are single-quoted on purpose
# plugin-upgrade.sh -- the plugin's upgrade prefetch across a REAL OPNsense major upgrade
# (26.1 -> 26.7, FreeBSD:14 -> FreeBSD:15) on `dut`. Design, inputs, the isp-side upstream
# NAT it adds/removes and the assertions: lab/vm/README.md "plugin-upgrade.sh".
# Invariant: no secret on argv or outside tmpfs (same scheme as plugin-roundtrip.sh).
set -euo pipefail
ORIG_PWD="$PWD"
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
# shellcheck source=lab-creds.sh
source ./lab-creds.sh   # _lab_creds_sq, LAB_CREDS_ACCEL_DIR
# shellcheck source=dut-lib.sh
source ./dut-lib.sh     # vm_config dut, DUT_*, dut_ssh, dut_account_*, dut_repo_*, dut_make_overlay

ME=plugin-upgrade.sh
die() { echo "$ME: $*" >&2; exit 1; }
step() { echo; echo "== [$(date -u +%H:%M:%S)] $* =="; }

for t in openssl ssh-keygen python3 shred jq sha256sum; do
    command -v "$t" >/dev/null || { echo "$ME: need $t" >&2; exit 2; }
done

abspath() { case "$1" in /*) echo "$1" ;; *) echo "$ORIG_PWD/$1" ;; esac; }

# -- inputs ------------------------------------------------------------------
[ -n "${IFPPPOE_REPO_TARBALL:-}" ] || die "set IFPPPOE_REPO_TARBALL (FreeBSD:14 repo.tar.gz of the branch under test; README \"plugin-upgrade.sh\")"
[ -n "${IFPPPOE_REPO_SIGNING_PUBKEY_PATH:-}" ] || die "set IFPPPOE_REPO_SIGNING_PUBKEY_PATH (the .pub that signed IFPPPOE_REPO_TARBALL)"
IFPPPOE_REPO_TARBALL="$(abspath "$IFPPPOE_REPO_TARBALL")"
IFPPPOE_REPO_SIGNING_PUBKEY_PATH="$(abspath "$IFPPPOE_REPO_SIGNING_PUBKEY_PATH")"
[ -f "$IFPPPOE_REPO_TARBALL" ] || die "IFPPPOE_REPO_TARBALL $IFPPPOE_REPO_TARBALL not found"
[ -f "$IFPPPOE_REPO_SIGNING_PUBKEY_PATH" ] || die "IFPPPOE_REPO_SIGNING_PUBKEY_PATH $IFPPPOE_REPO_SIGNING_PUBKEY_PATH not found"

UPGRADE_FROM="${UPGRADE_FROM:-26.1}"
case "$UPGRADE_FROM" in
    26.1) DEFAULT_IMAGE="OPNsense-26.1.6-nano-amd64.img.qcow2"; LEGS="26.7" ;;
    25.7) DEFAULT_IMAGE="$VM_BASE_IMAGE"; LEGS="26.1 26.7" ;;   # dut.qcow2, as plugin-roundtrip.sh
    *) die "UPGRADE_FROM must be 26.1 or 25.7 (got '$UPGRADE_FROM')" ;;
esac
UPGRADE_BASE_IMAGE="${UPGRADE_BASE_IMAGE:-$DEFAULT_IMAGE}"   # under $LAB_DIR/images on $VMHOST
UPGRADE_DUT_WAN_IP="${UPGRADE_DUT_WAN_IP:-10.99.0.250}"      # outside accel's 10.99.0.100-199 pool
PUBLISHED_REPO_BASE="${PUBLISHED_REPO_BASE:-https://nashant.github.io/if_pppoe}"
PUBLISHED_VERSION="${PUBLISHED_VERSION:-0.5.2}"
FROM_ABI="FreeBSD:14:amd64"
TARGET_ABI="FreeBSD:15:amd64"
PREFETCH_DIR="/var/cache/if_pppoe/prefetch"
PREFETCH_READY_LINE="${PREFETCH_READY_LINE:-abi-heal: prefetch: ready in $PREFETCH_DIR/${TARGET_ABI//:/-}}"
UPDATE_TIMEOUT="${UPDATE_TIMEOUT:-3600}"            # one minor-update run (s)
UPGRADE_STAGE_TIMEOUT="${UPGRADE_STAGE_TIMEOUT:-3600}"   # opnsense-update -u fetch + syshook (s)
UPGRADE_REBOOT_TIMEOUT="${UPGRADE_REBOOT_TIMEOUT:-2700}" # -B/-P reboots up to the final boot (s)
BOOT_TIMEOUT="${BOOT_TIMEOUT:-900}"
UPGRADE_OUT_DIR="$(abspath "${UPGRADE_OUT_DIR:-plugin-upgrade-out/$(date -u +%Y%m%dT%H%M%SZ)}")"
OUT="$UPGRADE_OUT_DIR"
mkdir -p "$OUT"

if dut_is_running; then
    die "dut is already running -- run './run.sh dut down' first."
fi
host_ssh "test -f \"\$HOME/$LAB_DIR/images/$UPGRADE_BASE_IMAGE\"" \
    || die "$VMHOST:$LAB_DIR/images/$UPGRADE_BASE_IMAGE missing (README \"plugin-upgrade.sh\": fetch-image.sh)"

RUNDIR="$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/if_pppoe-dut.XXXXXX")"
chmod 700 "$RUNDIR"
R_OVL_DIR=""
R_REPO_DIR=""
REPO_SERVER_STARTED=0
ACCOUNT_ADDED=0
PROVISIONED=0
UPSTREAM_ON=0
CAPTURE_SSH_PID=""
CAPTURE_TS_PID=""
DUT_PPPOE_USERNAME=""
STAGE="setup"
FAILS=()
T_START=$(date +%s)

# -- the dut's upstream: NAT on the lab isp VM, scoped to dut's pinned PPPoE address. The isp
# reaches the internet through its own qemu user-mode NIC, so $VMHOST's networking is untouched.
# $1 dut ip, $2 isp ppp gw (dut's IPCP DNS), $3 optional upstream DNS (default: isp's resolver).
_ISP_UPSTREAM_ON='set -eu
dut=$1; gw=$2; dns=${3:-}; table=if_pppoe_upgrade; state=/run/if_pppoe-upgrade.forward
up=$(ip -4 route show default | awk "{print \$5; exit}")
[ -n "$up" ] || { echo "isp: no IPv4 default route (user-mode NIC down?)" >&2; exit 3; }
if [ -z "$dns" ]; then
    dns=$(awk "/^nameserver [0-9.]+\$/ {print \$2}" /etc/resolv.conf | grep -v "^127\\." | head -n 1 || true)
fi
[ -n "$dns" ] || dns=10.0.2.3
if ! command -v nft >/dev/null; then
    echo "isp: installing nftables" >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables >/dev/null
fi
# a SIGKILLed run left its state file: keep the value from before THAT run
[ -f "$state" ] || sysctl -n net.ipv4.ip_forward > "$state"
prev=$(cat "$state")
if [ "$prev" = 1 ]; then
    fwd="oifname \"$up\" ip saddr != $dut drop
    iifname \"$up\" ip daddr != $dut drop"
else
    fwd="ip saddr != $dut ip daddr != $dut drop"
fi
nft delete table ip $table 2>/dev/null || true
nft -f - <<EOF
table ip $table {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    ip saddr $dut ip daddr $gw udp dport 53 dnat to $dns
    ip saddr $dut ip daddr $gw tcp dport 53 dnat to $dns
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $dut oifname "$up" masquerade
  }
  chain dut_forward {
    type filter hook forward priority filter; policy accept;
    $fwd
  }
}
EOF
sysctl -qw net.ipv4.ip_forward=1
echo "isp upstream on: $dut -> $up (masquerade), DNS $gw:53 -> $dns, ip_forward was $prev"'

_ISP_UPSTREAM_OFF='set -u
table=if_pppoe_upgrade; state=/run/if_pppoe-upgrade.forward
nft delete table ip $table 2>/dev/null || true
if [ -f "$state" ]; then sysctl -qw net.ipv4.ip_forward="$(cat "$state")"; rm -f "$state"; fi
echo "isp upstream off: table $table removed, ip_forward=$(sysctl -n net.ipv4.ip_forward)"'

isp_upstream_on() {
    UPSTREAM_ON=1   # before: a half-done setup is still undone at exit
    vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_ISP_UPSTREAM_ON") sh $UPGRADE_DUT_WAN_IP $LAB_ISP_PPP_GW ${UPGRADE_UPSTREAM_DNS:-}" </dev/null
}

# shellcheck disable=SC2329  # called from teardown (a trap)
isp_upstream_off() {
    vm_ssh "$ISP_VM" "sudo sh -c $(_lab_creds_sq "$_ISP_UPSTREAM_OFF")" </dev/null
}

# -- dut helpers --------------------------------------------------------------
# dut_sh [args]: stdin is a /bin/sh script run as root on dut (args must be plain words).
dut_sh() { dut_ssh "/bin/sh -s -- $*"; }

boottime() { dut_ssh "sysctl -n kern.boottime" 2>/dev/null | sed -n 's/.*sec = \([0-9]*\),.*/\1/p'; }

# api_call METHOD PATH [JSON]: the OPNsense API on dut's loopback. The key and secret go to
# curl as a config file on ssh stdin (-K -), never on any argv.
api_call() {
    local method="$1" path="$2" data="${3:-}"
    {
        printf 'user = "%s:%s"\n' "$DUT_API_KEY" "$DUT_API_SECRET"
        printf 'url = "https://127.0.0.1%s"\n' "$path"
        printf 'request = "%s"\n' "$method"
        if [ -n "$data" ]; then
            printf 'header = "Content-Type: application/json"\n'
            printf 'data = "%s"\n' "$(printf '%s' "$data" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        fi
    } | dut_ssh "curl -sS -k -f --max-time 120 -K -"
}

# wait_boot <old boottime> <timeout s>: a new kern.boottime, then rc.bootup done (core src/etc/rc runs it under flock on /var/run/booting, which is never removed).
wait_boot() {
    local old="$1" timeout="$2" t0 now
    t0=$(date +%s)
    while :; do
        now="$(boottime || true)"
        if [ -n "$now" ] && [ "$now" != "$old" ] && dut_ssh "/usr/local/bin/flock -n /var/run/booting true" 2>/dev/null; then
            echo "dut up again: kern.boottime $now (after $(( $(date +%s) - t0 ))s)"
            return 0
        fi
        [ $(( $(date +%s) - t0 )) -lt "$timeout" ] || die "no new, finished boot within ${timeout}s (last console lines: $OUT/console.log)"
        sleep 10
    done
}

# wait_wan: pppoe0 has the pinned address, default route via pppoe0, the gw answers.
wait_wan() {
    local tries=0 addr
    until dut_ssh "netstat -rn -f inet | grep -q '^default.*pppoe0'" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -lt 60 ] || { dut_ssh "ifconfig pppoe0; netstat -rn -f inet" >&2 || true; die "no default route via pppoe0 after ${tries}x3s"; }
        sleep 3
    done
    addr="$(dut_ssh "ifconfig pppoe0 inet" | awk '/inet /{print $2; exit}')"
    [ "$addr" = "$UPGRADE_DUT_WAN_IP" ] \
        || die "pppoe0 has '$addr', not the pinned $UPGRADE_DUT_WAN_IP (accel chap-secrets ip field) -- the isp NAT only covers that address"
    dut_ssh "ping -c2 -t5 $LAB_ISP_PPP_GW" >/dev/null || die "PPPoE peer $LAB_ISP_PPP_GW does not answer"
    echo "WAN up: pppoe0 $addr, default via pppoe0, peer $LAB_ISP_PPP_GW answers"
}

# net_check: the OPNsense mirror (pkg update) and the published plugin repo are reachable.
net_check() {
    local n=0
    until dut_sh "$PUBLISHED_REPO_BASE" >/dev/null 2>&1 <<'EOF'
set -e
fetch -q -T 30 -o /dev/null "$1/"
pkg update -f -r OPNsense
EOF
    do
        n=$((n + 1))
        [ "$n" -lt 6 ] || die "dut has no internet (pkg update -r OPNsense / fetch $PUBLISHED_REPO_BASE/ failing) -- see the isp upstream line above"
        sleep 20
    done
    echo "internet OK: OPNsense mirror + $PUBLISHED_REPO_BASE reachable from dut"
}

# fw_run <label> <timeout s> <configctl firmware action...>: what the GUI's firmware buttons
# run (Api/FirmwareController.php: `firmware flush` then the action, under launcher.sh's flock
# on /tmp/pkg_upgrade.progress). Waits for ***DONE*** / ***REBOOT***; sets FW_RESULT, FW_BOOT.
fw_run() {
    local label="$1" timeout="$2"; shift 2
    local t0 log="$OUT/$label.progress.log" content="" c nb n=0
    until dut_ssh "/usr/local/bin/flock -n /tmp/pkg_upgrade.progress true" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 60 ] || die "$label: firmware lock still held after 10 min"
        sleep 10
    done
    FW_BOOT="$(boottime)"
    # the launcher truncates the log itself; emptying it first (idle: lock free) means no
    # marker from an earlier run can be mistaken for this one's
    dut_ssh "cp /dev/null /tmp/pkg_upgrade.progress; configctl firmware flush >/dev/null; configctl firmware $*" >/dev/null
    t0=$(date +%s)
    FW_RESULT=""
    while :; do
        sleep 10
        if c="$(dut_ssh "cat /tmp/pkg_upgrade.progress" 2>/dev/null)"; then
            content="$c"
            printf '%s\n' "$content" > "$log"
            case "$content" in
                *'***REBOOT***'*) FW_RESULT=reboot; break ;;
                *'***DONE***'*) FW_RESULT="done"; break ;;
            esac
        elif nb="$(boottime || true)" && [ -n "$nb" ] && [ "$nb" != "$FW_BOOT" ]; then
            FW_RESULT=reboot; break   # rebooted between two polls
        fi
        if [ $(( $(date +%s) - t0 )) -ge 60 ] && [ -z "$content" ]; then
            die "$label: no firmware log 60s after 'configctl firmware $*' (launcher refused?)"
        fi
        [ $(( $(date +%s) - t0 )) -lt "$timeout" ] || { tail -n 30 "$log" >&2 || true; die "$label: not done within ${timeout}s"; }
    done
    echo "$label: $FW_RESULT after $(( $(date +%s) - t0 ))s (log: $log)"
}

# minor_update <series>: System -> Firmware -> Update until this series' last release is in
# (its core ships opnsense-update.conf's UPGRADE_RELEASE hint + the next series' fingerprint).
minor_update() {
    local want="$1" round now kern hint
    for round in 1 2 3; do
        STAGE="minor update to the release offering $want (round $round)"
        step "$STAGE"
        fw_run "update-$want-$round" "$UPDATE_TIMEOUT" update
        if [ "$FW_RESULT" = reboot ]; then wait_boot "$FW_BOOT" "$BOOT_TIMEOUT"; wait_wan; fi
        now='' kern='' hint=''
        { read -r now; read -r kern; read -r hint; } < <(dut_ssh 'opnsense-version; opnsense-update -vk; opnsense-update -vR' 2>/dev/null) || true
        echo "now ${now:-}, kernel ${kern:-}, upgrade hint '${hint:-}'"
        [ "$hint" != "$want" ] || return 0
    done
    die "no major upgrade to $want offered after 3 update rounds (opnsense-update -vR: '$hint')"
}

# major_upgrade <series>: System -> Firmware -> Upgrade (core upgrade.sh: opnsense-update -u,
# rc.syshook upgrade, -K, reboot), then early/05-upgrade's -B / -P reboots to the final boot.
major_upgrade() {
    local to="$1" label="upgrade-$1" ver pend
    STAGE="major upgrade to $to"
    step "$STAGE"
    [ "$(dut_ssh "opnsense-update -vR")" = "$to" ] || die "opnsense-update -vR does not offer $to"
    net_check
    T_TRIGGER=$(date +%s.%N)
    fw_run "$label" "$UPGRADE_STAGE_TIMEOUT" upgrade
    [ "$FW_RESULT" = reboot ] || { tail -n 40 "$OUT/$label.progress.log" >&2; die "$label ended without a reboot (aborted?)"; }
    step "waiting for the -B / -P reboots and the final $to boot (up to ${UPGRADE_REBOOT_TIMEOUT}s)"
    wait_boot "$FW_BOOT" "$UPGRADE_REBOOT_TIMEOUT"
    ver="$(dut_ssh "opnsense-version -v")"
    case "$ver" in "$to"*) ;; *) die "after the upgrade opnsense-version -v is '$ver', not $to*" ;; esac
    pend="$(dut_ssh "ls /var/cache/opnsense-update/.kernel.pending /var/cache/opnsense-update/.base.pending /var/cache/opnsense-update/.pkgs.pending" 2>/dev/null || true)"
    [ -z "$pend" ] || die "upgrade stages still pending after the final boot: $pend"
    dut_ssh "cat /var/cache/opnsense-update/.update.log" > "$OUT/$label.update.log" 2>/dev/null || true
    dut_ssh "cat /var/cache/opnsense-update/.upgrade.log" > "$OUT/$label.pkgs.log" 2>/dev/null || true
    FINAL_BOOT="$(boottime)"
    echo "upgraded: $(dut_ssh "opnsense-version"), boottime $FINAL_BOOT"
}

pkg_state() { dut_ssh "pkg query '%n %v %q' if-pppoe-kmod os-if-pppoe" 2>/dev/null || true; }

register_lab_repo() {
    local fp
    fp="$(sha256sum "$IFPPPOE_REPO_SIGNING_PUBKEY_PATH" | awk '{print $1}')"
    dut_sh "$IFPPPOE_REPO_URL" "$fp" <<'EOF'
set -e
mkdir -p /usr/local/etc/pkg/repos /usr/local/etc/pkg/fingerprints/IfPppoe/trusted
rm -f /usr/local/etc/pkg/fingerprints/IfPppoe/trusted/*
printf 'function: "sha256"\nfingerprint: "%s"\n' "$2" > /usr/local/etc/pkg/fingerprints/IfPppoe/trusted/IfPppoe
printf 'IfPppoe: {\n  url: "%s",\n  signature_type: "fingerprints",\n  fingerprints: "/usr/local/etc/pkg/fingerprints/IfPppoe",\n  enabled: yes\n}\n' "$1" > /usr/local/etc/pkg/repos/IfPppoe.conf
pkg update -f -r IfPppoe
EOF
}

install_plugin() {
    STAGE="plugin install (branch build, $FROM_ABI)"
    step "$STAGE"
    if [ "$REPO_SERVER_STARTED" != 1 ]; then dut_repo_serve "$IFPPPOE_REPO_TARBALL"; fi
    register_lab_repo
    fw_run plugin-install 1800 install os-if-pppoe
    pkg_state | tee "$OUT/pkgs-installed.txt"
    grep -q "^os-if-pppoe .* $FROM_ABI\$" "$OUT/pkgs-installed.txt" || die "os-if-pppoe not installed for $FROM_ABI"
    grep -q "^if-pppoe-kmod .* $FROM_ABI\$" "$OUT/pkgs-installed.txt" || die "if-pppoe-kmod not installed for $FROM_ABI"
}

enable_plugin() {
    local bid st
    STAGE="plugin enable + reboot (kernel driver on $(dut_ssh "opnsense-version -v"))"
    step "$STAGE"
    bid="$(dut_ssh "sysctl -n kern.build_id")"
    dut_ssh "awk '{print tolower(\$1)}' /usr/local/share/if_pppoe/build_ids" | grep -qix "$bid" \
        || die "the installed if-pppoe-kmod has no .ko for this kernel ($(dut_ssh "opnsense-update -vk"), build_id $bid): build IFPPPOE_REPO_TARBALL for it (README \"plugin-upgrade.sh\")"
    api_call POST /api/ifpppoe/settings/set '{"ifpppoe":{"general":{"enabled":"1","exclude":""}}}' >/dev/null
    api_call POST /api/ifpppoe/service/reconfigure >/dev/null
    st="$(api_call GET /api/ifpppoe/service/status)"
    jq -e '.reboot_required == true' <<<"$st" >/dev/null || die "enable + apply did not ask for a reboot: $st"
    local b; b="$(boottime)"
    dut_ssh "daemon -f /usr/local/etc/rc.reboot" >/dev/null
    wait_boot "$b" "$BOOT_TIMEOUT"
    wait_wan
    dut_ssh "cat /var/run/if_pppoe/boot.json" | tee "$OUT/boot-before-upgrade.json"
    jq -e '.result == "enabled" and .reason == "ok"' "$OUT/boot-before-upgrade.json" >/dev/null \
        || die "kernel PPPoE not armed before the upgrade (boot.json above)"
    api_call GET /api/ifpppoe/service/status > "$OUT/status-before-upgrade.json"
    jq -e 'any(.interfaces[]?; .friendly == "wan" and .backend == "kernel")' "$OUT/status-before-upgrade.json" >/dev/null \
        || die "wan is not on the kernel backend before the upgrade ($OUT/status-before-upgrade.json)"
    echo "kernel PPPoE armed on $(dut_ssh "opnsense-version"): boot.json enabled/ok, wan backend kernel"
}

# Point IfPppoe at the published repo (gen-repo-conf.sh's IfPppoe.conf + fingerprint, as served
# from Pages), so the prefetch has a real FreeBSD:15 catalogue signed by the release key.
use_published_repo() {
    local inst
    STAGE="switch IfPppoe to $PUBLISHED_REPO_BASE/\${ABI}"
    step "$STAGE"
    dut_sh "$PUBLISHED_REPO_BASE" "$TARGET_ABI" <<'EOF'
set -e
base=$1
fetch -q -T 60 -o /tmp/IfPppoe.conf.new "$base/client-conf/repos/IfPppoe.conf"
fetch -q -T 60 -o /tmp/IfPppoe.fp.new "$base/client-conf/fingerprints/IfPppoe/trusted/IfPppoe"
grep -qF "url: \"$base/\${ABI}\"" /tmp/IfPppoe.conf.new || { echo "published IfPppoe.conf has no $base/\${ABI} url" >&2; exit 1; }
rm -f /usr/local/etc/pkg/fingerprints/IfPppoe/trusted/*
mv /tmp/IfPppoe.fp.new /usr/local/etc/pkg/fingerprints/IfPppoe/trusted/IfPppoe
mv /tmp/IfPppoe.conf.new /usr/local/etc/pkg/repos/IfPppoe.conf
cat /usr/local/etc/pkg/repos/IfPppoe.conf
pkg update -f -r IfPppoe
pkg rquery -r IfPppoe '%n %v %q' os-if-pppoe if-pppoe-kmod
fetch -q -T 60 -o /dev/null "$base/$2/meta.conf"
EOF
    # abi-heal's downgrade guard compares the installed version with the repo's (pkg version -t):
    # the branch build must not be newer than what the prefetch will fetch.
    inst="$(dut_ssh "pkg query %v os-if-pppoe")"
    case "$(dut_ssh "pkg version -t $inst $PUBLISHED_VERSION")" in
        '>') die "installed os-if-pppoe $inst is newer than the published $PUBLISHED_VERSION: rebuild the branch with --version $PUBLISHED_VERSION" ;;
    esac
    echo "installed os-if-pppoe $inst vs published $TARGET_ABI $PUBLISHED_VERSION: not a downgrade"
}

# -- console capture: a timestamped copy of dut's serial console (the qemu chardev socket,
# free once provision-dut.sh's console step is done) for boot counting and hook timing.
console_capture_start() {
    mkfifo "$RUNDIR/console.fifo"
    python3 -u -c '
import sys, time
r = sys.stdin.buffer
while True:
    l = r.readline()
    if not l:
        break
    sys.stdout.write("%.3f %s\n" % (time.time(), l.rstrip(b"\r\n").decode("utf-8", "replace")))
    sys.stdout.flush()
' < "$RUNDIR/console.fifo" >> "$OUT/console.log" &
    CAPTURE_TS_PID=$!
    ssh -o ConnectTimeout=8 -o ServerAliveInterval=30 "$VMHOST" "sudo nc -U '$DUT_SOCK_PATH'" \
        < /dev/null > "$RUNDIR/console.fifo" 2>/dev/null &
    CAPTURE_SSH_PID=$!
    sleep 3
    kill -0 "$CAPTURE_SSH_PID" 2>/dev/null \
        || echo "$ME: WARNING: console capture did not connect; boot counting/hook timing will fail" >&2
}

# shellcheck disable=SC2329  # called from teardown (a trap)
console_capture_stop() {
    [ -z "$CAPTURE_SSH_PID" ] || kill "$CAPTURE_SSH_PID" 2>/dev/null
    [ -z "$CAPTURE_TS_PID" ] || { sleep 1; kill "$CAPTURE_TS_PID" 2>/dev/null; }
    CAPTURE_SSH_PID=""; CAPTURE_TS_PID=""
}

# console_report <since epoch>: boots since then, the final boot's console section, our early
# hook's wall time, and error lines in that section. Prints KEY=value lines.
console_report() {
    python3 - "$OUT/console.log" "$1" "$OUT/final-boot-console.log" <<'PY'
import re, sys
log, since, final_out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
lines = []
for raw in open(log, encoding="utf-8", errors="replace"):
    ts, _, text = raw.rstrip("\n").partition(" ")
    try:
        t = float(ts)
    except ValueError:
        continue
    if t >= since:
        lines.append((t, text))
banners = [i for i, (_, s) in enumerate(lines) if "Copyright (c) 1992-" in s]
print("BOOTS=%d" % len(banners))
final = lines[banners[-1]:] if banners else []
with open(final_out, "w") as f:
    for t, s in final:
        f.write("%.3f %s\n" % (t, s))
hook = None
for i, (t, s) in enumerate(final):
    if ">>> Invoking early script 'if-pppoe'" in s:
        end = next(((t2, s2) for t2, s2 in final[i + 1:] if not s2.startswith("if_pppoe:")), None)
        if end:
            hook = end[0] - t
print("EARLY_HOOK_S=%s" % ("%.1f" % hook if hook is not None else "unknown"))
pat = re.compile(r">>> Error in |syslog-ng.*(error|fail)|devd.*(error|fail|abort)|configd.*(error|fail|traceback)|"
                 r"Segmentation fault|core dumped|Abort trap|Traceback", re.I)
errs = [s for _, s in final if pat.search(s)]
print("ERRORS=%d" % len(errs))
for s in errs:
    print("ERRLINE=%s" % s)
PY
}

check() {
    local name="$1"; shift
    if "$@"; then echo "PASS: $name"; else echo "FAIL: $name"; FAILS+=("$name"); fi
}

# shellcheck disable=SC2329  # invoked via trap
teardown() {
    local rc=$?
    set +e
    trap '' INT TERM
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$PROVISIONED" = 1 ]; then
        echo "== dut-side state after the failure ($STAGE) ==" >&2
        dut_ssh /bin/sh -s >&2 <<'EOF' || true
echo "-- version"; opnsense-version; pkg config abi; sysctl -n kern.build_id
echo "-- pkg (pppoe)"; pkg query '%n %v %q' if-pppoe-kmod os-if-pppoe
echo "-- boot.json"; cat /var/run/if_pppoe/boot.json
echo "-- abi-heal.json"; cat /conf/if_pppoe/abi-heal.json
echo "-- prefetch"; ls -laR /var/cache/if_pppoe 2>&1 | head -30
echo "-- pending"; ls -la /var/cache/opnsense-update/ 2>&1
echo "-- progress (tail)"; tail -n 30 /tmp/pkg_upgrade.progress
echo "-- system log (if_pppoe)"; grep -h if_pppoe /var/log/system/latest.log 2>/dev/null | tail -n 30
echo "-- WAN"; ifconfig pppoe0 2>&1; netstat -rn -f inet | grep default
EOF
    fi
    console_capture_stop
    if [ "$rc" -ne 0 ] && [ -s "$OUT/console.log" ]; then
        echo "== last console lines ($OUT/console.log) ==" >&2
        tail -n 40 "$OUT/console.log" >&2
    fi
    # Credentials and the isp changes first, the slow VM shutdown last.
    if [ "$ACCOUNT_ADDED" = 1 ]; then
        dut_account_del \
            || echo "$ME: WARNING: removing accel-ppp account $DUT_PPPOE_USERNAME from $ISP_VM failed; its line is in $ISP_VM:$LAB_CREDS_ACCEL_DIR/chap-secrets (tmpfs)" >&2
    fi
    if [ "$UPSTREAM_ON" = 1 ]; then
        isp_upstream_off \
            || echo "$ME: WARNING: undoing the isp upstream failed; on $ISP_VM run: sudo nft delete table ip if_pppoe_upgrade; sudo sysctl -w net.ipv4.ip_forward=\$(cat /run/if_pppoe-upgrade.forward)" >&2
    fi
    if [ "$PROVISIONED" = 1 ]; then
        ./provision-dut.sh --scrub-seed >/dev/null
    fi
    find "$RUNDIR" -type f -exec shred -u {} + 2>/dev/null
    rm -rf "$RUNDIR"
    unset DUT_API_KEY DUT_API_SECRET DUT_PPPOE_PASSWORD
    dut_repo_stop
    if [ "$PROVISIONED" = 1 ]; then
        ./run.sh dut down
    fi
    dut_overlay_remove
    echo "$ME: logs in $OUT (wall time $(( ($(date +%s) - T_START) / 60 )) min)" >&2
    exit "$rc"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(stat -f -c %T "$RUNDIR")" = tmpfs ] || die "$RUNDIR is not tmpfs; refusing to put run credentials on disk"

# -- this run's credentials (builtins / command substitution only: nothing secret on argv) --
ssh-keygen -q -t ed25519 -N '' -C "if_pppoe-dut-ephemeral" -f "$RUNDIR/id_ed25519"
DUT_API_KEY="$(openssl rand -base64 60 | tr -d '\n')"
DUT_API_SECRET="$(openssl rand -base64 60 | tr -d '\n')"
DUT_PPPOE_USERNAME="dutrun-$(openssl rand -hex 4)"
DUT_PPPOE_PASSWORD="$(openssl rand -hex 24)"
case "$DUT_PPPOE_USERNAME" in
    dutrun-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) die "bad generated username" ;;
esac

step "dut from $UPGRADE_BASE_IMAGE (OPNsense $UPGRADE_FROM, legs: $LEGS), logs: $OUT"
# accel-pppd isn't a service: a freshly booted isp needs provision-isp.sh first
vm_ssh "$ISP_VM" 'pgrep -x accel-pppd >/dev/null' </dev/null \
    || die "accel-pppd isn't running on $ISP_VM -- run 'LAB_SLOT=1 ./provision-isp.sh' first"
vm_config dut   # VM_OVERLAY_SIZE (vm_ssh above may have switched the VM_* globals)
dut_make_overlay "\$HOME/$LAB_DIR/images/$UPGRADE_BASE_IMAGE" "$VM_OVERLAY_SIZE"

ACCOUNT_ADDED=1   # before `add`: a half-done add is still removed at exit
dut_account_add "$UPGRADE_DUT_WAN_IP"
step "isp upstream for $UPGRADE_DUT_WAN_IP"
isp_upstream_on

STAGE="provision"
PROVISIONED=1
LAB_RUN_DRIVE="$R_OVL_DIR/$DUT_VM_NAME-run.qcow2" \
DUT_SSH_KEY="$RUNDIR/id_ed25519" DUT_CONSOLE_LOG="$RUNDIR/dut-console.log" \
DUT_API_KEY="$DUT_API_KEY" DUT_API_SECRET="$DUT_API_SECRET" \
DUT_PPPOE_PASSWORD="$DUT_PPPOE_PASSWORD" DUT_PPPOE_USERNAME="$DUT_PPPOE_USERNAME" \
    ./provision-dut.sh
console_capture_start
wait_wan
net_check
echo "dut: $(dut_ssh "opnsense-version"), kernel $(dut_ssh "opnsense-update -vk")"

PLUGIN_INSTALLED=0
if [ "$UPGRADE_FROM" = 25.7 ]; then
    minor_update 26.1
    # Same-ABI major upgrade with the plugin installed: the prefetch must be a no-op.
    install_plugin
    PLUGIN_INSTALLED=1
    major_upgrade 26.1
    STAGE="same-ABI checks (25.7 -> 26.1)"
    step "$STAGE"
    grep -q ">>> Invoking upgrade script 'if-pppoe'" "$OUT/upgrade-26.1.update.log" \
        || die "the upgrade syshook did not run our hook (upgrade-26.1.update.log)"
    ! grep -q "abi-heal: prefetch: ready" "$OUT/upgrade-26.1.update.log" \
        || die "prefetch ran on a same-ABI (FreeBSD:14) upgrade"
    dut_ssh "test ! -e $PREFETCH_DIR" || die "$PREFETCH_DIR exists after a same-ABI upgrade"
    pkg_state | tee "$OUT/pkgs-after-26.1.txt"
    [ "$(grep -c " $FROM_ABI\$" "$OUT/pkgs-after-26.1.txt")" = 2 ] || die "plugin packages changed ABI on 25.7 -> 26.1"
    echo "same-ABI upgrade: hook ran, no prefetch, packages untouched"
    wait_wan
fi

minor_update 26.7
if [ "$PLUGIN_INSTALLED" = 0 ]; then install_plugin; fi
enable_plugin
use_published_repo
pkg_state > "$OUT/pkgs-before-upgrade.txt"

major_upgrade 26.7

# -- final assertions: collected, not fail-fast ---------------------------------
STAGE="final assertions"
step "$STAGE"
set +e
dut_ssh "pkg config abi" > "$OUT/abi-after.txt"
pkg_state > "$OUT/pkgs-after.txt"
dut_ssh "cat /var/run/if_pppoe/boot.json" > "$OUT/boot-after.json"
dut_ssh "cat /conf/if_pppoe/abi-heal.json" > "$OUT/abi-heal-after.json"
dut_ssh "dmesg -a" > "$OUT/dmesg-a.txt" 2>&1
dut_ssh "cat /var/log/system/latest.log" > "$OUT/system-latest.log" 2>&1
BOOT_SEC="$FINAL_BOOT"
echo "abi: $(cat "$OUT/abi-after.txt")"; cat "$OUT/pkgs-after.txt"
echo "boot.json: $(cat "$OUT/boot-after.json")"; echo "abi-heal.json: $(cat "$OUT/abi-heal-after.json")"

check "upgrade log: $PREFETCH_READY_LINE" grep -qF "$PREFETCH_READY_LINE" "$OUT/upgrade-26.7.update.log"
check "system ABI is $TARGET_ABI" grep -qx "$TARGET_ABI" "$OUT/abi-after.txt"
check "if-pppoe-kmod on $TARGET_ABI" grep -q "^if-pppoe-kmod .* $TARGET_ABI\$" "$OUT/pkgs-after.txt"
check "os-if-pppoe on $TARGET_ABI" grep -q "^os-if-pppoe .* $TARGET_ABI\$" "$OUT/pkgs-after.txt"
check "boot.json enabled/ok on this boot" jq -e --argjson b "${BOOT_SEC:-0}" \
    '.result == "enabled" and .reason == "ok" and .at >= $b' "$OUT/boot-after.json"
check "abi-heal.json: offline healed $FROM_ABI -> $TARGET_ABI" jq -e --arg f "$FROM_ABI" --arg t "$TARGET_ABI" \
    '.mode == "offline" and .result == "healed" and .from == $f and .to == $t' "$OUT/abi-heal-after.json"
check "prefetch dir gone" dut_ssh "test ! -e $PREFETCH_DIR"
dut_ssh "pkg update -f -r IfPppoe && pkg rquery -r IfPppoe '%n %v %q' os-if-pppoe" > "$OUT/ifpppoe-repo-after.txt" 2>&1
check "IfPppoe repo updates and offers os-if-pppoe for $TARGET_ABI" grep -q "^os-if-pppoe .* $TARGET_ABI\$" "$OUT/ifpppoe-repo-after.txt"
check "if_pppoe.ko loaded" dut_ssh "kldstat | grep -q if_pppoe"
wait_wan_ok() { ( wait_wan ); }
check "WAN up (pinned address, default via pppoe0, peer answers)" wait_wan_ok
api_call GET /api/ifpppoe/service/status > "$OUT/status-after.json"
check "wan on the kernel backend" jq -e 'any(.interfaces[]?; .friendly == "wan" and .backend == "kernel")' "$OUT/status-after.json"

console_report "$T_TRIGGER" > "$OUT/console-report.txt"
cat "$OUT/console-report.txt"
BOOTS="$(sed -n 's/^BOOTS=//p' "$OUT/console-report.txt")"
check "3 boots after the upgrade's reboot (-B, -P, final): no extra reboot" [ "${BOOTS:-0}" = 3 ]
check "final boot console: no syshook/syslog-ng/devd/configd errors" grep -qx 'ERRORS=0' "$OUT/console-report.txt"
grep -iE '(syslog-ng|devd|configd).*(error|fail)' "$OUT/system-latest.log" > "$OUT/system-log-errors.txt"
echo "system log error-ish lines (informational): $(wc -l < "$OUT/system-log-errors.txt") -> $OUT/system-log-errors.txt"
# json `at` stamps: abi-heal offline record vs kernel boot, and the gate after it
jq -rn --argjson b "${BOOT_SEC:-0}" --slurpfile h "$OUT/abi-heal-after.json" --slurpfile g "$OUT/boot-after.json" \
    '"boot -> offline install done: \($h[0].at - $b)s; offline done -> gate done: \($g[0].at - $h[0].at)s"' 2>/dev/null
check "no reboot after the final boot" [ "$(boottime)" = "$FINAL_BOOT" ]
set -e

echo
if [ "${#FAILS[@]}" -gt 0 ]; then
    printf 'FAILED: %s\n' "${FAILS[@]}"
    exit 1
fi
echo "ALL PASSED: $UPGRADE_FROM -> 26.7 with the prefetch (logs: $OUT)"
