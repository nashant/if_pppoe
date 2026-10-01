#!/bin/sh
# early/start/update syshooks, reapply.sh and abi-heal.sh against a fake /conf, /var/run
# and stubbed kldload/kldstat/kldunload/sysctl/hookctl/configctl/ifconfig/pkg.
# The last block runs the real hookctl.php (needs PHP) on a fixture copy.
set -u
. "$(dirname "$0")/lib.sh"

EARLY="${SRC}/etc/rc.syshook.d/early/50-if-pppoe"
START="${SRC}/etc/rc.syshook.d/start/50-if-pppoe"
UPDATE="${SRC}/etc/rc.syshook.d/update/05-if-pppoe"
BID=3f1c2a9b0d4e5f60718293a4b5c6d7e8f9a0b1c2

stub()
{
	# stub <name> <body>
	printf '#!/bin/sh\n%s\n' "$2" > "${S}/bin/$1"
	chmod +x "${S}/bin/$1"
}

setup()
{
	S="${IF_PPPOE_TEST_TMP}/sys-$1"
	rm -rf "${S}"
	mkdir -p "${S}/bin" "${S}/conf" "${S}/run" "${S}/kmod/${BID}" "${S}/share" "${S}/state"
	export IF_PPPOE_LIB="${SRC}/opnsense/scripts/if_pppoe/lib.sh"
	export IF_PPPOE_CONF_DIR="${S}/conf"
	export IF_PPPOE_RUN_DIR="${S}/run"
	export IF_PPPOE_SCRIPTS="${S}/scripts"
	export IF_PPPOE_KMOD_DIR="${S}/kmod"
	export IF_PPPOE_BUILD_IDS="${S}/share/build_ids"
	export IF_PPPOE_FEATURES_FILE="${S}/share/features"
	export IF_PPPOE_PHP="${S}/bin/php"
	export IF_PPPOE_SYSCTL="${S}/bin/sysctl"
	export IF_PPPOE_KLDLOAD="${S}/bin/kldload"
	export IF_PPPOE_KLDUNLOAD="${S}/bin/kldunload"
	export IF_PPPOE_KLDSTAT="${S}/bin/kldstat"
	export IF_PPPOE_SHA256="sha256sum"
	export IF_PPPOE_IFCONFIG="${S}/bin/ifconfig"
	export IF_PPPOE_CONFIGCTL="${S}/bin/configctl"
	export IF_PPPOE_LOGGER="${S}/bin/logger"
	export IF_PPPOE_TIMEOUT="${S}/bin/timeout"
	export IF_PPPOE_FLOCK="${S}/bin/flock"
	export IF_PPPOE_FW_LOCK="${S}/pkg_upgrade.progress"
	export IF_PPPOE_PKG="${S}/bin/pkg"
	export IF_PPPOE_DAEMON="${S}/bin/daemon"
	export IF_PPPOE_PGREP="${S}/bin/pgrep"
	export IF_PPPOE_SLEEP="${S}/bin/sleep"
	unset IF_PPPOE_HEAL_BG IF_PPPOE_HEAL_LOCKED
	export IF_PPPOE_NOW=1000000
	export ST="${S}/state"
	mkdir -p "${IF_PPPOE_SCRIPTS}"
	cp "${SRC}/opnsense/scripts/if_pppoe/reapply.sh" "${SRC}/opnsense/scripts/if_pppoe/abi-heal.sh" "${IF_PPPOE_SCRIPTS}/"
	: > "${S}/kmod/${BID}/if_pppoe.ko"
	echo "${BID}" > "${IF_PPPOE_BUILD_IDS}"
	printf 'if_pppoe_%s\n' linkevents ipv6 mssfix pfil_pass_foreign single_bytecount > "${IF_PPPOE_FEATURES_FILE}"
	echo enabled > "${S}/conf/desired"
	# sysctl: values from $ST/sysctl.<name>
	stub sysctl '[ "$1" = "-n" ] && shift; f="$ST/sysctl.$1"; [ -f "$f" ] && cat "$f" || exit 1'
	echo "${BID}" > "${ST}/sysctl.kern.build_id"
	for f in linkevents ipv6 mssfix pfil_pass_foreign single_bytecount; do
		echo 1 > "${ST}/sysctl.kern.features.if_pppoe_${f}"
	done
	stub kldload 'echo "kldload $*" >> "$ST/calls"; [ -f "$ST/kldload.fail" ] && exit 1; touch "$ST/loaded"'
	stub kldstat '[ -f "$ST/loaded" ]'
	stub kldunload 'echo "kldunload $*" >> "$ST/calls"; rm -f "$ST/loaded"'
	stub logger 'echo "logger $*" >> "$ST/log"'
	# php <hookctl.php> <cmd> ...: output/rc from $ST/hookctl.<cmd>.{out,rc}
	stub php 'shift; echo "hookctl $*" >> "$ST/calls"; c=$1; [ -f "$ST/hookctl.$c.out" ] && cat "$ST/hookctl.$c.out"; [ -f "$ST/hookctl.$c.rc" ] && exit $(cat "$ST/hookctl.$c.rc"); exit 0'
	echo applied > "${ST}/hookctl.apply.out"
	echo reverted > "${ST}/hookctl.revert.out"
	stub ifconfig 'echo "ifconfig $*" >> "$ST/calls"'
	stub configctl 'echo "configctl $*" >> "$ST/calls"'
	stub timeout 'shift 3; "$@"'
	# flock -n <file> [cmd...]: the firmware lock is held while $ST/fwbusy exists, the heal lock while $ST/heallocked does
	stub flock 'shift; f=$1; shift
case "$f" in *pkg_upgrade.progress) [ -f "$ST/fwbusy" ] && exit 1 ;; *abi-heal.lock) [ -f "$ST/heallocked" ] && exit 1 ;; esac
[ $# -gt 0 ] && exec "$@"; exit 0'
	stub daemon '[ "$1" = -f ] && shift; echo "daemon $*" >> "$ST/pkgcalls"; exec "$@"'
	stub pgrep '[ -f "$ST/pkgbusy" ]'
	stub sleep 'echo "sleep $*" >> "$ST/pkgcalls"; rm -f "$ST/pkgbusy"'
	# pkg: system ABI in $ST/abi, installed package ABIs in $ST/pkgabi.<name> (absent =
	# not installed), the IfPppoe catalogue in $ST/repoabi.<name>; calls to $ST/pkgcalls
	stub pkg 'echo "pkg $*" >> "$ST/pkgcalls"
case "$1" in
config) cat "$ST/abi" ;;
query) [ -f "$ST/pkgabi.$3" ] || exit 1; if [ "$2" = %n ]; then echo "$3"; else cat "$ST/pkgabi.$3"; fi ;;
update) [ -f "$ST/pkg.update.rc" ] && exit "$(cat "$ST/pkg.update.rc")"; exit 0 ;;
rquery) for n; do :; done; [ -f "$ST/repoabi.$n" ] && cat "$ST/repoabi.$n"; exit 0 ;;
install) [ -f "$ST/pkg.install.rc" ] && exit "$(cat "$ST/pkg.install.rc")"
	for n; do [ -f "$ST/repoabi.$n" ] && cp "$ST/repoabi.$n" "$ST/pkgabi.$n"; done; exit 0 ;;
*) exit 1 ;;
esac'
	echo FreeBSD:15:amd64 > "${ST}/abi"
	for p in if-pppoe-kmod os-if-pppoe; do
		echo FreeBSD:15:amd64 > "${ST}/pkgabi.${p}"
		echo FreeBSD:15:amd64 > "${ST}/repoabi.${p}"
	done
	# engine: exit code from $ST/engine.<subcommand>.rc (default 0)
	stub engine 'echo "engine $*" >> "$ST/calls"; [ -f "$ST/engine.$1.rc" ] && exit $(cat "$ST/engine.$1.rc"); exit 0'
	cp "${S}/bin/engine" "${IF_PPPOE_SCRIPTS}/engine"
}

early()
{
	sh "${EARLY}" > "${ST}/out" 2>&1
	echo $?
}

calls()
{
	cat "${ST}/calls" 2>/dev/null
}

bootres()
{
	sed -n 's/.*"result":"\([^"]*\)","reason":"\([^"]*\)".*/\1:\2/p' "${IF_PPPOE_RUN_DIR}/boot.json"
}

# --- happy path --------------------------------------------------------
setup ok
eq "enabled: exit 0" "$(early)" 0
eq "enabled: boot result" "$(bootres)" "enabled:ok"
check "enabled: boot.json carries no kmod identity" test "$(grep -c '"kmod"' "${IF_PPPOE_RUN_DIR}/boot.json")" -eq 0
contains "enabled: kldload by explicit path" "$(calls)" "kldload ${S}/kmod/${BID}/if_pppoe.ko"
contains "enabled: hookctl apply --reason=boot" "$(calls)" "hookctl apply --reason=boot"
check "enabled: boot.pending set until start" test -f "${S}/conf/boot.pending"
check "enabled: loaded.json recorded" test -f "${IF_PPPOE_RUN_DIR}/loaded.json"
eq "enabled: loaded.json build_id" "$(sed -n 's/.*"build_id":"\([^"]*\)".*/\1/p' "${IF_PPPOE_RUN_DIR}/loaded.json")" "${BID}"
eq "enabled: loaded.json sha256 matches the .ko" \
    "$(sed -n 's/.*"sha256":"\([^"]*\)".*/\1/p' "${IF_PPPOE_RUN_DIR}/loaded.json")" \
    "$(sha256sum "${S}/kmod/${BID}/if_pppoe.ko" | cut -d' ' -f1)"
sh "${START}"
check "start clears boot.pending" test ! -f "${S}/conf/boot.pending"
eq "start leaves no strikes" "$(cat "${S}/conf/strikes" 2>/dev/null)" ""

setup preloaded
touch "${ST}/loaded"
early >/dev/null
eq "module already loaded: no second kldload" "$(calls | grep -c kldload)" 0
eq "module already loaded: enabled" "$(bootres)" "enabled:ok"

# --- disabled ----------------------------------------------------------
setup disabled
echo disabled > "${S}/conf/desired"
touch "${ST}/loaded"
mkdir -p "${IF_PPPOE_RUN_DIR}"
echo '{"build_id":"stale","sha256":"stale"}' > "${IF_PPPOE_RUN_DIR}/loaded.json"
eq "disabled: exit 0" "$(early)" 0
eq "disabled: boot result" "$(bootres)" "disabled:desired-disabled"
contains "disabled: hookctl revert" "$(calls)" "hookctl revert --reason=boot"
contains "disabled: module unloaded" "$(calls)" "kldunload -n if_pppoe.ko"
check "disabled: no kldload" test "$(calls | grep -c kldload\ )" -eq 0
check "disabled: no boot.pending" test ! -f "${S}/conf/boot.pending"
check "disabled: loaded.json cleared on unload" test ! -f "${IF_PPPOE_RUN_DIR}/loaded.json"

setup nodesired
rm -f "${S}/conf/desired"
early >/dev/null
eq "missing desired file means disabled" "$(bootres)" "disabled:desired-disabled"

# --- kmod gating ---------------------------------------------------------
setup wrongkernel
echo 0000000000000000000000000000000000000000 > "${ST}/sysctl.kern.build_id"
eq "unknown kern.build_id: exit 0" "$(early)" 0
eq "unknown kern.build_id: failed" "$(bootres)" "failed:kernel-not-supported"
check "unknown kern.build_id: no kldload" test "$(calls | grep -c 'kldload ')" -eq 0
contains "unknown kern.build_id: reverted" "$(calls)" "hookctl revert --reason=boot"
check "unknown kern.build_id: notice written" test -s "${IF_PPPOE_RUN_DIR}/notice.d/boot-failed"
check "failed boot clears boot.pending" test ! -f "${S}/conf/boot.pending"

setup nobuildid
rm -f "${ST}/sysctl.kern.build_id"
early >/dev/null
eq "no kern.build_id sysctl: failed" "$(bootres)" "failed:no-build-id"

setup injection
echo '../../etc' > "${ST}/sysctl.kern.build_id"
early >/dev/null
eq "non-hex build id rejected" "$(bootres)" "failed:no-build-id"

setup komissing
rm -f "${S}/kmod/${BID}/if_pppoe.ko"
early >/dev/null
eq "listed build id but .ko missing: failed" "$(bootres)" "failed:kmod-missing"
contains "kmod-missing: identity has an empty ko hash" "$(cat "${IF_PPPOE_RUN_DIR}/boot.json")" '"ko":""}'
rm -f "${IF_PPPOE_FEATURES_FILE}"
early >/dev/null
contains "no features file: empty features hash" "$(cat "${IF_PPPOE_RUN_DIR}/boot.json")" '"features":"",'

setup kosum
echo "${BID} $(printf 'x' | sha256sum | cut -d' ' -f1)" > "${IF_PPPOE_BUILD_IDS}"
early >/dev/null
eq "kmod checksum mismatch: failed" "$(bootres)" "failed:kmod-checksum"
setup kosumok
echo "${BID} $(sha256sum < "${S}/kmod/${BID}/if_pppoe.ko" | cut -d' ' -f1)" > "${IF_PPPOE_BUILD_IDS}"
early >/dev/null
eq "kmod checksum match: enabled" "$(bootres)" "enabled:ok"

setup kldfail
touch "${ST}/kldload.fail"
early >/dev/null
eq "kldload fails: failed" "$(bootres)" "failed:kldload"
contains "kldload fails: reverted" "$(calls)" "hookctl revert"
eq "kldload fails: boot.json records the installed kmod identity" \
    "$(sed -n 's/.*"kmod":\({[^}]*}\).*/\1/p' "${IF_PPPOE_RUN_DIR}/boot.json")" \
    "{\"build_ids\":\"$(sha "${IF_PPPOE_BUILD_IDS}")\",\"features\":\"$(sha "${IF_PPPOE_FEATURES_FILE}")\",\"ko\":\"$(sha "${S}/kmod/${BID}/if_pppoe.ko")\"}"
check "kldload fails: boot.json is valid JSON" "${REAL_PHP:-php}" -r 'exit(is_array(json_decode(file_get_contents($argv[1]), true)) ? 0 : 1);' "${IF_PPPOE_RUN_DIR}/boot.json"

setup nofeature
rm -f "${ST}/sysctl.kern.features.if_pppoe_mssfix"
early >/dev/null
eq "missing FEATURE: failed with its name" "$(bootres)" "failed:feature-mssfix"
contains "missing FEATURE: module unloaded again" "$(calls)" "kldunload -n if_pppoe.ko"
check "missing FEATURE: hook never applied" test "$(calls | grep -c 'hookctl apply')" -eq 0

setup featzero
echo 0 > "${ST}/sysctl.kern.features.if_pppoe_ipv6"
early >/dev/null
eq "FEATURE present but 0: failed" "$(bootres)" "failed:feature-ipv6"

# --- hook refusal --------------------------------------------------------
setup hookrefused
echo 'refused:anchor (anchor:configure)' > "${ST}/hookctl.apply.out"
echo 2 > "${ST}/hookctl.apply.rc"
early >/dev/null
eq "hook refused: failed" "$(bootres)" "failed:hook"
check "hook refused: no revert (keeps refusal reason)" test "$(calls | grep -c 'hookctl revert')" -eq 0
contains "hook refused: notice carries reason" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/boot-failed")" "refused:anchor"
contains "hook refused: module unloaded" "$(calls)" "kldunload"

# --- strikes and latch -------------------------------------------------
setup strikes
early >/dev/null                          # boot 1 armed, never reaches start
IF_PPPOE_NOW=1000100; early >/dev/null    # boot 2: strike 1
eq "strike 1 recorded" "$(wc -l < "${S}/conf/strikes" | tr -d ' ')" 1
IF_PPPOE_NOW=1000200; early >/dev/null    # boot 3: strike 2
eq "two strikes: still enabled" "$(bootres)" "enabled:ok"
IF_PPPOE_NOW=1000300; early >/dev/null    # boot 4: strike 3 -> latch
eq "third unclean boot: latched" "$(bootres)" "latched:strikes"
check "latch file written" test -f "${S}/conf/latch"
check "latched: notice" test -s "${IF_PPPOE_RUN_DIR}/notice.d/boot-latched"
check "latched: boot.pending cleared" test ! -f "${S}/conf/boot.pending"
: > "${ST}/calls"
IF_PPPOE_NOW=1000400; early >/dev/null
eq "latched stays latched on next boot" "$(bootres)" "latched:strikes"
check "latched: no kldload" test "$(calls | grep -c 'kldload ')" -eq 0
sleep 1
echo enabled > "${S}/conf/desired"
touch "${S}/conf/desired"
IF_PPPOE_NOW=1000500; early >/dev/null
eq "desired rewritten after latch: armed again" "$(bootres)" "enabled:ok"
check "latch cleared" test ! -f "${S}/conf/latch"
check "strikes cleared" test ! -s "${S}/conf/strikes"

setup window
printf '%s\n' 900000 910000 > "${S}/conf/strikes"   # older than 24h at now=1000000
touch "${S}/conf/boot.pending"
early >/dev/null
eq "strikes older than 24h are pruned" "$(cat "${S}/conf/strikes")" "1000000"
eq "one fresh strike: still enabled" "$(bootres)" "enabled:ok"

setup cleanboots
for n in 1 2 3 4; do
	IF_PPPOE_NOW=$((1000000 + n)); early >/dev/null; sh "${START}"
done
eq "clean boots never strike" "$(cat "${S}/conf/strikes" 2>/dev/null)" ""
eq "clean boots: enabled" "$(bootres)" "enabled:ok"

# --- update / trigger / cron -------------------------------------------
setup upd-ok
echo applied > "${ST}/hookctl.apply.out"
sh "${UPDATE}"; rc=$?
eq "update: exit 0" "${rc}" 0
contains "update: hookctl apply --reapply --reason=update" "$(calls)" "hookctl apply --reapply --reason=update"
check "update ok: no fallback" test "$(calls | grep -v abiheal | grep -c configctl)" -eq 0
contains "update: ABI check handed to configd" "$(calls)" "configctl -d if-pppoe abiheal deferred"

upd_refused_setup()
{
	setup "$1"
	mkdir -p "${IF_PPPOE_RUN_DIR}/reg"
	echo '{"friendly":"wan","parent":"igb0"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
	echo '{"friendly":"opt2","parent":"vlan0.100"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe1.json"
	echo '{"friendly":"x;rm -rf /","parent":"igb0"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe2.json"
	echo '{"friendly":"wan"}' > "${IF_PPPOE_RUN_DIR}/reg/em0.json"
	echo 'refused:anchor (anchor:configure)' > "${ST}/hookctl.apply.out"
	echo 2 > "${ST}/hookctl.apply.rc"
}

# the engine owns the handover; the shell fallback must not run when it succeeds
upd_refused_setup upd-refused-engine
sh "${UPDATE}"; rc=$?
eq "update refused: exit 0 (engine path)" "${rc}" 0
contains "update refused: engine reconcile --after-firmware" "$(calls)" "engine reconcile --after-firmware"
check "update refused, engine ok: no shell teardown" test "$(calls | grep -v abiheal | grep -c -e 'ifconfig' -e 'engine reset' -e configctl)" -eq 0
check "update refused, engine ok: notice" test -s "${IF_PPPOE_RUN_DIR}/notice.d/update-fallback"

# engine missing
upd_refused_setup upd-refused-noengine
rm -f "${IF_PPPOE_SCRIPTS}/engine"
sh "${UPDATE}" >/dev/null
contains "no engine: shell fallback reconfigures wan" "$(calls)" "configctl -d interface reconfigure wan"
check "no engine: no engine calls" test "$(calls | grep -c '^engine')" -eq 0

# engine fails (e.g. a device lock was busy): shell fallback for the rest
upd_refused_setup upd-refused
echo 2 > "${ST}/engine.reconcile.rc"
sh "${UPDATE}"; rc=$?
eq "update refused: exit 0 (never fails core update)" "${rc}" 0
contains "engine failed: after-firmware was tried first" "$(calls | head -n 2)" "engine reconcile --after-firmware"
contains "update refused: engine reset wan" "$(calls)" "engine reset wan pppoe0"
contains "update refused: destroy pppoe0 (PADT)" "$(calls)" "ifconfig pppoe0 destroy"
contains "update refused: reconfigure wan to mpd5" "$(calls)" "configctl -d interface reconfigure wan"
contains "update refused: reconfigure opt2" "$(calls)" "configctl -d interface reconfigure opt2"
contains "update refused: bad friendly still destroyed" "$(calls)" "ifconfig pppoe2 destroy"
check "update refused: bad friendly never passed on" test "$(calls | grep -c 'rm -rf')" -eq 0
check "update refused: non-pppoe registry name ignored" test "$(calls | grep -c em0)" -eq 0
check "update refused: registry emptied" test ! -f "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
check "update refused: notice" test -s "${IF_PPPOE_RUN_DIR}/notice.d/update-fallback"

setup upd-paused
mkdir -p "${IF_PPPOE_RUN_DIR}/reg"
echo '{"friendly":"wan"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
echo 'paused:core-reinstall (25.7.11_9)' > "${ST}/hookctl.apply.out"
echo 2 > "${ST}/hookctl.apply.rc"
sh "${UPDATE}" >/dev/null
contains "same-version reinstall: WANs handed to the engine for mpd5" "$(calls)" "engine reconcile --after-firmware"
echo 1 > "${ST}/engine.reconcile.rc"
: > "${ST}/calls"
echo '{"friendly":"wan"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
sh "${UPDATE}" >/dev/null
contains "same-version reinstall, engine failed: WANs moved to mpd5" "$(calls)" "configctl -d interface reconfigure wan"

setup upd-noop
mkdir -p "${IF_PPPOE_RUN_DIR}/reg"
echo '{"friendly":"wan"}' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
echo 'refused:anchor (reapply: nothing to do)' > "${ST}/hookctl.apply.out"
echo 2 > "${ST}/hookctl.apply.rc"
sh "${IF_PPPOE_SCRIPTS}/reapply.sh" trigger >/dev/null
check "repeat refusal: no second fallback" test "$(calls | grep -c configctl)" -eq 0

setup upd-disabled
echo disabled > "${S}/conf/desired"
sh "${UPDATE}" >/dev/null
check "update while disabled: hookctl not called" test "$(calls | grep -c hookctl)" -eq 0

setup upd-latched
touch "${S}/conf/latch"
sh "${UPDATE}" >/dev/null
check "update while latched: hookctl not called" test "$(calls | grep -c hookctl)" -eq 0

setup cron-busy
touch "${IF_PPPOE_FW_LOCK}" "${ST}/fwbusy"
sh "${IF_PPPOE_SCRIPTS}/reapply.sh" cron >/dev/null
check "cron during firmware run: skipped" test "$(calls | grep -c hookctl)" -eq 0
rm -f "${ST}/fwbusy"
sh "${IF_PPPOE_SCRIPTS}/reapply.sh" cron >/dev/null
contains "cron when idle: reapply" "$(calls)" "hookctl apply --reapply --reason=cron"

# --- ABI change (OPNsense major upgrade) -----------------------------------
HEAL="${SRC}/opnsense/scripts/if_pppoe/abi-heal.sh"
INSTALL_CALL="pkg install -f -y -U -r IfPppoe if-pppoe-kmod os-if-pppoe"

old_abi()
{
	# packages still the FreeBSD:14 build, booted into the 26.7 (FreeBSD:15) kernel
	setup "$1"
	echo FreeBSD:14:amd64 > "${ST}/pkgabi.if-pppoe-kmod"
	echo FreeBSD:14:amd64 > "${ST}/pkgabi.os-if-pppoe"
	echo 8b6a8cad00000000000000000000000000000000 > "${ST}/sysctl.kern.build_id"
}

pkgcalls()
{
	cat "${ST}/pkgcalls" 2>/dev/null
}

heal_result()
{
	sed -n 's/.*"result":"\([^"]*\)".*/\1/p' "${S}/conf/abi-heal.json" 2>/dev/null
}

old_abi abi-early
eq "old-ABI kmod: exit 0" "$(early)" 0
eq "old-ABI kmod: distinct boot reason" "$(bootres)" "failed:kmod-abi-mismatch"
contains "old-ABI kmod: notice names both ABIs" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/boot-failed")" \
    "installed if-pppoe-kmod is built for FreeBSD:14:amd64 but this system is FreeBSD:15:amd64"
contains "old-ABI kmod: boot.json carries the kmod identity" "$(cat "${IF_PPPOE_RUN_DIR}/boot.json")" '"kmod":{'
check "old-ABI kmod: early boot never installs" test "$(pkgcalls | grep -c -e 'pkg install' -e 'pkg update')" -eq 0
check "old-ABI kmod: boot.json is valid JSON" "${REAL_PHP:-php}" -r 'exit(is_array(json_decode(file_get_contents($argv[1]), true)) ? 0 : 1);' "${IF_PPPOE_RUN_DIR}/boot.json"

setup abi-early-match
echo 8b6a8cad00000000000000000000000000000000 > "${ST}/sysctl.kern.build_id"
early >/dev/null
eq "matching ABI, unknown kernel: still kernel-not-supported" "$(bootres)" "failed:kernel-not-supported"

old_abi abi-heal-now
sh "${HEAL}" now > "${ST}/out" 2>&1; rc=$?
eq "heal: exit 0" "${rc}" 0
eq "heal: pkg install -f exactly once" "$(pkgcalls | grep -c 'pkg install')" 1
contains "heal: reinstalls both from IfPppoe" "$(pkgcalls)" "${INSTALL_CALL}"
contains "heal: refreshes the IfPppoe catalogue first" "$(pkgcalls)" "pkg update -f -r IfPppoe"
check "heal: never removes a package" test "$(pkgcalls | grep -c -e 'pkg delete' -e 'pkg remove' -e 'autoremove')" -eq 0
eq "heal: recorded" "$(heal_result)" "healed"
contains "heal: reboot notice" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/abi-reboot")" "reboot to arm kernel PPPoE"
check "heal: no problem notice" test ! -f "${IF_PPPOE_RUN_DIR}/notice.d/abi-heal"
: > "${ST}/pkgcalls"
sh "${HEAL}" now >/dev/null 2>&1
eq "heal again after success: no-op" "$(pkgcalls | grep -c -e 'pkg install' -e 'pkg update')" 0
early >/dev/null
check "next boot clears the reboot notice" test ! -f "${IF_PPPOE_RUN_DIR}/notice.d/abi-reboot"

setup abi-heal-match
for m in now cron boot deferred; do
	sh "${HEAL}" "${m}" >/dev/null 2>&1
done
eq "matching ABI: no pkg update/install in any mode" "$(pkgcalls | grep -c -e 'pkg install' -e 'pkg update')" 0
check "matching ABI: nothing recorded" test ! -f "${S}/conf/abi-heal.json"

old_abi abi-heal-norepo
echo 3 > "${ST}/pkg.update.rc"   # no FreeBSD:15:amd64 directory in the repository (404)
sh "${HEAL}" now >/dev/null 2>&1
eq "repo lacks the ABI (catalogue fetch fails): no install" "$(pkgcalls | grep -c 'pkg install')" 0
eq "repo lacks the ABI: recorded" "$(heal_result)" "unreachable"
contains "repo lacks the ABI: notice keeps mpd5" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/abi-heal")" "mpd5 stays in use"

old_abi abi-heal-wrongcat
echo FreeBSD:14:amd64 > "${ST}/repoabi.if-pppoe-kmod"   # catalogue offers only the old build
sh "${HEAL}" now >/dev/null 2>&1
eq "repo offers another ABI: refused, no install" "$(pkgcalls | grep -c 'pkg install')" 0
eq "repo offers another ABI: recorded" "$(heal_result)" "refused"
contains "repo offers another ABI: notice" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/abi-heal")" "has no FreeBSD:15:amd64 build of if-pppoe-kmod"
: > "${ST}/pkgcalls"
IF_PPPOE_NOW=1000600 sh "${HEAL}" cron >/dev/null 2>&1
eq "cron within the hour after a refusal: no retry" "$(pkgcalls | grep -c 'pkg update')" 0
IF_PPPOE_NOW=1003700 sh "${HEAL}" cron >/dev/null 2>&1
eq "cron an hour later: retries" "$(pkgcalls | grep -c 'pkg update')" 1
echo FreeBSD:15:amd64 > "${ST}/repoabi.if-pppoe-kmod"
IF_PPPOE_NOW=1003800 sh "${HEAL}" now >/dev/null 2>&1
eq "build published: healed" "$(heal_result)" "healed"
check "build published: problem notice cleared" test ! -f "${IF_PPPOE_RUN_DIR}/notice.d/abi-heal"

old_abi abi-heal-installfail
echo 1 > "${ST}/pkg.install.rc"
sh "${HEAL}" now >/dev/null 2>&1
eq "pkg install fails: recorded" "$(heal_result)" "failed"
check "pkg install fails: no reboot notice" test ! -f "${IF_PPPOE_RUN_DIR}/notice.d/abi-reboot"
contains "pkg install fails: manual command in the notice" "$(cat "${IF_PPPOE_RUN_DIR}/notice.d/abi-heal")" "pkg install -f -r IfPppoe if-pppoe-kmod os-if-pppoe"

old_abi abi-heal-kmodonly
rm -f "${ST}/pkgabi.os-if-pppoe"   # only if-pppoe-kmod installed
sh "${HEAL}" now >/dev/null 2>&1
contains "only the kmod installed: reinstalls only it" "$(pkgcalls)" "pkg install -f -y -U -r IfPppoe if-pppoe-kmod"
check "only the kmod installed: never installs os-if-pppoe" test "$(pkgcalls | grep 'pkg install' | grep -c os-if-pppoe)" -eq 0

old_abi abi-heal-fwbusy
touch "${ST}/fwbusy" "${IF_PPPOE_FW_LOCK}"
sh "${HEAL}" now >/dev/null 2>&1
eq "firmware run in progress: no pkg update/install" "$(pkgcalls | grep -c -e 'pkg install' -e 'pkg update')" 0

old_abi abi-heal-locked
touch "${ST}/heallocked"
sh "${HEAL}" now >/dev/null 2>&1
eq "another heal running: nothing" "$(pkgcalls | grep -c -e 'pkg install' -e 'pkg update')" 0

old_abi abi-heal-deferred
touch "${ST}/pkgbusy"   # pkg still running; the sleep stub ends it
sh "${HEAL}" deferred >/dev/null 2>&1
contains "deferred: detaches via daemon" "$(pkgcalls)" "daemon /bin/sh"
contains "deferred: waits while pkg runs" "$(pkgcalls)" "sleep 10"
eq "deferred: then installs once" "$(pkgcalls | grep -c 'pkg install')" 1

old_abi abi-heal-boot-retry
echo 3 > "${ST}/pkg.update.rc"
IF_PPPOE_HEAL_TRIES=3 sh "${HEAL}" boot >/dev/null 2>&1
eq "boot: retries while the repository is unreachable" "$(pkgcalls | grep -c 'pkg update')" 3
eq "boot: sleeps between tries" "$(pkgcalls | grep -c "sleep 30")" 2
eq "boot: never installs without a catalogue" "$(pkgcalls | grep -c 'pkg install')" 0

old_abi abi-start
sh "${START}" >/dev/null 2>&1
contains "start syshook: old ABI is reinstalled" "$(pkgcalls)" "${INSTALL_CALL}"
eq "start syshook: recorded" "$(heal_result)" "healed"
setup abi-start-match
sh "${START}" >/dev/null 2>&1
check "start syshook, matching ABI: no heal started" test "$(pkgcalls | grep -c -e daemon -e 'pkg update')" -eq 0

old_abi abi-nopkg
export IF_PPPOE_PKG=""
early >/dev/null
eq "no package database: plain kernel-not-supported" "$(bootres)" "failed:kernel-not-supported"
sh "${HEAL}" now >/dev/null 2>&1; rc=$?
eq "no package database: heal exits 0" "${rc}" 0

# --- uninstall.sh (pkg delete) -------------------------------------------
UNINSTALL="${SRC}/opnsense/scripts/if_pppoe/uninstall.sh"
setup uninstall
: > "${IF_PPPOE_SCRIPTS}/hookctl.php"
mkdir -p "${IF_PPPOE_RUN_DIR}/reg"
printf '{\n    "friendly": "wan",\n    "state": "up"\n}\n' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
printf '{\n    "friendly": "opt2"\n}\n' > "${IF_PPPOE_RUN_DIR}/reg/pppoe1.json"
printf '{\n    "friendly": "x;reboot"\n}\n' > "${IF_PPPOE_RUN_DIR}/reg/pppoe2.json"
sh "${UNINSTALL}"; rc=$?
eq "uninstall: exit 0" "${rc}" 0
# order: revert first, then per interface reset -> destroy -> reconfigure
want="hookctl revert --reason=uninstall
engine reset wan pppoe0
ifconfig pppoe0 destroy
configctl -d interface reconfigure wan
engine reset opt2 pppoe1
ifconfig pppoe1 destroy
configctl -d interface reconfigure opt2
ifconfig pppoe2 destroy"
eq "uninstall: revert, then reset + reconfigure each WAN" "$(calls)" "${want}"
check "uninstall: run dir removed" test ! -d "${IF_PPPOE_RUN_DIR}"
check "uninstall: conf dir removed after a good revert" test ! -d "${IF_PPPOE_CONF_DIR}"

setup uninstall-revert-fails
: > "${IF_PPPOE_SCRIPTS}/hookctl.php"
echo 2 > "${ST}/hookctl.revert.rc"
mkdir -p "${IF_PPPOE_RUN_DIR}/reg"
printf '{\n    "friendly": "wan"\n}\n' > "${IF_PPPOE_RUN_DIR}/reg/pppoe0.json"
sh "${UNINSTALL}" >/dev/null 2>&1
contains "uninstall, revert failed: WAN still handed back" "$(calls)" "configctl -d interface reconfigure wan"
check "uninstall, revert failed: conf dir kept for recovery" test -d "${IF_PPPOE_CONF_DIR}"

# --- early syshook with the real hookctl.php ---------------------------
if [ -n "${REAL_PHP:-}" ]; then
	setup real
	export IF_PPPOE_PHP="${REAL_PHP}"
	export IF_PPPOE_SCRIPTS="${SRC}/opnsense/scripts/if_pppoe"
	export IF_PPPOE_NO_SYSLOG=1 IF_PPPOE_PKG=""
	cp "${FIX}/25.7.11" "${S}/interfaces.inc"
	printf '{"product_version":"25.7.11_9"}\n' > "${S}/core"
	export IF_PPPOE_TARGET="${S}/interfaces.inc" IF_PPPOE_CORE_META="${S}/core" IF_PPPOE_CONFIG_XML="${S}/none.xml"
	early >/dev/null
	eq "real hookctl: boot enabled" "$(bootres)" "enabled:ok"
	eq "real hookctl: 2 hook lines in target" "$(grep -c 'os-if-pppoe:v1' "${S}/interfaces.inc")" 2
	echo disabled > "${S}/conf/desired"
	early >/dev/null
	eq "real hookctl: disabled boot restores pristine" "$(sha "${S}/interfaces.inc")" "$(sha "${FIX}/25.7.11")"
	echo enabled > "${S}/conf/desired"
	early >/dev/null
	cp "${FIX}/25.7.11" "${S}/interfaces.inc"
	printf '{"product_version":"25.7.12"}\n' > "${S}/core"
	sh "${UPDATE}" >/dev/null
	eq "real hookctl: update syshook re-applies after core update" "$(grep -c 'os-if-pppoe:v1' "${S}/interfaces.inc")" 2
else
	echo "# skip: real-hookctl block (set REAL_PHP)"
fi

finish
