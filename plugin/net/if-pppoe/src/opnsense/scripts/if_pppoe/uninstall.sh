#!/bin/sh
# Synchronous teardown for a standalone `pkg delete if-pppoe` (risk-register
# #9), run directly and in the foreground by +PRE_DEINSTALL -- NOT detached.
# pkg reaps and SIGKILLs every descendant of a pkg-script the instant that
# script returns (freebsd/pkg libpkg/scripts.c: pkg_reaper_acquire()/
# pkg_reaper_release(), the latter a procctl(PROC_REAP_KILL) when children
# remain; present since commit 2d94413914, so in 25.7's pkg too), so a
# backgrounded `&` job here would never survive to run. This script's own
# files are still on disk while +PRE_DEINSTALL runs (pkg-script(5): plain
# `pkg delete` order is pre-deinstall, then unlink, then post-deinstall).
#
# Order matters:
#   1. collect friendly/device pairs from the engine registry;
#   2. revert the interfaces.inc hook, so no interface configure from here on
#      can be claimed by the kernel path;
#   3. engine reset each pair (down scripts, LCP TermReq + PADT, destroy);
#   4. ask core to reconfigure each interface, which now starts mpd5 (the
#      same last step as the engine's and lib.sh's fallback). configctl -d
#      hands the job to configd, so pkg's reaper cannot kill it.
# The IF_PPPOE_* variables exist for tests only; production uses the defaults.
set -u

: "${IF_PPPOE_SCRIPTS:=/usr/local/opnsense/scripts/if_pppoe}"
: "${IF_PPPOE_RUN_DIR:=/var/run/if_pppoe}"
: "${IF_PPPOE_CONF_DIR:=/conf/if_pppoe}"
: "${IF_PPPOE_PHP:=/usr/local/bin/php}"
: "${IF_PPPOE_CONFIGCTL:=/usr/local/sbin/configctl}"
: "${IF_PPPOE_TIMEOUT:=/bin/timeout}"
: "${IF_PPPOE_LOGGER:=/usr/bin/logger}"
: "${IF_PPPOE_IFCONFIG:=/sbin/ifconfig}"

REG_DIR="${IF_PPPOE_RUN_DIR}/reg"

log() { ${IF_PPPOE_LOGGER} -t if_pppoe -p daemon.notice "uninstall: $*"; }
warn() { ${IF_PPPOE_LOGGER} -t if_pppoe -p daemon.warning "uninstall: $*"; }

# 1. "friendly device" per line. Registry JSON is one field per line
# (State.php Fs::writeJson, JSON_PRETTY_PRINT), so sed is enough here.
pairs=""
for regfile in "$REG_DIR"/pppoe*.json; do
	[ -f "$regfile" ] || continue
	device=$(basename "$regfile" .json)
	friendly=$(sed -n 's/.*"friendly"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$regfile" | head -n1)
	case "$device" in
	pppoe[0-9]|pppoe[0-9][0-9]|pppoe[0-9][0-9][0-9]|pppoe[0-9][0-9][0-9][0-9]) ;;
	*) continue ;;
	esac
	case "$friendly" in
	""|*[!a-z0-9_]*)
		warn "unusable friendly name in $regfile; $device is only destroyed"
		friendly="-"
		;;
	esac
	pairs="${pairs}${friendly} ${device}
"
done

# 2. revert the hook
revert_ok=1
if [ -f "${IF_PPPOE_SCRIPTS}/hookctl.php" ]; then
	if "${IF_PPPOE_PHP}" "${IF_PPPOE_SCRIPTS}/hookctl.php" revert --reason=uninstall; then
		log "interfaces.inc hook reverted"
	else
		revert_ok=0
		warn "hookctl.php revert failed; interfaces.inc lines may remain (inert once the engine binary is gone: the hook checks is_executable() first)"
	fi
else
	revert_ok=0
	warn "hookctl.php missing, skipping hook revert (lines left behind are inert)"
fi

# 3. tear down every kernel session, 4. hand the interface back to core (mpd5)
printf '%s' "$pairs" | while read -r friendly device; do
	[ -n "$device" ] || continue
	if [ "$friendly" != "-" ] && [ -x "${IF_PPPOE_SCRIPTS}/engine" ]; then
		if ${IF_PPPOE_TIMEOUT} -k 5 45 "${IF_PPPOE_SCRIPTS}/engine" reset "$friendly" "$device"; then
			log "reset $friendly ($device)"
		else
			warn "engine reset $friendly ($device) failed; destroying the clone directly"
		fi
	fi
	# destroy sends PADT; harmless when the engine already did it
	${IF_PPPOE_IFCONFIG} "$device" destroy 2>/dev/null || true
	if [ "$friendly" != "-" ]; then
		${IF_PPPOE_CONFIGCTL} -d interface reconfigure "$friendly" || \
		    warn "could not ask core to reconfigure $friendly; it stays down until the next reconfigure or reboot"
	fi
done

# Deliberately does NOT touch the if_pppoe kmod: unloading it is
# if-pppoe-kmod's own +PRE_DEINSTALL job, which re-checks for live clones
# itself (the loop above has already cleared them by the time it runs).
rm -rf "${IF_PPPOE_RUN_DIR}"

# Only clear persistent state (including the pristine interfaces.inc
# backups hookctl keeps) once the revert above actually succeeded -- a
# failed revert needs those backups for manual repair.
if [ "$revert_ok" -eq 1 ]; then
	rm -rf "${IF_PPPOE_CONF_DIR}"
else
	warn "leaving ${IF_PPPOE_CONF_DIR} in place for manual recovery"
fi

log "teardown complete"
