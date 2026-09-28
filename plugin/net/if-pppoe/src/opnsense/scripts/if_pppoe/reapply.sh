#!/bin/sh
# os-if-pppoe: put the interfaces.inc hook back after core replaced the file.
# usage: reapply.sh update|trigger|cron.  On refusal, managed WANs move to mpd5.
# Always exits 0 so it can never fail a core update.

. "${IF_PPPOE_LIB:-/usr/local/opnsense/scripts/if_pppoe/lib.sh}"
: "${IF_PPPOE_FW_LOCK:=/tmp/pkg_upgrade.progress}"
: "${IF_PPPOE_FLOCK:=/usr/local/bin/flock}"

reason="${1:-update}"
case "${reason}" in
update|trigger|cron) ;;
*) echo "usage: $0 update|trigger|cron" >&2; exit 0 ;;
esac

[ "$(ifp_desired)" = "enabled" ] || exit 0
[ -f "${IF_PPPOE_CONF_DIR}/latch" ] && exit 0

if [ "${reason}" = "cron" ] && [ -f "${IF_PPPOE_FW_LOCK}" ]; then
	# same probe as core's scripts/firmware/running.sh
	if ! ${IF_PPPOE_FLOCK} -n "${IF_PPPOE_FW_LOCK}" true 2>/dev/null; then
		exit 0
	fi
fi

out=$(ifp_hookctl apply --reapply --reason="${reason}" 2>/dev/null)
case "${out}" in
*"(reapply: nothing to do)"*)
	;;
applied*|reverted*)
	ifp_notice_clear update-fallback
	;;
refused:*|foreign*|paused:*)
	ifp_notice update-fallback "interfaces.inc hook not re-applied after a core change (${out}); PPPoE moved to mpd5"
	# The engine owns the handover; the shell copy is only for a missing or failing engine
	# (non-zero also means it could not hand back every WAN; the shell takes what is left).
	if [ -x "${IF_PPPOE_SCRIPTS}/engine" ] && \
	    ${IF_PPPOE_TIMEOUT} -k 5 120 "${IF_PPPOE_SCRIPTS}/engine" reconcile --after-firmware; then
		:
	else
		ifp_log "engine reconcile --after-firmware unavailable or failed; using the shell fallback" warning
		ifp_fallback_to_mpd5
	fi
	;;
*)
	ifp_log "hookctl reapply gave unexpected output: ${out}" err
	;;
esac
exit 0
