#!/bin/sh
# os-if-pppoe: reinstall if-pppoe-kmod and os-if-pppoe from the IfPppoe repository when
# they were built for another ABI than this system's (after an OPNsense major upgrade;
# why that happens and when each mode runs: docs/plugin/INSTALL.md, "OPNsense major upgrades").
# usage: abi-heal.sh deferred|boot|cron|now.  Never removes a package, refuses unless the
# repository offers this system's ABI for every installed plugin package; always exits 0.

. "${IF_PPPOE_LIB:-/usr/local/opnsense/scripts/if_pppoe/lib.sh}"
: "${IF_PPPOE_DAEMON:=/usr/sbin/daemon}"
: "${IF_PPPOE_PGREP:=/bin/pgrep}"
: "${IF_PPPOE_SLEEP:=sleep}"
: "${IF_PPPOE_HEAL_WAIT:=1800}"
: "${IF_PPPOE_HEAL_TRIES:=10}"
: "${IF_PPPOE_HEAL_RETRY:=30}"
: "${IF_PPPOE_HEAL_BACKOFF:=3600}"
IF_PPPOE_REPO=IfPppoe
STATE="${IF_PPPOE_CONF_DIR}/abi-heal.json"

mode="${1:-}"
case "${mode}" in
deferred|boot|cron|now) ;;
*) echo "usage: $0 deferred|boot|cron|now" >&2; exit 0 ;;
esac

[ -n "${IF_PPPOE_PKG}" ] || exit 0

# deferred and boot wait for minutes: detach from the caller (configd, rc) first
if [ -z "${IF_PPPOE_HEAL_BG:-}" ] && { [ "${mode}" = deferred ] || [ "${mode}" = boot ]; }; then
	IF_PPPOE_HEAL_BG=1 exec ${IF_PPPOE_DAEMON} -f /bin/sh "$0" "${mode}"
fi
# one heal at a time
if [ -z "${IF_PPPOE_HEAL_LOCKED:-}" ]; then
	mkdir -p "${IF_PPPOE_RUN_DIR}"
	IF_PPPOE_HEAL_LOCKED=1 exec ${IF_PPPOE_FLOCK} -n "${IF_PPPOE_RUN_DIR}/abi-heal.lock" /bin/sh "$0" "${mode}"
fi

record()
{
	# record <result> <from> <to>: fixed words and sanitised ABI strings only
	mkdir -p "${IF_PPPOE_CONF_DIR}"
	printf '{"at":%s,"mode":"%s","result":"%s","from":"%s","to":"%s"}\n' \
	    "$(ifp_now)" "${mode}" "${1}" "${2}" "${3}" > "${STATE}"
}

# a firmware run, or any pkg / opnsense-update still at work (early/05-upgrade runs
# opnsense-update -P without the firmware lock)
busy()
{
	ifp_firmware_busy && return 0
	${IF_PPPOE_PGREP} -q -x 'pkg(-static)?' 2>/dev/null && return 0
	${IF_PPPOE_PGREP} -q -f '(^|/)opnsense-update( |$)' 2>/dev/null && return 0
	return 1
}

# heal: 0 done or nothing to do, 1 retry later (busy or repository unreachable)
heal()
{
	if ! abi=$(ifp_abi_mismatch); then
		ifp_notice_clear abi-heal
		return 0
	fi
	# shellcheck disable=SC2086
	set -- ${abi}
	from=$2
	to=$3
	busy && return 1

	pkgs=""
	for p in ${IF_PPPOE_PACKAGES}; do
		${IF_PPPOE_PKG} query %n "${p}" >/dev/null 2>&1 && pkgs="${pkgs} ${p}"
	done

	# the repository URL ends in ${ABI} (gen-repo-conf.sh), so this fetches the
	# catalogue for the new ABI; it fails when that directory does not exist
	if ! out=$(${IF_PPPOE_PKG} update -f -r "${IF_PPPOE_REPO}" 2>&1); then
		ifp_log "abi-heal: pkg update -r ${IF_PPPOE_REPO} failed: $(echo "${out}" | tail -n 1)" warning
		record unreachable "${from}" "${to}"
		ifp_notice abi-heal "installed if-pppoe-kmod is built for ${from} but this system is ${to}; the ${IF_PPPOE_REPO} repository is unreachable or has no ${to} build, so mpd5 stays in use (retrying; or run: pkg install -f -r ${IF_PPPOE_REPO}${pkgs}, then reboot)"
		return 1
	fi
	for p in ${pkgs}; do
		r=$(${IF_PPPOE_PKG} rquery -U -r "${IF_PPPOE_REPO}" %q "${p}" 2>/dev/null | head -n 1)
		case "${r}" in
		""|*[!A-Za-z0-9:_.*-]*) r="" ;;
		esac
		# shellcheck disable=SC2254
		case "${to}" in
		${r:-/}) ;;
		*)
			ifp_log "abi-heal: ${IF_PPPOE_REPO} offers ${p} for '${r:-none}', not ${to}; not reinstalling" warning
			record refused "${from}" "${to}"
			ifp_notice abi-heal "installed if-pppoe-kmod is built for ${from} but this system is ${to}, and the ${IF_PPPOE_REPO} repository has no ${to} build of ${p}; kernel PPPoE stays off and mpd5 is used until one is published"
			return 0
			;;
		esac
	done

	ifp_log "abi-heal: reinstalling${pkgs} from ${IF_PPPOE_REPO}: installed for ${from}, system is ${to}"
	# shellcheck disable=SC2086
	if out=$(${IF_PPPOE_PKG} install -f -y -U -r "${IF_PPPOE_REPO}" ${pkgs} 2>&1) && ! ifp_abi_mismatch >/dev/null; then
		record healed "${from}" "${to}"
		ifp_notice_clear abi-heal
		ifp_notice abi-reboot "reinstalled${pkgs} for ${to} (was ${from}); reboot to arm kernel PPPoE"
		return 0
	fi
	ifp_log "abi-heal: pkg install failed: $(echo "${out}" | tail -n 1)" err
	record failed "${from}" "${to}"
	ifp_notice abi-heal "installed if-pppoe-kmod is built for ${from} but this system is ${to}; reinstalling it failed, mpd5 stays in use (run: pkg install -f -r ${IF_PPPOE_REPO}${pkgs}, then reboot)"
	return 0
}

case "${mode}" in
deferred)
	waited=0
	while busy && [ "${waited}" -lt "${IF_PPPOE_HEAL_WAIT}" ]; do
		${IF_PPPOE_SLEEP} 10
		waited=$((waited + 10))
	done
	heal
	;;
boot)
	n=1
	until heal || [ "${n}" -ge "${IF_PPPOE_HEAL_TRIES}" ]; do
		${IF_PPPOE_SLEEP} "${IF_PPPOE_HEAL_RETRY}"
		n=$((n + 1))
	done
	;;
cron)
	# a refusal or failed install waits an hour; unreachable retries every run
	last=$(sed -n -E 's/.*"at":([0-9]+),.*"result":"(refused|failed)".*/\1/p' "${STATE}" 2>/dev/null)
	if [ -n "${last}" ] && [ $(($(ifp_now) - last)) -lt "${IF_PPPOE_HEAL_BACKOFF}" ] && ifp_abi_mismatch >/dev/null; then
		exit 0
	fi
	heal
	;;
now)
	heal
	;;
esac
exit 0
