#!/bin/sh
# os-if-pppoe: reinstall if-pppoe-kmod and os-if-pppoe from the IfPppoe repository when
# they were built for another ABI than this system's (after an OPNsense major upgrade;
# why that happens and when each mode runs: docs/plugin/INSTALL.md, "OPNsense major upgrades").
# usage: abi-heal.sh deferred|boot|cron|now|prefetch|offline.  Never removes a package, refuses
# unless the repository offers this system's ABI for every installed plugin package; always exits 0.
# prefetch (upgrade syshook) and offline (early syshook) skip the extra reboot when the
# upgrade's target ABI is known beforehand: see prefetch() and offline().

. "${IF_PPPOE_LIB:-/usr/local/opnsense/scripts/if_pppoe/lib.sh}"
: "${IF_PPPOE_DAEMON:=/usr/sbin/daemon}"
: "${IF_PPPOE_PGREP:=/bin/pgrep}"
: "${IF_PPPOE_SLEEP:=sleep}"
: "${IF_PPPOE_HEAL_WAIT:=1800}"
: "${IF_PPPOE_HEAL_TRIES:=10}"
: "${IF_PPPOE_HEAL_RETRY:=30}"
: "${IF_PPPOE_HEAL_BACKOFF:=3600}"
: "${IF_PPPOE_TAR:=/usr/bin/tar}"
: "${IF_PPPOE_FETCH:=/usr/bin/fetch}"
: "${IF_PPPOE_REPO_CONF:=/usr/local/etc/pkg/repos/IfPppoe.conf}"
STATE="${IF_PPPOE_CONF_DIR}/abi-heal.json"
# pkg output goes to a file, never a pipe: os-if-pppoe's +POST_INSTALL restarts daemons
# that would inherit a pipe and keep $(...) waiting after pkg is gone (see to_out)
OUT="${IF_PPPOE_RUN_DIR}/abi-heal.out"

mode="${1:-}"
case "${mode}" in
deferred|boot|cron|now|prefetch|offline) ;;
*) echo "usage: $0 deferred|boot|cron|now|prefetch|offline" >&2; exit 0 ;;
esac

[ -n "${IF_PPPOE_PKG}" ] || exit 0

# deferred and boot wait for minutes: detach from the caller (configd, rc) first
if [ -z "${IF_PPPOE_HEAL_BG:-}" ] && { [ "${mode}" = deferred ] || [ "${mode}" = boot ]; }; then
	IF_PPPOE_HEAL_BG=1 exec ${IF_PPPOE_DAEMON} -f /bin/sh "$0" "${mode}"
fi
# one heal at a time; a prefetch waits a little for a running heal rather than skip silently
if [ -z "${IF_PPPOE_HEAL_LOCKED:-}" ]; then
	mkdir -p "${IF_PPPOE_RUN_DIR}"
	if [ "${mode}" = prefetch ]; then
		# the child always exits 0: a failure is flock's (lock still held after 30s)
		IF_PPPOE_HEAL_LOCKED=1 ${IF_PPPOE_FLOCK} -w 30 "${IF_PPPOE_RUN_DIR}/abi-heal.lock" /bin/sh "$0" "${mode}" && exit 0
		ifp_log "abi-heal: prefetch skipped: another abi-heal.sh still holds ${IF_PPPOE_RUN_DIR}/abi-heal.lock; the first boot on the new ABI reinstalls over the network instead" warning
		exit 0
	fi
	IF_PPPOE_HEAL_LOCKED=1 exec ${IF_PPPOE_FLOCK} -n "${IF_PPPOE_RUN_DIR}/abi-heal.lock" /bin/sh "$0" "${mode}"
fi

# to_out <cmd...>: run <cmd...> in a subshell with its output in ${OUT} and no stdin
to_out()
{
	( "$@" ) > "${OUT}" 2>&1 < /dev/null
}

# out_tail: the last line of what to_out captured, for a log line
out_tail()
{
	tail -n 1 "${OUT}" 2>/dev/null
}

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

# installed_pkgs: the plugin packages installed here, each with a leading space
installed_pkgs()
{
	for _p in ${IF_PPPOE_PACKAGES}; do
		${IF_PPPOE_PKG} query %n "${_p}" >/dev/null 2>&1 && printf ' %s' "${_p}"
	done
}

# prefetch_dir <abi>: the local repository prefetch() builds for <abi>
prefetch_dir()
{
	echo "${IF_PPPOE_PREFETCH_DIR}/$(echo "${1}" | tr ':' '-')"
}

# repo_conf <dir> [<url>]: <dir>/IfPppoe.conf, a copy of the installed one (same fingerprints)
# with its url replaced by <url>; for pkg -R <dir>, so no other repository is used
repo_conf()
{
	mkdir -p "${1}" || return 1
	if [ -z "${2:-}" ]; then
		cp "${IF_PPPOE_REPO_CONF}" "${1}/${IF_PPPOE_REPO}.conf"
		return
	fi
	sed -E 's#^([[:space:]]*[Uu][Rr][Ll][[:space:]]*:[[:space:]]*)"[^"]*"#\1"'"${2}"'"#' \
	    "${IF_PPPOE_REPO_CONF}" > "${1}/${IF_PPPOE_REPO}.conf" &&
	    grep -qF "\"${2}\"" "${1}/${IF_PPPOE_REPO}.conf"
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

	pkgs=$(installed_pkgs)

	# the repository URL ends in ${ABI} (gen-repo-conf.sh), so this fetches the
	# catalogue for the new ABI; it fails when that directory does not exist
	# shellcheck disable=SC2086
	if ! to_out ${IF_PPPOE_PKG} update -f -r "${IF_PPPOE_REPO}"; then
		ifp_log "abi-heal: pkg update -r ${IF_PPPOE_REPO} failed: $(out_tail)" warning
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
	if to_out ${IF_PPPOE_PKG} install -f -y -U -r "${IF_PPPOE_REPO}" ${pkgs} && ! ifp_abi_mismatch >/dev/null; then
		record healed "${from}" "${to}"
		ifp_notice_clear abi-heal
		ifp_notice abi-reboot "reinstalled${pkgs} for ${to} (was ${from}); reboot to arm kernel PPPoE"
		return 0
	fi
	ifp_log "abi-heal: pkg install failed: $(out_tail)" err
	record failed "${from}" "${to}"
	ifp_notice abi-heal "installed if-pppoe-kmod is built for ${from} but this system is ${to}; reinstalling it failed, mpd5 stays in use (run: pkg install -f -r ${IF_PPPOE_REPO}${pkgs}, then reboot)"
	return 0
}

# prefetch: from the upgrade syshook (sets staged, not yet rebooted, network up): a local
# repository with the installed plugin packages for the staged ABI, for offline() to install.
# <dir>/.ready (target release and ABI) is written last: offline() ignores a prefetch without it,
# e.g. one the upgrade syshook's timeout cut short.
prefetch()
{
	rm -rf "${IF_PPPOE_PREFETCH_DIR}"
	pkgs=$(installed_pkgs)
	[ -n "${pkgs}" ] || return 0
	# every set carries the ABI it was built for (opnsense/tools build/common.sh generate_set())
	to=""
	for set in "${IF_PPPOE_UPGRADE_DIR}"/.sets.pending/kernel-*.txz "${IF_PPPOE_UPGRADE_DIR}"/.sets.pending/base-*.txz; do
		[ -f "${set}" ] || continue
		to=$(${IF_PPPOE_TAR} -xqOf "${set}" ./.abi_hint 2>/dev/null | head -n 1)
		[ -n "${to}" ] && break
	done
	from=$(${IF_PPPOE_PKG} config abi 2>/dev/null)
	case "${to}" in
	""|*[!A-Za-z0-9:_.-]*)
		ifp_log "abi-heal: prefetch: no ABI in the staged sets, nothing to fetch"
		return 0
		;;
	"${from}") return 0 ;;
	esac
	# the release being staged: opnsense-update -u writes it to .kernel.pending / .base.pending
	# next to the sets; after the last stage it is in /usr/local/opnsense/version/pkgs
	release=""
	for m in kernel base; do
		release=$(head -n 1 "${IF_PPPOE_UPGRADE_DIR}/.${m}.pending" 2>/dev/null)
		[ -n "${release}" ] && break
	done
	case "${release}" in
	""|*[!A-Za-z0-9._-]*)
		ifp_log "abi-heal: prefetch: no staged release in ${IF_PPPOE_UPGRADE_DIR}, nothing fetched" warning
		return 0
		;;
	esac
	# pkg wants OSVERSION with ABI (pkg.conf(5)); only the major is known before the reboot, so
	# use its .0 and skip the OS version check (the offline install runs it on the new system)
	osver=$(echo "${to}" | cut -d: -f2)
	case "${osver}" in
	""|*[!0-9]*) return 0 ;;
	esac
	osver=$((osver * 100000))
	url=$(sed -n -E 's#^[[:space:]]*[Uu][Rr][Ll][[:space:]]*:[[:space:]]*"([^"]*)".*#\1#p' "${IF_PPPOE_REPO_CONF}" 2>/dev/null | head -n 1)
	# shellcheck disable=SC2016
	url=$(echo "${url%/}" | sed 's#${ABI}#'"${to}"'#g')
	case "${url}" in
	http://*|https://*) ;;
	*)
		ifp_log "abi-heal: prefetch: no http(s) url in ${IF_PPPOE_REPO_CONF}, nothing fetched" warning
		return 0
		;;
	esac
	dir=$(prefetch_dir "${to}")
	work="${IF_PPPOE_PREFETCH_DIR}/.work"
	ifp_log "abi-heal: prefetch:${pkgs} for ${release} (${to}; this system is ${from})"

	# pkg for the new ABI with its own database, cache and repositories (steps() below, via to_out)
	# shellcheck disable=SC2317
	xpkg()
	{
		_r=$1
		shift
		${IF_PPPOE_PKG} -o ABI="${to}" -o OSVERSION="${osver}" -o IGNORE_OSVERSION=yes \
		    -o PKG_DBDIR="${work}/db" -o PKG_CACHEDIR="${work}/cache" -R "${_r}" "$@"
	}
	# fetch -o puts each package at its repository path, checksummed against the catalogue
	# (pkg-fetch(8)); then the signed catalogue as published; then it is all read back from
	# scratch as a file:// repository, exactly as offline() will
	# shellcheck disable=SC2086,SC2317
	steps()
	{
	    mkdir -p "${dir}" "${work}" && repo_conf "${work}/remote" &&
	    xpkg "${work}/remote" update -f -r "${IF_PPPOE_REPO}" &&
	    xpkg "${work}/remote" fetch -y -U -o "${dir}" -r "${IF_PPPOE_REPO}" ${pkgs} &&
	    for f in meta.conf data.pkg packagesite.pkg; do
		${IF_PPPOE_FETCH} -q -T 60 -o "${dir}/${f}" "${url}/${f}" || exit 1
	    done &&
	    rm -rf "${work}/db" "${work}/cache" && repo_conf "${work}/local" "file://${dir}" &&
	    xpkg "${work}/local" update -f -r "${IF_PPPOE_REPO}" &&
	    xpkg "${work}/local" fetch -y -U -o "${dir}" -r "${IF_PPPOE_REPO}" ${pkgs} &&
	    printf '%s %s\n' "${release}" "${to}" > "${dir}/.ready"
	}
	if to_out steps; then
		rm -rf "${work}" "${OUT}"
		ifp_log "abi-heal: prefetch: ready in ${dir}; the first ${to} boot installs it"
		return 0
	fi
	ifp_log "abi-heal: prefetch for ${to} failed: $(out_tail); the first ${to} boot reinstalls over the network instead" warning
	rm -rf "${IF_PPPOE_PREFETCH_DIR}" "${OUT}"
	return 0
}

# offline: from the early syshook, before the kmod gate: install what prefetch() fetched for
# this system's ABI and release from the local repository, so the kmod loads this boot. The
# prefetch is used once, whatever the outcome (its marker goes before pkg runs, so a run the
# timeout cuts short is not retried); a failure leaves the other modes to reinstall later.
offline()
{
	[ -d "${IF_PPPOE_PREFETCH_DIR}" ] || return 0
	# early/05-upgrade still has sets to install and reboots after each
	for m in kernel base pkgs; do
		[ -f "${IF_PPPOE_UPGRADE_DIR}/.${m}.pending" ] && return 0
	done
	if abi=$(ifp_abi_mismatch); then
		# shellcheck disable=SC2086
		set -- ${abi}
		from=$2
		to=$3
		dir=$(prefetch_dir "${to}")
		repos="${IF_PPPOE_PREFETCH_DIR}/.repos"
		pkgs=$(installed_pkgs)
		ready=$(head -n 1 "${dir}/.ready" 2>/dev/null)
		rm -f "${dir}/.ready"
		# opnsense-update writes the release to version/pkgs once its last stage (-P) is done
		release=$(head -n 1 "${IF_PPPOE_VERSION_DIR}/pkgs" 2>/dev/null)
		# shellcheck disable=SC2086
		if [ -z "${ready}" ]; then
			ifp_log "abi-heal: offline: nothing prefetched for ${to}"
		elif [ "${ready}" != "${release} ${to}" ]; then
			ifp_log "abi-heal: offline: the prefetch is for ${ready}, this system is ${release:-unknown} ${to}; discarded" warning
		elif ! repo_conf "${repos}" "file://${dir}" ||
		    ! to_out ${IF_PPPOE_PKG} -R "${repos}" update -f -r "${IF_PPPOE_REPO}"; then
			offline_failed
		elif old=$(older "${repos}" ${pkgs}); then
			ifp_log "abi-heal: offline: the prefetch has${old}, older than installed; discarded" warning
		elif to_out ${IF_PPPOE_PKG} -R "${repos}" install -f -y -U -r "${IF_PPPOE_REPO}" ${pkgs} &&
		    ! ifp_abi_mismatch >/dev/null; then
			record healed "${from}" "${to}"
			ifp_notice_clear abi-heal
			ifp_log "abi-heal: offline: reinstalled${pkgs} for ${to} (was ${from}) from the prefetch"
		else
			offline_failed
		fi
	fi
	# the IfPppoe repo database now names the removed file:// packagesite, which pkg refuses
	# ("wrong packagesite") until the next forced update: drop it with the prefetch
	rm -rf "${IF_PPPOE_PREFETCH_DIR}" "${IF_PPPOE_PKG_DBDIR}/repos/${IF_PPPOE_REPO}" "${OUT}"
}

offline_failed()
{
	ifp_log "abi-heal: offline install from ${dir} failed: $(out_tail); reinstalling over the network once it is up" warning
}

# older <repos> <pkg>...: the packages the -R <repos> catalogue has older than installed, each
# with a leading space; fails when there are none
older()
{
	_r=$1
	shift
	_o=""
	for _p; do
		_nv=$(${IF_PPPOE_PKG} -R "${_r}" rquery -U -r "${IF_PPPOE_REPO}" %v "${_p}" 2>/dev/null | head -n 1)
		_iv=$(${IF_PPPOE_PKG} query %v "${_p}" 2>/dev/null)
		if [ -n "${_nv}" ] && [ -n "${_iv}" ] && [ "$(${IF_PPPOE_PKG} version -t "${_nv}" "${_iv}")" = "<" ]; then
			_o="${_o} ${_p}-${_nv}"
		fi
	done
	[ -n "${_o}" ] && echo "${_o}"
}

case "${mode}" in
prefetch)
	prefetch
	;;
offline)
	offline
	;;
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
