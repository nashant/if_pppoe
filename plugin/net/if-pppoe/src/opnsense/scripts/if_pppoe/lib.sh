#!/bin/sh
# Shared helpers for the os-if-pppoe syshooks (sourced, /bin/sh only).
# The IF_PPPOE_* variables exist so tests can relocate state and stub the
# system tools; production uses the defaults.

: "${IF_PPPOE_CONF_DIR:=/conf/if_pppoe}"
: "${IF_PPPOE_RUN_DIR:=/var/run/if_pppoe}"
: "${IF_PPPOE_SCRIPTS:=/usr/local/opnsense/scripts/if_pppoe}"
: "${IF_PPPOE_KMOD_DIR:=/usr/local/lib/if_pppoe}"
: "${IF_PPPOE_BUILD_IDS:=/usr/local/share/if_pppoe/build_ids}"
: "${IF_PPPOE_FEATURES_FILE:=/usr/local/share/if_pppoe/features}"
: "${IF_PPPOE_PHP:=/usr/local/bin/php}"
: "${IF_PPPOE_SYSCTL:=/sbin/sysctl}"
: "${IF_PPPOE_KLDLOAD:=/sbin/kldload}"
: "${IF_PPPOE_KLDUNLOAD:=/sbin/kldunload}"
: "${IF_PPPOE_KLDSTAT:=/sbin/kldstat}"
: "${IF_PPPOE_SHA256:=/sbin/sha256 -q}"
: "${IF_PPPOE_IFCONFIG:=/sbin/ifconfig}"
: "${IF_PPPOE_CONFIGCTL:=/usr/local/sbin/configctl}"
: "${IF_PPPOE_LOGGER:=/usr/bin/logger}"
: "${IF_PPPOE_TIMEOUT:=/bin/timeout}"
: "${IF_PPPOE_NOW:=}"
# "" = no package database (tests): the ABI check reports no mismatch
: "${IF_PPPOE_PKG=/usr/local/sbin/pkg}"
: "${IF_PPPOE_FW_LOCK:=/tmp/pkg_upgrade.progress}"
: "${IF_PPPOE_FLOCK:=/usr/local/bin/flock}"

IF_PPPOE_FEATURES="linkevents ipv6 mssfix pfil_pass_foreign single_bytecount"
IF_PPPOE_STRIKE_MAX=3
IF_PPPOE_STRIKE_WINDOW=86400
# the packages this plugin installs from its own IfPppoe repository
IF_PPPOE_PACKAGES="if-pppoe-kmod os-if-pppoe"

ifp_now()
{
	if [ -n "${IF_PPPOE_NOW}" ]; then
		echo "${IF_PPPOE_NOW}"
	else
		date +%s
	fi
}

ifp_log()
{
	${IF_PPPOE_LOGGER} -t if_pppoe -p "user.${2:-notice}" -- "${1}" 2>/dev/null
	echo "if_pppoe: ${1}"
}

# ifp_notice <key> <message>: one file per notice, read by the plugin's
# status class; the key is a fixed identifier chosen by the caller.
ifp_notice()
{
	mkdir -p "${IF_PPPOE_RUN_DIR}/notice.d"
	printf '%s\n' "${2}" > "${IF_PPPOE_RUN_DIR}/notice.d/${1}"
	ifp_log "${2}" warning
}

ifp_notice_clear()
{
	rm -f "${IF_PPPOE_RUN_DIR}/notice.d/${1}"
}

ifp_hookctl()
{
	${IF_PPPOE_PHP} "${IF_PPPOE_SCRIPTS}/hookctl.php" "$@"
}

ifp_desired()
{
	_d=$(head -n 1 "${IF_PPPOE_CONF_DIR}/desired" 2>/dev/null)
	case "${_d}" in
	enabled) echo enabled ;;
	*) echo disabled ;;
	esac
}

# ifp_boot_state <result> <reason> [<json member>]: fixed-vocabulary words only
# (no quoting needed); the optional third argument is appended verbatim
# (ifp_kmod_identity output).
ifp_boot_state()
{
	mkdir -p "${IF_PPPOE_RUN_DIR}"
	printf '{"desired":"%s","result":"%s","reason":"%s","at":%s%s}\n' \
	    "$(ifp_desired)" "${1}" "${2}" "$(ifp_now)" "${3:+,${3}}" > "${IF_PPPOE_RUN_DIR}/boot.json"
}

# ifp_sha256_of <file>: lowercase hex sha256, or nothing when unreadable
ifp_sha256_of()
{
	[ -f "${1}" ] || return 0
	_h=$(${IF_PPPOE_SHA256} "${1}" 2>/dev/null | awk '{print tolower($1)}')
	case "${_h}" in
	*[!0-9a-f]*) ;;
	*) echo "${_h}" ;;
	esac
}

# ifp_kmod_identity: the installed if-pppoe-kmod files this boot's gate read, as a
# boot.json member ("" = absent). Lets the plugin tell "a new package was installed
# since this failed boot" from "nothing changed" (Engine::kmodFixedSinceBoot()).
ifp_kmod_identity()
{
	_ibid=$(${IF_PPPOE_SYSCTL} -n kern.build_id 2>/dev/null)
	_iko=""
	case "${_ibid}" in
	""|*[!0-9a-fA-F]*) ;;
	*) _iko=$(ifp_sha256_of "${IF_PPPOE_KMOD_DIR}/${_ibid}/if_pppoe.ko") ;;
	esac
	printf '"kmod":{"build_ids":"%s","features":"%s","ko":"%s"}' \
	    "$(ifp_sha256_of "${IF_PPPOE_BUILD_IDS}")" "$(ifp_sha256_of "${IF_PPPOE_FEATURES_FILE}")" "${_iko}"
}

ifp_kmod_loaded()
{
	${IF_PPPOE_KLDSTAT} -q -n if_pppoe.ko 2>/dev/null
}

ifp_kmod_unload()
{
	if ifp_kmod_loaded; then
		${IF_PPPOE_KLDUNLOAD} -n if_pppoe.ko 2>/dev/null || \
		    ifp_log "could not unload if_pppoe.ko" warning
	fi
	rm -f "${IF_PPPOE_RUN_DIR}/loaded.json"
}

# ifp_kmod_record_loaded <ko-path>: records what's actually resident, so the
# plugin can later tell an installed-but-not-yet-loaded upgrade from a match.
ifp_kmod_record_loaded()
{
	_bid=$(${IF_PPPOE_SYSCTL} -n kern.build_id 2>/dev/null)
	_sum=$(${IF_PPPOE_SHA256} "${1}" 2>/dev/null | awk '{print tolower($1)}')
	[ -n "${_bid}" ] && [ -n "${_sum}" ] || return 0
	mkdir -p "${IF_PPPOE_RUN_DIR}"
	printf '{"build_id":"%s","sha256":"%s"}\n' "$(echo "${_bid}" | tr 'A-F' 'a-f')" "${_sum}" \
	    > "${IF_PPPOE_RUN_DIR}/loaded.json"
}

# ifp_kmod_path: print the shipped module for the running kernel, or fail
# with the reason on stdout.
ifp_kmod_path()
{
	_bid=$(${IF_PPPOE_SYSCTL} -n kern.build_id 2>/dev/null)
	case "${_bid}" in
	""|*[!0-9a-fA-F]*)
		echo "no-build-id"
		return 1
		;;
	esac
	_line=$(awk -v id="${_bid}" 'tolower($1) == tolower(id) { print; exit }' "${IF_PPPOE_BUILD_IDS}" 2>/dev/null)
	if [ -z "${_line}" ]; then
		echo "kernel-not-supported"
		return 1
	fi
	_ko="${IF_PPPOE_KMOD_DIR}/${_bid}/if_pppoe.ko"
	if [ ! -f "${_ko}" ]; then
		echo "kmod-missing"
		return 1
	fi
	# optional second field: sha256 of the .ko
	_want=$(echo "${_line}" | awk '{print tolower($2)}')
	case "${_want}" in
	"") ;;
	*)
		_have=$(${IF_PPPOE_SHA256} "${_ko}" 2>/dev/null | awk '{print tolower($1)}')
		if [ "${_have}" != "${_want}" ]; then
			echo "kmod-checksum"
			return 1
		fi
		;;
	esac
	echo "${_ko}"
}

# ifp_firmware_busy: a core firmware run holds its lock (same probe as core's
# scripts/firmware/running.sh; launcher.sh takes it with flock -n -o)
ifp_firmware_busy()
{
	[ -f "${IF_PPPOE_FW_LOCK}" ] && ! ${IF_PPPOE_FLOCK} -n "${IF_PPPOE_FW_LOCK}" true 2>/dev/null
}

# ifp_abi_mismatch: prints "<package> <package-abi> <system-abi>" and succeeds when an installed
# plugin package was built for another ABI than this system's `pkg config abi`
# (pkg-config(8), pkg-query(8) %q). An OPNsense major upgrade switches the ABI
# (FreeBSD:14:amd64 -> FreeBSD:15:amd64) but only upgrades the OPNsense repository's
# packages (opnsense-update install_pkgs(): `pkg upgrade -fy -r OPNsense`), so ours
# keep the old build at the same version and pkg never replaces them.
ifp_abi_mismatch()
{
	[ -n "${IF_PPPOE_PKG}" ] || return 1
	_sys=$(${IF_PPPOE_PKG} config abi 2>/dev/null)
	case "${_sys}" in
	""|*[!A-Za-z0-9:_.-]*) return 1 ;;
	esac
	for _p in ${IF_PPPOE_PACKAGES}; do
		_q=$(${IF_PPPOE_PKG} query %q "${_p}" 2>/dev/null)
		case "${_q}" in
		""|*[!A-Za-z0-9:_.*-]*) continue ;;
		esac
		# a package ABI may carry a '*' wildcard (FreeBSD:15:*): match it as a pattern
		# shellcheck disable=SC2254
		case "${_sys}" in
		${_q}) ;;
		*)
			echo "${_p} ${_q} ${_sys}"
			return 0
			;;
		esac
	done
	return 1
}

ifp_kmod_features()
{
	for _f in ${IF_PPPOE_FEATURES}; do
		_v=$(${IF_PPPOE_SYSCTL} -n "kern.features.if_pppoe_${_f}" 2>/dev/null)
		if [ "${_v}" != "1" ]; then
			echo "feature-${_f}"
			return 1
		fi
	done
	return 0
}

# ifp_fallback_to_mpd5: tear down every clone the engine registered and let
# core reconfigure the interface (the hook is absent, so core starts mpd5).
# Only for when `engine reconcile --after-firmware` is missing or fails (reapply.sh).
ifp_fallback_to_mpd5()
{
	for _reg in "${IF_PPPOE_RUN_DIR}"/reg/*.json; do
		[ -f "${_reg}" ] || continue
		_dev=$(basename "${_reg}" .json)
		_fr=$(sed -n 's/.*"friendly"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${_reg}" | head -n 1)
		case "${_dev}" in
		pppoe[0-9]|pppoe[0-9][0-9]|pppoe[0-9][0-9][0-9]) ;;
		*) continue ;;
		esac
		case "${_fr}" in
		""|*[!a-z0-9_]*) _fr="" ;;
		esac
		if [ -n "${_fr}" ] && [ -x "${IF_PPPOE_SCRIPTS}/engine" ]; then
			${IF_PPPOE_TIMEOUT} -k 5 45 "${IF_PPPOE_SCRIPTS}/engine" reset "${_fr}" "${_dev}" || true
		fi
		# destroy sends PADT; harmless if the engine already did it
		${IF_PPPOE_IFCONFIG} "${_dev}" destroy 2>/dev/null || true
		rm -f "${_reg}"
		if [ -n "${_fr}" ]; then
			ifp_log "falling back to mpd5 on ${_fr} (${_dev})" warning
			${IF_PPPOE_CONFIGCTL} -d interface reconfigure "${_fr}" || true
		fi
	done
}
