#!/bin/sh
# hookctl apply/revert/status/selftest against real interfaces.inc copies
# from OPNsense 25.7, 25.7.11, 26.1, 26.1.11 and 26.7.4 (see
# ../README.md for fixture provenance).
set -u
. "$(dirname "$0")/lib.sh"

export IF_PPPOE_NO_SYSLOG=1
export IF_PPPOE_PKG=""

setup()
{
	# setup <name> <fixture-tag> [core-version]
	W="${IF_PPPOE_TEST_TMP}/$1"
	rm -rf "${W}"
	mkdir -p "${W}/conf" "${W}/run" "${W}/inc"
	cp "${FIX}/$2" "${W}/inc/interfaces.inc"
	printf '{"product_version":"%s"}\n' "${3:-$2}" > "${W}/core"
	export IF_PPPOE_CONF_DIR="${W}/conf"
	export IF_PPPOE_RUN_DIR="${W}/run"
	export IF_PPPOE_TARGET="${W}/inc/interfaces.inc"
	export IF_PPPOE_CORE_META="${W}/core"
	export IF_PPPOE_CONFIG_XML="${W}/config.xml"
	T="${IF_PPPOE_TARGET}"
}

hk()
{
	${PHP} "${HOOKCTL}" "$@" 2>>"${W}/stderr"
}

stored()
{
	sed -n 's/^ *"status": "\(.*\)",*$/\1/p' "${IF_PPPOE_CONF_DIR}/hook.json"
}

live()
{
	hk status --json | sed -n 's/^ *"live": "\(.*\)",*$/\1/p'
}

for tag in 25.7 25.7.11 26.1 26.1.11 26.7.4; do
	setup "t-${tag}" "${tag}"
	orig=$(sha "${T}")
	eq "${tag}: live status pristine before apply" "$(live)" "pristine"
	out=$(hk apply --reason=test); rc=$?
	eq "${tag}: apply rc" "${rc}" 0
	eq "${tag}: apply output" "${out}" "applied"
	eq "${tag}: stored status" "$(stored)" "applied"
	eq "${tag}: status command" "$(hk status)" "applied"
	added=$(diff "${FIX}/${tag}" "${T}" | grep -c '^>')
	removed=$(diff "${FIX}/${tag}" "${T}" | grep -c '^<')
	eq "${tag}: exactly 2 lines added" "${added}" 2
	eq "${tag}: 0 lines removed" "${removed}" 0
	eq "${tag}: 2 markers" "$(grep -c 'os-if-pppoe:v1' "${T}")" 2
	# first statement of interface_ppps_reset
	n=$(grep -n '^function interface_ppps_reset(' "${T}" | cut -d: -f1)
	eq "${tag}: reset line is first statement" \
	    "$(sed -n "$((n + 2))p" "${T}" | cut -c1-24)" "    /* os-if-pppoe:v1 */"
	n=$(grep -n '    /\* fire up mpd \*/' "${T}" | cut -d: -f1)
	contains "${tag}: configure line right before /* fire up mpd */" \
	    "$(sed -n "$((n - 1))p" "${T}")" "engine configure %s %s %s %s %s"
	check "${tag}: php -l on patched file" ${PHP} -l "${T}"
	eq "${tag}: selftest" "$(hk selftest)" "ok"
	check "${tag}: pristine backup keyed by version+sha" \
	    test -f "${IF_PPPOE_CONF_DIR}/pristine/interfaces.inc.${tag}.${orig}"
	h1=$(sha "${T}")
	out=$(hk apply); rc=$?
	eq "${tag}: re-apply rc (idempotent)" "${rc}" 0
	eq "${tag}: re-apply leaves file unchanged" "$(sha "${T}")" "${h1}"
	out=$(hk revert --reason=test); rc=$?
	eq "${tag}: revert rc" "${rc}" 0
	eq "${tag}: revert byte-identical" "$(sha "${T}")" "${orig}"
	eq "${tag}: stored status after revert" "$(stored)" "reverted"
	out=$(hk revert); rc=$?
	eq "${tag}: second revert is a no-op" "${rc}:$(sha "${T}")" "0:${orig}"
	# functional: the real patched functions with stubbed helpers
	hk apply >/dev/null
	res=$(${PHP} "${HERE}/harness.php" "${T}")
	contains "${tag}: claimed -> no mpd5, engine argv" "${res}" \
	    '{"scenario":"claimed","engine":["reset:wan|pppoe0:mute","configure:wan|pppoe0|igb0|1492|:mute"],"mpd5":0,"killbypid":2}'
	contains "${tag}: ineligible -> mpd5" "${res}" '"scenario":"ineligible","engine":["reset:wan|pppoe0:mute","configure:wan|pppoe0|igb0|1492|:mute"],"mpd5":1'
	contains "${tag}: timeout -> mpd5" "${res}" '"scenario":"timeout","engine":["reset:wan|pppoe0:mute","configure:wan|pppoe0|igb0|1492|:mute"],"mpd5":1'
	contains "${tag}: no engine -> mpd5" "${res}" '{"scenario":"no-engine","engine":[],"mpd5":1,"killbypid":2}'
	contains "${tag}: engine throws -> mpd5" "${res}" '"scenario":"engine-throws","engine":["reset:wan|pppoe0:mute","configure:wan|pppoe0|igb0|1492|:mute"],"mpd5":1,"killbypid":2}'
	contains "${tag}: mtu/mru passed" "${res}" '"configure:wan|pppoe0|igb0|1500|1492:mute"'
	res=$(${PHP} "${HERE}/harness.php" "${FIX}/${tag}")
	contains "${tag}: pristine file -> no engine, mpd5" "${res}" '{"scenario":"claimed","engine":[],"mpd5":1,"killbypid":2}'
done

# --- refusals ---------------------------------------------------------

setup neg-anchor 25.7.11
sed 's#/usr/local/sbin/mpd5 -b -d /var/etc#/usr/local/sbin/mpd5 -b -k -d /var/etc#' "${FIX}/25.7.11" > "${T}"
before=$(sha "${T}")
out=$(hk apply); rc=$?
eq "modified configure anchor: refused rc" "${rc}" 2
contains "modified configure anchor: status" "${out}" "refused:anchor"
eq "modified configure anchor: file unchanged" "$(sha "${T}")" "${before}"

setup neg-reset-anchor 25.7.11
sed 's#^function interface_ppps_reset(\$interface, \$suspend, \$ifcfg, \$ppps)#function interface_ppps_reset($interface, $suspend, $ifcfg, $ppps, $x = null)#' "${FIX}/25.7.11" > "${T}"
out=$(hk apply); rc=$?
eq "modified reset signature: refused" "${rc}:${out%% *}" "2:refused:anchor"

setup neg-dup2 25.7.11
{ cat "${FIX}/25.7.11"; awk '/^function interface_ppps_reset\(/,/^}/' "${FIX}/25.7.11"; } > "${T}"
before=$(sha "${T}")
out=$(hk apply); rc=$?
eq "duplicate reset context: refused" "${rc}:${out%% *}" "2:refused:anchor"
eq "duplicate reset context: file unchanged" "$(sha "${T}")" "${before}"

setup neg-outside 25.7.11
# the configure context moved out of interface_ppps_configure()
{ cat "${FIX}/25.7.11" | sed "s#^    legacy_interface_flags(\$ifcfg\['if'\], 'down', false);\$#    legacy_interface_flags(\$ifcfg['if'], 'down',  false);#"; \
  printf 'function other($ifcfg)\n{\n    legacy_interface_flags($ifcfg['"'"'if'"'"'], '"'"'down'"'"', false);\n\n    /* fire up mpd */\n    mwexecf(\n        '"'"'/usr/local/sbin/mpd5 -b -d /var/etc -f %%s -p %%s -s ppp %%s'"'"',\n    );\n}\n'; } > "${T}"
out=$(hk apply); rc=$?
eq "context outside the function: refused" "${rc}:${out%% *}" "2:refused:anchor"

setup neg-foreign 25.7.11
sed 's#^    /\* fire up mpd \*/#    /* os-if-pppoe:v0 */ foo();\n&#' "${FIX}/25.7.11" > "${T}"
before=$(sha "${T}")
out=$(hk apply); rc=$?
eq "foreign marker: refused" "${rc}:${out%% *}" "2:foreign"
eq "foreign marker: file unchanged" "$(sha "${T}")" "${before}"
eq "foreign marker: status command" "$(hk status)" "foreign"

mkpkg()
{
	printf "#!/bin/sh\necho '/usr/local/etc/inc/interfaces.inc 1\$%s'\n" "$1" > "${W}/pkg"
	chmod +x "${W}/pkg"
}
setup neg-pkgsum 25.7.11
mkpkg 0000000000000000000000000000000000000000000000000000000000000000
before=$(sha "${T}")
out=$(IF_PPPOE_PKG="${W}/pkg" hk apply); rc=$?
eq "pkg checksum differs: foreign" "${rc}:${out}" "2:foreign (pkg-checksum)"
eq "pkg checksum differs: file unchanged" "$(sha "${T}")" "${before}"
out=$(IF_PPPOE_PKG="${W}/pkg" hk apply --reason=update); rc=$?
eq "pkg probe skipped during core update" "${rc}:${out}" "0:applied"
setup pos-pkgsum 25.7.11
mkpkg "$(sha "${T}")"
out=$(IF_PPPOE_PKG="${W}/pkg" hk apply); rc=$?
eq "pkg checksum matches: applies" "${rc}:${out}" "0:applied"

setup neg-lint 25.7.11
printf '\nfunction broken( {\n' >> "${T}"
before=$(sha "${T}")
out=$(hk apply); rc=$?
eq "pre-existing syntax error: refused:lint" "${rc}:${out%% *}" "2:refused:lint"
eq "pre-existing syntax error: file unchanged" "$(sha "${T}")" "${before}"
check "lint refusal leaves no temp file" test -z "$(ls -A "${W}/inc" | grep -v '^interfaces.inc$')"

setup neg-ha 25.7.11
printf '<?xml version="1.0"?>\n<opnsense><virtualip><vip><mode>carp</mode></vip></virtualip></opnsense>\n' > "${IF_PPPOE_CONFIG_XML}"
out=$(hk apply); rc=$?
eq "CARP VIP configured: refused:ha" "${rc}:${out%% *}" "2:refused:ha"
printf '<?xml version="1.0"?>\n<opnsense><hasync><pfsyncinterface>lan</pfsyncinterface></hasync></opnsense>\n' > "${IF_PPPOE_CONFIG_XML}"
out=$(hk apply); rc=$?
eq "hasync configured: refused:ha" "${rc}:${out%% *}" "2:refused:ha"
# the engine and the GUI refuse on pfsyncpeerip alone too; hookctl must agree
printf '<?xml version="1.0"?>\n<opnsense><hasync><pfsyncpeerip>192.0.2.2</pfsyncpeerip></hasync></opnsense>\n' > "${IF_PPPOE_CONFIG_XML}"
out=$(hk apply); rc=$?
eq "hasync pfsyncpeerip only: refused:ha" "${rc}:${out}" "2:refused:ha (hasync-pfsyncpeerip)"
printf '<?xml version="1.0"?>\n<opnsense><hasync><pfsyncinterface/><synchronizetoip/></hasync><virtualip><vip><mode>ipalias</mode></vip></virtualip></opnsense>\n' > "${IF_PPPOE_CONFIG_XML}"
out=$(hk apply); rc=$?
eq "empty hasync + ipalias VIP: applies" "${rc}:${out}" "0:applied"

# --- revert edge cases -------------------------------------------------

setup rev-handedit 25.7.11
orig=$(sha "${T}")
hk apply >/dev/null
sed -i 's#catch (\\Throwable \$if_pppoe_e) { }#catch (\\Throwable $if_pppoe_e) { /* x */ }#' "${T}"
eq "hand-edited hook line: live foreign" "$(live)" "foreign"
out=$(hk revert); rc=$?
eq "hand-edited hook line: revert restores pristine backup" "${rc}:$(sha "${T}")" "0:${orig}"

setup rev-nobackup 25.7.11
hk apply >/dev/null
rm -rf "${IF_PPPOE_CONF_DIR}/pristine"
sed -i 's#catch (\\Throwable \$if_pppoe_e) { }#catch (\\Throwable $if_pppoe_e) { /* x */ }#' "${T}"
before=$(sha "${T}")
out=$(hk revert); rc=$?
eq "hand-edited, no backup: refused:revert" "${rc}:${out%% *}" "2:refused:revert"
eq "hand-edited, no backup: file unchanged" "$(sha "${T}")" "${before}"

setup rev-otheredit 25.7.11
hk apply >/dev/null
# an unrelated edit elsewhere after apply: line removal works but sha differs
sed -i 's#^function interface_ppps_capable(#// local edit\n&#' "${T}"
orig=$(sha "${FIX}/25.7.11")
out=$(hk revert); rc=$?
eq "unrelated later edit: revert falls back to exact pristine" "${rc}:$(sha "${T}")" "0:${orig}"

# --- reapply (post core update) ---------------------------------------

setup re-reinstall 25.7.11 25.7.11_9
hk apply >/dev/null
cp "${FIX}/25.7.11" "${T}"          # same-version reinstall puts the pristine file back
out=$(hk apply --reapply --reason=update); rc=$?
eq "same-version reinstall: paused" "${rc}:${out%% *}" "2:paused:core-reinstall"
eq "same-version reinstall: file untouched" "$(sha "${T}")" "$(sha "${FIX}/25.7.11")"
out=$(hk apply --reason=boot); rc=$?
contains "paused: boot apply stays paused" "${rc}:${out}" "2:paused:core-reinstall"
sleep 1
echo enabled > "${IF_PPPOE_CONF_DIR}/desired"
touch -d '+2 seconds' "${IF_PPPOE_CONF_DIR}/desired" 2>/dev/null || true
out=$(hk apply --reason=boot); rc=$?
eq "paused: re-applied in GUI (desired rewritten) -> applies" "${rc}:${out}" "0:applied"

setup re-update 25.7 25.7_1
hk apply >/dev/null
cp "${FIX}/25.7.11" "${T}"
printf '{"product_version":"25.7.11_9"}\n' > "${IF_PPPOE_CORE_META}"
out=$(hk apply --reapply --reason=update); rc=$?
eq "core update 25.7 -> 25.7.11: re-applied" "${rc}:${out}" "0:applied"
check "core update: new pristine backup" \
    test -f "${IF_PPPOE_CONF_DIR}/pristine/interfaces.inc.25.7.11_9.$(sha "${FIX}/25.7.11")"

setup re-drift 25.7.11
hk apply >/dev/null
sed 's#/usr/local/sbin/mpd5 -b -d /var/etc#/usr/local/sbin/mpd5 -b -k -d /var/etc#' "${FIX}/25.7.11" > "${T}"
printf '{"product_version":"99.1"}\n' > "${IF_PPPOE_CORE_META}"
out=$(hk apply --reapply --reason=update); rc=$?
eq "core update with anchor drift: refused:anchor" "${rc}:${out%% *}" "2:refused:anchor"
out=$(hk apply --reapply --reason=trigger); rc=$?
contains "second reapply after refusal: nothing to do" "${out}" "(reapply: nothing to do)"

setup re-reverted 25.7.11
hk revert >/dev/null
out=$(hk apply --reapply --reason=cron); rc=$?
eq "reapply never arms a reverted hook" "${rc}:$(sha "${T}")" "0:$(sha "${FIX}/25.7.11")"

setup re-noop 25.7.11
hk apply >/dev/null
h=$(sha "${T}")
out=$(hk apply --reapply --reason=cron); rc=$?
eq "reapply with hook present: no-op" "${rc}:${out}:$(sha "${T}")" "0:applied:${h}"

# --- backups are pruned ------------------------------------------------
setup prune 25.7
for v in a b c d e; do
	printf '{"product_version":"25.7_%s"}\n' "${v}" > "${IF_PPPOE_CORE_META}"
	hk apply >/dev/null
	hk revert >/dev/null
done
eq "at most 3 pristine backups kept" "$(ls "${IF_PPPOE_CONF_DIR}/pristine" | wc -l | tr -d ' ')" 3

eq "usage error exit code" "$(hk bogus >/dev/null 2>&1; echo $?)" 64

finish
