#!/bin/sh
# No-FreeBSD-host tests: shellcheck + gen-repo-conf.sh functional test +
# Makefile structural checks (no bmake/pkg here, see INSTALL.md).
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FAIL=0
pass() { echo "ok - $*"; }
fail() { echo "FAIL - $*"; FAIL=1; }

# --- 1. shellcheck every sh script we ship or build with -------------------
SCRIPTS="
$REPO_ROOT/plugin/build/build-kmod.sh
$REPO_ROOT/plugin/build/build-plugin.sh
$REPO_ROOT/plugin/build/build-all.sh
$REPO_ROOT/plugin/build/discover-kernels.sh
$REPO_ROOT/plugin/build/lib/kbuild.sh
$REPO_ROOT/plugin/build/test-kernel-matrix.sh
$REPO_ROOT/plugin/build/make-repo.sh
$REPO_ROOT/plugin/build/gen-repo-conf.sh
$REPO_ROOT/plugin/build/publish-repo.sh
$REPO_ROOT/plugin/build/vendor-mk.sh
$REPO_ROOT/plugin/net/if-pppoe/+PRE_DEINSTALL
$REPO_ROOT/plugin/net/if-pppoe/+POST_INSTALL.post
$REPO_ROOT/plugin/net/if-pppoe/+POST_DEINSTALL.post
$REPO_ROOT/plugin/net/if-pppoe/src/opnsense/scripts/if_pppoe/uninstall.sh
$REPO_ROOT/plugin/kmod/if-pppoe-kmod/+POST_INSTALL
$REPO_ROOT/plugin/kmod/if-pppoe-kmod/+PRE_DEINSTALL
"
if command -v shellcheck >/dev/null 2>&1; then
	for f in $SCRIPTS; do
		[ -f "$f" ] || { fail "missing script: $f"; continue; }
		if shellcheck --shell=sh -x -P "$(dirname "$f")" "$f" >/tmp/if_pppoe-shellcheck.$$ 2>&1; then
			pass "shellcheck $f"
		else
			fail "shellcheck $f:"; sed 's/^/    /' /tmp/if_pppoe-shellcheck.$$
		fi
		rm -f /tmp/if_pppoe-shellcheck.$$
	done
else
	echo "skip - shellcheck not installed"
fi

# --- 2. gen-repo-conf.sh, functionally (needs only sha256/sha256sum) -------
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
: > "$TMPDIR/fake.pub"
echo "fake pubkey contents" > "$TMPDIR/fake.pub"

# ${ABI} below is literal, for pkg to expand later, not this shell.
# shellcheck disable=SC2016
"$REPO_ROOT/plugin/build/gen-repo-conf.sh" \
	--url 'http://lab-build-host.example/if_pppoe/repo/${ABI}' \
	--pub "$TMPDIR/fake.pub" \
	--out-dir "$TMPDIR/out" >/tmp/if_pppoe-genconf.$$ 2>&1 || {
	fail "gen-repo-conf.sh exited non-zero:"; sed 's/^/    /' /tmp/if_pppoe-genconf.$$
}
rm -f /tmp/if_pppoe-genconf.$$

CONF="$TMPDIR/out/repos/IfPppoe.conf"
FP="$TMPDIR/out/fingerprints/IfPppoe/trusted/IfPppoe"
if [ -f "$CONF" ] && grep -q 'signature_type: "fingerprints"' "$CONF" \
	&& grep -q 'fingerprints: "/usr/local/etc/pkg/fingerprints/IfPppoe"' "$CONF"; then
	pass "gen-repo-conf.sh: IfPppoe.conf has expected fields"
else
	fail "gen-repo-conf.sh: IfPppoe.conf missing or malformed (see $CONF)"
fi
if [ -f "$FP" ] && grep -q '^function: sha256$' "$FP" && grep -q '^fingerprint: "[0-9a-f]\{64\}"$' "$FP"; then
	pass "gen-repo-conf.sh: fingerprint file has expected function/fingerprint fields"
else
	fail "gen-repo-conf.sh: fingerprint file missing or malformed (see $FP)"
fi
EXPECT_SUM=$(sha256sum "$TMPDIR/fake.pub" | awk '{print $1}')
if grep -q "$EXPECT_SUM" "$FP" 2>/dev/null; then
	pass "gen-repo-conf.sh: fingerprint matches sha256sum of the pubkey file"
else
	fail "gen-repo-conf.sh: fingerprint does not match sha256sum of the pubkey file"
fi

# --- 3. structural checks on the BSD-make Makefiles (cannot execute them) --
KMOD_MK="$REPO_ROOT/plugin/kmod/if-pppoe-kmod/Makefile"
PLUGIN_MK="$REPO_ROOT/plugin/net/if-pppoe/Makefile"

check_recipe_tabs() {
	# Every non-comment, non-blank line immediately after a target's ':'
	# block must start with a real tab for bmake; a space there is a
	# silent "missing separator" error at build time we can catch now.
	awk '
		/^[A-Za-z_.][A-Za-z0-9_.-]*:.*$/ { intarget=1; next }
		/^$/ { intarget=0; next }
		/^\./ { next }
		intarget && $0 !~ /^\t/ { print NR": "$0; bad=1 }
		END { exit bad }
	' "$1"
}
for mk in "$KMOD_MK" "$PLUGIN_MK"; do
	if check_recipe_tabs "$mk"; then
		pass "$mk: recipe lines use real tabs"
	else
		fail "$mk: recipe line(s) above are not tab-indented (bmake 'missing separator')"
	fi
done

for field in name version origin comment maintainer www prefix licenselogic licenses; do
	if grep -q "\"$field\|$field:" "$KMOD_MK" >/dev/null 2>&1; then
		pass "$KMOD_MK manifest target mentions '$field'"
	else
		fail "$KMOD_MK manifest target missing '$field'"
	fi
done

if grep -q '^PLUGIN_DEPENDS=.*if-pppoe-kmod' "$PLUGIN_MK"; then
	pass "$PLUGIN_MK depends on if-pppoe-kmod"
else
	fail "$PLUGIN_MK does not declare PLUGIN_DEPENDS=if-pppoe-kmod"
fi
if grep -q '^KMOD_NAME=.*if-pppoe-kmod' "$KMOD_MK"; then
	pass "$KMOD_MK package name matches (if-pppoe-kmod)"
else
	fail "$KMOD_MK KMOD_NAME does not match if-pppoe-kmod"
fi

for f in "$REPO_ROOT/plugin/net/if-pppoe/pkg-descr" "$REPO_ROOT/plugin/kmod/if-pppoe-kmod/pkg-descr"; do
	if [ -s "$f" ]; then
		pass "$f is non-empty"
	else
		fail "$f is missing or empty"
	fi
done

# --- 4. src/ -> install-path simulation (plugins.mk `install`/`plist`: every
# file under src/ lands at ${LOCALBASE}/<path relative to src/>, e.g.
# Mk/plugins.mk:244-246 `tar -C ${.CURDIR}/src ... | tar -C ${DESTDIR}${LOCALBASE} -xpf -`).
# A file wrongly nested as src/usr/local/... would install doubled, under
# ${LOCALBASE}/usr/local/..., silently breaking anything (like +PRE_DEINSTALL
# here) that hard-codes the real /usr/local/... path.
PLUGIN_SRC="$REPO_ROOT/plugin/net/if-pppoe/src"
if [ -d "$PLUGIN_SRC/usr" ]; then
	fail "$PLUGIN_SRC/usr exists -- files under it install doubled at \${LOCALBASE}/usr/local/... (see Mk/plugins.mk install target)"
else
	pass "$PLUGIN_SRC has no usr/ subtree (no doubled-LOCALBASE risk)"
fi

if [ -d "$PLUGIN_SRC" ]; then
	(cd "$PLUGIN_SRC" && find * -type f 2>/dev/null) | while read -r relfile; do
		echo "/usr/local/$relfile"
	done > "$TMPDIR/installed-paths"
	# Every path +PRE_DEINSTALL/uninstall.sh hard-code must actually be one
	# of the paths the plist simulation says this package installs.
	for expect in /usr/local/opnsense/scripts/if_pppoe/uninstall.sh; do
		if grep -qxF "$expect" "$TMPDIR/installed-paths"; then
			pass "install-path simulation: $expect is produced by src/ -> \${LOCALBASE} mapping"
		else
			fail "install-path simulation: $expect is NOT produced by src/ -> \${LOCALBASE} mapping (got: $(tr '\n' ' ' < "$TMPDIR/installed-paths"))"
		fi
	done
fi

# --- 5. vendored Mk/ sanity: plugins.mk must exist and be includable-shaped -
for f in plugins.mk defaults.mk common.mk; do
	if [ -f "$REPO_ROOT/plugin/Mk/$f" ]; then
		pass "plugin/Mk/$f vendored"
	else
		fail "plugin/Mk/$f missing"
	fi
done
if [ -f "$REPO_ROOT/plugin/Mk/devel.mk" ]; then
	fail "plugin/Mk/devel.mk present (should be deliberately excluded, see plugin/Mk/VENDORED.md)"
else
	pass "plugin/Mk/devel.mk deliberately absent"
fi

# --- 6. build-plugin.sh pins ABI/PHP instead of trusting defaults.mk's
# no-opnsense-version fallback (PLUGIN_ABIS?=26.7), and asserts the built
# +MANIFEST actually declares the if-pppoe-kmod dependency it needs.
BUILD_PLUGIN_SH="$REPO_ROOT/plugin/build/build-plugin.sh"
if grep -q 'PLUGIN_ABIS.*25\.7' "$BUILD_PLUGIN_SH" && grep -q 'PLUGIN_ABIS=' "$BUILD_PLUGIN_SH"; then
	pass "$BUILD_PLUGIN_SH pins PLUGIN_ABIS=25.7"
else
	fail "$BUILD_PLUGIN_SH does not pin PLUGIN_ABIS to 25.7"
fi
if grep -q 'PLUGIN_PHP=' "$BUILD_PLUGIN_SH"; then
	pass "$BUILD_PLUGIN_SH pins PLUGIN_PHP"
else
	fail "$BUILD_PLUGIN_SH does not pin PLUGIN_PHP"
fi
if grep -q 'MANIFEST' "$BUILD_PLUGIN_SH" && grep -q 'if-pppoe-kmod' "$BUILD_PLUGIN_SH"; then
	pass "$BUILD_PLUGIN_SH asserts +MANIFEST declares if-pppoe-kmod"
else
	fail "$BUILD_PLUGIN_SH does not assert the built +MANIFEST declares if-pppoe-kmod"
fi

# --- 7. kmod Makefile verifies BUILD_ID against the kernel's own ELF
# build-id note instead of trusting the manifest line unchecked.
if grep -q "Build ID:" "$KMOD_MK" && grep -q '\-n \${KERNBUILDDIR}/kernel' "$KMOD_MK"; then
	pass "$KMOD_MK verifies BUILD_ID against \${KERNBUILDDIR}/kernel's ELF build-id note"
else
	fail "$KMOD_MK does not verify BUILD_ID against the kernel's own build-id note"
fi

# --- 8. kmod Makefile ships a features file next to build_ids, derived from
# the driver source, and package depends on both.
if grep -q '^features-file:' "$KMOD_MK" && grep -q 'sys/net/\*\.c' "$KMOD_MK"; then
	pass "$KMOD_MK has a features-file target deriving from sys/net/*.c"
else
	fail "$KMOD_MK is missing a features-file target deriving from the driver source"
fi
if grep -qE '^package: .*build-ids-file.*features-file|^package: .*features-file.*build-ids-file' "$KMOD_MK"; then
	pass "$KMOD_MK package depends on both build-ids-file and features-file"
else
	fail "$KMOD_MK package does not depend on both build-ids-file and features-file"
fi

# --- 9. multi-kernel packaging: prebuilt .kos, shipped kernels.json, and
# the os-if-pppoe revision a kernel-only refresh bumps.
if grep -q '^stage-prebuilt:' "$KMOD_MK" && grep -q 'KO=' "$REPO_ROOT/plugin/build/build-kmod.sh" \
	&& grep -q 'prebuilt' "$REPO_ROOT/plugin/build/build-kmod.sh"; then
	pass "$KMOD_MK has stage-prebuilt, build-kmod.sh accepts '<bid> prebuilt <ko>' lines"
else
	fail "stage-prebuilt target / build-kmod.sh prebuilt manifest lines missing"
fi
if grep -q '^kernels-json-file:' "$KMOD_MK" && grep -qE '^package: .*kernels-json-file' "$KMOD_MK" \
	&& grep -q 'share/if_pppoe/kernels.json' "$KMOD_MK"; then
	pass "$KMOD_MK ships share/if_pppoe/kernels.json and package depends on it"
else
	fail "$KMOD_MK does not ship kernels.json from package"
fi
if grep -q 'PLUGIN_REVISION="\$PLUGIN_REVISION"' "$BUILD_PLUGIN_SH"; then
	pass "$BUILD_PLUGIN_SH forwards PLUGIN_REVISION to plugins.mk"
else
	fail "$BUILD_PLUGIN_SH does not forward PLUGIN_REVISION"
fi
if grep -q 'KMOD_MAKE_ARGS' "$KMOD_MK" && grep -q 'WERROR=-Werror' "$REPO_ROOT/plugin/build/build-all.sh"; then
	pass "kernels-json builds keep -Werror (KMOD_MAKE_ARGS)"
else
	fail "kernels-json builds lost -Werror"
fi

# --- 10. discovery + build-all.sh --kernels-json, offline (stubs) ----------
if sh "$REPO_ROOT/plugin/build/test-kernel-matrix.sh" > "$TMPDIR/km.log" 2>&1; then
	grep -E '^(ok|skip) ' "$TMPDIR/km.log"
else
	grep -E '^(ok|skip|FAIL) |^    ' "$TMPDIR/km.log"
	fail "plugin/build/test-kernel-matrix.sh"
fi

echo
if [ "$FAIL" -eq 0 ]; then
	echo "All checks passed."
else
	echo "Some checks FAILED (see above)."
fi
exit "$FAIL"
