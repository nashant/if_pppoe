#!/bin/sh
# test-kernel-matrix.sh -- offline test of discover-kernels.sh (synthetic
# kernel sets in file:// dirs: tiny ELFs with a build-id note, a kern_conf
# section and a FreeBSD version string) and of build-all.sh --kernels-json
# grouping/drift/package filtering with make/config/git/pkg stubbed. Needs
# cc, readelf, objcopy, jq, xz. Run by test-packaging.sh.
# pass() never fails, so `check && pass || fail` is safe here:
# shellcheck disable=SC2015
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DISCOVER="$HERE/discover-kernels.sh"
FAIL=0
pass() { echo "ok - kernel-matrix: $*"; }
fail() { echo "FAIL - kernel-matrix: $*"; FAIL=1; }

for t in cc readelf objcopy jq xz; do
	command -v "$t" >/dev/null 2>&1 || { echo "skip - kernel-matrix: $t not installed"; exit 0; }
done

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# mkset DIR NAME FREEBSD_STRING CONFIG_TEXT -- DIR/NAME as an OPNsense-style
# kernel set holding ./boot/kernel/kernel.
mkset() {
	w="$T/build.$$"
	rm -rf "$w"
	mkdir -p "$w/boot/kernel"
	conf=$(printf '%s' "$4" | awk '{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); printf "%s\\n", $0 }')
	cat > "$w/k.c" <<EOF
__attribute__((section("kern_conf"), used)) char kernconfstring[] = "___$conf";
__attribute__((used)) const char version[] = "$3 #0 releng/x: Mon Jan  1 00:00:00 UTC 2026";
int main(void) { return 0; }
EOF
	cc -Wl,--build-id=sha1 -o "$w/boot/kernel/kernel" "$w/k.c"
	mkdir -p "$1"
	(cd "$w" && tar -cJf "$1/$2" ./boot/kernel/kernel)
	echo "sig" > "$1/$2.sig"
	rm -rf "$w"
}

CONF_A='machine amd64
cpu HAMMER
ident SMP
options SMP
options RSS
device pppoe'
# Same option set as A: other ident, comments, order, spacing, DEBUG.
CONF_A2='# OPNsense SMP
cpu   HAMMER
machine amd64
ident  SMP-2
makeoptions DEBUG=-g
options RSS
options SMP   # multi-core
device pppoe'
CONF_B="$CONF_A
options IPSEC"

S="$T/mirror"
mkset "$S/14/25.7/sets" kernel-25.7-amd64.txz "FreeBSD 14.3-RELEASE" "$CONF_A"
mkset "$S/14/25.7/sets" kernel-25.7.2-amd64.txz "FreeBSD 14.3-RELEASE-p1" "$CONF_A2"
mkset "$S/14/25.7/sets" kernel-25.7.10-amd64.txz "FreeBSD 14.3-RELEASE-p3" "$CONF_B"
# The sets dir also carries the next series' first kernel: must be ignored.
mkset "$S/14/25.7/sets" kernel-26.1-amd64.txz "FreeBSD 14.3-RELEASE-p4" "$CONF_A"
touch "$S/14/25.7/sets/base-25.7-amd64.txz"
mkset "$S/15/26.7/sets" kernel-26.7-amd64.txz "FreeBSD 15.1-RELEASE" "$CONF_A"

cat > "$T/versions.json" <<EOF
{"entries":[
 {"opnsense_series":"25.7","freebsd_abi":"FreeBSD:14:amd64","kernel_sets_url":"file://$S/14/25.7/sets/"},
 {"opnsense_series":"26.7","freebsd_abi":"FreeBSD:15:amd64","kernel_sets_url":"file://$S/15/26.7/sets/"}]}
EOF

if sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k.json" --cache "$T/cache" \
	--groups "$T/groups.json" --configs-dir "$T/configs" 2> "$T/log1"; then
	pass "runs against the synthetic mirror"
else
	fail "exited non-zero:"; sed 's/^/    /' "$T/log1"
fi

got=$(jq -r 'map(.version) | join(" ")' "$T/k.json" 2>/dev/null || true)
[ "$got" = "25.7 25.7.2 25.7.10 26.7" ] && pass "all patch releases, next-series kernel and .sig ignored, version-sorted" \
	|| fail "versions: '$got'"
got=$(jq -r 'map(.abi) | unique | join(" ")' "$T/k.json" 2>/dev/null || true)
[ "$got" = "FreeBSD:14:amd64 FreeBSD:15:amd64" ] && pass "abi from the kernel's FreeBSD major" || fail "abis: '$got'"
got=$(jq -r '[.[] | select(.version == "25.7" or .version == "25.7.2") | .config_hash] | unique | length' "$T/k.json" 2>/dev/null || true)
[ "$got" = 1 ] && pass "ident/comments/order/DEBUG do not change config_hash" || fail "25.7 and 25.7.2 hash differently"
got=$(jq -r '[.[] | select(.abi == "FreeBSD:14:amd64") | .config_hash] | unique | length' "$T/k.json" 2>/dev/null || true)
[ "$got" = 2 ] && pass "a real option change does" || fail "expected 2 configs in ABI 14, got '$got'"
bid=$(jq -r '.[0].build_id' "$T/k.json" 2>/dev/null || true)
want=$(tar -xOJf "$S/14/25.7/sets/kernel-25.7-amd64.txz" ./boot/kernel/kernel > "$T/kk" && readelf -n "$T/kk" | awk '/Build ID:/{print $NF}')
[ -n "$bid" ] && [ "$bid" = "$want" ] && pass "build_id is the ELF GNU build-id" || fail "build_id '$bid' != '$want'"
sha=$(jq -r '.[0].sha256' "$T/k.json" 2>/dev/null || true)
[ "$sha" = "$(sha256sum "$S/14/25.7/sets/kernel-25.7-amd64.txz" | awk '{print $1}')" ] && pass "sha256 of the set" || fail "sha256 '$sha'"
jq -e 'all(.[]; .src_tag == .version and .freebsd_version != "" and (.url | endswith("-amd64.txz")))' "$T/k.json" > /dev/null 2>&1 \
	&& pass "src_tag/freebsd_version/url fields" || fail "entry fields"
got=$(jq -r 'map(.members | length) | join(",")' "$T/groups.json" 2>/dev/null || true)
[ "$got" = "2,1,1" ] && pass "groups.json groups by (abi, config_hash)" || fail "groups: '$got'"
[ "$(jq -r '.[0].representative' "$T/groups.json")" = "$(jq -r '.[1].build_id' "$T/k.json")" ] \
	&& pass "group representative is its newest member" || fail "representative"
[ "$(find "$T/configs" -name '*.conf' | wc -l | tr -d ' ')" = 4 ] && grep -q '^options SMP' "$T/configs/$bid.conf" \
	&& ! grep -q '^___' "$T/configs/$bid.conf" && pass "configs-dir has each embedded config, tag stripped" || fail "configs-dir"

# Warm cache: no downloads, same result.
sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k2.json" --cache "$T/cache" 2> "$T/log2" || true
if ! grep -q 'fetching' "$T/log2" && cmp -s "$T/k.json" "$T/k2.json"; then
	pass "warm cache re-reads only the listings"
else
	fail "warm cache refetched or changed the result"; sed 's/^/    /' "$T/log2"
fi

# --series filter.
sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k3.json" --cache "$T/cache" --series 26.7 2> /dev/null || true
[ "$(jq -r 'map(.version) | join(" ")' "$T/k3.json" 2>/dev/null)" = "26.7" ] && pass "--series" || fail "--series"

# --union keeps a kernel whose set left the mirror.
mv "$S/14/25.7/sets/kernel-25.7.2-amd64.txz" "$T/"
sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k4.json" --cache "$T/cache" 2> /dev/null || true
sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k5.json" --cache "$T/cache" --union "$T/k.json" 2> "$T/log5" || true
[ "$(jq length "$T/k4.json" 2>/dev/null)" = 3 ] && [ "$(jq length "$T/k5.json" 2>/dev/null)" = 4 ] \
	&& grep -q 'kept from --union' "$T/log5" && pass "--union keeps vanished sets" || fail "--union"
mv "$T/kernel-25.7.2-amd64.txz" "$S/14/25.7/sets/"

# A FreeBSD 15 kernel in a FreeBSD:14 series is an error, not a silent entry.
mkset "$S/14/25.7/sets" kernel-25.7.11-amd64.txz "FreeBSD 15.1-RELEASE" "$CONF_A"
if sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k6.json" --cache "$T/cache" 2> "$T/log6"; then
	fail "ABI mismatch was accepted"
else
	grep -q 'FreeBSD:15:amd64' "$T/log6" && pass "ABI mismatch fails loudly" || fail "ABI mismatch message"
fi
rm -f "$S/14/25.7/sets/kernel-25.7.11-amd64.txz"

# A kernel without an embedded config fails loudly (no blind grouping).
w="$T/noconf"
mkdir -p "$w/boot/kernel"
printf 'const char v[] = "FreeBSD 14.3-RELEASE-p9";\nint main(void){return 0;}\n' > "$w/k.c"
cc -Wl,--build-id=sha1 -o "$w/boot/kernel/kernel" "$w/k.c"
(cd "$w" && tar -cJf "$S/14/25.7/sets/kernel-25.7.12-amd64.txz" ./boot/kernel/kernel)
if sh "$DISCOVER" --versions "$T/versions.json" --out "$T/k7.json" --cache "$T/cache" 2> "$T/log7"; then
	fail "kernel without kern_conf was accepted"
else
	grep -q 'no embedded config' "$T/log7" && pass "missing embedded config fails loudly" || fail "no-config message"
fi

# --- build-all.sh --kernels-json, with the FreeBSD tools stubbed -------------
R="$T/repo"
mkdir -p "$R/plugin/net/if-pppoe" "$R/sys/modules/if_pppoe"
cp -R "$HERE" "$R/plugin/build"
cp -R "$HERE/../kmod" "$R/plugin/kmod"
cp "$HERE/../net/if-pppoe/Makefile" "$R/plugin/net/if-pppoe/Makefile"
rm -rf "$R/plugin/kmod/if-pppoe-kmod/work"
STUBS="$T/stubs"
mkdir -p "$STUBS"
STUB_LOG="$T/stub.log"
export STUB_LOG
: > "$STUB_LOG"

cat > "$STUBS/make" <<'STUB'
#!/bin/sh
dir=. qv= targets=
while [ $# -gt 0 ]; do
	case "$1" in
	-C) dir=$2; shift ;;
	-V) qv=$2; shift ;;
	*=*) export "$1" ;;
	*) targets="$targets $1" ;;
	esac
	shift
done
echo "make $dir$targets${qv:+ -V $qv} BUILD_ID=${BUILD_ID:-} KMOD_MAKE_ARGS=${KMOD_MAKE_ARGS:-} PLUGIN_REVISION=${PLUGIN_REVISION:-} PLUGIN_ABIS=${PLUGIN_ABIS:-}" >> "$STUB_LOG"
W="$dir/work/src/usr/local"
case "$dir" in
*/sys/modules/if_pppoe) [ "$qv" != .OBJDIR ] || echo "$MAKEOBJDIRPREFIX/if_pppoe" ;;
*/plugin/kmod/if-pppoe-kmod)
	for t in $targets; do
		case "$t" in
		stage-one)
			got=$(readelf -n "$KERNBUILDDIR/kernel" | awk '/Build ID:/{print $NF}')
			[ "$got" = "$BUILD_ID" ] || { echo "stub stage-one: bid mismatch" >&2; exit 1; }
			od="$dir/work/obj-$BUILD_ID/if_pppoe"
			mkdir -p "$od" "$W/lib/if_pppoe/$BUILD_ID"
			ln -sf "$SYSDIR/amd64/include" "$od/machine"
			printf 'if_pppoe.o: %s/sys/mbuf.h machine/param.h \\\n  /nonexistent/if_pppoe.h opt_global.h\n' "$SYSDIR" > "$od/.depend.if_pppoe.o"
			echo "ko sys=$SYSDIR args=$KMOD_MAKE_ARGS" > "$W/lib/if_pppoe/$BUILD_ID/if_pppoe.ko"
			;;
		stage-prebuilt)
			mkdir -p "$W/lib/if_pppoe/$BUILD_ID"
			cp "$KO" "$W/lib/if_pppoe/$BUILD_ID/if_pppoe.ko"
			;;
		package)
			mkdir -p "$dir/work/pkg"
			(cd "$W/lib/if_pppoe" && ls -1) | sed 's|.*|/usr/local/lib/if_pppoe/&/if_pppoe.ko|' \
				> "$dir/work/pkg/if-pppoe-kmod-$KMOD_VERSION.pkg"
			cp "$KERNELS_JSON" "$dir/work/shipped-kernels.json"
			;;
		esac
	done
	;;
*/plugin/net/if-pppoe)
	v=$(sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' "$dir/Makefile")
	[ "${PLUGIN_REVISION:-0}" = 0 ] || v="${v}_$PLUGIN_REVISION"
	mkdir -p "$dir/work/pkg" "$dir/work/src"
	echo plugin > "$dir/work/pkg/os-if-pppoe-$v.pkg"
	printf 'deps: {\n  if-pppoe-kmod: { version: "x" }\n}\n' > "$dir/work/src/+MANIFEST"
	;;
esac
STUB
cat > "$STUBS/config" <<'STUB'
#!/bin/sh
[ "$1" = -d ] || exit 1
[ -z "${STUB_CONFIG_NEED:-}" ] || grep -qF "$STUB_CONFIG_NEED" "$3" || exit 1
mkdir -p "$2"
sed -e 's/#.*//' -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//' "$3" |
	grep -vE '^$|^ident( |$)|^makeoptions DEBUG' | LC_ALL=C sort -u > "$2/opt_global.h"
: > "$2/opt_inet.h"
: > "$2/opt_inet6.h"
echo '#define RSS 1' > "$2/opt_rss.h"
STUB
cat > "$STUBS/git" <<'STUB'
#!/bin/sh
echo "git $*" >> "$STUB_LOG"
d=.
if [ "$1" = -C ]; then d=$2; shift 2; fi
case "$1" in
clone)
	tag= prev=
	for a; do [ "$prev" = --branch ] && tag=$a; prev=$a; done
	mkdir -p "$a/sys/amd64/conf" "$a/sys/amd64/include" "$a/sys/sys"
	touch "$a/sys/sys/mbuf.h" "$a/sys/amd64/include/param.h"
	echo "$tag" > "$a/.tag"
	;;
log) echo "opnsense/src stub $(cat "$d/.tag")" ;;
diff)
	other=
	for a; do case "$a" in refs/tags/*) other=${a#refs/tags/} ;; esac; done
	for t in ${DRIFT_TAGS:-}; do
		[ "$t" != "$other" ] || printf '%s\n' "$@" | grep '^sys/sys/'
	done
	;;
esac
exit 0
STUB
cat > "$STUBS/pkg" <<'STUB'
#!/bin/sh
echo "pkg $*" >> "$STUB_LOG"
rdir=
while :; do
	case "$1" in
	-r) shift 2 ;;
	-R) rdir=$2; shift 2 ;;
	-o) shift 2 ;;
	*) break ;;
	esac
done
cmd=$1
shift
repo=
[ -z "$rdir" ] || repo=$(sed -n 's|.*url: "file://\([^"]*\)".*|\1|p' "$rdir"/*.conf)
ver() { f=$(ls "$repo/$1"-*.pkg | head -n 1); f=${f##*/"$1"-}; echo "${f%.pkg}"; }
case "$cmd" in
query) [ "$1" != -F ] || grep '^/usr/local' "$2" ;;
rquery)
	case "$3" in
	%v) ver "$4" ;;
	%dn-%dv) echo "if-pppoe-kmod-$(ver if-pppoe-kmod)" ;;
	esac
	;;
install) printf '\tif-pppoe-kmod: %s\n' "$(ver if-pppoe-kmod)" ;;
esac
exit 0
STUB
chmod +x "$STUBS/make" "$STUBS/config" "$STUBS/git" "$STUBS/pkg"

B="$T/bmirror/14/25.7/sets"
mkset "$B" kernel-25.7-amd64.txz "FreeBSD 14.3-RELEASE" "$CONF_A"
mkset "$B" kernel-25.7.2-amd64.txz "FreeBSD 14.3-RELEASE-p1" "$CONF_A2"
mkset "$B" kernel-25.7.5-amd64.txz "FreeBSD 14.3-RELEASE-p2" "$CONF_A"
mkset "$B" kernel-25.7.10-amd64.txz "FreeBSD 14.3-RELEASE-p3" "$CONF_B"
for tag in 25.7 25.7.2 25.7.5; do
	mkdir -p "$T/tools/$tag/config/25.7"
	printf '%s\nmakeoptions DEBUG=%%%%DEBUG%%%%\n# tools config\n' "$CONF_A" > "$T/tools/$tag/config/25.7/SMP"
done
mkdir -p "$T/tools/25.7.10/config/25.7"
printf '%s\n# tools config\n' "$CONF_B" > "$T/tools/25.7.10/config/25.7/SMP"
cat > "$T/bversions.json" <<EOF
{"entries":[{"opnsense_series":"25.7","freebsd_abi":"FreeBSD:14:amd64","kernel_sets_url":"file://$B/"}]}
EOF
KD="$T/kernels"
sh "$DISCOVER" --versions "$T/bversions.json" --out "$KD/kernels.json" --cache "$T/cache" \
	--configs-dir "$KD/configs" 2> /dev/null || fail "discovery for the build test"
bid_of() { jq -r --arg v "$1" '.[] | select(.version == $v) | .build_id' "$KD/kernels.json"; }

run_build_all() {
	env PATH="$STUBS:$PATH" BUILD_ALL_WORK="$T/work" TOOLS_RAW="file://$T/tools" \
		SRC_REPO="file:///nonexistent" DRIFT_TAGS="25.7" \
		sh "$R/plugin/build/build-all.sh" --kernels-json "$KD/kernels.json" \
		--abi FreeBSD:14:amd64 --cache "$T/kbcache" --out "$T/out" "$@"
}

if run_build_all --phase kmods --version 0.4_3 > "$T/kmods.log" 2>&1; then
	pass "build-all.sh --phase kmods runs"
else
	fail "build-all.sh --phase kmods failed:"; sed 's/^/    /' "$T/kmods.log"
fi
got=$(jq -r 'sort_by(.version) | map("\(.version)<-\(.built_from)") | join(" ")' "$T/out/kmods.json" 2>/dev/null || true)
if [ "$got" = "25.7<-25.7 25.7.10<-25.7.10 25.7.2<-25.7.5 25.7.5<-25.7.5" ]; then
	pass "same config shares the newest member's build; header drift and other configs build separately"
else
	fail "grouping: '$got'"
fi
n=$(grep -c 'if-pppoe-kmod stage-one' "$STUB_LOG" || true)
[ "$n" = 3 ] && pass "one stage-one per build group (3 for 4 kernels)" || fail "stage-one ran $n times"
grep -q 'KMOD_MAKE_ARGS=WERROR=-Werror' "$STUB_LOG" && pass "module built with -Werror" || fail "no WERROR passed"
if cmp -s "$T/out/ko/$(bid_of 25.7.2)/if_pppoe.ko" "$T/out/ko/$(bid_of 25.7.5)/if_pppoe.ko" &&
	[ "$(cat "$T/out/ko/$(bid_of 25.7.2)/build_id")" = "$(bid_of 25.7.2)" ]; then
	pass "group member gets the representative's .ko under its own build_id"
else
	fail "member .ko"
fi
[ "$(find "$T/kbcache" -name 'kbuild-*.tar.gz' | wc -l | tr -d ' ')" = 3 ] &&
	pass "one cached kernel build dir per built src tag" || fail "kbuild cache"
grep -q "generated from the published kernel's embedded config" "$T/kmods.log" &&
	pass "opt_*.h come from the published kernel's embedded config" || fail "embedded config not used"
# An embedded config config(8) rejects falls back to opnsense/tools (the
# stub config accepts only files carrying the tools marker line).
if env STUB_CONFIG_NEED='# tools config' BUILD_ALL_WORK="$T/work-fb" PATH="$STUBS:$PATH" \
	TOOLS_RAW="file://$T/tools" SRC_REPO="file:///nonexistent" DRIFT_TAGS="25.7" \
	sh "$R/plugin/build/build-all.sh" --kernels-json "$KD/kernels.json" --abi FreeBSD:14:amd64 \
	--cache "$T/kbcache-fb" --out "$T/out-fb" --phase kmods --version 0.4_3 > "$T/kmods-fb.log" 2>&1 &&
	grep -q 'embedded config not usable by config -d; trying opnsense/tools' "$T/kmods-fb.log"; then
	pass "unusable embedded config falls back to the opnsense/tools config"
else
	fail "tools fallback:"; sed 's/^/    /' "$T/kmods-fb.log"
fi

# kb_tools_config: exact tag, else the newest same-series tag <= the
# version; never a later tag, another series or a pre-release.
TT="$T/tools-fallback"
for tag in 26.1 26.1.3 26.1.7 26.1.r1 26.7; do
	d=$(echo "$tag" | cut -d. -f1-2)
	mkdir -p "$TT/$tag/config/$d"
	echo "conf of $tag" > "$TT/$tag/config/$d/SMP"
done
tc() { (TOOLS_RAW="file://$TT"; . "$HERE/lib/kbuild.sh"; kb_tools_config "$1" "$2" SMP "$T/tc.conf") 2>/dev/null; }
[ "$(tc 26.1.7 26.1)" = 26.1.7 ] && pass "tools config: exact tag" || fail "tools config: exact tag -> '$(tc 26.1.7 26.1)'"
[ "$(tc 26.1.6 26.1)" = 26.1.3 ] && grep -q 'conf of 26.1.3' "$T/tc.conf" &&
	pass "tools config: untagged 26.1.6 falls back to 26.1.3" || fail "tools config: 26.1.6 -> '$(tc 26.1.6 26.1)'"
[ "$(tc 26.1.2 26.1)" = 26.1 ] && pass "tools config: 26.1.2 falls back to 26.1" || fail "tools config: 26.1.2 -> '$(tc 26.1.2 26.1)'"
if tc 25.7.9 25.7 > /dev/null; then fail "tools config: 25.7.9 used another series' config"; else pass "tools config: no same-series tag fails"; fi
: > "$STUB_LOG"
run_build_all --phase kmods --version 0.4_3 > "$T/kmods2.log" 2>&1 || fail "warm kmods run failed"
if grep -q 'git clone' "$STUB_LOG"; then fail "warm cache cloned again"; else pass "warm cache reuses the kernel build dirs"; fi

jq -r '.[].build_id' "$KD/kernels.json" | grep -v "$(bid_of 25.7.2)" > "$T/pass.txt"
: > "$STUB_LOG"
if run_build_all --phase package --version 0.4_3 --pass-build-ids "$T/pass.txt" > "$T/pkg.log" 2>&1; then
	pass "build-all.sh --phase package runs"
else
	fail "build-all.sh --phase package failed:"; sed 's/^/    /' "$T/pkg.log"
fi
[ "$(cat "$T/out/dropped-build-ids.txt" 2>/dev/null)" = "$(bid_of 25.7.2) 25.7.2" ] &&
	pass "a build_id missing from the pass list is dropped and reported" || fail "dropped list"
if [ "$(jq -r 'map(.version) | join(" ")' "$T/out/kernels-shipped.json" 2>/dev/null)" = "25.7 25.7.5 25.7.10" ] &&
	cmp -s "$T/out/kernels-shipped.json" "$R/plugin/kmod/if-pppoe-kmod/work/shipped-kernels.json"; then
	pass "package ships kernels.json for exactly the packaged build_ids"
else
	fail "shipped kernels.json"
fi
n=$(grep -c 'if-pppoe-kmod stage-prebuilt' "$STUB_LOG" || true)
[ "$n" = 3 ] && pass "package phase stages prebuilt .kos only" || fail "stage-prebuilt ran $n times"
if [ -f "$T/out/pkg/if-pppoe-kmod-0.4_3.pkg" ] && [ -f "$T/out/pkg/os-if-pppoe-0.4_3.pkg" ] &&
	grep -q 'if-pppoe package BUILD_ID= KMOD_MAKE_ARGS= PLUGIN_REVISION=3' "$STUB_LOG"; then
	pass "0.4_3 bumps both packages (PLUGIN_REVISION=3)"
else
	fail "refresh versions"
fi
grep -q 'ok: os-if-pppoe-0.4_3 pulls if-pppoe-kmod-0.4_3' "$T/pkg.log" && [ -f "$T/out/repo.tar.gz" ] &&
	pass "resolve check and flat repo tarball" || fail "resolve check / repo.tar.gz"

if run_build_all --phase package --version 0.4_3 --plugin-revision 2 > "$T/bad1.log" 2>&1; then
	fail "--plugin-revision 2 with --version 0.4_3 accepted"
else
	pass "--plugin-revision must agree with the version's _N"
fi
echo 0000000000000000000000000000000000000000 > "$T/nopass.txt"
if run_build_all --phase package --version 0.4 --pass-build-ids "$T/nopass.txt" > "$T/bad2.log" 2>&1; then
	fail "an empty pass list produced a package"
else
	grep -q 'no build_id left' "$T/bad2.log" && pass "nothing passing means no package" || fail "empty pass list message"
fi

exit "$FAIL"
