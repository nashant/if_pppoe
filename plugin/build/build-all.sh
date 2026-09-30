#!/bin/sh
# build-all.sh -- one-command OPNsense package build: if-pppoe-kmod (one
# .ko per kern.build_id), os-if-pppoe, optional signed repo. Runs ON a
# FreeBSD build host, as non-root (build-plugin.sh's header). CI
# (.github/scripts/freebsd-build.sh) and local builds share this script.
# Walkthrough: docs/plugin/INSTALL.md "BUILD"; CI: docs/CI.md.
#
# Two ways to name the kernels:
#
# A. Kernels-json mode (CI, and local builds of every published kernel):
#   build-all.sh --kernels-json FILE --abi ABI --version VERSION --out DIR
#                [--phase kmods|package|all] [--pass-build-ids FILE]
#                [--plugin-revision N] [--kernconf NAME] [--cache DIR]
#                [--configs-dir DIR] [--key KEY [--pub PUB] [--gen-key]]
#   FILE is discover-kernels.sh output; every entry of ABI gets a .ko.
#   Kernels with the same config_hash share one kernel build dir (a
#   `config -d` of the newest member's opnsense/src tag, lib/kbuild.sh);
#   the module is built once per group and the .ko staged for every
#   member (stage-prebuilt), after two guards per member: its own embedded
#   config must give identical opt_*.h, and no header the module build
#   included (.depend) may differ between the member's src tag and the
#   group's -- a member that fails the header check gets its own build.
#     --phase kmods    build DIR/ko/<bid>/if_pppoe.ko + DIR/kmods.json
#     --phase package  package the .kos in DIR/ko (only those listed in
#                      --pass-build-ids, when given: the smoke-tested ones;
#                      the rest are listed in DIR/dropped-build-ids.txt)
#     --phase all      both (default)
#   --plugin-revision N  os-if-pppoe version <PLUGIN_VERSION>_N; defaults
#                      to the _N of --version (0.4_3 -> 3), else 0.
#   --kernconf        OPNsense kernel config name (default SMP).
#   --cache           kernel sets + prepared kernel build dirs (default
#                      $KB_CACHE or ~/.cache/if_pppoe-kbuild).
#   --configs-dir     embedded configs from discovery (<bid>.conf; default
#                      configs/ next to FILE); missing ones are read from
#                      the kernel set.
#   The package phase also checks that pkg resolves os-if-pppoe to
#   if-pppoe-kmod-VERSION from the built repo.
#
# B. Lab mode (--target-kernel, unchanged): for each --target-kernel,
#   overlay the lab's already-collected SMP KERNBUILDDIR with that kernel
#   binary and build against it:
#   build-all.sh --target-kernel FILE-OR-URL [--target-conftxt FILE] \
#                [--target-kernel ...] --version VERSION --out DIR \
#                [--key KEY [--pub PUB] [--gen-key]] [--skip-config-check]
#                [--plugin-revision N]
#
#   --target-kernel  Either a path to a kernel binary already on this host
#                     (e.g. scp'd off a router's world-readable
#                     /boot/kernel/kernel), or an http(s):// URL. A URL
#                     ending in .txz is treated as an OPNsense kernel SET
#                     (as served under .github/versions.json's
#                     kernel_sets_url, e.g. kernel-<tag>-amd64.txz) and
#                     boot/kernel/kernel is extracted from it; any other URL
#                     is fetched as the kernel file directly. Repeat this
#                     flag for multiple kernels -- they all land in ONE
#                     if-pppoe-kmod package (its build_ids manifest), which
#                     is how the plugin engine picks a .ko by the running
#                     kern.build_id (docs/plugin/{README,interfaces-inc-hook}.md).
#   --target-conftxt  Optional, must directly follow the --target-kernel it
#                     applies to. Use this kernel's ALREADY-EXTRACTED
#                     embedded config (e.g. that box's own
#                     `sysctl -n kern.conftxt`) instead of running
#                     `config -x` on the --target-kernel binary. Needed
#                     when the target kernel's own config -x can't extract
#                     one (stripped kernel, no INCLUDE_CONFIG_FILE).
#   --skip-config-check   Skip the config-equivalence check below entirely
#                      (both the lab SMP kernel's and every --target-kernel's
#                      embedded config). Only for a kernel whose config
#                      genuinely can't be extracted or supplied any other
#                      way -- it removes the one thing that catches a
#                      module silently built against the wrong kernel
#                      options.
#   All --target-kernel arguments must be the SAME series/src tree as the
#   lab's collected SMP kernel (they share one SYSDIR); for another series
#   use kernels-json mode, or run once per series with another LAB_HOME.
#
# Common:
#   --version         if-pppoe-kmod package version (build-kmod.sh --version);
#                      0.4_N is a kernel-only refresh (PORTREVISION-style).
#   --out             Directory for the built .pkg files and repo.tar.gz
#                      (a FLAT repo: lab/vm/plugin-roundtrip.sh serves it
#                      as is).
#   --key / --pub     Sign the repo (make-repo.sh). --pub, if omitted,
#                      defaults the way make-repo.sh itself does (KEY with
#                      .key -> .pub, or KEY.pub). A --key that doesn't
#                      exist yet is an error UNLESS --gen-key is also
#                      given, in which case a fresh keypair is generated
#                      there. Omit --key/--pub entirely for an UNSIGNED
#                      repo (`pkg repo` with no signing_command) -- fine
#                      for lab iteration, but a real pkg client needs a
#                      signed FINGERPRINTS repo (docs/plugin/INSTALL.md).
#
# Env overrides:
#   LAB_HOME      (lab mode) Default $HOME/if_pppoe-lab. Must already hold
#                 kernel/SMP/{kernel,KERNBUILDDIR} (lab/vm/build-kernel.sh
#                 collect) and src/sys (the same src checkout) -- this
#                 script only READS them, never writes.
#   BUILD_ALL_WORK  Scratch dir (default plugin/build/work-all); wiped.
#   PLUGIN_ABIS, PLUGIN_PHP   Forwarded to build-plugin.sh (its own
#                             defaults: 25.7 / 83).
#   SRC_REPO, TOOLS_RAW, TOOLS_REPO   (kernels-json mode) see
#                 lib/kbuild.sh kb_prepare.
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="$REPO_ROOT/plugin/build"
KMOD_DIR="$REPO_ROOT/plugin/kmod/if-pppoe-kmod"
PLUGIN_DIR="$REPO_ROOT/plugin/net/if-pppoe"
# shellcheck source=lib/kbuild.sh
. "$BUILD_DIR/lib/kbuild.sh"

LAB_HOME="${LAB_HOME:-$HOME/if_pppoe-lab}"
LAB_SMP_KERNEL="$LAB_HOME/kernel/SMP/kernel"
LAB_SMP_KBD_FILE="$LAB_HOME/kernel/SMP/KERNBUILDDIR"
LAB_SYSDIR="$LAB_HOME/src/sys"

WORK="${BUILD_ALL_WORK:-$BUILD_DIR/work-all}"
MANIFEST="$WORK/kernels.conf"

KMOD_VERSION=
OUT_DIR=
KEY=
PUB=
GEN_KEY=0
SKIP_CONFIG_CHECK=0
KERNELS_JSON=
ABI=
PHASE=all
PASS_BUILD_IDS=
PLUGIN_REVISION=
KERNCONF=SMP
CACHE="${KB_CACHE:-${HOME:-/tmp}/.cache/if_pppoe-kbuild}"
CONFIGS_DIR=
# newline-separated "spec<US>conftxt-override", in --target-kernel order;
# US (0x1f) can't appear in a path/URL, so it safely separates the two
# fields on one line without quoting.
US=$(printf '\037')
TARGET_KERNELS=""
NTARGETS=0
PENDING_SPEC=
PENDING_CONFTXT=

die() { echo "build-all.sh: $*" >&2; exit 1; }

usage() {
	cat <<'EOF2' >&2
usage: build-all.sh --kernels-json FILE --abi ABI --version VERSION --out DIR
                     [--phase kmods|package|all] [--pass-build-ids FILE]
                     [--plugin-revision N] [--kernconf NAME] [--cache DIR]
                     [--configs-dir DIR] [--key KEYFILE [--pub PUBFILE] [--gen-key]]
       build-all.sh --target-kernel FILE-OR-URL [--target-conftxt FILE]
                     [--target-kernel ...] --version VERSION --out DIR
                     [--key KEYFILE [--pub PUBFILE] [--gen-key]]
                     [--skip-config-check] [--plugin-revision N]
See this script's header comment for what each flag does.
EOF2
	exit 1
}

flush_pending_target() {
	[ -n "$PENDING_SPEC" ] || return 0
	TARGET_KERNELS="$TARGET_KERNELS
$PENDING_SPEC$US$PENDING_CONFTXT"
	NTARGETS=$((NTARGETS + 1))
	PENDING_SPEC=
	PENDING_CONFTXT=
}

while [ $# -gt 0 ]; do
	case "$1" in
	--target-kernel)
		shift
		[ $# -gt 0 ] || usage
		flush_pending_target
		PENDING_SPEC="$1"
		;;
	--target-conftxt)
		shift
		[ $# -gt 0 ] || usage
		[ -n "$PENDING_SPEC" ] || { echo "build-all.sh: --target-conftxt must directly follow the --target-kernel it applies to" >&2; usage; }
		PENDING_CONFTXT="$1"
		;;
	--skip-config-check) SKIP_CONFIG_CHECK=1 ;;
	--kernels-json) shift; KERNELS_JSON=${1:?} ;;
	--abi) shift; ABI=${1:?} ;;
	--phase) shift; PHASE=${1:?} ;;
	--pass-build-ids) shift; PASS_BUILD_IDS=${1:?} ;;
	--plugin-revision) shift; PLUGIN_REVISION=${1:?} ;;
	--kernconf) shift; KERNCONF=${1:?} ;;
	--cache) shift; CACHE=${1:?} ;;
	--configs-dir) shift; CONFIGS_DIR=${1:?} ;;
	--version) shift; KMOD_VERSION=${1:?} ;;
	--out) shift; OUT_DIR=${1:?} ;;
	--key) shift; KEY=${1:?} ;;
	--pub) shift; PUB=${1:?} ;;
	--gen-key) GEN_KEY=1 ;;
	-h|--help) usage ;;
	*) echo "build-all.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done
flush_pending_target

[ -n "$KMOD_VERSION" ] || { echo "build-all.sh: --version is required" >&2; usage; }
[ -n "$OUT_DIR" ] || { echo "build-all.sh: --out is required" >&2; usage; }
[ -n "$KEY" ] || [ -z "$PUB" ] || die "--pub given without --key"
[ -n "$KEY" ] || [ "$GEN_KEY" -eq 0 ] || die "--gen-key given without --key"
case "$PHASE" in kmods|package|all) ;; *) die "--phase must be kmods, package or all" ;; esac

# 0.4_3 is a kernel-only refresh: os-if-pppoe gets the same _3 (both
# packages bump together, so pkg upgrades both; docs/CI.md "Nightly refresh").
case "$KMOD_VERSION" in
*_*) ver_rev=${KMOD_VERSION##*_} ;;
*) ver_rev=0 ;;
esac
case "$ver_rev" in ''|*[!0-9]*) die "--version $KMOD_VERSION: the _N suffix must be a number" ;; esac
if [ -z "$PLUGIN_REVISION" ]; then
	PLUGIN_REVISION=$ver_rev
elif [ "$PLUGIN_REVISION" != "$ver_rev" ] && [ "$ver_rev" != 0 ]; then
	die "--plugin-revision $PLUGIN_REVISION disagrees with --version $KMOD_VERSION"
fi
case "$PLUGIN_REVISION" in ''|*[!0-9]*) die "--plugin-revision must be a non-negative integer" ;; esac
export PLUGIN_REVISION

if [ -n "$KERNELS_JSON" ]; then
	MODE=kernels-json
	[ "$NTARGETS" -eq 0 ] || die "--kernels-json and --target-kernel are separate modes"
	[ -n "$ABI" ] || die "--abi is required with --kernels-json"
	[ -f "$KERNELS_JSON" ] || die "--kernels-json $KERNELS_JSON not found"
	KERNELS_JSON=$(cd "$(dirname "$KERNELS_JSON")" && pwd)/$(basename "$KERNELS_JSON")
	[ -n "$CONFIGS_DIR" ] || CONFIGS_DIR="$(dirname "$KERNELS_JSON")/configs"
	export KMOD_ABI="$ABI"
else
	MODE=lab
	[ "$NTARGETS" -gt 0 ] || { echo "build-all.sh: --kernels-json or at least one --target-kernel is required" >&2; usage; }
	[ "$PHASE" = all ] || die "--phase needs --kernels-json"
	[ -z "$PASS_BUILD_IDS" ] || die "--pass-build-ids needs --kernels-json"
	[ -z "$ABI" ] || export KMOD_ABI="$ABI"
fi

command -v make >/dev/null 2>&1 || die "make not found"
if [ "$PHASE" != kmods ]; then
	command -v pkg >/dev/null 2>&1 || die "pkg(8) not found; this must run on a FreeBSD host"
fi
if [ "$MODE" = kernels-json ]; then
	command -v jq >/dev/null 2>&1 || die "jq not found (pkg install jq)"
fi
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
rm -rf "$WORK" "$KMOD_DIR/work" "$PLUGIN_DIR/work"
mkdir -p "$WORK"

# --- package tail shared by both modes ---------------------------------------
# finish_packages KMOD_PKG -- register the kmod in a private pkg db, build
# os-if-pppoe against it, write OUT_DIR/pkg, a flat repo in $REPO_DIR
# (signed with --key) and OUT_DIR/repo.tar.gz.
REPO_DIR="$WORK/repo"
finish_packages() {
	KMOD_PKG=$1
	# The build host has no root (no sudo/doas, root ssh refused), so register
	# if-pppoe-kmod in a throwaway, non-root pkg database instead of the
	# system one: `-r` gives `pkg add` a root prefix to unpack into, and
	# PKG_DBDIR (exported so build-plugin.sh's own bare `pkg query`/`pkg add`
	# calls see the same database too) moves the installed-package records
	# out of /var/db/pkg, which this user can't write.
	echo ">>> registering if-pppoe-kmod in a private pkg db"
	PKG_ROOT="$WORK/pkgroot"
	PKG_DBDIR="$WORK/pkgdb"
	rm -rf "$PKG_ROOT" "$PKG_DBDIR"
	mkdir -p "$PKG_ROOT" "$PKG_DBDIR"
	export INSTALL_AS_USER=yes
	export PKG_DBDIR
	pkg -r "$PKG_ROOT" add -M "$KMOD_PKG"

	echo ">>> build-plugin.sh (against the private pkg db, PLUGIN_REVISION=$PLUGIN_REVISION)"
	# No --kmod-pkg: it's already installed into PKG_DBDIR above, which
	# build-plugin.sh's own `pkg query` (same PKG_DBDIR, exported) sees too --
	# if it ever didn't, this fails with its clear "not installed" message
	# instead of a --kmod-pkg fallback `pkg add` into /.
	sh "$BUILD_DIR/build-plugin.sh"
	PLUGIN_PKG=$(find "$PLUGIN_DIR/work/pkg" -name 'os-if-pppoe-*.pkg' 2>/dev/null | head -1)
	[ -n "$PLUGIN_PKG" ] || die "build-plugin.sh did not produce a .pkg under $PLUGIN_DIR/work/pkg"

	echo ">>> assembling $OUT_DIR/pkg"
	rm -rf "$OUT_DIR/pkg"
	mkdir -p "$OUT_DIR/pkg"
	cp "$KMOD_DIR"/work/pkg/*.pkg "$PLUGIN_DIR"/work/pkg/*.pkg "$OUT_DIR/pkg/"

	rm -rf "$REPO_DIR"
	mkdir -p "$REPO_DIR"
	cp "$OUT_DIR"/pkg/*.pkg "$REPO_DIR/"

	if [ -n "$KEY" ]; then
		if [ ! -f "$KEY" ]; then
			[ "$GEN_KEY" -eq 1 ] || die "signing key not found: $KEY (pass --gen-key to generate a new one there)"
			echo ">>> make-repo.sh --gen-key (new signing key at $KEY)"
			if [ -n "$PUB" ]; then
				sh "$BUILD_DIR/make-repo.sh" --gen-key --key "$KEY" --pub "$PUB"
			else
				sh "$BUILD_DIR/make-repo.sh" --gen-key --key "$KEY"
			fi
		fi
		echo ">>> make-repo.sh (signed)"
		# No PUB default here: let make-repo.sh apply its own (KEY with
		# .key -> .pub, else KEY.pub) rather than risk the two disagreeing.
		if [ -n "$PUB" ]; then
			sh "$BUILD_DIR/make-repo.sh" --repo-dir "$REPO_DIR" --key "$KEY" --pub "$PUB"
		else
			sh "$BUILD_DIR/make-repo.sh" --repo-dir "$REPO_DIR" --key "$KEY"
		fi
	else
		echo ">>> pkg repo (UNSIGNED -- no --key given; fine for lab iteration only, see docs/plugin/INSTALL.md)"
		pkg repo "$REPO_DIR"
	fi
}

# resolve_check -- R5 (docs/CI.md "Packages"): from the repo just built,
# pkg must resolve os-if-pppoe to exactly if-pppoe-kmod-KMOD_VERSION, so
# a kernel-only refresh (both at _N) really upgrades the kmod. A private
# pkg db, repo conf dir (pkg -R) and root: nothing on the host changes.
resolve_check() {
	echo ">>> pkg resolve check (os-if-pppoe -> if-pppoe-kmod-$KMOD_VERSION)"
	rc="$WORK/resolve"
	rm -rf "$rc"
	mkdir -p "$rc/repos" "$rc/db" "$rc/cache" "$rc/root"
	cat > "$rc/repos/IfPppoeCheck.conf" <<EOF2
IfPppoeCheck: { url: "file://$REPO_DIR", signature_type: "none", enabled: yes }
EOF2
	plugin_base=$(sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' "$PLUGIN_DIR/Makefile")
	want_plugin=$plugin_base
	[ "$PLUGIN_REVISION" = 0 ] || want_plugin="${plugin_base}_$PLUGIN_REVISION"
	# Setting ABI alone makes pkg guess OSVERSION as <major>00000 and refuse
	# the repo it just built ("wrong OS version"); this is only a resolve
	# check against our own repo, so the OS version is not what's tested.
	rpkg() {
		PKG_DBDIR="$rc/db" INSTALL_AS_USER=yes IGNORE_OSVERSION=yes pkg -R "$rc/repos" \
			-o PKG_CACHEDIR="$rc/cache" -o ABI="$ABI" "$@"
	}
	rpkg update -f -r IfPppoeCheck || die "resolve check: pkg update from $REPO_DIR failed"
	got=$(rpkg rquery -r IfPppoeCheck '%v' if-pppoe-kmod) || die "resolve check: no if-pppoe-kmod in the repo"
	[ "$got" = "$KMOD_VERSION" ] || die "resolve check: repo has if-pppoe-kmod-$got, expected $KMOD_VERSION"
	got=$(rpkg rquery -r IfPppoeCheck '%v' os-if-pppoe) || die "resolve check: no os-if-pppoe in the repo"
	[ "$got" = "$want_plugin" ] || die "resolve check: repo has os-if-pppoe-$got, expected $want_plugin"
	deps=$(rpkg rquery -r IfPppoeCheck '%dn-%dv' os-if-pppoe)
	echo "$deps" | grep -qxF "if-pppoe-kmod-$KMOD_VERSION" ||
		die "resolve check: os-if-pppoe depends on '$deps', not if-pppoe-kmod-$KMOD_VERSION"
	rpkg -r "$rc/root" install -n -y -r IfPppoeCheck os-if-pppoe > "$rc/plan.txt" 2>&1 ||
		{ sed 's/^/  /' "$rc/plan.txt" >&2; die "resolve check: pkg install -n os-if-pppoe failed"; }
	grep -Eq "if-pppoe-kmod:? $KMOD_VERSION" "$rc/plan.txt" ||
		{ sed 's/^/  /' "$rc/plan.txt" >&2; die "resolve check: installing os-if-pppoe would not pull if-pppoe-kmod-$KMOD_VERSION"; }
	sed 's/^/  /' "$rc/plan.txt"
	echo "    ok: os-if-pppoe-$want_plugin pulls if-pppoe-kmod-$KMOD_VERSION"
}

write_repo_tarball() {
	tar -czf "$OUT_DIR/repo.tar.gz" -C "$REPO_DIR" .
	echo ">>> done: $OUT_DIR/pkg/*.pkg and $OUT_DIR/repo.tar.gz"
}

# --- kernels-json mode ---------------------------------------------------------
KB_ROOT="$WORK/kbuild"

# record BID VERSION SERIES GROUP_BID BUILT_FROM_TAG -- one kmods.json row.
record_ko() {
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" \
		"$(kb_sha256 "$OUT_DIR/ko/$1/if_pppoe.ko")" >> "$WORK/built.tsv"
}

# member_config BID URL SHA -- path of BID's embedded config (discovery's
# configs dir, else read from its kernel set).
member_config() {
	if [ -s "$CONFIGS_DIR/$1.conf" ]; then
		echo "$CONFIGS_DIR/$1.conf"
		return 0
	fi
	set_path=$(kb_get_set "$2" "$3" "$CACHE") || return 1
	kb_extract_kernel "$set_path" "$WORK/member-kernel" || return 1
	kb_extract_config "$WORK/member-kernel" "$WORK/member-$1.conf" || return 1
	rm -f "$WORK/member-kernel"
	echo "$WORK/member-$1.conf"
}

# build_group FILE NEXT_FILE -- FILE: one member per line (tsv: bid version
# series src_tag url sha256). Builds the newest member, stages the rest
# from it, and appends members with header drift to NEXT_FILE.
build_group() {
	gfile=$1 next=$2
	while IFS= read -r line; do
		printf '%s\t%s\n' "$(kb_version_key "$(printf '%s\n' "$line" | cut -f2)")" "$line"
	done < "$gfile" | LC_ALL=C sort | cut -f2- > "$gfile.sorted"
	rep=$(tail -n 1 "$gfile.sorted")
	IFS="$(printf '\t')" read -r r_bid r_ver r_series r_tag r_url r_sha <<EOF2
$rep
EOF2
	echo "::group::kernel group of $r_ver ($(wc -l < "$gfile.sorted" | tr -d ' ') kernel(s))"
	kb_prepare "$r_tag" "$r_series" "$KERNCONF" "$r_url" "$r_sha" "$r_bid" "$KB_ROOT" "$CACHE" ||
		die "could not prepare a kernel build dir for $r_ver"
	r_src=$KB_SRC r_kbd=$KB_KBD
	kv=$(kb_kernel_version "$r_kbd/kernel")
	echo "kernel $r_ver: $kv build_id=$r_bid"

	make -C "$KMOD_DIR" BUILD_ID="$r_bid" KERNBUILDDIR="$r_kbd" SYSDIR="$r_src/sys" \
		KMOD_MAKE_ARGS="WERROR=-Werror" stage-one
	mkdir -p "$OUT_DIR/ko/$r_bid"
	cp "$KMOD_DIR/work/src/usr/local/lib/if_pppoe/$r_bid/if_pppoe.ko" "$OUT_DIR/ko/$r_bid/if_pppoe.ko"
	echo "$r_bid" > "$OUT_DIR/ko/$r_bid/build_id"
	record_ko "$r_bid" "$r_ver" "$r_series" "$r_bid" "$r_tag"

	objdir=$(env MAKEOBJDIRPREFIX="$KMOD_DIR/work/obj-$r_bid" make -C "$REPO_ROOT/sys/modules/if_pppoe" \
		KERNBUILDDIR="$r_kbd" SYSDIR="$r_src/sys" -V .OBJDIR)
	hdrs="$WORK/headers-$r_bid"
	kb_module_headers "$objdir" "$r_src" > "$hdrs"
	if [ -s "$hdrs" ]; then
		echo "module build included $(wc -l < "$hdrs" | tr -d ' ') opnsense/src headers (header-drift check input)"
	else
		echo "::warning::no .depend files in $objdir; every other kernel of this group gets its own build"
	fi

	while IFS="$(printf '\t')" read -r m_bid m_ver m_series m_tag m_url m_sha; do
		[ "$m_bid" != "$r_bid" ] || continue
		if [ ! -s "$hdrs" ]; then
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$m_bid" "$m_ver" "$m_series" "$m_tag" "$m_url" "$m_sha" >> "$next"
			continue
		fi
		drift=$(kb_header_drift "$r_src" "$m_tag" "$hdrs") || die "could not fetch opnsense/src tag $m_tag"
		if [ -n "$drift" ]; then
			echo "$m_ver: headers differ from $r_tag, gets its own build:"
			printf '%s\n' "$drift" | sed 's/^/    /'
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$m_bid" "$m_ver" "$m_series" "$m_tag" "$m_url" "$m_sha" >> "$next"
			continue
		fi
		conf=$(member_config "$m_bid" "$m_url" "$m_sha") || die "no embedded config for $m_ver"
		crc=0
		kb_opt_crosscheck "$r_kbd" "$r_src/sys" "$conf" "kernel-$m_ver" || crc=$?
		case $crc in
		0) ;;
		1) die "kernel-$m_ver shares config_hash with $r_ver but not its opt_*.h" ;;
		*) echo "::warning::kernel-$m_ver: embedded config not usable by config -d; opt_*.h not cross-checked" ;;
		esac
		mkdir -p "$OUT_DIR/ko/$m_bid"
		cp "$OUT_DIR/ko/$r_bid/if_pppoe.ko" "$OUT_DIR/ko/$m_bid/if_pppoe.ko"
		echo "$m_bid" > "$OUT_DIR/ko/$m_bid/build_id"
		record_ko "$m_bid" "$m_ver" "$m_series" "$r_bid" "$r_tag"
		echo "$m_ver: shares $r_ver's .ko (same config, no header drift)"
	done < "$gfile.sorted"
	# The clone is cached as a tarball; free the VM disk for the next group.
	rm -rf "${r_src%/src}"
	echo "::endgroup::"
}

do_kmods() {
	command -v config >/dev/null 2>&1 || die "config(8) not found; this must run on a FreeBSD host"
	command -v git >/dev/null 2>&1 || die "git not found (pkg install git-lite)"
	jq --arg abi "$ABI" '[.[] | select(.abi == $abi)]' "$KERNELS_JSON" > "$WORK/abi-kernels.json"
	[ "$(jq length "$WORK/abi-kernels.json")" -gt 0 ] || die "$KERNELS_JSON has no kernels for $ABI"
	rm -rf "$OUT_DIR/ko" "$OUT_DIR/kmods.json"
	mkdir -p "$OUT_DIR/ko" "$WORK/groups"
	: > "$WORK/built.tsv"
	jq -r 'group_by(.config_hash) | to_entries[] | .key as $i | .value[]
		| [$i, .build_id, .version, .series, .src_tag, .url, .sha256] | @tsv' \
		"$WORK/abi-kernels.json" | while IFS="$(printf '\t')" read -r i rest; do
			printf '%s\n' "$rest" >> "$WORK/groups/$i.tsv"
		done
	ng=$(find "$WORK/groups" -name '*.tsv' | wc -l | tr -d ' ')
	echo ">>> $ABI: $(jq length "$WORK/abi-kernels.json") kernel(s) in $ng config group(s)"
	gi=0
	while [ -f "$WORK/groups/$gi.tsv" ]; do
		build_group "$WORK/groups/$gi.tsv" "$WORK/groups/$ng.tsv"
		[ ! -s "$WORK/groups/$ng.tsv" ] || ng=$((ng + 1))
		gi=$((gi + 1))
	done
	jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
		| {build_id: .[0], version: .[1], series: .[2], group: .[3], built_from: .[4], ko_sha256: .[5]})' \
		"$WORK/built.tsv" > "$OUT_DIR/kmods.json"
	nb=$(jq length "$OUT_DIR/kmods.json")
	[ "$nb" = "$(jq length "$WORK/abi-kernels.json")" ] || die "internal: built $nb .ko(s) for $(jq length "$WORK/abi-kernels.json") kernels"
	echo ">>> $ABI: $nb .ko(s) from $(jq '[.[].group] | unique | length' "$OUT_DIR/kmods.json") build(s) in $OUT_DIR/ko"
}

do_package() {
	[ -d "$OUT_DIR/ko" ] || die "no $OUT_DIR/ko -- run --phase kmods first"
	jq --arg abi "$ABI" '[.[] | select(.abi == $abi)]' "$KERNELS_JSON" > "$WORK/abi-kernels.json"
	(cd "$OUT_DIR/ko" && ls -1) | grep -Ex '[0-9a-f]{16,}' | LC_ALL=C sort > "$WORK/built.txt" || true
	[ -s "$WORK/built.txt" ] || die "$OUT_DIR/ko holds no .ko directories"
	if [ -n "$PASS_BUILD_IDS" ]; then
		[ -f "$PASS_BUILD_IDS" ] || die "--pass-build-ids $PASS_BUILD_IDS not found"
		grep -Eox '[0-9a-f]{16,}' "$PASS_BUILD_IDS" | LC_ALL=C sort -u > "$WORK/pass.txt" || true
	else
		cp "$WORK/built.txt" "$WORK/pass.txt"
	fi
	jq -r '.[].build_id' "$WORK/abi-kernels.json" | LC_ALL=C sort -u > "$WORK/abi-bids.txt"
	LC_ALL=C comm -12 "$WORK/built.txt" "$WORK/pass.txt" | LC_ALL=C comm -12 - "$WORK/abi-bids.txt" > "$WORK/ship.txt"
	LC_ALL=C comm -23 "$WORK/pass.txt" "$WORK/built.txt" | while read -r b; do
		echo "::warning::pass list names $b but no .ko was built for it"
	done
	LC_ALL=C comm -23 "$WORK/built.txt" "$WORK/ship.txt" > "$WORK/dropped.txt"
	: > "$OUT_DIR/dropped-build-ids.txt"
	while read -r b; do
		v=$(jq -r --arg b "$b" '.[] | select(.build_id == $b) | .version' "$WORK/abi-kernels.json")
		echo "$b ${v:-unknown}" >> "$OUT_DIR/dropped-build-ids.txt"
		echo "::warning::kernel ${v:-?} ($b) did not pass smoke; not packaged (the boot hook falls back to mpd5 there)"
	done < "$WORK/dropped.txt"
	[ -s "$WORK/ship.txt" ] || die "no build_id left to package (none passed)"
	jq --rawfile ids "$WORK/ship.txt" '($ids | split("\n") | map(select(length > 0))) as $b
		| [.[] | select(.build_id | IN($b[]))]' "$WORK/abi-kernels.json" > "$OUT_DIR/kernels-shipped.json"
	: > "$MANIFEST"
	while read -r b; do
		echo "$b prebuilt $OUT_DIR/ko/$b/if_pppoe.ko" >> "$MANIFEST"
	done < "$WORK/ship.txt"
	rm -rf "$KMOD_DIR/work" "$PLUGIN_DIR/work"
	echo ">>> build-kmod.sh --manifest ($(wc -l < "$MANIFEST" | tr -d ' ') kernel(s), $ABI)"
	sh "$BUILD_DIR/build-kmod.sh" --manifest "$MANIFEST" --version "$KMOD_VERSION" \
		--kernels-json "$OUT_DIR/kernels-shipped.json"
	KMOD_PKG=$(find "$KMOD_DIR/work/pkg" -name 'if-pppoe-kmod-*.pkg' 2>/dev/null | head -1)
	[ -n "$KMOD_PKG" ] || die "build-kmod.sh did not produce a .pkg under $KMOD_DIR/work/pkg"
	pkg query -F "$KMOD_PKG" '%Fp' | sed -n 's|^/usr/local/lib/if_pppoe/\([0-9a-f]*\)/if_pppoe\.ko$|\1|p' |
		LC_ALL=C sort > "$WORK/pkg-bids.txt"
	cmp -s "$WORK/pkg-bids.txt" "$WORK/ship.txt" || die "$KMOD_PKG does not hold exactly the passing build_ids"
	finish_packages "$KMOD_PKG"
	resolve_check
	write_repo_tarball
}

if [ "$MODE" = kernels-json ]; then
	case "$PHASE" in
	kmods) do_kmods ;;
	package) do_package ;;
	all) do_kmods; do_package ;;
	esac
	exit 0
fi

# --- lab mode (--target-kernel) -------------------------------------------------
command -v config >/dev/null 2>&1 || die "config(8) not found; this must run on a FreeBSD host"
if [ ! -f "$LAB_SMP_KERNEL" ] || [ ! -f "$LAB_SMP_KBD_FILE" ]; then
	echo "build-all.sh: LAB_HOME=$LAB_HOME has no collected kernel/SMP (run lab/vm/build-kernel.sh collect there first)" >&2
	exit 1
fi
LAB_SMP_KBD=$(cat "$LAB_SMP_KBD_FILE")
[ -d "$LAB_SMP_KBD" ] || die "$LAB_SMP_KBD_FILE names a KERNBUILDDIR that doesn't exist: $LAB_SMP_KBD"
[ -d "$LAB_SYSDIR" ] || die "LAB_HOME=$LAB_HOME has no src/sys (SYSDIR)"

mkdir -p "$WORK/kernels"
: > "$MANIFEST"

build_id_of() { kb_build_id "$1"; }

# verify_conf_equivalence TARGET_KERNEL BUILD_ID CONFTXT_OVERRIDE -- extracts
# each kernel's embedded config with config(8) -x (GENERIC's
# INCLUDE_CONFIG_FILE, which OPNsense's SMP config includes; same mechanism
# docs/CI.md's freebsd-build.sh cross-check uses, there against a freshly
# generated config instead of the lab's own kernel) and fails loudly if the
# two differ by anything other than a `makeoptions DEBUG` line, OR if
# extraction itself fails on either side. This is a config sanity check
# ONLY -- it does not stop stage-one reusing a stale .ko object across
# targets; see if-pppoe-kmod/Makefile's stage-one `clean` and its README.md.
# CONFTXT_OVERRIDE (--target-conftxt), when given, is used
# in place of running config -x on TARGET_KERNEL -- for a kernel whose own
# config -x can't extract one. --skip-config-check bypasses this function
# entirely (see its call site). Both sides go through the identical
# extraction/normalization, so it doesn't matter whether config -x expands
# `include` lines (unverified either way) -- any expansion behavior
# applies equally to both.
REF_CONFTXT="$WORK/ref.conftxt"
verify_conf_equivalence() {
	target_kernel="$1"
	build_id="$2"
	conftxt_override="$3"
	tgt_conftxt="$WORK/tgt-$build_id.conftxt"

	if [ ! -s "$REF_CONFTXT" ]; then
		if ! config -x "$LAB_SMP_KERNEL" > "$REF_CONFTXT" 2>"$WORK/ref.conftxt.err"; then
			echo "build-all.sh: config -x could not extract an embedded config from the lab SMP kernel ($LAB_SMP_KERNEL):" >&2
			sed 's/^/  /' "$WORK/ref.conftxt.err" >&2
			echo "build-all.sh: pass --skip-config-check to build anyway (not recommended -- see this script's header)" >&2
			exit 1
		fi
	fi

	if [ -n "$conftxt_override" ]; then
		[ -f "$conftxt_override" ] || { echo "build-all.sh: --target-conftxt '$conftxt_override' not found" >&2; exit 1; }
		cp "$conftxt_override" "$tgt_conftxt"
	elif ! config -x "$target_kernel" > "$tgt_conftxt" 2>"$WORK/tgt-$build_id.conftxt.err"; then
		echo "build-all.sh: config -x could not extract an embedded config from build_id=$build_id's kernel ($target_kernel):" >&2
		sed 's/^/  /' "$WORK/tgt-$build_id.conftxt.err" >&2
		echo "build-all.sh: pass --target-conftxt FILE (e.g. that box's own \`sysctl -n kern.conftxt\`) or --skip-config-check for this target" >&2
		exit 1
	fi
	[ -s "$tgt_conftxt" ] || { echo "build-all.sh: build_id=$build_id's embedded config extracted empty; refusing to treat that as equivalent" >&2; exit 1; }

	ref_norm="$WORK/ref.conftxt.norm"
	tgt_norm="$WORK/tgt-$build_id.conftxt.norm"
	# Sorted, so this only compares option SETS -- an ordering-only
	# difference (e.g. `include` expansion order) is not flagged.
	grep -vE '^[[:space:]]*makeoptions[[:space:]]+DEBUG([[:space:]]|=)' "$REF_CONFTXT" | sed '/^[[:space:]]*$/d' | sort > "$ref_norm"
	grep -vE '^[[:space:]]*makeoptions[[:space:]]+DEBUG([[:space:]]|=)' "$tgt_conftxt" | sed '/^[[:space:]]*$/d' | sort > "$tgt_norm"

	if ! diff -u "$ref_norm" "$tgt_norm" > "$WORK/diff-$build_id.txt"; then
		echo "build-all.sh: embedded config for build_id=$build_id differs from the lab SMP kernel by more than 'makeoptions DEBUG' -- the kmod would silently build against the wrong options:" >&2
		sed 's/^/  /' "$WORK/diff-$build_id.txt" >&2
		exit 1
	fi
	echo "    config equivalent to the lab SMP kernel (only makeoptions DEBUG differs, if at all)"
}

n=0
while IFS= read -r line; do
	[ -n "$line" ] || continue
	spec="${line%%"$US"*}"
	conftxt_override="${line#*"$US"}"
	[ "$conftxt_override" != "$line" ] || conftxt_override=""
	n=$((n + 1))
	kdir="$WORK/kernels/$n"
	mkdir -p "$kdir"

	case "$spec" in
	http://*.txz|https://*.txz)
		echo ">>> target kernel #$n: fetching kernel set $spec"
		command -v fetch >/dev/null 2>&1 || { echo "build-all.sh: fetch(1) not found; this must run on a FreeBSD host" >&2; exit 1; }
		fetch -q -o "$kdir/kernel.txz" "$spec"
		sha256 "$kdir/kernel.txz" 2>/dev/null || sha256sum "$kdir/kernel.txz"
		mkdir -p "$kdir/kset"
		tar -xf "$kdir/kernel.txz" -C "$kdir/kset" --include '*boot/kernel/kernel'
		[ -f "$kdir/kset/boot/kernel/kernel" ] || { echo "build-all.sh: $spec's kernel set has no boot/kernel/kernel" >&2; exit 1; }
		mv "$kdir/kset/boot/kernel/kernel" "$kdir/kernel"
		rm -rf "$kdir/kset" "$kdir/kernel.txz"
		;;
	http://*|https://*)
		echo ">>> target kernel #$n: fetching $spec"
		command -v fetch >/dev/null 2>&1 || { echo "build-all.sh: fetch(1) not found; this must run on a FreeBSD host" >&2; exit 1; }
		fetch -q -o "$kdir/kernel" "$spec"
		;;
	*)
		[ -f "$spec" ] || {
			echo "build-all.sh: --target-kernel '$spec' is not an existing file and not an http(s):// URL" >&2
			exit 1
		}
		cp "$spec" "$kdir/kernel"
		;;
	esac

	TARGET_KERNEL="$kdir/kernel"
	BUILD_ID=$(build_id_of "$TARGET_KERNEL")
	[ -n "$BUILD_ID" ] || { echo "build-all.sh: no GNU build-id note in '$spec' (need readelf(1) or elfdump(1))" >&2; exit 1; }
	echo ">>> target kernel #$n: $spec -> build_id=$BUILD_ID"
	grep -q "^$BUILD_ID " "$MANIFEST" && { echo "build-all.sh: build_id=$BUILD_ID (from '$spec') was already given by an earlier --target-kernel; remove the duplicate" >&2; exit 1; }

	if [ "$SKIP_CONFIG_CHECK" -eq 1 ]; then
		echo "    config-equivalence check skipped (--skip-config-check)"
	else
		verify_conf_equivalence "$TARGET_KERNEL" "$BUILD_ID" "$conftxt_override"
	fi

	OVL="$WORK/kobj-$BUILD_ID"
	rm -rf "$OVL"
	mkdir -p "$OVL"
	# The glob list also matches dotfiles (excluding . and ..), so every
	# entry of LAB_SMP_KBD is symlinked, not just the visible ones.
	for entry in "$LAB_SMP_KBD"/* "$LAB_SMP_KBD"/.[!.]* "$LAB_SMP_KBD"/..?*; do
		[ -e "$entry" ] || continue
		base=$(basename "$entry")
		[ "$base" = kernel ] && continue
		ln -s "$entry" "$OVL/$base"
	done
	cp "$TARGET_KERNEL" "$OVL/kernel"

	printf '%s %s %s\n' "$BUILD_ID" "$OVL" "$LAB_SYSDIR" >> "$MANIFEST"
done <<EOF
$TARGET_KERNELS
EOF

echo ">>> build-kmod.sh --manifest ($n kernel build(s))"
sh "$BUILD_DIR/build-kmod.sh" --manifest "$MANIFEST" --version "$KMOD_VERSION"
KMOD_PKG=$(find "$KMOD_DIR/work/pkg" -name 'if-pppoe-kmod-*.pkg' 2>/dev/null | head -1)
[ -n "$KMOD_PKG" ] || die "build-kmod.sh did not produce a .pkg under $KMOD_DIR/work/pkg"
finish_packages "$KMOD_PKG"
write_repo_tarball
