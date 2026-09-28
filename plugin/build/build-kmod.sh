#!/bin/sh
# Runs stage-one per manifest line, then one package build. FreeBSD-host
# only; see plugin/kmod/if-pppoe-kmod/README.md. Manifest lines (default
# plugin/build/kernels.conf, '#'-comments ok):
#   <build_id> <KERNBUILDDIR> <SYSDIR>   build against that kernel build dir
#   <build_id> prebuilt <path/if_pppoe.ko>   stage an already built .ko
# --kernels-json ships that discovery output's entries (make KERNELS_JSON=).
# Env KMOD_MAKE_ARGS is forwarded to stage-one (e.g. WERROR=-Werror).
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KMOD_DIR="$REPO_ROOT/plugin/kmod/if-pppoe-kmod"
MANIFEST="$REPO_ROOT/plugin/build/kernels.conf"
KMOD_VERSION=0.1
KERNELS_JSON=

usage() {
	echo "usage: build-kmod.sh [--manifest FILE] [--version VERSION] [--kernels-json FILE]" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--manifest) shift; MANIFEST=${1:?} ;;
	--version) shift; KMOD_VERSION=${1:?} ;;
	--kernels-json) shift; KERNELS_JSON=${1:?} ;;
	-h|--help) usage ;;
	*) echo "build-kmod.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

[ -f "$MANIFEST" ] || { echo "build-kmod.sh: manifest not found: $MANIFEST (see this script's header for the format)" >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "build-kmod.sh: make not found" >&2; exit 1; }

n=0
while IFS=' ' read -r build_id kernbuilddir sysdir _rest; do
	case "$build_id" in ''|'#'*) continue ;; esac
	[ -n "$kernbuilddir" ] && [ -n "$sysdir" ] || {
		echo "build-kmod.sh: malformed manifest line: $build_id $kernbuilddir $sysdir" >&2
		exit 1
	}
	if [ "$kernbuilddir" = prebuilt ]; then
		echo ">>> stage-prebuilt BUILD_ID=$build_id"
		make -C "$KMOD_DIR" BUILD_ID="$build_id" KO="$sysdir" stage-prebuilt
	else
		echo ">>> stage-one BUILD_ID=$build_id"
		make -C "$KMOD_DIR" BUILD_ID="$build_id" KERNBUILDDIR="$kernbuilddir" SYSDIR="$sysdir" \
			${KMOD_MAKE_ARGS:+KMOD_MAKE_ARGS="$KMOD_MAKE_ARGS"} stage-one
	fi
	n=$((n + 1))
done < "$MANIFEST"

[ "$n" -gt 0 ] || { echo "build-kmod.sh: manifest had no kernel lines, nothing staged" >&2; exit 1; }

echo ">>> packaging ($n kernel build(s) staged)"
if [ -n "$KERNELS_JSON" ]; then
	[ -f "$KERNELS_JSON" ] || { echo "build-kmod.sh: --kernels-json $KERNELS_JSON not found" >&2; exit 1; }
	KERNELS_JSON=$(cd "$(dirname "$KERNELS_JSON")" && pwd)/$(basename "$KERNELS_JSON")
	make -C "$KMOD_DIR" KMOD_VERSION="$KMOD_VERSION" KERNELS_JSON="$KERNELS_JSON" package
else
	make -C "$KMOD_DIR" KMOD_VERSION="$KMOD_VERSION" package
fi
