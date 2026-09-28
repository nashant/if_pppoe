#!/bin/sh
# Builds os-if-pppoe via vendored Mk/plugins.mk (plugin/Mk/VENDORED.md).
# FreeBSD-host only. plugins.mk's `manifest` target errors "Missing
# dependency" unless if-pppoe-kmod is already pkg-installed; --kmod-pkg
# installs it here, or build-kmod.sh + `pkg add` it yourself first.
#
# Pass 25.7 explicitly: defaults.mk falls back to PLUGIN_ABIS?=26.7 (master's
# default) without /usr/local/sbin/opnsense-version, e.g. a plain FreeBSD
# build VM. PLUGIN_PHP=83 is 25.7's own PHP (8.3.x, CE_25.7.html changelog),
# in defaults.mk's own major+minor-digits encoding. One os-if-pppoe serves
# every series of a FreeBSD ABI, so CI passes that ABI's series list with
# the lowest first (PLUGIN_ABI, the version file's product_abi, is the first
# word). PLUGIN_REVISION=N makes the package version <PLUGIN_VERSION>_N
# (plugins.mk), for kernel-only refreshes (docs/CI.md "Nightly refresh").
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PLUGIN_DIR="$REPO_ROOT/plugin/net/if-pppoe"
PLUGIN_ABIS="${PLUGIN_ABIS:-25.7}"
PLUGIN_PHP="${PLUGIN_PHP:-83}"
PLUGIN_REVISION="${PLUGIN_REVISION:-0}"
KMOD_PKG=

usage() {
	echo "usage: build-plugin.sh [--kmod-pkg PATH/if-pppoe-kmod-*.pkg]" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--kmod-pkg) shift; KMOD_PKG=${1:?} ;;
	-h|--help) usage ;;
	*) echo "build-plugin.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

command -v make >/dev/null 2>&1 || { echo "build-plugin.sh: make not found" >&2; exit 1; }
command -v pkg >/dev/null 2>&1 || { echo "build-plugin.sh: pkg(8) not found; this must run on a FreeBSD host" >&2; exit 1; }

if [ -n "$KMOD_PKG" ]; then
	[ -f "$KMOD_PKG" ] || { echo "build-plugin.sh: $KMOD_PKG not found" >&2; exit 1; }
	pkg query '%n' if-pppoe-kmod >/dev/null 2>&1 || pkg add "$KMOD_PKG"
fi

pkg query '%n' if-pppoe-kmod >/dev/null 2>&1 || {
	echo "build-plugin.sh: if-pppoe-kmod is not installed on this build host." >&2
	echo "                 Build it (build-kmod.sh) and either 'pkg add' the .pkg" >&2
	echo "                 or pass --kmod-pkg here." >&2
	exit 1
}

case "$PLUGIN_REVISION" in
''|*[!0-9]*) echo "build-plugin.sh: PLUGIN_REVISION must be a non-negative integer (got '$PLUGIN_REVISION')" >&2; exit 1 ;;
esac

make -C "$PLUGIN_DIR" PLUGIN_ABIS="$PLUGIN_ABIS" PLUGIN_PHP="$PLUGIN_PHP" \
	PLUGIN_REVISION="$PLUGIN_REVISION" package

MANIFEST="$PLUGIN_DIR/work/src/+MANIFEST"
if ! grep -q '^[[:space:]]*if-pppoe-kmod:' "$MANIFEST" 2>/dev/null; then
	echo "build-plugin.sh: built +MANIFEST ($MANIFEST) does not declare an if-pppoe-kmod dependency" >&2
	exit 1
fi
echo ">>> $(ls "$PLUGIN_DIR"/work/pkg/*.pkg 2>/dev/null || echo '(no .pkg found -- check make output above)')"
