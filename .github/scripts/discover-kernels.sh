#!/bin/sh
# discover-kernels.sh run OUT_DIR | listing-key -- CI wrapper around
# plugin/build/discover-kernels.sh for .github/versions.json (ubuntu runner,
# binutils; no VM). See docs/CI.md "Kernel discovery".
#   run OUT_DIR   write OUT_DIR/kernels.json, groups.json and configs/
#   listing-key   print a sha256 over the kernel set names currently listed
#                 (the actions/cache key for the set cache)
# Env: VERSIONS_FILE (default .github/versions.json), DISCOVER_SERIES
# (space-separated series, default all), KERNEL_SETS_CACHE (default
# $RUNNER_TEMP/kernel-sets), PREV_KERNELS_JSON (optional: --union input).
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS_FILE=${VERSIONS_FILE:-$ROOT/.github/versions.json}
CACHE=${KERNEL_SETS_CACHE:-${RUNNER_TEMP:-/tmp}/kernel-sets}

series_args() {
	for s in ${DISCOVER_SERIES:-}; do printf ' --series %s' "$s"; done
}

case "${1:-}" in
run)
	out=${2:?usage: discover-kernels.sh run OUT_DIR}
	mkdir -p "$out"
	set -- --versions "$VERSIONS_FILE" --out "$out/kernels.json" --cache "$CACHE" \
		--groups "$out/groups.json" --configs-dir "$out/configs"
	if [ -n "${PREV_KERNELS_JSON:-}" ] && [ -s "$PREV_KERNELS_JSON" ]; then
		set -- "$@" --union "$PREV_KERNELS_JSON"
	fi
	# shellcheck disable=SC2046 # series_args is a flag list
	sh "$ROOT/plugin/build/discover-kernels.sh" "$@" $(series_args)
	;;
listing-key)
	# shellcheck source=../../plugin/build/lib/kbuild.sh
	. "$ROOT/plugin/build/lib/kbuild.sh"
	jq -r '.entries[] | "\(.opnsense_series)\t\(.kernel_sets_url)"' "$VERSIONS_FILE" |
		while IFS="$(printf '\t')" read -r series url; do
			echo "$series"
			kb_list_dir "$url" | grep -E '^kernel-.*-amd64\.txz$' | sort
		done | kb_sha256_stdin
	;;
*)
	echo "usage: discover-kernels.sh run OUT_DIR | listing-key" >&2
	exit 1
	;;
esac
