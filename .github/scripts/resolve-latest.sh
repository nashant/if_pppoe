#!/bin/sh
# resolve-latest.sh OUT_JSON -- rewrite .github/versions.json with the newest
# released tags of each series, for nightly.yml. Needs gh (GH_TOKEN) + jq + curl.
#
# Tag rules (docs/CI.md#how-latest-is-resolved):
#   core: newest opnsense/core tag matching ^SERIES(\.N)?$ (skips .a/.b/.r*).
#   src:  newest opnsense/src tag <= that core tag whose kernel set
#         (kernel-<src>-amd64.txz) is published under kernel_sets_url. src is
#         only re-tagged when the kernel changes, and src tags past a series'
#         last community release belong to Business Edition, which has no
#         community kernel set -- the set check excludes both cases.
# The resolved pins no longer decide which kernels get a .ko: discovery
# (plugin/build/discover-kernels.sh) covers every kernel-<series>*.txz in
# kernel_sets_url. opnsense_src_tag/opnsense_core_tag only pick the toolchain
# (opnsense/tools config, FreeBSD VM release) and the default/newest kernel of
# a series; drift here is informational (Renovate), not a coverage gap.
# Also writes new-series.txt (next to OUT_JSON) listing released core series
# (X.Y tags) newer than every entry, so nightly can nag to add them.
# TAGS_DIR=<dir with core.txt/src.txt> and SETS_DIR=<dir with one listing
# file per series> replace the network lookups for offline testing.
set -eu

out=${1:?usage: resolve-latest.sh OUT_JSON}
file=${VERSIONS_FILE:-$(dirname "$0")/../versions.json}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

list_tags() { # repo -> one tag per line
	if [ -n "${TAGS_DIR:-}" ]; then
		cat "$TAGS_DIR/$1.txt"
	else
		gh api --paginate "repos/opnsense/$1/tags?per_page=100" --jq '.[].name'
	fi
}

set_exists() { # series url src_tag
	if [ -n "${SETS_DIR:-}" ]; then
		grep -qxF "kernel-$3-amd64.txz" "$SETS_DIR/$1.txt"
	else
		curl -fsSIL --retry 3 -o /dev/null "$2kernel-$3-amd64.txz"
	fi
}

list_tags core > "$work/core"
list_tags src > "$work/src"

cp "$file" "$work/cur.json"
n=$(jq '.entries | length' "$file")
i=0
while [ "$i" -lt "$n" ]; do
	series=$(jq -r ".entries[$i].opnsense_series" "$file")
	url=$(jq -r ".entries[$i].kernel_sets_url" "$file")
	re="^$(printf '%s' "$series" | sed 's/\./\\./g')(\\.[0-9]+)?\$"

	core=$(grep -E "$re" "$work/core" | sort -V | tail -n 1 || true)
	[ -n "$core" ] || { echo "resolve-latest: no released core tag for $series" >&2; exit 1; }

	src=
	grep -E "$re" "$work/src" | sort -rV > "$work/cands" || true
	while IFS= read -r cand; do
		# first candidate (descending) that is <= core and has a kernel set
		[ "$(printf '%s\n%s\n' "$cand" "$core" | sort -V | tail -n 1)" = "$core" ] || continue
		if set_exists "$series" "$url" "$cand"; then
			src=$cand
			break
		fi
		echo "resolve-latest: $series: src $cand <= core $core has no kernel set, skipping" >&2
	done < "$work/cands"
	[ -n "$src" ] || { echo "resolve-latest: $series: no src tag <= $core with a kernel set" >&2; exit 1; }

	echo "resolve-latest: $series core=$core src=$src (pinned: $(jq -r ".entries[$i] | \"\(.opnsense_core_tag)/\(.opnsense_src_tag)\"" "$file"))" >&2
	jq --argjson i "$i" --arg core "$core" --arg src "$src" '
		.entries[$i] |= (.pinned_core_tag = .opnsense_core_tag
			| .pinned_src_tag = .opnsense_src_tag
			| .opnsense_core_tag = $core
			| .opnsense_src_tag = $src)
	' "$work/cur.json" > "$work/next.json"
	mv "$work/next.json" "$work/cur.json"
	i=$((i + 1))
done
mv "$work/cur.json" "$out"

newest=$(jq -r '.entries[].opnsense_series' "$file" | sort -V | tail -n 1)
grep -E '^[0-9]+\.[0-9]+$' "$work/core" | sort -V | while IFS= read -r s; do
	[ "$(printf '%s\n%s\n' "$s" "$newest" | sort -V | tail -n 1)" = "$newest" ] || echo "$s"
done > "$(dirname "$out")/new-series.txt"
