#!/bin/sh
# discover-kernels.sh -- list every published OPNsense kernel set of each
# versions.json series and write kernels.json: one entry per kern.build_id
# (format: docs/CI.md "Kernel discovery"). Runs on Linux (CI: binutils)
# or FreeBSD (build-all.sh's local twin). Needs jq, tar with xz, readelf
# or elfdump, objcopy or config(8), strings, curl or fetch(1).
#
# usage: discover-kernels.sh --versions FILE --out kernels.json
#            [--cache DIR] [--series S]... [--union PREV.json]
#            [--groups FILE] [--configs-dir DIR]
#   --cache        sets/<sha256>.txz plus per-set results; a warm cache
#                  makes a rerun fetch only the directory listings.
#   --series       limit to these series (repeatable; default: all).
#   --union        keep PREV.json entries of the selected series whose set
#                  is no longer listed (the mirror dropped it), instead of
#                  silently shrinking coverage.
#   --groups       also write the initial build groups (same abi and
#                  config_hash) as JSON.
#   --configs-dir  also write each kernel's embedded config as <bid>.conf
#                  (build-all.sh's per-member opt_*.h guard reads them).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/kbuild.sh
. "$HERE/lib/kbuild.sh"

die() { echo "discover-kernels.sh: $*" >&2; exit 1; }
usage() { sed -n '8,20p' "$0" >&2; exit 1; }

VERSIONS='' OUT='' CACHE='' UNION='' GROUPS_OUT='' CONFIGS='' SERIES=''
while [ $# -gt 0 ]; do
	case "$1" in
	--versions) shift; VERSIONS=${1:?} ;;
	--out) shift; OUT=${1:?} ;;
	--cache) shift; CACHE=${1:?} ;;
	--series) shift; SERIES="$SERIES ${1:?}" ;;
	--union) shift; UNION=${1:?} ;;
	--groups) shift; GROUPS_OUT=${1:?} ;;
	--configs-dir) shift; CONFIGS=${1:?} ;;
	-h|--help) usage ;;
	*) echo "discover-kernels.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done
[ -n "$VERSIONS" ] && [ -n "$OUT" ] || usage
[ -f "$VERSIONS" ] || die "$VERSIONS not found"
command -v jq >/dev/null 2>&1 || die "jq not installed"
command -v strings >/dev/null 2>&1 || die "strings not installed (binutils)"

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
CACHE=${CACHE:-$T/cache}
mkdir -p "$CACHE/sets" "$CACHE/index" "$CACHE/meta" "$CACHE/configs"
[ -z "$CONFIGS" ] || mkdir -p "$CONFIGS"
: > "$T/entries"

jq -r '.entries[] | [.opnsense_series, .freebsd_abi, .kernel_sets_url] | @tsv' "$VERSIONS" > "$T/series"
[ -s "$T/series" ] || die "$VERSIONS has no entries"

want_series() {
	[ -n "$SERIES" ] || return 0
	for s in $SERIES; do [ "$s" = "$1" ] && return 0; done
	return 1
}

# inspect URL -> sets SHA, BID, FVER, CHASH (from the cache when this URL
# was inspected before, else by downloading and reading the kernel).
inspect() {
	ukey=$(printf '%s' "$1" | kb_sha256_stdin)
	if [ -s "$CACHE/index/$ukey" ]; then
		SHA=$(cat "$CACHE/index/$ukey")
		if [ -s "$CACHE/meta/$SHA" ] && [ -s "$CACHE/configs/$SHA.conf" ]; then
			read -r BID FVER CHASH < "$CACHE/meta/$SHA"
			return 0
		fi
	fi
	echo ">>> fetching $1" >&2
	kb_fetch "$1" "$T/set.txz" || die "could not download $1"
	SHA=$(kb_sha256 "$T/set.txz")
	kb_extract_kernel "$T/set.txz" "$T/kernel" || die "$1: no boot/kernel/kernel in the set"
	mv "$T/set.txz" "$CACHE/sets/$SHA.txz"
	BID=$(kb_build_id "$T/kernel")
	echo "$BID" | grep -Eq '^[0-9a-f]{16,}$' || die "$1: no GNU build-id note in boot/kernel/kernel (got '$BID')"
	FVER=$(kb_kernel_version "$T/kernel" | sed -n 's/^FreeBSD \([0-9]*\.[0-9]*\)-.*/\1/p')
	[ -n "$FVER" ] || die "$1: no 'FreeBSD X.Y-' version string in the kernel"
	kb_extract_config "$T/kernel" "$CACHE/configs/$SHA.conf" ||
		die "$1: no embedded config (INCLUDE_CONFIG_FILE); refusing to group it blindly"
	CHASH=$(kb_config_hash "$CACHE/configs/$SHA.conf") || die "$1: embedded config normalises to nothing"
	echo "$BID $FVER $CHASH" > "$CACHE/meta/$SHA"
	echo "$SHA" > "$CACHE/index/$ukey"
	rm -f "$T/kernel"
}

while IFS="$(printf '\t')" read -r series abi url; do
	want_series "$series" || continue
	case "$url" in */) ;; *) url="$url/" ;; esac
	sre=$(printf '%s' "$series" | sed 's/\./\\./g')
	# The sets dir also carries the NEXT series' first kernel (e.g. 25.7/
	# lists kernel-26.1-amd64.txz), and .sig files: prefix match only.
	kb_list_dir "$url" > "$T/listing" || die "could not list $url"
	grep -E "^kernel-$sre(\\.[0-9]+)*(_[0-9]+)?-amd64\\.txz\$" "$T/listing" | sort -u > "$T/names" || true
	[ -s "$T/names" ] || die "no kernel-$series*-amd64.txz under $url"
	echo ">>> $series: $(wc -l < "$T/names" | tr -d ' ') kernel set(s) at $url" >&2
	while IFS= read -r name; do
		version=${name#kernel-}
		version=${version%-amd64.txz}
		inspect "$url$name"
		major=${FVER%%.*}
		kabi="FreeBSD:$major:amd64"
		[ "$kabi" = "$abi" ] || die "$url$name is a FreeBSD $FVER kernel ($kabi), but versions.json says $series is $abi"
		[ -z "$CONFIGS" ] || cp "$CACHE/configs/$SHA.conf" "$CONFIGS/$BID.conf"
		jq -nc --arg series "$series" --arg version "$version" --arg abi "$abi" \
			--arg fv "$FVER" --arg url "$url$name" --arg sha "$SHA" --arg bid "$BID" \
			--arg ch "$CHASH" \
			'{series: $series, version: $version, abi: $abi, freebsd_version: $fv,
			  src_tag: $version, url: $url, sha256: $sha, build_id: $bid, config_hash: $ch}' \
			>> "$T/entries"
		echo "    $version: build_id=$BID FreeBSD $FVER config=$(echo "$CHASH" | cut -c1-12)" >&2
	done < "$T/names"
done < "$T/series"

[ -s "$T/entries" ] || die "no kernels discovered (series filter:${SERIES:- none})"

# shellcheck disable=SC2016 # jq program, not shell
JQ_DEFS='def vkey: [scan("[0-9]+") | tonumber];
def order: sort_by(.abi, (.series | vkey), (.version | vkey));'

# Same kernel published under two versions (no rebuild): keep the first.
jq -s "$JQ_DEFS"'
	group_by(.build_id)
	| map(select(length > 1) | "discover-kernels.sh: build_id \(.[0].build_id) is published as " + (map(.version) | join(", ")) + "; keeping the lowest")
	| .[]' "$T/entries" >&2 || true
jq -s "$JQ_DEFS"'group_by(.build_id) | map(sort_by(.version | vkey) | .[0]) | order' \
	"$T/entries" > "$T/kernels.json"

if [ -n "$UNION" ] && [ -s "$UNION" ]; then
	# shellcheck disable=SC2086 # word-split the series list on purpose
	sel=$(printf '%s\n' $SERIES | jq -Rsc 'split("\n") | map(select(length > 0))')
	jq --slurpfile prev "$UNION" --argjson sel "$sel" "$JQ_DEFS"'
		(map(.build_id)) as $have
		| . + [$prev[0][] | select(($sel | length) == 0 or (.series | IN($sel[])))
			| select(.build_id | IN($have[]) | not)]
		| order' "$T/kernels.json" > "$T/union.json"
	jq -r --slurpfile cur "$T/kernels.json" '
		($cur[0] | map(.build_id)) as $have
		| .[] | select(.build_id | IN($have[]) | not)
		| "discover-kernels.sh: \(.version) (\(.build_id)) no longer listed; kept from --union"' \
		"$T/union.json" >&2
	if [ -n "$CONFIGS" ]; then
		jq -r '.[] | "\(.build_id) \(.sha256)"' "$T/union.json" | while read -r b s; do
			[ -f "$CONFIGS/$b.conf" ] || [ ! -f "$CACHE/configs/$s.conf" ] ||
				cp "$CACHE/configs/$s.conf" "$CONFIGS/$b.conf"
		done
	fi
	mv "$T/union.json" "$T/kernels.json"
fi

jq -e 'type == "array" and length > 0 and all(.[];
	(.build_id | test("^[0-9a-f]{16,}$")) and (.sha256 | test("^[0-9a-f]{64}$"))
	and (.config_hash | test("^[0-9a-f]{64}$")) and (.abi | test("^FreeBSD:[0-9]+:amd64$"))
	and (.series as $s | .version | startswith($s)))' "$T/kernels.json" > /dev/null ||
	die "internal: produced kernels.json fails its own schema check"
mkdir -p "$(dirname "$OUT")"
cp "$T/kernels.json" "$OUT"

if [ -n "$GROUPS_OUT" ]; then
	jq "$JQ_DEFS"'group_by([.abi, .config_hash])
		| map(sort_by(.version | vkey)
			| {abi: .[0].abi, config_hash: .[0].config_hash,
			   representative: .[-1].build_id,
			   members: map({build_id, version})})
		| sort_by(.abi, (.members[-1].version | vkey))' "$OUT" > "$GROUPS_OUT"
fi

jq -r 'group_by(.abi)[] | "\(.[0].abi): \(length) kernel(s), \(map(.config_hash) | unique | length) config(s): \(map(.version) | join(" "))"' "$OUT" >&2
