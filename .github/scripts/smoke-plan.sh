#!/bin/sh
# smoke-plan.sh -- decide which discovered kernels the smoke job boots and
# shard them. Env: KERNELS_JSON KMOD_SRC_ID SMOKE_SCOPE [COMPAT_JSON]
# [SMOKE_ABIS] [SHARD_SIZE] [VERSIONS_FILE] [OUT_DIR].
#
# SMOKE_SCOPE: all | untested (no cached result for (bid, KMOD_SRC_ID); a
# cached fail stays failed) | latest-per-series (newest version per series,
# always smoked, for PR CI). SMOKE_ABIS limits the ABIs (space list; empty =
# every ABI in KERNELS_JSON). Writes OUT_DIR/{matrix.json,abis.json,
# planned.txt} and, under GitHub Actions, the outputs matrix, abis, count.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
: "${KERNELS_JSON:?}" "${KMOD_SRC_ID:?}"
SMOKE_SCOPE=${SMOKE_SCOPE:-latest-per-series}
COMPAT_JSON=${COMPAT_JSON:-}
SMOKE_ABIS=${SMOKE_ABIS:-}
SHARD_SIZE=${SHARD_SIZE:-5}
VERSIONS_FILE=${VERSIONS_FILE:-$HERE/../versions.json}
OUT_DIR=${OUT_DIR:-.}
die() { echo "smoke-plan.sh: $*" >&2; exit 1; }
case "$SMOKE_SCOPE" in all | untested | latest-per-series) ;; *) die "unknown SMOKE_SCOPE $SMOKE_SCOPE" ;; esac
case "$SHARD_SIZE" in '' | *[!0-9]* | 0) die "SHARD_SIZE must be a positive integer" ;; esac
printf '%s' "$KMOD_SRC_ID" | grep -Eqx '[0-9a-f]{64}' || die "KMOD_SRC_ID is not a sha256"
jq -e 'type == "array" and length > 0' "$KERNELS_JSON" > /dev/null || die "$KERNELS_JSON: empty or not an array"
mkdir -p "$OUT_DIR"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# Per-ABI guest userland and status from versions.json: the newest FreeBSD
# of the ABI's series; supported if any series of the ABI is (matrix.sh abi).
jq -c '[.entries | group_by(.freebsd_abi)[] | {
	abi: .[0].freebsd_abi,
	freebsd_version: ([.[].freebsd_version] | sort_by(split(".") | map(tonumber)) | last),
	status: (if any(.[]; .status == "supported") then "supported" else "experimental" end)}]' \
	"$VERSIONS_FILE" > "$T/abis-all.json"

# Kernels in scope, oldest first per ABI (so the shard's newest boots last
# and the best-effort dial can run on it without another reboot).
jq -c --arg abis "$SMOKE_ABIS" '
	def vkey: [.version | scan("[0-9]+") | tonumber];
	($abis | split(" ") | map(select(length > 0))) as $want
	| [.[] | select(($want | length) == 0 or (.abi as $a | $want | index($a)))]
	| sort_by(.abi, vkey)' "$KERNELS_JSON" > "$T/kernels.json"
jq -e 'length > 0' "$T/kernels.json" > /dev/null || die "no kernels for SMOKE_ABIS='$SMOKE_ABIS'"

# Kernels to smoke, per scope.
: > "$T/planned.txt"
case "$SMOKE_SCOPE" in
all) jq -r '.[].build_id' "$T/kernels.json" > "$T/planned.txt" ;;
latest-per-series)
	jq -r 'def vkey: [.version | scan("[0-9]+") | tonumber];
		group_by(.series)[] | sort_by(vkey) | last | .build_id' "$T/kernels.json" > "$T/planned.txt"
	;;
untested)
	for bid in $(jq -r '.[].build_id' "$T/kernels.json"); do
		if r=$(sh "$HERE/compat.sh" lookup "$COMPAT_JSON" "$bid" "$KMOD_SRC_ID"); then
			echo "smoke-plan.sh: $bid cached $r, not re-smoked" >&2
		else
			echo "$bid" >> "$T/planned.txt"
		fi
	done
	;;
esac

jq -c --rawfile planned "$T/planned.txt" --slurpfile abis "$T/abis-all.json" --argjson size "$SHARD_SIZE" '
	($planned | split("\n") | map(select(length > 0))) as $p
	| ($abis[0] | map({key: .abi, value: .}) | from_entries) as $meta
	| {include: [group_by(.abi)[]
		| map(select(.build_id as $b | $p | index($b))) | select(length > 0)
		| .[0].abi as $abi
		| ($meta[$abi] // error("ABI \($abi) not in versions.json")) as $m
		| [range(0; length; $size) as $i | .[$i:$i + $size]] | to_entries[]
		| {abi: $abi, slug: ($abi | gsub(":"; "-")), freebsd_version: $m.freebsd_version,
		   status: $m.status, shard: (.key + 1),
		   build_ids: (.value | map(.build_id) | join(" ")),
		   versions: (.value | map(.version) | join(" ")),
		   newest: (.value | last | .build_id)}]}' "$T/kernels.json" > "$OUT_DIR/matrix.json"

jq -c --slurpfile abis "$T/abis-all.json" '
	($abis[0] | map({key: .abi, value: .}) | from_entries) as $meta
	| {include: [map(.abi) | unique[] | {abi: ., slug: gsub(":"; "-"), status: ($meta[.].status // "experimental")}]}' \
	"$T/kernels.json" > "$OUT_DIR/abis.json"
cp "$T/planned.txt" "$OUT_DIR/planned.txt"

count=$(jq '.include | length' "$OUT_DIR/matrix.json")
nk=$(grep -c . "$T/planned.txt" || true)
echo "smoke-plan.sh: scope=$SMOKE_SCOPE: $nk of $(jq length "$T/kernels.json") kernels to smoke in $count shard(s)" >&2
if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		echo "matrix=$(cat "$OUT_DIR/matrix.json")"
		echo "abis=$(cat "$OUT_DIR/abis.json")"
		echo "count=$count"
	} >> "$GITHUB_OUTPUT"
fi
