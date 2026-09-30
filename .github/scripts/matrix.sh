#!/bin/sh
# matrix.sh build|abi|php [STATUSES] -- emit a GitHub Actions matrix (compact
# JSON, {"include":[...]}) from .github/versions.json.
#   build  one row per entry whose status is in STATUSES (comma list,
#          default "supported,experimental").
#   abi    one row per freebsd_abi over those entries (one kmod package per
#          ABI): abi_slug, freebsd_version (highest), series (space-joined,
#          lowest first), status (supported if any member is), php/python/
#          kernconf of the lowest series.
#   php    one row per distinct php_version; experimental only when every
#          entry using that PHP is experimental.
# VERSIONS_FILE overrides the input (nightly.yml feeds resolved latest tags).
set -eu

mode=${1:?usage: matrix.sh build|abi|php [STATUSES]}
statuses=${2:-supported,experimental}
file=${VERSIONS_FILE:-$(dirname "$0")/../versions.json}
command -v jq >/dev/null 2>&1 || { echo "matrix.sh: jq not installed" >&2; exit 1; }

case "$mode" in
build)
	jq -c --arg st "$statuses" '
		($st | split(",")) as $want
		| {include: [.entries[] | select(.status as $s | $want | index($s))]}
		| if (.include | length) == 0 then error("no entries match statuses \($st)") else . end
	' "$file"
	;;
abi)
	jq -c --arg st "$statuses" '
		def vkey: split(".") | map(tonumber);
		($st | split(",")) as $want
		| [.entries[] | select(.status as $s | $want | index($s))]
		| if length == 0 then error("no entries match statuses \($st)") else . end
		| {include: [group_by(.freebsd_abi)[] | sort_by(.opnsense_series | vkey)
			| if (map(.kernconf) | unique | length) > 1
			  then error("\(.[0].freebsd_abi): series disagree on kernconf") else . end
			| {freebsd_abi: .[0].freebsd_abi,
			   abi_slug: (.[0].freebsd_abi | gsub(":"; "-")),
			   freebsd_version: (map(.freebsd_version) | max_by(vkey)),
			   series: (map(.opnsense_series) | join(" ")),
			   status: (if any(.[]; .status == "supported") then "supported" else "experimental" end),
			   php_version: .[0].php_version,
			   python_version: .[0].python_version,
			   kernconf: .[0].kernconf}]}
	' "$file"
	;;
php)
	jq -c '
		{include: [.entries | group_by(.php_version)[]
			| {php_version: .[0].php_version,
			   experimental: (all(.[]; .status == "experimental")),
			   series: ([.[].opnsense_series] | join(" "))}]}
	' "$file"
	;;
*)
	echo "matrix.sh: unknown mode $mode" >&2
	exit 1
	;;
esac
