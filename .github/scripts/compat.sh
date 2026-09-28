#!/bin/sh
# compat.sh -- the per-kernel smoke result cache (compat.json). See
# docs/CI.md "Smoke" and the kernel-matrix plan, section 2.2.
#
#   compat.sh kmod-src [REPO]
#       Print KMOD_SRC_ID: sha256 of `git ls-tree -r HEAD --` KMOD_SRC_PATHS
#       in REPO (default: this checkout). Any change to the driver,
#       pppoectl, the kmod packaging, or what decides the kernel build dir
#       (and so the opt_*.h) a .ko is compiled against -- plugin/build
#       (build-all.sh, lib/kbuild.sh), freebsd-build.sh, versions.json --
#       changes it and so invalidates every cached result.
#   compat.sh lookup COMPAT BUILD_ID KMOD_SRC
#       Print the newest cached result (pass|fail) for (BUILD_ID, KMOD_SRC);
#       exit non-zero when there is none. A missing COMPAT file is an empty cache.
#   compat.sh merge OUT PREV [PART...]
#       Write OUT = PREV's results + every PART's results (history is kept;
#       exact duplicates dropped; sorted by time). PREV and PARTs may be
#       missing (skipped). Malformed JSON or schema != 1 is an error.
#   compat.sh pass-list ABI KERNELS COMPAT KMOD_SRC [PLANNED [GONE]]
#       Print, one per line, the build_ids of ABI in KERNELS (kernels.json)
#       that the package may ship: the newest result for (bid, KMOD_SRC) is
#       pass, or there is no result and the bid is not listed in PLANNED
#       (a file, one bid per line: the bids this run tried to smoke). A
#       planned bid with no result (smoke infrastructure failure), a
#       planned bid listed in GONE (a file, one bid per line: its kernel set
#       is no longer on the mirror, smoke-vm.sh set-gone.txt) and a cached
#       or fresh fail are all excluded.
#   compat.sh fail-list ABI KERNELS COMPAT KMOD_SRC [PLANNED [GONE]]
#       The complement of pass-list within ABI, as "bid version reason";
#       reason is the fail detail, "no-result" or "set-gone".
set -eu

die() { echo "compat.sh: $*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || die "jq not installed"
# Temp files instead of pipelines: POSIX sh has no pipefail, and a die()
# inside a pipeline would only end its subshell.
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# Read a compat file (or nothing) as a results array; validates the schema.
results_of() { # FILE
	if [ ! -s "$1" ]; then
		echo '[]'
		return 0
	fi
	jq -ce 'if type == "object" and .schema == 1 and (.results | type) == "array"
		then .results else error("not a schema-1 compat.json") end' "$1" \
		|| die "$1: malformed compat.json"
}

# What a cached result vouches for: the module source and everything that
# shapes the kernel build dir it is compiled in.
KMOD_SRC_PATHS="sys sbin/pppoectl plugin/kmod plugin/build .github/scripts/freebsd-build.sh .github/versions.json"

cmd_kmod_src() {
	repo=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
	# shellcheck disable=SC2086 # a path list, split on purpose
	git -C "$repo" ls-tree -r HEAD -- $KMOD_SRC_PATHS > "$T/tree" || die "git ls-tree failed in $repo"
	[ -s "$T/tree" ] || die "$repo: none of $KMOD_SRC_PATHS in HEAD"
	sha256sum < "$T/tree" | awk '{print $1}'
}

cmd_lookup() {
	[ $# -eq 3 ] || die "usage: lookup COMPAT BUILD_ID KMOD_SRC"
	results_of "$1" > "$T/r"
	jq -er --arg b "$2" --arg k "$3" '
		[.[] | select(.build_id == $b and .kmod_src == $k)]
		| sort_by(.at) | last | .result // empty' "$T/r"
}

cmd_merge() {
	[ $# -ge 2 ] || die "usage: merge OUT PREV [PART...]"
	out=$1
	shift
	tmp=$T/acc
	echo '[]' > "$tmp"
	for f in "$@"; do
		[ -e "$f" ] || { echo "compat.sh: $f absent, skipped" >&2; continue; }
		results_of "$f" > "$T/r"
		jq -c --slurpfile acc "$tmp" '$acc[0] + .' "$T/r" > "$tmp.n"
		mv "$tmp.n" "$tmp"
	done
	jq -e 'all(.[]; (.build_id | test("^[0-9a-f]{40}$")) and (.kmod_src | test("^[0-9a-f]{64}$"))
		and (.result == "pass" or .result == "fail") and (.at | type) == "string")' "$tmp" > /dev/null \
		|| die "merge: invalid result entry"
	mkdir -p "$(dirname "$out")"
	jq '{schema: 1, results: (unique_by([.build_id, .kmod_src, .at, .result]) | sort_by(.at, .build_id))}' \
		"$tmp" > "$out.tmp"
	mv "$out.tmp" "$out"
}

# Shared by pass-list / fail-list: one object per kernel of ABI with its
# verdict ("pass", "fail", "unsmoked", "gone" or "missing").
bids_of() { # FILE -> JSON array of the build_ids in it (none: [])
	if [ -n "${1:-}" ] && [ -s "$1" ]; then
		{ grep -Eo '[0-9a-f]{40}' "$1" || true; } | jq -Rsc 'split("\n") | map(select(length > 0))'
	else
		echo '[]'
	fi
}

verdicts() { # ABI KERNELS COMPAT KMOD_SRC [PLANNED [GONE]]
	[ $# -ge 4 ] || die "usage: pass-list|fail-list ABI KERNELS COMPAT KMOD_SRC [PLANNED [GONE]]"
	[ -s "$2" ] || die "$2: no kernels.json"
	planned=$(bids_of "${5:-}")
	gone=$(bids_of "${6:-}")
	results_of "$3" > "$T/r"
	jq -c --arg abi "$1" --arg k "$4" --argjson planned "$planned" --argjson gone "$gone" \
		--slurpfile kernels "$2" '
		. as $res
		| $kernels[0][] | select(.abi == $abi)
		| .build_id as $b
		| ([$res[] | select(.build_id == $b and .kmod_src == $k)] | sort_by(.at) | last) as $r
		| {build_id: $b, version,
		   verdict: (if $r then $r.result
			elif ($planned | index($b)) then (if ($gone | index($b)) then "gone" else "missing" end)
			else "unsmoked" end),
		   detail: ($r.detail // "")}' "$T/r"
}

cmd_pass_list() {
	verdicts "$@" > "$T/v"
	jq -r 'select(.verdict == "pass" or .verdict == "unsmoked") | .build_id' "$T/v"
}

cmd_fail_list() {
	verdicts "$@" > "$T/v"
	jq -r 'select(.verdict == "fail" or .verdict == "missing" or .verdict == "gone")
		| "\(.build_id) \(.version) \(if .verdict == "missing" then "no-result"
			elif .verdict == "gone" then "set-gone" else .detail end)"' "$T/v"
}

cmd=${1:-}
[ $# -eq 0 ] || shift
case "$cmd" in
kmod-src) cmd_kmod_src "$@" ;;
lookup) cmd_lookup "$@" ;;
merge) cmd_merge "$@" ;;
pass-list) cmd_pass_list "$@" ;;
fail-list) cmd_fail_list "$@" ;;
*) die "usage: compat.sh kmod-src|lookup|merge|pass-list|fail-list ..." ;;
esac
