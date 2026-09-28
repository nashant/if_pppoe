#!/bin/sh
# refresh-plan.sh -- the pure parts of nightly.yml's kernel-only refresh.
#   base-version TAG        v0.4_3 -> 0.4 (strips v and a _N refresh suffix)
#   next-revision VER       stdin: tag names (git tags and release tags, any
#                           mix, duplicates fine). Prints 1 + the largest N
#                           of any v<VER>_<N>, or 1 when there is none, so a
#                           number is never reused even after a release was
#                           deleted (its git tag still counts).
#   new-build-ids NEW OLD   kernels.json files: build_ids in NEW not in OLD,
#                           one per line, sorted. A missing OLD is an error
#                           (no baseline means no refresh, not "all new").
set -eu

die() { echo "refresh-plan.sh: $*" >&2; exit 1; }

case "${1:-}" in
base-version)
	t=${2:?usage: base-version TAG}
	v=${t#v}
	v=${v%%_*}
	printf '%s' "$v" | grep -Eqx '[0-9]+(\.[0-9]+)*' || die "not a release tag: $t"
	echo "$v"
	;;
next-revision)
	ver=${2:?usage: next-revision VER}
	printf '%s' "$ver" | grep -Eqx '[0-9]+(\.[0-9]+)*' || die "not a version: $ver"
	re="^v$(printf '%s' "$ver" | sed 's/\./\\./g')_[0-9]+\$"
	max=$(grep -E "$re" | sed 's/.*_//' | sort -n | tail -n 1 || true)
	echo $((${max:-0} + 1))
	;;
new-build-ids)
	new=${2:?usage: new-build-ids NEW OLD}
	old=${3:?usage: new-build-ids NEW OLD}
	[ -s "$old" ] || die "$old: no previous kernels.json"
	command -v jq >/dev/null 2>&1 || die "jq not installed"
	jq -r --slurpfile old "$old" '
		[$old[0][].build_id] as $o | .[].build_id | select(. as $b | $o | index($b) | not)' "$new" \
		| LC_ALL=C sort -u
	;;
*)
	die "usage: refresh-plan.sh base-version|next-revision|new-build-ids ..."
	;;
esac
