#!/bin/sh
# latest-release.sh -- print the tag of the release GitHub marks Latest.
# Prints nothing and exits 0 when there is no full release yet (HTTP 404);
# any other failure passes gh's error to stderr and exits non-zero.
# Needs GH_REPO (owner/name) and GH_TOKEN, like the other gh calls in CI.
#
# Not `gh release list --limit 1`: that sorts by created_at, which for a
# release is the date of its target commit. A kernel refresh v<ver>_<N>
# targets v<ver>'s commit, so it sorts behind v<ver> and the list would keep
# returning the base release. publish.yml always creates releases with
# --latest, so the Latest marker is authoritative.
set -eu

err=$(mktemp)
trap 'rm -f "$err"' EXIT

# gh api prints the error body to stdout on failure, so only echo on success.
if tag=$(gh api "repos/${GH_REPO:?}/releases/latest" --jq .tag_name 2>"$err"); then
	printf '%s\n' "$tag"
	exit 0
fi
if grep -q 'HTTP 404' "$err"; then
	exit 0
fi
cat "$err" >&2
exit 1
