#!/bin/bash
# release-assets.sh DIST OUT -- turn one build.yml run's downloaded artifacts
# into GitHub Release assets (publish.yml). Runs on the ubuntu runner; needs jq
# and sha256sum. No secrets are read or written here.
#
# Inputs (env):
#   MATRIX             matrix.sh abi output: {"include":[{freebsd_abi, series,
#                      status, ...}]}; supported ABIs are required, experimental
#                      ones are published when they built.
#   TAG                release tag (for coverage.json and the notes).
#   NOTES              optional text put at the top of the release notes.
#   REQUIRE_BUILD_IDS  optional space list: the new build_ids of a nightly
#                      kernel-only refresh. One that failed smoke is dropped
#                      and reported (dropped-new.txt); exit 1 and publish
#                      nothing only when one of a supported ABI has no smoke
#                      result, or when none was covered or smoked.
#
# DIST holds one directory per artifact (actions/download-artifact with a
# pattern). Files are located by name, so an artifact-prefix is harmless:
#   *kernels*/kernels.json            discovery output (all ABIs), required
#   *compat*/compat.json              merged smoke cache, optional
#   *pkg-<slug>*/pkg/*.pkg            packages
#   *pkg-<slug>*/repo-<slug>.tar.gz   signed repo: <ABI>/ plus client-conf/
#   *pkg-<slug>*/build-info.json      build info (else *kmods-<slug>*/)
#   *pass-build-ids-<slug>*/pass-build-ids*  build_ids the package holds
# where <slug> is the ABI with ':' replaced by '-' (FreeBSD-14-amd64).
#
# OUT receives (docs/CI.md#releases):
#   if_pppoe-repo-<slug>.tar.gz, <slug>-<pkgname>.pkg, build-info-<slug>.json,
#   kernels.json, compat.json, coverage.json, SHA256SUMS
# and, next to OUT (not assets), notes.md and dropped-new.txt (the new
# build_ids dropped by the refresh gate, "abi bid version reason" per line;
# empty when none).
set -euo pipefail

dist=${1:?usage: release-assets.sh DIST OUT}
out=${2:?usage: release-assets.sh DIST OUT}
: "${MATRIX:?MATRIX (matrix.sh abi output) is required}"
TAG=${TAG:-unknown}
NOTES=${NOTES:-}
REQUIRE_BUILD_IDS=${REQUIRE_BUILD_IDS:-}

command -v jq >/dev/null 2>&1 || { echo "release-assets.sh: jq not installed" >&2; exit 1; }
[ -d "$dist" ] || { echo "release-assets.sh: $dist is not a directory" >&2; exit 1; }
mkdir -p "$out"
notes="$(dirname "$out")/notes.md"
droppednew="$(dirname "$out")/dropped-new.txt"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

err() { echo "::error::$*" >&2; exit 1; }
warn() { echo "::warning::$*" >&2; }

# one_file NAME DIRGLOB -> the single file called NAME under a directory
# matching DIRGLOB; identical duplicates are fine, differing ones are not.
one_file() {
	local name=$1 dirglob=$2 first='' f
	while IFS= read -r f; do
		if [ -z "$first" ]; then
			first=$f
		elif ! cmp -s "$first" "$f"; then
			err "two different $name files: $first and $f"
		fi
	done < <(find "$dist" -type f -name "$name" -path "$dirglob" | LC_ALL=C sort)
	printf '%s' "$first"
}

kernels=$(one_file kernels.json '*kernels*/*')
[ -n "$kernels" ] || err "no kernels.json in $dist (kernels artifact from build.yml's discover job)"
jq -e 'type == "array" and all(.[]; has("build_id") and has("abi") and has("version"))' "$kernels" >/dev/null \
	|| err "$kernels is not a kernels.json array"
compat=$(one_file compat.json '*compat*/*')
[ -n "$compat" ] || warn "no compat.json in $dist: coverage falls back to the pass-build-ids lists only"

rows=$(jq -c '.include[]' <<<"$MATRIX")
[ -n "$rows" ] || err "MATRIX has no rows"

printf '[]' > "$work/coverage.json"
published=0
while IFS= read -r row; do
	abi=$(jq -r '.freebsd_abi' <<<"$row")
	status=$(jq -r '.status // "supported"' <<<"$row")
	series=$(jq -r '.series // ""' <<<"$row")
	slug=$(printf '%s' "$abi" | tr ':' '-')
	need() { # message: fatal for a supported ABI, skip for experimental
		if [ "$status" = supported ]; then err "$abi: $1"; fi
		warn "$abi (experimental): $1; not published"
		return 1
	}

	repo=$(one_file "repo-$slug.tar.gz" "*pkg-$slug*/*")
	[ -n "$repo" ] || { need "no signed repo-$slug.tar.gz" || continue; }
	# The tarball must hold the <ABI>/ catalogue and client-conf/, nothing else
	# at the top (pages.yml merges several of them into one site).
	top=$(tar -tzf "$repo" | sed -e 's|^\./||' -e 's|/.*||' | grep -v '^$' | LC_ALL=C sort -u | paste -sd' ')
	[ "$top" = "$abi client-conf" ] || [ "$top" = "client-conf $abi" ] \
		|| { need "repo-$slug.tar.gz top level is '$top', expected '$abi' and 'client-conf'" || continue; }
	tar -tzf "$repo" | grep -Eq "^(\./)?$abi/meta(\.conf)?$" \
		|| { need "repo-$slug.tar.gz has no $abi/meta.conf (unsigned or empty catalogue)" || continue; }

	pkgs=()
	while IFS= read -r p; do pkgs+=("$p"); done \
		< <(find "$dist" -type f -name '*.pkg' -path "*pkg-$slug*/pkg/*" | LC_ALL=C sort)
	[ "${#pkgs[@]}" -gt 0 ] || { need "no packages in the pkg-$slug artifact" || continue; }

	# Build_ids the package holds: the smoke merge job's list. Without it, the
	# newest compat.json result per build_id of this ABI.
	passf=$work/pass-$slug
	: > "$passf"
	while IFS= read -r f; do
		grep -Eo '^[0-9a-f]{16,}' "$f" >> "$passf" || true
	done < <(find "$dist" -type f -name 'pass-build-ids*' \
		\( -path "*pass-build-ids-$slug*/*" -o -path "*compat*/pass/$slug/*" \))
	if [ ! -s "$passf" ]; then
		if [ -n "$compat" ]; then
			warn "$abi: no pass-build-ids-$slug artifact; using compat.json's newest result per build_id"
			jq -r --arg abi "$abi" '
				[.results[] | select(.abi == $abi)] | group_by(.build_id)[]
				| max_by(.at) | select(.result == "pass") | .build_id' "$compat" > "$passf"
		else
			need "neither pass-build-ids-$slug nor compat.json: cannot tell which kernels are covered" || continue
		fi
	fi
	LC_ALL=C sort -u -o "$passf" "$passf"
	jq -R . "$passf" | jq -s . > "$passf.json"

	cov=$(jq -c --arg abi "$abi" --arg slug "$slug" --arg status "$status" --arg series "$series" \
		--slurpfile pass "$passf.json" --slurpfile compat <([ -n "$compat" ] && cat "$compat" || echo '{"results":[]}') '
		($pass[0]) as $p
		| ($compat[0].results // [] | map(select(.abi == $abi)) | group_by(.build_id)
			| map({key: .[0].build_id, value: (max_by(.at) | {result, detail})}) | from_entries) as $c
		| [.[] | select(.abi == $abi)] as $k
		| {abi: $abi, slug: $slug, status: $status, series: ($series | split(" ") | map(select(. != ""))),
		   covered: [$k[] | select(.build_id as $b | $p | index($b)) | {series, version, build_id}],
		   dropped: [$k[] | select(.build_id as $b | $p | index($b) | not)
			| {series, version, build_id, result: ($c[.build_id].result // "untested"),
			   detail: ($c[.build_id].detail // "")}]}' "$kernels")
	ncov=$(jq '.covered | length' <<<"$cov")
	[ "$ncov" -gt 0 ] || { need "no kernel of this ABI passed smoke; the package would cover nothing" || continue; }
	# A pass list naming a build_id that discovery never saw means the two
	# artifacts come from different runs.
	stray=$(jq -r --slurpfile k "$kernels" --arg abi "$abi" \
		'.[] | select(. as $b | [$k[0][] | select(.abi == $abi) | .build_id] | index($b) | not)' "$passf.json")
	[ -z "$stray" ] || err "$abi: pass-build-ids not in kernels.json: $stray"

	cp "$repo" "$out/if_pppoe-repo-$slug.tar.gz"
	for p in "${pkgs[@]}"; do cp "$p" "$out/$slug-$(basename "$p")"; done
	info=$(one_file build-info.json "*pkg-$slug*/*")
	[ -z "$info" ] && info=$(one_file build-info.json "*kmods-$slug*/*")
	if [ -n "$info" ]; then cp "$info" "$out/build-info-$slug.json"; else warn "$abi: no build-info.json"; fi

	jq --argjson c "$cov" '. + [$c]' "$work/coverage.json" > "$work/c.json"
	mv "$work/c.json" "$work/coverage.json"
	published=$((published + 1))
done <<<"$rows"

[ "$published" -gt 0 ] || err "nothing to publish"

# Refresh gate (nightly kernel-only refresh, REQUIRE_BUILD_IDS = the new
# build_ids). A new build_id that failed smoke is dropped like in a code
# release: it stays in kernels.json with its compat.json fail result, so no
# later run retries it, and it is listed in the notes and in dropped-new.txt
# (nightly.yml's report opens the nightly-failure issue from it). Publishing
# is refused only when
#  - a new build_id of a supported ABI has no result at all (smoke
#    infrastructure failure; smoke.yml's merge gate normally stops the run
#    first): publishing would record it in kernels.json unsmoked, and
#  - no new build_id was covered or smoked: nothing would change.
# Reasons come from the smoke merge's failed-build-ids.txt ("bid version
# reason"), else from the compat.json result in coverage.json.
reasons=$work/reasons
: > "$reasons"
while IFS= read -r f; do
	grep -E '^[0-9a-f]{16,} ' "$f" >> "$reasons" || true
done < <(find "$dist" -type f -name 'failed-build-ids*' \
	\( -path '*pass-build-ids-*' -o -path '*compat*/pass/*' \))
missing='' newcov=0 newdrop=0
: > "$droppednew"
for bid in $REQUIRE_BUILD_IDS; do
	abi=$(jq -r --arg b "$bid" '[.[] | select(.build_id == $b) | .abi][0] // ""' "$kernels")
	st=$(jq -r --arg a "$abi" --argjson m "$MATRIX" \
		'[$m.include[] | select(.freebsd_abi == $a) | .status // "supported"][0] // "absent"' <<<'null')
	ok=$(jq -r --arg b "$bid" '[.[].covered[] | select(.build_id == $b)] | length' "$work/coverage.json")
	if [ "$ok" -gt 0 ]; then
		newcov=$((newcov + 1))
		continue
	fi
	ver=$(jq -r --arg b "$bid" '[.[] | select(.build_id == $b) | .version][0] // "?"' "$kernels")
	why=$(awk -v b="$bid" '$1 == b { $1 = ""; $2 = ""; sub(/^  */, ""); print; exit }' "$reasons")
	if [ -z "$why" ]; then
		res=$(jq -r --arg b "$bid" '[.[].dropped[] | select(.build_id == $b) | .result][0] // "no-result"' \
			"$work/coverage.json")
		case "$res" in fail) why=fail ;; *) why=no-result ;; esac
	fi
	if [ "$why" = no-result ]; then
		if [ "$st" = supported ]; then
			missing="$missing $bid"
		else
			warn "new build_id $bid ($ver, ${abi:-unknown ABI} ${st}) has no smoke result; not blocking"
		fi
		continue
	fi
	warn "new build_id $bid ($ver, $abi) dropped: $why"
	printf '%s %s %s %s\n' "$abi" "$bid" "$ver" "$why" >> "$droppednew"
	newdrop=$((newdrop + 1))
done
[ -z "$missing" ] || err "new build_ids with no smoke result (smoke infrastructure failure):$missing; nothing published"
if [ -n "$REQUIRE_BUILD_IDS" ] && [ "$newcov" -eq 0 ] && [ "$newdrop" -eq 0 ]; then
	err "no new build_id was covered or smoked ($REQUIRE_BUILD_IDS); nothing published"
fi

cp "$kernels" "$out/kernels.json"
[ -z "$compat" ] || cp "$compat" "$out/compat.json"
jq --arg tag "$TAG" '{schema: 1, tag: $tag, abis: .}' "$work/coverage.json" > "$out/coverage.json"
(cd "$out" && rm -f SHA256SUMS && sha256sum -- * > "$work/SHA256SUMS" && mv "$work/SHA256SUMS" SHA256SUMS)

{
	if [ -n "$NOTES" ]; then printf '%s\n\n' "$NOTES"; fi
	echo "## Covered OPNsense kernels"
	echo
	echo "if-pppoe-kmod carries one if_pppoe.ko per kernel build below; the boot hook loads the one matching the running kern.build_id and falls back to mpd5 on any other kernel."
	jq -r '.abis[] |
		"\n### \(.abi) (OPNsense \(.series | join(", ")))\(if .status == "experimental" then " [experimental]" else "" end)\n",
		(.covered | group_by(.series)[] | "- \(.[0].series): \(map(.version) | join(", "))"),
		(if (.dropped | length) > 0 then
			"\nDropped (no .ko shipped; these kernels use mpd5):",
			(.dropped[] | "- \(.version) `\(.build_id)`: \(.result)\(if .detail != "" then " (\(.detail))" else "" end)")
		 else empty end)' "$out/coverage.json"
	if [ -s "$droppednew" ]; then
		echo
		echo "## New kernels dropped by this refresh"
		echo
		echo "These newly published kernels failed the CI smoke test; the boot hook refuses them and uses mpd5. Their fail result is in compat.json, so they are not retried until the module source changes (a new kmod_src, docs/CI.md)."
		while read -r a b v w; do echo "- $v ($a) \`$b\`: $w"; done < "$droppednew"
	fi
	echo
	echo "## Install"
	echo
	echo "Each if_pppoe-repo-<ABI>.tar.gz is a signed pkg repo (<ABI>/) plus client-conf/ (IfPppoe.conf with url <base>/\${ABI}, fingerprint, public key); client-conf/ is identical for every ABI. kernels.json lists every discovered kernel (version <-> build_id), compat.json the smoke results, coverage.json what each package covers. See docs/plugin/INSTALL.md."
} > "$notes"

ls -la "$out"
cat "$notes"
