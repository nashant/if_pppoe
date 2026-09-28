#!/bin/bash
# pages-site.sh DL SITE TAG -- build the GitHub Pages tree (pages.yml) from a
# release's downloaded assets in DL: every if_pppoe-repo-<slug>.tar.gz
# (<ABI>/ + client-conf/), plus kernels.json, compat.json, coverage.json.
# Layout: SITE/<ABI>/ per ABI, one SITE/client-conf/ (it must be identical in
# every tarball: one key, one url <base>/${ABI}), the three JSON files, and
# index.html.
set -euo pipefail

dl=${1:?usage: pages-site.sh DL SITE TAG}
site=${2:?usage: pages-site.sh DL SITE TAG}
tag=${3:?usage: pages-site.sh DL SITE TAG}
err() { echo "::error::$*" >&2; exit 1; }
html() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

mkdir -p "$site"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

shopt -s nullglob
archives=("$dl"/if_pppoe-repo-*.tar.gz)
[ "${#archives[@]}" -gt 0 ] || err "$tag has no if_pppoe-repo-*.tar.gz asset"
abis=()
for a in "${archives[@]}"; do
	x="$work/$(basename "$a" .tar.gz)"
	mkdir -p "$x"
	tar -xzf "$a" -C "$x"
	[ -d "$x/client-conf" ] || err "$(basename "$a") has no client-conf/"
	if [ -d "$site/client-conf" ]; then
		diff -r "$site/client-conf" "$x/client-conf" >/dev/null \
			|| err "$(basename "$a"): client-conf/ differs from another ABI's (key or URL mismatch)"
	else
		cp -R "$x/client-conf" "$site/client-conf"
	fi
	found=0
	for d in "$x"/FreeBSD:*/; do
		abi=$(basename "$d")
		[ ! -e "$site/$abi" ] || err "ABI $abi appears in more than one repo tarball"
		cp -R "$d" "$site/$abi"
		abis+=("$abi")
		found=1
	done
	[ "$found" -eq 1 ] || err "$(basename "$a") has no FreeBSD:<major>:<arch>/ catalogue"
done

for f in kernels.json compat.json coverage.json; do
	if [ -f "$dl/$f" ]; then cp "$dl/$f" "$site/$f"; else echo "::warning::$tag has no $f asset" >&2; fi
done

{
	echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>if_pppoe package repository</title></head><body>'
	echo "<h1>if_pppoe package repository</h1><p>Signed pkg(8) repositories from release <strong>$(printf '%s' "$tag" | html)</strong>, one per FreeBSD ABI.</p><ul>"
	for abi in "${abis[@]}"; do
		e=$(printf '%s' "$abi" | html)
		echo "<li><a href=\"./$e/\">$e/</a>"
		if [ -f "$site/coverage.json" ]; then
			jq -r --arg abi "$abi" '.abis[] | select(.abi == $abi) |
				" (OPNsense \(.series | join(", ")))<br>Supported kernels: \(.covered | map(.version) | join(", "))",
				(if (.dropped | length) > 0 then "<br>Not covered (mpd5 is used): \(.dropped | map(.version) | join(", "))" else empty end)' \
				"$site/coverage.json" | html | sed 's/&lt;br&gt;/<br>/g'
		fi
		echo '</li>'
	done
	# shellcheck disable=SC2016 # ${ABI} is pkg's variable, printed literally
	echo '</ul><p>Client registration for every ABI: <a href="./client-conf/">client-conf/</a> (IfPppoe.conf with url <code>&lt;base&gt;/${ABI}</code>, fingerprint, public key). Kernel list: <a href="./kernels.json">kernels.json</a>; smoke results: <a href="./compat.json">compat.json</a>. See docs/plugin/INSTALL.md.</p></body></html>'
} > "$site/index.html"
find "$site" -maxdepth 2 | LC_ALL=C sort
