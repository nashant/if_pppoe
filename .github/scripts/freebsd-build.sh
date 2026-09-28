#!/bin/sh
# freebsd-build.sh --phase kmods|package -- runs INSIDE the FreeBSD VM
# (vmactions/freebsd-vm) from the repo root, for ONE FreeBSD ABI (all its
# OPNsense series). A thin wrapper over plugin/build/build-all.sh's
# kernels-json mode, so CI and local builds share one path; docs/CI.md.
#   kmods    userland (-Werror) into $OUT_DIR/bin, and a .ko for every
#            kernel of FREEBSD_ABI in KERNELS_JSON into $OUT_DIR/ko/<bid>/,
#            plus build-info.json
#   package  if-pppoe-kmod (the .kos in $OUT_DIR/ko listed in
#            PASS_BUILD_IDS, when set) + os-if-pppoe, and with
#            IF_PPPOE_REPO_SIGNING_KEY_FILE the signed repo tarball
#            repo-<ABI_SLUG>.tar.gz (<ABI>/ + client-conf/)
set -eu

PHASE=
case "${1:-}" in
--phase) PHASE=${2:-} ;;
esac
case "$PHASE" in
kmods|package) ;;
*) echo "usage: freebsd-build.sh --phase kmods|package" >&2; exit 1 ;;
esac

require() {
	for v; do
		eval "val=\${$v:-}"
		[ -n "$val" ] || { echo "freebsd-build.sh: $v is not set" >&2; exit 1; }
	done
}
require FREEBSD_VERSION FREEBSD_ABI KERNELS_JSON KERNCONF OPNSENSE_SERIES \
	PHP_VERSION PYTHON_VERSION

REPO_ROOT=$(pwd)
[ -f sys/modules/if_pppoe/Makefile ] || { echo "freebsd-build.sh: run from the repo root" >&2; exit 1; }
[ -f "$KERNELS_JSON" ] || { echo "freebsd-build.sh: KERNELS_JSON=$KERNELS_JSON not found" >&2; exit 1; }
KERNELS_JSON=$(cd "$(dirname "$KERNELS_JSON")" && pwd)/$(basename "$KERNELS_JSON")

ABI_SLUG=$(printf '%s' "$FREEBSD_ABI" | tr ':' '-')
KMOD_VERSION=${KMOD_VERSION:-0.0.0.ci}
OUT_DIR=${OUT_DIR:-$REPO_ROOT/out/$ABI_SLUG}
CACHE_DIR=${CACHE_DIR:-$REPO_ROOT/.ci-cache}
WORK=${WORK:-/var/tmp/if_pppoe-ci}
# Outside the rsync'd workspace: copyback must not haul src clones back.
export BUILD_ALL_WORK="$WORK/build-all"

T0=$(date +%s)
TIMINGS=""
step() {
	now=$(date +%s)
	[ -z "${_step:-}" ] || TIMINGS="$TIMINGS\"$_step\":$((now - _t)),"
	_step=$1
	_t=$now
	echo "::group::$1"
}
endgroup() { echo "::endgroup::"; }
timings() {
	now=$(date +%s)
	TIMINGS="$TIMINGS\"$_step\":$((now - _t)),\"total\":$((now - T0))"
	echo "{$TIMINGS}"
}

mkdir -p "$WORK" "$OUT_DIR" "$CACHE_DIR"

phase_kmods() {
	step "userland"
	UOBJ="$WORK/uobj"
	rm -rf "$UOBJ"
	mkdir -p "$UOBJ" "$OUT_DIR/bin"
	for d in sbin/pppoectl tools/pppoeparms tools/spppauth tools/spppioctl tools/spppkeepalive; do
		[ -f "$d/Makefile" ] || continue
		# WARNS in each Makefile already turns on -Werror (bsd.sys.mk).
		env MAKEOBJDIRPREFIX="$UOBJ" make -C "$d" obj
		env MAKEOBJDIRPREFIX="$UOBJ" make -C "$d"
		prog=$(env MAKEOBJDIRPREFIX="$UOBJ" make -C "$d" -V PROG)
		cp "$(env MAKEOBJDIRPREFIX="$UOBJ" make -C "$d" -V .OBJDIR)/$prog" "$OUT_DIR/bin/$prog"
	done
	ls -la "$OUT_DIR/bin"
	endgroup

	step "kernel modules ($FREEBSD_ABI)"
	sh plugin/build/build-all.sh --kernels-json "$KERNELS_JSON" --abi "$FREEBSD_ABI" \
		--phase kmods --version "$KMOD_VERSION" --kernconf "$KERNCONF" \
		--cache "$CACHE_DIR" --out "$OUT_DIR"
	# Keep only this run's kernel build dirs in the actions cache, and no
	# kernel sets (each kbuild tarball already holds its kernel).
	keep=$(jq -r --arg kc "$KERNCONF" '[.[].built_from] | unique | .[] | "kbuild-\(.)-\($kc).tar.gz"' "$OUT_DIR/kmods.json")
	for f in "$CACHE_DIR"/kbuild-*.tar.gz; do
		[ -e "$f" ] || continue
		echo "$keep" | grep -qxF "$(basename "$f")" || { echo "cache: pruning $(basename "$f")"; rm -f "$f"; }
	done
	rm -rf "$CACHE_DIR/sets"
	endgroup

	step "build-info"
	jq -n --arg abi "$FREEBSD_ABI" --arg slug "$ABI_SLUG" --arg fv "$FREEBSD_VERSION" \
		--arg series "$OPNSENSE_SERIES" --arg kc "$KERNCONF" --arg kv "$KMOD_VERSION" \
		--arg src "${KMOD_SRC_ID:-}" --arg host "$(uname -r)" \
		--slurpfile kernels "$OUT_DIR/kmods.json" --argjson t "$(timings)" \
		'{freebsd_abi: $abi, abi_slug: $slug, freebsd_version: $fv,
		  opnsense_series: ($series | split(" ")), kernconf: $kc, kmod_version: $kv,
		  kmod_src: $src, kernels: $kernels[0], host: $host, timings_s: $t}' \
		> "$OUT_DIR/build-info.json"
	cat "$OUT_DIR/build-info.json"
	endgroup
}

phase_package() {
	step "packages ($FREEBSD_ABI)"
	[ -d "$OUT_DIR/ko" ] || { echo "freebsd-build.sh: $OUT_DIR/ko missing (download the kmods artifact there)" >&2; exit 1; }
	# One os-if-pppoe per ABI: every series of it, lowest first (its
	# product_abi); PHP/Python are the lowest series' (matrix.sh abi).
	PLUGIN_ABIS="$OPNSENSE_SERIES"
	PLUGIN_PHP=$(printf '%s' "$PHP_VERSION" | tr -d .)
	PLUGIN_PYTHON=$(printf '%s' "$PYTHON_VERSION" | tr -d .)
	export PLUGIN_ABIS PLUGIN_PHP PLUGIN_PYTHON
	set -- --kernels-json "$KERNELS_JSON" --abi "$FREEBSD_ABI" --phase package \
		--version "$KMOD_VERSION" --out "$OUT_DIR"
	[ -z "${PASS_BUILD_IDS:-}" ] || set -- "$@" --pass-build-ids "$PASS_BUILD_IDS"
	[ -z "${PLUGIN_REVISION:-}" ] || set -- "$@" --plugin-revision "$PLUGIN_REVISION"
	sh plugin/build/build-all.sh "$@"
	# The flat repo build-all.sh made is unsigned: not a CI deliverable.
	rm -f "$OUT_DIR/repo.tar.gz"
	for p in "$OUT_DIR"/pkg/*.pkg; do
		echo "== $p"
		pkg info -F "$p" | sed -n '1,12p'
		pkg query -F "$p" '%Fp' | sed 's/^/  /'
	done
	endgroup

	# The key arrives as a file (build.yml writes it into the synced
	# workspace): a multi-line PEM does not survive a VM env var.
	if [ -n "${IF_PPPOE_REPO_SIGNING_KEY_FILE:-}" ]; then
		step "signed repo"
		: "${IF_PPPOE_REPO_URL_BASE:?set IF_PPPOE_REPO_URL_BASE (repo variable) for the client repo URL}"
		keydir=$(mktemp -d)
		trap 'rm -rf "$keydir"' EXIT
		(umask 077 && cp "$IF_PPPOE_REPO_SIGNING_KEY_FILE" "$keydir/repo.key")
		rm -f "$IF_PPPOE_REPO_SIGNING_KEY_FILE"
		openssl rsa -in "$keydir/repo.key" -pubout -out "$keydir/repo.pub" 2>/dev/null
		REPO_DIR="$WORK/repo/$FREEBSD_ABI"
		rm -rf "$WORK/repo"
		mkdir -p "$REPO_DIR"
		cp "$OUT_DIR"/pkg/*.pkg "$REPO_DIR/"
		sh plugin/build/make-repo.sh --repo-dir "$REPO_DIR" --key "$keydir/repo.key" --pub "$keydir/repo.pub"
		# One URL for every series and ABI: pkg expands ${ABI} on the
		# client, so 25.7 -> 26.1 keeps the repo and 26.7 switches to
		# FreeBSD:15:amd64/ by itself. Keep it literal here.
		# shellcheck disable=SC2016
		sh plugin/build/gen-repo-conf.sh --url "${IF_PPPOE_REPO_URL_BASE%/}"'/${ABI}' \
			--pub "$keydir/repo.pub" --out-dir "$WORK/repo/client-conf"
		cp "$keydir/repo.pub" "$WORK/repo/client-conf/IfPppoe.pub"
		tar -czf "$OUT_DIR/repo-$ABI_SLUG.tar.gz" -C "$WORK/repo" .
		rm -rf "$keydir"
		trap - EXIT
		endgroup
	fi

	step "build-info"
	[ -s "$OUT_DIR/build-info.json" ] || echo '{}' > "$OUT_DIR/build-info.json"
	jq --arg kv "$KMOD_VERSION" --arg pr "${PLUGIN_REVISION:-}" \
		--slurpfile shipped "$OUT_DIR/kernels-shipped.json" \
		--rawfile dropped "$OUT_DIR/dropped-build-ids.txt" \
		--arg pkgs "$(find "$OUT_DIR/pkg" -name '*.pkg' -exec basename {} \; | sort)" \
		--argjson t "$(timings)" \
		'. + {kmod_version: $kv, plugin_revision: $pr,
		      packaged: [$shipped[0][] | {build_id, version}],
		      dropped: ($dropped | split("\n") | map(select(length > 0) | split(" ") | {build_id: .[0], version: .[1]})),
		      packages: ($pkgs | split("\n") | map(select(length > 0))),
		      package_timings_s: $t}' \
		"$OUT_DIR/build-info.json" > "$OUT_DIR/build-info.json.new"
	mv "$OUT_DIR/build-info.json.new" "$OUT_DIR/build-info.json"
	cat "$OUT_DIR/build-info.json"
	endgroup
}

case "$PHASE" in
kmods) phase_kmods ;;
package) phase_package ;;
esac
