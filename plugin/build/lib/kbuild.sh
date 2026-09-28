# shellcheck shell=sh
# Sourced by discover-kernels.sh, build-all.sh and freebsd-build.sh. Kernel
# facts are read identically on Linux and FreeBSD so config_hash agrees.

kb_log() { echo "$*" >&2; }

# kb_sha256 FILE -- hex sha256 of FILE.
kb_sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		sha256 -q "$1"
	fi
}

# kb_sha256_stdin -- hex sha256 of stdin.
kb_sha256_stdin() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | awk '{print $1}'
	else
		sha256 -q
	fi
}

# kb_fetch URL OUT -- download URL to OUT (curl, else fetch(1)). file://
# URLs work with both, which is what the offline tests use.
kb_fetch() {
	rm -f "$2.part"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2.part" "$1" || { rm -f "$2.part"; return 1; }
	elif command -v fetch >/dev/null 2>&1; then
		fetch -q -o "$2.part" "$1" || { rm -f "$2.part"; return 1; }
	else
		kb_log "kbuild: neither curl nor fetch(1) found"
		return 1
	fi
	mv "$2.part" "$2"
}

# kb_list_dir URL -- print the file names an Apache-style autoindex at URL
# links to (href="name"), one per line. A file:// URL naming a local
# directory is listed with ls instead (offline tests, local mirrors).
kb_list_dir() {
	case "$1" in
	file://*)
		_ld=${1#file://}
		if [ -d "$_ld" ]; then
			ls -1 "$_ld"
			return 0
		fi
		;;
	esac
	_l=$(mktemp)
	if ! kb_fetch "$1" "$_l"; then
		rm -f "$_l"
		kb_log "kbuild: could not fetch listing $1"
		return 1
	fi
	grep -oE 'href="[^"?/][^"]*"' "$_l" | sed -e 's/^href="//' -e 's/"$//'
	rm -f "$_l"
}

# kb_build_id KERNEL -- lowercase hex of the GNU build-id ELF note
# (what `sysctl kern.build_id` reports for that kernel, see
# plugin/kmod/if-pppoe-kmod/README.md "BUILD_ID").
kb_build_id() {
	if command -v readelf >/dev/null 2>&1; then
		readelf -n "$1" 2>/dev/null | awk '/Build ID:/{print tolower($NF); exit}'
	elif command -v elfdump >/dev/null 2>&1; then
		elfdump -n "$1" 2>/dev/null | awk '/Build ID:/{print tolower($NF); exit}'
	fi
}

# kb_kernel_version KERNEL -- "FreeBSD 14.3-RELEASE-p4" style string the
# kernel carries (same grep freebsd-build.sh always used).
kb_kernel_version() {
	strings "$1" | grep -m 1 -oE 'FreeBSD [0-9]+\.[0-9]+-[A-Za-z0-9.-]+' || true
}

# kb_extract_kernel TXZ OUT -- write the set's boot/kernel/kernel to OUT.
kb_extract_kernel() {
	if tar --version 2>/dev/null | grep -q 'GNU tar'; then
		tar -xOf "$1" --wildcards '*boot/kernel/kernel' > "$2" 2>/dev/null || true
	else
		tar -xOf "$1" --include '*boot/kernel/kernel' > "$2" 2>/dev/null || true
	fi
	[ -s "$2" ] || { kb_log "kbuild: $1 has no boot/kernel/kernel"; return 1; }
}

# kb_extract_config KERNEL OUT -- INCLUDE_CONFIG_FILE text (ELF section
# kern_conf, what config -x reads). objcopy first so Linux and FreeBSD
# extract identical bytes; config -x as fallback. NULs and "___" dropped.
kb_extract_config() {
	: > "$2"
	_raw=$(mktemp)
	if command -v objcopy >/dev/null 2>&1 &&
		objcopy -O binary --only-section=kern_conf "$1" "$_raw" 2>/dev/null && [ -s "$_raw" ]; then
		:
	elif command -v config >/dev/null 2>&1 && config -x "$1" > "$_raw" 2>/dev/null && [ -s "$_raw" ]; then
		:
	else
		rm -f "$_raw"
		kb_log "kbuild: no embedded config (kern_conf section) in $1"
		return 1
	fi
	tr -d '\000' < "$_raw" | sed 's/^___//' > "$2"
	rm -f "$_raw"
	[ -s "$2" ] || { kb_log "kbuild: embedded config of $1 is empty"; return 1; }
}

# kb_normalise_config FILE -- the normal form config_hash is taken over
# (docs/CI.md "Kernel discovery"): tag stripped, comments/blank lines/
# `ident`/`makeoptions DEBUG*` dropped, whitespace collapsed, LC_ALL=C
# sort -u. Order-insensitive on purpose: only the option SET matters.
kb_normalise_config() {
	sed -e 's/^___//' -e 's/#.*$//' -e 's/[[:space:]][[:space:]]*/ /g' \
		-e 's/^ //' -e 's/ $//' "$1" |
		grep -vE '^$|^ident( |$)|^makeoptions DEBUG' |
		LC_ALL=C sort -u
}

# kb_config_hash FILE -- sha256 of kb_normalise_config FILE. Refuses an
# empty normal form (no silent "everything shares one config" grouping).
kb_config_hash() {
	_n=$(mktemp)
	kb_normalise_config "$1" > "$_n"
	if [ ! -s "$_n" ]; then
		rm -f "$_n"
		kb_log "kbuild: normalised config of $1 is empty"
		return 1
	fi
	kb_sha256 "$_n"
	rm -f "$_n"
}

# kb_version_key VERSION -- a sort -V-free sortable key ("25.7.11" ->
# "00025.00007.00011"), for hosts whose sort lacks -V.
kb_version_key() {
	echo "$1" | tr '._' '  ' | awk '{ for (i = 1; i <= NF; i++) printf "%s%05d", (i > 1 ? "." : ""), $i; print "" }'
}

# kb_get_set URL SHA256 CACHE_DIR -- path of the set (CACHE_DIR/sets/<sha>.txz),
# downloaded if needed; a missing set or sha mismatch fails (never guess).
kb_get_set() {
	mkdir -p "$3/sets"
	_f="$3/sets/$2.txz"
	if [ -s "$_f" ] && [ "$(kb_sha256 "$_f")" = "$2" ]; then
		echo "$_f"
		return 0
	fi
	kb_fetch "$1" "$_f.dl" || { kb_log "kbuild: could not download $1 (removed from the mirror?)"; return 1; }
	_got=$(kb_sha256 "$_f.dl")
	if [ "$_got" != "$2" ]; then
		rm -f "$_f.dl"
		kb_log "kbuild: $1 has sha256 $_got, kernels.json recorded $2 -- rerun discovery"
		return 1
	fi
	mv "$_f.dl" "$_f"
	echo "$_f"
}

# kb_opt_crosscheck KBD SRC_SYS CONF LABEL -- config -d CONF and cmp opt_*.h
# with KBD's. 0 match, 1 mismatch, 2 CONF not loadable by config(8) (warn).
kb_opt_crosscheck() {
	_oc_kbd=$1 _oc_sys=$2 _oc_conf=$3 _oc_label=$4
	_oc_tmp=$(mktemp -d)
	_oc_name="CI_EMBEDDED_$$"
	cp "$_oc_conf" "$_oc_sys/amd64/conf/$_oc_name"
	if ! (cd "$_oc_sys/amd64/conf" && config -d "$_oc_tmp/kbd" "$_oc_name") > "$_oc_tmp/config.log" 2>&1; then
		sed -n '1,20p' "$_oc_tmp/config.log" >&2
		rm -rf "$_oc_tmp" "$_oc_sys/amd64/conf/$_oc_name"
		return 2
	fi
	rm -f "$_oc_sys/amd64/conf/$_oc_name"
	_oc_bad=""
	{ (cd "$_oc_kbd" && ls opt_*.h); (cd "$_oc_tmp/kbd" && ls opt_*.h); } | sort -u > "$_oc_tmp/names"
	while IFS= read -r _oc_h; do
		cmp -s "$_oc_kbd/$_oc_h" "$_oc_tmp/kbd/$_oc_h" || _oc_bad="$_oc_bad $_oc_h"
	done < "$_oc_tmp/names"
	if [ -n "$_oc_bad" ]; then
		kb_log "kbuild: $_oc_label: opt headers differ from $_oc_kbd:$_oc_bad"
		for _oc_h in $_oc_bad; do diff -u "$_oc_kbd/$_oc_h" "$_oc_tmp/kbd/$_oc_h" >&2 || true; done
		rm -rf "$_oc_tmp"
		return 1
	fi
	rm -rf "$_oc_tmp"
	return 0
}

# kb_prepare TAG SERIES KERNCONF SET_URL SET_SHA BUILD_ID ROOT CACHE_DIR --
# config -d-only kernel build dir for opnsense/src@TAG (docs/CI.md "Kernel
# build dir"), cached as kbuild-TAG-KERNCONF.tar.gz. Sets KB_SRC, KB_KBD.
kb_prepare() {
	_tag=$1 _series=$2 _kc=$3 _url=$4 _sha=$5 _bid=$6 _root=$7 _cache=$8
	_name="kbuild-$_tag-$_kc"
	_tar="$_cache/$_name.tar.gz"
	KB_SRC="$_root/$_name/src"
	KB_KBD="$_root/$_name/kbuild/$_kc"
	_srcrepo=${SRC_REPO:-https://github.com/opnsense/src}
	_tools=${TOOLS_RAW:-https://raw.githubusercontent.com/opnsense/tools}
	mkdir -p "$_cache" "$_root"
	rm -rf "${_root:?}/$_name"
	if [ -f "$_tar" ]; then
		kb_log "kbuild: cache hit $_tar"
		mkdir -p "$_root/$_name"
		tar -xzf "$_tar" -C "$_root/$_name" || return 1
	else
		kb_log "kbuild: preparing $_name"
		mkdir -p "$_root/$_name"
		# Blobless, depth-1, sparse: only sys/ is materialised.
		git clone --quiet --depth 1 --filter=blob:none --sparse \
			--branch "$_tag" "$_srcrepo" "$KB_SRC" || return 1
		git -C "$KB_SRC" sparse-checkout set sys || return 1
		git -C "$KB_SRC" log -1 --format='opnsense/src %H %cI' >&2

		# kernel-<tag> is built from opnsense/tools@<tag>; tools has no
		# tag for every kernel patch, so fall back to TOOLS_FALLBACK_REF
		# (default master) -- the cross-check below catches a config
		# that does not match the published kernel.
		_cf="$_root/$_name/$_kc.conf"
		if ! kb_fetch "$_tools/$_tag/config/$_series/$_kc" "$_cf"; then
			_fb=${TOOLS_FALLBACK_REF:-master}
			kb_log "kbuild: opnsense/tools has no $_tag tag; using $_fb for config/$_series/$_kc"
			echo "::warning::opnsense/tools has no $_tag tag; using $_fb for config/$_series/$_kc"
			kb_fetch "$_tools/$_fb/config/$_series/$_kc" "$_cf" || return 1
		fi
		sed '/%%DEBUG%%/d' "$_cf" > "$KB_SRC/sys/amd64/conf/$_kc"
		mkdir -p "$KB_KBD"
		(cd "$KB_SRC/sys/amd64/conf" && config -d "$KB_KBD" "$_kc") >&2 || return 1

		_set=$(kb_get_set "$_url" "$_sha" "$_cache") || return 1
		kb_extract_kernel "$_set" "$KB_KBD/kernel" || return 1

		_emb="$_root/$_name/embedded.conf"
		if kb_extract_config "$KB_KBD/kernel" "$_emb"; then
			_rc=0
			kb_opt_crosscheck "$KB_KBD" "$KB_SRC/sys" "$_emb" "kernel-$_tag" || _rc=$?
			case $_rc in
			0) kb_log "opt_*.h match the published kernel's embedded config ($_tag)" ;;
			1) kb_log "kbuild: opt headers from the tools config differ from kernel-$_tag's embedded config"; return 1 ;;
			*) echo "::warning::kernel-$_tag: embedded config not usable by config -d; opt_*.h not cross-checked" ;;
			esac
		else
			echo "::warning::kernel-$_tag: no embedded config; opt_*.h not cross-checked"
		fi
		tar -czf "$_tar" -C "$_root/$_name" src kbuild || return 1
	fi
	for _h in opt_global.h opt_inet.h opt_inet6.h opt_rss.h; do
		[ -f "$KB_KBD/$_h" ] || { kb_log "kbuild: config(8) did not produce $KB_KBD/$_h"; return 1; }
	done
	grep -q '^#define RSS 1' "$KB_KBD/opt_rss.h" ||
		{ kb_log "kbuild: $_kc has no 'options RSS' -- wrong config?"; return 1; }
	_got=$(kb_build_id "$KB_KBD/kernel")
	[ "$_got" = "$_bid" ] ||
		{ kb_log "kbuild: $KB_KBD/kernel has build-id '$_got', kernels.json says $_bid"; return 1; }
}

# kb_module_headers OBJDIR SRC -- SRC-relative headers the build in OBJDIR
# included (.depend.*). Empty output means "unknown", not "none".
kb_module_headers() {
	_od=$1
	_sr=$(cd "$2" && pwd -P)
	find "$_od" -maxdepth 1 -name '.depend*' -type f 2>/dev/null | while IFS= read -r _d; do
		tr -s ' \134' '\n' < "$_d"
	done | sed 's/:$//' | grep '\.h$' | sort -u | while IFS= read -r _p; do
		case "$_p" in
		/*) _abs=$_p ;;
		*) _abs="$_od/$_p" ;;
		esac
		_dir=$(cd "$(dirname "$_abs")" 2>/dev/null && pwd -P) || continue
		_rp="$_dir/$(basename "$_abs")"
		case "$_rp" in "$_sr"/*) echo "${_rp#"$_sr"/}" ;; esac
	done | sort -u
}

# kb_header_drift SRC OTHER_TAG HEADERS_FILE -- print the headers listed in
# HEADERS_FILE that differ between SRC's checked-out tag (HEAD) and
# OTHER_TAG (tree-only fetch into SRC; blob contents are never needed to
# compare object ids). Non-zero on fetch failure.
kb_header_drift() {
	git -C "$1" fetch --quiet --depth 1 --filter=blob:none origin \
		"+refs/tags/$2:refs/tags/$2" >&2 || return 1
	# shellcheck disable=SC2046 # one pathspec per header line
	git -C "$1" diff --name-only --no-renames HEAD "refs/tags/$2" -- $(cat "$3")
}
