#!/bin/sh
# Generate the one-time client registration for the repo make-repo.sh built:
# /usr/local/etc/pkg/repos/IfPppoe.conf and a fingerprints/trusted/IfPppoe
# file, per pkg.conf(5) and pkg-repo(8)'s FINGERPRINTS EXAMPLES (cloned pkg
# source, docs/pkg-repo.8, commit cd0a561ecc894f3c9811004490d59a5df26c94ad).
#
# Published repos are laid out one per FreeBSD ABI, <base>/<ABI>/ (CI:
# <IF_PPPOE_REPO_URL_BASE>/FreeBSD:14:amd64/ for OPNsense 25.7 and 26.1,
# .../FreeBSD:15:amd64/ for 26.7). Pass the URL with pkg's own ${ABI}
# variable left literal (single quotes), so one IfPppoe.conf follows the box
# across series upgrades:
#
#   gen-repo-conf.sh --url 'https://<host>/if_pppoe/repo/${ABI}' --pub repo.pub
#
# pkg.conf(5) (freebsd/pkg docs/pkg.conf.5): "ABI: Expands to the ABI string
# (e.g. FreeBSD:14:amd64)". A URL ending in /<series> (e.g. /25.7) is the old
# per-series layout; it is accepted with a warning, because it would stop
# resolving after an OPNsense series upgrade.
set -eu

REPO_TAG=IfPppoe
OUT_DIR=.

usage() {
	echo "usage: gen-repo-conf.sh --url URL --pub PUBFILE [--out-dir DIR] [--tag TAG]" >&2
	exit 1
}

URL=
PUB=

while [ $# -gt 0 ]; do
	case "$1" in
	--url) shift; URL=${1:?} ;;
	--pub) shift; PUB=${1:?} ;;
	--out-dir) shift; OUT_DIR=${1:?} ;;
	--tag) shift; REPO_TAG=${1:?} ;;
	-h|--help) usage ;;
	*) echo "gen-repo-conf.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

[ -n "$URL" ] && [ -n "$PUB" ] || usage
[ -f "$PUB" ] || { echo "gen-repo-conf.sh: public key not found: $PUB" >&2; exit 1; }

# ERE: an OPNsense series segment (NN.N or NN.NN) at the end of the URL.
if printf '%s\n' "$URL" | grep -Eq '/[0-9]{2}\.[0-9]{1,2}/?$'; then
	echo "gen-repo-conf.sh: warning: --url ends in an OPNsense series ($URL);" >&2
	# shellcheck disable=SC2016 # ${ABI} is pkg's variable, shown literally
	echo '  repos are published per ABI only: use <base>/${ABI}, not <base>/${ABI}/<series>' >&2
fi

# sha256(1) is FreeBSD base; fall back to sha256sum for a dry run on Linux.
if command -v sha256 >/dev/null 2>&1; then
	SUM=$(sha256 -q "$PUB")
else
	SUM=$(sha256sum "$PUB" | awk '{print $1}')
fi

mkdir -p "$OUT_DIR/repos" "$OUT_DIR/fingerprints/$REPO_TAG/trusted"

cat > "$OUT_DIR/repos/$REPO_TAG.conf" <<EOF
$REPO_TAG: {
    url: "$URL",
    enabled: true,
    signature_type: "fingerprints",
    fingerprints: "/usr/local/etc/pkg/fingerprints/$REPO_TAG"
}
EOF

cat > "$OUT_DIR/fingerprints/$REPO_TAG/trusted/$REPO_TAG" <<EOF
function: sha256
fingerprint: "$SUM"
EOF

cat <<EOF
gen-repo-conf.sh: wrote
  $OUT_DIR/repos/$REPO_TAG.conf              -> /usr/local/etc/pkg/repos/$REPO_TAG.conf
  $OUT_DIR/fingerprints/$REPO_TAG/trusted/$REPO_TAG -> /usr/local/etc/pkg/fingerprints/$REPO_TAG/trusted/$REPO_TAG
See docs/plugin/INSTALL.md for the one-time registration steps on the box.
EOF
