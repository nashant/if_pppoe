#!/bin/sh
# Signs via `pkg repo <dir> signing_command:` (paired with client
# SIGNATURE_TYPE FINGERPRINTS), not local `rsa:<keyfile>`; see README.md.
# The catalogue is written flat into --repo-dir. Published repos are one per
# FreeBSD ABI (<base>/<ABI>/, client URL <base>/${ABI}), so CI passes a
# --repo-dir that already ends in the ABI (.github/scripts/freebsd-build.sh)
# and publish-repo.sh appends --abi for a manual publish.
set -eu

usage() {
	cat <<'EOF' >&2
usage: make-repo.sh --repo-dir DIR --key KEYFILE [--pub PUBFILE] [--out-dir DIR]
       make-repo.sh --gen-key --key KEYFILE [--pub PUBFILE]

  --gen-key           generate a 2048-bit RSA keypair at --key / --pub and exit
                       (openssl genrsa + openssl rsa -pubout, per pkg-repo(8))
  --repo-dir DIR       directory tree containing the .pkg files to catalogue
                       (searched recursively by `pkg repo`; also where the
                       catalogue files are written unless --out-dir is given)
  --key KEYFILE        RSA private key PEM (must exist; never copied into
                       --repo-dir or this git checkout)
  --pub PUBFILE        RSA public key PEM (default: KEYFILE with .key -> .pub,
                       or KEYFILE.pub)
  --out-dir DIR        write the catalogue here instead of --repo-dir
EOF
	exit 1
}

GEN_KEY=0
REPO_DIR=
KEY=
PUB=
OUT_DIR=

while [ $# -gt 0 ]; do
	case "$1" in
	--gen-key) GEN_KEY=1 ;;
	--repo-dir) shift; REPO_DIR=${1:?} ;;
	--key) shift; KEY=${1:?} ;;
	--pub) shift; PUB=${1:?} ;;
	--out-dir) shift; OUT_DIR=${1:?} ;;
	-h|--help) usage ;;
	*) echo "make-repo.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

[ -n "$KEY" ] || usage
[ -n "$PUB" ] || PUB=$(printf '%s' "$KEY" | sed 's/\.key$/.pub/')
[ "$PUB" != "$KEY" ] || PUB="$KEY.pub"

if [ "$GEN_KEY" -eq 1 ]; then
	[ ! -e "$KEY" ] || { echo "make-repo.sh: $KEY already exists, refusing to overwrite" >&2; exit 1; }
	umask 077
	openssl genrsa -out "$KEY" 2048
	chmod 0400 "$KEY"
	openssl rsa -in "$KEY" -out "$PUB" -pubout
	echo "make-repo.sh: wrote $KEY (0400) and $PUB"
	exit 0
fi

[ -n "$REPO_DIR" ] || usage
[ -f "$KEY" ] || { echo "make-repo.sh: key not found: $KEY" >&2; exit 1; }
[ -f "$PUB" ] || { echo "make-repo.sh: public key not found: $PUB (pass --pub or --gen-key first)" >&2; exit 1; }
[ -d "$REPO_DIR" ] || { echo "make-repo.sh: repo dir not found: $REPO_DIR" >&2; exit 1; }
command -v pkg >/dev/null 2>&1 || { echo "make-repo.sh: pkg(8) not found; this must run on a FreeBSD host with pkg installed" >&2; exit 1; }

SIGN_CMD_SCRIPT=$(mktemp)
trap 'rm -f "$SIGN_CMD_SCRIPT"' EXIT
# Local signer: reads the SHA256 pkg feeds on stdin and emits pkg-repo(8)'s
# SIGNATURE/CERT text format (swap for a remote signing host if needed).
# $KEY/$PUB go through the environment, not interpolated into the heredoc,
# so a path containing a single quote can't break out of it / inject shell.
export IF_PPPOE_SIGN_KEY="$KEY"
export IF_PPPOE_SIGN_PUB="$PUB"
cat > "$SIGN_CMD_SCRIPT" <<'EOF'
#!/bin/sh
set -eu
read -r sum
[ -n "$sum" ] || exit 1
echo SIGNATURE
printf '%s' "$sum" | openssl dgst -sign "$IF_PPPOE_SIGN_KEY" -sha256 -binary
echo
echo CERT
cat "$IF_PPPOE_SIGN_PUB"
echo END
EOF
chmod +x "$SIGN_CMD_SCRIPT"

OUT_ARGS=""
[ -z "$OUT_DIR" ] || OUT_ARGS="-o $OUT_DIR"

# shellcheck disable=SC2086 # OUT_ARGS is intentionally word-split (0 or 2 tokens)
pkg repo $OUT_ARGS "$REPO_DIR" signing_command: "$SIGN_CMD_SCRIPT"

echo "make-repo.sh: repo catalogue written under ${OUT_DIR:-$REPO_DIR}"
echo "make-repo.sh: run gen-repo-conf.sh with --pub $PUB to produce the client fingerprint + repo .conf"
