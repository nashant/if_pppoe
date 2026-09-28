#!/bin/sh
# rsync a built repo dir to the HTTP-served directory on the publish host
# (web server assumed, not verified here -- see docs/plugin/INSTALL.md).
#
# Repos are published one per FreeBSD ABI: clients register the URL with
# pkg's literal ${ABI} substitution (<base>/${ABI}), and the same catalogue
# serves every OPNsense series of that ABI (25.7 and 26.1 on FreeBSD:14:amd64,
# 26.7 on FreeBSD:15:amd64). make-repo.sh's catalogue is flat, so this
# publishes it under <remote-dir>/<ABI>. --abi is required (the package set
# is ABI-specific; there is no safe default), unless --no-abi-subdir says
# --remote-dir already ends in the ABI segment.
set -eu

HOST=${PUBLISH_HOST:-}
ABI=
ABI_SUBDIR=1
REMOTE_DIR=

usage() {
	echo "usage: PUBLISH_HOST=host publish-repo.sh --repo-dir DIR --remote-dir DIR (--abi ABI | --no-abi-subdir) [--host HOST]" >&2
	exit 1
}

REPO_DIR=

while [ $# -gt 0 ]; do
	case "$1" in
	--repo-dir) shift; REPO_DIR=${1:?} ;;
	--remote-dir) shift; REMOTE_DIR=${1:?} ;;
	--host) shift; HOST=${1:?} ;;
	--abi) shift; ABI=${1:?} ;;
	--no-abi-subdir) ABI_SUBDIR=0 ;;
	-h|--help) usage ;;
	*) echo "publish-repo.sh: unknown argument: $1" >&2; usage ;;
	esac
	shift
done

{ [ -n "$REPO_DIR" ] && [ -n "$REMOTE_DIR" ]; } || usage
[ -n "$HOST" ] || { echo "publish-repo.sh: no host set: pass --host or set PUBLISH_HOST" >&2; usage; }
if [ "$ABI_SUBDIR" -eq 1 ]; then
	[ -n "$ABI" ] || { echo "publish-repo.sh: pass --abi (e.g. FreeBSD:14:amd64 for OPNsense 25.7/26.1, FreeBSD:15:amd64 for 26.7)" >&2; usage; }
	case "$ABI" in
	FreeBSD:[0-9]*:*) ;;
	*) echo "publish-repo.sh: --abi must look like FreeBSD:<major>:<arch>, got: $ABI" >&2; exit 1 ;;
	esac
fi
[ -d "$REPO_DIR" ] || { echo "publish-repo.sh: repo dir not found: $REPO_DIR" >&2; exit 1; }
command -v rsync >/dev/null 2>&1 || { echo "publish-repo.sh: rsync not found locally" >&2; exit 1; }

TARGET_DIR=$REMOTE_DIR
[ "$ABI_SUBDIR" -eq 0 ] || TARGET_DIR="$REMOTE_DIR/$ABI"

rsync -avz --delete "$REPO_DIR"/ "$HOST:$TARGET_DIR"/
echo "publish-repo.sh: published to $HOST:$TARGET_DIR"
echo "publish-repo.sh: this must equal the ABI-substituted form of the --url"
echo "                 given to gen-repo-conf.sh, e.g. for"
echo "                 http://$HOST/<web-path>/\${ABI} with ABI=${ABI:-<ABI>} that's:"
echo "                 http://$HOST/<web-path>/${ABI:-<ABI>}"
echo "publish-repo.sh: verify it's actually served over HTTP there, e.g.:"
echo "    curl -fsS http://$HOST/<web-path>/${ABI:-<ABI>}/meta.conf"
