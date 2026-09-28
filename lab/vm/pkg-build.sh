#!/usr/bin/env bash
# pkg-build.sh -- host-side wrapper for plugin/build/build-all.sh: syncs the
# tracked tree to the shared `build` VM (git archive for a commit-ish, or a
# live tar of a worktree's tracked files -- exactly as lab/vm/build-check.sh
# does; see its header for the -m/mtime rationale) into its OWN work dir,
# kept out of build-check.sh's and build-module.sh's (which verification
# runs use concurrently): ~/if_pppoe-lab/work-pkg/<sha>[-dirty]. It then runs
# build-all.sh there with the given arguments and fetches the produced
# repo.tar.gz and pkg/*.pkg back.
#
#   ./pkg-build.sh [--clean] [<commit-ish>|<worktree path>] [--local-out DIR] \
#       -- --target-kernel /home/freebsd/router-kernel --version 0.3 \
#          --key /home/freebsd/.if_pppoe-repo-signing.key
#
# Everything after `--` is forwarded verbatim to build-all.sh (see its
# header for --target-kernel/--version/--key/--pub). --key/--pub name paths
# ALREADY on the build VM (plugin/build/README.md: "signing key kept
# outside the repo") -- this script never uploads or downloads key
# material. They must be absolute paths on the VM (e.g.
# /home/freebsd/..., VM_SSH_USER in lab/vm/common.sh): this wrapper's own
# shell would expand a `~` against the LOCAL user's home before forwarding
# it, and quoting doesn't help, since printf %q (below) then sends that
# wrong path as a literal string over ssh instead of a `~` for the remote
# shell to expand. Omit --out in the forwarded args; this script manages
# the remote --out itself (the work dir's own out/) so it can fetch the
# result back, and appends its own --out last, which wins over anything
# forwarded.
#
# --clean wipes the remote work dir first instead of reusing it.
# --local-out DIR (this wrapper's own flag, not forwarded): where the
# fetched repo.tar.gz and pkg/ land locally (default ./pkg-build-out,
# resolved against the CALLER's cwd, not this script's own directory).
#
# LAB_HOME, PLUGIN_ABIS, PLUGIN_PHP: forwarded to the remote build-all.sh
# invocation as env overrides (its own header lists them) if set in THIS
# shell's environment -- e.g. LAB_HOME=~/if_pppoe-lab-26.1 to build for
# another series' lab-collected kernel, entirely through this wrapper.
set -euo pipefail
ORIG_PWD="$PWD"
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

REPO_ROOT="$(cd ../.. && pwd)"
SYNC_TOP_DIRS="sys sbin tools plugin"  # everything build-all.sh needs

CLEAN=0
ARG=""
LOCAL_OUT="./pkg-build-out"
BUILD_ALL_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --clean) CLEAN=1; shift ;;
        --local-out) shift; LOCAL_OUT="${1:?}"; shift ;;
        --) shift; BUILD_ALL_ARGS=("$@"); break ;;
        -*) echo "usage: $0 [--clean] [--local-out DIR] [<commit-ish>|<worktree path>] -- <build-all.sh args...>" >&2; exit 1 ;;
        *) ARG="$1"; shift ;;
    esac
done

[ "${#BUILD_ALL_ARGS[@]}" -gt 0 ] || { echo "pkg-build.sh: pass build-all.sh's own arguments after '--' (at least --target-kernel and --version)" >&2; exit 1; }

# Relative --local-out / worktree-path arguments are the CALLER's relative
# paths, not relative to this script's own directory (which we already cd'd
# into, above, to source common.sh).
case "$LOCAL_OUT" in
    /*) : ;;
    *) LOCAL_OUT="$ORIG_PWD/$LOCAL_OUT" ;;
esac
ARG_ABS=""
if [ -n "$ARG" ]; then
    case "$ARG" in
        /*) ARG_ABS="$ARG" ;;
        *) ARG_ABS="$ORIG_PWD/$ARG" ;;
    esac
fi

# --- Resolve the source: commit-ish (git archive) or worktree path (tar of
#     tracked files, read live off disk) -- same as build-check.sh. ---------
SRC_KIND=""
if [ -z "$ARG" ]; then
    SRC_KIND=worktree
    SRC_PATH="$REPO_ROOT"
elif git -C "$REPO_ROOT" rev-parse --verify --quiet "${ARG}^{commit}" >/dev/null; then
    SRC_KIND=commit
    SRC_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "${ARG}^{commit}")"
elif [ -d "$ARG_ABS" ] && git -C "$ARG_ABS" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SRC_KIND=worktree
    SRC_PATH="$(cd "$ARG_ABS" && pwd)"
else
    echo "pkg-build.sh: '$ARG' is neither a valid commit-ish in $REPO_ROOT nor an existing git worktree path" >&2
    exit 1
fi

if [ "$SRC_KIND" = commit ]; then
    SHA="$(git -C "$REPO_ROOT" rev-parse --short "$SRC_COMMIT")"
    SRC_LABEL="commit:$SRC_COMMIT${ARG:+ ($ARG)}"
else
    SHA="$(git -C "$SRC_PATH" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if ! git -C "$SRC_PATH" diff --quiet 2>/dev/null || ! git -C "$SRC_PATH" diff --cached --quiet 2>/dev/null; then
        SHA="$SHA-dirty"
    fi
    SRC_LABEL="worktree:$SRC_PATH ($SHA)"
fi

EXIST_DIRS=""
for d in $SYNC_TOP_DIRS; do
    if [ "$SRC_KIND" = commit ]; then
        if git -C "$REPO_ROOT" cat-file -e "$SRC_COMMIT:$d" 2>/dev/null; then
            EXIST_DIRS="$EXIST_DIRS $d"
        fi
    else
        if [ -d "$SRC_PATH/$d" ]; then
            EXIST_DIRS="$EXIST_DIRS $d"
        fi
    fi
done
EXIST_DIRS="${EXIST_DIRS# }"
[ -n "$EXIST_DIRS" ] || { echo "pkg-build.sh: none of ($SYNC_TOP_DIRS) exist in $SRC_LABEL" >&2; exit 1; }

echo "pkg-build.sh: source = $SRC_LABEL"

TMPTAR="$(mktemp)"
trap 'rm -f "$TMPTAR"' EXIT
case "$SRC_KIND" in
    commit)
        git -C "$REPO_ROOT" archive --format=tar "$SRC_COMMIT" -- $EXIST_DIRS > "$TMPTAR"
        ;;
    worktree)
        ( cd "$SRC_PATH" && git ls-files -z -- $EXIST_DIRS ) | tar -C "$SRC_PATH" --null -T - -cf "$TMPTAR"
        ;;
esac

WORK='$HOME/if_pppoe-lab/work-pkg/'"$SHA"
if [ "$CLEAN" = 1 ]; then
    vm_ssh build "rm -rf $WORK"
fi
vm_ssh build "mkdir -p $WORK"
# -m: force "now" mtimes -- a commit's archive carries the commit's own
# timestamp (not monotonic across arbitrary shas), which could otherwise
# leave a .o looking newer than a source file from a later build here.
vm_ssh build "tar -C $WORK -xmf -" < "$TMPTAR"
echo "pkg-build.sh: synced to build:$WORK"

REMOTE_OUT="$WORK/out"
REMOTE_ARGS=""
for a in "${BUILD_ALL_ARGS[@]}"; do
    REMOTE_ARGS="$REMOTE_ARGS $(printf '%q' "$a")"
done

REMOTE_ENV=""
for v in LAB_HOME PLUGIN_ABIS PLUGIN_PHP; do
    if [ -n "${!v:-}" ]; then
        REMOTE_ENV="$REMOTE_ENV $v=$(printf '%q' "${!v}")"
    fi
done

echo "pkg-build.sh: running build-all.sh on build:$WORK"
vm_ssh build "cd $WORK &&$REMOTE_ENV sh plugin/build/build-all.sh$REMOTE_ARGS --out $REMOTE_OUT"

mkdir -p "$LOCAL_OUT"
vm_ssh build "tar -C $REMOTE_OUT -cf - ." | tar -C "$LOCAL_OUT" -xf -
echo "pkg-build.sh: fetched build output to $LOCAL_OUT/ (repo.tar.gz, pkg/*.pkg)"
ls -la "$LOCAL_OUT"
