#!/usr/bin/env bash
# build-check.sh [--clean] [<commit-ish>|<worktree path>] — fast compile-only
# lane on the shared `build` VM: no lab slot needed, no client/isp/mpdsrv VM
# touched. Builds the if_pppoe kmod against both collected kernel variants
# (SMP, SMPW), plus the PPPOE_TEST_REFLECT variant when the synced Makefile
# defines it, plus sbin/pppoectl and tools/* — PASS/FAIL per target, compiler
# output verbatim on failure.
#
#   ./build-check.sh                  # this worktree's tracked files, live
#                                      # off disk (so local edits are included)
#   ./build-check.sh <commit-ish>     # `git archive` that commit
#   ./build-check.sh /path/to/wt      # another worktree, same as above
#   ./build-check.sh --clean [...]    # force a full rebuild (wipe first)
#
# BUILD_CHECK_VM=build15 runs the same lane on the FreeBSD 15.1 (OPNsense
# 26.7) build VM; BUILD_CHECK_SMPW=0 skips the SMPW variant (default: 1 on
# `build`, 0 on `build15`, which has only the SMP objdir unless one was built).
#
# Own dirs on the shared build VM, kept out of build-module.sh's/the lab's
# slot dirs (work, modobj, work-slotN, ...) which verification runs use
# concurrently: everything lives under $HOME/if_pppoe-lab/work-check/, one
# subdir per kernel-ABI variant (SMP, SMPW, SMP-reflect, host for the
# userland tools) so a stale object from one variant is never linked into
# another -- MAKEOBJDIRPREFIX does NOT redirect these out-of-tree builds
# (bmake's .OBJDIR resolves under .CURDIR here regardless; build-module.sh's
# own header comment notes the same thing), so physical separation is the
# only thing that actually keeps them apart.
#
# Warm reuse: each variant dir keeps a `.sync-sha256` of the last tree it
# received. A run whose source hashes the same as last time skips the
# tar-send/extract entirely for that variant (mtimes untouched, so bmake's
# own dependency check does the rest -- typically a no-op). A worktree
# source (unlike a commit) keeps each file's real mtime through the tar, so
# even a changed source recompiles only what actually changed. --clean
# forces a wipe (and full rebuild) regardless of the hash.
#
# -Werror: the out-of-tree Makefiles here don't set it themselves, but the
# OPNsense src tree's share/mk/bsd.sys.mk turns WARNS>=1 into -Werror
# whenever MK_WERROR!=no, the build system's default (confirmed live:
# `make -V CFLAGS -V MK_WERROR` on the build VM already shows -Werror in
# the kmod's resolved CFLAGS; every non-kmod Makefile here sets WARNS?=3)
# -- so nothing extra is needed, just don't override it away.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

REPO_ROOT="$(cd ../.. && pwd)"
SYNC_TOP_DIRS="sys spikes tools sbin"   # what the kmod/pppoectl/tools need

CLEAN=0
ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --clean) CLEAN=1; shift ;;
        --) shift; break ;;
        -*) echo "usage: $0 [--clean] [<commit-ish>|<worktree path>]" >&2; exit 1 ;;
        *) ARG="$1"; shift ;;
    esac
done
[ $# -eq 0 ] || { echo "usage: $0 [--clean] [<commit-ish>|<worktree path>]" >&2; exit 1; }

BUILD_VM="${BUILD_CHECK_VM:-build}"
case "$BUILD_VM" in
    build)   WANT_SMPW="${BUILD_CHECK_SMPW:-1}" ;;
    build15) WANT_SMPW="${BUILD_CHECK_SMPW:-0}" ;;
    *) echo "build-check: BUILD_CHECK_VM must be build or build15 (got '$BUILD_VM')" >&2; exit 1 ;;
esac
echo "build-check: VM = $BUILD_VM"

WORK='$HOME/if_pppoe-lab/work-check'
LOCKDIR='$HOME/if_pppoe-lab/build-check.lock'
SYSDIR='$HOME/if_pppoe-lab/src/sys'
KBD_SMP='$(cat $HOME/if_pppoe-lab/kernel/SMP/KERNBUILDDIR)'
KBD_SMPW='$(cat $HOME/if_pppoe-lab/kernel/SMPW/KERNBUILDDIR)'
DIR_SMP="$WORK/SMP"
DIR_SMPW="$WORK/SMPW"
DIR_REFLECT="$WORK/SMP-reflect"
DIR_HOST="$WORK/host"

LOCK_WAIT="${BUILD_CHECK_LOCK_WAIT:-180}"     # seconds to wait for a busy lock
LOCK_STALE="${BUILD_CHECK_LOCK_STALE:-900}"   # seconds after which a held lock is reclaimed

# --- Resolve the source: commit-ish (git archive) or worktree path (tar of
#     tracked files, read live off disk so local modifications are included)
SRC_KIND=""
SRC_LABEL=""
if [ -z "$ARG" ]; then
    SRC_KIND=worktree
    SRC_PATH="$REPO_ROOT"
elif git -C "$REPO_ROOT" rev-parse --verify --quiet "${ARG}^{commit}" >/dev/null; then
    SRC_KIND=commit
    SRC_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "${ARG}^{commit}")"
elif [ -d "$ARG" ] && git -C "$ARG" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SRC_KIND=worktree
    SRC_PATH="$(cd "$ARG" && pwd)"
else
    echo "build-check: '$ARG' is neither a valid commit-ish in $REPO_ROOT nor an existing git worktree path" >&2
    exit 1
fi

if [ "$SRC_KIND" = commit ]; then
    SRC_LABEL="commit:$SRC_COMMIT${ARG:+ ($ARG)}"
else
    DIRTY=""
    if ! git -C "$SRC_PATH" diff --quiet 2>/dev/null; then DIRTY="+dirty"; fi
    SRC_LABEL="worktree:$SRC_PATH ($(git -C "$SRC_PATH" rev-parse --short HEAD 2>/dev/null || echo unknown)$DIRTY)"
fi

# Which top-level dirs actually exist at this source (older commits may
# predate one of them).
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
[ -n "$EXIST_DIRS" ] || { echo "build-check: none of ($SYNC_TOP_DIRS) exist in $SRC_LABEL" >&2; exit 1; }

# Does the source's kmod Makefile define PPPOE_TEST_REFLECT?
HAVE_REFLECT=0
if [ "$SRC_KIND" = commit ]; then
    if git -C "$REPO_ROOT" cat-file -e "$SRC_COMMIT:sys/modules/if_pppoe/Makefile" 2>/dev/null; then
        if git -C "$REPO_ROOT" show "$SRC_COMMIT:sys/modules/if_pppoe/Makefile" | grep -q PPPOE_TEST_REFLECT; then
            HAVE_REFLECT=1
        fi
    fi
else
    if [ -f "$SRC_PATH/sys/modules/if_pppoe/Makefile" ]; then
        if grep -q PPPOE_TEST_REFLECT "$SRC_PATH/sys/modules/if_pppoe/Makefile"; then
            HAVE_REFLECT=1
        fi
    fi
fi

echo "build-check: source = $SRC_LABEL"
if [ "$HAVE_REFLECT" = 1 ]; then
    echo "build-check: PPPOE_TEST_REFLECT supported -- building it too"
else
    echo "build-check: PPPOE_TEST_REFLECT not defined by this Makefile -- skipping"
fi

# --- Build the local tar once (all variants sync from the same bytes) -----
TMPTAR="$(mktemp)"
case "$SRC_KIND" in
    commit)
        git -C "$REPO_ROOT" archive --format=tar "$SRC_COMMIT" -- $EXIST_DIRS > "$TMPTAR"
        ;;
    worktree)
        ( cd "$SRC_PATH" && git ls-files -z -- $EXIST_DIRS ) | tar -C "$SRC_PATH" --null -T - -cf "$TMPTAR"
        ;;
esac
TARSHA="$(sha256sum "$TMPTAR" | awk '{print $1}')"

# --- Lock (mkdir is atomic; a lock held longer than LOCK_STALE is treated
#     as abandoned rather than making every future run wait forever) -------
HELD_LOCK=0
release_lock() {
    [ "$HELD_LOCK" = 1 ] || return 0
    vm_ssh "$BUILD_VM" "rmdir $LOCKDIR 2>/dev/null || true" >/dev/null 2>&1 || true
    HELD_LOCK=0
}
cleanup() {
    release_lock
    rm -f "$TMPTAR" 2>/dev/null || true
}
trap cleanup EXIT

acquire_lock() {
    local waited=0
    while :; do
        local out
        out="$(vm_ssh "$BUILD_VM" sh -s <<EOF
if mkdir $LOCKDIR 2>/dev/null; then
    echo ACQUIRED
    exit 0
fi
now=\$(date +%s)
mtime=\$(stat -f %m $LOCKDIR 2>/dev/null || echo 0)
age=\$((now - mtime))
if [ "\$age" -gt $LOCK_STALE ]; then
    rmdir $LOCKDIR 2>/dev/null
    if mkdir $LOCKDIR 2>/dev/null; then
        echo "ACQUIRED-STALE age=\${age}s"
        exit 0
    fi
fi
echo "BUSY age=\${age}s"
EOF
)"
        case "$out" in
            ACQUIRED)
                HELD_LOCK=1
                return 0
                ;;
            ACQUIRED-STALE*)
                HELD_LOCK=1
                echo "build-check: reclaimed an abandoned lock ($out)" >&2
                return 0
                ;;
            *)
                if [ "$waited" -ge "$LOCK_WAIT" ]; then
                    echo "build-check: timed out waiting ${LOCK_WAIT}s for $LOCKDIR ($out)" >&2
                    exit 1
                fi
                sleep 5
                waited=$((waited + 5))
                ;;
        esac
    done
}

t0=$(date +%s)
acquire_lock
t_lock=$(date +%s)

# --- Sync each variant dir, skipping the tar-send/extract entirely when
#     its last-synced hash already matches (the warm/no-op case) -----------
sync_variant() {
    local dir="$1" label="$2" marker
    if [ "$CLEAN" = 1 ]; then
        vm_ssh "$BUILD_VM" "rm -rf $dir"
    fi
    marker="$(vm_ssh "$BUILD_VM" "mkdir -p $dir && { cat $dir/.sync-sha256 2>/dev/null || true; }")"
    if [ "$marker" = "$TARSHA" ]; then
        echo "sync: $label unchanged ($TARSHA), skipping"
        return 0
    fi
    echo "sync: $label -> extracting ($TARSHA)"
    # -m: force "now" mtimes on extraction. `git archive` stamps every entry
    # with the COMMIT's timestamp (not monotonic across arbitrary commits),
    # so without -m an older commit's files can land with an OLDER mtime
    # than a .o already built here from a later commit, and bmake silently
    # keeps the stale .o (confirmed live: this is exactly how 0b1534f's
    # broken if_sppp.h first passed instead of failing).
    vm_ssh "$BUILD_VM" "tar -C $dir -xmf - && echo $TARSHA > $dir/.sync-sha256" < "$TMPTAR"
}

sync_variant "$DIR_SMP" "SMP"
if [ "$WANT_SMPW" = 1 ]; then
    sync_variant "$DIR_SMPW" "SMPW"
fi
if [ "$HAVE_REFLECT" = 1 ]; then
    sync_variant "$DIR_REFLECT" "SMP-reflect"
fi
sync_variant "$DIR_HOST" "host"
t_sync=$(date +%s)

# --- Build. One ssh call for every target so the lock is held for the
#     shortest possible span; POSIX sh only (no bash on the build VM guest).
SMPW_LINE=""
if [ "$WANT_SMPW" = 1 ]; then
    SMPW_LINE="run kmod-SMPW $DIR_SMPW/sys/modules/if_pppoe KERNBUILDDIR=$KBD_SMPW SYSDIR=$SYSDIR"
fi
REFLECT_LINE=""
if [ "$HAVE_REFLECT" = 1 ]; then
    REFLECT_LINE="run kmod-SMP-reflect $DIR_REFLECT/sys/modules/if_pppoe KERNBUILDDIR=$KBD_SMP SYSDIR=$SYSDIR PPPOE_TEST_REFLECT=1"
fi

BUILD_OUT="$(vm_ssh "$BUILD_VM" sh -s <<EOF 2>&1
set -u
FAIL=0

run() {
    label="\$1"; dir="\$2"; shift 2
    echo "=== BEGIN \$label \$(date +%s) ==="
    make -C "\$dir" "\$@"
    rc=\$?
    echo "=== RC=\$rc \$label \$(date +%s) ==="
    [ "\$rc" -eq 0 ] || FAIL=1
}

run kmod-SMP $DIR_SMP/sys/modules/if_pppoe KERNBUILDDIR=$KBD_SMP SYSDIR=$SYSDIR
$SMPW_LINE
$REFLECT_LINE
run sbin-pppoectl $DIR_HOST/sbin/pppoectl
run tools-pppoeparms $DIR_HOST/tools/pppoeparms
run tools-spppauth $DIR_HOST/tools/spppauth
run tools-spppioctl $DIR_HOST/tools/spppioctl
run tools-spppkeepalive $DIR_HOST/tools/spppkeepalive

exit \$FAIL
EOF
)" && BUILD_RC=0 || BUILD_RC=$?
t_build=$(date +%s)

release_lock

# --- Parse "=== BEGIN label ts ===" / "=== RC=n label ts ===" markers and
#     print a concise PASS/FAIL summary, with verbatim output on failure ---
echo
echo "== build-check summary =="
echo "source:  $SRC_LABEL"
echo "lock:    $((t_lock - t0))s wait"
echo "sync:    $((t_sync - t_lock))s"
echo "build:   $((t_build - t_sync))s"
echo

OVERALL=0
cur_label=""
cur_start=0
cur_buf=""
print_result() {
    local label="$1" rc="$2" dur="$3" buf="$4"
    if [ "$rc" -eq 0 ]; then
        printf '  %-22s PASS  %ds\n' "$label" "$dur"
    else
        printf '  %-22s FAIL  %ds (exit %d)\n' "$label" "$dur" "$rc"
        echo "  ---- $label output (verbatim) ----"
        printf '%s\n' "$buf" | sed 's/^/  /'
        echo "  -----------------------------------"
        OVERALL=1
    fi
}
while IFS= read -r line; do
    case "$line" in
        "=== BEGIN "*)
            rest="${line#=== BEGIN }"; rest="${rest% ===}"
            cur_label="${rest% *}"; cur_start="${rest##* }"
            cur_buf=""
            ;;
        "=== RC="*)
            rest="${line#=== RC=}"
            rc="${rest%% *}"
            rest="${rest#* }"; rest="${rest% ===}"
            end_ts="${rest##* }"
            print_result "$cur_label" "$rc" "$((end_ts - cur_start))" "$cur_buf"
            ;;
        *)
            if [ -n "$cur_label" ]; then
                if [ -n "$cur_buf" ]; then
                    cur_buf="$cur_buf
$line"
                else
                    cur_buf="$line"
                fi
            fi
            ;;
    esac
done <<<"$BUILD_OUT"

if [ "$HAVE_REFLECT" != 1 ]; then
    printf '  %-22s SKIP  (Makefile has no PPPOE_TEST_REFLECT option)\n' kmod-SMP-reflect
fi
if [ "$WANT_SMPW" != 1 ]; then
    printf '  %-22s SKIP  (BUILD_CHECK_SMPW=0)\n' kmod-SMPW
fi

echo
if [ "$BUILD_RC" -ne 0 ] && [ "$OVERALL" -eq 0 ]; then
    # ssh/transport-level failure with no parsed per-target output at all.
    echo "build-check: remote build script exited $BUILD_RC with no parsed target output:"
    printf '%s\n' "$BUILD_OUT"
    OVERALL=1
fi

if [ "$OVERALL" -eq 0 ]; then
    echo "build-check: PASS  (wall $((t_build - t0))s)"
else
    echo "build-check: FAIL  (wall $((t_build - t0))s)"
fi
exit "$OVERALL"
