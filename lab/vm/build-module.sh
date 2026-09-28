#!/usr/bin/env bash
# build-module.sh — build an out-of-tree kmod from this repo inside the `build`
# VM against the collected OPNsense SMP KERNBUILDDIR, and ship the .ko to the
# `client` VM. Sources are copied (tar over ssh, as build-kernel.sh does) into
# $HOME/if_pppoe-lab/work/ in the build VM; the opnsense/src checkout at
# $HOME/if_pppoe-lab/src is used read-only as SYSDIR.
#
#   ./build-module.sh sync                       # push repo sys/ spikes/ tools/
#   ./build-module.sh build sys/modules/if_pppoe # bmake the kmod, print .ko path
#   ./build-module.sh deploy sys/modules/if_pppoe if_pppoe.ko
#   ./build-module.sh load if_pppoe.ko [kldload-args...]
#   ./build-module.sh unload if_pppoe
#
# LAB_SLOT=N: builds in the build VM's $HOME/if_pppoe-lab/work-slotN and ships
# to that slot's client VM (client<N>); slot 1 = work/ and client, as before.
#
# `build`'s LAST stdout line is always the resolved .ko path — safe to `| tail -1`.
# `sync` forces every `build` to fully rebuild: MAKEOBJDIRPREFIX is inert here
# (.OBJDIR resolves under $WORK, not $OBJPFX), so `sync`'s wipe deletes objects too.
# `load`/`unload` fail loudly rather than no-op if already in the target state.
#
# KERNEL_VARIANT (default SMP) selects which collected kernel variant the kmod
# is built against: $HOME/if_pppoe-lab/kernel/<variant>/KERNBUILDDIR on the
# build VM. The kmod MUST be rebuilt per kernel variant — opt_global.h (with
# INVARIANTS/WITNESS for the SMPW debug kernel) is symlinked out of
# KERNBUILDDIR — a release-built .ko cannot load on the SMPW kernel and vice
# versa. The object tree is shared between variants; `build` cleans it when
# the variant changes (see the stamp below), so no stale object is linked in.
#
# PPPOE_TEST_HOOKS (default 1) builds the lab's test hooks into the kmod
# (PPPOE_TEST_REFLECT=1 -> net.pppoe.reflect, needed by test_datapath.py).
# Set PPPOE_TEST_HOOKS=0 for a module you intend to ship.  bsd.kmod.mk does
# not rebuild on a CFLAGS change, so `build` records the variant it built
# (KERNEL_VARIANT + hook vars) in a stamp next to the sources and runs
# `make clean` first whenever the requested variant differs: switching
# PPPOE_TEST_HOOKS or KERNEL_VARIANT can never link a stale object.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

KERNEL_VARIANT="${KERNEL_VARIANT:-SMP}"
PPPOE_TEST_HOOKS="${PPPOE_TEST_HOOKS:-1}"
case "$PPPOE_TEST_HOOKS" in
    0) HOOK_VARS='' ;;
    1) HOOK_VARS='PPPOE_TEST_REFLECT=1' ;;
    *) echo "PPPOE_TEST_HOOKS must be 0 or 1, got '$PPPOE_TEST_HOOKS'" >&2; exit 1 ;;
esac
REPO_ROOT="$(cd ../.. && pwd)"
# Per-slot work/obj dirs on the SHARED build VM: `sync` wipes $WORK, so two
# slots building at once must never share it (slot 1 keeps the old paths).
SLOT_SFX="$(slot_suffix "$LAB_SLOT")"
WORK='$HOME/if_pppoe-lab/work'"$SLOT_SFX"
OBJPFX='$HOME/if_pppoe-lab/modobj'"$SLOT_SFX"
SYSDIR='$HOME/if_pppoe-lab/src/sys'
KBD='$(cat $HOME/if_pppoe-lab/kernel/'"$KERNEL_VARIANT"'/KERNBUILDDIR)'

usage() {
    echo "usage: $0 sync | build <reldir> | deploy <reldir> <ko> | load <ko> [kldload-args...] | unload <name>" >&2
    echo "       env: KERNEL_VARIANT=<SMP|SMPW> (default SMP) selects the KERNBUILDDIR the kmod is built against" >&2
    echo "            PPPOE_TEST_HOOKS=<0|1> (default 1) builds in the lab test hooks (net.pppoe.reflect)" >&2
    exit 1
}

cmd_sync() {
    local dirs=()
    for d in sys spikes tools; do
        [ -d "$REPO_ROOT/$d" ] && dirs+=("$d")
    done
    [ "${#dirs[@]}" -gt 0 ] || { echo "sync: nothing to sync (no sys/, spikes/, or tools/ in $REPO_ROOT)" >&2; exit 1; }
    vm_ssh build "sh -c 'rm -rf $WORK && mkdir -p $WORK'"
    tar -C "$REPO_ROOT" -cf - "${dirs[@]}" | vm_ssh build "tar -C $WORK -xf -"
    vm_ssh build "ls -la $WORK"
}

# Query `make` variables for $reldir as their own ssh round trip (same
# MAKEOBJDIRPREFIX/KERNBUILDDIR/SYSDIR as the real build) so the result is
# never mixed with build/compiler stdout — one line per variable, in order.
query_make_vars() {
    local reldir="$1"; shift
    local out
    out="$(vm_ssh build sh -s <<EOF
set -eu
env MAKEOBJDIRPREFIX="$OBJPFX" \
    make -C "$WORK/$reldir" KERNBUILDDIR="$KBD" SYSDIR="$SYSDIR" $(printf -- '-V %q ' "$@")
EOF
)"
    printf '%s\n' "$out"
}

cmd_build() {
    local reldir="$1"
    [ -n "$reldir" ] || usage

    vm_ssh build sh -s <<EOF
set -eu
mkdir -p "$OBJPFX"
stamp="$WORK/$reldir/.build-variant"
want="$KERNEL_VARIANT $HOOK_VARS"
if [ ! -f "\$stamp" ] || [ "\$(cat "\$stamp")" != "\$want" ]; then
    env MAKEOBJDIRPREFIX="$OBJPFX" \
        make -C "$WORK/$reldir" KERNBUILDDIR="$KBD" SYSDIR="$SYSDIR" clean
fi
env MAKEOBJDIRPREFIX="$OBJPFX" \
    make -C "$WORK/$reldir" KERNBUILDDIR="$KBD" SYSDIR="$SYSDIR" $HOOK_VARS
printf '%s\n' "\$want" > "\$stamp"
EOF

    local vars objdir kmod ko_path
    vars="$(query_make_vars "$reldir" .OBJDIR KMOD)"
    objdir="$(printf '%s\n' "$vars" | sed -n '1p')"
    kmod="$(printf '%s\n' "$vars" | sed -n '2p')"
    if [ -z "$objdir" ] || [ -z "$kmod" ]; then
        echo "build: could not resolve .OBJDIR/KMOD for '$reldir' (got: $(printf '%s' "$vars" | tr '\n' '|'))" >&2
        exit 1
    fi
    ko_path="$objdir/$kmod.ko"
    if ! vm_ssh build "[ -f '$ko_path' ]"; then
        echo "build: expected .ko not found at '$ko_path' after building '$reldir'" >&2
        exit 1
    fi
    # LAST line of stdout, guaranteed nothing prints after it — callers may
    # pipe to `| tail -1` for the .ko path.
    echo "$ko_path"
}

cmd_deploy() {
    local reldir="$1" ko="$2" ko_path ko_base
    [ -n "$reldir" ] && [ -n "$ko" ] || usage

    ko_path="$(cmd_build "$reldir" | tail -1)"
    ko_base="$(basename -- "$ko_path")"
    if [ "$ko_base" != "$ko" ]; then
        echo "deploy: built .ko is '$ko_base' (at '$ko_path'), not the requested '$ko'" >&2
        exit 1
    fi
    echo "objdir=$(dirname -- "$ko_path")"

    vm_ssh build "tar -C '$(dirname -- "$ko_path")' -cf - '$ko'" | vm_ssh client "tar -C /tmp -xf -"
    if ! vm_ssh client "[ -f '/tmp/$ko' ]"; then
        echo "deploy: '$ko' did not land at /tmp/$ko on the client VM" >&2
        exit 1
    fi
    vm_ssh client "ls -la /tmp/$ko"
}

# Print the client VM's last dmesg lines to stderr — best-effort context for
# a load/unload failure. Never itself causes a failure.
dump_dmesg() {
    echo "---- last dmesg lines on client ----" >&2
    vm_ssh client "dmesg | tail -n 20" >&2 || echo "(could not fetch dmesg)" >&2
    echo "-------------------------------------" >&2
}

cmd_load() {
    local ko="$1"; shift
    [ -n "$ko" ] || usage
    local -a kld_args=("$@")
    local kld_extra=""
    if [ "${#kld_args[@]}" -gt 0 ]; then
        kld_extra="${kld_args[*]} "
    fi

    local rc=0
    echo | vm_ssh client "su -m root -c 'kldload $kld_extra/tmp/$ko'" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "load: kldload /tmp/$ko failed (exit $rc)" >&2
        dump_dmesg
        exit "$rc"
    fi

    # kldload's own exit status can be 0 without the expected file actually
    # being the thing now resident (e.g. it was already loaded under a
    # different id) — confirm by exact filename, not a grep/count heuristic.
    if ! vm_ssh client "kldstat -q -n '$ko'"; then
        echo "load: kldload /tmp/$ko exited 0 but 'kldstat -q -n $ko' does not confirm it is loaded" >&2
        dump_dmesg
        exit 1
    fi
    echo "load: $ko loaded (kldstat -q -n $ko confirms)"
}

cmd_unload() {
    local name="$1"
    [ -n "$name" ] || usage

    local rc=0
    echo | vm_ssh client "su -m root -c 'kldunload $name'" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "unload: kldunload $name failed (exit $rc)" >&2
        dump_dmesg
        exit "$rc"
    fi

    if vm_ssh client "kldstat -q -m '$name'"; then
        echo "unload: kldunload $name exited 0 but 'kldstat -q -m $name' still reports it loaded" >&2
        dump_dmesg
        exit 1
    fi
    echo "unload: $name unloaded (kldstat -q -m $name confirms absent)"
}

[ $# -ge 1 ] || usage
action="$1"; shift
case "$action" in
    sync)   [ $# -eq 0 ] || usage; cmd_sync ;;
    build)  [ $# -eq 1 ] || usage; cmd_build "$1" ;;
    deploy) [ $# -eq 2 ] || usage; cmd_deploy "$1" "$2" ;;
    load)   [ $# -ge 1 ] || usage; cmd_load "$@" ;;
    unload) [ $# -eq 1 ] || usage; cmd_unload "$1" ;;
    *)      usage ;;
esac
