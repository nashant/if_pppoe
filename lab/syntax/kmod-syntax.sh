#!/bin/sh
# kmod-syntax.sh <SYSDIR> [clang|docker] -- compile-only (-fsyntax-only)
# smoke of the if_pppoe kmod sources against a bare FreeBSD/OPNsense sys/
# tree, with no kernel objdir. The opt_*.h headers are stubbed from the lab
# SMP kernel's (OPNsense config/25.7/SMP, build VM objdir) and the flags
# mirror bsd.kmod.mk's amd64 CFLAGS as resolved on the build VM
# (`make -V CFLAGS`). It catches KPI (header) breakage on a FreeBSD release
# that has no lab objdir yet. It does not link and it does not see the
# kernel's real opt_*.h, so a PASS is necessary, not sufficient:
# lab/vm/build-check.sh (or CI's freebsd-build.sh) stays the real compile.
#
#   sh lab/syntax/kmod-syntax.sh /path/to/src/sys            # host clang
#   sh lab/syntax/kmod-syntax.sh /path/to/src/sys docker     # silkeh/clang:19
#
# A sys/ tree without a full clone:
#   g clone --depth 1 --filter=blob:none --sparse -b releng/15.1 \
#       https://github.com/freebsd/freebsd-src.git fbsd-15.1
#   g -C fbsd-15.1 sparse-checkout set sys
set -eu

SYSDIR="${1:?usage: $0 <SYSDIR> [clang|docker]}"
CLANG="${2:-clang}"
SYSDIR="$(cd "$SYSDIR" && pwd)"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ver="$(sed -n 's/^#define[[:space:]]*__FreeBSD_version[[:space:]]*\([0-9]*\).*/\1/p' "$SYSDIR/sys/param.h")"
major=$((ver / 100000))
echo "kmod-syntax: SYSDIR=$SYSDIR __FreeBSD_version=$ver"

# machine/ and x86/ links, as bsd.kmod.mk creates in the obj dir.
ln -s "$SYSDIR/amd64/include" "$TMP/machine"
ln -s "$SYSDIR/x86/include" "$TMP/x86"

# opt_*.h: the subset of the lab SMP kernel's that can change a header's
# shape (VIMAGE, RSS, INET/INET6, SMP, NUMA, KDTRACE_HOOKS, ...).
cat > "$TMP/opt_global.h" <<'OPT'
#define KDB 1
#define CC_CUBIC 1
#define COMPAT_FREEBSD13 1
#define KDTRACE_HOOKS 1
#define NEW_PCIB 1
#define DEBUGNET 1
#define EARLY_AP_STARTUP 1
#define NUMA 1
#define VIMAGE 1
#define RACCT 1
#define RCTL 1
#define DEV_NETMAP 1
#define SMP 1
#define TCP_HHOOK 1
#define NETLINK 1
#define MAC 1
#define AUDIT 1
OPT
printf '#define INET 1\n#define TCP_OFFLOAD 1\n' > "$TMP/opt_inet.h"
printf '#define INET6 1\n' > "$TMP/opt_inet6.h"
printf '#define RSS 1\n' > "$TMP/opt_rss.h"
# Generated kobj headers sys/bus.h includes (bsd.kmod.mk builds them too).
for m in kern/device_if.m kern/bus_if.m; do
    (cd "$TMP" && awk -f "$SYSDIR/tools/makeobjops.awk" "$SYSDIR/$m" -h)
done

# bsd.kmod.mk's amd64 CFLAGS minus -O2/-pipe/-Werror, so one run reports
# every diagnostic instead of stopping at the first -Werror.  CSTD is
# sys/conf/kern.mk's: gnu99 on 14.x, gnu17 from 15.0.
std=gnu99
[ "$major" -lt 15 ] || std=gnu17
CFLAGS="--target=x86_64-unknown-freebsd${major} -fsyntax-only \
 -fno-strict-aliasing -D_KERNEL -DKLD_MODULE -nostdinc \
 -I$REPO/sys -DHAVE_KERNEL_OPTION_HEADERS -include $TMP/opt_global.h \
 -I$TMP -I$SYSDIR -I$SYSDIR/contrib/ck/include -fno-common \
 -mcmodel=kernel -mno-red-zone -mno-mmx -mno-sse -msoft-float \
 -ffreestanding -fwrapv -fstack-protector -Wall -Wstrict-prototypes \
 -Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wundef \
 -Wno-pointer-sign -D__printf__=__freebsd_kprintf__ \
 -Wno-unknown-pragmas -Wno-address-of-packed-member \
 -Wno-format-zero-length -mno-aes -mno-avx -std=$std"

run_cc() {
    if [ "$CLANG" = docker ]; then
        docker run --rm -u "$(id -u):$(id -g)" \
            -v "$SYSDIR:$SYSDIR:ro" -v "$REPO:$REPO:ro" -v "$TMP:$TMP:ro" \
            silkeh/clang:19 clang "$@"
    else
        "$CLANG" "$@"
    fi
}

rc=0
for src in if_pppoe.c if_pppoe_disc.c if_pppoe_netisr.c if_spppsubr.c; do
    # shellcheck disable=SC2086
    if run_cc $CFLAGS "$REPO/sys/net/$src" > "$TMP/$src.log" 2>&1; then
        echo "  $src: PASS ($(grep -c 'warning:' "$TMP/$src.log" || true) warnings)"
    else
        echo "  $src: FAIL ($(grep -c 'error:' "$TMP/$src.log" || true) errors)"
        rc=1
    fi
    sed 's/^/    /' "$TMP/$src.log"
done
exit $rc
