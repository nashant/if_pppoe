#
# pppoectl(8) — FreeBSD bsd.prog.mk build of the NetBSD tool.
#
# The tool source (pppoectl.c) started byte-identical to NetBSD/src at pin
# 5ee7eb6e8db7128264453921994932a2c2a5af70 (plus the port notice only).
# Local deltas since: p3-ctl-abi's hardening (listed in docs/PORTING-sppp.md)
# and the {no}mssfix keywords for the driver's TCP MSS clamp (all under
# #ifdef PPPOESETMSSFIX).  Requirement R005 "NetBSD pppoectl works
# unmodified" still holds (same ioctl ABI, same CLI). All other FreeBSD-14
# accommodations live here, in the build, never in the source:
#
#   1. -D__NetBSD__  — the pin's own #ifndef __NetBSD__ variant branches
#      (pppoectl_argument enable-vj/disable-vj, print_vals idle_time and
#      enable_vj lines) reference spppauthcfg.defs / PHASE_DEAD, which are
#      NetBSD-kernel-visible fields that this port deliberately does not
#      expose (VJ compression and the on-demand idle-timeout are spec
#      section 2 non-goals).  Compiling the NetBSD variant is the upstream-
#      sanctioned way to select the NetBSD code path; both variants drive
#      the identical SPPP* ioctl ABI.
#      Side effect: FreeBSD's net/dlt.h has platform-conditional defines of
#      DLT_PFSYNC (18 at line ~196 when __NetBSD__/__OpenBSD__/... is set,
#      121 under __FreeBSD__), so -D__NetBSD__ makes it trip -Wmacro-
#      redefined under WARNS/ -Werror.  DLT_PFSYNC is unused in this TU
#      (it only appears under SPPP_FILTER, never defined here), so the
#      redefinition is benign and silenced with -Wno-macro-redefined.
#   2. -D__dead=__dead2 — FreeBSD sys/cdefs.h spells the noreturn attribute
#      __dead2 (NetBSD spells it __dead).
#   3. fparseln(3) — FreeBSD ships it in libutil (NetBSD has it in libc),
#      and libutil.h only prototypes it after <stdio.h> (its _STDIO_H_
#      guard), so both are force-included in order, plus -lutil.
#   4. -D'__BIT(n)=...' — the vendored NetBSD if_sppp.h bit constants use
#      NetBSD's __BIT() macro, absent from FreeBSD base headers.
#
# IFNAME/ioctl ABI: <net/if_sppp.h> and <net/if_pppoe.h> come from this
# repo's vendored sys/net (same pristine headers the driver is built
# against), so the ioctl numbers and struct layouts match the kernel
# exactly.  Build with `make -C sbin/pppoectl`, or on the lab client VM
# after rsync'ing sbin/ + sys/ (see tests/functional/lab.py's tool deploy).

PROG=	pppoectl
MAN=	pppoectl.8
SRCS=	pppoectl.c

CFLAGS+=	-D__NetBSD__
CFLAGS+=	-D__dead=__dead2
CFLAGS+=	-D'__BIT(n)=(1UL<<(n))'
CFLAGS+=	-include stdio.h -include libutil.h
CFLAGS+=	-Wno-macro-redefined
CFLAGS+=	-I${.CURDIR}/../../sys
LDADD+=		-lutil
DPADD+=		${LIBUTIL}

WARNS?=	3

.include <bsd.prog.mk>