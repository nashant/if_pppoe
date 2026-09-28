# Out-of-tree kmod for the OPNsense SMP kernel.  Build with:
#   make -C sys/modules/if_pppoe \
#       KERNBUILDDIR=<obj>/.../sys/SMP \
#       SYSDIR=<opnsense/src>/sys
# lab/vm/build-module.sh does exactly that inside the `build` VM.
# SYSDIR may be FreeBSD 14.3 (OPNsense 25.7/26.1) or 15.1 (26.7).

.PATH:	${.CURDIR}/../../net

KMOD=	if_pppoe
SRCS=	if_pppoe.c
SRCS+=	if_pppoe_disc.c
SRCS+=	if_pppoe_netisr.c
# Vendored NetBSD sppp(4) at pin 5ee7eb6e8db7 (S01 T1/T2): compiled against
# the FreeBSD 14.3 kernel through net/if_sppp_compat.h, linked into the
# module so it carries the sppp_* symbols (S01 T3).  Datapath wiring lands
# in S02+.
SRCS+=	if_spppsubr.c
SRCS+=	opt_global.h opt_inet.h opt_inet6.h opt_rss.h

CFLAGS+=	-I${.CURDIR}/../..

# PPPOE_TEST_REFLECT=1 compiles in net.pppoe.reflect, the lab's TX-path
# test hook (tests/functional/test_datapath.py).  Off by default: a release
# module must not carry it.  lab/vm/build-module.sh passes it unless
# PPPOE_TEST_HOOKS=0.
.if defined(PPPOE_TEST_REFLECT) && ${PPPOE_TEST_REFLECT} != "0"
CFLAGS+=	-DPPPOE_TEST_REFLECT
.endif

.include <bsd.kmod.mk>
