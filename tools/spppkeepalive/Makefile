PROG=	spppkeepalive
MAN=
# <net/if_sppp.h> is this repo's vendored header (same one the driver
# builds against, sys/net/if_sppp.h), not a base-system header.
CFLAGS+=	-I${.CURDIR}/../../sys
WARNS?=	3

.include <bsd.prog.mk>