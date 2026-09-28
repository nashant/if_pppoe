# FreeBSD-only build-time check (see check_ioctl_group.c). Run on the
# lab/build VM, not on this checkout's host:
#
#   make -C tests/ioctl-abi check
#
CC?=		cc
CFLAGS+=	-std=c11 -Wall -Werror -I${.CURDIR}/../../sys

.PHONY: check clean

check: check_ioctl_group.o

check_ioctl_group.o: check_ioctl_group.c
	${CC} ${CFLAGS} -c ${.ALLSRC} -o ${.TARGET}

clean:
	rm -f check_ioctl_group.o
