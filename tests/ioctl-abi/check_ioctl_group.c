/*
 * p3-ctl-abi build-time check.
 *
 * Two independent properties, both required for SPPP_/PPPOE_ ioctls to
 * ever reach pppoe_ioctl()/sppp_ioctl():
 *
 *   1. Every one of them is on ioctl group 'i'. soo_ioctl() (sys/kern/
 *      sys_socket.c) routes strictly on IOCGROUP(cmd): only 'i' goes to
 *      ifioctl() -> ifhwioctl() -> (ENOIOCTL) -> the driver's own
 *      if_ioctl. Any other group is handed to the socket's pr_control
 *      (in_control() for pppoectl(8)'s AF_INET socket), which returns
 *      EADDRNOTAVAIL immediately because pr_control's ifp is NULL --
 *      this driver would never be reached at all. (An earlier draft of
 *      this fix moved everything to a private group 'P' for exactly the
 *      opposite, wrong, reason; see docs/PORTING-sppp.md.)
 *
 *   2. None of them has the same full _IOWR/_IOW/_IOR value (group +
 *      number + direction + payload size) as a generic SIOC* ioctl that
 *      ifhwioctl()/in_control()/in6_control() already answer on group
 *      'i' -- those run before the driver's own if_ioctl ever sees the
 *      call. Collision is on the FULL value: two ioctls sharing a
 *      number but differing in direction or struct size are already
 *      different `unsigned long` values and can never compare equal, so
 *      only same-number pairs are checked below; every other SPPP_/
 *      PPPOE_ number (verified by the enumeration below to have no
 *      generic user at all) cannot collide by construction.
 *
 * This checkout has no FreeBSD toolchain/headers, so this file can only
 * be compiled on the FreeBSD 14.3 lab/build VM (a real GENERIC-ish
 * userland, not this driver's own headers for sockio.h/in6_var.h). A
 * successful compile (no link step needed) IS the test:
 *
 *   make -C tests/ioctl-abi check
 *
 * The full source-of-truth enumeration (every group-'i' SIOC* in
 * sys/sys/sockio.h and sys/netinet6/in6_var.h; sys/netinet/in_var.h
 * defines none) is fetched and reconciled in docs/PORTING-sppp.md's
 * "ioctl number collision" table -- keep the two in sync.
 */
#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet6/in6_var.h>
#include <net/if_sppp.h>
#include <net/if_pppoe.h>

/* --- 1. routing requirement: every SPPP_/PPPOE_ ioctl is on group 'i' --- */

#define CHECK_GROUP(x) \
	_Static_assert(IOCGROUP(x) == 'i', #x " must stay on ioctl group 'i' -- " \
	    "soo_ioctl() only routes group 'i' to ifioctl()")

CHECK_GROUP(PPPOESETPARMS);
CHECK_GROUP(PPPOEGETPARMS);
CHECK_GROUP(PPPOEGETSESSION);
CHECK_GROUP(SPPPGETAUTHCFG);
CHECK_GROUP(SPPPSETAUTHCFG);
CHECK_GROUP(SPPPGETLCPCFG);
CHECK_GROUP(SPPPSETLCPCFG);
CHECK_GROUP(SPPPGETSTATUS);
CHECK_GROUP(SPPPGETSTATUSNCP);
CHECK_GROUP(SPPPGETIDLETO);
CHECK_GROUP(SPPPSETIDLETO);
CHECK_GROUP(__SPPPGETIDLETO50);
CHECK_GROUP(__SPPPSETIDLETO50);
CHECK_GROUP(SPPPGETAUTHFAILURES);
CHECK_GROUP(SPPPSETAUTHFAILURE);
CHECK_GROUP(SPPPSETDNSOPTS);
CHECK_GROUP(SPPPGETDNSOPTS);
CHECK_GROUP(SPPPGETDNSADDRS);
CHECK_GROUP(SPPPSETKEEPALIVE);
CHECK_GROUP(SPPPGETKEEPALIVE);
CHECK_GROUP(__SPPPSETKEEPALIVE50);
CHECK_GROUP(__SPPPGETKEEPALIVE50);
CHECK_GROUP(SPPPGETLCPSTATUS);
CHECK_GROUP(SPPPGETIPCPSTATUS);
CHECK_GROUP(SPPPGETIPV6CPSTATUS);
CHECK_GROUP(SPPPGETNCPCFG);
CHECK_GROUP(SPPPSETNCPCFG);
CHECK_GROUP(SPPPIOCSDIALFILT);
CHECK_GROUP(SPPPIOCSIACTIVE);
CHECK_GROUP(SPPPIOCSOACTIVE);

/*
 * --- 2. exhaustive collision check, restricted to numbers that could
 * possibly collide (see file header: a different number is always a
 * different value). Every SPPP_/PPPOE_ number in 110-146 is listed;
 * numbers with no generic 'i'-group user in sockio.h/in6_var.h are
 * called out explicitly as "no generic user at this number" so the
 * absence is a checked fact, not a silent omission.
 */

/* 110-112 (PPPOE*): no generic 'i'-group ioctl at 110, 111 or 112. */

/* 120: SIOCIFGCLONERS (_IOWR, struct if_clonereq) */
_Static_assert(SPPPGETAUTHCFG != SIOCIFGCLONERS, "120 vs SIOCIFGCLONERS");
/* 121: SIOCIFDESTROY (_IOW, struct ifreq) */
_Static_assert(SPPPSETAUTHCFG != SIOCIFDESTROY, "121 vs SIOCIFDESTROY");
/* 122: SIOCIFCREATE (_IOWR, struct ifreq) */
_Static_assert(SPPPGETLCPCFG != SIOCIFCREATE, "122 vs SIOCIFCREATE");
/* 123: SIOCSDRVSPEC (_IOW, struct ifdrv) / SIOCGDRVSPEC (_IOWR, struct ifdrv) */
_Static_assert(SPPPSETLCPCFG != SIOCSDRVSPEC, "123 vs SIOCSDRVSPEC");
_Static_assert(SPPPSETLCPCFG != SIOCGDRVSPEC, "123 vs SIOCGDRVSPEC");
/* 124: SIOCIFCREATE2 (_IOWR, struct ifreq) */
_Static_assert(SPPPGETSTATUS != SIOCIFCREATE2, "124 vs SIOCIFCREATE2");

/* 125-134 (SPPPGETIDLETO/SETIDLETO/AUTHFAILURES/SETAUTHFAILURE/DNSOPTS/
 * DNSADDRS/KEEPALIVE/STATUSNCP): no generic 'i'-group ioctl at any number
 * 125 through 134 in either header. */

/* 135: SIOCAIFGROUP (_IOW, struct ifgroupreq) */
_Static_assert(SPPPGETLCPSTATUS != SIOCAIFGROUP, "135 vs SIOCAIFGROUP");
/* 136: SPPPGETIPCPSTATUS lives at 200 now (the one true collision, see
 * the negative control below) -- nothing of ours is at 136 any more. */
/* 137: SIOCDIFGROUP (_IOW, struct ifgroupreq) */
_Static_assert(SPPPGETIPV6CPSTATUS != SIOCDIFGROUP, "137 vs SIOCDIFGROUP");
/* 138: SIOCGIFGMEMB (_IOWR, struct ifgroupreq) */
_Static_assert(SPPPGETNCPCFG != SIOCGIFGMEMB, "138 vs SIOCGIFGMEMB");
/* 139: SIOCGIFXMEDIA (_IOWR, struct ifmediareq) */
_Static_assert(SPPPSETNCPCFG != SIOCGIFXMEDIA, "139 vs SIOCGIFXMEDIA");

/* 144-146 (SPPPIOCS{DIALFILT,IACTIVE,OACTIVE}): no generic 'i'-group
 * ioctl at 144, 145 or 146. */

/* 200 (SPPPGETIPCPSTATUS, renumbered from 136): no generic 'i'-group
 * ioctl anywhere near 200 -- sockio.h's highest 'i'-group number is 156,
 * in6_var.h's is 109. */

/*
 * --- 3. negative control: prove this checker is not vacuous by showing
 * the *pre-fix* SPPPGETIPCPSTATUS value (group 'i', number 136) really
 * did collide with SIOCGIFGROUP. If this assertion ever failed to hold,
 * the positive checks above would not have caught the original bug
 * either.
 */
#define OLD_SPPPGETIPCPSTATUS	_IOWR('i', 136, struct spppipcpstatus)
_Static_assert(OLD_SPPPGETIPCPSTATUS == SIOCGIFGROUP,
    "negative control failed: the pre-fix SPPPGETIPCPSTATUS value no "
    "longer equals SIOCGIFGROUP -- this checker would not have caught "
    "the original bug, so its positive assertions above are not trusted");

int
main(void)
{
	return 0;
}
