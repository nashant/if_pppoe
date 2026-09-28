/*
 * Spike S2 (throwaway): set an IPv4 p2p address and an IPv6 address on an
 * existing interface from kernel context on FreeBSD 14.3, the way the
 * ported sppp IPCP/IPv6CP code will have to.
 *
 * Usage:
 *   sysctl net.s2_inaddr.apply=tun0
 * then check `ifconfig tun0`.
 *
 * Deviations from the task brief:
 *   - <sys/sockio.h> is included: SIOCAIFADDR is defined there
 *     (sys/sys/sockio.h:84), and SIOCAIFADDR_IN6 needs _IOW() from
 *     <sys/ioccom.h> which sockio.h pulls in.
 *   - <netinet6/nd6.h> is included: ND6_INFINITE_LIFETIME lives there
 *     (sys/netinet6/nd6.h:178), not in <netinet6/in6_var.h>.
 *   - The WHOLE task body -- ifunit_ref() included, not just the two ioctls --
 *     runs inside CURVNET_SET()/CURVNET_RESTORE().  The target kernel has
 *     VIMAGE (client `sysctl -n kern.conftxt` => "options VIMAGE"), curvnet is
 *     curthread->td_vnet (sys/net/vnet.h:176) and VNET_PTR() dereferences it
 *     (sys/net/vnet.h:304).  A taskqueue_thread task starts with td_vnet ==
 *     NULL, so the brief's unwrapped code page-faults -- measured, in
 *     ifunit_ref() (V_ifnet), before it ever reached in_control_ioctl()
 *     (verbatim backtrace recorded separately).
 *     The vnet is captured in the sysctl handler (a user thread, which has
 *     curvnet set) -- the driver equivalent is the vnet if_attach() stamped
 *     into ifp->if_vnet, reachable as if_getvnet(ifp) (sys/net/if_var.h:630).
 *     net.s2_inaddr.use_curvnet=0 reproduces the panic on demand.
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

static char		s2_ifname[IFNAMSIZ];
static struct task	s2_task;
static int		s2_v4_error = -1;
static int		s2_v6_error = -1;
static int		s2_curvnet_null = -1;
static int		s2_use_curvnet = 1;
#ifdef VIMAGE
static struct vnet	*s2_vnet;
#endif

static void
s2_ioctls(struct ifnet *ifp)
{
	struct in_aliasreq ifra;
	struct in6_aliasreq ifra6;

	/* IPv4: 10.64.0.2 --> 10.64.0.1, /32, as IPCP would apply it. */
	bzero(&ifra, sizeof(ifra));
	strlcpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin_family = AF_INET;
	ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_addr.sin_addr.s_addr = htonl(0x0A400002);	/* 10.64.0.2 */
	ifra.ifra_dstaddr.sin_family = AF_INET;
	ifra.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_dstaddr.sin_addr.s_addr = htonl(0x0A400001);	/* 10.64.0.1 */
	ifra.ifra_mask.sin_family = AF_INET;
	ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_mask.sin_addr.s_addr = htonl(0xFFFFFFFF);
	s2_v4_error = in_control_ioctl(SIOCAIFADDR, &ifra, ifp,
	    curthread->td_ucred);

	/* IPv6: fe80::1:2 link-local, as IPv6CP would apply it. */
	bzero(&ifra6, sizeof(ifra6));
	strlcpy(ifra6.ifra_name, if_name(ifp), sizeof(ifra6.ifra_name));
	ifra6.ifra_addr.sin6_family = AF_INET6;
	ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_addr.sin6_addr.s6_addr[0] = 0xfe;
	ifra6.ifra_addr.sin6_addr.s6_addr[1] = 0x80;
	ifra6.ifra_addr.sin6_addr.s6_addr[14] = 0x01;
	ifra6.ifra_addr.sin6_addr.s6_addr[15] = 0x02;
	ifra6.ifra_prefixmask.sin6_family = AF_INET6;
	ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	memset(&ifra6.ifra_prefixmask.sin6_addr, 0xff, 8);
	ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	s2_v6_error = in6_control_ioctl(SIOCAIFADDR_IN6, &ifra6, ifp,
	    curthread->td_ucred);
}

static void
s2_body(void)
{
	struct ifnet *ifp;

	ifp = ifunit_ref(s2_ifname);
	if (ifp == NULL) {
		s2_v4_error = ENXIO;
		s2_v6_error = ENXIO;
		return;
	}
	s2_ioctls(ifp);
	if_rele(ifp);
}

static void
s2_apply(void *ctx __unused, int pending __unused)
{

	s2_curvnet_null = (curvnet == NULL);
#ifdef VIMAGE
	if (s2_use_curvnet) {
		CURVNET_SET(s2_vnet);
		s2_body();
		CURVNET_RESTORE();
		return;
	}
#endif
	s2_body();
}

static int
s2_sysctl_apply(SYSCTL_HANDLER_ARGS)
{
	char buf[IFNAMSIZ];
	int error;

	strlcpy(buf, s2_ifname, sizeof(buf));
	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	strlcpy(s2_ifname, buf, sizeof(s2_ifname));
#ifdef VIMAGE
	/*
	 * Capture the caller's vnet: a sysctl handler runs in a user thread,
	 * which has curvnet set; the taskqueue_thread task does not.
	 */
	s2_vnet = curvnet;
#endif
	taskqueue_enqueue(taskqueue_thread, &s2_task);
	return (0);
}

static SYSCTL_NODE(_net, OID_AUTO, s2_inaddr, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "spike S2");
SYSCTL_PROC(_net_s2_inaddr, OID_AUTO, apply,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0, s2_sysctl_apply, "A",
    "write an interface name to apply the test addresses to it");
SYSCTL_INT(_net_s2_inaddr, OID_AUTO, v4_error, CTLFLAG_RD, &s2_v4_error, 0,
    "errno from in_control_ioctl(SIOCAIFADDR)");
SYSCTL_INT(_net_s2_inaddr, OID_AUTO, v6_error, CTLFLAG_RD, &s2_v6_error, 0,
    "errno from in6_control_ioctl(SIOCAIFADDR_IN6)");
SYSCTL_INT(_net_s2_inaddr, OID_AUTO, curvnet_null, CTLFLAG_RD,
    &s2_curvnet_null, 0,
    "1 if curvnet was NULL on entry to the taskqueue_thread task");
SYSCTL_INT(_net_s2_inaddr, OID_AUTO, use_curvnet, CTLFLAG_RW,
    &s2_use_curvnet, 0,
    "run the task body inside CURVNET_SET(); 0 page-faults under VIMAGE");

static int
s2_modevent(module_t mod __unused, int type, void *data __unused)
{

	switch (type) {
	case MOD_LOAD:
		TASK_INIT(&s2_task, 0, s2_apply, NULL);
		return (0);
	case MOD_UNLOAD:
		taskqueue_drain(taskqueue_thread, &s2_task);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t s2_mod = { "s2_inaddr", s2_modevent, NULL };
DECLARE_MODULE(s2_inaddr, s2_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(s2_inaddr, 1);
