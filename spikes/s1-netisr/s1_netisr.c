/*
 * Spike S1 (throwaway): does a PFIL_TYPE_ETHERNET hook plus a private netisr
 * protocol with NETISR_POLICY_CPU + NETISR_DISPATCH_HYBRID actually spread
 * PPPoE session frames across CPUs?  Evidence only; deleted logic, not a
 * dependency of if_pppoe.
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/netisr.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define	S1_NETISR_PPPOE_DATA	11	/* < NETISR_MAXPROT (16), unused */
#define	S1_PPPOE_STRIP		20	/* 14 Ethernet + 6 PPPoE */

static pfil_hook_t	s1_hook;
static counter_u64_t	s1_seen[MAXCPU];
static counter_u64_t	s1_hooked;

static uint32_t
s1_hash_inner(struct mbuf *m)
{
	const struct ip *ip;
	uint32_t h;

	if (m->m_len < sizeof(uint16_t) + sizeof(struct ip))
		return (0);
	/* 2-byte PPP protocol field is at the front after the 20-byte strip. */
	ip = (const struct ip *)(mtod(m, const uint8_t *) + sizeof(uint16_t));
	if (ip->ip_v != 4)
		return (0);
	h = ntohl(ip->ip_src.s_addr) ^ ntohl(ip->ip_dst.s_addr);
	h ^= (uint32_t)ip->ip_p << 16;
	h ^= h >> 16;
	h *= 0x85ebca6bu;
	h ^= h >> 13;
	return (h);
}

static struct mbuf *
s1_m2cpuid(struct mbuf *m, uintptr_t source __unused, u_int *cpuid)
{
	u_int n;

	n = netisr_get_cpucount();
	if (n <= 1) {
		*cpuid = curcpu;
		return (m);
	}
	*cpuid = netisr_get_cpuid(m->m_pkthdr.flowid % n);
	return (m);
}

static void
s1_data_input(struct mbuf *m)
{

	counter_u64_add(s1_seen[curcpu], 1);
	m_freem(m);
}

static struct netisr_handler s1_nh = {
	.nh_name = "s1pppoe",
	.nh_handler = s1_data_input,
	.nh_m2cpuid = s1_m2cpuid,
	.nh_proto = S1_NETISR_PPPOE_DATA,
	.nh_qlimit = 1000,
	.nh_policy = NETISR_POLICY_CPU,
	.nh_dispatch = NETISR_DISPATCH_HYBRID,
};

static pfil_return_t
s1_pfil_in(struct mbuf **mp, struct ifnet *ifp __unused, int flags __unused,
    void *ruleset __unused, struct inpcb *inp __unused)
{
	struct mbuf *m = *mp;
	const struct ether_header *eh;

	NET_EPOCH_ASSERT();

	if (m->m_len < ETHER_HDR_LEN)
		return (PFIL_PASS);
	/* A tagged frame belongs to the vlan child, not to us. */
	if ((m->m_flags & M_VLANTAG) != 0 &&
	    EVL_VLANOFTAG(m->m_pkthdr.ether_vtag) != 0)
		return (PFIL_PASS);
	eh = mtod(m, const struct ether_header *);
	if (ntohs(eh->ether_type) != ETHERTYPE_PPPOE)
		return (PFIL_PASS);

	counter_u64_add(s1_hooked, 1);
	if (m->m_pkthdr.len <= S1_PPPOE_STRIP)
		return (PFIL_PASS);
	if (m->m_len < S1_PPPOE_STRIP + sizeof(uint16_t) + sizeof(struct ip)) {
		m = m_pullup(m, MIN(m->m_pkthdr.len,
		    S1_PPPOE_STRIP + sizeof(uint16_t) + sizeof(struct ip)));
		if (m == NULL) {
			*mp = NULL;
			return (PFIL_CONSUMED);
		}
	}
	m_adj(m, S1_PPPOE_STRIP);
	m->m_pkthdr.flowid = s1_hash_inner(m);
	M_HASHTYPE_SET(m, M_HASHTYPE_OPAQUE_HASH);
	netisr_dispatch(S1_NETISR_PPPOE_DATA, m);
	*mp = NULL;
	return (PFIL_CONSUMED);
}

static int
s1_sysctl_percpu(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	int error, i;

	sbuf_new_for_sysctl(&sb, NULL, 128, req);
	for (i = 0; i < mp_maxid + 1; i++) {
		if (!CPU_ABSENT(i))
			sbuf_printf(&sb, "cpu%d=%ju ", i,
			    (uintmax_t)counter_u64_fetch(s1_seen[i]));
	}
	sbuf_printf(&sb, "hooked=%ju",
	    (uintmax_t)counter_u64_fetch(s1_hooked));
	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static SYSCTL_NODE(_net, OID_AUTO, s1_netisr, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "spike S1");
SYSCTL_PROC(_net_s1_netisr, OID_AUTO, counts,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, 0, 0, s1_sysctl_percpu, "A",
    "per-CPU handler invocations");

static int
s1_modevent(module_t mod __unused, int type, void *data __unused)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN,
		.pa_type = PFIL_TYPE_ETHERNET,
		.pa_mbuf_chk = s1_pfil_in,
		.pa_modname = "s1_netisr",
		.pa_rulname = "default",
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR,
	};
	int i;

	switch (type) {
	case MOD_LOAD:
		for (i = 0; i < MAXCPU; i++)
			s1_seen[i] = counter_u64_alloc(M_WAITOK);
		s1_hooked = counter_u64_alloc(M_WAITOK);
		netisr_register(&s1_nh);
		s1_hook = pfil_add_hook(&pha);
		pla.pa_head = V_link_pfil_head;
		pla.pa_hook = s1_hook;
		pfil_link(&pla);
		return (0);
	case MOD_UNLOAD:
		pfil_remove_hook(s1_hook);
		netisr_unregister(&s1_nh);
		for (i = 0; i < MAXCPU; i++)
			counter_u64_free(s1_seen[i]);
		counter_u64_free(s1_hooked);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t s1_mod = { "s1_netisr", s1_modevent, NULL };
DECLARE_MODULE(s1_netisr, s1_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(s1_netisr, 1);
