/* pppoe_hash_inner() / pppoe_m2cpuid() -- sys/net/if_pppoe_netisr.c.
 * The kshim RSS hash is a stand-in (not Toeplitz): assert what the driver
 * does with it, never particular hash values. */
#include "ktest.h"

static struct mbuf *
ppp_ip4(uint8_t proto, uint16_t off, int hl, bool ports)
{
	uint8_t b[2 + 60 + 4];
	struct ip *ip = (struct ip *)(b + 2);
	size_t n;

	memset(b, 0, sizeof(b));
	b[0] = 0x00;
	b[1] = 0x21;
	ip->ip_v = 4;
	ip->ip_hl = hl;
	ip->ip_p = proto;
	ip->ip_off = htons(off);
	ip->ip_src.s_addr = htonl(0x0a000001);
	ip->ip_dst.s_addr = htonl(0x0a000002);
	n = 2 + (hl < 5 ? 20 : hl * 4);
	if (ports) {
		b[n] = 0x04; b[n + 1] = 0xd2;	/* 1234 */
		b[n + 2] = 0x00; b[n + 3] = 0x50;	/* 80 */
		n += 4;
	}
	return (kshim_mbuf_from(b, (int)n));
}

/* Rewrite the source port of a ppp_ip4(..., 5, true) frame. */
static void
ppp_ip4_sport(struct mbuf *m, uint16_t sport)
{
	be16enc(mtod(m, uint8_t *) + 2 + 20, sport);
}

KTEST(netisr_hash_inner, ipv4_tcp_hashed_with_ports)
{
	struct mbuf *a = ppp_ip4(IPPROTO_TCP, 0, 5, true);
	struct mbuf *b = ppp_ip4(IPPROTO_TCP, 0, 5, true);

	KT_ASSERT(pppoe_hash_inner(a));
	KT_ASSERT(pppoe_hash_inner(b));
	/* p2/scaling (R3): always M_HASHTYPE_OPAQUE_HASH -- a software hash,
	 * not RSS, and must not be mistaken for one. */
	KT_EQ(M_HASHTYPE_GET(a), M_HASHTYPE_OPAQUE_HASH);
	KT_EQ(a->m_pkthdr.flowid, b->m_pkthdr.flowid);	/* same flow */
	/* Ports are in the key: another source port is another flow. */
	ppp_ip4_sport(b, 4321);
	KT_ASSERT(pppoe_hash_inner(b));
	KT_ASSERT(a->m_pkthdr.flowid != b->m_pkthdr.flowid);
	m_freem(a);
	m_freem(b);
}

KTEST(netisr_hash_inner, ipv4_without_l4_is_2tuple)
{
	struct mbuf *m = ppp_ip4(IPPROTO_TCP, 0, 5, false);
	struct mbuf *a = ppp_ip4(IPPROTO_ICMP, 0, 5, true);
	struct mbuf *b = ppp_ip4(IPPROTO_ICMP, 0, 5, true);
	struct mbuf *c = ppp_ip4(IPPROTO_ICMP, 0, 5, false);

	KT_ASSERT(pppoe_hash_inner(m));
	KT_EQ(M_HASHTYPE_GET(m), M_HASHTYPE_OPAQUE_HASH);
	/* Not TCP/UDP: addrs + proto only, so the would-be port octets are
	 * not in the key -- changing them, or dropping them, is one flow. */
	ppp_ip4_sport(b, 4321);
	KT_ASSERT(pppoe_hash_inner(a));
	KT_ASSERT(pppoe_hash_inner(b));
	KT_ASSERT(pppoe_hash_inner(c));
	KT_EQ(a->m_pkthdr.flowid, b->m_pkthdr.flowid);
	KT_EQ(a->m_pkthdr.flowid, c->m_pkthdr.flowid);
	m_freem(m);
	m_freem(a);
	m_freem(b);
	m_freem(c);
}

KTEST(netisr_hash_inner, ipv4_fragment_hashed_without_ports_bad_header_unhashed)
{
	struct mbuf *frag = ppp_ip4(IPPROTO_UDP, 185, 5, true);
	struct mbuf *frag2 = ppp_ip4(IPPROTO_UDP, 185, 5, false);
	struct mbuf *hl4 = ppp_ip4(IPPROTO_UDP, 0, 4, true);
	struct mbuf *mf = ppp_ip4(IPPROTO_UDP, IP_MF, 5, true);

	/* p2/scaling (R3): a later fragment IS hashed, on addrs+proto only
	 * (it carries no ports), whatever its payload octets hold. */
	KT_ASSERT(pppoe_hash_inner(frag));
	KT_ASSERT(pppoe_hash_inner(frag2));
	KT_EQ(frag->m_pkthdr.flowid, frag2->m_pkthdr.flowid);
	KT_ASSERT(!pppoe_hash_inner(hl4));
	/* The first fragment (offset 0, MF set) carries the ports but ALSO
	 * hashes on addrs+proto only (docs/PERF-DESIGN.md "Per-flow
	 * ordering"), so every fragment of a datagram shares a workstream. */
	KT_ASSERT(pppoe_hash_inner(mf));
	KT_EQ(mf->m_pkthdr.flowid, frag->m_pkthdr.flowid);
	m_freem(frag);
	m_freem(frag2);
	m_freem(hl4);
	m_freem(mf);
}

KTEST(netisr_hash_inner, short_or_non_ip_unhashed)
{
	uint8_t one[1] = { 0 }, lcp[6] = { 0xc0, 0x21, 1, 1, 0, 4 };
	uint8_t trunc[2 + 19] = { 0x00, 0x21, 0x45 };
	struct mbuf *a = kshim_mbuf_from(one, 1);
	struct mbuf *b = kshim_mbuf_from(lcp, sizeof(lcp));
	struct mbuf *c = kshim_mbuf_from(trunc, sizeof(trunc));

	KT_ASSERT(!pppoe_hash_inner(a));
	KT_ASSERT(!pppoe_hash_inner(b));
	KT_ASSERT(!pppoe_hash_inner(c));
	m_freem(a);
	m_freem(b);
	m_freem(c);
}

KTEST(netisr_hash_inner, ipv6_udp_hashed)
{
	uint8_t b[2 + 40 + 4];
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(b + 2);
	struct mbuf *m;

	memset(b, 0, sizeof(b));
	b[1] = 0x57;
	ip6->ip6_flow = IPV6_VERSION;	/* first octet 0x60 */
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_src.s6_addr[15] = 1;
	b[2 + 40] = 0x13;		/* sport 5000 */
	b[2 + 40 + 1] = 0x88;
	m = kshim_mbuf_from(b, sizeof(b));
	KT_ASSERT(pppoe_hash_inner(m));
	KT_EQ(M_HASHTYPE_GET(m), M_HASHTYPE_OPAQUE_HASH);
	m_freem(m);
}

/* The seed of a module loaded before random(4) is seeded (loader.conf) is
 * redrawn once it is: at most one attempt a second, on pppoe_taskq,
 * then fixed for good. */
KTEST(netisr_hash_seed, unseeded_at_load_redrawn_once_seeded)
{
	struct mbuf *a = ppp_ip4(IPPROTO_TCP, 0, 5, true);
	struct mbuf *b = ppp_ip4(IPPROTO_TCP, 0, 5, true);
	uint32_t weak;
	int shared0 = taskqueue_thread->tq_enqueued;

	kshim_random_seeded = false;
	pppoe_hash_init();
	KT_ASSERT(pppoe_hash_inner(a));
	weak = a->m_pkthdr.flowid;
	KT_EQ(kshim_tasks_pending(), 0);	/* not within a second of load */
	kshim_ticks += hz;
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(kshim_run_tasks(), 1);		/* still unseeded: no change */
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(a->m_pkthdr.flowid, weak);
	kshim_random_seeded = true;
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(kshim_tasks_pending(), 0);	/* rate limited */
	kshim_ticks += hz;
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(kshim_run_tasks(), 1);
	KT_ASSERT(pppoe_hash_inner(b));
	KT_ASSERT(b->m_pkthdr.flowid != weak);	/* the seed was redrawn */
	kshim_ticks += hz;
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(kshim_tasks_pending(), 0);	/* and is fixed from now on */
	KT_EQ(a->m_pkthdr.flowid, b->m_pkthdr.flowid);
	KT_EQ(taskqueue_thread->tq_enqueued, shared0);
	m_freem(a);
	m_freem(b);
}

KTEST(netisr_hash_seed, seeded_at_load_never_redrawn)
{
	struct mbuf *a = ppp_ip4(IPPROTO_UDP, 0, 5, true);
	uint32_t f;

	pppoe_hash_init();
	KT_ASSERT(pppoe_hash_inner(a));
	f = a->m_pkthdr.flowid;
	kshim_ticks += 10 * hz;
	KT_ASSERT(pppoe_hash_inner(a));
	KT_EQ(kshim_tasks_pending(), 0);
	KT_EQ(a->m_pkthdr.flowid, f);
	m_freem(a);
}

/* m2cpuid: hashed frames by flowid, the rest by session id (p2/scaling).
 * p2/scaling's dispatch map read (pppoe_m2cpuid()) added NET_EPOCH_ASSERT();
 * pppoe_dispatch_init() was never called here, so the map stays NULL and
 * every lookup takes the plain "key % n" fallback, unchanged from before. */
KTEST(netisr_m2cpuid, spreads_by_flowid_else_session)
{
	struct pppoe_softc *sc = fx_pppoe_new();
	struct mbuf *m = kshim_mbuf_from("\x00\x21", 2);
	struct epoch_tracker et;
	u_int cpu = 99;

	NET_EPOCH_ENTER(et);
	kshim_netisr_ncpu = 1;
	KT_ASSERT(pppoe_m2cpuid(m, 0, &cpu) == m);
	KT_EQ(cpu, curcpu);
	kshim_netisr_ncpu = 4;
	M_HASHTYPE_SET(m, M_HASHTYPE_RSS_TCP_IPV4);
	m->m_pkthdr.flowid = 10;
	pppoe_m2cpuid(m, 0, &cpu);
	KT_EQ(cpu, 10 % 4);
	M_HASHTYPE_SET(m, M_HASHTYPE_NONE);
	sc->sc_session = 7;
	m->m_pkthdr.rcvif = sc->sc_ifp;
	pppoe_m2cpuid(m, 0, &cpu);
	KT_EQ(cpu, 7 % 4);
	m->m_pkthdr.rcvif = NULL;
	pppoe_m2cpuid(m, 0, &cpu);
	KT_EQ(cpu, 0);
	NET_EPOCH_EXIT(et);
	sc->sc_session = 0;
	m_freem(m);
	fx_pppoe_free(sc);
}
