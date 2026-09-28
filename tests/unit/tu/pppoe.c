/* Unit-test TU for sys/net/if_pppoe.c: the real source, then fixtures and
 * the tests that need its statics. */
#include <net/if_pppoe.c>

#include "fx.h"

const uint8_t fx_ac_mac[6] = { 0x02, 0, 0, 0, 0, 0xaa };
const uint8_t fx_our_mac[6] = { 0x02, 0, 0, 0, 0, 0x01 };
static int fx_unit;

/* After the MTX_SYSINIT/SX_SYSINIT constructors (priority 101). */
static void __attribute__((constructor(102)))
fx_module_load(void)
{
	/* In the kernel's order: MOD_LOAD (SI_SUB_PSEUDO) comes first. */
	(void)pppoe_modevent(NULL, MOD_LOAD, NULL);
	pppoe_vnet_init(NULL);
	/* The load-time printf is not a test's business. */
	kshim_log_clear();
}

struct pppoe_softc *
fx_pppoe_new(void)
{
	struct ifnet *ifp = NULL;
	struct pppoe_softc *sc;

	KT_FX_ASSERT(kshim_clone_create(fx_unit++, &ifp) == 0);
	sc = if_getsoftc(ifp);
	/* sppp_attach() queued nothing; the link-state task is a no-op. */
	return (sc);
}

void
fx_pppoe_free(struct pppoe_softc *sc)
{
	struct ifnet *parent = sc->sc_parent;

	(void)kshim_clone_destroy(sc->sc_ifp);
	kshim_run_tasks();
	if (parent != NULL)
		kshim_tx_flush(parent);
}

struct ifnet *fx_pppoe_ifp(struct pppoe_softc *sc) { return (sc->sc_ifp); }
struct sppp *fx_pppoe_sppp(struct pppoe_softc *sc) { return (&sc->ppp); }

struct ifnet *
fx_parent_new(const char *name)
{
	struct ifnet *ifp = kshim_ifnet_new(name, IFT_ETHER);

	kshim_ifnet_set_lladdr(ifp, fx_our_mac);
	ifp->if_flags |= IFF_UP;
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	return (ifp);
}

void
fx_parent_free(struct ifnet *ifp)
{
	kshim_tx_flush(ifp);
	kshim_ifnet_free(ifp);
}

int
fx_pppoe_bind(struct pppoe_softc *sc, struct ifnet *parent)
{
	struct pppoediscparms p;

	memset(&p, 0, sizeof(p));
	strlcpy(p.ifname, sc->sc_ifp->if_xname, sizeof(p.ifname));
	strlcpy(p.eth_ifname, parent->if_xname, sizeof(p.eth_ifname));
	return (pppoe_ioctl_setparms(sc, &p));
}

int
fx_pfil_in(struct ifnet *parent, struct mbuf **mp)
{
	struct epoch_tracker et;
	int r;

	NET_EPOCH_ENTER(et);
	r = pppoe_pfil_in(mp, parent, PFIL_IN, NULL, NULL);
	NET_EPOCH_EXIT(et);
	return (r);
}

void
fx_pppoe_session_up(struct pppoe_softc *sc, uint16_t session,
    const uint8_t peer[6])
{
	PPPOE_SC_LOCK(sc);
	sc->sc_state = PPPOE_STATE_SESSION;
	sc->sc_session = session;
	memcpy(&sc->sc_dest, peer, ETHER_ADDR_LEN);
	PPPOE_SC_UNLOCK(sc);
	taskqueue_enqueue(pppoe_taskq, &sc->sc_session_task);
	kshim_run_tasks();
}

/* The fuzz build links the fixtures above but not the tests. */
#ifndef KTEST_NO_TESTS
#include "../t/pppoe_session.c"
#include "../t/pppoe_hunique.c"
#include "../t/pppoe_kpi.c"
#endif
