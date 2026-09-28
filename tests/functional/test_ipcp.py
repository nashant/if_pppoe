"""IPCP layer: pool address, primary DNS, and iface MTU == negotiated MRU."""
from __future__ import annotations

import scapy.layers.ppp as ppp

from lab import ACCEL_GW, ACCEL_POOL_RE


def test_address_in_pool(client, wait_iface_up):
    client.dial(service="lab")
    state = wait_iface_up(client, timeout=20)
    assert state["inet"] and ACCEL_POOL_RE.match(state["inet"]), (
        f"pppoe0 inet {state['inet']!r} not in the accel-ppp pool 10.99.0.100-199"
    )
    assert state["inet_peer"] == ACCEL_GW, f"peer address {state['inet_peer']!r} != gw {ACCEL_GW}"


def _is_ipcp_dns_ack(p) -> bool:
    if not p.haslayer(ppp.PPP_IPCP):
        return False
    ipcp = p[ppp.PPP_IPCP]
    if ipcp.code != 2:  # only Configure-Ack reflects an actually-agreed value
        return False
    return any(
        opt.type == 129 and getattr(opt, "data", "0.0.0.0") != "0.0.0.0"
        for opt in ipcp.options
    )


def test_dns_requested_and_received(client, sniffer):
    sniffer.start()
    client.dial(service="lab")
    # Wait for the actual event (an IPCP Configure-Ack carrying a nonzero
    # primary-DNS option) instead of a blind sleep(2): 20s matches the other
    # dial-and-observe tests in this file and is far more generous than the
    # old fixed 2s, which could race a slow (SMPW) negotiation.
    found = sniffer.wait_for(_is_ipcp_dns_ack, timeout=20)
    sniffer.stop()
    assert found is not None, (
        "no accepted (Configure-Ack) primary-DNS IPCP option observed within 20s"
    )

    dns_values = {
        opt.data
        for p in sniffer.packets
        if _is_ipcp_dns_ack(p)
        for opt in p[ppp.PPP_IPCP].options
        if opt.type == 129 and getattr(opt, "data", "0.0.0.0") != "0.0.0.0"
    }
    assert dns_values, "no accepted (Configure-Ack) primary-DNS IPCP option observed"
    assert dns_values == {"10.99.0.1"}, f"negotiated primary DNS != 10.99.0.1: {dns_values}"


def test_iface_mtu_equals_negotiated_mru(client, sniffer, wait_iface_up):
    sniffer.start()
    client.dial(service="lab")
    state = wait_iface_up(client, timeout=20)
    sniffer.stop()

    mru_values = set()
    for p in sniffer.packets:
        if not p.haslayer(ppp.PPP_LCP_Configure):
            continue
        cfg = p[ppp.PPP_LCP_Configure]
        if cfg.code != 2:  # Configure-Ack: an agreed MRU
            continue
        for opt in cfg.options:
            if hasattr(opt, "max_recv_unit"):
                mru_values.add(opt.max_recv_unit)
    assert mru_values, "no LCP Configure-Ack MRU option observed"
    assert state["mtu"] in mru_values, f"iface mtu {state['mtu']} not among negotiated MRU values {mru_values}"
