#!/usr/bin/env python3
"""Seed corpora for tests/unit/fuzz, built from well-formed scapy frames.

Same layers the lab suite uses (tests/functional: scapy.layers.ppp,
PPPoED); each fuzzer's input framing is documented in its fuzz/fz_*.c.
Usage: python3 corpus/gen_seeds.py corpus   (make -C tests/unit seeds)
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import scapy.layers.ppp as ppp
from scapy.layers.ppp import PPPoED, PPPoED_Tags, PPPoETag
from scapy.layers.l2 import Ether
from scapy.packet import Raw

HUNIQ = b"HUNIQUE!"  # fz_pppoe_input sets sc_hunique to this token
SESSION = 0x1234     # ...and this session id for the SESSION state


def lcp_opts() -> list[bytes]:
    C = ppp.PPP_LCP_Configure
    return [
        bytes(C(code=1, id=1, options=[ppp.PPP_LCP_MRU_Option(max_recv_unit=1492),
                                        ppp.PPP_LCP_Magic_Number_Option(magic_number=0x11223344)])),
        bytes(C(code=1, id=2, options=[ppp.PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc023)])),
        bytes(C(code=1, id=3, options=[ppp.PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm=5)])),
        bytes(C(code=1, id=4, options=[ppp.PPP_LCP_ACCM_Option(accm=0),
                                        ppp.PPP_LCP_Option(type=7, len=2), ppp.PPP_LCP_Option(type=8, len=2)])),
        bytes(C(code=1, id=5, options=[ppp.PPP_LCP_Option(type=19, len=9, data=b"\x03\x02\x00\x00\x00\x00\x01")])),
        bytes(C(code=3, id=6, options=[ppp.PPP_LCP_MRU_Option(max_recv_unit=1400)])),
        bytes(C(code=4, id=7, options=[ppp.PPP_LCP_Magic_Number_Option(magic_number=1)])),
    ]


def ipcp_opts() -> list[bytes]:
    I = ppp.PPP_IPCP
    return [
        bytes(I(code=1, id=1, options=[ppp.PPP_IPCP_Option_IPAddress(data="0.0.0.0")])),
        bytes(I(code=1, id=2, options=[ppp.PPP_IPCP_Option_IPAddress(data="100.64.0.7")])),
        bytes(I(code=3, id=3, options=[ppp.PPP_IPCP_Option_IPAddress(data="100.64.0.8"),
                                        ppp.PPP_IPCP_Option_DNS1(data="9.9.9.9"),
                                        ppp.PPP_IPCP_Option_DNS2(data="1.1.1.1")])),
        bytes(I(code=4, id=4, options=[ppp.PPP_IPCP_Option_DNS1(data="0.0.0.0")])),
        bytes(I(code=1, id=5)),
    ]


def ipv6cp_opts() -> list[bytes]:
    # scapy has no IPv6CP layer: same CP framing, option 1 = Interface-Id.
    def cp(code: int, ident: int, opts: bytes) -> bytes:
        return struct.pack("!BBH", code, ident, 4 + len(opts)) + opts
    ifid = b"\x01\x0a" + bytes.fromhex("021122fffe334455")
    return [cp(1, 1, ifid), cp(1, 2, b"\x01\x0a" + bytes(8)), cp(3, 3, ifid),
            cp(4, 4, ifid), cp(1, 5, b"")]


def pppoe_disc(code: int, session: int, tags: list[tuple[int, bytes]]) -> bytes:
    body = PPPoED(code=code, sessionid=session) / PPPoED_Tags(
        tag_list=[PPPoETag(tag_type=t, tag_value=v) for t, v in tags])
    return bytes(body)


def pppoe_seeds() -> list[bytes]:
    base = [(0x0101, b""), (0x0102, b"ac1"), (0x0103, HUNIQ)]
    out = []
    # ctl: bit0 session ethertype, bits1-2 state (1 PADI_SENT, 2 PADR_SENT,
    # 3 SESSION), bit3 RFC 4638 requested; then seglen (0 = one mbuf).
    for ctl, frame in [
        (0x02, pppoe_disc(0x07, 0, base + [(0x0104, b"COOKIE"), (0x0110, b"RLY")])),
        (0x0a, pppoe_disc(0x07, 0, base + [(0x0120, b"\x05\xdc")])),
        (0x02, pppoe_disc(0x07, 0, base + [(0x0203, b"generic error")])),
        (0x04, pppoe_disc(0x65, SESSION, base)),
        (0x0c, pppoe_disc(0x65, SESSION, base + [(0x0120, b"\x05\xdc")])),
        (0x06, pppoe_disc(0xa7, SESSION, [])),
        (0x06, pppoe_disc(0xa7, SESSION, [(0x0103, HUNIQ)])),
    ]:
        out.append(bytes([ctl, 0]) + frame)
        out.append(bytes([ctl, 17]) + frame)          # chained
    lcp = bytes(ppp.PPP(proto=0xc021)) + lcp_opts()[0]
    sess = bytes(PPPoED(code=0, sessionid=SESSION)) + lcp  # PPPoE hdr + PPP
    sess = sess[:4] + struct.pack("!H", len(lcp)) + sess[6:]
    out.append(bytes([0x07, 0]) + sess)
    out.append(bytes([0x07, 5]) + sess + bytes(20))   # padded, chained
    return out


def sppp_input_seeds() -> list[bytes]:
    def fr(proto: int, pkt: bytes) -> bytes:
        f = struct.pack("!H", proto) + pkt
        return struct.pack("!H", len(f)) + f
    pap = bytes(ppp.PPP_PAP_Request(id=1, username=b"peer", password=b"psec"))
    chal = bytes(ppp.PPP_CHAP_ChallengeResponse(code=1, id=2, value=bytes(range(16)), optional_name=b"ac"))
    echo = bytes(ppp.PPP_LCP_Echo(code=9, id=3, magic_number=0x55667788, data=b"hi"))
    lcp = lcp_opts()
    ipcp = ipcp_opts()
    v6 = ipv6cp_opts()
    # ctl: bits 0-2 phase (1 ESTABLISH .. 4 NETWORK), bits 1-2 LCP state,
    # bit3 configure auth, bit4 CHAP, bit5 we authenticate, bit6 IFF_DEBUG.
    return [
        bytes([0x03]) + fr(0xc021, lcp[0]) + fr(0xc021, lcp[5]),
        bytes([0x0b]) + fr(0xc021, lcp[1]) + fr(0xc023, pap),
        bytes([0x1b]) + fr(0xc021, lcp[2]) + fr(0xc223, chal),
        bytes([0x7c]) + fr(0xc223, chal) + fr(0xc023, pap),
        bytes([0x06]) + fr(0xc021, echo),
        bytes([0x44]) + fr(0x8021, ipcp[0]) + fr(0x8021, ipcp[2]) + fr(0x8057, v6[0]),
        bytes([0x04]) + fr(0x4321, b"\x01\x02\x03") + fr(0xc021, struct.pack("!BBHH", 8, 9, 6, 0x8021)),
        bytes([0x04]) + fr(0x0021, bytes(20)) + fr(0x0057, bytes(40)),
    ]


def write(outdir: Path, name: str, seeds: list[bytes]) -> None:
    d = outdir / name
    d.mkdir(parents=True, exist_ok=True)
    for s in seeds:
        (d / hashlib.sha1(s).hexdigest()).write_bytes(s)
    print(f"{name}: {len(seeds)} seeds")


def main() -> None:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus")
    # fz_*_confreq input: [flags][CP packet]; flags documented there.
    for name, pkts in (("lcp_confreq", lcp_opts()), ("ipcp_confreq", ipcp_opts()),
                       ("ipv6cp_confreq", ipv6cp_opts())):
        write(outdir, name, [bytes([f]) + p for p in pkts for f in (0x00, 0x3f)])
    write(outdir, "pppoe_input", pppoe_seeds())
    write(outdir, "sppp_input", sppp_input_seeds())


if __name__ == "__main__":
    main()
