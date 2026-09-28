"""Link events, the single link-state writer and capability flags (p3-events).

The OPNsense plugin mirrors mpd5's ppp-linkup/ppp-linkdown scripts from
devd(8) notifications the driver emits through devctl(4):

    !system=PPPOE subsystem=pppoe0 type=SESSION_UP session=N ac=MAC parent=vtnet1
    !system=PPPOE subsystem=pppoe0 type=IPCP_UP local=A remote=B dns1=C dns2=D mtu=M
    !system=PPPOE subsystem=pppoe0 type=IPCP_DOWN local=A remote=B dns1=C dns2=D mtu=M
    !system=PPPOE subsystem=pppoe0 type=IPV6CP_UP local=fe80::.. remote=fe80::.. mtu=M
    !system=PPPOE subsystem=pppoe0 type=AUTH_FAIL proto=pap|chap failures=N
    !system=PPPOE subsystem=pppoe0 type=SESSION_DOWN session=N ac=MAC

IPCP_UP / IPV6CP_UP go out from the driver's address task only after the
negotiated address is on pppoe0, so a devd action that runs core's
ppp-linkup.sh (which reads the address back from the interface) sees it.

and the base kernel's own `!system=IFNET subsystem=pppoe0 type=LINK_UP`
(if_link_state_change() -> do_link_state_change()) must fire exactly once
per dial: link state is UP iff IPCP or IPv6CP is Opened, written only by
the sppp layer.  Before this group three writers raced -- the PADS arm set
UP, every non-NETWORK sppp phase change set DOWN, NETWORK set UP again --
so each dial went UP, DOWN, UP and fired three devd LINK events.

Oracle: a devd(8) client on the client VM.  `nc -d -U /var/run/devd.pipe`
(stream socket; -d: never read stdin, so daemon(8)'s /dev/null stdin does
not end the capture) runs under daemon(8) with its output in DEVD_OUT,
through a sh read loop (DEVD_SH) that, like a devd action would, runs
`ifconfig pppoe0` the moment it reads a PPPOE *_UP record and writes the
result as a `#SNAP` line right after it (parse_devd() attaches it to that
event as "_snap").
start() does not return until the capture PROVES it is attached: a probe
`lo` clone is created and its `!system=IFNET ... type=ATTACH` must show up
first (the route-monitor lo0-probe pattern of test_reconnect.py) --
pid-alive is not proof of attachment.

The cleared-ring dmesg window (`sysctl kern.msgbuf_clear=1`, see
test_reconnect.py) is the second, independent oracle for the link-state
count: `pppoe0: link state changed to UP` is printed by the base kernel
once per real transition (if_link_state_change() dedups equal states).

Driver-only: the client must be the in-kernel stack (CLIENT=if_pppoe).
"""
from __future__ import annotations

import base64
import ipaddress
import os
import random
import re
import struct
import time

import pytest

from lab import ACCEL_GW, ACCEL_POOL_RE, _ssh_stdin

pytestmark = pytest.mark.skipif(
    os.environ.get("CLIENT", "mpd5") != "if_pppoe",
    reason="driver-specific: devctl/link-state/kern.features of the in-kernel "
    "client (CLIENT=if_pppoe)",
)

DEVD_PIPE = "/var/run/devd.pipe"
DEVD_PID = "/tmp/devd-listen.pid"
DEVD_OUT = "/tmp/devd-listen.out"
DEVD_SH = "/tmp/devd-listen.sh"
# The listener: every devd line verbatim, plus an `ifconfig pppoe0` snapshot
# taken as soon as a PPPOE IPCP_UP / IPV6CP_UP record is read.  Run as
# `sh DEVD_SH`; no `!` anywhere (not even a #! line): it travels through the
# remote login shell, which may expand history.
DEVD_SCRIPT = f"""nc -d -U {DEVD_PIPE} | while IFS= read -r l; do
\tprintf '%s\\n' "$l"
\tcase "$l" in
\t*'system=PPPOE '*' type=IPCP_UP'*|*'system=PPPOE '*' type=IPV6CP_UP'*)
\t\tprintf '#SNAP %s\\n' "$(ifconfig pppoe0 2>&1 | tr '\\n' ' ')";;
\tesac
done
"""
# pkill pattern for the listener's nc; the [/] keeps it from matching the
# `sh -c` running the pkill itself.
_NC_PAT = "'nc -d -U [/]var/run/devd.pipe'"
ACCEL_DNS1 = "10.99.0.1"  # test_ipcp.py::test_dns_requested_and_received

_EVENT_RE = re.compile(
    r"^!system=(?P<system>\S+) subsystem=(?P<subsystem>\S+) "
    r"type=(?P<type>\S+)(?: (?P<data>.*))?$"
)


def parse_devd(raw: str) -> list[dict]:
    """Parse devd `!` notification lines into dicts, in order:
    {"system", "subsystem", "type", **key=value data}.  A `#SNAP <text>`
    line (DEVD_SCRIPT) is attached to the event before it as "_snap".
    Lines of any other shape (`+`/`-`/`?` device events, partial lines)
    are skipped."""
    out = []
    for line in raw.splitlines():
        if line.startswith("#SNAP "):
            if out:
                out[-1]["_snap"] = line[len("#SNAP "):]
            continue
        m = _EVENT_RE.match(line.strip())
        if not m:
            continue
        ev = {"system": m.group("system"), "subsystem": m.group("subsystem"),
              "type": m.group("type")}
        for tok in (m.group("data") or "").split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                ev[k] = v
        out.append(ev)
    return out


def _pppoe_events(events, iface="pppoe0", types=None):
    return [e for e in events
            if e["system"] == "PPPOE" and e["subsystem"] == iface
            and (types is None or e["type"] in types)]


def _since_attach(events, iface="pppoe0"):
    """The events from the LAST `IFNET <iface> ATTACH` on: what the current
    clone did.  A destroyed predecessor's late records (IPCP_DOWN,
    SESSION_DOWN, LINK_DOWN from hangup()'s teardown, forwarded by devd
    after the listener attached) fall before it."""
    idx = [i for i, e in enumerate(events)
           if e["system"] == "IFNET" and e["subsystem"] == iface
           and e["type"] == "ATTACH"]
    return events[idx[-1]:] if idx else events


def _hangup_quiesced(client, iface="pppoe0", timeout=15.0):
    """hangup() and wait until the clone is really gone.  Its destroy path
    drains the session and address tasks (the teardown records' emitters)
    before if_detach(), so once `ifconfig` no longer finds it, no more
    records from it are coming out of the kernel."""
    client.hangup()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.run(f"ifconfig {iface}").returncode != 0:
            time.sleep(1)  # let devd forward what is already queued
            return
        time.sleep(0.5)
    pytest.fail(f"{iface} still present {timeout}s after hangup()")


def _link_events(events, iface="pppoe0"):
    """The base kernel's IFNET LINK_UP/LINK_DOWN for `iface`, in order."""
    return [e["type"] for e in events
            if e["system"] == "IFNET" and e["subsystem"] == iface
            and e["type"] in ("LINK_UP", "LINK_DOWN")]


class _DevdListener:
    """devd(8) client on the client VM; see the module docstring."""

    def __init__(self, client):
        self.client = client

    def start(self):
        c = self.client
        r = c.run(f"test -S {DEVD_PIPE}")
        if r.returncode != 0:
            pytest.fail(f"{DEVD_PIPE} is not a socket on the client VM -- "
                        "devd(8) is not running, so no devctl oracle exists")
        c.run(f"pkill -9 -f {_NC_PAT}; "
              f"kill -9 $(cat {DEVD_PID} 2>/dev/null) 2>/dev/null", root=True)
        r = c.run(f": > {DEVD_OUT}", root=True)
        assert r.returncode == 0, f"could not truncate {DEVD_OUT}: {r.stderr}"
        r = c.run(f"cat > {DEVD_SH} <<'DEVD_EOF'\n{DEVD_SCRIPT}DEVD_EOF\n",
                  root=True)
        assert r.returncode == 0, f"could not write {DEVD_SH}: {r.stderr}"
        r = c.run(
            f"daemon -f -p {DEVD_PID} sh -c "
            f"'sh {DEVD_SH} > {DEVD_OUT} 2>&1'",
            root=True, timeout=10,
        )
        assert r.returncode == 0, f"daemon devd listener failed: {r.stderr}"
        # Attach proof: a probe lo clone's IFNET ATTACH must be captured.
        unit = random.randint(200, 250)
        probe = f"lo{unit}"
        c.run(f"ifconfig {probe} destroy", root=True)
        deadline = time.time() + 8
        while time.time() < deadline:
            c.run(f"ifconfig {probe} create", root=True)
            c.run(f"ifconfig {probe} destroy", root=True)
            raw = c.run(f"cat {DEVD_OUT}", root=True).stdout
            if f"subsystem={probe} type=ATTACH" in raw:
                return
            time.sleep(0.5)
        self.stop()
        raise RuntimeError(
            "devd listener never attached -- the probe lo clone's IFNET "
            "ATTACH was never captured, so event assertions would pass or "
            "fail vacuously"
        )

    def read(self) -> list[dict]:
        return parse_devd(self.client.run(f"cat {DEVD_OUT}", root=True).stdout)

    def wait_for(self, pred, timeout=30.0, poll=0.5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            evs = self.read()
            hit = [e for e in evs if pred(e)]
            if hit:
                return hit[0], evs
            time.sleep(poll)
        return None, self.read()

    def stop(self) -> list[dict]:
        evs = self.read()
        # daemon(8) -p names the sh; its nc and read-loop children go too.
        self.client.run(f"pkill -9 -f {_NC_PAT}; "
                        f"kill -9 $(cat {DEVD_PID} 2>/dev/null) 2>/dev/null",
                        root=True)
        return evs


@pytest.fixture
def devd(client):
    listener = _DevdListener(client)
    try:
        yield listener
    finally:
        listener.stop()


def _dmesg_clear(client):
    r = client.run("sysctl kern.msgbuf_clear=1", root=True)
    assert r.returncode == 0, f"kern.msgbuf_clear failed: {r.stderr}"


def _dmesg_link_changes(client, iface="pppoe0"):
    out = []
    for line in client.run("dmesg").stdout.splitlines():
        if f"{iface}: link state changed to UP" in line:
            out.append("UP")
        elif f"{iface}: link state changed to DOWN" in line:
            out.append("DOWN")
    return out


def _fmt(evs):
    return "\n".join(str(e) for e in evs[-40:])


def _dial_lab(client, wait_iface_up, **kw):
    client.dial(service="lab", **kw)
    st = wait_iface_up(client, timeout=30)
    assert st["up"] and st["inet"], f"dial did not complete: {st['raw']}"
    return st


# ---------------------------------------------------------------------------
# (1) devctl notifications
# ---------------------------------------------------------------------------


def test_dial_emits_session_up_then_ipcp_up_with_negotiated_values(
        client, devd, wait_iface_up):
    """One dial -> SESSION_UP (session id, AC MAC, parent) then IPCP_UP whose
    local/remote/dns1/mtu equal what the interface actually got.  Only the
    new clone's records count (_since_attach): the previous clone's
    teardown records may still be forwarded after the listener attaches."""
    _hangup_quiesced(client)
    devd.start()
    st = _dial_lab(client, wait_iface_up)
    ipcp_up, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "IPCP_UP", timeout=15)
    assert ipcp_up is not None, f"no PPPOE IPCP_UP event:\n{_fmt(evs)}"
    evs = _since_attach(evs)
    assert ipcp_up["subsystem"] == "pppoe0"
    assert ipcp_up.get("local") == st["inet"], (ipcp_up, st["raw"])
    assert ACCEL_POOL_RE.match(ipcp_up["local"]), ipcp_up
    assert ipcp_up.get("remote") == ACCEL_GW == st["inet_peer"], ipcp_up
    assert ipcp_up.get("dns1") == ACCEL_DNS1, ipcp_up
    assert "dns2" in ipcp_up, ipcp_up  # key always present (0.0.0.0 if none)
    assert int(ipcp_up.get("mtu", "-1")) == st["mtu"], (ipcp_up, st["mtu"])

    sess = _pppoe_events(evs, types=("SESSION_UP",))
    assert len(sess) == 1, f"expected one SESSION_UP:\n{_fmt(evs)}"
    parms = client.parms()
    assert int(sess[0]["session"]) == parms["session"] != 0, (sess[0], parms)
    assert re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", sess[0]["ac"]), sess[0]
    assert sess[0]["parent"] == "vtnet1", sess[0]
    ppp = _pppoe_events(evs)
    assert ppp.index(sess[0]) < ppp.index(ipcp_up), (
        f"SESSION_UP must precede IPCP_UP:\n{_fmt(evs)}")
    assert not _pppoe_events(evs, types=("IPCP_DOWN", "SESSION_DOWN",
                                         "AUTH_FAIL")), _fmt(evs)


def test_ipcp_up_arrives_after_the_address_is_applied(
        client, devd, wait_iface_up):
    """mpd5 runs its up-script only after it has addressed the interface,
    and core's ppp-linkup.sh reads the address back from pppoe0.  So when
    the listener reads IPCP_UP and at once runs `ifconfig pppoe0` (what a
    devd action does), pppoe0 must already carry `inet LOCAL --> REMOTE`
    with the event's values.  (A necessary-condition oracle: the snapshot
    is taken a fork+exec after the read, so an address applied within that
    window would also pass; the kernel side orders it strictly -- IPCP_UP
    leaves pppoe_addr_apply() after its SIOCAIFADDR.)"""
    _hangup_quiesced(client)
    devd.start()
    _dial_lab(client, wait_iface_up)
    ipcp_up, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "IPCP_UP", timeout=15)
    assert ipcp_up is not None, f"no PPPOE IPCP_UP event:\n{_fmt(evs)}"
    snap = ipcp_up.get("_snap")
    assert snap is not None, (
        f"listener wrote no #SNAP after IPCP_UP:\n{_fmt(evs)}")
    want = f"inet {ipcp_up['local']} --> {ipcp_up['remote']} "
    assert want in snap + " ", (
        f"pppoe0 did not carry {want.strip()!r} when IPCP_UP was read:\n"
        f"{snap}")


def test_padt_emits_ipcp_down_and_session_down(
        client, accel_server, devd, wait_iface_up):
    """Server-side terminate -> PADT -> IPCP_DOWN naming the address that
    went away, and SESSION_DOWN naming the session that closed."""
    st = _dial_lab(client, wait_iface_up)
    session = client.parms()["session"]
    devd.start()
    accel_server.terminate_all("hard")
    down, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "IPCP_DOWN",
        timeout=20)
    assert down is not None, f"no PPPOE IPCP_DOWN after PADT:\n{_fmt(evs)}"
    assert down["subsystem"] == "pppoe0"
    assert down.get("local") == st["inet"], (down, st["inet"])
    assert down.get("remote") == ACCEL_GW, down
    sd, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "SESSION_DOWN",
        timeout=10)
    assert sd is not None, f"no PPPOE SESSION_DOWN after PADT:\n{_fmt(evs)}"
    assert int(sd["session"]) == session, (sd, session)


def test_bad_password_emits_auth_fail(client, devd):
    """A PAP Authenticate-Nak from the AC -> AUTH_FAIL proto=pap, and never
    an IPCP_UP."""
    _hangup_quiesced(client)
    devd.start()
    client.dial(service="lab", password="definitely-wrong",
                accept=("pap",))
    af, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "AUTH_FAIL",
        timeout=30)
    assert af is not None, f"no PPPOE AUTH_FAIL for a bad password:\n{_fmt(evs)}"
    assert af["subsystem"] == "pppoe0"
    assert af.get("proto") == "pap", af
    assert int(af.get("failures", "0")) >= 1, af
    assert not _pppoe_events(evs, types=("IPCP_UP",)), _fmt(evs)


@pytest.mark.needs_mpdsrv
def test_ipv6cp_up_event_names_the_applied_link_local(client, devd,
                                                      wait_iface_up):
    """Against mpdsrv (the only peer that opens IPv6CP, see test_ipv6cp.py):
    IPV6CP_UP carries the link-local IPv6CP applied to pppoe0, and that
    link-local is already on pppoe0 when the record is read (the #SNAP)."""
    client.run("sysctl net.inet6.ip6.dad_count=0", root=True)
    _hangup_quiesced(client)
    devd.start()
    client.dial(service="mpdlab")
    wait_iface_up(client, timeout=30)
    up6, evs = devd.wait_for(
        lambda e: e["system"] == "PPPOE" and e["type"] == "IPV6CP_UP",
        timeout=20)
    assert up6 is not None, f"no PPPOE IPV6CP_UP against mpdsrv:\n{_fmt(evs)}"
    deadline = time.time() + 20
    ll = None
    while time.time() < deadline and not ll:
        ll = client.iface_state()["inet6_ll"]
        time.sleep(1)
    assert ll, "no link-local on pppoe0 after IPv6CP"
    assert (ipaddress.IPv6Address(up6["local"])
            == ipaddress.IPv6Address(ll)), (up6, ll)
    assert ipaddress.IPv6Address(up6["remote"]).is_link_local, up6
    snap = up6.get("_snap") or ""
    snap_ll = re.findall(r"inet6 (fe80::[0-9a-f:]+)", snap)
    assert any(ipaddress.IPv6Address(a) == ipaddress.IPv6Address(up6["local"])
               for a in snap_ll), (
        f"pppoe0 did not carry {up6['local']} when IPV6CP_UP was read:\n"
        f"{snap}")


# ---------------------------------------------------------------------------
# (2) single link-state writer
# ---------------------------------------------------------------------------


def test_one_link_up_per_dial_no_flap(client, devd, wait_iface_up):
    """A dial from a fresh clone moves link state DOWN -> UP exactly once:
    one IFNET LINK_UP, no LINK_DOWN after it, one dmesg `changed to UP`.
    The old three-writer code produced UP (PADS), DOWN (ESTABLISH phase),
    UP (NETWORK phase)."""
    _hangup_quiesced(client)
    devd.start()
    _dmesg_clear(client)
    _dial_lab(client, wait_iface_up)
    time.sleep(5)  # let LCP/IPv6CP settle: a late flap must land in-window
    evs = _since_attach(devd.read())
    links = _link_events(evs)
    dmesg = _dmesg_link_changes(client)
    assert links.count("LINK_UP") == 1, (
        f"expected exactly one IFNET LINK_UP for pppoe0 per dial, saw "
        f"{links}\n{_fmt(evs)}")
    assert "LINK_DOWN" not in links[links.index("LINK_UP"):], links
    assert dmesg.count("UP") == 1, f"dmesg link changes: {dmesg}"
    assert "DOWN" not in dmesg[dmesg.index("UP"):], dmesg
    # Link UP is the NCP opening, not the PADS; IPCP_UP follows once the
    # address task has applied the address.
    ppp_types = [e["type"] for e in _pppoe_events(evs)]
    assert "IPCP_UP" in ppp_types, _fmt(evs)


def test_restart_link_is_one_down_then_one_up(client, devd, wait_iface_up):
    """`ifconfig down; ifconfig up` on a live session: exactly one LINK_DOWN
    then exactly one LINK_UP (the old code visited DOWN/UP twice)."""
    _dial_lab(client, wait_iface_up)
    devd.start()
    client.restart_link()
    st = wait_iface_up(client, timeout=60)
    assert st["up"] and st["inet"], st["raw"]
    time.sleep(3)
    evs = devd.read()
    assert _link_events(evs) == ["LINK_DOWN", "LINK_UP"], _fmt(evs)


# ---------------------------------------------------------------------------
# (4) capability framework
# ---------------------------------------------------------------------------


def test_kern_features_advertises_linkevents(client):
    """The plugin gates eligibility on kern.features.if_pppoe_* (FEATURE(9));
    the sysctl exists only while the module is loaded."""
    r = client.run("sysctl -n kern.features.if_pppoe_linkevents")
    assert r.returncode == 0 and r.stdout.strip() == "1", (
        f"kern.features.if_pppoe_linkevents missing: {r.stdout}{r.stderr}")


def _fetch_ko(client) -> bytes:
    """The deployed if_pppoe.ko's bytes, base64 over the ssh channel."""
    r = client.run(f"openssl base64 -in {client.KO}", root=True, timeout=60)
    assert r.returncode == 0, f"could not read {client.KO}: {r.stderr}"
    return base64.b64decode("".join(r.stdout.split()))


def _tied_depend(osreldate: int) -> bytes:
    """DECLARE_MODULE_TIED(...) emits MODULE_DEPEND(if_pppoe, kernel, V, V,
    V) with V = the build's __FreeBSD_version: a struct mod_depend {int
    md_ver_minimum, md_ver_preferred, md_ver_maximum} of three equal ints
    in the module's data.  Plain DECLARE_MODULE has maximum
    MODULE_KERNEL_MAXVER (the branch's x99999), so this triple is absent."""
    return struct.pack("<3i", osreldate, osreldate, osreldate)


def test_module_depends_on_exactly_the_running_kernel(client):
    """The .ko's kernel dependency is pinned min == pref == max ==
    kern.osreldate (spec item 4: DECLARE_MODULE_TIED).  The base commit's
    DECLARE_MODULE fails this: its maximum is MODULE_KERNEL_MAXVER."""
    osreldate = int(client.sysctl("kern.osreldate"))
    ko = _fetch_ko(client)
    n = ko.count(_tied_depend(osreldate))
    assert n == 1, (
        f"expected one mod_depend {{{osreldate},{osreldate},{osreldate}}} "
        f"in {client.KO}, found {n}: the module is not tied to this kernel")


def test_module_refuses_to_load_on_a_foreign_kernel(client):
    """Rewrite the tied kernel dependency to osreldate+1 (a kernel newer
    than the running one) and kldload the copy: the kernel linker must
    refuse it (`KLD ...: depends on kernel - not available or version
    mismatch`) and leave no if_pppoe module loaded.  The real module is
    reloaded afterwards; the autouse restore fixture redials."""
    osreldate = int(client.sysctl("kern.osreldate"))
    ko = _fetch_ko(client)
    tied = _tied_depend(osreldate)
    assert ko.count(tied) == 1, "module not tied (see the test above)"
    foreign = ko.replace(tied, _tied_depend(osreldate + 1))
    path = "/tmp/if_pppoe_foreign.ko"
    b64 = base64.b64encode(foreign).decode()
    b64 = "".join(b64[i:i + 64] + "\n" for i in range(0, len(b64), 64))
    r = _ssh_stdin(client.port, f"openssl base64 -d -out {path}", b64,
                   timeout=60)
    assert r.returncode == 0, f"could not write {path}: {r.stderr}"
    try:
        client.run("ifconfig pppoe0 destroy", root=True)
        client.kldunload()
        assert client.run("kldstat -q -n if_pppoe").returncode != 0, (
            "if_pppoe still loaded; the foreign load would fail vacuously "
            "with EEXIST")
        _dmesg_clear(client)
        r = client.run(f"kldload {path}", root=True)
        assert r.returncode != 0, (
            f"kldload accepted a module tied to kernel {osreldate + 1} on "
            f"kernel {osreldate}: {r.stdout}{r.stderr}")
        assert client.run("kldstat -q -n if_pppoe").returncode != 0
        dmesg = client.run("dmesg").stdout
        assert re.search(r"depends on kernel", dmesg), (
            f"refusal was not the kernel dependency check:\n{dmesg[-2000:]}\n"
            f"{r.stdout}{r.stderr}")
    finally:
        client.run(f"rm -f {path}", root=True)
        client.kldload()
