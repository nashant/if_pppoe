"""Object-lifetime tests for the in-kernel if_pppoe clone (fix group g2).

The teardown shapes, each one a use-after-free or black-hole the driver
used to have:

  (a) `ifconfig pppoe0 destroy` while the interface is being hit from
      every entry point -- `ping -f` and a UDP blaster on the client
      through pppoe_output(), an injected stream of well-formed session
      frames through the pfil hook -> netisr -> pppoe_data_input() ->
      sppp_input() chain, and parallel ioctl loops (pppoectl's SPPP*
      reads, ifconfig, PPPOEGETPARMS) through pppoe_ioctl() ->
      sppp_ioctl() -- looped, with the M_PPPOE malloc type flat across the
      loop.  Before the fix pppoe_clone_destroy() ran sppp_detach() (which
      destroyed pp_lock and the sppp workqueue) while ifp->if_softc still
      pointed at the softc, so every one of those entry points could reach
      dead sppp state.  That window is short, so on the old code this test
      catches it probabilistically (a 72c6ad8 run panicked with "mtx_lock()
      of destroyed mutex" in sppp_params() <- pppoe_ioctl(); another passed
      all 20 turns with a single ioctl loop, hence the parallel ones now).
      The destroy now waits for every softc hold to drain, so a hold that
      is never released would hang it: the destroy is also time-bounded.
  (b) A pppoe clone dialled INSIDE a vnet jail, torn down by `jail -r`
      with traffic still arriving: the jail's parent (an epair end) is
      if_vmove()d home -- an ifnet_departure_event in the jail's vnet, which
      must log the departure -- and the clone is destroyed by the vnet's
      SYSUNINIT, after which M_PPPOE must be back where it was.
  (c) Parent departure: a session on a vlan parent whose vlan is destroyed
      mid-session.  The clone must drop the session and the parent (the
      ifnet_departure_event handler), and a recreated vlan re-bound with
      PPPOESETPARMS must dial again by itself (the interface is still up,
      so LCP still wants the link).
  (d) PPPOESETPARMS on a live session must be refused with EBUSY rather
      than swapping the parent out from under it (a black-holed session).
  (e) `ifconfig pppoe0 vnet <jail>` on a dialled clone: it must hang up
      and let go of its vnet0 parent, dial again inside the jail on a
      parent of the jail's (which needs the softc re-linked into the jail
      vnet's softc list, where discovery looks it up), and survive being
      handed back to vnet0 by `jail -r`.
  (f) Such a moved clone destroyed away from home: from inside the jail
      (its sppp keepalive membership must have moved with it), and by a
      kldunload while the jail lives on (the jail's teardown must destroy
      it before freeing its per-vnet state).

All of them are `datapath` tests: the conftest `driver` fixture hangs up the
CLIENT seam first and re-dials it afterwards.  Every interface this file
creates on the client VM is exempted from the base system's devd/rc
autoconfiguration by conftest's session fixture (lab.RC_AUTOCONF_EXEMPT) --
otherwise devd's `pccard_ether <if> start` would `ifconfig up` and DHCP
them behind the test's back.
"""
from __future__ import annotations

import errno
import re
import socket
import threading
import time

import pytest
from scapy.all import IP, UDP, Ether, IPv6, PPPoED, Raw

from hardening_probe import (
    _client_ssh_up,
    _dmesg_leak_count,
    _serial_offset,
    _serial_panic_hits,
    _serial_tail,
    _vmstat_pppoe_row,
)
from lab import (
    auth_cfg_cmd,
    ACCEL_GW,
    PADS,
    PPPOE_STATE_INITIAL,
    PPPOE_STATE_PADI_SENT,
    PPPOE_STATE_SESSION,
    IfPppoeDriver,
    PPPoESniffer,
)

pytestmark = [pytest.mark.datapath, pytest.mark.lifecycle]

PPPOECTL = "/usr/local/sbin/pppoectl"
# Every background load of test (a) runs under daemon(8) with its pidfile
# matching this glob, so one kill tears all of it down.
LOAD_PID_GLOB = "/tmp/lifecycle-load.*.pid"
# Parallel pppoectl loops: SPPPGET* -> sppp_params() takes pp_lock, the
# exact call the pre-fix destroy raced ("mtx_lock() of destroyed mutex" in
# sppp_params() <- pppoe_ioctl(), seen on the 72c6ad8 baseline).  Several
# at once, because the pre-fix window (sppp_detach() to the if_softc NULL
# store) is short and each loop turn is a fork/exec.
SPPP_IOCTL_LOOPS = 4
# Each UDP blaster exits by itself this soon after its loop is killed, so no
# orphan keeps sending into the next iteration.
TX_BLAST_S = 3
# Generous: a destroy that waits on a leaked softc hold never returns at all.
DESTROY_BOUND_S = 30

# Fixed unit numbers, so conftest can exempt the names from devd/rc
# autoconfiguration before the interfaces exist (lab.RC_AUTOCONF_EXEMPT).
JAIL = "pppoevnet"
JAIL_CTL = "pppoevnetctl"  # clone-free control jail for M_PPPOE accounting
JAIL_EPAIR = "epair76"
JAIL_BRIDGE = "bridge76"
VLAN_EPAIR = "epair77"
VLAN_BRIDGE = "bridge77"
VLAN_CLIENT = "vlan77"  # pppoe0's parent: tag 77 on epair77a
VLAN_UNTAG = "vlan78"  # the far end: tag 77 on epair77b, bridged to vtnet1
VLAN_TAG = 77
NOAC_EPAIR = "epair79"  # a parent no AC answers on: discovery stays PADI_SENT

DESTROY_LOOPS = 20
# More parent departures than the driver's parent set has slots
# (PPPOE_MAX_PARENTS == 8 in if_pppoe.c): a departure that does not give its
# slot back makes a later re-bind fail with ENOSPC.
PARENT_CYCLES = 10


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _parse_parms(out: str) -> dict:
    """`pppoeparms -d` output -> {key: str|int}; mirrors IfPppoeDriver.parms."""
    parms = {}
    for token in out.split():
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        parms[k] = int(v) if v.isdigit() else v
    return parms


def _wait_inet(run, iface="pppoe0", timeout=25):
    """The IPCP-negotiated IPv4 address on `iface`, or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) --> ",
                      run(f"ifconfig {iface}").stdout)
        if m:
            return m.group(1)
        time.sleep(0.5)
    return None


def _dial_capturing_pads(sniffer, up, wait_state, timeout=20):
    """Bring the clone up with the sniffer running; return (parms, PADS).

    The PADS is the only place the AC's MAC and the session id are both
    visible from outside the kernel, and the RX flood below needs both.
    """
    sniffer.start()
    try:
        up()
        parms = wait_state(timeout)
        session = parms.get("session")
        pads = sniffer.wait_for(
            lambda p: p.haslayer(PPPoED)
            and p[PPPoED].code == PADS
            and p[PPPoED].sessionid == session,
            timeout=5,
        )
    finally:
        sniffer.stop()  # the flood below must not land in its buffer
    return parms, pads


class _SessionFlood:
    """Background RX load: well-formed PPPoE session frames carrying IPv4/UDP
    to the client's negotiated address (plus one IPv6 frame in four, for
    pppoe_data_input()'s IPv6 arm), sent from the AC's MAC with the live
    session id, onto br-isp from the lab host.

    Unlike traffic generated on the client VM, this keeps arriving through
    the teardown under test -- `jail -r` kills every process in the jail
    before the vnet goes, and an `ifconfig destroy` does not stop frames
    already on the wire.  Each frame takes the full RX chain: pfil hook ->
    session lookup -> netisr -> pppoe_data_input() -> sppp_input() ->
    ip_input().  A raw AF_PACKET socket (the lab host is Linux) rather than
    scapy's sendp(): sendp() opens a socket per call and cannot sustain a
    flood.
    """

    def __init__(self, dst_mac, src_mac, session, dst_ip,
                 iface=PPPoESniffer.IFACE):
        v4 = b"\x00\x21" + bytes(
            IP(src=ACCEL_GW, dst=dst_ip) / UDP(sport=9, dport=9)
            / Raw(b"f" * 512)
        )
        v6 = b"\x00\x57" + bytes(
            IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=9, dport=9)
            / Raw(b"f" * 512)
        )
        self._frames = [self._frame(dst_mac, src_mac, session, ppp)
                        for ppp in (v4, v4, v4, v6)] * 16
        self._iface = iface
        self._stop = threading.Event()
        self._thread = None
        self._sock = None
        self.sent = 0
        self.error = None

    @staticmethod
    def _frame(dst_mac, src_mac, session, ppp):
        pppoe = (b"\x11\x00" + session.to_bytes(2, "big")
                 + len(ppp).to_bytes(2, "big") + ppp)
        return bytes(Ether(dst=dst_mac, src=src_mac, type=0x8864)
                     / Raw(pppoe))

    def start(self):
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._sock.bind((self._iface, 0))
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                for frame in self._frames:
                    self._sock.send(frame)
                    self.sent += 1
            except OSError as exc:
                if exc.errno != errno.ENOBUFS:
                    self.error = exc  # the socket is unusable: stop
                    return
                time.sleep(0.001)  # tx queue full: back off, keep flooding

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        if self._sock is not None:
            self._sock.close()


def _no_panic_since(offset, what):
    tail = _serial_tail(offset)
    assert tail is not None, "client serial log unreadable -- no panic oracle"
    hits = _serial_panic_hits(tail)
    assert not hits, f"panic signature on the client console {what}: {hits}"


def _wait_vmstat_row(driver, want, timeout=10.0):
    """Poll the M_PPPOE row until it equals `want` (the softc free is a
    NET_EPOCH_CALL, so it lands shortly after the destroy returns)."""
    deadline = time.time() + timeout
    row = _vmstat_pppoe_row(driver)
    while row != want and time.time() < deadline:
        time.sleep(0.5)
        row = _vmstat_pppoe_row(driver)
    return row


# ---------------------------------------------------------------------------
# (a) clone destroy under flood, looped.
# ---------------------------------------------------------------------------
def _daemon(driver, name, loop):
    """Run the sh loop `loop` under daemon(8), pidfile per LOAD_PID_GLOB."""
    pidfile = LOAD_PID_GLOB.replace("*", name)
    r = driver.run(f"daemon -f -p {pidfile} sh -c '{loop}'", root=True)
    assert r.returncode == 0, f"background load {name}: {r.stderr}"


def _start_load(driver):
    """Background load on pppoe0 from the client VM itself, every entry
    point the destroy must quiesce:

      - SPPP_IOCTL_LOOPS pppoectl loops (SPPP* reads -> pppoe_ioctl() ->
        sppp_ioctl() -> sppp_params(), which takes pp_lock);
      - one loop of SIOCGIF* (ifconfig) and PPPOEGETPARMS (pppoeparms -d);
      - `ping -f` and a UDP blaster (nc -u from /dev/zero, 16 KiB datagrams
        fragmented to the session MTU) to the AC's address, both through
        pppoe_output() -> sppp_output().  ping -f alone drops to 100 pps
        once replies stop, which is exactly when the destroy runs.

    Errors are expected (and discarded) once pppoe0 is gone."""
    for n in range(SPPP_IOCTL_LOOPS):
        _daemon(driver, f"sppp{n}",
                f"while :; do {PPPOECTL} pppoe0 >/dev/null 2>&1; done")
    _daemon(driver, "ifioctl",
            "while :; do ifconfig pppoe0 >/dev/null 2>&1; "
            f"{driver.PARMS} -d pppoe0 >/dev/null 2>&1; done")
    _daemon(driver, "ping",
            f"exec ping -q -f -s 1400 {ACCEL_GW} >/dev/null 2>&1")
    _daemon(driver, "udp",
            f"while :; do timeout {TX_BLAST_S} nc -u {ACCEL_GW} 9 "
            "</dev/zero >/dev/null 2>&1; done")


def _stop_load(driver):
    driver.run(f"for f in {LOAD_PID_GLOB}; do [ -f $f ] && "
               "kill $(cat $f) 2>/dev/null; rm -f $f; done", root=True)


def test_clone_destroy_under_flood_is_safe_and_leak_free(driver, sniffer):
    """20x: dial, flood pppoe0 from both directions while parallel ioctl
    loops hammer it, `ifconfig pppoe0 destroy` mid-flood.  No panic, the destroy
    returns promptly (a leaked softc hold would park it in its hold-drain
    loop for good), the VM keeps answering, and M_PPPOE is flat across the
    loop (the module is loaded once, so the malloc type's counters span
    every iteration)."""
    driver.kldload()
    driver.destroy()
    before = _vmstat_pppoe_row(driver)
    assert before is not None, "vmstat -m unreadable"
    leaks_before = _dmesg_leak_count(driver)
    offset = _serial_offset()

    for i in range(DESTROY_LOOPS):
        driver.create(iface="pppoe0", parent="vtnet1", service="lab",
                      reload=False)
        parms, pads = _dial_capturing_pads(
            sniffer, lambda: driver.up("pppoe0"),
            lambda t: driver.wait_state(PPPOE_STATE_SESSION, timeout=t))
        assert parms.get("state") == PPPOE_STATE_SESSION, f"iter {i}: {parms}"
        assert pads is not None, f"iter {i}: no PADS captured for {parms}"
        inet = _wait_inet(driver.run)
        assert inet, f"iter {i}: IPCP never applied an address to pppoe0"

        flood = _SessionFlood(dst_mac=driver.mac, src_mac=pads[Ether].src,
                              session=parms["session"], dst_ip=inet)
        try:
            _start_load(driver)
            flood.start()
            time.sleep(1.0)  # let every load reach steady state
            t0 = time.monotonic()
            r = driver.run("ifconfig pppoe0 destroy", root=True, timeout=60)
            took = time.monotonic() - t0
        finally:
            flood.stop()
            _stop_load(driver)
        assert r.returncode == 0, (
            f"iter {i}: ifconfig pppoe0 destroy failed: {r.stdout}\n{r.stderr}")
        assert took < DESTROY_BOUND_S, (
            f"iter {i}: ifconfig pppoe0 destroy took {took:.1f}s -- a softc "
            "hold that is never released keeps the destroy waiting")
        assert flood.sent > 0, f"iter {i}: the RX flood never sent ({flood.error})"
        assert "pppoe0" not in driver.run("ifconfig -l").stdout.split(), (
            f"iter {i}: pppoe0 outlived its destroy")
        assert _client_ssh_up(), f"iter {i}: client VM stopped answering ssh"

    _no_panic_since(offset, f"during {DESTROY_LOOPS} destroy-under-flood cycles")
    after = _wait_vmstat_row(driver, before)
    assert after == before, (
        f"M_PPPOE not flat across {DESTROY_LOOPS} cycles: "
        f"before {before}, after {after}")
    assert _dmesg_leak_count(driver) == leaks_before, (
        "new 'leaked memory on destroy' line in dmesg")


# ---------------------------------------------------------------------------
# (b) vnet jail: dial inside, jail -r under traffic.
# ---------------------------------------------------------------------------
def _jail_gone(driver, name, timeout=30):
    """True once `name` is gone from the jail list, dying jails included.

    `jail -r` can return while the jail (and so its vnet) is still dying on
    its last reference; M_PPPOE accounting must wait for the vnet itself."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if driver.run(f"jls -d -j {name} jid").returncode != 0:
            return True
        time.sleep(0.5)
    return False


def _jail_cleanup(driver):
    for name in (JAIL, JAIL_CTL):
        driver.run(f"jail -r {name}", root=True, timeout=60)
    driver.run(f"ifconfig {JAIL_BRIDGE} destroy", root=True)
    driver.run(f"ifconfig {JAIL_EPAIR}a destroy", root=True)


def _jail_setup(driver, load_after_jail=True):
    """A persistent vnet jail holding epair76b, whose other end is bridged
    to vtnet1 (the accel segment).  Returns a jexec runner.

    load_after_jail: if_pppoe is (re)loaded AFTER the jail exists, so the
    jail's vnet gets its per-vnet init from kldload's vnet_sysinit for an
    existing vnet.  With False the module is loaded first and the jail's
    vnet_alloc() runs pppoe_vnet_init() itself -- the path that, at
    SI_SUB_PSEUDO, ran before the link pfil head existed and left the jail
    without its RX hook."""
    _jail_cleanup(driver)  # a previous crashed run's leftovers
    driver.kldunload()
    assert driver.run("kldstat -q -n if_pppoe").returncode != 0, (
        "if_pppoe still resident after kldunload")
    load = [f"kldload {driver.KO}"]
    for cmd in (
        *(() if load_after_jail else load),
        f"ifconfig {JAIL_EPAIR} create",
        f"ifconfig {JAIL_EPAIR}a up",
        f"ifconfig {JAIL_BRIDGE} create",
        f"ifconfig {JAIL_BRIDGE} addm vtnet1 addm {JAIL_EPAIR}a up",
        f"jail -c name={JAIL} host.hostname={JAIL} vnet persist "
        f"vnet.interface={JAIL_EPAIR}b",
        *(load if load_after_jail else ()),
    ):
        r = driver.run(cmd, root=True)
        assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"
    r = driver.run(f"jexec {JAIL} ifconfig {JAIL_EPAIR}b up", root=True)
    assert r.returncode == 0, f"jexec ifconfig up: {r.stdout}\n{r.stderr}"
    return lambda cmd, **kw: driver.run(f"jexec {JAIL} {cmd}", root=True, **kw)


def _jail_wait_state(jexec, want, timeout):
    deadline = time.time() + timeout
    parms = {}
    while time.time() < deadline:
        parms = _parse_parms(jexec(f"{IfPppoeDriver.PARMS} -d pppoe0").stdout)
        if parms.get("state") == want:
            break
        time.sleep(0.5)
    return parms


def _wait_iface_in_vnet0(driver, name, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if name in driver.run("ifconfig -l").stdout.split():
            return True
        time.sleep(0.5)
    return False


def _assert_mpppoe_settled(driver, before, leaks_before, what):
    """M_PPPOE back at `before`, and no leak reported by its destroy.

    `before` was sampled with vnet0 plus ONE clone-free vnet jail alive,
    and each vnet owns an M_PPPOE allocation of its own (the per-CPU
    dispatch counters, pppoe_cpu_hits_init()).  So recreate that shape --
    a fresh empty vnet jail -- and the row must match exactly once the
    torn-down jail's vnet is really gone.  Then unload the module: a
    malloc type reports anything still allocated when it is destroyed
    ("leaked memory on destroy").  The module is loaded again afterwards."""
    ctl = driver.run(f"jail -c name={JAIL_CTL} vnet persist", root=True)
    assert ctl.returncode == 0, f"control jail: {ctl.stdout}\n{ctl.stderr}"
    try:
        after = _wait_vmstat_row(driver, before, timeout=30)
    finally:
        driver.run(f"jail -r {JAIL_CTL}", root=True, timeout=60)
    assert after == before, (
        f"M_PPPOE not back after {what}: before {before}, after {after}")
    assert _jail_gone(driver, JAIL_CTL), f"{JAIL_CTL} never finished dying"
    r = driver.kldunload()
    assert driver.run("kldstat -q -n if_pppoe").returncode != 0, (
        f"kldunload after {what} did not take: {r.stderr}")
    assert _dmesg_leak_count(driver) == leaks_before, (
        f"M_PPPOE leaked across {what}:\n" + driver.run("dmesg").stdout[-2000:])
    r = driver.run(f"kldload {driver.KO}", root=True)
    assert r.returncode == 0, f"kldload: {r.stdout}\n{r.stderr}"


def test_vnet_jail_session_survives_jail_removal_under_traffic(driver, sniffer):
    """A pppoe clone dialled inside a vnet jail over an epair bridged to
    vtnet1, then `jail -r` while the session is flooded.

    `jail -r` is where the lifetime rules meet: the epair end is if_vmove()d
    back to vnet0 -- an ifnet_departure_event in the jail's vnet, before the
    jail vnet's SYSUNINIT destroys the clone -- while frames for its session
    keep arriving from the lab host.  The departure must be handled (its log
    line is the evidence the handler ran inside the dying vnet: before the
    fix nothing noticed, and the clone was destroyed still bound to an
    ifnet that had left), nothing may panic, and every M_PPPOE byte the jail
    and its clone took must come back."""
    try:
        jexec = _jail_setup(driver)
        # vnet0 plus the (clone-free) jail vnet: see _assert_mpppoe_settled.
        before = _vmstat_pppoe_row(driver)
        assert before is not None, "vmstat -m unreadable"
        for cmd in (
            "ifconfig pppoe0 create",
            "ifconfig pppoe0 down",
            f"{driver.PARMS} -e {JAIL_EPAIR}b -s lab pppoe0",
        ):
            r = jexec(cmd)
            assert r.returncode == 0, f"jexec {cmd}: {r.stdout}\n{r.stderr}"
        cmd, secret = auth_cfg_cmd(proto="pap", poctl=PPPOECTL)
        r = jexec(cmd, stdin=secret)
        assert r.returncode == 0, f"jexec {cmd}: {r.stdout}\n{r.stderr}"

        parms, pads = _dial_capturing_pads(
            sniffer, lambda: jexec("ifconfig pppoe0 up"),
            lambda t: _jail_wait_state(jexec, PPPOE_STATE_SESSION, t),
            timeout=30)
        assert parms.get("state") == PPPOE_STATE_SESSION, (
            f"the in-jail clone never reached SESSION: {parms}")
        assert pads is not None, f"no PADS captured for {parms}"
        inet = _wait_inet(jexec)
        assert inet, "IPCP never applied an address to the in-jail pppoe0"

        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        leaks_before = _dmesg_leak_count(driver)
        offset = _serial_offset()
        flood = _SessionFlood(dst_mac=pads[Ether].dst, src_mac=pads[Ether].src,
                              session=parms["session"], dst_ip=inet)
        r = jexec(f"daemon -f ping -f -s 1400 {ACCEL_GW}")
        assert r.returncode == 0, f"in-jail ping flood: {r.stderr}"
        flood.start()
        try:
            time.sleep(2.0)
            r = driver.run(f"jail -r {JAIL}", root=True, timeout=90)
            # The epair end reappearing in vnet0 is the vnet teardown's own
            # evidence, so keep flooding until then.
            returned = _wait_iface_in_vnet0(driver, f"{JAIL_EPAIR}b")
        finally:
            flood.stop()
        assert r.returncode == 0, f"jail -r failed: {r.stdout}\n{r.stderr}"
        assert returned, (
            f"{JAIL_EPAIR}b never came back to vnet0 -- the jail's vnet was "
            "not torn down")
        assert flood.sent > 0, f"the RX flood never sent ({flood.error})"
        assert _client_ssh_up(), "client VM stopped answering ssh after jail -r"
        _no_panic_since(offset, "across jail -r of a vnet with a live session")
        assert _jail_gone(driver, JAIL), f"{JAIL} never finished dying"
        dmesg = driver.run("dmesg").stdout
        assert f"pppoe0: parent {JAIL_EPAIR}b departed" in dmesg, (
            "the in-jail clone never heard its parent leave the vnet:\n"
            + dmesg[-2000:])
        # The module must still be usable in vnet0 afterwards.
        assert driver.run("kldstat -q -n if_pppoe").returncode == 0, (
            "if_pppoe vanished with the jail")
        _assert_mpppoe_settled(driver, before, leaks_before,
                               "jail -r of a vnet with a live session")
    finally:
        _jail_cleanup(driver)


def test_vnet_jail_created_after_kldload_dials(driver):
    """A vnet jail created while if_pppoe is loaded gets the RX hook: a
    clone inside it dials to SESSION and IPCP applies an address.

    vnet_alloc() runs every vnet constructor in (subsystem, order) order.
    pppoe_vnet_init() used to sit at SI_SUB_PSEUDO, ahead of
    vnet_ether_init() (SI_SUB_PROTO_IF), so pfil_link() found no link pfil
    head, dmesg said "pppoe: pfil_link(...) failed: 2", and the PADO never
    reached the clone.  At SI_SUB_PROTO_IF the head exists first."""
    try:
        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        jexec = _jail_setup(driver, load_after_jail=False)
        dmesg = driver.run("dmesg").stdout
        assert "pppoe: pfil_link" not in dmesg, (
            "the jail's vnet init could not link the pfil hook:\n"
            + dmesg[-2000:])
        for cmd in (
            "ifconfig pppoe0 create",
            "ifconfig pppoe0 down",
            f"{driver.PARMS} -e {JAIL_EPAIR}b -s lab pppoe0",
        ):
            r = jexec(cmd)
            assert r.returncode == 0, f"jexec {cmd}: {r.stdout}\n{r.stderr}"
        cmd, secret = auth_cfg_cmd(proto="pap", poctl=PPPOECTL)
        r = jexec(cmd, stdin=secret)
        assert r.returncode == 0, f"jexec {cmd}: {r.stdout}\n{r.stderr}"
        r = jexec("ifconfig pppoe0 up")
        assert r.returncode == 0, f"jexec ifconfig pppoe0 up: {r.stdout}\n{r.stderr}"
        parms = _jail_wait_state(jexec, PPPOE_STATE_SESSION, 30)
        assert parms.get("state") == PPPOE_STATE_SESSION, (
            f"a clone in a jail created after kldload never dialled: {parms}")
        assert _wait_inet(jexec), (
            "IPCP never applied an address to the in-jail pppoe0")
    finally:
        _jail_cleanup(driver)


# ---------------------------------------------------------------------------
# (c) parent departure: vlan destroyed mid-session.
# ---------------------------------------------------------------------------
def _vlan_cleanup(driver):
    for ifn in (VLAN_BRIDGE, VLAN_CLIENT, VLAN_UNTAG, f"{VLAN_EPAIR}a"):
        driver.run(f"ifconfig {ifn} destroy", root=True)


def _vlan_create_client(driver):
    cmd = (f"ifconfig {VLAN_CLIENT} create vlan {VLAN_TAG} "
           f"vlandev {VLAN_EPAIR}a up")
    r = driver.run(cmd, root=True)
    assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"


def test_parent_departure_resets_the_clone_and_rebind_redials(driver, sniffer):
    """Session on a vlan parent; `ifconfig vlan77 destroy` mid-session.

    The accel peer is on the untagged segment, so the vlan is looped back
    to it: vlan77 (tag 77 on epair77a) is pppoe0's parent, its frames cross
    the epair tagged, vlan78 (tag 77 on epair77b) untags them and a bridge
    joins vlan78 to vtnet1.

    After the destroy the clone must be back at INITIAL with no parent, the
    kernel must log the departure, and nothing may panic.  (The handler
    sends a best-effort PADT on the departing vlan first; whether a vlan
    mid-destroy still delivers it is not asserted.)  Recreating the vlan
    and re-binding it with PPPOESETPARMS (legal again at INITIAL) must dial
    a new session with no `ifconfig down/up`: the interface never went
    down, so LCP is still waiting for the lower layer.

    Then, with pppoe0 down (so no turn waits on a dial), PARENT_CYCLES more
    destroy/recreate/re-bind turns -- more than the parent set has slots.
    Every turn must drop the parent, and every re-bind must succeed: a
    departure that cleared sc_parent but never released the parent-set
    slot (pppoe_parent_del()) or the ifnet reference fills the set, and the
    ninth re-bind fails with ENOSPC.  A final `ifconfig up` must still
    dial on the last vlan."""
    mtu_before = driver.iface_state("vtnet1")["mtu"]
    assert mtu_before is not None, "could not read vtnet1's MTU"
    _vlan_cleanup(driver)
    try:
        for cmd in (
            f"ifconfig {VLAN_EPAIR} create",
            f"ifconfig {VLAN_EPAIR}a up",
            f"ifconfig {VLAN_EPAIR}b up",
            f"ifconfig {VLAN_UNTAG} create vlan {VLAN_TAG} "
            f"vlandev {VLAN_EPAIR}b up",
            f"ifconfig {VLAN_BRIDGE} create",
        ):
            r = driver.run(cmd, root=True)
            assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"
        _vlan_create_client(driver)
        # if_bridge refuses a member whose MTU it cannot bring to the
        # bridge's.  If the epair cannot carry a 1500-byte vlan payload,
        # vlan78 is 1496: seed the bridge with it so vtnet1 is the member
        # that gets lowered (restored in the finally).
        r = driver.run(f"ifconfig {VLAN_BRIDGE} addm vtnet1 addm {VLAN_UNTAG} up",
                       root=True)
        if r.returncode != 0:
            driver.run(f"ifconfig {VLAN_BRIDGE} deletem vtnet1", root=True)
            r = driver.run(
                f"ifconfig {VLAN_BRIDGE} addm {VLAN_UNTAG} addm vtnet1 up",
                root=True)
        assert r.returncode == 0, f"bridge {VLAN_BRIDGE}: {r.stdout}\n{r.stderr}"

        driver.create(iface="pppoe0", parent=VLAN_CLIENT, service="lab")
        parms, _ = _dial_capturing_pads(
            sniffer, lambda: driver.up("pppoe0"),
            lambda t: driver.wait_state(PPPOE_STATE_SESSION, timeout=t),
            timeout=30)
        assert parms.get("state") == PPPOE_STATE_SESSION, (
            f"no session over the vlan parent: {parms}")
        assert parms["parent"] == VLAN_CLIENT, parms

        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        offset = _serial_offset()
        r = driver.run(f"ifconfig {VLAN_CLIENT} destroy", root=True, timeout=60)
        assert r.returncode == 0, f"vlan destroy: {r.stdout}\n{r.stderr}"

        back = driver.wait_state(PPPOE_STATE_INITIAL, timeout=10)
        assert back.get("state") == PPPOE_STATE_INITIAL, (
            f"the session outlived its parent: {back}")
        assert back.get("session") == 0, back
        assert back.get("parent") == "", (
            f"the clone still names a departed parent: {back}")
        dmesg = driver.run("dmesg").stdout
        assert f"pppoe0: parent {VLAN_CLIENT} departed" in dmesg, (
            "no departure log line:\n" + dmesg[-2000:])
        assert _client_ssh_up(), "client VM stopped answering ssh"
        _no_panic_since(offset, "after the parent vlan was destroyed")

        _vlan_create_client(driver)
        r = driver.run(f"{driver.PARMS} -e {VLAN_CLIENT} -s lab pppoe0",
                       root=True)
        assert r.returncode == 0, (
            f"re-binding the recreated vlan at INITIAL failed: {r.stderr}")
        # No down/up: pppoe0 is still IFF_UP and its LCP is still waiting
        # for the lower layer, so the bind itself must start discovery.
        assert driver.iface_state("pppoe0")["up"], (
            "pppoe0 lost IFF_UP across the departure")
        again = driver.wait_state(PPPOE_STATE_SESSION, timeout=30)
        assert again.get("state") == PPPOE_STATE_SESSION, (
            f"re-binding the recreated vlan did not redial: {again}")
        assert again["parent"] == VLAN_CLIENT, again

        driver.down("pppoe0")
        idle = driver.wait_state(PPPOE_STATE_INITIAL, timeout=10)
        assert idle.get("state") == PPPOE_STATE_INITIAL, idle
        for i in range(PARENT_CYCLES):
            r = driver.run(f"ifconfig {VLAN_CLIENT} destroy", root=True,
                           timeout=60)
            assert r.returncode == 0, (
                f"cycle {i}: vlan destroy: {r.stdout}\n{r.stderr}")
            assert VLAN_CLIENT not in driver.run("ifconfig -l").stdout.split(), (
                f"cycle {i}: {VLAN_CLIENT} survived its destroy")
            gone = driver.parms("pppoe0")
            assert gone.get("parent") == "", (
                f"cycle {i}: the clone still names a departed parent: {gone}")
            _vlan_create_client(driver)
            r = driver.run(f"{driver.PARMS} -e {VLAN_CLIENT} -s lab pppoe0",
                           root=True)
            assert r.returncode == 0, (
                f"cycle {i}: re-bind failed -- a departure that leaks its "
                f"parent-set slot runs out after 8 (ENOSPC): "
                f"{r.stdout}\n{r.stderr}")
        _no_panic_since(offset, f"across {PARENT_CYCLES} more parent departures")
        driver.up("pppoe0")
        final = driver.wait_state(PPPOE_STATE_SESSION, timeout=30)
        assert final.get("state") == PPPOE_STATE_SESSION, (
            f"no session on the last recreated vlan: {final}")
        assert final["parent"] == VLAN_CLIENT, final
    finally:
        driver.destroy()
        _vlan_cleanup(driver)
        driver.run(f"ifconfig vtnet1 mtu {mtu_before}", root=True)


# ---------------------------------------------------------------------------
# (d) PPPOESETPARMS on a live session.
# ---------------------------------------------------------------------------
def test_setparms_on_a_live_session_is_refused_with_ebusy(driver):
    """Swapping the parent (or the service/AC names) under an established
    session black-holes it: frames keep going out the old parent's
    session while the RX hook stops recognising it.  The ioctl must fail
    with EBUSY and leave the session alone; at INITIAL it is legal again.

    Mid-discovery is refused too: bound to an epair nothing answers on,
    `ifconfig up` leaves the clone retrying PADIs in PADI_SENT, and a
    PPPOESETPARMS there must also fail with EBUSY and change nothing."""
    driver.create(iface="pppoe0", parent="vtnet1", service="lab")
    driver.up("pppoe0")
    live = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert live.get("state") == PPPOE_STATE_SESSION, live

    r = driver.run(f"{driver.PARMS} -e vtnet1 -s other pppoe0", root=True)
    assert r.returncode != 0, "PPPOESETPARMS on a live session succeeded"
    assert "busy" in (r.stderr + r.stdout).lower(), (
        f"expected EBUSY, got: {r.stdout}\n{r.stderr}")

    after = driver.parms("pppoe0")
    assert after["state"] == PPPOE_STATE_SESSION, after
    assert after["session"] == live["session"], (after, live)
    assert after["service"] == "lab", after
    assert after["parent"] == "vtnet1", after

    driver.down("pppoe0")
    back = driver.wait_state(PPPOE_STATE_INITIAL, timeout=10)
    assert back.get("state") == PPPOE_STATE_INITIAL, back
    r = driver.run(f"{driver.PARMS} -e vtnet1 -s lab pppoe0", root=True)
    assert r.returncode == 0, f"PPPOESETPARMS at INITIAL failed: {r.stderr}"

    driver.run(f"ifconfig {NOAC_EPAIR}a destroy", root=True)
    try:
        for cmd in (f"ifconfig {NOAC_EPAIR} create",
                    f"ifconfig {NOAC_EPAIR}a up",
                    f"ifconfig {NOAC_EPAIR}b up",
                    f"{driver.PARMS} -e {NOAC_EPAIR}a -s lab pppoe0"):
            r = driver.run(cmd, root=True)
            assert r.returncode == 0, f"{cmd}: {r.stdout}\n{r.stderr}"
        driver.up("pppoe0")
        disc = driver.wait_state(PPPOE_STATE_PADI_SENT, timeout=10)
        assert disc.get("state") == PPPOE_STATE_PADI_SENT, (
            f"bound to an AC-less epair, pppoe0 is not in discovery: {disc}")
        r = driver.run(f"{driver.PARMS} -e vtnet1 -s lab pppoe0", root=True)
        assert r.returncode != 0, "PPPOESETPARMS in PADI_SENT succeeded"
        assert "busy" in (r.stderr + r.stdout).lower(), (
            f"expected EBUSY in PADI_SENT, got: {r.stdout}\n{r.stderr}")
        still = driver.parms("pppoe0")
        assert still["parent"] == f"{NOAC_EPAIR}a", still
        assert still["state"] == PPPOE_STATE_PADI_SENT, still
    finally:
        driver.destroy()
        driver.run(f"ifconfig {NOAC_EPAIR}a destroy", root=True)


# ---------------------------------------------------------------------------
# (e) our own clone moved between vnets.
# ---------------------------------------------------------------------------
def _dial_pppoe0_in_vnet0(driver):
    driver.create(iface="pppoe0", parent="vtnet1", service="lab",
                  reload=False)
    driver.up("pppoe0")
    live = driver.wait_state(PPPOE_STATE_SESSION, timeout=20)
    assert live.get("state") == PPPOE_STATE_SESSION, live


def _move_pppoe0_into_jail_and_dial(driver, jexec):
    """`ifconfig pppoe0 vnet JAIL` on the dialled clone, then bind it to the
    jail's epair and dial again from inside (skip if the move is refused)."""
    r = driver.run(f"ifconfig pppoe0 vnet {JAIL}", root=True, timeout=60)
    if r.returncode != 0:
        pytest.skip("this kernel refuses to move a pppoe clone between "
                    f"vnets: {r.stderr.strip()}")
    assert "pppoe0" not in driver.run("ifconfig -l").stdout.split(), (
        "pppoe0 still in vnet0 after the move")
    moved = _jail_wait_state(jexec, PPPOE_STATE_INITIAL, 10)
    assert moved.get("state") == PPPOE_STATE_INITIAL, (
        f"the moved clone kept its vnet0 session: {moved}")
    assert moved.get("session") == 0, moved
    assert moved.get("parent") == "", (
        f"the moved clone still names a vnet0 parent: {moved}")
    dmesg = driver.run("dmesg").stdout
    assert "pppoe0: leaving its vnet" in dmesg, (
        "no vnet-move log line:\n" + dmesg[-2000:])

    for cmd in (
        "ifconfig pppoe0 down",
        f"{driver.PARMS} -e {JAIL_EPAIR}b -s lab pppoe0",
        "ifconfig pppoe0 up",
    ):
        r = jexec(cmd)
        assert r.returncode == 0, f"jexec {cmd}: {r.stdout}\n{r.stderr}"
    again = _jail_wait_state(jexec, PPPOE_STATE_SESSION, 30)
    assert again.get("state") == PPPOE_STATE_SESSION, (
        "the moved clone cannot dial inside the jail (is it linked into "
        f"the jail vnet's softc list?): {again}")
    assert again.get("parent") == f"{JAIL_EPAIR}b", again


def test_clone_moved_into_a_vnet_jail_rehomes_and_redials(driver):
    """`ifconfig pppoe0 vnet <jail>` on a dialled clone, then `jail -r`.

    Everything a softc belongs to is per-vnet: the session hash, the softc
    list discovery looks Host-Uniq up in, the parent set -- and its parent
    is an ifnet of the vnet it is leaving.  Before the fix the moved clone
    kept all of it: it still claimed its vnet0 session and parent from
    inside the jail, and stayed linked into vnet0's softc list, so a PADO
    arriving in the jail could never find it.  Now the move hangs up (PADT
    on the vnet0 parent), drops the parent, and re-links the softc into the
    jail's list: bound to the jail's epair it must dial again from inside.
    `jail -r` then hands it back to vnet0 (it was created there), where it
    must be inert and destroyable, with M_PPPOE back where it started."""
    try:
        jexec = _jail_setup(driver)
        before = _vmstat_pppoe_row(driver)
        assert before is not None, "vmstat -m unreadable"
        _dial_pppoe0_in_vnet0(driver)

        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        leaks_before = _dmesg_leak_count(driver)
        offset = _serial_offset()
        _move_pppoe0_into_jail_and_dial(driver, jexec)

        r = driver.run(f"jail -r {JAIL}", root=True, timeout=90)
        assert r.returncode == 0, f"jail -r failed: {r.stdout}\n{r.stderr}"
        assert _wait_iface_in_vnet0(driver, "pppoe0"), (
            "pppoe0 never came home to vnet0 on jail -r")
        assert _jail_gone(driver, JAIL), f"{JAIL} never finished dying"
        home = driver.wait_state(PPPOE_STATE_INITIAL, timeout=10)
        assert home.get("state") == PPPOE_STATE_INITIAL, home
        assert home.get("parent") == "", (
            f"pppoe0 came home still bound to a jail ifnet: {home}")
        assert _client_ssh_up(), "client VM stopped answering ssh"
        _no_panic_since(offset, "across a pppoe clone's vnet round trip")

        r = driver.run("ifconfig pppoe0 destroy", root=True, timeout=60)
        assert r.returncode == 0, f"destroy after the round trip: {r.stderr}"
        _assert_mpppoe_settled(driver, before, leaks_before,
                               "a pppoe clone's round trip through a jail")
    finally:
        driver.destroy()
        _jail_cleanup(driver)


# ---------------------------------------------------------------------------
# (f) a moved clone destroyed away from home: in the jail, and by kldunload.
# ---------------------------------------------------------------------------
# Two sppp keepalive periods (DEFAULT_KEEPALIVE_INTERVAL, 10 s, in
# if_spppsubr.c): every vnet's keepalive callout walks its interface list at
# least once in that time, so a freed interface left linked on one is
# touched before the test looks for a panic.
KEEPALIVE_WAIT_S = 25


def test_clone_moved_into_a_vnet_jail_can_be_destroyed_there(driver):
    """A dialled clone moved into a vnet jail and dialled again there, then
    `ifconfig pppoe0 destroy` from inside the jail.

    The sppp keepalive list is per-vnet and sppp_detach() used to unlink
    the interface from curvnet's list only.  A clone that moved without its
    keepalive membership stayed on vnet0's list, driven by vnet0's callout
    under vnet0's curvnet onto a parent in the jail -- and the destroy,
    running with curvnet set to the jail, missed it, leaving a freed
    interface for vnet0's next keepalive tick to lock.  So: destroy inside
    the jail, sit out two keepalive periods, no panic, and M_PPPOE back."""
    try:
        jexec = _jail_setup(driver)
        before = _vmstat_pppoe_row(driver)
        assert before is not None, "vmstat -m unreadable"
        _dial_pppoe0_in_vnet0(driver)

        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        leaks_before = _dmesg_leak_count(driver)
        offset = _serial_offset()
        _move_pppoe0_into_jail_and_dial(driver, jexec)

        r = jexec("ifconfig pppoe0 destroy", timeout=60)
        assert r.returncode == 0, (
            f"destroying the moved clone inside the jail: {r.stdout}\n{r.stderr}")
        assert "pppoe0" not in jexec("ifconfig -l").stdout.split(), (
            "pppoe0 outlived its destroy inside the jail")
        assert "pppoe0" not in driver.run("ifconfig -l").stdout.split(), (
            "pppoe0 reappeared in vnet0 after its destroy inside the jail")
        time.sleep(KEEPALIVE_WAIT_S)
        assert _client_ssh_up(), "client VM stopped answering ssh"
        _no_panic_since(offset, "after destroying a moved clone in its jail")

        r = driver.run(f"jail -r {JAIL}", root=True, timeout=90)
        assert r.returncode == 0, f"jail -r failed: {r.stdout}\n{r.stderr}"
        assert _jail_gone(driver, JAIL), f"{JAIL} never finished dying"
        _assert_mpppoe_settled(driver, before, leaks_before,
                               "destroying a moved clone inside its jail")
    finally:
        driver.destroy()
        _jail_cleanup(driver)


def test_kldunload_with_a_clone_moved_into_a_live_jail(driver):
    """A dialled clone moved into a vnet jail and dialled again there, then
    kldunload from vnet0 while the jail lives on.

    The clone is on vnet0's cloner but sits in the jail's vnet, on the
    jail's softc list and keepalive list.  The unload runs each per-vnet
    teardown across every vnet in turn, and if the jail's comes first its
    per-vnet counters are freed before vnet0's cloner gets to destroy the
    clone (with curvnet set to the jail): the jail's teardown must destroy
    such guests itself, first.  The module must go, taking the clone with
    it -- an ifnet left in the jail would call into unloaded code -- with
    nothing leaked and no panic across two keepalive periods."""
    try:
        jexec = _jail_setup(driver)
        _dial_pppoe0_in_vnet0(driver)

        driver.run("sysctl kern.msgbuf_clear=1", root=True)
        leaks_before = _dmesg_leak_count(driver)
        offset = _serial_offset()
        _move_pppoe0_into_jail_and_dial(driver, jexec)

        r = driver.kldunload()
        assert r.returncode == 0, f"kldunload: {r.stdout}\n{r.stderr}"
        assert driver.run("kldstat -q -n if_pppoe").returncode != 0, (
            "if_pppoe still resident after kldunload")
        assert "pppoe0" not in jexec("ifconfig -l").stdout.split(), (
            "the moved clone outlived the module that implements it")
        time.sleep(KEEPALIVE_WAIT_S)
        assert _client_ssh_up(), "client VM stopped answering ssh"
        _no_panic_since(offset, "after kldunload with a clone in a live jail")
        dmesg = driver.run("dmesg").stdout
        assert _dmesg_leak_count(driver) == leaks_before, (
            "M_PPPOE leaked across the unload:\n" + dmesg[-2000:])
        assert "pppoe: cannot destroy" not in dmesg, (
            "the jail's teardown could not destroy the guest clone:\n"
            + dmesg[-2000:])
    finally:
        _jail_cleanup(driver)
        # Not driver.destroy() with the module gone: naming pppoe0 to
        # ifconfig autoloads whatever if_pppoe.ko the module path holds.
        if driver.run("kldstat -q -n if_pppoe").returncode == 0:
            driver.destroy()
        else:
            driver.run(f"kldload {driver.KO}", root=True)
