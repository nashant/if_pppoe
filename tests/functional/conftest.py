"""Fixtures for the functional PPPoE test harness. Run ON <LAB_HOST>,
under sudo (scapy needs raw sockets on br-isp) -- see README.md and
lab/Makefile's test-func target.
"""
from __future__ import annotations

import os
import socket
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from lab import (  # noqa: E402
    CLIENT_SSH_PORT,
    AccelServer,
    IfPppoeClient,
    IfPppoeDriver,
    Mpd5Client,
    MpdsrvServer,
    PPPOE_STATE_INITIAL,
    PPPoESniffer,
    _ssh,
    exempt_from_rc_autoconf,
)

from labcreds import lab_session  # noqa: E402

# There is no fixed lab account: the session-scoped `lab_creds` fixture
# generates one per run and every dial()/create() defaults to it
# (lab.active_creds()).  See labcreds.py.
LAB_SERVICE = "lab"


def pytest_configure(config):
    for name, doc in (
        ("soak", "long-running (hours) tests, excluded by default: run with -m soak"),
        ("fuzz", "malformed-frame robustness tests"),
        ("needs_mpdsrv", "test dials the mpdsrv VM (mpd5 server) instead of accel-ppp"),
        ("datapath", "in-kernel if_pppoe discovery/session data-path tests (plan 1)"),
        ("reconnect", "reconnect-trigger tests: RTM_IFINFO DOWN/UP pair on terminate/restart_link, PADT on clone destroy, IPv6 link-local rebuild (M003 S03)"),
        ("seam_unit", "pure-Python unit tests of the IfPppoeClient runner seam; the live lab-restore fixture is skipped for them"),
        ("lifecycle", "clone/vnet teardown ordering, parent departure and live PPPOESETPARMS (test_lifecycle.py)"),
    ):
        config.addinivalue_line("markers", f"{name}: {doc}")


def _lab_reachable(timeout: float = 2.0) -> bool:
    """True when the client-VM ssh hostfwd (127.0.0.1:2223) answers.

    The functional harness is designed to run ON <LAB_HOST> (see
    README.md): VM operations go over a direct ssh to the guest's
    user-mode-NIC hostfwd and the sniffer needs raw sockets on br-isp.
    Outside the lab host the port is closed, so a bare root `pytest` run
    must skip this tier cleanly rather than error on ssh connection
    failures / missing scapy raw-socket capabilities.
    """
    try:
        with socket.create_connection(("127.0.0.1", CLIENT_SSH_PORT), timeout=timeout):
            return True
    except OSError:
        return False


LAB_REACHABLE = _lab_reachable()


def pytest_ignore_collect(collection_path, config):
    """Do not even import the functional test modules off the lab host.

    The modules import scapy at module level for raw-socket sniffing that
    only exists on <LAB_HOST>, so a bare root `pytest` run on a non-lab
    host must not fail at collection when scapy is absent either.  This
    hook is scoped to this conftest's directory (tests/functional/), so
    the offline tiers (tests/perf) are unaffected.

    One file is exempt: test_client_seam.py is a pure-Python unit test of
    the IfPppoeClient runner seam (S05 T2) -- no VM, no scapy raw
    sockets, no root -- so it is collected, and must pass, on any host.
    It imports lab.py, whose only module-level dependencies are stdlib
    (scapy is lazy), so the no-scapy protection above is preserved.
    """
    if LAB_REACHABLE:
        return False
    if collection_path.name in ("test_client_seam.py", "test_ioctl_abi_offline.py"):
        return False
    return collection_path.name.startswith("test_") and collection_path.name.endswith(".py")


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Make the off-lab behaviour visible: when the lab is unreachable the
    functional tier is not collected at all (except the pure-Python seam
    unit tests, test_client_seam.py), so say so explicitly instead of
    letting the modules vanish silently.
    """
    if not LAB_REACHABLE:
        terminalreporter.write_sep(
            "-",
            "lab VMs not reachable on 127.0.0.1:%d -- tests/functional "
            "tier ignored (run on <LAB_HOST> via `make -C lab "
            "test-func`); only the runner-seam unit tests run here"
            % CLIENT_SSH_PORT,
        )


def _wait_iface_up(client, timeout=30, poll=1.0):
    deadline = time.time() + timeout
    last = None
    restarts = 0
    while time.time() < deadline:
        last = client.iface_state()
        if last["up"] and last["inet"]:
            last["dial_stall_restarts"] = restarts
            return last
        # Dial-start stall watchdog (S05 T3, run 2 evidence: a dial whose
        # capture window held ZERO frames for 20s+ -- no destroy-PADT, no
        # PADI -- i.e. sppp never opened LCP and the pppoe FSM stays pinned
        # at PPPOE_STATE_INITIAL; the S04 born-UP clone race that the
        # forced-down workaround in _ensure_clone only mitigates).  When the
        # interface is administratively up but the driver FSM is still
        # INITIAL, force an explicit down/up cycle, which re-enters
        # SIOCSIFFLAGS and restarts LCP + discovery.  This lives here, not
        # in IfPppoeClient.dial(), because dial()'s command sequence is the
        # byte-for-byte surface the S05 T2 runner-seam contract pins in
        # test_client_seam.py.  Only driver clients expose pppoeparms state
        # (mpd5 has none), and only the INITIAL signature (no LCP ever
        # opened) triggers a restart -- a session negotiating normally, or
        # one the server refuses (PADI_SENT with retransmits running), is
        # left alone so real server-side failures stay visible.
        if restarts < 2 and hasattr(client, "parms"):
            try:
                if client.parms().get("state") == PPPOE_STATE_INITIAL:
                    restarts += 1
                    print(
                        f"_wait_iface_up: dial-stall watchdog restart #{restarts} "
                        "(FSM stuck at PPPOE_STATE_INITIAL) -- known driver "
                        "race, see S05 T3; follow-up: fix the underlying "
                        "born-UP clone race instead of masking it here"
                    )
                    client.restart_link()
            except AssertionError:
                pass  # pppoeparms unavailable -- leave the wait to time out
        time.sleep(poll)
    if last is not None:
        last["dial_stall_restarts"] = restarts
    return last


def _wait_iface_gone(client, iface="pppoe0", timeout=30, poll=0.5):
    """True once `iface` has disappeared from `ifconfig -l` on the client VM."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if iface not in client.run("ifconfig -l").stdout.split():
            return True
        time.sleep(poll)
    return False


@pytest.fixture
def client():
    which = os.environ.get("CLIENT", "mpd5")
    if which == "mpd5":
        return Mpd5Client()
    if which == "if_pppoe":
        return IfPppoeClient()
    pytest.skip(f"CLIENT={which!r} is not a supported client backend")


@pytest.fixture
def server():
    which = os.environ.get("SERVER", "accel")
    if which == "accel":
        return AccelServer()
    if which == "mpdsrv":
        return MpdsrvServer()
    if which == "hw":
        pytest.skip("SERVER=hw: the physical-router PPPoE-server backend is not implemented yet")
    pytest.skip(f"SERVER={which!r} is not a supported server backend")


@pytest.fixture
def driver(client, lab_creds):
    """Low-level if_pppoe control surface for the `datapath` tests, which
    always drive the in-kernel driver directly rather than the CLIENT seam.

    mpd5 owns both the interface name `pppoe0` and the parent `vtnet1` while
    its session is up, so `ifconfig pppoe0 create` fails with EEXIST. The
    hangup and the redial live here, not in the autouse
    `_restore_client_to_lab` fixture, so that "hang up -> test -> destroy the
    clone -> redial" is one straight line in a single fixture and does not
    depend on pytest's fixture-finalisation order.
    """
    d = IfPppoeDriver()
    # Everything after this point is inside the try: a setup-phase failure
    # (e.g. pppoe0 outliving the hangup) must still reach the redial, or mpd5
    # stays down for the rest of the session. d.destroy() on an absent
    # interface is a no-op -- IfPppoeDriver.destroy ignores the return code.
    try:
        client.hangup()
        assert _wait_iface_gone(client, "pppoe0", timeout=30), (
            "mpd5 stopped but pppoe0 is still present on the client VM; "
            "the in-kernel clone cannot take that name"
        )
        yield d
    finally:
        d.destroy()
        try:
            client.dial(service=LAB_SERVICE)
            _wait_iface_up(client, timeout=30)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            print(f"WARNING: failed to restore client to service 'lab': {exc}")


def _client_mpd5_quiesce(client_key: str):
    """Stop the client VM's mpd5 when the in-kernel driver is the client.

    MEM055 (and now the S05 slice-verification rerun): mpd5 autostarts on
    the client VM (rcvar mpd_enable), and when it runs alongside a
    CLIENT=if_pppoe suite it dials from the SAME vtnet1 MAC the driver
    uses.  Its discovery bursts (visible as ~5s-cadence PADI clusters in
    accel-ppp's "discarding PADI packet (Service-Name mismatch)" log and
    as the ng0 interface it leaves behind) interleave with the driver's
    exchanges, and a unicast PADO/PADS addressed to the shared MAC can be
    consumed by mpd5's netgraph node instead of the driver's softc -- the
    exact "redial stalls at PPPOE_STATE_PADI_SENT, no PADO" failure seen
    in the post-T4 full-suite runs (s05-t4-run-mpdsrv-1.log,
    s05-slice-accel-rerun.log) after mpd5 was restarted on the client VM
    at 05:11:50, between T3's green runs and those failures.

    The interference is bursty -- most dials land between mpd5's retries
    and pass -- which is why the failure is intermittent and passes in
    isolation.  Stopping mpd5 returns the segment to the state every
    green T3 run had: one PPPoE client per MAC.  pytest_sessionfinish
    starts it again so the VM returns to its provisioned boot state.
    """
    if not LAB_REACHABLE or client_key == "mpd5":
        return False
    r = _ssh(CLIENT_SSH_PORT, "service mpd5 onestatus")
    if r.returncode != 0:
        return False  # not running -- nothing to quiesce
    r = _ssh(CLIENT_SSH_PORT, 'echo | su -m root -c "service mpd5 stop"')
    assert r.returncode == 0, f"mpd5 stop failed: {r.stdout}\n{r.stderr}"
    time.sleep(2)  # let the netgraph node detach from vtnet1
    return True


def _client_mpd5_restore():
    """Best-effort restart of the client VM's mpd5 after a driver run.

    Mirrors run-pap.sh's teardown (which re-enables both rcvars after its
    clean mpd5-free boot): the provisioned client VM boots with mpd5
    running, so leave it that way once the suite is over.  Failures here
    must not fail the session -- the next run's quiesce guard re-stops it.
    """
    if not LAB_REACHABLE:
        return
    r = _ssh(CLIENT_SSH_PORT, 'echo | su -m root -c "service mpd5 start"')
    if r.returncode != 0:
        print(f"WARNING: could not restart mpd5 after the suite: {r.stdout}\n{r.stderr}")


@pytest.fixture(scope="session", autouse=True)
def lab_creds():
    """This run's generated PPPoE account (labcreds.lab_session): installed
    on the accel-ppp and mpdsrv tmpfs account files, the client's mpd5 conf
    dir put on tmpfs, all undone at session teardown.  None off the lab."""
    if not LAB_REACHABLE:
        yield None
        return
    with lab_session() as creds:
        yield creds


@pytest.fixture(scope="session", autouse=True)
def mpd5_quiesced(lab_creds):
    """One mpd5 stop per suite invocation when CLIENT != mpd5.

    Session-scoped (not per-test): the stop costs one ssh round trip and
    mpd5 cannot come back mid-run on its own (rcvar start is a boot-time
    event), so once per pytest process is both sufficient and the only
    placement that does not perturb per-test timing surfaces.
    """
    stopped = _client_mpd5_quiesce(os.environ.get("CLIENT", "mpd5"))
    yield
    if stopped:
        _client_mpd5_restore()


@pytest.fixture(scope="session", autouse=True)
def rc_autoconf_exempt():
    """Keep devd/rc autoconfiguration off every interface the suite creates.

    See lab.RC_AUTOCONF_EXEMPT: without it devd's `pccard_ether <if> start`
    brings fresh pppoe0 clones up (and dials them) behind the tests' backs,
    and its `stop` on a clone's DETACH reloads if_pppoe right after a
    kldunload.  Session-scoped and idempotent; the rc.conf entries are left
    in place (provision-client.sh sets the same ones).
    """
    if LAB_REACHABLE:
        exempt_from_rc_autoconf(IfPppoeDriver().run)
    yield


@pytest.fixture
def accel_server():
    """The isp-netns accel-ppp server object, regardless of SERVER.

    The tests that dial service "lab" always talk to accel-ppp -- the netns
    is up in every lab run whatever SERVER says -- so they must not inherit
    the SERVER-selected `server` fixture: under SERVER=mpdsrv that returns
    the mpdsrv VM's MpdsrvServer, the wrong peer for a service-"lab"
    session (its sessions() scrapes the mpdlab 10.99.2.x pool, its
    log_tail reads the mpdsrv VM's daemon log, and its terminate_all is
    not implemented).  Pinning the peer the test actually dials keeps
    SERVER=mpdsrv runs green without changing any accel behaviour.
    """
    return AccelServer()


@pytest.fixture
def sniffer():
    s = PPPoESniffer()
    yield s
    s.stop()  # never leave a sniffer running past its test


@pytest.fixture(autouse=True)
def _restore_client_to_lab(request, client, lab_creds):
    """Every test starts from -- and must leave -- the client dialed to
    service "lab" (accel-ppp) with an address, per the Task 6 brief's rule
    against leaving the lab in a bad state.

    `datapath` tests are exempt: the `driver` fixture does their hangup and
    their redial itself, in the order the in-kernel clone needs.

    `seam_unit` tests (test_client_seam.py) are exempt too: they are
    pure-Python unit tests of the IfPppoeClient runner seam -- every
    command goes to an injected fake runner or a monkeypatched `_ssh`, so
    they never touch the VM.  Restoring the real client after each one
    would dial the VM ~30s per test for nothing, and could mutate live
    session state while other suites were mid-run.
    """
    if "seam_unit" in request.keywords:
        yield
        return
    if "datapath" in request.keywords:
        # The `driver` fixture owns the hangup and the redial for these tests
        # (it needs them in a fixed order around d.destroy()), so this arm is
        # a no-op -- but only if the test actually requests `driver`.
        assert "driver" in request.fixturenames, (
            "datapath tests must request the driver fixture "
            "(it owns the mpd5 hangup/redial)"
        )
        yield
        return
    yield
    try:
        client.dial(service=LAB_SERVICE)
        _wait_iface_up(client, timeout=30)
    except Exception as exc:  # pragma: no cover - best-effort cleanup
        print(f"WARNING: failed to restore client to service 'lab': {exc}")


@pytest.fixture
def wait_iface_up():
    return _wait_iface_up


def pytest_sessionfinish(session, exitstatus):
    """Nothing to restore by hand any more: the suite's mpd.conf rewrites
    (Mpd5Client.dial's single "harness" label) all went to the tmpfs that
    the lab_creds fixture mounted over the client's mpd5 conf dir, and its
    teardown unmounted it -- the provisioned on-disk mpd.conf
    (provision-client.sh) is back in place, untouched.  It carries no
    account, so the client is no longer left dialed after a run."""
