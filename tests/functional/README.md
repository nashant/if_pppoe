# tests/functional — PPPoE functional test harness (pytest + scapy)

Validates the lab's PPPoE discovery/LCP/IPCP/IPv6CP behavior against the
known-good `mpd5` client (Task 5's `client` VM) before this harness is later
pointed at the in-kernel `if_pppoe` driver. Runs **on `<LAB_HOST>`**
(scapy needs raw sockets on `br-isp`), driven from anywhere via
`lab/Makefile`.

## Running

`<LAB_HOST>` below is your lab host running the VM/netns harness (see
`lab/vm/README.md`, `lab/isp-netns/README.md`) -- substitute its real
hostname, or export it as `VMHOST`/an ssh config alias for the `lab/`
tooling that reads it from the environment.

```
make -C lab test-func CLIENT=mpd5 SERVER=accel
```

`test-func` rsyncs this directory to `<LAB_HOST>:~/if_pppoe-lab/tests-functional/`
and runs `pytest -m "not soak"` there under `sudo` (needed for scapy's raw
sockets and for `ip netns exec isp accel-cmd ...`). One-time host prereq if
`venv/bin/python3` doesn't exist yet: `python3-venv`/`python3.12-venv` must
be installed (`sudo apt-get install -y python3.12-venv` on <LAB_HOST>) --
`test-func` creates and populates the venv itself after that, idempotently.

`CLIENT` (`mpd5` | `if_pppoe`) and `SERVER` (`accel` | `mpdsrv` | `hw`)
select the fixture backends; only `mpd5` and `accel`/`mpdsrv` are
implemented today (see "Plugging in a new client/server" below).

Select other subsets directly with `-k`/`-m`, e.g.:
```
ssh <LAB_HOST> 'cd if_pppoe-lab && sudo venv/bin/python3 -m pytest tests-functional -m fuzz'
ssh <LAB_HOST> 'cd if_pppoe-lab && sudo venv/bin/python3 -m pytest tests-functional -m soak'   # 24h, not run by default
```

## Markers

- `soak` — long-running (hours) tests; excluded by `-m "not soak"`, the
  default `test-func` selection. `test_soak.py` holds the mpd5 24h redial
  loop and (with `CLIENT=if_pppoe`) the driver's 24h session soak
  (`test_if_pppoe_24h_soak_no_leak_no_drop`, S04 T1): one live session with
  continuous ping traffic (`daemon -f`, pid file `/tmp/soak.pid` on the
  client VM), which additionally asserts no `M_PPPOE` growth (InUse <= 4
  over the run), no `netstat -Q` QDrops on the `pppoe` netisr protocol row,
  and no `net.pppoe.tx_errors`; a session-down failure embeds the
  accel-ppp log tail in the message. The hourly checks live in the
  module-level `soak_hourly_check()` helper so S05's sustained multi-flow
  run can import them. Run the driver soak detached (24h wall-clock, do
  not run other lab work on the client VM while the clock runs):

  ```sh
  ssh <LAB_HOST> 'cd if_pppoe-lab && nohup sudo env CLIENT=if_pppoe \
      SERVER=accel venv/bin/python3 -m pytest tests-functional \
      -m soak -k no_leak_no_drop -v > /tmp/soak.log 2>&1 &'
  ```

  `-k no_leak_no_drop` selects exactly the driver soak: under
  `CLIENT=if_pppoe` a bare `-m soak` would also collect the mpd5 redial
  loop and the datapath PADI-backoff case. Poll with
  `pgrep -af "pytest.*-m soak"` + `tail /tmp/soak.log`; the expected verdict
  is `1 passed in ~864xx s`.
- `fuzz` — malformed-PPPoE-frame robustness tests (`test_fuzz.py`). Included
  by default (only `soak` is excluded).
- `needs_mpdsrv` — test dials the `mpdsrv` VM (a second, non-accel-ppp mpd5
  PPPoE server) instead of the default accel-ppp backend.
- `test_scaling.py` (`datapath`; its redial-under-traffic case also
  `lifecycle`) — the p2/scaling data path (docs/PERF-DESIGN.md): flow
  spreading within `net.pppoe.dispatch_cpus`, one flow and one
  datagram's fragments on one worker, the one-prepend IP transmit frame
  and counters, redials and dispatch-map swaps under traffic.
- `lifecycle` — clone/vnet teardown ordering (`test_lifecycle.py`): destroy
  under a two-way flood plus an ioctl loop (20x, M_PPPOE flat, destroy
  time-bounded), a clone dialled inside a vnet jail torn down by `jail -r`
  (departure logged, M_PPPOE back), parent (vlan) departure mid-session with
  a rebind that redials by itself (then 10 more departures, past the parent
  set's 8 slots), PPPOESETPARMS on a live session and mid-discovery (EBUSY),
  a dialled clone moved into a vnet jail and back, and such a moved clone
  destroyed inside the jail and by a kldunload with the jail alive.  Also
  `datapath`.  It creates `epair76`/`bridge76`/`epair77`/`bridge77`/
  `vlan77`/`vlan78`/`epair79` and the jails `pppoevnet`/`pppoevnetctl` on
  the client VM, all torn down
  again, and kldunloads/reloads if_pppoe around the jail tests; the names are in
  `lab.RC_AUTOCONF_EXEMPT`, which conftest marks NOAUTO in the VM's rc.conf
  so devd does not configure (and, for pppoe0, dial) them behind the tests.

## Fixtures (`conftest.py` / `lab.py`)

- `client` — selected by `CLIENT` env var. `mpd5` gives an `Mpd5Client`
  wrapping ssh to the `client` VM: `dial(service, user, password, mtu=None,
  max_payload=None, accept=("pap","chap","eap"))` rewrites `mpd.conf` to a
  single `harness:` label and restarts mpd5; `hangup()`, `restart_link()`,
  `iface_state()` (`inet`/`inet_peer`/`inet6_ll`/`mtu`/`flags`/`up`),
  `run(cmd, root=False)`. `if_pppoe` gives an `IfPppoeClient` that drives
  the in-kernel client (S02/S03) through `pppoectl(8)` (S05 T1, the
  verbatim NetBSD tool, R005) over the SPPP* ioctl surface: `dial()`
  (re)creates the `pppoe0` clone, binds the parent with `pppoectl -e`,
  programs `myauthproto`/`myauthname`/`myauthsecret` (+ `passiveauthproto`
  when several methods are allowed), `query-dns=3` and the ~10s keepalive
  via pppoectl, then `ifconfig pppoe0 up`; `hangup()` destroys the clone;
  `restart_link()` down/up re-dials; `iface_state()`/`run()` as the driver.
- `server` — selected by `SERVER` env var. `accel` gives an `AccelServer`
  (`sessions()`, `terminate_all()`, `set_option("service-name"|"ac-name",
  v)` via live `accel-cmd`, `log_tail()`); `mpdsrv` gives a much thinner
  `MpdsrvServer` (ssh-scraped `sessions()`/`log_tail()` only -- mpd5 has no
  accel-cmd-equivalent control API in this lab). `hw` is a stub.
- `sniffer` — a `PPPoESniffer` (scapy `AsyncSniffer` on `br-isp`, filtered
  to `pppoed or pppoes`). `.start()`/`.stop()`, `.packets`, `.wait_for(pred,
  timeout)`. Always stopped at teardown (never leaves a sniffer running).
- an autouse fixture redials the client to service `lab` after every test
  (so one test's failure state doesn't leak into the next), and
  `pytest_sessionfinish` in `conftest.py` writes back the pristine two-label
  `mpd.conf` (byte-identical to `provision-client.sh`'s) at the very end,
  so `verify-lab.sh` and friends keep working unmodified after this suite
  has been rewriting `mpd.conf` mid-run.

## Off the lab host: the tier is ignored, not failed

`conftest.py` probes the client-VM ssh hostfwd (`127.0.0.1:2223`) at import
and, when it does not answer, **ignores the directory at collection**
(`pytest_ignore_collect`) instead of failing every test on ssh connection
refused — and, because the test modules import scapy at module level,
failing at collection when scapy is absent too.  A bare `pytest` from the
repo root therefore runs the offline tiers (`tests/perf`) and reports the
functional tier as ignored with an explanatory terminal line, while
`make -C lab test-func` on <LAB_HOST> (where the port answers) is
completely unaffected.

One file is exempt from that gate: `test_client_seam.py` is a pure-Python
unit test of the `IfPppoeClient` runner seam (below) — no VM, no scapy raw
sockets, no root — so it is collected on every host and must pass wherever
pytest runs it.

## Xfail policy: zero xfails (M002 S05 T4)

The M002 end-state suite carries **no xfail markers anywhere**. The two
xfails that existed through S05 T3 are now passing tests:

- `test_lcp.py::test_mru_mtu_1500_with_mpdsrv` (`needs_mpdsrv`) -- was
  xfailed because the mpd5 *client* never emits the RFC 4638
  PPP-Max-Payload tag; the in-kernel `if_pppoe` client does, so the test
  now asserts the PADI offer (tag 0x0120 = 1500) and the peer-honoring
  RFC 4638 §5.1 MTU write-back (expected MTU computed from the captured
  PADS grant -- 1492 against today's tag-silent mpd5 5.9_19 server, live-
  re-proven during the flip).  The full 1500-byte payload round-trip stays
  an M003 item (`lab/vm/README.md` "Known issue").
- `test_ipv6cp.py::test_ipv6cp_negotiated_and_link_local` -- was xfailed
  because it dialed accel-ppp, whose PPP kernel driver refuses IPv6
  outright.  It now dials the mpdsrv service (`needs_mpdsrv`) where IPv6CP
  negotiates to Opened and the negotiated fe80:: is applied in-kernel.
  The accel-ppp exception itself is asserted positively by
  `test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only` (Configure-Requests
  go out, no Configure-Ack ever) -- an accel-side limitation that can
  never complete is pinned as a passing assertion, not an expected failure.

## Lab config change made for this task

`lab/isp-netns/accel-ppp.conf` gained a `[dns]` section (`dns1=10.99.0.1`)
-- it was previously absent, so IPCP's `req-pri-dns` had no DNS server to
hand out (`test_ipcp.py::test_dns_requested_and_received` needs one). Per
the brief, re-rendered and restarted via `up.sh` itself (its `sed` render
of `accel-ppp.conf` -> `accel-ppp.rendered.conf` at `up.sh:72`, re-run) --
confirmed live: the session's IPCP Configure-Ack now carries option 129
(Primary-DNS) = `10.99.0.1`.

## Plugging in a new server (and later clients)

Add a class in `lab.py` implementing the same `server` surface used above,
then extend `conftest.py`'s `server` fixture to return it for that env-var
value instead of `pytest.skip()`-ing.  No test file should need to change --
they only go through the fixtures.

## The if_pppoe backend (CLIENT=if_pppoe)

`CLIENT=if_pppoe SERVER=accel` runs the whole suite against the in-kernel
`if_pppoe`/sppp client (`IfPppoeClient` in `lab.py`) instead of mpd5, with
credentials and control surface driven by the ported `pppoectl(8)` (S05 T1,
verbatim NetBSD, R005).  This is the harness that gates the driver: it
dials, authenticates (PAP/CHAP-MD5), negotiates IPv4+IPCP with the accel
pool DNS, and carries traffic -- no mpd5 anywhere.

Datapath PPP-layer coverage lives in `test_datapath.py` (`test_lcp_echo_*
_sent_at_keepalive_cadence`, `test_pap_auth_negotiated_through_pppoectl`,
`test_chap_auth_negotiated_through_pppoectl`,
`test_ipcp_negotiates_pool_address_and_dns_through_pppoectl`).  These drive
the in-kernel client through `pppoectl` (not the `spppauth` helper) so they
double as the tool's live auth/keepalive/query-dns mode proof.  They are
`datapath`-marked, so they run under both `CLIENT=mpd5` and
`CLIENT=if_pppoe` (the `driver` fixture owns the hangup/redial either way).

### if_pppoe / accel state (post S05 T4)

Running with `SERVER=accel`, IPv6CP against the netns server stays
offer-only -- accel-ppp's PPP kernel driver refuses IPv6 outright, so
IPv6CP can never complete against accel regardless of the client backend;
that limitation is asserted positively by `test_ipv6cp.py::
test_ipv6cp_accel_stays_offer_only` (Configure-Request on the wire, never
a Configure-Ack).  IPv4/LCP/auth/IPCP/keepalive on the if_pppoe backend
are fully green, and the formerly-xfailed RFC 4638 (mpdsrv) and IPv6CP
(mpdsrv) cases now pass -- zero xfails remain in the suite (S05 T4).

`IfPppoeClient.dial` maps the mpd5-style `accept` set to the sppp `myauth`
protocol: `accept=("pap",)` -> `myauthproto=pap`, `accept=("chap",)` ->
`myauthproto=chap`, and multiple/allowed methods -> `myauthproto=pap` +
`passiveauthproto` (the server's LCP Auth-Protocol choice wins).  EAP alone
is rejected: sppp has no EAP (spec section 2 non-goal).

## The client runner seam (S05 T2)

`IfPppoeClient(runner=None)` is the single injectable command-invocation
seam for the fixture client: **every** pppoectl(8)/ifconfig PPPoE-control
command it issues funnels through the one overridden `run(cmd, root=False,
timeout=20)`:

* the parent bind `pppoectl -e vtnet1 [-s service] pppoe0`
  (PPPOESETPARMS),
* the auth config + DNS/keepalive options in one `pppoectl pppoe0
  myauthproto=... [passiveauthproto] myauthname=... myauthsecret=...
  query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1` call
  (SPPPSETAUTHCFG + SPPPSETDNSOPTS + SPPPSETKEEPALIVE),
* `ifconfig pppoe0 mtu N`, `ifconfig pppoe0 up`/`down`, the pppoe0 clone
  create/destroy in `dial`/`hangup`, and the module-load guard in
  `_ensure_clone`.

Two modes:

* **Default (`runner=None`)** — the pre-seam executor, byte-for-byte:
  `root=True` commands are wrapped as `echo | su -m root -c '<cmd>'` and
the whole thing goes over the ssh hostfwd (`_ssh`) exactly as before the
seam existed.  No caller-visible behaviour changes.
* **Injected runner** — `runner(cmd, root=False, timeout=20)` receives
the exact built command string and the `root`/`timeout` arguments the
pre-seam `run()` would have received, and whatever it returns (a
`CompletedProcess`-like object with `returncode`/`stdout`/`stderr`) — or
raises — flows straight back to the caller.  A fake can therefore script
canned output and exercise every failure path the real executor can hit
(dial's own `returncode` asserts, propagated ssh/subprocess exceptions).

`test_client_seam.py` pins this contract on any host (it is exempt from
the off-lab gate): exact command strings per dial/hangup/restart_link
variant, output/returncode flow-back, failure/exit-code handling, and the
byte-identical default path against a monkeypatched `_ssh`.  This seam is
the hook the M003 hardening/soak/fuzz work drives to observe and script
client commands without live VMs.
