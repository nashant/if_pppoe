# Testing

Operator documentation for the if_pppoe test lab: how to run each test tier
and what "pass" means at each one. This document describes the strategy for
Phase 0 (lab bring-up) through Phase 4 (production trial); driver code does
not exist yet, so Tiers 1-4 below describe the harness these later phases
will exercise.

**A note on evidence-log citations below:** `tests/results/` is a local,
gitignored run-output directory the test harness (re)creates on demand; it
is not part of this repository, so the specific log filenames cited in the
result matrices below are historical pointers to a given run's own output,
not files you can open in this checkout.

## Lab topology

- **DUT**: `<DUT_HOST>` — OPNsense 25.7.11 / FreeBSD 14.3, kernel SMP
  (GENERIC+RSS+VIMAGE); a J4125-class 4-core router with four 2.5G NICs.
- **PPPoE peer**: **not a consumer router.** A consumer Wi-Fi router was
  meant to run accel-ppp from a third-party package on its own bridge,
  reached over one of the DUT's LAN NICs, but that package is broken on
  its hardware and the router is parked as a peer — see "Current status"
  below. The peer actually in use is accel-ppp in netns `isp` on `<LAB_HOST>`
  (`lab/isp-netns/`). For hardware runs the DUT reaches it over a tagged
  VLAN on the existing LAN trunk: DUT LAN NIC, VLAN-tagged <-> switch <->
  `<LAB_HOST>`'s bonded NIC <-> `br-isp` (`lab/peer/README.md`); no extra
  cabling and no change to `<LAB_HOST>`'s bond. The switch must pass that
  VLAN on both ports (unverified) and the router-side VLAN/PPPoE client
  still needs router root.
- **VM host**: `<LAB_HOST>` — Ubuntu 24.04, KVM.

## Current status / known gaps (2026-09-12)

- **Consumer-router PPPoE peer: parked, not working.** The router's
  third-party `accel-ppp 1.14.0-1` `aarch64-k3.10` package aborts
  `accel-pppd` with `exit_group(1)` and no log output as soon as any
  control module (`pppoe`, `pptp`, `l2tp`, `ipoe`) loads — a
  package-level defect, not a config error. The lab's PPPoE
  server today is `lab/isp-netns` (accel-ppp in a netns on `<LAB_HOST>`)
  or the mpd5-server VM (`lab/vm`); Tier 2 below runs against the netns,
  not that router.
- **Tier 0 baselines: not recorded.** `tests/results/` holds only
  `.gitkeep`. Blocked on interactive `sudo` on `<DUT_HOST>` needing a
  password this harness can't supply non-interactively.
- **mpd5 client RFC 4638 gap: closed for if_pppoe; server-side gap remains.**
  The mpd5 *client* never emitted the RFC 4638 PPP-Max-Payload tag (the old
  `test_mru_mtu_1500_with_mpdsrv` xfail) — the in-kernel `if_pppoe` client
  does, and the suite now asserts the offer and the peer-honoring MTU
  write-back against mpdsrv. The *server* side gap remains: mpd5 5.9_19's
  PADO/PADS carries no PPP-Max-Payload tag (live-captured in S04), so the
  driver's RFC 4638 §5.1 write-back honestly holds pppoe0 at 1492 and the
  full 1500-byte payload round-trip stays an M003 item — see
  `lab/vm/README.md`'s "Known issue" (the br-isp/tap MTU ≥ 1508
  prerequisite).

## Pass criteria

- **Throughput**: >= 2.3 Gbit/s down and up with >= 4 flows through pf+NAT.
- **Single flow**: >= 1.25x the mpd5 baseline on the same rig.

## Tier 0 — baselines

Establishes the ceiling and the incumbent (mpd5) baseline before any driver
work starts. Run in order:

1. Speedtest through the current consumer-router handoff.
2. Plain-Ethernet iperf3 ceiling, DUT <-> consumer router over its LAN NIC
   (no PPPoE).
3. mpd5 client on DUT vs accel-ppp: full perf matrix (see Tier 3), plus
   repeats with `net.isr.dispatch=deferred`, `net.isr.maxthreads=-1`,
   `net.isr.bindthreads=1`.
4. **Already triggered**: the consumer router's accel-ppp package is broken
   (see "Current status" above), so `<LAB_HOST>` via a tagged VLAN on the
   LAN trunk is the PPPoE server peer this and later tiers compare against,
   not that router.

**Pass**: baseline numbers recorded for all of the above. **Not yet done**
— blocked on DUT root; see "Current status" above.

## Tier 1 — functional (VMs on `<LAB_HOST>`)

Topology: a FreeBSD 14.3 client VM running the OPNsense SMP kernel <->
bridge <-> netns `isp` running accel-ppp, plus an mpd5-server VM for RFC
4638 cases. Harness is pytest + scapy running on the host, driving the VMs
over ssh.

Run:

```
make -C lab test-func
```

Before trusting a new or changed test, run the same suite with
`CLIENT=mpd5` first to validate the harness against a known-good client,
then switch to the driver under test.

Cases implemented today (see `tests/functional/*.py`, `tests/functional/README.md`):

- **Discovery**: PADI/PADO/PADR/PADS; service-name empty/mismatch; AC-Name;
  multiple PADO; Host-Uniq echo; server PADT; client PADT on `ifconfig down`;
  retransmit/backoff; malformed-tag fuzzing.
- **LCP**: MRU 1492 with accel-ppp; RFC 4638 max-payload against mpdsrv
  (PADI offers the administrator's 1500 as tag 0x0120 and the MTU lands on
  the peer-honoring §5.1 value — 1492 while mpd5 5.9_19 is tag-silent);
  magic number; echo keepalive at 10s and 60s; PAP and CHAP-MD5 success;
  bad password -> terminate+retry, no IPCP.
- **IPCP**: address, primary DNS.
- **IPv6CP**: negotiated + link-local against mpdsrv (accel-ppp stays
  offer-only — its kernel driver refuses IPv6 — asserted positively by
  `test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only`).
- **ifnet**: MTU follows negotiation. 24h soak (`test_soak.py`, written and
  reviewed but not run in CI by default — see `tests/functional/README.md`'s
  `soak` marker).

**Planned, not yet implemented** (driver-phase work; no test file exists for
these — `grep -rl 'pf\|pfctl\|vnet\|jail\|kldunload\|tcpmssfix' tests/functional/*.py`
returns nothing): ACFC/PFC refused; secondary DNS; VJ refused; RA; link
up/down hooks; counters; `kldunload` with an active session; VNET jail
create/destroy; **pf** (NAT, states, MSS clamp); the on-demand/idle-timeout/
tcpmssfix/up-down-scripts/max-payload/service-name parity-checklist items
against mpd5.

**Out of scope**: MLPPP, mrru.

**Pass**: all non-soak cases green with `CLIENT=if_pppoe`; the 24h soak case
completes with no dropped session and no leaked jail/vnet state; parity
checklist has no unexplained divergence from mpd5.

### Tier 1 result matrix — M002 end state (CLIENT=if_pppoe, zero xfails)

Recorded end-state of the functional suite with the in-kernel `if_pppoe`
client backend (M002 S05 T4, 2026-09-22). Both formerly-xfailed cases now
pass and **zero xfail markers remain in the suite**. Full-run evidence
(the completed, post-mpd5-quiesce verification runs from S05 T4):
`tests/results/s05-t4-fix-accel-3.log` (SERVER=accel) and
`tests/results/s05-t4-run-mpdsrv-2.log` (SERVER=mpdsrv), both full-suite
single runs; T3's two consecutive green SERVER=accel runs remain recorded in
`s05-t3-run-final-{1,2}.log`, and the S05 T2 runner-seam / T3 harness-
hardening notes below are unchanged.

| metric | value |
|--------|-------|
| collected (both runs) | 65 (63 selected: `-m "not soak"` deselects 2) |
| passed (SERVER=accel run, `s05-t4-fix-accel-3.log`) | **63** |
| passed (SERVER=mpdsrv run, `s05-t4-run-mpdsrv-2.log`) | **63** |
| xfailed | **0** in both runs (both former xfails now pass: `test_lcp.py::test_mru_mtu_1500_with_mpdsrv`, `test_ipv6cp.py::test_ipv6cp_negotiated_and_link_local`) |
| failed | **0** in both runs (the earlier stray-mpd5 interference that flunked `test_datapath.py::test_session_frames_are_decapsulated_and_counted` and `test_redial_still_offers_the_administrators_max_payload` in the interrupted first mpdsrv attempt is now prevented by the session-scoped client-VM mpd5 quiesce in conftest, and the datapath counter bracket carries a documented +2 reader/straddle allowance) |
| secrets in run output | 0 (suite R011 assertions green; grep of every captured T4 run log, the client serial log, and /var/log/messages: zero hits) |
| duration | ~12 min per run (`<LAB_HOST>`, sudo + scapy) |

- **Former xfail 1 — RFC 4638 max-payload (mpdsrv): now passing.** The old
  xfail described the mpd5 *client* never emitting the tag; the in-kernel
  client offers 1500 as tag 0x0120 in PADI (asserted on the wire), and the
  MTU assertion now expects the peer-honoring RFC 4638 §5.1 value computed
  from the captured PADS grant — 1492 against today's tag-silent mpd5
  5.9_19 server (live-re-proven during the flip). The 1500-byte payload
  round-trip remains an M003 item.
- **Former xfail 2 — IPv6CP negotiated link-local: now passing against
  mpdsrv.** The test dials the mpdsrv service (`needs_mpdsrv`) where IPv6CP
  reaches Opened and the negotiated fe80:: is applied in-kernel. The accel
  exception is pinned as a positive offer-only assertion
  (`test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only`): Configure-Requests
  go out, no Configure-Ack ever.
  *Correction (p3-ipv6rx):* the ping6 half of
  `test_ipv6cp_negotiated_and_link_local` was a local false pass in these
  runs. Its peer scrape took the first fe80::/64 in mpdsrv's `ifconfig -a`,
  which is the vtnet link-local and not the ngN tunnel's. The
  driver still dropped every received PPP_IPV6 frame at that point, so only
  a locally answered address could reply. The scrape now goes through
  `lab.mpdsrv_tunnel()` (ngN whose p2p peer is the session address) and
  asserts it differs from pppoe0's own, so that ping only passes on a
  driver with IPv6 RX. The tunnel address is read live: mpd5's IPv6CP
  layer has no options, so its interface identifier cannot be pinned.
- **Fixture correctness for SERVER=mpdsrv runs**: tests that dial service
  "lab" pin the accel peer explicitly (conftest `accel_server` fixture) so
  a SERVER=mpdsrv run cannot hand them the mpdsrv VM's server object.
- **Harness hardening recorded with this matrix**: `PPPoESniffer.start()`
  now proves the capture is attached by requiring it to see an injected
  readiness probe, replacing a `sleep(0.3)` guess that lost whole discovery
  exchanges when the fast in-kernel dial beat the attach (baseline run:
  exactly two teardown PADTs captured, no PADI/PADO/PADR/PADS); the
  discovery-ordering test waits for the session instead of a blind
  `sleep(2)`; conftest's `_wait_iface_up` carries a dial-start stall
  watchdog (when pppoe0 is administratively up but the driver FSM is still
  INITIAL -- sppp never opened LCP, zero frames on the wire -- it forces an
  explicit down/up cycle; this lives in the wait helper, not `dial()`, so
  the dial command sequence stays byte-for-byte under the S05 T2
  runner-seam contract); the datapath counter-bracket test cross-pairs its
  sess_in reads so a frame landing in a snapshot's own inter-command gap
  cannot push the interface counter outside the bracket; the server-PADT
  re-dial test waits for the FSM to actually leave SESSION before timing
  the re-dial (padt_rx counts stale-session PADTs too, so it can move long
  before the tear-down).
- **T4 harness additions recorded with this matrix**: (a) the datapath
  bracket's upper bound carries a documented **+2 straddle allowance** --
  the driver's sess_in/Ipkts counter pair (if_pppoe.c:1092-1093) is two
  separate per-CPU counter adds with no barrier, so an RX thread preempted
  between the two adds during a snapshot leaves Ipkts 1-2 frames above the
  bracket (proven live in the S05 T4 bracket-loop probe: module counters
  ended exactly at sess_in == data_in == 13 while Ipkts read 14) -- the
  exact data_in == sess_in equality and the lost-frame lower bound are
  unchanged, and a failing bracket now dumps the full `sysctl net.pppoe`
  counter set so the next failure is self-diagnosing; (b) `make -C lab
  test-func` now captures the remote pytest output to a durable file on
  the VM (`last-func-$(SERVER).log`) and, when the ssh transport dies
  mid-run (rc 255), recovers the verdict log via scp before failing -- a
  run can no longer be lost with no verdict.

### Tier 1 result matrix — M003 S03 end state (CLIENT=if_pppoe)

Recorded end-state of the functional suite after M003 S03 (reconnect fix,
ALTQ detection, reconnect test set), 2026-09-25. Evidence logs pinned under
`tests/results/reconnect/`: `s03-func-accel.log` (SERVER=accel),
`s03-func-mpdsrv.log` (SERVER=mpdsrv), `s03-hardening.log` (hardening probe).
Three full-suite runs were taken this slice (accel x2, mpdsrv x1); all three
carry the identical verdict, so the single failure below is deterministic,
not flaky.

| metric | value |
|--------|-------|
| collected (all runs) | 73 (71 selected: `-m "not soak"` deselects 2 soak cases; +5 S03 reconnect cases vs M002's 65/63) |
| accel run 1 + run 2 (identical) | **69 passed, 1 failed, 1 skipped** (`s03-func-accel.log`, ~14 min each) |
| mpdsrv run | **69 passed, 1 failed, 1 skipped** (same single failure; `s03-func-mpdsrv.log`) |
| S03 reconnect cases | **all green in both runs**: `test_reconnect.py` accel-marked cases (server-terminate RTM_IFINFO DOWN/UP pair, restart_link pair, PADT-on-clone-destroy) and the needs_mpdsrv IPv6 link-local rebuild case all pass in both full runs (targeted 2x-green T3 evidence: `tests/results/reconnect/s03-t3-run{5,6}.log`) |
| ALTQ flip-or-skip test | **1 skipped with recorded reason** (`test_reconnect.py::test_altq_on_the_parent_is_detected_and_warned_about`): the OPNsense SMP lab kernel is built without ALTQ (`kern.features.altq` absent; pf.ko loads but cbq cannot attach), so the plan-mandated skip path lands with the kern.features.altq probe result and pfctl stderr in the log (T4 evidence: `tests/results/reconnect/s03-t4-run{1,2}.log`) |
| failed | **1** — `test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only` (deterministic in all 3 runs; passed in both M002 S05 T4 full runs): the accel-side capture now shows an IPv6CP negotiation burst (codes {1 Configure-Req, 2 Configure-Ack, 3 Configure-Nak}) inside the accel offer-only test's capture window, where M002 saw only the client's ConfReq. The capture is filtered only by PPP proto (no session/MAC filter) and the preceding `test_ipv6cp_negotiated_and_link_local` leaves an mpdlab/mpdsrv session up across the adjacency, so the burst is either the leftover mpdsrv session's IPv6CP exchange overlapping the capture window or an S03-driver-induced change in the fresh accel session's IPv6CP offer; the S03 reconnect tests run *after* `test_ipv6cp.py` (collection order: fuzz, ipcp, ipv6cp, lcp, pap, reconnect, sppp_ioctl_live) so they cannot have contributed within a run. **Resolved post-run per STEP 4 (recorded deviation; evidence pinned under `tests/results/reconnect/`).** The three prior-attempt diagnostic probes (s03-t5-diag-offer{,2,3}.log) settle the attribution: separating the capture by PPPoE session id shows the burst is on the FRESH accel session (sid 11712, 26+40 frames) while the leftover mpdlab session (sid 11648) contributes only 2 ConfReq frames — and the burst is the accel peer itself: accel-ppp 1.14.0 on the Debian isp VM (2026-09-23 migration; M002's green 2026-09-22 runs predate it) **initiates** IPv6CP — it sends its own ConfReq (ifid `01:00:00:00:00:00:00:00`) and ConfNaks every client ifid proposal with `02:00:...` (diag-offer3: client ConfReq ids 0x01–0x0f all ConfNak'ed, negotiation still never completes, seeded-ifid link-local kept — the pinned offer-only exception HOLDS, and NOT S03 code). The old direction-blind `2 not in codes` assertion false-fails on the client's RFC 5072-mandated ConfAck of accel's own ConfReq (code 2 frames are client→server). The STEP 4 allowance (one targeted test-file-only fix + immediate re-run) was consumed exactly once: the assertion in `tests/functional/test_ipv6cp.py::test_ipv6cp_accel_stays_offer_only` is now direction-aware (`1 in client_codes`, `2 not in server_codes` — server-sent frames only, loud-failure contract retained), and the affected test re-ran **green twice** standalone (`s03-t5-offer-fixed-run{1,2}.log`, 14.99 s / 13.88 s). The pinned full-suite logs above predate the fix and record the pre-fix run state verbatim. |
| secrets in run output | 0 (R011 assertions green) |
| duration | ~14 min per full-suite run (`<LAB_HOST>`, sudo + scapy) |

### Tier 1 result matrix — M003 S04 (soak + backend shim; placeholder rows)

M003 S04 rows, opened during S04-T04 (2026-09-25). Both rows are recorded
here as placeholders so the matrix shape for the slice is visible up front;
each flips to its recorded verdict when its owning task completes — the
soak row by S04-T05, the shim row by S04-T06:

| row | owner | status | evidence |
|-----|-------|--------|----------|
| 24h soak (`test_soak.py` via the `soak` marker: no dropped session, no leaked jail/vnet state, M_PPPOE + leak count flat across the window) | S04-T05 | **placeholder — soak running on the lab client VM (started 2026-09-25); verdict recorded by S04-T05** | soak run log under `tests/results/soak/` at completion |
| backend shim live validation (os-if-pppoe plugin on the client VM: `if-pppoe-ctl` status/entries/dial/undial round-trip, the `is_ours()` refusal path on foreign clones, non-destructive handback checks) | S04-T06 | **placeholder — scheduled strictly after the 24h soak completes so the destructive paths cannot disturb the soak's session** | S04-T06 evidence log |

- **Soak row**: asserted against the Tier 1 pass criterion above (no
  dropped session, no leaked state, flat `vmstat -m` pppoe row). Do not
  read any intermediate soak number as a verdict — standing rule D025:
  lab numbers are relative indications only.
- **Shim row**: exercises the plugin's console surface only
  (`configctl`/`if-pppoe-ctl`); the OPNsense GUI page itself is verified
  on-box in M003 S06 — see the verification-status legend in
  [docs/DEPLOY.md](DEPLOY.md) §2.

### Tier 1 hardening-probe rows — M003 S02 (kldunload-under-traffic / VNET jail / M_PPPOE)

Standalone probe `tests/functional/hardening_probe.py` (deliberately NOT pytest-collectable,
MEM008): 10 traffic-under-unload cycles (live session, iperf3, PROMPT kldunload, PADT sniffed,
serial panic oracle, ssh liveness), 5 VNET jail create/destroy cycles, like-for-like M_PPPOE
accounting (vmstat -m pppoe row flat + dmesg 'leaked memory on destroy' count flat). Evidence:
`tests/results/hardening/smpw-run.log` (+ `smpw-evidence/` idle-baseline and post-run dmesg).

| kernel | run | result | notes |
|--------|-----|--------|-------|
| kernel.SMP (release) | M003 S02 T3 (2026-09-24) | **89/89 PASS** | post-MEM093-fix; M_PPPOE flat 1->1 (32 B), leak count 41->41 across 10 unloads; fuzz gate green |
| kernel.SMP (release) | M003 S03 T5 (2026-09-25) | **90/90 PASS** (143 s) | post-S03-driver regression (T1 touched the teardown paths the probe hammers in its 10 unload cycles + phase-B re-dial): all fatal gates pass — 10/10 traffic-under-unload cycles (PADT oracle, ssh alive), 5/5 jail cycles, M_PPPOE flat, leak count flat, no panic; final-state dump shows a fresh healthy session (pppoe0 inet 10.99.0.199, fe80:: ll present, MTU 1492). Check count is now 90 vs S02's recorded 89 — the probe's check set grew by one between S02 and S03; every check in the current probe file passes. Evidence: `tests/results/reconnect/s03-hardening.log` |
| kernel.SMPW (WITNESS/INVARIANTS/DIAGNOSTIC) | M003 S02 T4 (2026-09-24) | **89/89 PASS** (runs 4+5, post phase-B fix) | Caught + fixed a genuine INVARIANTS panic: `mtx_lock() of spin mutex sppp_wq` (if_sppp_compat.h) — all wq_mtx sites now `mtx_lock_spin`, taskqueue_enqueue moved outside the spin mutex. The second 83/89 failure mode (phase-B re-dial precondition timing out deterministically right after the 10th unload-under-traffic cycle on the slower debug kernel: state=0, padi_retries=0 for the whole 20 s window, cascading into 5 'session still up' FAILs) was fixed in `tests/functional/hardening_probe.py`: a shared `_establish_session()` dial helper (45 s wait_state for the debug kernel + the one bounded down→up discovery restart the traffic cycles already encode) plus a 3 s settle after the 10th PADT before the phase-B re-dial; back-to-back runs 4+5 fully green (145 s / 148 s). All fatal gates pass: 10/10 traffic-under-unload cycles (PADT oracle, ssh alive), 5/5 jail cycles, M_PPPOE flat (1->1, 32 B), leak count flat, no panic. Witness triage: no witness entries naming the driver's own locks (sc_mtx/pppoe_parents_lock/sppp_wq/spppq); the two WARNING-level signatures from the earlier runs recur unchanged (62x `uma_zalloc_debug` WARN: malloc(M_WAITOK) under the 'sppp' sleep mutex in sppp_params SPPPSETAUTHCFG — also present in the fresh idle baseline, i.e. boot-time rc pppoe0 bring-up noise, not probe-caused; 1x LOR vnet_sxlock -> ifnet_detach_sx triggered by pppoe_clone_destroy inside the framework-mandated VNET_SYSUNINIT unload path) — follow-ups recorded in `tests/results/hardening/smpw-run.log` |

## Tier 2 — interop

The non-fuzz subset of Tier 1, run against real hardware instead of the
lab VMs, using service name `lab`. **The consumer-router peer is
unavailable** (see "Current status" above) — run this against `<LAB_HOST>`
via a tagged VLAN on the LAN trunk instead.

**Pass**: same subset that passes in Tier 1 also passes against the
hardware peer.

## Tier 3 — performance matrix

Run per backend (`mpd5`, `mpd5-tuned`, `if_pppoe`; `plain` for a no-PPPoE
ceiling run — see `tests/perf/README.md`):

- TCP down/up x flows {1, 4, 8, 16} x 60s.
- UDP 1400B.
- UDP 64B PPS.

LAN endpoint: `<LAB_HOST>`'s bonded NIC via its LAN-facing member. Internet
endpoint: **the consumer-router WAN handoff is unavailable for this** (see
"Current status" above) — use `<LAB_HOST>` via a tagged VLAN on the LAN
trunk per Tier 0 step 4.

Run:

```
make -C lab test-perf BACKEND=if_pppoe
make -C lab baseline          # equivalent to BACKEND=mpd5
```

Collect on the DUT for every run: `top -SHP`, `vmstat -i`, `netstat -m`,
`ifconfig` error counters, pf state count, and iperf3 JSON output saved to
`tests/results/*.json`.

**Pass**: if_pppoe meets the pass criteria above (>= 2.3 Gbit/s at >= 4
flows, >= 1.25x mpd5 single-flow) and no backend shows abnormal resource
use (CPU pegged, mbuf exhaustion, climbing error counters) relative to its
own baseline run.

### M002 lab relative A/B — pre-certification rehearsal (S06)

Before hardware certification, M002 S06 ran the perf matrix as an
**mpd5 vs in-kernel if_pppoe A/B on the identical VM lab topology**
(accel-ppp netns peer, pppoe-client-vm DUT, 30 s runs, TCP flows {1, 4, 8}
+ UDP 1400 B, both directions). Results and the recorded verdict live in
`tests/results/lab-ab/` — table via `python3 tests/perf/summarize.py
tests/results/lab-ab/<per-run JSONs>`, verdict in
`tests/results/lab-ab/verdict.md`, per-CPU spread / netisr evidence in
`tests/results/lab-ab/spread-*.txt`. Summary of the direction observed:
single-flow TCP parity-or-better (UDP within lab noise), no flow-count
serialisation regression (if_pppoe scales, mpd5 flat; 2.1x mpd5 at 8 TCP
flows), and netisr spread of the private `pppoe` protocol observed across
multiple CPUs with zero QDrops.

### Phase 2 scaling — forwarded ratio-to-raw, not a Gbit/s floor

The phase-2 scaling workstream (`p2/scaling`) is judged by forwarded
throughput as a fraction of the raw (non-PPPoE) path and CPU
distribution/lock contention, **not** the 2.3 Gbit/s floor above (that
remains the hardware Tier 3 certification target on this lab's specific
WAN sync rate). `make -C lab test-perf-fwd BACKEND=if_pppoe|mpd5|raw`
plus `tests/perf/summarize.py --ratio-baseline raw` produce that ratio
table; see `docs/PERF-FWD-DESIGN.md`.

**These lab numbers are a relative indication only.** The 2.3 Gbit/s
pf+NAT floor and the 1.25x mpd5 single-flow ratio above remain
**router-only certification targets deferred to M003 Tier 3 on
the DUT** — do not read the VM lab results as hardware pass/fail.

## Tier 4 — production trial

ONT to the DUT's WAN NIC, PPPoE on the ISP's tagged VLAN, the consumer
router kept as fallback. Run only after Tiers 1-3 pass.

**Pass**: sustained production traffic with no regressions vs the consumer-
router fallback path, over a soak period judged representative of real usage.
