# Forwarded perf harness — design (phase 2 scaling, p2-harness)

**Status:** run end to end in lab slot 2 (2026-09-27, SMP kernel on the
router VM): `make -C lab test-perf-fwd LAB_SLOT=2 BACKEND=if_pppoe|raw|mpd5`.
Results under `tests/results/perf/<stamp>-<backend>-<sha>-slot2/`. The first
end-to-end runs found and fixed the bugs listed in "Found by running it"
below; every claim about a FreeBSD tool's own output format is cited (man
page / real capture).

## One command, any slot

```
LAB_SLOT=2 ./lab/vm/fetch-image.sh lan && ./lab/vm/run.sh lan2 up && LAB_SLOT=2 ./lab/vm/provision-lan.sh
make -C lab test-perf-fwd LAB_SLOT=2 BACKEND=raw
make -C lab test-perf-fwd LAB_SLOT=2 BACKEND=if_pppoe
make -C lab test-perf-fwd-ratio FWD_RAW_DIR=... FWD_DIR=...
```

`test-perf-fwd` brings the backend up itself (`lab/vm/perf-backend.sh`:
if_pppoe dials from `/tmp/if_pppoe.ko` -- deploy it first with
`build-module.sh` for the kernel variant the client VM runs; mpd5 restarts
its "lab" label; raw tears PPPoE down), enables router mode, and runs the
matrix with the root collectors on (`--root-cmd 'echo | su -m root -c {}'`:
pf verified enabled around every run, lockstat sampled during the
highest-flow-count runs). For numbers that measure the router rather than
qemu, launch the slot's client/isp/lan with `LAB_VHOST=1 LAB_NET_QUEUES=N`
(`lab/vm/run.sh`, see "VM-lab limits").

## What this measures, and why not 2.3 Gbit/s

The phase-2 scaling goal is CPU distribution and headroom, not an absolute
number: forwarded throughput through pf/NAT as a fraction of the raw
(non-PPPoE) path, at 1/4/16 flows, both directions, judged alongside
`top -HSP` (no single CPU saturated) and lock contention (no driver lock
serializing the data path). The old Tier 3 pass bar (`docs/TESTING.md`,
`tests/perf/README.md`: >= 2.3 Gbit/s at >= 4 flows) was a hardware
certification target on a specific WAN sync rate -- it does not apply to this
workstream and `tests/perf/summarize.py --ratio-baseline raw`'s ratio column
is what to read instead.

## Topology (VM lab, `lab/vm/`)

```
lan<N> --(vtnet, br-lan<N>)--> client<N> (router: pf NAT, WAN=pppoe0/raw) --(vtnet1, br-isp<N>)--> isp<N>
192.168.77.10                  192.168.77.2 / WAN addr                         accel-ppp + iperf3 -s
```

(slot 1: `lan`, `client`, `isp`, `br-lan`, `br-isp`.)

- **lan VM** runs `iperf3 -c` (`run_matrix.py --client`) -- added for router-mode
  (S06); see `lab/vm/provision-lan.sh`.
- **client VM** is the router under test: `router-mode.sh enable <pppoe0|raw>`
  puts a WAN interface behind pf NAT from `vtnet2` (`--dut` for collectors).
  Both PPPoE backends are `pppoe0`: the lab's mpd.conf renames mpd5's
  ng_iface (`set iface name pppoe0`), so `run_matrix.py` tells if_pppoe from
  mpd5 by `ifconfig -g pppoe` membership (if_pppoe clones join the group,
  ng_iface does not), not by name.
- **isp VM** is both the accel-ppp PPPoE server *and* (this branch) the raw
  baseline's L3 peer, and runs `iperf3 -s` (`--server`).

### Reaching the VMs by name -- and why `--server` is not one of these aliases

`ssh_collectors.py` builds a bare `ssh host cmd` argv -- it doesn't source
`lab/vm/common.sh`, so it can't call `vm_ssh()`. `lab/vm/ssh-config.sh` prints
one `Host lab-<name>` block per VM (`ProxyJump <LAB_HOST>`, each VM's own
user-mode-net ssh port from `common.sh`'s `vm_config`), and `run_matrix.py
--ssh-config <that file>` (`ssh_collectors.configure()`) makes `--client
lab-lan --dut lab-client` resolve the same way `vm_ssh` already does.
`make -C lab test-perf-fwd` generates this config into a temp file per
invocation and removes it via an `EXIT` trap -- not a fallthrough `rm`
after `run_matrix.py`, which `set -eu` would skip on any failure, leaking
the temp file on every failed run (final-review minor, fixed on this
branch). The result directory name also carries a timestamp-plus-git-SHA
(`<UTC-timestamp>-<backend>-<sha>`, not just a date), so two same-day runs
of the same backend -- e.g. A/B-ing p2/scaling commits -- don't overwrite
each other's `matrix.json`.

`--server`, in contrast, is never ssh'd to -- `run_matrix.py` only ever
places it literally in `iperf3 -c <server> ...`, run *on* the lan VM. An
ssh-config alias like `lab-isp` is meaningless there: the lan VM has no such
host entry (aliases are local to whichever machine's `-F <config>` names
them), and even if it somehow resolved, it would name the isp VM's
management address, not its accel-ppp/raw data-plane one on `br-isp`. This
was the final-review blocker ("the one-command harness can never measure
forwarded traffic") -- fixed by `lab/vm/perf-target.sh BACKEND`, the single
place mapping `if_pppoe`/`mpd5` -> `10.99.0.1` (the accel-ppp gw) and
`raw` -> `192.168.99.1` (`provision-isp-raw.sh`'s alias), which both
`lab/Makefile`'s `test-perf-fwd` and `tests/perf/test_perf_target.py`
source from.

## The "raw" baseline: same NICs, same bridge, no PPPoE

`--backend raw` measures the identical physical path (client VM's `vtnet1` on
`br-isp`, same bridge the PPPoE session rides) with the encapsulation and
negotiation removed, so the ratio isolates PPPoE's own cost rather than also
absorbing a topology difference:

- `lab/vm/teardown-nonraw.sh` runs first (`test-perf-fwd BACKEND=raw`):
  stops mpd5, destroys any `pppoe0`-`pppoe3`/`ng0`, and `kldunload`s
  `if_pppoe` on the client VM -- otherwise every raw frame still passes the
  previous backend's `if_pppoe` pfil hook or `ng_ether`/`ng_pppoe` hook,
  slowing the baseline and biasing the ratio in PPPoE's favour
  (final-review minor). Best-effort by design; the real enforcement is the
  raw preflight below.
- `router-mode.sh enable raw` gives `vtnet1` a static `192.168.99.2/24` and
  points pf's `nat`/`scrub` at it instead of `pppoe0`/`ng0`.
- `provision-isp-raw.sh` gives the isp VM's already-bridged NIC (the same one
  accel-pppd listens on) an *additional* `192.168.99.1/24` -- a second address
  on one NIC, harmless to accel-pppd (binds by interface name).
- **No PPPoE MSS clamp on raw.** `scrub on pppoe0 max-mss 1452` matches PPPoE's
  1492-byte MTU; applying the same clamp to `raw`'s full 1500-byte MTU would
  cap its TCP segment size below its real ceiling and bias the ratio in
  PPPoE's favour. `raw` gets a plain `scrub on vtnet1` (no clamp).
- **Known caveat, not yet fixed by tooling:** `ifconfig` aliases persist
  across `router-mode.sh` passes. Switching *away* from `raw` now removes the
  `192.168.99.2/24` alias (see the router-mode.sh fix commit on this branch),
  but the isp-side address from `provision-isp-raw.sh` is left in place
  permanently once added -- harmless (accel-ppp ignores it), so it's not
  cleaned up automatically.

## Forwarded-traffic validation (final-review major: "correctly labelled but meaningless")

Two checks close the gap between "iperf3 printed a number" and "that number
came from traffic that actually went through the DUT's forwarding path":

- **Raw preflight** (`parsers.validate_backend_preflight("raw", ...)`):
  before the matrix runs, aborts unless (a) no `pppoe\d+`/`ng\d+` interface
  is up (a leftover from a prior backend pass would route some frames
  through `if_pppoe`'s or `ng_ether`'s pfil hook instead) and, when an
  `ifconfig vtnet1` capture is given, (b) `vtnet1` carries the expected
  `192.168.99.2` raw-baseline address.
- **Per-run byte-delta check** (`parsers.validate_forwarded_bytes`, called
  from `run_matrix.execute_run` after every run): compares the LAN
  (`vtnet2`) and WAN (the interface the preflight found up: `pppoe0` or
  `vtnet1`) `netstat -ibnd` byte deltas (before vs. after) against iperf3's
  own reported *received* bytes, and aborts the run if either is below 90%
  of it -- catching a wrong target IP, a stale route, or the lan VM leaving
  through its slirp NIC instead of the bridged one. (Received, not sent: a
  UDP `-b 0` flood through a saturated router is mostly dropped before the
  far-side interface ever sees it.)
- **pf in the path** (with `--root-cmd`): `pfctl -si` before/after every
  run; the run aborts unless `Status: Enabled`, and the state counters
  (current entries / searches / inserts) are recorded.

Both checks needed `DEFAULT_IFACE_PATTERN` widened to also match `vtnet\d+`
(previously only `igc\d+|pppoe\d+|ng\d+` -- the VM lab's NICs weren't
captured by `netstat -ibnd` parsing at all).

## New DUT collectors (R2/R3/T-item observability)

Added to `run_matrix.py`'s before/after snapshot, additively (existing
consumers/fixtures are schema-compatible):

- **`netstat -Q`** -- the netisr protocol table + per-workstream (per-CPU)
  `Handled`/`QDrops`/`Queued` counters for the private `pppoe` netisr protocol
  (`if_pppoe_netisr.c`). `parsers.parse_netstat_Q` /
  `diff_pppoe_workstreams` turn two snapshots into a per-CPU delta -- a
  non-zero `qdrops` delta on any CPU is a netisr queue overflow (`nh_qlimit`,
  the R023 tunable this same review flags for a default bump to 4096).
  `diff_netisr_workstreams` records the same delta for *every* protocol
  (`netisr_delta`: ip, ether, arp, pppoe, ...) -- the raw baseline has no
  pppoe row, and decapsulated traffic continues as ip; `summarize.py`'s
  "netisr qdrops" column is the sum, broken down by protocol.
- **`top -SHPn`** -- besides each core's mean idle, `cpu_busy_peak_per_core`
  is each core's worst `-s` interval (100 - min idle); `summarize.py`'s
  "peak core busy%" names the busiest core. A core near 100% there is a
  serialisation point the mean would dilute.
  Fixtures are a **real capture** (T2 spread evidence, sliced from
  `tests/results/lab-ab/spread-netisr-q.txt`), cross-checked against
  `tests/results/lab-ab/verdict.md`'s own reported per-CPU deltas.
- **`sysctl net.pppoe`** -- every counter/tunable under that node
  (`if_pppoe.c`'s `SYSCTL_COUNTER_U64`/`SYSCTL_INT` block), plus the
  PROC-handler `net.pppoe.cpu_hits` (`cpu0=N cpu1=M ...`,
  `if_pppoe_netisr.c:pppoe_sysctl_cpu_hits`), special-cased into a per-CPU
  dict. Also a real capture (same fixture source).
- **`vmstat -z`**, filtered to `mbuf*` zone rows -- mbuf/cluster pressure
  under load. Column layout (8 comma-separated plain integers per row --
  `SIZE,LIMIT,USED,FREE,REQ,FAIL,SLEEP,XDOM`, 7 without `XDOM` on an
  older/differently-built vmstat) is cited from `usr.bin/vmstat/vmstat.c`'s
  `domemstat_zone()` on `releng/14.3` (replaces an earlier fixture/regex
  copied from a 2012 FreeBSD-9 forum post, whose 7-column, comma-tolerant
  parse silently merged two fields against a real 8-column row -- review
  feedback, fixed on this branch). `parsers.parse_vmstat_z_mbuf` keys
  columns off the collected `ITEM ...` header line, not a fixed count.

## lockstat / pmcstat: corrected against the real man pages

The review brief's shorthand ("`lockstat -P -s 10`") doesn't parse as a
timed system-wide sample against the real `lockstat(1)`:

- **`-s <depth>`** is stack-trace depth ("histogram plus stack traces up to
  *depth* frames deep"), not a duration.
- **`-D <count>`** limits displayed events to the top *count*, also not a
  duration.
- `lockstat(1)`'s own DESCRIPTION gives the actual idiom: *"lockstat gathers
  data until the specified command completes... to gather statistics for a
  fixed-time interval, use sleep(1) as the command, as follows: `lockstat
  sleep 5`."*
- Root is required ("access to lockstat is restricted to the superuser by
  default").

So the real, correct invocation this harness uses is
**`lockstat -P -s <depth> sleep <duration>`** (sort by count*time product,
10-frame stacks, bounded to `duration` wall-clock seconds by the `sleep`
command) -- implemented in `ssh_collectors.run_lockstat_sample`. It runs
*during* the load: `run_matrix.py --lockstat max-flows|all --root-cmd T`
starts it a few seconds into the chosen runs and stops it before iperf3's
teardown (`lockstat_window`), after `kldload dtraceall` if needed.
`parsers.parse_lockstat` summarises each section (adaptive mutex spin /
block, spin lock spin, ...) into its top locks by total wait time
(sum of count x mean nsec over the lock's caller rows) with the busiest
caller; the raw text is kept too. Layout confirmed against a real capture
(`tests/perf/fixtures/lockstat_sample.txt`, the slot-2 SMP client VM under 4
forwarded TCP flows). The standalone `sample_lockstat.py` (`--sudo` or
`--root-cmd`) remains for a one-off sample. Verified available in the VM lab:
the SMP and SMPW kernels both carry `options KDTRACE_HOOKS`
(`sysctl kern.conftxt`).

**`command -v lockstat` is a binary-presence probe, not a real-availability
check** -- it says nothing about whether DTrace/lockstat providers are
loaded or whether the caller has root, so `run_matrix.py`'s meta field is
named `lockstat_binary_present` (not `lockstat_available`, which overstated
what was actually checked -- review finding). Same caveat for `pmcstat -L`.

`pmcstat(8)`'s `-T` ("top mode") is documented as interactive-only (curses,
hotkeys) with no plain-text/non-interactive top-N report flag -- so rather
than ship an unverified non-interactive invocation, this harness only probes
*availability* (`pmcstat -L`) and reports it, per the review brief's own
expectation ("likely not [available]; skip gracefully"). Real sampling in
top/counting mode is future work if a VM ever does expose usable PMCs.

pmcstat is expected to report unavailable in the VM lab (no vPMU
passthrough for hwpmc(4) under KVM).

## Ratio table

`tests/perf/summarize.py --ratio-baseline raw <raw-matrix.json>
<backend-matrix.json>` divides each row's Gbit/s by the same-shaped (flows,
proto, direction, pkt_len) `raw` row's Gbit/s across all given files; a shape
with no matching baseline prints `n/a`, not a fabricated number.
`make -C lab test-perf-fwd-ratio FWD_DIR=... FWD_RAW_DIR=...` wraps this for
two already-run `test-perf-fwd` result directories.

## VM-lab limits (read the numbers, not just the ratio, with this in mind)

Per `tests/results/lab-ab/verdict.md`'s own caveats from the M002 S06 A/B:
4-vCPU VM DUT, vhost/tap bridges, and (now) accel-ppp in its own VM all
underestimate absolute throughput versus hardware -- the lab's own mpd5
numbers there are far below the hardware `j4105-mpd5-matrix-f*.json`
baselines. Read **absolute** Gbit/s figures from this harness as indicative
only; the **ratio** (this backend / raw) and the **CPU-saturation profile**
(`top -HSP`'s per-core idle%, `netstat -Q`'s per-CPU Handled spread) are what
phase-2 scaling work should be judged by, matching the GOAL stated in the
review brief.

**Launch the VMs with `LAB_VHOST=1 LAB_NET_QUEUES=N` for scaling work.**
With `run.sh`'s default NICs (qemu userspace virtio, one queue pair) the
first slot-2 runs capped *every* backend, raw included, near 1-1.5 Gbit/s
with no router core above ~45% busy (`tests/results/perf/20260927T095249Z-*`,
`20260927T100201Z-*`): the lab, not the router, was the bottleneck, and one
queue per NIC also hides whether receive work spreads across cores. With
vhost-net and 4 queue pairs on client2/isp2 (2 on lan2) the same matrix
reached 3-4 Gbit/s and the router's cores 50-90% busy
(`20260927T101710Z-if_pppoe-*`, `20260927T102545Z-raw-*`,
`20260927T103420Z-mpd5-*`, ratio table `20260927-slot2-vhost-ratio.txt`).
Kernel choice matters too: measure on the SMP kernel (`KERNEL_VARIANT=SMP
./provision-client.sh`, then an SMP-built `if_pppoe.ko`); the SMPW
WITNESS/INVARIANTS kernel adds per-lock-operation overhead that falls on the
PPPoE path (more locks per packet) far more than on raw.

Also still limiting: the isp VM's Debian iperf3 is 3.12, single-threaded
for all streams (multi-threaded iperf3 is 3.16+), and the VM host is shared
with the other slots -- a raw run under host load average 13-15 is visibly
noisier than one at 3-5 -- note `ssh <LAB_HOST> uptime` next to each
run, and repeat a run before trusting a ratio above 1.

## Found by running it (2026-09-27, slot 2)

- `router-mode.sh enable` was not re-runnable (`pfctl -e` exits 1 once pf
  is on, killing the `set -euo pipefail` remote script silently).
- `teardown-nonraw.sh` ran `bash -s` on the FreeBSD client (no bash).
- BACKEND=mpd5 pointed pf at `ng0`, which the lab's mpd5 never creates
  (it names the bundle `pppoe0`); preflight could not tell mpd5 from
  if_pppoe by name either.
- The download/upload labels were swapped (see `build_run_specs`).
- UDP gbps was the sender's rate; now the receiver's.
- `parse_top` dropped every kernel thread (NICE `-`/`ki31`, shared pid 12),
  so `top_threads` never showed netisr/intr threads; result files from these
  runs had `top_threads` recomputed from their saved `top_raw`.

## What's still manual

- pmcstat stays unavailable in the VM lab (no vPMU).
- The kernel-side scaling changes this harness is meant to measure (T1-T4,
  R1-R4) are a separate branch, `p2/scaling`; this harness measures whatever
  lands there, it doesn't implement it.
