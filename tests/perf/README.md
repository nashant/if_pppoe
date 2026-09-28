# tests/perf — iperf3 performance matrix

Runs the Tier 0 / Tier 3 iperf3 matrix (see `docs/TESTING.md`) against a
backend (`mpd5`, `mpd5-tuned`, `if_pppoe`, `plain` for a hardware no-PPPoE
ceiling run, or `raw` for the phase-2 forwarded-harness no-PPPoE baseline
-- see `docs/PERF-FWD-DESIGN.md`) and records JSON results plus DUT
resource metrics under `tests/results/`.

## Prerequisites

- `iperf3 -s` already listening on `--server` (start it yourself, e.g.
  `ssh SERVER iperf3 -s -D`, and stop it when done).
- ssh access (key-based, no password prompt) to `--client` (runs
  `iperf3 -c`), `--dut` (read-only metric collection, no root needed),
  and implicitly `--server` if you need to start `iperf3 -s` there.
- Python 3.12+, stdlib only. `pytest` only needed to run the test suite.
- No root anywhere, and nothing is installed on the DUT — all DUT
  commands are read-only (`netstat`, `sysctl -r`, `vmstat -i`, `top`,
  and a best-effort `pfctl -si` that is recorded as `"n/a"` when it
  fails without root, which is expected).

Any other ssh failure (dead host, auth failure, dropped connection) or
an iperf3 connection failure aborts the whole matrix with a clear error
on stderr and a non-zero exit, instead of recording a silently
empty/fake-looking sample.

## Usage

```
python3 tests/perf/run_matrix.py \
    --backend if_pppoe \
    --server iperf-server.example \
    --client lab-client.example \
    --dut router.example \
    --duration 60 \
    --flows 1,4,8,16 \
    --out tests/results/if_pppoe-$(date -u +%Y%m%dT%H%M%SZ).json
```

Add `--dry-run` to print the full planned command list (every ssh
collector call and every `iperf3 -c` invocation) without touching the
network or writing a file.

Add `--ssh-config PATH` to reach `--client`/`--dut` through an ssh client
config file (`ssh -F PATH`) instead of a bare hostname -- this is how the
forwarded VM-lab matrix reaches VM aliases (`lab-client`, `lab-lan`) that
are only ssh-able through `<LAB_HOST>` as a `ProxyJump` on a per-VM port
(see `lab/vm/ssh-config.sh`). `--server` is different: it's never ssh'd to,
only placed literally in `iperf3 -c <server> ...` run on `--client` -- it
must be the actual data-plane IP the DUT forwards to (`lab/vm/perf-target.sh`
picks this per BACKEND for the VM lab), not an ssh alias (see
`docs/PERF-FWD-DESIGN.md`).

For each `--flows` value N, the matrix runs, in order:

1. TCP download (server -> client): `iperf3 -c SERVER -P N -t D -J -R`
2. TCP upload (client -> server): same, without `-R`
3. UDP 1400B download: `iperf3 -c SERVER -u -l 1400 -b 0 -P N -t D -J -R`
4. UDP 1400B upload: same, without `-R`
5. UDP 64B PPS test (download only): `iperf3 -c SERVER -u -l 64 -b 0 -P N -t D -J -R`

(`-R`: "the server sends data to the client",
https://software.es.net/iperf/invoking.html. Result files written before
2026-09-27 had download/upload swapped.) UDP Gbit/s is the receiver's rate
(`end.sum_received`); the sender's is kept as `sent_gbps`.

Before and after every run, over `ssh DUT` (read-only): `netstat -m |
head -5`, `netstat -ibnd` (interfaces matching `igc\d+|pppoe\d+|ng\d+`
by default), `sysctl net.isr.dispatch net.isr.maxthreads
net.isr.bindthreads` (once, recorded in `meta`), a best-effort
`pfctl -si` current-entries count, `netstat -Q` (netisr per-CPU pppoe
workstream Handled/QDrops -- R2/R3 review items), `sysctl net.pppoe`
(every counter, including the per-CPU `net.pppoe.cpu_hits`), and
`vmstat -z` filtered to the `mbuf*` zone rows. Once, before the matrix,
a root-free binary-presence probe for `lockstat`/`pmcstat` is recorded in
`meta` (`lockstat_binary_present`, `pmcstat_available`); a `true` says only
that the binary exists. With `--root-cmd TEMPLATE` (`'{}'` = the quoted
command, e.g. `'sudo -n sh -c {}'`, or the VM lab's `'echo | su -m root -c
{}'`), `pfctl -si` runs before/after every run (abort unless pf is
Enabled) and `--lockstat max-flows|all` samples `lockstat -P -s 10 sleep T`
during the chosen runs (`dut.lockstat_top`: each section's top locks by
total wait). `netstat -Q` is also diffed for every protocol
(`dut.netisr_delta`), and each core's worst top interval is kept
(`dut.cpu_busy_peak_per_core`). During the run, `top -SHPn -d N -s 5`
is sampled in parallel with the `iperf3 -c` call, with N sized (via
`parsers.top_iterations_for`) so `N * 5s` spans the whole `--duration`
(floored at 3 iterations for very short runs) rather than only the
first few seconds. It's reduced to the mean per-core idle% and the top
5 threads by peak WCPU across all snapshots after the first (the first
is dropped as a FreeBSD `top` warm-up sample); the raw text is kept
alongside as `dut.top_raw` for audit/re-derivation. A `vmstat -i`
before/after pair yields the delta of `igc*` queue interrupts.

### Output JSON schema

```
{
  "meta": {backend, server, client, dut, started, duration, flows,
            dut_uname, dut_sysctls},
  "runs": [
    {flows, proto, direction, pkt_len,
     iperf: <parsed iperf3 -J output>,
     gbps, retransmits (TCP) | lost_percent (UDP),
     dut: {cpu_idle_per_core, top_threads, top_raw, if_errors_delta,
           irq_delta, mbuf_before, mbuf_after,
           pppoe_netisr_delta (per-CPU {handled, qdrops, queued}),
           pppoe_cpu_hits_delta (per-CPU net.pppoe.cpu_hits delta),
           vmstat_z_mbuf_before, vmstat_z_mbuf_after}}
  ]
}
```

### Summarizing results

```
python3 tests/perf/summarize.py tests/results/if_pppoe-*.json
```

prints a table: `backend | flows | proto | dir | Gbit/s | retrans/loss
| min core idle%`.

Add `--ratio-baseline raw` (across all the files given, backend can mix)
to append a `ratio-to-raw` column: each row's Gbit/s divided by the
same-shaped (`flows`, `proto`, `dir`, `pkt_len`) `raw`-backend row's
Gbit/s -- `docs/PERF-FWD-DESIGN.md` and the GOAL in the phase-2 scaling
brief judge by this ratio (and per-CPU spread), not an absolute Gbit/s
floor. A shape with no matching baseline row prints `n/a` rather than a
fabricated ratio.

## Forwarded (pf/NAT) matrix in the VM lab -- phase 2 scaling

`make -C lab test-perf-fwd BACKEND=if_pppoe|mpd5|raw` runs this matrix
through the VM lab's pf+NAT router path (not router-local iperf) and is
judged by throughput-as-a-fraction-of-raw and CPU spread, not the Gbit/s
floor below -- see `docs/PERF-FWD-DESIGN.md`.

## Pass criteria (from docs/TESTING.md)

- Throughput: >= 2.3 Gbit/s down and up with >= 4 flows.
- Single flow: >= 1.25x the mpd5 baseline on the same rig.

Run the `mpd5` backend first to establish the baseline, then compare
`summarize.py`'s Gbit/s column for `flows=4`/`flows=8`/`flows=16` rows
against the 2.3 Gbit/s floor, and the `flows=1` row against 1.25x the
mpd5 `flows=1` number. The `retrans/loss` and `min core idle%` columns
back the "no abnormal resource use" half of the Tier 3 pass bar (rising
retransmits/loss or a core pegged near 0% idle relative to that
backend's own baseline run is a fail even if throughput passes).

## Tests

```
pytest tests/perf -q
```

`test_parse.py` covers the `netstat -m`/`netstat -ibnd`/`vmstat
-i`/`top`/`pfctl -si`/iperf3-JSON parsers against real fixtures
captured over ssh from the DUT (under `fixtures/`, `netstat_*`,
`vmstat_i_*`, `top_sample.txt`) and from `<LAB_HOST>` (`iperf_*.json`,
including a captured connection-error shape and a `-u -R` reverse-UDP
capture, via throwaway loopback `iperf3 -s -D` servers killed
immediately after each capture), an output-schema check, ssh/iperf3
failure-handling tests (an injected failing runner plus one real,
network-only test against an unreachable address), an end-to-end
`--dry-run` test, an end-to-end abort test against an unreachable DUT
hostname, and a `summarize.py` table-rendering test.
