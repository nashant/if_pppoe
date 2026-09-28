# Host unit tests and fuzzers (`tests/unit/`)

A fast, host-runnable test layer that compiles the **real** kernel source
(`sys/net/*.c`) against a userland shim and exercises it directly. No QEMU,
no root, no network — `make -C tests/unit check` builds with
AddressSanitizer + UndefinedBehaviorSanitizer and runs every unit test in
well under a second. This complements the lab suite (`tests/functional`,
`tests/integration`), which stays the source of truth for anything that
needs a live kernel (see "What cannot be tested here").

The older `tests/sppp_*.c` transcribe the FSM into a userland *model*; these
tests instead `#include` the actual `sys/net/*.c`, so a change to the driver
is a change to what is tested.

## Layout

```
tests/unit/
  Makefile            check / fuzz / fuzz-regress / fuzz-docker targets
  include/            empty stand-ins for <sys/*.h>, <net/*.h>, ... so the
                      kernel sources' own #includes resolve to our shim
  kshim/
    kern.h            the kernel KPI surface (types, macros, prototypes),
                      force-included (-include) ahead of every TU
    kshim.c           its implementation: mbufs, locks, taskqueue, callouts,
                      counters, ifnet, netisr, pfil, MD5, log capture
    kshim.h           test-facing controls (kshim_reset, tx capture, ...)
  runner/             ktest.h + main.c: a dependency-free test runner
  tu/                 one TU per kernel source; each #includes the .c under
                      test, defines its fixtures, then #includes its t/*.c
  t/                  the tests themselves (grouped by area)
  fuzz/               libFuzzer targets
  corpus/             seed corpora (gen_seeds.py builds them from scapy)
  crashes/            minimised crash reproducers, replayed by fuzz-regress
```

Each kernel source is compiled exactly once, inside its `tu/<x>.c`:

| TU            | source under test          |
|---------------|----------------------------|
| `tu/sppp.c`   | `sys/net/if_spppsubr.c`    |
| `tu/pppoe.c`  | `sys/net/if_pppoe.c`       |
| `tu/disc.c`   | `sys/net/if_pppoe_disc.c`  |
| `tu/netisr.c` | `sys/net/if_pppoe_netisr.c`|

Including the `.c` gives the test file access to every `static` function and
`VNET_DEFINE_STATIC` global in it — no source changes, no exported test
hooks. The fuzz build reuses the same TUs with `-DKTEST_NO_TESTS`, which
drops the `t/*.c` includes and keeps only the fixtures.

## Running

```
make -C tests/unit check                 # build (ASan+UBSan) + run all
make -C tests/unit check TESTS=lcp        # only tests whose suite.name matches
make -C tests/unit list                   # list test names
make -C tests/unit check CC=clang         # clang instead of the default cc
```

`check` fails on: a failed assertion, a `panic()`/`KASSERT()`, a lock left
held, a queued taskqueue item left behind, or a leaked mbuf / `M_PPPOE`
allocation (each test brackets these). An `xfail` is a test that documents a
known, still-open bug: it is expected to fail, and the run stays green. If an
`xfail` ever *passes* it is reported as `XPASS` and fails the run — that is
the signal to delete the `XFAIL` because the bug is fixed.

## Adding a test for a new kernel function

1. Find the TU for the source your function lives in (table above). If the
   function is `static`, you must add the test inside that TU's `t/*.c`
   chain so the `#include <net/...c>` makes it visible.

2. Add a `t/<area>.c` (or extend one) with `KTEST(suite, name) { ... }`, and
   `#include "../t/<area>.c"` from the TU, inside its `#ifndef KTEST_NO_TESTS`
   block. Assertions: `KT_EQ`, `KT_NE`, `KT_ASSERT`, `KT_MEMEQ`, `KT_STREQ`,
   `KT_LOGGED("substr")` / `KT_NOT_LOGGED`, and `KT_EXPECT_PANIC(stmt, "substr")`
   for a KASSERT you expect to fire.

3. If the function needs a softc / sppp / parent, use the fixtures in `fx.h`
   (`fx_pppoe_new`, `fx_parent_new`, `fx_pppoe_bind`, `fx_sppp_confreq`,
   `fx_sppp_input`, `fx_pfil_in`, ...). Build packets with `t/frames.h`
   (`fr_start`/`fr_tag`/`fr_finish`) or `t/cp_util.h` (`cp_pkt`, `cp_tx_pop`).

4. Feed a **heap** buffer sized to the input, not a stack array, so ASan
   bounds the parser's reads exactly — `fx_sppp_confreq()` and
   `kshim_mbuf_from()` already do this. Reach for a real frame the peer
   could send; the point is to run the same bytes the wire would.

5. Need a KPI the shim does not model yet? Add a prototype/macro to
   `kshim/kern.h` and, if it needs behaviour, an implementation in
   `kshim.c`. Keep it the smallest thing that lets the code under test run;
   record any unavoidable per-function stub in a comment there. Most KPIs
   are either no-ops, record-and-return, or a faithful copy of the algorithm
   (as `m_pullup`/`m_adj`/MD5 are).

### The pending driver branches

The harness is structured so each can add tests without touching the shim:

- **p3/p3-mss** (MSS clamp): add `t/sppp_mss.c`, feed `fx_sppp_input()` a
  TCP-SYN payload on an opened session and assert the clamped MSS option on
  the transmitted frame (`cp_tx_pop`). The clamp is a pure function of the
  mbuf, ideal here.
- **p2/scaling** (inner flow hash, `pppoe_m2cpuid`, dispatch cpuset): extend
  `t/netisr_hash.c`. Set `kshim_netisr_ncpu` and assert the spread; the RSS
  hash in the shim is a stand-in, so assert *distribution and stability*
  (same flow -> same CPU), never specific hash values.
- **p3/p3-ipv6rx** (IPv6 payload RX): extend `t/sppp_input.c`; the
  `PPP_IPV6`/IPv6CP arms and `ip6_input()` are already stubbed
  (`kshim_ip6_input_calls`).

## Fuzzing

libFuzzer targets (`clang -fsanitize=fuzzer,address,undefined`), one per
parser, each with a seed corpus built from well-formed frames:

| target            | entry point exercised                              |
|-------------------|----------------------------------------------------|
| `fz_lcp_confreq`  | `sppp_lcp_confreq/confnak/confrej`                 |
| `fz_ipcp_confreq` | `sppp_ipcp_confreq/confnak/confrej`                |
| `fz_ipv6cp_confreq`| `sppp_ipv6cp_confreq/confnak/confrej`             |
| `fz_pppoe_input`  | the pfil RX hook: `pppoe_disc_input`, `pppoe_sess_input` |
| `fz_sppp_input`   | `sppp_input` -> CP dispatch, PAP/CHAP, timeouts    |

```
make -C tests/unit fuzz FUZZ_SECONDS=60    # every target for N seconds
make -C tests/unit fuzz-regress            # replay seeds + crash repros, once
make -C tests/unit seeds                   # regenerate corpus/ (needs scapy)
```

Seeds are read-only under `corpus/<target>/`; new inputs and crash artifacts
land under `build/`. A reproducer for a bug that has been **fixed** goes in
`crashes/<target>/` — `fuzz-regress` replays those under ASan on every run
(and in CI) and they must pass. A reproducer for a bug that is still **open**
goes in `known-crashes/<target>/` and is replayed by `make fuzz-known`, which
is expected to fail until the bug is fixed (so it stays out of CI).

### Fixed findings (were open as of 2026-09-27, fixed on p3/fuzz-fixes)

Found by the fuzzers on the first ~2-minute run, each pinned as an `xfail`
unit test (`fuzz_pass2_auth_stride_overread`, `fuzz_address_signed_shift_ub`);
both are now normal passing `KTEST`s and their minimised inputs moved from
`known-crashes/` to `crashes/{lcp_confreq,ipcp_confreq,sppp_input}/`:

1. `sppp_lcp_confreq()` pass-2 heap over-read (`if_spppsubr.c:3082`/`:3158`):
   pass 2 rewrote the Auth-Protocol stride (`l = 4`/`5`, used by the loop's
   `len -= l, p += l`) to size the NAK option it was building, desyncing
   pass 2 from pass 1's walk of the same buffer. Fixed by using a separate
   `naklen` for the NAK option and adding pass 2 its own `l < 2 || l > len`
   guard (also added to the IPCP and IPv6CP pass-2 loops).
2. `sppp_ipcp_confreq()` signed-shift UB (`if_spppsubr.c:4047`, also `:4270`,
   `:4304`, `:4312`): the address was built with `p[2] << 24` on a signed
   `int`, so a peer address `>= 128.0.0.0` was signed overflow. LCP already
   cast to `uint32_t`; IPCP now does too. Also reached end-to-end via
   `fz_sppp_input` (`crashes/sppp_input/`).
3. `sppp_lcp_confreq()` pass-1 `LCP_OPT_MP_EID` debug log over-read
   (`if_spppsubr.c:2983`, found by the 60s post-fix `fz_lcp_confreq` run):
   the `if (debug) addlog(..., p[2], l)` after the class switch read `p[2]`
   unconditionally, even when `l < 3` (an option too short to carry a class
   octet). Fixed by only reading `p[2]` when `l >= 3`.
The first byte(s) of each input are a small control header (debug flag, auth
config, FSM state, mbuf segment size) so one corpus reaches many arms; the
exact framing is documented at the top of each `fuzz/fz_*.c`.

### No local clang

This host has only gcc; clang lives in a container. Every fuzz goal has a
`-docker` wrapper that runs it in `silkeh/clang:19` against this tree:

```
make -C tests/unit fuzz-docker FUZZ_SECONDS=120
make -C tests/unit fuzz-docker FUZZ_GOAL=fuzz-regress
```

## What cannot be tested here (stays in the lab)

The shim is single-threaded and models only *shapes* of the kernel, so these
belong to `tests/functional`/`tests/integration` on the QEMU lab:

- **Real locking / SMP races.** Locks here only track ownership (a
  WITNESS-lite: recursion, unowned unlock, lock-held-across-taskqueue and
  KASSERT(WLOCKED) all fire), but there is no concurrency, no lock ordering,
  no actual contention or memory-ordering behaviour.
- **epoch(9) reclamation.** `NET_EPOCH_ENTER/EXIT` only count depth and
  assert "in epoch"; `NET_EPOCH_CALL` runs the callback inline and
  `NET_EPOCH_WAIT` is a no-op. Deferred-free correctness and the
  destroy-vs-RX races are lab-only.
- **Real ifnet / netisr / pfil.** `if_transmit`, `netisr_dispatch`,
  `ether_output_frame`, `ip_input` capture or count and return; there is no
  driver, no queueing discipline, no per-CPU workstreams, no VIMAGE.
- **callouts / taskqueue timing.** They run when a test explicitly fires
  them (`kshim_callout_fire`, `kshim_run_tasks`); there is no clock.
- **`MHLEN` and mbuf geometry** are approximations of amd64 FreeBSD 14, set
  in `kern.h`; exact cluster thresholds are confirmed in the lab.
- **Anything below the driver** (ioctl plumbing through `ifioctl`, address
  application via `in_control_ioctl`, DAD, devd) is stubbed to success.

So a green `make check` means the parsers and state machines are correct on
the bytes tested; it does not replace a lab dial. Both run in CI.
