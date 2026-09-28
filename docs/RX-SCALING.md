# RX throughput scaling — analysis and fix plan (R023, MEM094/095)

**Requirement:** >= 2.3 Gbit/s RX with >= 4 flows on the DUT (2.5G sync WAN).
**Measured (2026-09-24 live rehearsal):** RX 1.01 Gbit/s single stream, 1.10-1.15
Gbit/s aggregate over 4 streams (even per-flow spread — netisr spreading WORKS);
TX 1.48 Gbit/s single stream; raw LAN (no PPPoE) 1.83 Gbit/s; zero retransmits;
session stable 45+ min. Server side (accel-ppp, kernel data path) ~0% CPU.

## Root cause

The RX demux is single-CPU by construction:

1. `pppoe_sess_input()` (if_pppoe.c:1031) runs as a pfil ETHERNET hook — on the
   CPU that the parent NIC's receive queue delivered the frame to.
2. **igc RSS cannot hash PPPoE frames** (no outer IP; ethertype 0x8864/0x8864).
   The L2 hash (server MAC -> router MAC) is constant for the whole session, so
   every session frame lands on ONE igc RX queue / ONE CPU.
3. That single CPU runs the whole per-packet demux: m_pullup guard, session
   lookup (epoch, lockless), `BPF_MTAP` (unconditional), `if_inc_counter` x2,
   `pppoe_hash_inner()` software hash, `netisr_dispatch()`.
4. The inner-hash spreading (pppoe_hash_inner -> pppoe_m2cpuid -> per-flow
   netisr workstreams, HYBRID) works — 4 flows spread evenly across workers —
   but it happens AFTER the single-CPU stage, so it cannot lift the aggregate.

At ~1.1 Gbit/s with 1492-byte frames that is ~92k pps of single-threaded demux
(~11 us/packet), and 2.3 Gbit/s needs ~193k pps — the demux must get ~2x cheaper
per packet, or spread, or both.

## Fix options (in evaluation order)

1. **Cut per-packet demux cost** (cheapest, do first):
   - `BPF_MTAP(sc->sc_ifp, m)` runs unconditionally — gate on
     `bpf_peers_present(sc_ifp)` (macro is cheap when no listeners, but verify
     the generated code; consider moving the tap after the netisr enqueue).
   - The two `if_inc_counter` calls are per-packet atomics — consider
     per-CPU counters or moving them to the netisr worker.
   - `m_pullup` guard: for the common cluster-backed frame it is a compare;
     verify the compiler does not pessimise the cold path.
   - `pppoe_hash_inner()`: the software RSS hash is a few multiplies — fine;
     but confirm `rss_proto_software_hash_v4` is not doing key setup per call.
2. **Spread the demux across the igc queues**: igc supports multiple RX queues;
   RSS cannot differentiate one session's frames, but **Flow Director /
   ntuple filters** can match on ethertype + MAC and steer to selected queues.
   Alternatively, use several accel-side sessions (multi-session PPPoE, e.g.
   one per flow class) — hardware then spreads by MAC — but that changes the
   service model; treat as last resort.
3. **Move work off the RX-queue CPU**: restructure so the pfil hook does the
   minimum (strip + hash + stash the session pointer) and the netisr worker
   does lookup + counters + MTAP. Preserves per-flow ordering (the inner-hash
   m2cpuid already pins a flow to one worker).
4. **Attribute before fixing**: `top -1H` during `iperf3 -c ... -R -P 4` —
   one pegged CPU in the igc taskq/netisr confirms; `netstat -Q pppoe` before
   and during shows queue depth/drops; `pmcstat -T` or `dtrace` profile the
   demux if available on the router.

## Non-negotiables

- D008/D012 teardown invariants and the two distinct NET_EPOCH_WAIT()s stay.
- The pinned suite (37/2/2) and the 66/66 teardown probe gate every change.
- Per-flow ordering: same inner 5-tuple must keep hashing to the same CPU
  (pppoe_m2cpuid) — reordering within a TCP flow is a regression.
- All throughput numbers via iperf3 (MEM094: python http.server caps ~976 Mbps
  on one core and faked the RX ceiling once already).

## Regression harness

The lab matrix (S02) runs the identical accel topology both directions,
flows 1/4/8, mpd5 vs if_pppoe — this is the canary that keeps the fix honest
without touching the router. Baseline for the fix: RX >= 1.10 Gbit/s today.
