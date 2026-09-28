# Data-path scaling design (phase 2, branch `p2/scaling`)

Goal: forward through pf/NAT at a rate approaching the raw (non-PPPoE) path
on any link -- 2.5G today, 10G later -- at 1, 4 and 16 flows in both
directions, with no single CPU saturated (`top -HSP`) and no driver lock
contention (`lockstat`). This document describes the per-packet paths after
the series and argues why each lock-free read is safe against destroy,
redial and parent departure. It extends `docs/RX-SCALING.md` (the analysis)
and does not replace the D008/D012 teardown invariants.

None of this has been measured yet: the series was written without lab
access. Each item is one commit so it can be measured and bisected on its
own; the "measure" lines say what should move.

## The per-packet paths after the series

RX, serial stage (parent NIC's RX CPU, `pppoe_pfil_in()` ->
`pppoe_sess_input()`): parent-set check, VLAN/ethertype check, header
validation, epoch-only session lookup, 20-byte strip, inner hash, the
`netisr_dispatch()` call. No lock, no interface counter, no BPF.

RX, parallel stage (netisr worker picked by `pppoe_m2cpuid()`,
`pppoe_data_input()`): one epoch load of `if_softc`, IPACKETS/IBYTES,
BPF tap, `sppp_input()`. The PPP_IP/PPP_IPV6 arms read the lock-free NCP
gate and call `ip_input()`/`ip6_input()` in place. `pp_last_receive` is
stored at most once a second.

TX (`pppoe_output()`, the caller's CPU): enter the net epoch, one load of
`if_softc`, `sppp_output()` (lock-free NCP gate), `pppoe_xmit_proto()` ->
`pppoe_encap_output()`: one acquire load of the session snapshot, a bound
check, one 22-byte `M_PREPEND`, an 18-byte `memcpy` plus the length and
protocol, `ether_output_frame()` on the parent. No lock, no shared atomic.

sppp's control frames (LCP, auth, NCPs) still go through `if_transmit`
(`pppoe_transmit()`) with the protocol field already on the mbuf, and still
take `pp_lock`. They are rare.

## Items

| Item | Commit subject | What it removes | Measure |
|---|---|---|---|
| R3 | cheap always-compiled inner-flow hash | software Toeplitz on the RX CPU; no spreading at all without `options RSS` | RX-CPU cycles/packet (`pmcstat`), `net.pppoe.cpu_hits` spread |
| R4 | `net.pppoe.dispatch_cpus` | 1/n of flows forwarded in place on the saturated RX CPU | RX CPU idle % in `top -HSP` at 4/16 flows |
| RX-move | charge RX counters and BPF tap on the worker | 2 counter adds + BPF check on the serial stage | RX-CPU cycles/packet |
| qlimit | netisr queue limit 4096 | queue overflow on bursts (`netstat -Q` QDrops) | `net.pppoe.netisr_enqueue_drop` |
| R2 | `pp_last_receive` on change only | one cache line written by every worker per packet | `pmcstat` cache-miss / HITM on `sppp_input` |
| R1/T3 | lock-free NCP gate | `pp_lock` (an exclusive mtx) per IP packet both ways | `lockstat` on "sppp" |
| T1 | epoch-only softc on TX | global `pppoe_sc_hold_lock` + 4 `sc_refs` atomics per TX packet | `lockstat` on "pppoe sc hold" |
| T2 | immutable session snapshot | `sc_mtx` per TX packet, `if_addr` read per packet | `lockstat` on "pppoe softc" |
| T4 | one 22-byte prepend | second `M_PREPEND` (and a second mbuf when space ran out) | TX cycles/packet |
| layout | snapshot pointer on its own line | control-plane writes invalidating the TX line | small; `pmcstat` HITM |

## Concurrency argument

The object lifetimes are unchanged from `p1/g2-lifecycle`; the fast path
only uses what they already guarantee.

### The softc (T1)

`pppoe_clone_destroy()` (unchanged ordering):

1. under `sc_mtx`: `sc_detaching = true`, `pppoe_disconnect()` (clears the
   session and, via `pppoe_clear_softc()`, the TX snapshot), lift
   `sc_parent`;
2. unlist from `V_pppoe_softcs`, drain the session task, unhash;
3. release the parent (`pppoe_parent_del()`, `if_rele()`);
4. `if_softc = NULL` (under `pppoe_sc_hold_lock`, for the ioctl holds);
5. `NET_EPOCH_WAIT()`;
6. wait for `sc_refs == 1` (ioctl and event-handler holds only);
7. `sppp_detach()`, drain the address task, `if_detach()`, `if_free()`;
8. drop the last ref -> `NET_EPOCH_CALL(pppoe_softc_free)`.

`pppoe_output()`, `pppoe_transmit()` and `pppoe_data_input()` load
`if_softc` once inside a net-epoch section and use the softc only inside
it. A load that returns non-NULL happened before step 4's store became
visible, so its section began before step 5 and step 5 waits for it: the
softc, its `struct sppp` (step 7) and its memory (step 8, itself deferred)
are all alive until the section ends. A load after step 4 returns NULL and
the packet is dropped. That is exactly the guarantee the hold gave; the
hold is kept only where the path may sleep (ioctl, departure/arrival
handlers), because a sleeping thread may not sit in an epoch section.

`ip_output()` and `ip6_output()` both `NET_EPOCH_ASSERT()` in releng/14.3,
so `pppoe_output()`'s `NET_EPOCH_ENTER()` nests (legal: each section has
its own tracker) and costs a per-CPU record insert, no shared write. It is
kept rather than asserted so a caller outside a section cannot reach the
softc unprotected -- the M002/S03/T2 panic came from such a race.
`sppp_output()` never sleeps: `pp_lock` is a mutex and `sppp_wq_add()` only
enqueues.

### The TX snapshot (T2)

`struct pppoe_tx_snap` is built completely, then published with
`atomic_store_rel_ptr()` under `sc_mtx` by the PADS arm; readers use
`atomic_load_acq_ptr()`, so they see a fully initialised snapshot or NULL.
It is never modified after publication. A replaced or cleared snapshot is
freed with `NET_EPOCH_CALL()`, so it outlives every section that could
have loaded it.

Invariant: a non-NULL snapshot exists only in `PPPOE_STATE_SESSION`, and
`pppoe_clear_softc()` -- the only way out of that state -- clears it. Every
path that lifts `sc_parent` and `if_rele()`s it passes through
`pppoe_clear_softc()` first, under the same `sc_mtx` hold or an earlier
one:

- destroy: `pppoe_disconnect()` in step 1, parent released in step 3;
- parent departure (`pppoe_parent_departed()`): `pppoe_clear_softc()`, then
  `sc_parent = NULL`, then `if_rele()`, then `NET_EPOCH_WAIT()` before the
  handler returns (so no transmitter still uses the departing ifnet when
  `if_detach_internal()` goes on to tear it down);
- vnet move (`pppoe_vmove_out()`): `pppoe_disconnect()` first;
- `PPPOESETPARMS` only swaps the parent at `PPPOE_STATE_INITIAL`, where no
  snapshot exists.

So `ts_parent` can borrow the softc's own `if_ref`: when a reader loaded
the snapshot, the ref was still held; the ref is dropped only after the
clear; the ifnet's free (the last `if_rele()` ->
`NET_EPOCH_CALL(if_free_deferred)`, releng/14.3 sys/net/if.c:715-721) is
scheduled at or after that drop, hence after the reader's section began,
hence deferred past it. The parent's MAC is copied into the snapshot at publish
time, so the TX path never dereferences `if_addr` (which a departing
parent frees after the departure event).

Redial: PADT or LCP-down clears the snapshot (TX drops with ENETDOWN, as it
did when `sc_state != SESSION`); the next PADS publishes a new one. A
transmitter that loaded the old snapshot just before the clear sends one
last frame on the old session -- the same window the old code had between
dropping `sc_mtx` and `ether_output_frame()`.

Accepted staleness: a parent MAC change during a session is not reflected
until the next session. There is no `iflladdr_event` handler to republish
the snapshot, because republishing would not save the session:

- RFC 2516 identifies a session by the two MACs and the session id. The AC
  learned our MAC from the PADI/PADR and keeps sending to it. The parent's
  receive filter now passes the new MAC, so the AC's frames stop arriving
  (unless the parent is promiscuous), whatever our frames carry.
- Our frames with the new source MAC match no session on an AC that checks
  the pair. With the old MAC, as the frozen snapshot sends them, the AC
  still accepts them. So the stale snapshot is no worse than a new one.
- Recovery is the normal redial. `PP_DEVF_KEEPALIVE` is on
  (`if_pppoe.c`, `pppoe_clone_create()`). With no frames received for
  `pp_max_noreceive` (15 s) and `pp_maxalive` (3) unanswered LCP echoes,
  one per 10 s keepalive tick (`if_spppsubr.c` `DEFAULT_*`), sppp restarts
  LCP. LCP-down clears the snapshot (above), and the next discovery takes
  the parent's current MAC. Discovery frames copy it per frame with
  `pppoe_lladdr_copy()`, and the next PADS copies it into the new
  snapshot.

A handler that forced that redial straight away would only shorten the
outage from about a minute to a discovery round trip.

Allocation: the snapshot is `malloc(M_NOWAIT)`ed in the PADS arm before
anything is committed. On failure the PADS is ignored and the still-armed
PADR timer retries.

### The NCP gate (R1/T3)

`struct sppp`'s `pp_dp_open` holds `1 << IDX_IPCP` / `1 << IDX_IPV6CP`
while that NCP is `STATE_OPENED`. It is updated with `atomic_set_int()` /
`atomic_clear_int()` in `sppp_cp_change_state()` and `sppp_cp_init()` --
the only writers of `scp[].state` -- under `pp_lock`, and read with
`atomic_load_int()`. The old code took `pp_lock` only to read the state and
dropped it before delivering or sending, so the state could change right
after either way: a packet racing an NCP transition is delivered/sent or
dropped on one side of the transition, as before. The `struct sppp` read is
alive for the reasons in "The softc".

### `pp_last_receive` (R2)

Read and compared first, stored only when `time_uptime` has moved. The
keepalive reads the same one-second value. Relaxed access, as before.

### The dispatch map (R4)

A malloc'd array of raw workstream indices, published by pointer
(`atomic_store_rel_ptr()` under an sx), read with an acquire load inside
the epoch `netisr_dispatch_src()` asserts, freed with `NET_EPOCH_CALL()`.
Its contents never change after publication, so a flow's workstream is
stable until an administrator changes `net.pppoe.dispatch_cpus` (a one-off
move). A map built for a different workstream count (a loader-loaded module
runs before netisr starts its per-CPU threads) is not used; the frame falls
back to `key % n` and kicks a rebuild on `taskqueue_thread`.

## Per-flow ordering

- One flow key -> one workstream: the hash is a pure function of the inner
  header and a per-boot seed; the map is fixed; netisr HYBRID queues rather
  than dispatching in place when the target workstream is busy or has work
  pending (`netisr_dispatch_src()`, releng/14.3 sys/net/netisr.c:1186), so in-place and queued frames of one
  workstream stay ordered.
- IPv4 fragments (MF set or offset != 0, the first included) hash on
  addresses + protocol, so a datagram's fragments share a workstream. A
  flow that mixes fragmented and whole packets can reorder between the two
  kinds; TCP sets DF and does not fragment in practice.
- IPv6: a fragment's next header is `IPPROTO_FRAGMENT`, so it never takes
  the ports arm; same property.
- Unhashable frames (control protocols) use the session id, as before.
- Map rebuilds reorder briefly. `pppoe_dispatch_rebuild()` publishes a new
  map when `net.pppoe.dispatch_cpus` is written, and once after a
  loader-loaded module sees netisr's workstream count change (until then,
  frames take the `key % n` fallback, which is another mapping again). A
  flow whose `key % dm_n` entry moves has frames still queued on its old
  workstream while new ones go to the new workstream, run in place or
  queued there. The two workstreams drain independently, so the new
  frames can overtake the queued ones. The window closes once the old
  workstream has drained what it held for that flow. That is at most
  `net.pppoe.netisr_qlimit` frames per workstream, normally far fewer.
  TCP treats this as a one-off reorder (dup ACKs, at worst a spurious fast
  retransmit). Nothing is lost. A flow whose entry did not move is not
  affected. No drain or barrier is attempted, because netisr has no public
  API to wait for another workstream's queue (see `MOD_UNLOAD` in
  `if_pppoe.c`).
- The flow-hash seed changes at most once, when a module loaded before
  random(4) was seeded redraws it (`pppoe_hash_init()`). Every flow is
  remapped at that point, with the same brief reorder window as a map
  rebuild.

## `net.pppoe.dispatch_cpus` tradeoffs

- `auto` (default) excludes CPU 0. Intel NICs steer frames their RSS
  cannot hash (all PPPoE frames) to queue 0, and iflib binds queue 0's
  interrupt to the first CPU of the device's set, normally CPU 0. I have
  not verified either for every NIC; check with `vmstat -i` / `top -HSP`
  which CPU runs the parent's RX queue and set the list explicitly if it
  is not CPU 0.
- Excluding the RX CPU turns the 1/n of frames that used to be processed
  in place into cross-CPU enqueues plus wakeups. It pays when the RX CPU is
  the bottleneck (one high-rate session); on a 2-CPU box it leaves one
  forwarding CPU -- use `all` there.
- The exclusion is static on purpose: deriving it per frame from `curcpu`
  would move a flow between workstreams whenever the interrupt moved, and
  reorder it.

## Known remaining costs

- Forwarded packets arrive from the LAN NIC with about 14 bytes of leading
  space (the stripped Ethernet header; not verified per driver), so the
  22-byte prepend still allocates an mbuf per packet. T4 halves the
  prepends, it does not remove that allocation; avoiding it needs the LAN
  driver to leave more headroom. Locally originated packets are covered:
  the module grows `max_linkhdr` (16 by default, releng/14.3
  sys/kern/uipc_mbuf.c:126) to 24 at load with `max_linkhdr_grow()`, so
  the stack reserves room for the whole header.
- The RX serial stage remains one CPU per session: RSS cannot hash PPPoE.
  It is now as short as it can be in software (no lock, no counter, no BPF,
  a cheap hash). Beyond that: NIC flow steering on ethertype, or several
  sessions.
- The ifnet packet and byte counters are per-CPU `counter(9)` adds on the
  workers (RX, `pppoe_data_input()`) and the transmitting CPU (TX,
  `pppoe_encap_output()`), charged once: sppp's own adds are compiled out
  (`SPPP_LOWER_COUNTS_BYTES`, from `p3/p3-pfil-counters`).

## Tunables and sysctls added

| Name | Kind | Default | Meaning |
|---|---|---|---|
| `net.pppoe.dispatch_cpus` | tunable + sysctl (string) | `auto` | CPUs flows are spread over: `auto`, `all`, or `1-3,5` |
| `net.pppoe.dispatch_map` | sysctl (read-only) | -- | CPUs the spec resolved to |
| `net.pppoe.netisr_qlimit` | tunable + sysctl | 4096 | per-workstream queue limit (<= `net.isr.maxqlimit`) |
| `net.pppoe.netisr_enqueue_drop` | counter (from `p3/p3-pfil-counters`) | -- | frames `netisr_dispatch()` refused |
