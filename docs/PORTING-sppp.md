# Porting NetBSD sppp(4) to FreeBSD 14.3 (OPNsense 25.7)

Source pin: `NetBSD/src` commit `5ee7eb6e8db7128264453921994932a2c2a5af70`
(trunk, 2026-09-12T21:03:50Z). Fetch any file with:

```sh
gh api -H "Accept: application/vnd.github.raw" \
  "repos/NetBSD/src/contents/<path>?ref=5ee7eb6e8db7128264453921994932a2c2a5af70"
```

The three files below were fetched at that pin on 2026-09-19. The vendor
state at the pin is byte-identical to the last commit that touched all three
paths, `e70d6c71bc89a08d87edf53b01d9cd0677fa4409` (verified by re-fetching
that commit and comparing SHA-256 — 2026-07-28 07:10:42Z, matching the
`$NetBSD:` RCS ids in the file headers).

## Provenance

| NetBSD path | Lines at the pin (pristine) | SHA-256 (pristine) | Lands at |
|---|---|---|---|
| `sys/net/if_sppp.h` | 260 | `f91cf5f0f38dfe3f1b1233a2f90d25360fa71a4955d740bd2b4b8eb24c24172d` | `sys/net/if_sppp.h` |
| `sys/net/if_spppvar.h` | 312 | `395049d92ba9c43cfd81659383445a8330c16ad3ddbc478804a68247662d6418` | `sys/net/if_spppvar.h` |
| `sys/net/if_spppsubr.c` | 6866 | `20368eb0f1d5e729b46eb589b63d46dacf51d7c344c68c0164f5d7091d978c24` | `sys/net/if_spppsubr.c` |

Vendoring rule: the three files are kept pristine (`sha256sum` must equal the
values above) with exactly one addition — the `FreeBSD port notice` block
inserted immediately after the original NetBSD licence/copyright header in
each file. The original licence text is never modified. `wc -l` of the
vendored (noticed) files is therefore pristine + 13 per file
(273 / 325 / 6879).

Note on the `if_spppsubr.c` header: at this pin the top copyright block is the
historical Cronyx Engineering Ltd. / Joerg Wunsch / itojun text with the
FreeBSD Project disclaimer, as carried forward from FreeBSD's original
`if_spppsubr.c` — it is a permissive BSD-style licence, not a NetBSD
Foundation BSD-2 block. Do not rewrite it; the port notice sits below it.

## Deliberately not ported

These features were deliberately dropped. Their ioctls/code paths are removed
or never wired; T2-T5 reject them (or leave them unreachable) rather than
half-porting them.

| Feature | NetBSD location (pristine, at the pin) | Why |
|---|---|---|
| Idle timeout (`SPPPGETIDLETO` 125 / `SPPPSETIDLETO` 126, incl. legacy `__SPPPGETIDLETO50` 125 / `__SPPPSETIDLETO50` 126) | `sys/net/if_sppp.h:115-118`; `pp_idle_timeout` in `sys/net/if_spppvar.h:169-171` | Spec §2 non-goal and §8 "Not implemented". pppoectl list mode still calls 125, so the driver answers with always-disabled stubs (see decision below). |
| Dial filters (`SPPPIOCSDIALFILT` 144, `SPPPIOCSIACTIVE` 145, `SPPPIOCSOACTIVE` 146) | `sys/net/if_sppp.h:255-257` | Spec §8 "Not implemented"; pulls in `bpf_program` and `psref`. |
| `SPPP_FILTER` (`pp_dial_filt`, `pp_active_filt_*`, `sppp_update_last_activity`) | `sys/net/if_spppvar.h:208-226`; uses at `sys/net/if_spppsubr.c:834, 879, 892, 910-911, 1304-1309` | Only used by the dial filters above; `pserialize_*`/`psref_*` are NetBSD-only and would otherwise need shims. |
| On-demand dialling (`pp_ondemand`, `IFF_AUTO`) | `sys/net/if_spppvar.h:172`, `IFF_AUTO` shim at `sys/net/if_spppsubr.c:154`, uses at `:1035, :1062` | Spec §2 non-goal. |
| `PPPOE_SERVER` (PADO/PADR server arms) | `sys/net/if_pppoe.c` (M001 driver, client-only) | Spec §2 non-goal (client only). |
| MS-CHAP v1/v2, EAP, VJ and deflate compression | not present in NetBSD sppp at the pin | Spec §2 non-goal. |
| Cisco HDLC mode (`PP_CISCO` remnants: `CISCO_MULTICAST/UNICAST/KEEPALIVE`, `struct cisco_packet`, inline reject arms) | `sys/net/if_spppsubr.c:208-213, 253-261, 713-719` | Never reachable from a PPPoE lower layer; the pin already rejects Cisco frames in PPP mode. |

### Decision: idle-timeout ioctls answered with always-disabled stubs

`pppoectl` list mode unconditionally calls `SPPPGETIDLETO` (125) and would die
unless the driver answers 125/126. Requirement R005 ("NetBSD pppoectl works
unmodified") wins, so the driver implements 125/126 as always-disabled stubs
(return zeroed `spppidletimeout` / accept-and-ignore). This keeps the
"no idle-timeout mechanism ported" claim true while keeping the tool verbatim.
(Implemented in S02/S03 with the rest of the SET/GET ioctl group.)

## NetBSD KPI → FreeBSD 14.3 KPI (skeleton)

Every mapping below is implemented in `sys/net/if_sppp_compat.h` unless the
"How" column says the call site is edited directly. The **Status** column
starts at `planned`; S01 (T2/T3) promotes each row to `proven` when the
compile+link loop through `if_sppp_compat.h` succeeds with the symbol in the
object, and records any row the compile loop actually needed but this table
missed. This table is the audit trail for the port; it must list every macro
the vendored source uses.

| NetBSD | FreeBSD 14.3 | How | FreeBSD citation | Status |
|---|---|---|---|---|
| `kmem_zalloc(n, KM_SLEEP)` | `malloc(n, M_PPPOE, M_WAITOK \| M_ZERO)` | macro | `sys/sys/malloc.h` | planned |
| `kmem_alloc(n, KM_NOSLEEP)` | `malloc(n, M_PPPOE, M_NOWAIT)` | macro | `sys/sys/malloc.h` | planned |
| `kmem_free(p, n)` | `free(p, M_PPPOE)` | macro (size dropped) | `sys/sys/malloc.h` | planned |
| `kmem_intr_free(p, n)` | `free(p, M_PPPOE)` | macro | — | planned |
| `callout_t` | `struct callout` | typedef | `sys/sys/callout.h` | planned |
| `callout_init(&c, CALLOUT_MPSAFE)` + `callout_setfunc(&c, f, a)` | `callout_init_mtx(&c, &sp->pp_mtx, 0)` + the function passed to `callout_reset()` | call sites edited; the mutex makes `callout_stop()` race-free | `sys/sys/callout.h` | planned |
| `callout_schedule(&c, ticks)` | `callout_reset(&c, ticks, f, a)` | macro per timer (each timer has one handler) | — | planned |
| `callout_halt(&c, lock)` | `callout_drain(&c)` | macro | — | planned |
| `krwlock_t` + `rw_enter/rw_exit` (the `sppp` lock) | `struct mtx` + `mtx_lock/mtx_unlock` | macro; the sppp lock is only taken for control frames and ioctls (spec §9), so a mutex is cheaper than an `sx` and lets callouts share it | `sys/sys/mutex.h` | planned |
| `kmutex_t` + `mutex_enter/mutex_exit` | `struct mtx` + `mtx_lock/mtx_unlock` | macro | `sys/sys/mutex.h` | planned |
| `workqueue_create/enqueue/destroy`, `struct work` | `taskqueue_thread`, `struct task`, `TASK_INIT`, `taskqueue_enqueue`, `taskqueue_drain` | `sppp_wq_*` reimplemented in the compat header (one shared module taskqueue, per-interface task, pending flag — research amendment 4) | `sys/sys/taskqueue.h` | planned |
| `if_statinc(ifp, if_ierrors)` — also `if_ibytes`, `if_iqdrops`, `if_noproto`, `if_oerrors` | `if_inc_counter(ifp, IFCOUNTER_IERRORS, 1)` (each name maps to its IFCOUNTER_* enum) | macro per counter name | `sys/net/if_var.h` | planned |
| `if_statadd(ifp, if_obytes, n)` | `if_inc_counter(ifp, IFCOUNTER_OBYTES, n)` | macro | `sys/net/if_var.h` | planned |
| `ifp->if_xname` | `if_name(ifp)` | macro | `sys/net/if_var.h` | planned |
| `cprng_strong32()` | `arc4random()` | macro | `sys/sys/libkern.h` | planned |
| `MD5_CTX`, `MD5Init/Update/Final` | identical names | `#include <sys/md5.h>` (verify header path at S01) | `sys/sys/md5.h` | planned |
| `kauth_authorize_network(..., KAUTH_REQ_NETWORK_INTERFACE_SETPRIV, ...)` | `priv_check(curthread, PRIV_NET_SETIFPHYS)` | call sites edited | `sys/sys/priv.h` | planned |
| `sppp_rt_ifmsg(ifp)` | `rt_ifmsg(ifp)` (FreeBSD 14.3 1-arg form) | the static helper is kept in if_spppsubr.c (now takes `struct sppp *sp`); the inner call is a call-site edit to native `rt_ifmsg()` | `sys/net/route.h` | planned |
| `if_down(ifp)` / `if_up(ifp)` | identical names | — | `sys/net/if_var.h` | planned |
| `m_copyback(m, off, len, cp)` | identical (returns void on FreeBSD; NetBSD too) | — | `sys/sys/mbuf.h` | planned |
| `m_pullup`, `M_PREPEND`, `m_freem`, `m_gethdr` | identical | — | `sys/sys/mbuf.h` | planned |
| `M_REGION_GET(p, T, m, off, len)` | `m_pullup()` + pointer arithmetic | macro | — | planned |
| `bpf_mtap(ifp, m, BPF_D_IN)` | `BPF_MTAP(ifp, m)` (direction is implicit) | macro | `sys/net/bpf.h` | planned |
| `log(LOG_INFO, ...)` | identical | `#include <sys/syslog.h>` | `sys/sys/syslog.h` | planned |
| `KASSERT(cond)` (no message) | `KASSERT(cond, ("%s", __func__))` | macro `SPPP_KASSERT(cond)` | `sys/sys/systm.h` | planned |
| `cpu_softintr_p()` | always-false static inline in the compat header (FreeBSD 14.3 has no such KPI) | compat function; the vendored `KASSERT(!cpu_softintr_p())` work-handler guards hold because those handlers run on `taskqueue_thread`, never in a software-interrupt context | `sys/sys/cpu.h` | planned |
| `sppp_set_ip_addrs(sp)` calling NetBSD `in_ifinit()` | `pppoe_set_ip_addrs()` → `in_control_ioctl(SIOCAIFADDR, ...)` from `taskqueue_thread` | rewritten (S03) | `sys/netinet/in.c` | planned |
| `sppp_update_ip6_addr(sp)` | `pppoe_set_ip6_addr()` → `in6_control_ioctl(SIOCAIFADDR_IN6, ...)` from `taskqueue_thread` | rewritten (S04) | `sys/netinet6/in6_var.h` | planned |
| `pserialize_*`, `psref_*` | removed with `SPPP_FILTER` | — | — | planned |
| `atomic_load_relaxed/atomic_store_relaxed` | `atomic_load_int/atomic_store_int` (and `_ptr` variants) | macro | `sys/sys/atomic_common.h` | planned |
| `<net/ethertypes.h>` | `<net/ethernet.h>` | include edited | `sys/net/ethernet.h` | planned |
| `<sys/cprng.h>`, `<sys/kauth.h>`, `<sys/workqueue.h>`, `<sys/once.h>`, `<sys/pserialize.h>`, `<sys/psref.h>`, `<sys/compat_stub.h>` | dropped | includes edited | — | planned |
| `kmem_intr_alloc(n, KM_NOSLEEP)` | `malloc(n, M_PPPOE, M_NOWAIT)` (interrupt path: never wait; T2 Step 4 audit) | macro | `sys/sys/malloc.h` | planned |
| `callout_destroy(&c)` | no FreeBSD counterpart for embedded `struct callout`; `callout_drain(&c)` only | macro | `sys/sys/callout.h` | planned |
| `atomic_load_acquire` / `atomic_store_release` | plain volatile access (SPPP_FILTER-only sites, compiled out) | macro | — | planned |
| `__BIT(n)` | `(1 << (n))` | macro | — | planned |
| `__read_mostly` | empty (no cacheline attribute on FreeBSD) | macro | — | planned |
| `__predict_true/__predict_false` | `__builtin_expect(!!(e), 1/0)` | macro | `sys/sys/cdefs.h` | planned |
| `__UNCONST(x)` | cdefs has it; compatibility alias | macro | `sys/sys/cdefs.h` | planned |
| `ISSET/SET/CLR(x, v)` | bit-ops helpers (FreeBSD has no ISSET) | macro | — | planned |
| `M_DONTWAIT` | `M_NOWAIT` | macro | `sys/sys/mbuf.h` | planned |
| `m_reset_rcvif(m)` | `(m)->m_pkthdr.rcvif = NULL` | macro | `sys/sys/mbuf.h` | planned |
| `MGETHDR(m, how, MT_DATA)` | FreeBSD mbuf.h has `MGETHDR`; `M_DONTWAIT`->`M_NOWAIT` | — | `sys/sys/mbuf.h` | planned |
| `M_PREPEND`, `m_pullup`, `m_freem`, `m_adj` | identical | — | `sys/sys/mbuf.h` | planned |
| `if_transmit_lock(ifp, m)` | `if_transmit(ifp, m)` (14.3 folded the lock-in name away) | macro | `sys/net/if_var.h` | planned |
| `IF_QFULL/IF_IS_EMPTY/IF_PURGE/IF_DROP(ifq)` | FreeBSD ifq.h has `_IF_QFULL`/`IFQ_*`; aliases bridge the names (IF_DROP = dequeue+free) | macro | `sys/net/ifq.h` | planned |
| `IFQ_CLASSIFY(ifq, m, af)` | no-op (no ALTQ classify on FreeBSD) | macro | `sys/net/ifq.h` | planned |
| `IFQ_LOCK_INIT` / `IFQ_LOCK_DESTROY` | dropped with the deleted `pp_fastq`/`pp_cpq` ifqueues | — | — | planned |
| `cprng_fast32()` / `cprng_strong(gen, buf, len, flags)` | `arc4random()` / `arc4random_buf(buf, len)` | macro | `sys/sys/libkern.h` | planned |
| `mutex_obj_alloc(MUTEX_DEFAULT, IPL_SOFTNET)` | `sppp_mutex_obj_alloc()` (malloc + `mtx_init`) | macro | `sys/sys/mutex.h` | planned |
| `rw_init/rw_destroy/rw_read_held/rw_write_held` | `mtx_init/mtx_destroy/mtx_owned` | macro | `sys/sys/mutex.h` | planned |
| `pktqueue_t *pktq` / `ip_pktq` / `ip6_pktq` / `pktq_enqueue` | direct `ip_input(m)` / `ip6_input(m)` (no second netisr hop; spec §6.5) | compat struct + function | `sys/netinet/ip_var.h`, `sys/netinet6/ip6_var.h` | planned |
| `pktq_rps_hash_func_t` / `sppp_pktq_rps_hash_p` / `pktq_rps_hash` | RPS not ported: int-typed global seeded 0, hash drops | macro | — | planned |
| `time_uptime32` | `(uint32_t)time_uptime` | macro | `sys/sys/systm.h` | planned |
| `PPP_MINMRU`, `PPP_NOPROTO` | `128`, `0` (FreeBSD ppp_defs.h lacks them) | macro | `sys/net/ppp_defs.h` | planned |
| `PRI_SOFTNET`, `IPL_SOFTNET`, `WQ_MPSAFE`, `MUTEX_DEFAULT` | macro args to the shim (swallowed) | macro | — | planned |
| `IN6_PRINT(buf, addr)` | `inet_ntop(AF_INET6, ...)` | macro | `sys/netinet/in.h` | planned |
| `bpf_mtap(ifp, m, dir)` | `if_bpfmtap(ifp, m)` | macro | `sys/net/if_var.h` | planned |
| `KASSERTMSG` | not used at the pin | — | — | planned |
| `sppp_sysctl_flags/sppp_sysctl_setup`, `sysctl_teardown` | dropped (sysctllog not ported) | — | — | planned |
| `if_alloc_sadl` | dropped | — | — | planned |
| `ifioctl_common()` calls | dropped (FreeBSD ifioctl did the common work) | — | — | planned |
| `ifa_rtrequest` / `p2p_rtrequest` | **no such member on FreeBSD 14.3** (`struct ifaddr` has none; `struct ifnet` has none) — the SIOCINITIFADDR arm is a no-op; S03's `in_control_ioctl(SIOCAIFADDR)` owns route semantics | — | `sys/net/if_var.h`, `sys/net/if_private.h` | planned |
| `SPPPSUBR_MPSAFE` | `1` (compiles in the direct-transmit tail of `sppp_output`) | macro | — | planned |
| `sppp_from_ifp(ifp)` | `(struct sppp *)if_getllsoftc(ifp)` — the only ifp→sppp path (softc-embed contract) | function | `sys/net/if_var.h` | planned |
| `sppp_rx_payload(sp)` | removed: every PPP frame, payload included, now goes through `sppp_input()`, which does the `pp_last_receive` poke itself | — | — | removed |

### Compile breakers dropped in S01 (T2)

- `sppp_sysctl_setup` / `sppp_sysctl_flags` (NetBSD sysctllog) — dropped.
- `if_alloc_sadl` — dropped.
- `ifioctl_common()` calls — dropped (FreeBSD ifioctl already did the common work).
- The dead `#if defined(__FreeBSD__) && __FreeBSD__ >= 3` `struct callout_handle
  ch[IDX_COUNT]` block in the vendored `if_spppvar.h` — deleted (no such type on
  FreeBSD 14.3; compile breaker).

### Calling-context rules this port must obey

1. `in_control_ioctl()` takes `sx_xlock(&in_control_sx)` — **sleepable context
   only**. Address changes therefore run on `taskqueue_thread`, never from the
   netisr handler, the pfil hook, or a callout.
2. The sppp mutex (`pp_mtx`) is taken only for control protocol frames and
   ioctls (spec §9). `PPP_IP`/`PPP_IPV6` frames bypass it entirely; the
   `sppp_input` control path is sleep-free (no `KM_SLEEP`/`M_WAITOK`
   allocation, audited in S01).

   **T2 audit (2026-09-19):** `sppp_input` (netisr RX) itself allocates
   nothing; its reachable control handlers allocate only with
   `kmem_intr_alloc(..., KM_NOSLEEP)` (→ `M_NOWAIT`) and the output mbuf
   builders use `MGETHDR(m, M_DONTWAIT→M_NOWAIT, MT_DATA)`.  Every
   sleeping allocation site sits outside the input path by construction:
   `kmem_alloc(..., KM_SLEEP)` at line 1446 is inside the `#ifdef
   SPPP_FILTER` dial-filter ioctl arm (compile breakers dropped,
   SPPP_FILTER not ported); the second `kmem_alloc(..., KM_SLEEP)` at
   line 6619 is in `sppp_notify_tlf_wlocked()` (runs on the taskqueue
   thread, sleepable); and the four `M_WAITOK` `malloc(M_DEVBUF)` sites
   (lines 5949–6000) are in `sppp_params()` (SPPPIO* ioctl path,
   sleepable).  So the netisr RX control path never issues a sleeping
   allocation and keeps calling-context rule 2; T3's compile+link loop
   re-verifies under the module build.
3. The parent's transmit (`pppoe_transmit()`/`ether_output_frame()`) must not
   be called with `pp_mtx` or `sc_mtx` held.

## Struct surgery (S01, T2)

Applied on 2026-09-19; the diff is read against the pristine SHA-256s in the
provenance table above. Every delta below is a deliberate layout change; the
rest of the vendored text is untouched.

### softc-embed contract

`struct pppoe_softc` (T3) gains `struct sppp ppp;` — one embedded sppp per
cloned interface.  The driver points `if_setllsoftc(ifp, &sc->ppp)` at attach
(if_softc stays the driver's own `pppoe_softc` handle, as in M001), so
`sppp_from_ifp(ifp)` is a pure container-of read of the link-layer softc
slot.  The embedded `struct sppp` is a single allocation with the softc
(`malloc(M_PPPOE)` in `pppoe_clone_create`), keeping the two lifetimes
identical; teardown drains the work queue before the free (S02/S05 rule).

### struct sppp / struct sppp_work layout delta (vs pristine)

- `struct ifnet pp_if` (value-embedded, "must be first") → `struct ifnet
  *pp_if` back-pointer.  Every `&sp->pp_if` / `sp->pp_if.` call site is
  rewritten to `sp->pp_if` / `sp->pp_if->` (grep-verifiable, Step 3).
- `struct ifqueue pp_fastq` / `pp_cpq` deleted.  SPPPSUBR_MPSAFE=1 compiles
  the direct-transmit tail of `sppp_output()` in (and the legacy
  enqueue/start body out); `sppp_cp_send()`/`sppp_auth_send()` now count
  bytes, drop the sppp lock, and call `if_transmit` directly.  The queue
  helpers `sppp_flush`/`sppp_isempty`/`sppp_dequeue` operate on
  `ifp->if_snd` only (a FreeBSD `struct ifaltq` — first fields are the
  ifqueue, so the IFQ_* macros apply unchanged).
- `struct work work` in `struct sppp_work` deleted (research amendment 4:
  never embed a task per work item).  The (func, arg, state) triple stays
  plus a `wq_next` link field chaining the interface's pending work items.
- The dead `#if defined(__FreeBSD__) && __FreeBSD__ >= 3` block (`struct
  callout_handle ch[IDX_COUNT]` + `pap_my_to_ch`) is deleted — `struct
  callout_handle` does not exist on FreeBSD 14.3 (compile breaker).
- `struct sysctllog *pp_sysctl_log` dropped together with
  `sppp_sysctl_setup`/`sppp_sysctl_flags` (sysctllog is NetBSD-only);
  `if_alloc_sadl()` and the four `ifioctl_common()` calls are dropped
  (FreeBSD's ifioctl already performed the common work).
- The public entry points keep their `struct ifnet *` signatures
  (`sppp_attach/detach/input/output/ioctl`), so the host dispatch is
  type-identical to M001's expectations.

### sppp_wq_* shim (research amendment 4)

Reimplemented in `if_sppp_compat.h` section B on the **module-level
`taskqueue_thread`** with **one `struct task` per interface** and a spin-
locked FIFO of pending `struct sppp_work` chained by `wq_next` plus the
`wq_pending` flag (enqueue coalescing).  `sppp_wq_add()` is sleep-free and
safe from the netisr RX path / callout / ioctl contexts (calling-context
rule 2): it only CASes item state FREE→BUSY and pushes a pointer; the task
drains the FIFO under the sppp lock, invoking each handler as NetBSD did.
`sppp_wq_wait()` marks the item UNAVAIL and drains the task.  This preserves
NetBSD's per-CP ordering for the (single) control-protocol thread while
using exactly one task object per interface — none per work item.

### Fixes that are not layout (also T2)

- `__packed` on the three vendored structs is dropped: FreeBSD 14.3 clang
  does not define the GCC alias, and the members are byte layouts anyway.
- `#if defined(_KERNEL_OPT)` block trimmed to the opt headers that exist in
  the FreeBSD module build (`opt_inet.h`, `opt_inet6.h`); the NetBSD-only
  opt_ files are gone.

## T2 field notes (verified deltas, 2026-09-19)

- **MD5 header path**: verified `sys/sys/md5.h` exists on FreeBSD 14.3
  (fetched releng/14.3); `sys/md5.h` does not.  The vendored
  `#include <sys/md5.h>` resolves correctly, so no include change is
  needed.  `MD5_CTX`/`MD5Init/Update/Final` signatures match.
- **`atomic_load_relaxed/atomic_store_relaxed`**: FreeBSD 14.3 has no
  relaxed-ordering atomics and no `atomic_load_int` names (the plan's
  `sys/sys/atomic_common.h` citation is a NetBSD path).  Mapping: plain
  volatile access — all sites are bool/int/uint32 flags where NetBSD's
  relaxed contract is a single aligned word load/store; T3's compile loop
  and S02's live dials confirm under WITNESS.
- **`callout_init` maps to `callout_init_mtx(&c, NULL, 0)`** in this static
  layer; the per-softc binding to the sppp lock (race-free `callout_stop`)
  lands with the S02 wiring that makes each callout per-interface.
- **`ifp->if_xname` is kept as a field** (14.3 `net/if_private.h` keeps
  `char if_xname[IFNAMSIZ]`), so the vendored `->if_xname` accesses compile
  unchanged; `if_name()` is used at the `SPPP_LOG`/attach call sites that
  only have a bare `ifp`.
- **`if_transmit_lock` does not exist on 14.3** (folded into `if_transmit`) —
  compat maps the name.
- **`if_rtrequest`/`ifa_rtrequest` do not exist on 14.3** — the plan's
  "move onto ifp->if_rtrequest" target is stale; the SIOCINITIFADDR arm is
  now a no-op and S03's address application owns p2p route semantics.
- **`sppp_get/set/clear_ip_addrs`, `sppp_get_ip6_addrs`,
  `sppp_update_ip6_addr` remain NetBSD-formed** (they call `in_ifinit`/
  `if_first_addr_psref`/`curlwp_bind`/psref helpers) — those rows are the
  `rewritten (S03)`/`rewritten (S04)` KPI-table entries, out of T2 scope.
  T3's compile loop logs each as it surfaces and S03 replaces the bodies
  with the `in_control_ioctl` taskqueue recipe (spike S2).
- **`M_DONTWAIT` → `M_NOWAIT`** and **`m_reset_rcvif`** (only used at the
  two auth/cp send mbuf builders) are provided by the compat header.
- **Workqueue names/priority**: `PRI_SOFTNET`/`IPL_SOFTNET`/`WQ_MPSAFE`/
  `MUTEX_DEFAULT` are swallowed macro arguments; the shim task uses
  priority 0 on the shared `taskqueue_thread`.
- **`sppp_wq_*` API surface** (compat header section B): exactly four
  entry points — `sppp_wq_create()`, `sppp_wq_add()`, `sppp_wq_wait()`,
  `sppp_wq_destroy()` — plus the internal `sppp_wq_set()` binder and
  `sppp_wq_task()` drainer, all on the one module-level
  `taskqueue_thread` with a single per-interface `struct task`
  (`wq_task`) and the `wq_pending` enqueue-coalescing flag.
- **`cpu_softintr_p()`**: FreeBSD 14.3 has no such KPI; the compat header
  stubs it always-false, which makes the vendored
  `KASSERT(!cpu_softintr_p())` work-handler guards trivially hold on
  `taskqueue_thread`.
- **`IN6_PRINT`** is implemented via the internal static inline
  `sppp_in6_print()` helper (`inet_ntop(AF_INET6, ...)` into the caller's
  buffer), defined in compat-header section A under `#ifdef INET6`;
  `sppp_in6_print` is also the symbol the IN6_PRINT row's "How" refers to.
- **`sppp_rt_ifmsg()`**: kept as a static function in if_spppsubr.c; its
  signature ported from `struct ifnet *` to `struct sppp *` (reads
  `sp->pp_if`) and its inner call edited to FreeBSD's 1-arg `rt_ifmsg()`.
- **Internal markers in the compat header** (not KPI mappings, listed for
  completeness): `_NET_IF_SPPP_COMPAT_H_` (include guard),
  `SPPP_COMPAT_STRUCTS_DEFINED` (section-B guard used by if_spppvar.h's
  second include) and `SPPP_WQ_TASK_PRIO` (task priority).

## Compile-loop log (S01, T3)

Every compile-breaker the S01 T3 module build actually hit, in fix order.
Build loop: `lab/vm/build-module.sh sync && build sys/modules/if_pppoe` on
`build` (OPNsense 25.7 = FreeBSD 14.3-RELEASE-p16, amd64 SMP).  Final state:
if_spppsubr.c compiles clean under the kmod `-Werror` flag set and links into
if_pppoe.ko (94 `sppp_` symbols, including sppp_attach/detach/input/output/
ioctl, no undefined sppp refs).  2026-09-20.

| # | Symptom (cc error) | Root cause | Fix | Status |
|---|---|---|---|---|
| 1 | `__KERNEL_RCSID` undeclared | NetBSD-only cdefs macro | call-site edit: drop (replaced by a comment) | proven |
| 2 | `sys/inttypes.h` not found | NetBSD-only header path | include edited: `<sys/inttypes.h>` → `<sys/stdint.h>` (both in if_spppsubr.c and compat section A) | proven |
| 3 | `sys/atomic.h` not found | NetBSD-only header path | include dropped (FreeBSD `machine/atomic.h` comes transitively via `sys/systm.h`) | proven |
| 4 | `sys/cpu.h: call to undeclared BUS_READ_IVAR/device_get_parent` | FreeBSD `sys/cpu.h` requires `sys/bus.h` first | `#include <sys/bus.h>` before `<sys/cpu.h>` in both files | proven |
| 5 | `in_var.h: struct ifaddr incomplete` | `netinet/in_var.h` needs `net/if_var.h` first | `#include <net/if_var.h>` added to if_spppsubr.c's net block (compat section A already ordered it) | proven |
| 6 | `sys/log.h` not found | NetBSD-only; FreeBSD `log()` is in `sys/systm.h`, LOG_* in `sys/syslog.h` | include dropped | proven |
| 7 | `rw_init/rw_destroy/rw_enter/... macro redefined` | FreeBSD sys/rwlock.h (via systm.h) ships its own rw_* over `struct rwlock` | compat retires the FreeBSD spellings with `#undef` before the mtx-based defines | proven |
| 8 | `__read_mostly / __predict_true / __predict_false macro redefined` | FreeBSD already defines all three (systm.h / cdefs.h) | compat defines removed (rows now “native”) | proven |
| 9 | `callout_init_mtx: member reference base type void` | FreeBSD's callout_init_mtx expands `&(mtx)->lock_object` which does not typecheck on bare `NULL` | compat passes `(struct mtx *)NULL` | proven |
| 10 | `ip6_input undeclared` (compat `pktq_enqueue`) | `netinet6/ip6_var.h` was not included; also `#if defined(_KERNEL_OPT)` never fires in module builds | compat includes `netinet6/ip6_var.h` under `#ifdef INET6`; the vendored opt guard widened to `defined(_KERNEL_OPT) \|\| defined(HAVE_KERNEL_OPTION_HEADERS)` so `opt_inet6.h` actually runs | proven |
| 11 | `task_fn_t: incompatible function pointer` | FreeBSD TASK_INIT wants `void (*)(void *, int)` | `sppp_wq_task(void *ctx, int pending)` | proven |
| 12 | `IFF_RUNNING undeclared` | FreeBSD net/if.h only defines it for userland | compat: `IFF_RUNNING → IFF_DRV_RUNNING` | proven |
| 13 | `PRI_SOFTNET / IPL_SOFTNET / WQ_MPSAFE undeclared` | NetBSD scheduler enums passed to the sppp_wq_create shim | compat defines all three as 0 (swallowed args) | proven |
| 14 | `SIOCINITIFADDR undeclared` | NetBSD-only ioctl | compat defines it (`_IOW('i', 122, struct ifreq)`, no-op arm) | proven |
| 15 | `PRIu64 undeclared` (`%"PRIu64"`) | FreeBSD ships no PRI* in kernel headers | compat defines `PRIu64 "lu"` (amd64 uint64_t == ulong) | proven |
| 16 | `va_list / va_start / va_end undeclared` | FreeBSD kernel varargs live in `sys/_stdarg.h` | `#include <sys/_stdarg.h>` in compat section A | proven |
| 17 | `netinet6/in6.h: "do not include once directly"` | FreeBSD requires `netinet/in.h` to pull in6.h (KAME guard) | compat no longer includes `netinet6/in6.h` explicitly (in.h does it under INET6) | proven |
| 18 | `__UNCONST: discards qualifiers` | compat's typeof-based __UNCONST preserved const | `#define __UNCONST(_x) ((void *)(uintptr_t)(_x))` | proven |
| 19 | `if_output_fn_t: incompatible pointer types` | NetBSD `sppp_output` took `const struct route *`; FreeBSD's if_output_fn_t wants plain `struct route *` | call-site edit: drop the const (both the prototype and the definition) | proven |
| 20 | `IFNET_LOCK/IFNET_UNLOCK undeclared` | NetBSD per-interface ifnet lock | compat: `IFNET_LOCK(_ifp) → IFNET_WLOCK()`, `IFNET_UNLOCK → IFNET_WUNLOCK()` (FreeBSD global ifnet sx) | proven |
| 21 | `rt_ifmsg: expected 2 args, have 1` | FreeBSD rt_ifmsg is `(ifp, int)` | call-site edit: `rt_ifmsg(ifp, 0)` in sppp_rt_ifmsg | proven |
| 22 | `addlog undeclared` | NetBSD log(9)/addlog(9) append pair has no FreeBSD counterpart | if_spppsubr.c assembles each record ("ifname: " + text, then addlog() appends) in a per-thread slot under a leaf mutex and emits it as one log(9) call at the SPPP_LOG() priority (sppp_log/sppp_addlog, `__printflike`) + `addlog` macro | proven |
| 23 | `psref / curlwp_bind / if_first_addr_psref / in_ifinit / in_addrhash* / pfil_run_addrhooks` (address helpers) | NetBSD-only psref/ifaddr plumbing (KPI rows marked `rewritten (S03)`/`rewritten (S04)`) | S01 bodies rewritten with the native FreeBSD `if_addrhead` walk under `IF_ADDR_WLOCK/IF_ADDR_WUNLOCK` (CK_STAILQ_FOREACH); the apply arm logs that S03 owns the full SIOCAIFADDR recipe (behavior-minimal stand-in, unreachable before the S02 wiring) | proven (compile) |
| 24 | `if_area: sipcp saved_hisaddr` … `pktq_rps_hash_func_t int` vs `= NULL` | compat typedef'd the RPS hash func as `int` | compat now typedefs `pktq_rps_hash_func_t` as `void *` (vendored `= NULL` and `? :` spellings typecheck) | proven |
| 25 | NetBSD `MODULE(MODULE_CLASS_MISC, sppp_subr)` + `sppp_subr_modcmd` | NetBSD module glue is meaningless on FreeBSD (the driver owns the module) | dropped (comment marks the deletion) | proven |
| 26 | `MODULE_HOOK_CALL(sppp_params_50_hook, ...)` | NetBSD compat-stub hook for 50-series ioctls (do-not-port table) | default arm returns EINVAL directly | proven |

### T2 field notes (verified deltas)

The T2 list above is unchanged; T3 confirmed every item in the module build, and
found no remaining NetBSD KPI outside the table.  KPI-table status: rows the
table marked `rewritten (S03)`/`rewritten (S04)` stay `planned` — T1's original
placeholder line now reads: **the four address helpers get S01-T3 compile-clean
FreeBSD-native stand-ins** and the S03/S04 rewrites proceed from those.

## S02 wiring (T1) — the driver/PPP seam, 2026-09-20

`if_pppoe.c` now drives the vendored state machine (plan-2 Task 3, verified in
the lab below):
- Clone create embeds `struct sppp ppp` first in `struct pppoe_softc`
  (if_pppoe_var.h), sets `if_setllsoftc(ifp, &sc->ppp)` + `pp_if`, calls
  `sppp_attach(ifp)`, then fills `pp_tls`/`pp_tlf` (`pppoe_tls()`/`pppoe_tlf()`),
  `pp_framebytes = PPPOE_HEADERLEN`, and `PP_DEVF_KEEPALIVE | PP_DEVF_NOFRAMING`.
- `pppoe_ioctl(SIOCSIFFLAGS)` keeps only the local down half (stop callout +
  PADT on IFF_UP clear) and chains to `sppp_ioctl()`, which opens/closes LCP;
  LCP's This-Layer-Up/Down call `pppoe_tls()`/`pppoe_tlf()` and those start/stop
  discovery.  The plan-1 direct `pppoe_connect()` on IFF_UP is gone (Async: the
  LCP open fires on the sppp taskqueue a hop later).
- The `default:` arm of `pppoe_ioctl()` is `sppp_ioctl()` (SPPPGET/SET* etc.),
  replacing the plan-1-mandated EINVAL.  `pppoe_tlf()` deliberately does NOT
  stop the discovery callout when IFF_UP is still set (M001's PADT auto-redial
  must survive a This-Layer-Down after a lost session).
- `pppoe_data_input()` keeps the reflect arm first, then bifurcates: PPP_LCP /
  PAP / CHAP / IPCP / IPv6CP (and unknown protos) -> `sppp_input()`; the
  PPP_IP/PPP_IPV6 payload arm stays lock-free (R016) and only pokes
  `pp_last_receive`/`pp_last_activity` via `sppp_rx_payload()` (research
  amendment 3) — delivery/gating lands with S03's IPCP wiring.  (Superseded:
  S03 retired the PPP_IP intercept and p3-ipv6rx the PPP_IPV6 one, so
  `pppoe_data_input()` now hands every frame to `sppp_input()` and
  `sppp_rx_payload()` is gone.)
- PADS sets `sc_want_up`, `pppoe_clear_softc()` sets `sc_want_down`, and
  `pppoe_session_task()` delivers both as `pp_up()`/`pp_down()` outside sc_mtx.
- Clone destroy calls `sppp_detach(ifp)` before the softc free (M001 ruling #1):
  it removes the interface from the keepalive list, waits out every pending
  work item and drains the taskqueue.

curvnet additions (M001 ruling #3): `sppp_wq_task()` in the compat header wraps
every handler invocation in `CURVNET_SET(if_getvnet(sp->pp_if))` —
taskqueue_thread carries no vnet, but handlers transmit through
`if_transmit()` -> `pppoe_transmit()` (V_pppoe_stats, V_link_pfil_head) and
from S03 apply addresses via in_control_ioctl().

M002/S03/T2 made the sppp keepalive machinery per-vnet (VNET_DEFINE'd): the
interface list `spppq`, the `keepalive_ch` callout, the `sppp_keepalive_cnt`
tick counter and `sppp_keepalive_interval` each live in the vnet data block;
sppp_keepalive_vnet_init()/sppp_keepalive_vnet_uninit() (VNET_SYSINIT/
VNET_SYSUNINIT) reset the copied list head, initialize the (copied-
then-re-zeroed) callout, capture the vnet as the callout arg, and drain the
callout before the vnet data block is freed.  `sppp_keepalive()` therefore
sets curvnet from its callout arg ONCE (softclock carries no vnet) instead
of the old per-interface CURVNET_SET around the ECHO_REQ `sppp_cp_send()`;
`spppq_lock` stays a single module-level mutex (sync primitive only, never
per-vnet data).

Deviations from plan-2 Task 3: SIOCSIFMTU is NOT chained to sppp_ioctl() — its
PPP_MINMRU(128)/PP_MTU(1500) bounds would regress this driver's RFC 4638 and
68-byte MTU floor; the LCP options are reset to their defaults, and the MRU
option re-derived from if_mtu, at LCP Open and at every lower-layer Up
(sppp_lcp_defaults), so negotiation follows if_mtu without the chained arm
(S03 owns live-MRU renegotiation).

MTU/MRU (wb/mru-mtu): if_mtu has one writer, `pppoe_mtu_update()` in
if_pppoe.c, under sc_mtx: the link MTU (SIOCSIFMTU, or the PADS arm's RFC 4638
result) capped by the peer's MRU while LCP is up.  sppp's LCP tlu/tld hand it
the peer MRU through `pppoe_set_peer_mru()` instead of writing if_mtu under
IFNET_LOCK and saving/restoring `pp_saved_mtu` (now unused).  The route/ND
notification (`rt_ifmsg()` + `if_notifymtu()`) goes out from `sc_mtu_task`.
The peer's MRU is accepted in [PPP_MINMRU (128), 65535]; a smaller one is
nak'ed with 128.

## Upstream bugs found by fz_lcp_confreq/fz_ipcp_confreq, fixed here (2026-09-27)

Both bugs are inherited verbatim from the NetBSD pin above (`sppp_lcp_confreq`
and `sppp_ipcp_confreq` in `sys/net/if_spppsubr.c`) and are peer-triggerable on
NetBSD too; worth filing upstream via `send-pr`.

1. **`sppp_lcp_confreq()` pass-2 heap over-read.** The pass-2 loop
   (`for (len = origlen; len > 1; len -= l, p += l)`) has no `l > len` guard,
   unlike pass 1. The `LCP_OPT_AUTH_PROTO` nak arm reused the loop variable
   `l` (set to 4 or 5, the NAK option's length) instead of leaving it at the
   on-wire option length, so `len -= l, p += l` desyncs from pass 1's walk of
   the same buffer whenever a ConfReq's auth option is followed by crafted
   trailing bytes and an auth protocol is configured — the next iteration
   reads `p[2]`/`p[3]` past the option buffer. Fixed by naming the NAK
   option's length `naklen` (distinct from the stride `l`) and adding pass 2
   its own `l < 2 || l > len` guard (also applied to IPCP's and IPv6CP's
   pass-2 loops as hardening, though neither had the stride-reuse bug).
2. **`sppp_ipcp_confreq()` signed-shift UB.** The IPCP address (`ConfReq`
   pass 2), the Configure-Nak `wantaddr`, and both DNS options were each
   assembled with `p[2] << 24 | ...` on a signed `int`; `p[2]` is a `u_char`
   promoted to `int`, so any peer address `>= 128.0.0.0` shifts a set sign
   bit into a signed type — undefined behavior (benign on twos-complement
   without `-ftrapv`, but real UB the fuzzer's UBSan build traps on). LCP's
   equivalent magic-number parse already cast to `uint32_t` first; IPCP now
   does the same at all four sites.

Reproducers: `tests/unit/crashes/lcp_confreq/crash-06fa0de8...`,
`tests/unit/crashes/ipcp_confreq/crash-1e2e511c...`, and (bug 2, reached via
the full `sppp_input()` dispatch) `tests/unit/crashes/sppp_input/crash-c72d9a8...`.

A third, unrelated over-read surfaced in the post-fix 60s `fz_lcp_confreq`
run: `sppp_lcp_confreq()` pass 1's `LCP_OPT_MP_EID` debug log
(`addlog(" [invalid class %d len %d]", p[2], l)`) read `p[2]` even when
`l < 3`, i.e. an option too short to carry a class octet — over-reads
whenever `IFF_DEBUG` is set and a peer sends a truncated MP-EID option.
Also inherited from NetBSD verbatim; fixed by only reading `p[2]` when
`l >= 3`. Reproducer: `tests/unit/crashes/lcp_confreq/crash-0f6701b6...`.
## p3-ctl-abi: ioctl number collision (SPPPGETIPCPSTATUS vs SIOCGIFGROUP), 2026-09-27

**This section was corrected during review.** The first draft moved every
`SPPP*`/`PPPOE*` ioctl to a private group letter `'P'`. That was wrong and
would have broken the driver outright: `soo_ioctl()` (`sys/kern/sys_socket.c`,
fetched from `raw.githubusercontent.com/freebsd/freebsd-src/releng/14.3`)
routes strictly on `IOCGROUP(cmd)`:

```c
if (IOCGROUP(cmd) == 'i')
	error = ifioctl(so, cmd, data, td);
else if (IOCGROUP(cmd) == 'r') {
	...rtioctl_fib(cmd, data, so->so_fibnum);
} else {
	...so->so_proto->pr_control(so, cmd, data, 0, td);
}
```

Group `'i'` is not merely "the group generic SIOC\* ioctls happen to use" --
it is the *only* group `soo_ioctl()` ever hands to `ifioctl()`, which is the
sole path from there to `ifhwioctl()`'s `ENOIOCTL` fallthrough and then the
driver's own `if_ioctl`. `pppoectl(8)` opens `socket(AF_INET, SOCK_DGRAM, 0)`
(pppoectl.c:214), so a non-`'i'` group is handed instead to `in_control()`,
which returns `EADDRNOTAVAIL` immediately when `ifp == NULL` (the `pr_control`
call passes a NULL `ifp`) -- `pppoe_ioctl()` would never run at all. **Group
`'i'` must be kept.**

The real bug is narrower: one ioctl number collides with a generic `SIOC*`
ioctl that group `'i'` already carries. Collision is on the *full* `_IO{,W,R,WR}`
value (direction + payload size + group + number), not the number alone, so
same-number ioctls with a different direction or a different `sizeof()` do
NOT collide -- they simply never compare equal as `unsigned long` values,
regardless of what a naive same-number table implies.

Full enumeration of every group-`'i'` `SIOC*` this session fetched from the
real FreeBSD 14.3 sources (`sys/sys/sockio.h`, `sys/netinet6/in6_var.h`,
`sys/netinet/in_var.h` -- the last defines none at all) against every
`SPPP*`/`PPPOE*` number (110-146; numbers 125-134, 144-146 and 110-112 are
not used by any generic `'i'`-group ioctl in either header -- confirmed by
enumeration, not assumed):

| Ours | Number | Generic ioctl(s) at that number | Same full value? |
|---|---|---|---|
| `SPPPGETAUTHCFG` | 120 | `SIOCIFGCLONERS` (`_IOWR`, `struct if_clonereq`, 16B) | no -- size differs (80B) |
| `SPPPSETAUTHCFG` | 121 | `SIOCIFDESTROY` (`_IOW`, `struct ifreq`, 32B) | no -- size differs (80B) |
| `SPPPGETLCPCFG` | 122 | `SIOCIFCREATE` (`_IOWR`, `struct ifreq`, 32B) | no -- size differs (20B) |
| `SPPPSETLCPCFG` | 123 | `SIOCSDRVSPEC`(`_IOW`)/`SIOCGDRVSPEC`(`_IOWR`), `struct ifdrv`, 40B | no -- size differs (20B) |
| `SPPPGETSTATUS` | 124 | `SIOCIFCREATE2` (`_IOWR`, `struct ifreq`, 32B) | no -- size differs (20B) |
| `SPPPGETLCPSTATUS` | 135 | `SIOCAIFGROUP` (`_IOW`, `struct ifgroupreq`, 40B) | no -- direction differs (`_IOWR`) and size differs (48B) |
| `SPPPGETIPCPSTATUS` | **136** | `SIOCGIFGROUP` (`_IOWR`, `struct ifgroupreq`, **40B**) | **yes -- `struct spppipcpstatus` is also 40B on amd64. True collision.** |
| `SPPPGETIPV6CPSTATUS` | 137 | `SIOCDIFGROUP` (`_IOW`, `struct ifgroupreq`, 40B) | no -- direction differs (`_IOWR`) and size differs (48B) |
| `SPPPGETNCPCFG` | 138 | `SIOCGIFGMEMB` (`_IOWR`, `struct ifgroupreq`, 40B) | no -- size differs (20B) |
| `SPPPSETNCPCFG` | 139 | `SIOCGIFXMEDIA` (`_IOWR`, `struct ifmediareq`) | no -- direction differs (`_IOW`) |

`tests/results/pppoectl-t1.txt:25` "IPCP state: unknown" on a session with a
negotiated address (LCP=opened proves the ioctl path itself works) is the
live evidence for the one true collision: `SPPPGETIPCPSTATUS` never reached
`pppoe_ioctl()` because `ifhwioctl()` answered `SIOCGIFGROUP` first.

**Fix**: keep every `SPPP*`/`PPPOE*` ioctl on group `'i'`. Renumber only
`SPPPGETIPCPSTATUS`, from 136 to a number with no generic user in either
header (`sockio.h`'s highest `'i'`-group number is 156, `in6_var.h`'s is
109) -- **200**. `pppoectl.c` needed no source change either way: it only
ever spells the header macro, never a bare number.

**Deviation from the vendoring rule**: `sys/net/if_sppp.h` is one of the
three files the "Provenance" table above pins to an exact pristine
SHA-256 with exactly one addition (the port notice). This is the *second*
intentional edit to that file (one macro's number) -- its SHA-256 no
longer matches the pinned value. `sys/net/if_pppoe.h` is this port's own
file (not NetBSD-vendored) and needed no change at all (its own three
ioctls, 110-112, never collided).

**Verification**: `tests/functional/test_ioctl_abi_offline.py` pins the
source-level invariants offline, on any host, today: every `SPPP*`/`PPPOE*`
ioctl still on group `'i'`, `SPPPGETIPCPSTATUS` renumbered to 200 and every
other number unchanged. The actual proof needs real FreeBSD 14.3 headers:
`tests/ioctl-abi/check_ioctl_group.c` (built by the lab/build-VM verifier:
`make -C tests/ioctl-abi check`) statically asserts `IOCGROUP()` is `'i'`
for every one of our ioctls (the routing requirement above), asserts
inequality against every generic `SIOC*` enumerated in the table, and
includes a negative control that recreates the pre-fix `SPPPGETIPCPSTATUS`
value and proves it *does* equal `SIOCGIFGROUP` (so the checker is
demonstrably not vacuous). `test_sppp_ioctl_surface_live.py`'s in-kernel
sweep (120-139 all answered) and the new live `pppoectl -d -d` /
`interface not found` tests in `test_pppoectl_ctl_live.py` are the live
proof that nothing broke and that the fix actually restores real IPCP
status.

## p3-ctl-abi: tools/spppauth, spppioctl, spppkeepalive now include the vendored header

Each of these three host-side probe tools used to privately redeclare the
`SPPP*` structs and ioctl numbers (`_IOWR('i', 120, struct spppauthcfg)`,
...) instead of including `<net/if_sppp.h>` -- exactly the kind of copy the
group-letter fix above could have silently desynced. They now
`#include <net/if_sppp.h>` with `-I${.CURDIR}/../../sys` in their
Makefiles (the same pattern `sbin/pppoectl/Makefile` already used), so a
future renumbering fails loudly (a build break) instead of silently. The
embedded C helpers in `tests/functional/test_sppp_ioctl_live.py` and
`test_sppp_ctl_robustness.py` get the same treatment at test time: the
live-suite fixtures upload this checkout's own `sys/net/if_sppp.h`/
`if_pppoe.h` to the client VM and compile the helper `#include`-ing them,
rather than embedding a third private copy of the ABI.

## p3-ctl-abi: pppoectl.c hardening deltas from the NetBSD pin, 2026-09-27

`pppoectl.c` was byte-identical to the NetBSD pin (plus the port notice).
It no longer is; every delta below is a real bug found in this port, not a
style change, and the ioctl ABI/CLI surface (R005) is unchanged:

- **`-f missing-file` silently exited 0**: `if (configname && (fp =
  fopen(...)))` is false on a failed `fopen()`, so the whole load-config
  block is skipped with no error and no output. Now `fopen()` failure is
  `err(EX_NOINPUT, ...)`. `-f /dev/stdin` needs no special case -- it was
  always just another path to the same `fopen()` -- so a caller (the
  OPNsense plugin) can pipe a secret in without ever putting it on argv.
- **New `-S`**: reads one line verbatim from stdin for `myauthsecret`,
  bypassing `fparseln(..., FPARSELN_UNESCALL)` entirely, so a secret
  containing `\`, a space or `#` is never mangled the way `-f`'s
  line-oriented `key=value` parsing would mangle it.
- **`print_error()` got the wrong "errno"**: every ioctl-failure call site
  passed `ioctl()`'s own return value (always exactly `-1`) as the "error"
  parameter, so `print_error()`'s `error == -1` branch fired for every
  failure and `strerror(error)` (the real-errno branch) was dead code.
  Every call site now captures `errno` immediately after the failing
  `ioctl()`/call and passes that; `print_error()`'s "interface not found"
  sentinel is now `ENXIO` (what `ifioctl()`'s generic name lookup returns
  when the driver never sees the call), so a *different* real error
  (`EBUSY`, `EPERM`, ...) is finally reported correctly instead of being
  misreported as "interface not found".
- **`atoi()`/`atol()` → `strtonum(3)`**: `atoi("garbage")` returns `0`,
  indistinguishable from an actually-typed `0`; `max-noreceive=`,
  `max-alive-missed=`, `alive-interval=`, `lcp-timeout=`,
  `max-auth-failure=` and `query-dns=` now go through a `parse_num()`
  wrapper around `strtonum(3)` with an explicit range per field, so
  non-numeric or out-of-range input is a hard `errx()`, not a silently
  accepted `0`.
- **`strncpy()` → `strlcpy()` for every `ifname` field**: `strncpy(dst,
  src, sizeof(dst))` does not NUL-terminate `dst` when `src` is `>=
  sizeof(dst)` long, so an over-long interface name could leave an
  unterminated string handed straight to the kernel. `set_ifname()` uses
  `strlcpy()` and treats a truncated result as `errx(EX_USAGE, ...)`
  rather than silently probing/setting whatever interface the truncated
  name happens to name.
- **`-S` conflicts, now rejected instead of silently mishandled** (review
  finding): `-S` used to be silently ignored in `-e` (`PPPOESETPARMS`)
  mode (that branch returns before `-S`'s stdin read ever runs), silently
  raced `-f /dev/stdin` for the same stdin, and was silently overridable
  by a later `myauthsecret=`/`myauthkey=` from `-f` or argv. All three are
  now `errx(EX_USAGE, ...)` at parse time instead of a silent no-op. The
  secret buffer is registered with `atexit()` and scrubbed with
  `explicit_bzero()` before the process exits (covers every `err()`/
  `errx()` exit path, not just the normal `return 0`), and a trailing
  `\r` (CRLF input) is stripped the same way the existing `\n` strip is.
- **`print_error()`'s `ENXIO` sentinel depends on staying on group `'i'`**
  (review finding, see the ioctl-collision section above): `ENXIO` is what
  `ifioctl()`'s `ifunit_ref()` name lookup returns before the driver's own
  `if_ioctl` runs at all. A group other than `'i'` bypasses `ifioctl()`
  entirely (routed instead to `in_control()`, which fails with
  `EADDRNOTAVAIL` before ever looking at an interface name), so this
  sentinel -- and the whole ioctl surface -- only works because
  `SPPP*`/`PPPOE*` stayed on group `'i'`.
