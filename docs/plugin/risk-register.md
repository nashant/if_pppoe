# Option 1: final critic review and risk register

Option 1 is a sound path. It fails safe to stock mpd5 in every case the clusters found, with one exception: if someone clicks Apply during a core update, the WAN is down until the post-update reconcile runs. Two clusters disagreed on how the hook runs, and I've settled that below (the out-of-process line, C1). The register rests on that choice.

The target is not what the brief says: 26.7 runs FreeBSD 15.1. There is a lot of driver work and three unmerged driver-fix branches to land before the plugin can claim any interface. That work is the critical path.

## (b) Spot-checks of the five most load-bearing claims

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | An uncatchable PHP fatal in rc.bootup drops the box to single-user mode | **Confirmed** | `g show 26.7:src/etc/rc` prints `/usr/local/bin/flock -n -o ${BOOTLOCK} /usr/local/etc/rc.bootup \|\| exit 1`. `touch ${BOOTLOCK}` runs just before it and nothing removes the file. |
| 2 | Core runs `ifconfig <if> down` on the clone *before* the configure anchor, so every stock configure (and every hooked one) sends a PADT for the kernel session | **Confirmed** | 26.7 `interfaces.inc`: `killbypid(...)` → `file_put_contents("/var/etc/mpd_{$interface}.conf", $mpdconf)` → `legacy_interface_flags($ifcfg['if'], 'down', false);` → `/* fire up mpd */`. |
| 3 | The pfil hook consumes every discovery frame, and IPv6 payload is dropped | **Confirmed** | `sys/net/if_pppoe.c:1015-1019`: `pppoe_disc_input(ifp, m); *mp = NULL; return (PFIL_CONSUMED);`. `:1080-1094` at 3708dfc: `if (proto == PPP_IPV6) { ... sppp_rx_payload(...); goto drop; }`. **IPv6 half fixed in p3-ipv6rx:** PPP_IPV6 now falls through to `sppp_input()`, which delivers to ip6_input() while IPv6CP is OPENED; advertised as `kern.features.if_pppoe_ipv6` (C9), proven by `tests/functional/test_ipv6_rx.py`. |
| 4 | Byte counters are counted twice, and the auth ioctl sleeps while holding a mutex | **Confirmed** | IBYTES at `if_pppoe.c:1268`, then `sppp_input()` again at `if_spppsubr.c:773`, reached via `if_pppoe.c:1107`. OBYTES at `if_pppoe.c:1631` and at spppsubr `:1186/1199/1648/5575`. `if_sppp_compat.h`: `typedef struct mtx krwlock_t;`. `malloc(..., M_WAITOK)` and `copyin` run between `SPPP_LOCK` (6108) and `SPPP_UNLOCK` (`if_spppsubr.c:6132-6189`). |
| 5 | OPNsense 26.7 runs FreeBSD 15.1, not 14 | **Confirmed** | docs.opnsense.org/releases/CE_26.7.html: "src: FreeBSD 15.1-RELEASE-p1 plus assorted stable/15 networking commits" and "PHP 8.5". The lab box is on `14.3-RELEASE-p7` / `OPNsense 25.7.11_9` (`ssh <ROUTER_HOST> freebsd-version -k; opnsense-version`). |

I also checked a side claim for the out-of-process hook line. `/bin/timeout` exists and `/usr/bin/timeout -> ../../bin/timeout` (ls on `<ROUTER_HOST>`). The line should call `/bin/timeout`.

## (a) Conflicts between clusters, and how I resolved them

| ID | Conflict | Resolution |
|---|---|---|
| C1 | **How the hook runs.** php-boot-safety wants an in-process closure include, a shutdown handler and `pcntl_exec` to re-run rc.bootup. security-ops S4 wants an out-of-process `mwexecf(timeout … hook …)` that never includes plugin PHP. | **Adopt S4.** No plugin PHP is ever loaded into core processes, so a redeclare, OOM, exit or compile error can't reach rc.bootup. That removes the 8.3 recursion-OOM hole and the unproven "re-run rc.bootup" step. Line (v1 marker, nothing deployed yet): `/* os-if-pppoe:v1 */ try { if (is_executable(H) && mwexecf('/bin/timeout -k 5 45 '.H.' configure %s %s %s %s %s %s', [$interface, $ifcfg['if'] ?? '', implode(',', (array)$ports), (string)($mtus[0] ?? ''), $ipv4_mode ?? '', $ipv6_mode ?? ''], true) === 0) { return; } } catch (\Throwable $e) { }`. The reset line is the same with `reset %s %s`, and its result is ignored. Only non-secret scalars go on argv. The engine reads credentials from config.xml. **Consequence:** the config-semantics C5 locals contract becomes an argv contract. The engine must recompute anything else from config.xml; C9 showed `write_config()` reloads `$config`, so disk matches memory at the known callers, but that needs a test. The php-boot-safety CI rules (no named functions, lint on 8.3 and 8.5) still apply to the engine and the Status class. |
| C2 | **What happens on a same-version core reinstall.** patch-lifecycle (3) says re-apply. security-ops P1 says pause. patch-lifecycle D also adds a pkg trigger that re-applies on any transaction that touches interfaces.inc. | **P1 wins.** A reinstall is the documented repair action, and pausing falls back to stock mpd5. The update syshook, the pkg trigger and early/50 all re-apply **only if** `hook.json.status == applied` **and** the core version/sha differs from the recorded one. A same-version reinstall sets `paused:core-reinstall`, moves WANs to mpd5 and raises a banner. The "Reinstall core" action (item 6 step 4) still sets `disabled` first. |
| C3 | **Detecting upgrade vs removal in +PRE_DEINSTALL.** security-ops U1 guards on `PKG_UPGRADE`. patch-lifecycle (5) spawns a detached reconciler that checks the final state. | **Adopt patch-lifecycle (5).** U1 is wrong for split upgrades and for a leaked `PKG_UPGRADE` (`scripts.c:106-108` never unsets it). The U2 uninstall steps move into the self-contained `uninstall.sh`, which runs only once `pkg query os-if-pppoe` says the package is gone. |
| C4 | **State paths and names.** The clusters proposed `managed.<friendly>`, `clone.<if>.json`, `managed/<if>`, `status.json`, and three different lock names. | **One layout.** Volatile: `/var/run/if_pppoe/{reg/<if>.json {friendly,parent,gen,state}, lock/<if>, hook.lock, ready, status.json, pending/<friendly>, state/<if>.inet\|.inet6}`. Persistent (0700): `/conf/if_pppoe/{hook.json, pristine/<sha>, enabled, latch (boot-level), fallback.<if>.json (watchdog), boot.pending, strikes, armed.lastboot, clean.shutdown}`. One per-interface lock, `lock/<if>`, is used by the engine, reconcile, the watchdog and teardown. `hook.lock` is used only for file edits. |
| C5 | **Three separate reconcilers.** patch-lifecycle (hook invariants), config-semantics C2 (orphans) and link-events R3 (link state). | **One `engine reconcile [--after-firmware]`** with three passes (hook invariant → orphans/CARP → link state), holding `lock/<if>` taken with a non-blocking flock (skip if busy). The link and orphan passes run every minute from cron. The hook-integrity check runs every 5 minutes. It also runs from start/50, carp/30, the update syshook (deferred until pkg is idle) and after `devd restart`. |
| C6 | **patch-lifecycle 1b "failopen" vs the watchdog.** 1b makes the clone self-destroy on IFF_UP clear. link-events R7 and the watchdog use `ifconfig down/up` on the existing clone. Core's own down, just before the anchor, would also start an async self-destroy that races the hook's `ifconfig create` (EEXIST). | **Defer 1b** (needs a decision, D1). If it is built: (i) do the destroy synchronously in the ioctl path, or have the engine poll until the name has gone before create; (ii) arm failopen only while the hook is absent (`hookctl` sets `failopen 1` on pause, refusal or uninstall, and clears it on apply); (iii) the watchdog and reconcile never use `ifconfig down`, only `pppoectl` or `configctl interface reconfigure`. |
| C7 | **Credentials path.** php-boot-safety R8 pipes the password from hook-impl. security-ops C1 has the engine read config.xml. | **The engine reads config.xml** (this follows from C1). The secret goes to `pppoectl -S` on stdin (one line, verbatim). The other settings go in a private 0600 `-f` temp file, escaped as in config-semantics C6, that is unlinked after the call. pppoectl rejects `-S -f /dev/stdin` (rc 64). The pppoectl fixes from security-ops C1c and C2 (err on fopen failure; raw `-S` stdin secret) are driver-fix items. |
| C8 | **Which syshook re-applies after a core update.** patch-lifecycle uses `update/05-if-pppoe`. security-ops P1 needs a sha check. | Use update/05 with the sha and version check from C2. Anchor refused → `hook fallback` after pkg is idle, as in patch-lifecycle (2). |
| C9 | **Kmod capability detection.** mss-traffic proposes a `net.pppoe.features` bitmask. link-events proposes `kern.features.*` via FEATURE(9). | Use **FEATURE(9)** (`kern.features.if_pppoe_{linkevents,ipv6,mssfix,pfil_pass_foreign,single_bytecount}`). A missing sysctl reads as absent, and the build needs no extra ABI discipline. Keep `DECLARE_MODULE_TIED` and the per-`kern.build_id` directories for load gating. |
| C10 | **Where eligibility is decided.** config-semantics C7 and link-events want checks inside the hook. | Everything is decided in the engine (C1). The hook line only passes argv. The CARP-hold predicate (link-events R9) also moves into the engine: exit 0 with no clone means "claimed, held". |

## (c) Risks no cluster covered

1. **26.7 needs a FreeBSD 15.1 port, and 26.1 (FreeBSD 14.3) needs its own build.** php-boot-safety noted this only in passing. The kmod has only been exercised on 14.3. Every eligibility rule assumes the module loads. Owner: driver-fix / packaging.
2. **driver-finish lacks the fixes on the unmerged branches.** p1/g2-lifecycle has `fc4d142 let go of a parent on ifnet_departure_event`, `7562de8 quiesce every softc reader before sppp_detach`, and `624ddb4 refuse PPPOESETPARMS unless the session is INITIAL`; p1/g3-ioctl-log has the sleeping-under-mutex and zfree fixes (`g log driver-finish..p1/g2-lifecycle`). `g grep ifnet_departure driver-finish -- sys` returns nothing, so on driver-finish a destroyed VLAN parent leaves the clone pointing at a freed ifnet. `reconfigure_vlans.php:83` (`legacy_interface_destroy`) and VLAN edits hit exactly this path. The 624ddb4 fix also forces the engine order create → `-e parent` → up, which C5's order already follows.
3. **Callers no cluster tested:** `rc.reload_all:53` (`interfaces_configure`, which redials every managed WAN), `setports.php:43`, `ifctl.sh:165`, the Interfaces Overview **Reload** button (`/api/interfaces/overview/reload_interface`; overview.volt:109-118 offers it for `pppoe`), and the InitialSetup wizard, which rewrites `ppps` (InitialSetup.php:307-334). They all pass through the hook, but they belong in the lab matrix.
4. **pf, ALTQ and shaper state across destroy/recreate on every configure.** pf rules that name `pppoe0` and shaper queues would have to survive the destroy and recreate. This is unverified; config-semantics only raised it for scrub.
5. **The benefit case is not proven.** RX-SCALING.md (commit 72c6ad8) documents a 1.1G RX ceiling. Option 1 brings a permanent core-file patch and a support burden. If the kernel path doesn't clearly beat mpd5 on target hardware after the R023 fix, the risk isn't worth it.
6. **The 26.1 → 26.7 major upgrade.** The ABI moves from FreeBSD:14 to FreeBSD:15, so a `${ABI}` repo path must already have 15.1 kmods before users upgrade. It is unverified whether the major-upgrade flow keeps third-party repos enabled and runs our update syshook. The fail-safe is kernel-mismatch → mpd5.
7. **HA XMLRPC sync** can copy the plugin model to a backup that lacks the kmod. That degrades to mpd5, which is fine, but the backup should show the reason. Low.

## (d) Risk register

| # | Risk | Mitigation (after resolution) | Confidence | Residual | Test | Owner |
|---|---|---|---|---|---|---|
| 1 | A PHP fatal or hang in plugin code during rc.bootup → single-user console | Out-of-process hook line (C1). `/bin/timeout -k 5 45`. A non-zero exit means stock mpd5. Engine is transactional (destroys its own clone on failure) | Verified (rc L240; timeout on box) | SIGKILL or a hang is bounded at about 50 s per WAN. One PHP spawn per configure (~50-100 ms, not measured) | Broken engine variants (redeclare, loop, exit 255) → reboot reaches multi-user with the WAN on mpd5. v1-include contrast run | plugin |
| 2 | Kmod panic or boot loop | early/50: build_id match, sha check, `boot.pending`, `DECLARE_MODULE_TIED`. Strikes (3 in 24 h) latch. `/var/crash` check | Plausible | Recovery depends on the box rebooting. A panic that hangs without rebooting still needs a power cycle | Power-cut drill; induced panic ×3 → latched on the 3rd boot | driver-fix + plugin |
| 3 | Kmod lacks the 15.1 port and the g1/g2/g3 fixes (departure UAF, destroy quiesce, auth mutex) | Merge p1/g1, g2, g3. Port to 15.1. Build per `kern.build_id` for 26.1 (14.3) and 26.7 (15.1) | Verified (branches, docs) | Every new OPNsense kernel runs on mpd5 until a kmod ships for it | WITNESS/INVARIANTS stress; VLAN parent destroy while a session is up | driver-fix / packaging |
| 4 | Missing kmod features: link events, IPv6 RX, MSS clamp, PFIL_PASS for foreign frames, single byte count, single link-state writer | Driver work items from link-events R1/R2/R5 and mss-traffic 1/2/3. Eligibility gated on `kern.features.*` (C9). Until they ship: ineligible, stays on mpd5 | Verified (spot-checks 3 and 4) | IPv6 and dual-stack stay on mpd5 until the RX fix (p3-ipv6rx; gate on `kern.features.if_pppoe_ipv6`). MSS needs the kmod clamp or the pf gate | Per-feature lab tests in the clusters; old .ko → ineligible notice | driver-fix |
| 5 | Core update window: a stock configure PADTs the kernel session and mpd5 can't take over (pfil swallow, name collision) | update/05 applies synchronously. pkg trigger. Deferred `reconcile --after-firmware`. Cron backstop. Services Apply deferred while firmware is busy | Verified | GUI Apply during the update → WAN down until reconcile (seconds to minutes). Optional failopen (D1) | `pkg install -f opnsense` + configure loop; reconcile restores within 60 s | plugin / packaging |
| 6 | Anchor drift in a new core → hook refused | Refusal → deferred `hook fallback` to mpd5, notice, early refuses. CI on core master, stable and RC tags. Pre-flight fetch of the pending core | Verified | Days on mpd5 until the plugin update | Modified-anchor core package in the lab | plugin / packaging |
| 7 | Concurrent writers to interfaces.inc (pkg, opnsense-patch, hand edits) | CAS atomic_write. Busy detection without taking the firmware lock. Post-idle invariant `revert(sha) == pkg DB %Fs`. Classification pristine / ours / foreign / foreign-with-hook | Verified | A microsecond gap before rename, covered by the invariant | Rename-race harness; opnsense-patch on a patched box | plugin |
| 8 | Byte-exact revert when the backup is missing or lines were edited | Chain: exact line removal → `/conf` pristine by sha → `pkg fetch` extract → Reinstall core (disable first). Every step verified against the pkg DB. `/tmp/bk` symlink bug fixed (U3) | Verified | Needs network if the local copies are gone | Harness over tags; corrupted-line drill | plugin |
| 9 | Plugin upgrade vs removal (PKG_UPGRADE split, leak) | Superseded: a detached `uninstall.sh --wait` never runs — pkg's reaper SIGKILLs anything still a descendant of a pkg-script once it returns (`libpkg/scripts.c` `pkg_reaper_*`). `uninstall.sh` now runs synchronously, in the foreground, from `+PRE_DEINSTALL` itself, while its own files are still on disk (pkg unlinks them only after `+PRE_DEINSTALL` returns) | Verified (pkg source, this session) | `+PRE_DEINSTALL` runtime is bounded by however long teardown of all registered interfaces + hook revert takes (seconds, not the old 300s poll) | Dummy-package removal with a registered interface → confirm teardown ran before pkg unlinks the scripts dir | packaging |
| 10 | Same-version core reinstall fights our re-apply | Pause on the sha/version check (C2) | Plausible (`pkg install -f` runs POST_INSTALL: unverified) | Any same-version reinstall pauses the plugin (fail-safe) | GUI Reinstall → paused banner, clean `pkg check` | plugin |
| 11 | Reset sees the old config; callers that skip reset (H1, C2); stale clones | Registry-plus-kernel teardown. One `if_pppoe_teardown` (destroy, then linkdown scripts). Orphan reconcile each minute | Verified (`ifconfig -g pppoe` membership plausible) | Orphan window up to 60 s | Assignment change, setaddr, type change, console reassign | plugin |
| 12 | A configure without reset keeps stale parameters; concurrent configures | Unconditional teardown + create under `lock/<if>`, gen bump | Verified / locking plausible | One extra redial | Triple parallel reconfigure → one session | plugin |
| 13 | mpd5 and the clone collide on the name | Every non-zero engine exit destroys our clone first. `ngctl shutdown` wait before create | Verified | ng node lingering >3 s → mpd5 for that configure | Flip mpd5 ↔ managed both ways | plugin |
| 14 | Option parity (on-demand, idle, host-uniq, MRU, MTU >1500, MLPPP, parent type, auth-fail latch) | Engine eligibility table. `max-auth-failure=0`. Parent check through `pppoectl -e` exit code. isset() semantics | Verified | Keepalive about 60-70 s; MS-CHAPv2/EAP-only ISPs are caught only by the watchdog | Table-driven harness; parent matrix | plugin + driver-fix |
| 15 | Credentials: argv, fparseln corruption, silent `-f` failure, mpd conf on disk, log and trace leaks | Engine reads config.xml → stdin. Escaping plus a raw `-S` option. `err()` on fopen failure. Unlink `mpd_<if>.conf`. `proc_open` not mwexec. `exception_ignore_args`. g3 zfree | Verified | Millisecond window for mpd conf. Trailing-space handling unverified | Special-character password matrix; ps scrape; log grep | driver-fix + plugin |
| 16 | Link, gateway and DNS parity; lost devd events | devctl IPCP/IPv6CP events → level-triggered reconcile calling core's ppp-linkup/down.sh. Priority-200 swallow rule for IFNET events | Verified | Up to 60 s convergence after a lost event | Diff harness mpd5 vs kernel (routes, gateways, pf) | driver-fix + plugin |
| 17 | CARP backup dials | Engine CARP-hold predicate (claim, no clone). carp/30 hook. Reconcile. Watchdog never falls back while held | Verified | Lone node with disconnectppps dials after self-promotion | Two-VM HA drill | plugin |
| 18 | Watchdog misfires (ISP outage latch, boot, stale arm) | Gen tokens, lock-probed boot check, mpd5-as-arbiter probation, bounded expiry | Verified | ISP recovery during the D2 window → a false latch, which expires | Drills (a)-(e) in mss-traffic 4 | plugin |
| 19 | Web or noroot context; configd socket is 0666 | MVC + configd only. `allowed_groups:wheel,wwwonly`. Argument whitelist. Engine runs STOCK when not root | Verified / noroot end-to-end plausible | An admin can delegate the write privilege | ACL, CSRF and noroot tests | plugin |
| 20 | Health audit shows interfaces.inc modified; support stance | Integrity panel, `hookctl explain`, one-click byte-exact Disable, firmware-scoped notice, docs | Verified (health.sh `pkg check -sa`) | Policy unknown | Health before and after Disable | plugin |
| 21 | Supply chain and a failing repo blocking core update checks | Fingerprint-signed repo with an offline key, priority 5, rotation. CI canary. Banner and repo toggle. Honest metadata (tier 4, own origin) | Verified | TOFU bootstrap; key compromise pushes root code | Tamper, 404 and rotation drills | packaging |
| 22 | Secondary storage paths (mfs, /var/etc persistence) | Layout from C4 | Verified | Config restore lands on mpd5 until Apply | `use_mfs_*` reboot | plugin |
| 23 | **New:** callers not in any test matrix (reload_all, Overview Reload, setports, wizard, VLAN reconfigure) | Add them to the lab matrix. Covered by the teardown/create semantics | Verified (`g grep` at 26.7) | none expected | One drill per caller | plugin |
| 24 | **New:** pf, ALTQ and shaper state across per-configure destroy/recreate | Measure. If rules don't reattach, trigger `filter_configure` after create | Unverified | Possible loss of shaping or rules until the next filter reload | `pfctl -sr/-sq` before and after `configctl interface reconfigure` | plugin |
| 25 | **New:** 26.1 → 26.7 major upgrade (ABI 14 → 15) | Publish 15.1 kmods before GA use. Kernel-mismatch → mpd5. Check repo survival on major upgrade | Unverified | Runs on mpd5 until the kmod exists | Lab major upgrade with the plugin enabled | packaging |
| 26 | **New:** the benefit doesn't justify the patch | Performance gate before release (post-R023 kernel vs mpd5, iperf3 -P16) | n/a | — | tests/perf on target hardware | driver-fix |
| 27 | **New:** `net.pppoe.term_unknown=1` PADTs a same-NIC mpd5 session that the AC gave our last-closed id (mpd5 shares the parent MAC, so the RFC 2516 key matches) | Default off. Attribution only for `net.pppoe.term_unknown_window` seconds (default 180) after the close, and never while our softc is negotiating or holding that id. The plugin keeps `term_unknown=0` whenever any mpd5 PPPoE link shares the parent | Plausible | An AC that reissues the id to mpd5 inside the window, with term_unknown set by hand | tests/functional/test_pfil_counters.py term_unknown attribution cases | driver-fix / plugin |

## Go/no-go for Option 1

**Go**, on these conditions:
- the out-of-process hook line (C1) is used;
- no interface is claimed until the driver-fix gate is done: 15.1 port, g1/g2/g3 merged, the FEATURE-gated work items from row 4, and pppoectl `-f`/`-S`;
- the performance gate (row 26) passes.

Each failure mode the clusters found ends in "stock mpd5 plus a GUI notice", except the one Apply-during-update case in the top five below.

**Top 5 residual risks, ranked:**
1. **The size of the driver work** (row 3 plus row 4, including 15.1). Nothing ships without it. The risk is schedule, not safety.
2. **The core-update window:** if someone clicks Apply during a core update, the WAN is down until reconcile runs (row 5). This is the only path where the WAN goes down rather than falling back to mpd5.
3. **Kmod panic or hang recovery** needs a reboot or power cycle (row 2). Strikes stop a boot loop but can't fix a hung box.
4. **A support policy refusal** while the patch is present (row 20). Not verifiable.
5. **The third-party repo and signing key** (row 21): an outage blocks GUI update checks, and a key compromise gives root.

**Needs your decision:**
- **D1:** build the failopen kernel flag (patch-lifecycle 1b, constrained as in C6), or accept residual #2.
- **D2:** confirm "same-version core reinstall pauses the plugin" (C2).
- **D3:** MSS: in-kmod clamp (recommended) or the interim pf-gate eligibility rule only.
- **D4:** support both 26.1 (14.3) and 26.7 (15.1), or 26.7 only.
- **D5:** maintainer address and repo host. p4-design.md:55 uses your corporate email.
- **D6:** is IPv6/dual-stack in scope for v1, or is v1 IPv4-only with IPv6 staying on mpd5?

**Needs a live box:**
- `ifconfig -g pppoe` lists kmod clones.
- `pppoectl -S -f <file>` works, and `-S -f /dev/stdin` exits 64.
- The pkg version shipped with 26.7.
- pkg trigger `cleanup` with sandbox=false.
- `pkg install -f` runs +POST_INSTALL.
- mpd5 behaviour on the iface-name collision.
- pf and ALTQ across destroy/recreate.
- noroot Apply.
- The stop syshook on a plain `reboot`.
- Every row's lab test on 26.1 and 26.7 VMs (`<LAB_HOST>`). The consumer-router peer still needs router root and a switch VLAN.

Nothing in the if_pppoe repo was changed.

Files are in the session's scratchpad directory:
- core/ (26.7 clone used for the spot-checks)
- p4-design.md
- p4-critique.md
- ifinc-patch-analysis.md
- ifinc/ref/hookctl.php (still has the /tmp/bk symlink bug)
