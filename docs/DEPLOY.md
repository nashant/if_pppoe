# Deploying the in-kernel PPPoE driver on an OPNsense router

Target: OPNsense 25.7 (FreeBSD 14.3, kernel `SMP` = GENERIC+RSS+VIMAGE).
The plugin replaces the userland `mpd5` PPPoE client with the in-kernel
`if_pppoe` driver, driven from **Services → In-kernel PPPoE (if_pppoe)**.

This runbook is **UI-first**: every operation has a web-UI path as the
primary route and a root-shell (console) fallback labelled as such. Nothing
here edits your PPP configuration — credentials, parent interface and
service name keep flowing from the WAN entry that `mpd5` already uses.

**Verification status legend.** Each section is marked:

- **lab-checked** — the non-GUI console commands in the section were
  executed on the lab client VM (FreeBSD 14.3-RELEASE-p7 + the OPNsense SMP
  kernel, via `<LAB_HOST>`) during S04-T04, 2026-09-25; outputs match the
  expectations below. The checklist at the end lists every command.
- **verified on-box in S06** — the step needs the full OPNsense GUI stack
  (php / configd / nginx); the lab VM has none of those, so it is flagged
  for the on-box S06 validation and is **not** claimed verified here.

Standing rule (D025): any lab-VM number in this document is a relative
indication only; never read it as a real-router result.

## 0. Install

### 0.1 Package (console — the authoritative install)

The plugin package is served from a LAN-hosted pkg repo, e.g. on `<LAB_HOST>`:

```console
# one-shot, no repo config:
pkg add -f <PKG_REPO_URL>/os-if-pppoe-0.1.7.pkg

# or as a persistent repo — /usr/local/etc/pkg/repos/if-pppoe.conf:
#   if-pppoe: {
#       url: "<PKG_REPO_URL>",
#       enabled: yes
#   }
pkg update && pkg upgrade
```

The package origin is `opnsense/os-pppoe`, so the plugin also appears under
**System → Firmware → Packages** on the box. [UI alternative — verified
on-box in S06.]

### 0.2 Kernel-specificity rule (read before installing)

The kmod is compiled against **one exact kernel build**. The packages come
in two variants and they must **never be mixed**:

| variant | for | notes |
|---------|-----|-------|
| SMP | OPNsense 25.7 production kernel (GENERIC+RSS+VIMAGE) | the normal case, incl. `<DUT_HOST>` |
| SMPW | WITNESS / INVARIANTS / DIAGNOSTIC debug kernel | lab debugging only |

A module built for the other kernel variant fails to load
(`kldload: an error occurs while loading the module`, plus
`KLD if_pppoe.ko: depends on kernel - not available` in `dmesg`). One
package per kernel — check which kernel the box runs
(`uname -v`, `kldstat`) before picking the package.

*lab-checked: a kmod/kernel mismatch surfaces exactly as this error pair —
observed during M002/M003 kernel swaps; both variants build from the same
tree via `lab/vm/build-module.sh` (`KERNEL_VARIANT=SMP|SMPW`).*

`build-module.sh` compiles in the lab's `net.pppoe.reflect` test hook by
default (`PPPOE_TEST_REFLECT=1`). Build a module you mean to ship with
`PPPOE_TEST_HOOKS=0` (a variant change forces a clean rebuild). `sysctl -N net.pppoe.reflect` must
fail on a release module.

## 1. Loader tunables (Settings → Tunables)

Inbound PPPoE work only spreads across CPUs when netisr has more than one
workstream. Both knobs are read-only-after-boot tunables
(`CTLFLAG_RDTUN`), so they can only be set at boot time.

**UI path (primary):** **System → Settings → Tunables**, add:

| Tunable | Value |
|---|---|
| `net.isr.maxthreads` | `4` |
| `net.isr.bindthreads` | `1` |

then reboot (**System → Power / reboot**) so they take effect.

**Never set `net.isr.dispatch`.** It is one global consulted by every
protocol registered `NETISR_DISPATCH_DEFAULT` (ip, ip6, arp, igmp, rtsock);
flipping it to `hybrid`/`deferred` to "help" PPPoE drags all the other
LAN traffic through an extra queue and SWI hop — a straight regression.
`if_pppoe` sidesteps the global by registering its own netisr protocol with
per-protocol policy and dispatch. The UI Tunables page never needs to touch
it.

`net.inet.rss.enabled=1` is optional — spreading works without it.

**Console fallback:**

```console
sysrc -f /boot/loader.conf net.isr.maxthreads=4 net.isr.bindthreads=1
shutdown -r now
# after the reboot:
sysctl net.isr.maxthreads net.isr.bindthreads net.isr.numthreads
# expect: maxthreads 4, bindthreads 1, numthreads 4
netstat -Q | head -4
# expect: "Thread count    4    4"
```

*lab-checked (client VM, 2026-09-25): the three sysctls report
`4 / 1 / 4`, `netstat -Q` header shows `Thread count 4 / Limit 4`, and the
`pppoe` protocol row shows `Policy cpu, Dispatch hybrid` with its handled
counts spread across 4 workstreams, QDrops 0.* Setting the two tunables
through the OPNsense Tunables UI itself — verified on-box in S06.

## 2. The toggle page: Services → In-kernel PPPoE (if_pppoe)

After §0's install, the menu gains **Services → In-kernel PPPoE
(if_pppoe)** (`/services_ifpppoe.php`). There is deliberately **no
settings page**: the in-kernel client takes over the WAN that `mpd5`
currently owns, reading every active PPPoE entry (parent interface,
credentials, service name, `ptpid` interface assignment) straight from the
existing configuration. [Page rendering verified on-box in S06.]

### 2.1 Enable (take over from mpd5)

Press **Enable (take over from mpd5)**. Enable stops mpd5, `kldload`s
`if_pppoe.ko`, recreates each entry's `pppoeN` clone on its parent with its
own service/auth (CHAP first, PAP fallback), dials in-kernel, then
re-runs the interface configuration so address/gateway/rules re-attach.
**Allow ~40 s** — the page waits for the PPPoE session and reloads with the
session state and an action log.

**Reboot persistence (0.1.7):** a successful Enable is durable — it writes
the state marker `/var/db/if-pppoe/state`, pins `mpd5_enable` /
`mpd_enable` to `NO` (previous values recorded), and installs the boot hook
`/usr/local/etc/rc.d/if_pppoe` (ordered `# BEFORE: mpd5`). A reboot while
enabled therefore brings the **kmod session back up at boot and mpd5 stays
off** — same stanzas, same credentials read from the existing WAN entries.

**Console fallback (same engine the page calls via configd):**

```console
configctl if-pppoe enable     # full takeover (what the Enable button runs)
configctl if-pppoe status     # module state, per-clone state, counters
```

*lab-checked subset (client VM, S04-T04): `pppoectl -d pppoe0` prints
`state = session` — the exact string `if-pppoe-ctl`'s session detection
greps for, proving the current-tree `pppoectl` build is compatible. The
full `enable`/`status` round-trip through the installed ctl is exercised on
the lab VM in S04-T06; the page + configd path is verified on-box in S06.*

### 2.2 Status readout and diagnostics

The **Diagnostics / debug** panel on the page shows `if-pppoe-ctl status`:
module load state (`kldstat`), `ifconfig pppoeN` (address, LCP/PPPoE
flags), `pppoectl -d pppoeN` (auth proto, LCP/IPCP, PPPoE session state)
and the `net.pppoe.*` counters.

Deeper console dives (root):

```console
pppoectl -d -d pppoe0         # verbose state dump
sysctl net.pppoe              # raw counters
dmesg | tail                  # driver events (PADI/PADS/PADT, ALTQ warning)
```

*lab-checked: `pppoectl -d pppoe0`, `sysctl net.pppoe` and `vmstat -m`
executed on the client VM; `pppoectl` never echoes a credential.*

### 2.3 Per-entry Dial / Undial rehearsal

The page lists every PPPoE entry from **Interfaces → Point-to-Point**
with **Dial (kernel driver)** and **Undial** buttons. **Dial** brings up
exactly that one interface with the kernel driver — using the entry's own
parent/credentials/service — without touching mpd5 or the real WAN; ideal
for rehearsing against a lab PPPoE server on a spare NIC before the full
takeover. **Undial** destroys just that clone.

The backend refuses to touch a `pppoeN` clone it does not own (the
`is_ours()` guard): mpd5-owned netgraph clones are never destroyed. [Page
buttons verified on-box in S06; the guard's refusal path is lab-exercised
in S04-T06.]

**Console fallback:**

```console
configctl if-pppoe dial   <ifname>     # one entry, kernel driver
configctl if-pppoe undial <ifname>     # destroy just that clone
```

### 2.4 Disable (hand back to mpd5)

Press **Disable (hand back to mpd5)**: the kernel session is torn down,
the module `kldunload`ed, mpd5 is restarted (it re-dials), and the
persistence is reversed — state marker removed, mpd5 rcvars restored to
their pre-enable values. See §5.

## 3. Shaping and ALTQ — read this before configuring traffic shaping

iflib only selects a parent TX queue per mbuf when the mbuf carries a hash
type **and ALTQ is not enabled on that interface**. Enabling an ALTQ
discipline on the PPPoE **parent** therefore collapses all PPPoE transmits
onto TX queue 0.

- Shape on the `pppoeN` interface itself (the driver supports ALTQ on its
  own interface), or
- use dummynet (`dnctl` / `ipfw`) instead of ALTQ.
- **Never** put ALTQ on the PPPoE parent while the kernel driver is bound
  to it.

`sysctl net.pppoe.parent_altq` reports `1` when a bound parent has ALTQ
enabled, and the driver emits a **one-shot** warning to `dmesg` when it
detects it (it does not repeat per packet):

```console
sysctl net.pppoe.parent_altq      # expect 0 on a clean setup
dmesg | grep -i altq              # the one-shot warning, if it ever fired
```

*lab-checked: `net.pppoe.parent_altq` exists and reads `0` on the lab
client; the OPNsense 25.7 lab kernel is built without ALTQ
(`kern.features.altq` absent — pf.ko loads but cbq cannot attach), so the
warning path is exercised by the S03 ALTQ-detection test's skip branch
with the probe result recorded. The on-box ALTQ-parent warning itself —
verified on-box in S06.*

Per-NIC traits are documented examples only, never driver criteria: e.g.
the lab's I225 (`igc`) cannot hash inside a PPPoE frame, so its RX queue
selection stays fixed (a cost shared with every in-kernel PPPoE
implementation); what the driver adds is spreading everything *after*
decapsulation (`net.pppoe.cpu_hits`). A NIC that can hash inside the frame
would show it differently — the driver does not depend on either behaviour.

## 4. Counters and troubleshooting

All counters are `net.pppoe.*` sysctls:

| sysctl | meaning |
|---|---|
| `hook_seen` | Ethernet frames the pfil hook inspected on bound parents |
| `disc_in` | discovery frames (0x8863) consumed |
| `disc_malformed` | discovery frames dropped as malformed |
| `disc_err_tag` | discovery frames carrying Service-Name-Error / AC-System-Error / Generic-Error |
| `sess_in` | session frames (0x8864) consumed |
| `sess_nosession` | session frames matching no session — wrong parent or stale session id |
| `sess_short` | truncated/malformed session frames |
| `data_in` | decapsulated PPP frames delivered to sppp (== `sess_in` when healthy) |
| `tx_frames` / `tx_errors` | frames handed to the parent / transmit failures, `tx_parent_down` included (should stay flat while every parent is up and running) |
| `tx_parent_down` | frames dropped because the parent was not up (`IFF_UP`) and running (`IFF_DRV_RUNNING`); also in `tx_errors`. Rises while a parent is down; discovery retries on its timer. The PADT sent when a parent departs needs only `IFF_DRV_RUNNING` |
| `padt_rx` / `padt_tx` | PADTs received / sent |
| `padt_unknown` | PADTs naming a session the driver does not know (needs `net.pppoe.term_unknown=1` to also terminate) |
| `term_unknown` / `term_unknown_pps` / `term_unknown_window` | send a PADT for frames of a session this box closed (same parent, same AC) / the PADT rate limit / how many seconds after the close that attribution holds (default 180). Every other unknown session is passed up the stack. Keep `term_unknown=0` when mpd5 shares the parent: inside the window the AC may reissue our old id to mpd5's session |
| `auth_backoff_max` | cap, in seconds, on the redial delay after consecutive authentication failures (1, 2, 4 ... s; default 300, clamped to 86400, `0` redials at once). A loader tunable too. The link is never given up for good |
| `parent_altq` | `1` when a bound parent has ALTQ enabled (see §3) |
| `cpu_hits` | per-CPU netisr handler invocations (want >1 cpu under load) |

Leak / queue checks:

```console
vmstat -m | grep -w pppoe         # M_PPPOE row: InUse should stay flat across sessions
netstat -Q | grep pppoe           # the pppoe protocol row: QDrops column stays 0
sysctl net.pppoe.cpu_hits         # spread across more than one cpu under load
```

*lab-checked (client VM, 2026-09-25, mid-soak): every sysctl in the table
above exists on the S03-era kmod; `vmstat -m` shows the `pppoe` row at the
known flat level; `netstat -Q` shows the `pppoe` row spread across 4
workstreams with 0 drops; `cpu_hits` shows counts on cpu0..cpu3.*

Common failures:

| Symptom | Likely cause |
|---|---|
| `hook_seen` stays 0 | the parent is not bound — re-run the parent bind (`pppoectl -e <parent>`), or re-Enable |
| `disc_in` moves, `pppoectl -d` stays at `state = padi_sent` | service-name mismatch, or the AC is not answering — check `padi retries` in `pppoectl -d pppoe0` and `disc_err_tag` for an error tag from the AC |
| `sess_nosession` climbs | frames for another session on the same segment, or the peer MAC changed without a PADO |
| `state = session` but no address | authentication or IPCP failure — `pppoectl -d -d pppoe0` and `dmesg` show the LCP/auth transitions |
| `cpu_hits` all on one CPU | `net.isr.numthreads` is 1: the §1 tunables were not applied or the box was not rebooted |
| `parent_altq` = 1 + one-shot dmesg warning | ALTQ is enabled on the PPPoE parent (§3): TX collapses onto queue 0 — move the discipline onto pppoeN or use dummynet |
| `padt_unknown` climbs | PADTs arriving for sessions the driver does not know (foreign mpd5/other client on the segment, or post-restart peers); set `net.pppoe.term_unknown=1` if stale peers must be answered with a terminate |
| throughput stuck at ~1 TX queue | see §3 — ALTQ on the parent |
| M_PPPOE (`vmstat -m`) grows across enable/disable cycles | leak — record `vmstat -m` before/after and `dmesg`'s "leaked memory on destroy" count; a 32-byte step per clone is the known MEM093 item, more is a bug |

## 5. Rollback to mpd5

`if_pppoe` and mpd5 must not own the same parent at the same time; the
Enable/Disable toggle guarantees the handoff is exclusive. Rollback is
always reversible and never edits your PPP configuration.

**UI path (primary):** Services → In-kernel PPPoE (if_pppoe) →
**Disable (hand back to mpd5)**. [On-box in S06.]

**Console fallback:**

```console
configctl if-pppoe disable
```

which (identical to the 0.1.7 Disable): tears the kernel sessions down
(each clone sends its PADT), `kldunload`s the module, removes the
`/var/db/if-pppoe/state` marker, restores the `mpd5_enable` / `mpd_enable`
rcvars to their pre-enable values, restarts mpd5, and re-runs the interface
configuration so mpd5's session re-attaches.

```console
# verify the handback:
ifconfig -l | tr ' ' '\n' | grep -E 'pppoe|ng'
pppoectl -d pppoe0 2>&1 || true   # driver-owned clone is gone; mpd5's netgraph pppoeN is not touched by this tool
netstat -rn -f inet | head        # WAN route back via mpd5's session
```

**Reboot-with-toggle-on behaviour (0.1.7):** if the box reboots while the
toggle is on, the boot hook (`/usr/local/etc/rc.d/if_pppoe`, ordered
before mpd5) sees the state marker and re-runs the enable — the kmod
session comes up before mpd5 starts and mpd5 stays off. You do **not**
wake up on mpd5 with the module unloaded (that was the 0.1.6 gap).

**Full uninstall** (removes the module tooling, fully undoes persistence
even if the ctl tool is already gone):

```console
cd /tmp/os-if-pppoe && ./uninstall.sh     # disable + rc script + marker + rcvar restore
# or, for the pkg install: pkg remove os-pppoe   (pre-deinstall stops the service first)
```

The two §1 loader tunables are harmless with mpd5 (they only raise the
netisr workstream count) and can be left in place; removing them needs
another reboot.

*lab-checked subset: the non-destructive parts of the handback path
(`configctl`-guard behaviour, `is_ours()` refusal on foreign clones) are
exercised on the lab VM in S04-T06; the destructive clone-teardown live run
also happens in T06, strictly after the 24h soak completes, so it cannot
disturb the soak's session. The full on-box Disable round-trip is verified
on-box in S06.*

## 6. OPNsense 26.7 / FreeBSD 15.1 build note

Everything above targets OPNsense **25.7** on FreeBSD **14.3** (`SMP`).
When the production router moves to OPNsense **26.7 / FreeBSD 15.1**, the
kmod and `pppoectl` must be rebuilt against that kernel's build dir —
the module is kernel-build-specific (§0.2) and 14.3-built binaries will not
load on a 15.1 kernel. The build path is the same
(`lab/vm/build-module.sh` against the collected 26.7/15.1 kernel, then
`lab/pkg/build-os-pppoe.sh` to repackage); the plugin shell/PHP layer is
kernel-independent. This is the S07 packaging slice's job — nothing on the
25.7 path changes until then.

## Verification checklist (S04-T04, 2026-09-25)

Executed against the lab client VM (FreeBSD 14.3-RELEASE-p7 + OPNsense SMP
kernel) via `<LAB_HOST>`, read-only, while the 24h soak was running:

| # | command block | result |
|---|---|---|
| 1 | `kldstat \| grep if_pppoe` | PASS — module loaded |
| 2 | `sysctl net.isr.maxthreads net.isr.bindthreads net.isr.numthreads` | PASS — 4 / 1 / 4 |
| 3 | `netstat -Q \| head -4` | PASS — `Thread count 4 / Limit 4` |
| 4 | `netstat -Q \| grep pppoe` | PASS — row present, `cpu` policy, `hybrid` dispatch, QDrops 0, spread across 4 WSIDs |
| 5 | `pppoectl -d pppoe0` | PASS — `state = session` (the compat string `if-pppoe-ctl` greps) |
| 6 | `sysctl net.pppoe.parent_altq net.pppoe.padt_unknown net.pppoe.tx_errors` | PASS — all exist (`0 / 0 / 2` on the lab box) |
| 7 | `sysctl net.pppoe` (full set) | PASS — every §4 table row present on the kmod |
| 8 | `vmstat -m \| grep -w pppoe` | PASS — M_PPPOE row flat at the known level |

Deferred with reasons (never silently claimed):

- `if-pppoe-ctl status / entries / dial / undial` live round-trip and the
  `is_ours()` refusal path — **S04-T06** (the plugin install on the client
  VM happens there, strictly after the soak finishes).
- Destructive handback mechanics (§5 clone teardown / `kldunload`) —
  **S04-T06** (would destroy the soak's live session now).
- All OPNsense GUI steps (Tunables page, Firmware → Packages, the toggle
  page itself, `configctl` round-trips) — **verified on-box in S06**.