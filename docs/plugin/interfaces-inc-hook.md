# interfaces.inc hook ("Option 1"): stability, minimal patch, apply/revert mechanism

All evidence comes from a clone of github.com/opnsense/core in `scratchpad/core`. The working files are in `scratchpad/ifinc/`:
- per-tag extracts: `ifinc/<tag>/`
- the patch: `ifinc/os-if-pppoe-26.7.diff`, also copied to `scratchpad/os-if-pppoe-26.7.diff`
- the functional harness: `ifinc/t/`
- the reference apply/revert tool and its tests: `ifinc/ref/hookctl.php`, `ifinc/ref/test.sh`, `ifinc/ref/test.out`

PHP tests ran in the `php:8.2-cli`, `php:8.3-cli`, `php:8.4-cli` and `php:8.5-cli` docker images. OPNsense 26.7 ships PHP 8.5 (`opnsense/tools` `config/26.7/build.conf`: `PHP?= 85`; `opnsense/ports` also carries `lang/php85`). `Mk/defaults.mk:46-47` derives `CORE_PHP` from the build host's `php -v`, so the version isn't pinned in core, but the port's own build config fixes it per series.

**Update, 2026-09-28:** the anchor logic is now covered by the automated
suite, not just this one-off research clone. `plugin/net/if-pppoe/tests/fixtures/interfaces.inc/{26.1.11,26.7.4}`
are verbatim `src/etc/inc/interfaces.inc` copies from opnsense/core at its
*latest* 26.1.x and 26.7.x tags (26.1 and 26.7 above were the bare
first-release tags), fetched via the GitHub contents API and run through
`hookctl_test.sh`'s full apply/revert/selftest/refusal battery (see
`tests/README.md`). 26.7's CE release notes
(docs.opnsense.org/releases/CE_26.7.html) confirm PHP 8.5.x, answering the
"haven't verified" note above; `hook/run.sh` was re-run against the real
`php:8.5-cli` image (PHP 8.5.11) and passed (168 + 89, 0 failed), same as
8.2–8.4.

Tags and commits:

| tag | commit | interfaces.inc lines |
|---|---|---|
| 25.1 | 0445667ad2 | 4295 |
| 25.7 | bbd245bb09 | 4165 |
| 25.7.11 | b968f4ffea | 4276 |
| 26.1 | 33126e9196 | 4300 |
| 26.7 | e879c8f93c | 4190 |
| master | cdde38bee1 (2026-09-25) | 4135 |

---

## 1. How much the relevant code changed

### 1.1 The three ppps functions are byte-identical or nearly so

Each function was extracted from `^function NAME(` to the first `^}` (`ifinc/extract.awk`). Hash prefixes (sha256, first 12 characters):

```
interface_ppps_capable   dc4372b51820  identical in 25.1 25.7 25.7.11 26.1 26.7 master
interface_ppps_reset     8575fe7f6d03  identical in 25.1 25.7 25.7.11 26.1 26.7 master
interface_ppps_configure 3b7fcff0df7e 25.1 | 9525e4ff72df 25.7 | e9b0dc80ed0b 25.7.11 = 26.1 = 26.7 = master
```

The whole diff of `interface_ppps_configure` between 25.1 and master is two lines, both far from the anchors:

```
164c164  -  if (isset($config['system']['dnsallowoverride'])) {
         +  if (!empty($config['system']['dnsallowoverride'])) {
314c314  -  shell_safe('/usr/sbin/daemon -f .../ppp-rename.sh %s %s %s', ...);
         +  mwexecfb('/usr/local/opnsense/scripts/interfaces/ppp-rename.sh %s %s %s', ...);
```

### 1.2 Commits touching each function, compared with the whole file

Command: `g log --no-patch -L'/^function FN(/,/^}/:src/etc/inc/interfaces.inc' <merge-base(tag,master)>..origin/master`.

| window | whole file | ppps_capable | ppps_reset | ppps_configure |
|---|---|---|---|---|
| since 25.1 (mb 2025-01-21) | 138 | 0 | 0 | 2 (`592a62b0df` wizard 2025-03-03, `b10962a593` shell_safe→mwexecfb 2025-11-17) |
| since 25.7 / 25.7.11 (mb 2025-07-10) | 117 | 0 | 0 | 1 |
| since 26.1 (mb 2026-01-20) | 61 | 0 | 0 | 0 |
| since 26.7 (mb 2026-07-06) | 41 | 0 | 0 | 0 |
| since 2024-01-01 (the "198" figure) | 198 | 1 | 1 | 14 |

The 5 lines right around the mpd5 launch (`/precaution for post-start/,+6`) were last touched on 2024-08-12 (`4b77d13eef`, `62a09bfa0a`). Before that the last change was `2e77966907` on 2022-02-02.

**Conclusion:** "198 commits" describes the file. The functions we anchor in changed 0 times since 26.1 and 2 times since 25.1, and neither of those changes was near an anchor.

### 1.3 Call sites

Hashes of the extracted callers:

```
file                      25.1     25.7     25.7.11  26.1     26.7     master
interface_reset.php       ebc7afc  ebc7afc  e7fdd0f  0164743  77485d3  188e7e1
interface_suspend.php     779ea04  779ea04  779ea04  779ea04  779ea04  779ea04
interface_configure.php   e7cfbc3  7be6d7a  1af3911  e2c9a03  e2c9a03  97d7aae
20-ppp (carp syshook)     b2ffc37  b2ffc37  a36c52c  a36c52c  bf89c4a  bf89c4a
interfaces_ppps_edit.php  689e468  2ca5f2a  6579807  6579807  88242a9  2fe692e
rc.configure_interface    8190336  (identical in all six)
```

The callers change often, but the calls into the hooked functions have the same form in every tag:
- `interface_reset`: `interface_ppps_reset($interface, $suspend, $ifcfg, $ppps);`. That is line 101 of the extracted function at 25.1 and 26.7, and line 91 at master.
- `interface_configure`: `interface_ppps_configure($interface);`. That is line 149 at 25.1, 169 at 26.7 and 159 at master. On master, `interface_configure` gained `$batch, $all_devices` parameters, but the ppps call is unchanged.
- `interface_suspend` → `interface_reset($interface, false, true)` (identical in all six).
- `20-ppp`: `interface_suspend($ifkey)` on BACKUP (plus INIT from 26.7), and `interface_ppps_configure($ifkey)` on MASTER.
- `interfaces_ppps_edit.php`: `write_config();`, then `interface_ppps_configure($pppif)` for each interface bound to the PPP device. It never calls reset (26.7 L295-300).
- `rc.configure_interface`: `exit_on_bootup(); … interface_configure(true, $argument, true);`. No reset.

The patch never touches callers, so their churn doesn't matter. It only matters that they all go through the two hooked functions, and they do.

`mpd5` appears in exactly one executable place at 26.7:

```
$ g grep -n mpd5 26.7 -- src
src/etc/inc/interfaces.inc:973:  /* we only test for PPP capability that needs mpd5 */   (comment)
src/etc/inc/interfaces.inc:1305: /* mpd5 modem chat script ... */                       (comment)
src/etc/inc/interfaces.inc:1328: '/usr/local/sbin/mpd5 -b -d /var/etc -f %s -p %s -s ppp %s',
src/etc/inc/interfaces.inc:2353: /* XXX mpd5 $realhwif may be a device node path */     (comment)
src/opnsense/scripts/interfaces/ppp-rename.sh:26  (comment)
```

### 1.4 Stable anchors (present, unique and unchanged in all six tags)

- **Reset:** `function interface_ppps_reset($interface, $suspend, $ifcfg, $ppps)\n{\n    if (!interface_ppps_capable($ifcfg, $ppps)) {\n`
- **Configure:** `    legacy_interface_flags($ifcfg['if'], 'down', false);\n\n    /* fire up mpd */\n    mwexecf(\n        '/usr/local/sbin/mpd5 -b -d /var/etc -f %s -p %s -s ppp %s',\n`

Uniqueness is asserted with `substr_count(...) === 1`. The reference tool also checks that each match lies inside the named function's span.

---

## 2. The minimal patch (26.7): 2 inserted lines, 0 lines changed

The patch adds one line at the top of `interface_ppps_reset()`. It adds one line in `interface_ppps_configure()`, directly before `/* fire up mpd */`. At that point core has already done the following:
- run the `capable`/`enable`/ipv4-ipv6-mode guards
- resolved `$ports`, `$mtus`, `$mrus` and so on
- raised the parent interfaces
- run `killbypid` on any old mpd5
- written `mpd_<if>.conf`
- set `$ifcfg['if']` down

```diff
--- a/src/etc/inc/interfaces.inc
+++ b/src/etc/inc/interfaces.inc
@@ -1001,6 +1001,7 @@
 
 function interface_ppps_reset($interface, $suspend, $ifcfg, $ppps)
 {
+    /* os-if-pppoe:v1 */ try { if (is_file('/usr/local/opnsense/scripts/if_pppoe/hook.inc') && (include_once '/usr/local/opnsense/scripts/if_pppoe/hook.inc') && function_exists('if_pppoe_hook')) { if_pppoe_hook('reset', get_defined_vars()); } } catch (\Throwable $if_pppoe_e) { log_msg('os-if-pppoe: reset hook failed: ' . $if_pppoe_e->getMessage(), LOG_ERR); }
     if (!interface_ppps_capable($ifcfg, $ppps)) {
         return;
     }
@@ -1323,6 +1324,7 @@
     /* precaution for post-start 'up' check */
     legacy_interface_flags($ifcfg['if'], 'down', false);
 
+    /* os-if-pppoe:v1 */ try { if (is_file('/usr/local/opnsense/scripts/if_pppoe/hook.inc') && (include_once '/usr/local/opnsense/scripts/if_pppoe/hook.inc') && function_exists('if_pppoe_hook') && if_pppoe_hook('configure', get_defined_vars())) { return; } } catch (\Throwable $if_pppoe_e) { log_msg('os-if-pppoe: configure hook failed, using mpd5: ' . $if_pppoe_e->getMessage(), LOG_ERR); }
     /* fire up mpd */
     mwexecf(
         '/usr/local/sbin/mpd5 -b -d /var/etc -f %s -p %s -s ppp %s',
```

### 2.1 Semantics

**Reset:** the hook's return value is ignored, so core's own `killbypid`/ondemand logic always runs afterwards. The reset path gains no control-flow change.
- `get_defined_vars()` hands the hook the **old** `$ifcfg`/`$ppps` that core passes in. This addresses critique H1.
- The line runs before the `capable` check, so the hook can also tear down a registry-held clone when the old config is no longer PPP.

**Configure:** the only new control flow is `return`, taken when the hook returns true.
- The hook receives every local core computed: `interface, config, ifcfg, ppps, ipv4_mode, ipv6_mode, ppp, idx, ports, localips, gateways, subnets, mtus, mpdconf, mpdconf_arr, bandwidths, mrus, mrrus, provider, hostuniq, …`. This is the verified key list from the harness.
- When it returns true it skips the mpd5 launch, `ppp-rename.sh`, the 20 s up-wait, `ngctl setautosrc` and `legacy_interface_mtu`. **The hook must therefore set the clone MTU from `$mtus[0]` itself.**
- The hook should also `@unlink("/var/etc/mpd_{$interface}.conf")`, which contains the password, because mpd5 won't consume it.
- This placement also covers the CARP MASTER path (`20-ppp` calls `interface_ppps_configure`). Core's current and future guards in the function preamble are respected, which addresses critique H4. Open PR opnsense/core#9896 would add a CARP guard to this preamble.
- A prefixed variable name (`$if_pppoe_e`) is used because neither function contains a `$e` or `$h` variable (grep returned nothing). It still can't collide.

### 2.2 Applies to every tag with zero fuzz

The commands are in `ifinc/`. Each tag's file was copied to `src/etc/inc/` in a temp dir, then these ran: `g apply --check -v`, `patch -p1 --dry-run -F0`, then apply, `patch -R`, and `cmp` against the original.

```
===== 25.1     Hunk #1 succeeded at 943 (offset -58 lines).  Hunk #2 succeeded at 1266 (offset -58 lines).  apply+revert byte-identical: OK
===== 25.7     Hunk #1 succeeded at 919 (offset -82 lines).  Hunk #2 succeeded at 1242 (offset -82 lines).  apply+revert byte-identical: OK
===== 25.7.11  Hunk #1 succeeded at 1011 (offset 10 lines).  Hunk #2 succeeded at 1334 (offset 10 lines).  apply+revert byte-identical: OK
===== 26.1     Hunk #1 succeeded at 1019 (offset 18 lines).  Hunk #2 succeeded at 1342 (offset 18 lines).  apply+revert byte-identical: OK
===== 26.7     (exact)                                                                                   apply+revert byte-identical: OK
===== master   Hunk #1 succeeded at 1010 (offset 9 lines).   Hunk #2 succeeded at 1333 (offset 9 lines).   apply+revert byte-identical: OK
```

`git apply --check` and GNU `patch -F0` gave identical results on every tag. There was no fuzz anywhere, only line offsets.

### 2.3 Lint and functional behaviour (PHP 8.2.34 / 8.3.35 / 8.4.26)

`php -l` on the patched 26.7 file returned `No syntax errors detected` on all three versions.

The harness `ifinc/t/harness.php` evals the three patched functions from the patched file. Core helpers are stubbed and their calls recorded. The harness then calls `interface_ppps_reset` (with old-config arguments) and `interface_ppps_configure` for each `hook.inc` variant:

```
absent       mpd5_launched=1 killbypid=2 hook_seen=null logs=[]
managed      mpd5_launched=0 killbypid=2 hook_seen=["reset:interface,suspend,ifcfg,ppps","configure:interface,config,ifcfg,ppps,...,mtus,mpdconf,..."] logs=[]
unmanaged    mpd5_launched=1 killbypid=2 ...
throws       mpd5_launched=1 ... logs=["os-if-pppoe: reset hook failed: boom","os-if-pppoe: configure hook failed, using mpd5: boom"]
error        mpd5_launched=1 ... logs=["...Call to undefined function undefined_fn()" x2]
parseerror   mpd5_launched=1 hook_seen=null logs=["os-if-pppoe: reset hook failed: syntax error, unexpected token \"{\", expecting variable"]
returnsfalse mpd5_launched=1 hook_seen=null logs=[]
```

The output was identical on 8.2, 8.3 and 8.4.

**Uncatchable failures (verified):**
- If `hook.inc` redeclares an existing function, the result is `Fatal error: Cannot redeclare killbypid()`.
- Memory exhaustion gives `Fatal error: Allowed memory size … exhausted`.

Neither passes through `catch (\Throwable)`, and both kill the calling PHP process. That means `rc.bootup` or `rc.configure_interface`.

**Mitigations:**
- `hook.inc` must be a tiny shim. Every declaration goes inside `if (!function_exists(...))`, and it declares no classes and no core-colliding names.
- Heavy work runs out of process: `mwexec` of `pppoectl` and of the engine script.
- Lint and self-test `hook.inc` at package build, in `+POST_INSTALL`, and in every `apply`.
- Keep the boot crash guard in §3.6.

---

## 3. The apply/revert mechanism

### 3.1 Reference implementation (tested)

`ifinc/ref/hookctl.php` is about 70 lines of PHP and has `apply | revert | status`. It uses no `sed`, `patch` or `git`:
- **Exact context:** it searches for the concatenated `pre+post` context block and requires `substr_count === 1`.
- **Function span:** it requires the match to lie inside `function interface_ppps_{reset,configure}(` … `\n}\n`, and requires that function to be declared only once.
- **Insertion:** it inserts the canonical line between `pre` and `post`.
- **Markers:** the marker `/* os-if-pppoe:v1 */` means already applied. Any other `os-if-pppoe:` marker means refuse: it is a foreign or old version and needs a v-migration path.
- **Round-trip check before writing:** `revert(apply(x)) === x`, byte for byte, or refuse.
- **Atomic write:** write a temp file in the same directory, copy mode/owner/group, run `php -l` on the temp file, then `rename()`.
- **Revert** removes exactly our canonical lines and requires each one to be found exactly once. If a line was hand-edited, it refuses rather than guess.

Why not `patch(1)`? FreeBSD's `patch(1)` exists and has `-C/--check`, `-F`, `-R`, `-N`, `-b` and `-o` (https://man.freebsd.org/cgi/man.cgi?query=patch&sektion=1&manpath=FreeBSD+14.3-RELEASE). But its man page says `-F` "only applies to context diffs", so zero-fuzz behaviour on unified diffs is not documented. `git` is not something to rely on at runtime; I haven't verified whether OPNsense ships it by default. Keep the `.diff` as the CI artifact and do the on-box match in PHP.

Results (`ifinc/ref/test.out`):

```
25.1:    status0=pristine-applicable apply=0 status1=applied [2 lines added] reapply=0 idempotent=yes revert=0 byte-identical=yes
25.7:    (same)
25.7.11: (same)
26.1:    (same)
26.7:    (same)
master:  (same)
hookctl output == os-if-pppoe-26.7.diff result: yes
neg1 (core changes the mpd5 launch line):  refused: configure: context not found exactly once   rc=2, file unchanged
neg2 (context duplicated in file):         refused: reset: context not found exactly once       rc=2
neg3 (our line hand-edited, then revert):  refused: configure: our exact line not found once    rc=2
```

### 3.2 State and backup

The state file is `/conf/if_pppoe/hook.json`, kept under `/conf` so it survives `use_mfs_var` (critique M3). It records:
- `core_version` (`pkg query '%v' opnsense`)
- `pristine_sha256`
- `patched_sha256`
- `hook_version` (`v1`)
- `applied_at`
- `status` (`applied` | `refused:<reason>` | `reverted` | `foreign`)

The backup is `/conf/if_pppoe/pristine/interfaces.inc.<core_version>.<sha256>`. Keep the last 2 or 3.

To decide whether the file is pristine before patching:
- First choice: `pkg check -s opnsense` must not list `interfaces.inc`. `pkg-check(8)`: "-s … detects installed packages with invalid checksums", and it accepts a package pattern (https://man.freebsd.org/cgi/man.cgi?query=pkg-check&sektion=8&manpath=freebsd-ports). The man page documents neither the output format nor the exit codes, so parse the output for the path.
- Alternative: compare `sha256` with `pkg query '%Fp %Fs' opnsense`. I haven't verified the stored checksum format; it may carry a hash-type prefix, so normalise it.
- If the file is not pristine and has no `v1` marker, the status is `foreign`. Don't patch; stay on mpd5 and show a notice. We never patch on top of somebody else's edit.

Revert:
1. Try line-removal revert.
2. Check `sha256(result) == pristine_sha256` from the state for the same `core_version`.
3. If that fails, restore the backup keyed by the current `core_version` and sha.
4. If that fails too, the last resort is `pkg fetch` plus extracting the file from the package, or `pkg install -f opnsense`. I haven't verified the package-internal path format for extraction. Surface this as a GUI action rather than doing it automatically, because reinstalling core is heavy.
5. Finally, `pkg check -s opnsense` must come back clean for `interfaces.inc`.

### 3.3 Triggers

All triggers take one `flock` on `/var/run/if_pppoe.hook.lock`.

| Trigger | Action |
|---|---|
| Services page: Enable + Apply (configd `ifpppoe hook apply`) | apply → self-test (§3.4) → then reconfigure the selected WANs. If the result is not `applied`, `enabled` stays effective-off, the GUI shows `mpd5 (hook unavailable: <reason>)`, and no interface is switched |
| Services page: Disable + Apply | reconfigure the managed WANs to mpd5 first (the hook is still present and returns false, so the clone is torn down and mpd5 starts), then revert |
| `+PRE_DEINSTALL` | same as Disable (critique M7: guard it so an upgrade does not do this; this is unverified pkg behaviour) |
| `+POST_INSTALL` (plugin upgrade) | if enabled: re-apply (idempotent). Also lint `hook.inc` |
| `/usr/local/etc/rc.syshook.d/update/50-if-pppoe` | runs from core's `+POST_INSTALL` last line `/usr/local/etc/rc.syshook update` (verified in 25.1, 26.7 and master). If enabled: **apply immediately**. That needs only the file, php and the lock, not the pkg DB, which keeps the window short. Then `daemon -f hookctl reconcile`, which waits for the firmware lock `/tmp/pkg_upgrade.progress` (taken with `flock -n -o` in `scripts/firmware/launcher.sh:94`, 26.7) and then records `core_version` and checks pkg checksums. I haven't verified whether pkg holds its DB lock while it runs `+POST_INSTALL`, which is why the pkg queries are deferred |
| `/usr/local/etc/rc.syshook.d/early/50-if-pppoe` | boot, after `05-upgrade` (which may reboot) and before `rc.bootup` (26.7 `src/etc/rc` L229 php, L232 early, L240 bootup). If enabled and not applied: apply. The php CLI is usable at this point because `rc.subr.d/php` has run; the "PHP starts working here" banner refers to the config subsystem. Don't call configctl |
| `_cron` (every 5 min) | `hookctl status`. If enabled and not applied: apply or notice. This is a backstop only |

### 3.4 Self-test after apply

The self-test runs in a separate `php` process so that a fatal can't hurt the caller.
1. Run `php -l` on the new file and on `hook.inc`.
2. Run `php -r 'require_once "config.inc"; require_once "interfaces.inc"; …'`, which includes the real file. Use `ReflectionFunction('interface_ppps_configure')` / `('interface_ppps_reset')` and check that the marker's line number lies between `getStartLine()` and `getEndLine()`. Use the tokenizer to confirm that our `return` is the only new `T_RETURN`.
3. Call `if_pppoe_hook('selftest', [])` and expect `true` with no side effects.

If any step fails, restore the pristine backup with an atomic rename and set `status=refused:selftest`. The WAN stays on mpd5.

### 3.5 Concurrency and core updates while enabled

- **Plugin Apply during a firmware run:** if the `/tmp/pkg_upgrade.progress` lock is held, `hookctl` refuses with "firmware update in progress, retry". The update syshook re-applies once the firmware run finishes.
- **Core update replaces the file:**
  - Between pkg writing `interfaces.inc` and `rc.syshook update` running, the hook is absent.
  - Any `interface_configure` or `interface_reset` in that window behaves as stock. It kills a missing mpd5 pidfile and starts mpd5 while the kernel clone still holds `pppoeN`.
  - Nothing in a core-only update reconfigures interfaces as far as I found: `update/10-refresh.sh` runs only `rc.configure_firmware` and pyc cleanup (26.7). So the window is realistically hit only by a concurrent CARP event, a user Apply or a PPP link event. That is plausible, not proven.
  - The `managed.<friendly>` registry plus the hook's configure-time cleanup (critique H1/H2) repairs the state on the next configure.
- **New core no longer matches (context changed):**
  - Apply refuses and state becomes `refused:context`.
  - The update syshook then runs `configctl interface reconfigure <friendly>` for each registry-held interface, **after** tearing down the kernel clone itself with `ifconfig destroy`, which sends PADT. That way the box ends up on mpd5 cleanly rather than with an orphaned clone.
  - The GUI shows "OPNsense <ver> changed interface_ppps_*(); os-if-pppoe <ver> does not support it yet. Running on mpd5."
  - Never fuzz-apply.

### 3.6 Boot crash guard (for the uncatchable fatals in §2.3)

- The early syshook writes `/conf/if_pppoe/boot.pending`.
- A `start` syshook, which runs after `rc.bootup` returns, removes it.
- If early finds `boot.pending` already present (the previous boot never completed `rc.bootup`), it reverts the patch, sets `status=refused:boot-failure`, and leaves the plugin effective-off until the user re-enables it.

This is a design proposal; I haven't tested it on a box.

---

## 4. Zero-patch alternatives at 26.7

| Candidate | Exists at 26.7? | Evidence |
|---|---|---|
| `plugins_*` dispatch inside the ppps functions | **No** | The functions shown in §1.1 contain no `plugins_` call. `interface_configure` calls `plugins_devices()` (L18) and runs the device `function` only when `$reload` is set and `realhwif` is in `names`. For PPP, `realhwif` is the parent port (`interface_ppps_hardware`). Execution then continues to `interface_ppps_configure($interface)` (L169) regardless |
| Override a function from `plugins.inc.d` | **No** | `interfaces.inc` declares every function unconditionally (grep finds no `function_exists` guard). A plugin declaration of `interface_ppps_configure` is a redeclare fatal. `plugins_devices()` wraps its include in `catch (\Error)`, but a redeclare is uncatchable (verified in §2.3) |
| `file_exists`-guarded include, or a configurable mpd5 path | **No** | The mpd5 path is a literal in the `mwexecf` at L1328. `interfaces.inc` has a single `require_once("interfaces.lib.inc")` (L33) and no optional includes |
| Wrap `/usr/local/sbin/mpd5` (a shim binary) | Technically possible, **not recommended** | Core's `killbypid(pidfile)` in reset and configure would kill our shim, so teardown would work naturally. But: the shim replaces a file owned by the `mpd5` package (so `pkg check -s` flags that instead); `ppp-rename.sh` loops about 10 s looking for a netgraph node that never appears (26.7 `ppp-rename.sh` L35-49); `ngctl msg <port>: setautosrc 1` fails; the up-wait adds up to 20 s. It moves the patch problem to another package |
| **Plugin-owned device (OpenVPN/WireGuard pattern)** | **Yes, a real zero-patch path, with a UX cost** | See below |

### The plugin-owned device pattern

The plugin registers its clone through `<plugin>_devices()`. This is the same shape as `wireguard_devices()` (26.7 `plugins.inc.d/wireguard.inc` L101-121: `function`, `configurable`, `pattern '^wg'`, `volatile`, `names`) and the plugin-owned `ovpn*` devices. The user assigns WAN to that device with IPv4 type "None". There is then no `<ppps>` entry, `interface_ppps_capable()` returns false, and mpd5 is never started.

Core's downstream code is device-generic:
- `Gateways.php` (26.7 L386-435) creates a dynamic gateway for **any** enabled interface where `Autoconf::getRouter($device)` finds `/tmp/<dev>_router`.
- `rc.newwanip` is device-driven.
- `get_nameservers()` (`system.inc` L349-375) reads `ifctl -nl`.
- The plugin's up-script does exactly what `plugins.inc.d/openvpn/ovpn-linkup` L27-30 does: `ifctl -4rd -i IF -a <peer>`, `ifctl -4nd …`, `configctl -d interface newip IF force`.

The cost:
- Switching needs an interface re-assignment instead of a Services toggle.
- The Interfaces → Point-to-Point UI is not used, so credentials live in the plugin model.
- IPv6 (`dhcp6` over a non-PPP device) and the device naming both need verification. The plugin's `pattern` must not claim `^pppoe`, which core PPP uses, so the clone would need a rename such as `kpppoe0`. I haven't verified that the kmod clone supports `ifconfig … name`.
- MSS clamping must be configured manually, as in critique H6.

**Verdict:** there is no zero-line-change hook for transparently replacing mpd5 on an existing PPP entry at 26.7. The only zero-patch route is the plugin-owned-device model. It is supportable and upgrade-proof, but it changes the user workflow. Upstream, a two-line `plugins_run('ppp_configure'|'ppp_reset', …)` at the same two anchors would make Option 1 unnecessary. That is worth an issue or PR.

---

## 5. Residual risks

1. **Health/audit noise:** `firmware/health.sh:264` (26.7) runs `pkg check -sa`, which will list `/usr/local/etc/inc/interfaces.inc` as a checksum mismatch whenever the hook is applied. The Services page should say so, and Disable should make the audit clean again (§3.2 revert check). Users who paste health output into support threads will expose it.
2. **Support stance:** a modified core file puts the box outside what the OPNsense project supports. I haven't verified a written policy; this is general knowledge. Expect "revert modifications first" answers. Make the GUI Disable button one-click and byte-exact.
3. **Upgrade windows:** see §3.5. They are fail-safe to mpd5 except in the orphaned-clone case, which the registry cleanup must handle. It needs a lab drill: a core minor update with a live kernel session, followed by an immediate Apply.
4. **New core breaks the context:** the box falls back to mpd5 until we ship a plugin update with a `v2` anchor set. Anchor stability is good (0 changes since 26.1, 5 anchor lines untouched since 2024-08). But a refactor like master's new `interface_configure($batch, $all_devices)` could arrive in the ppps functions without notice. Mitigation: CI that runs `hookctl.php` against `opnsense/core` master nightly.
5. **Uncatchable PHP fatals in `hook.inc`** (§2.3): these can take down `rc.bootup`'s interface configuration. Mitigations are the shim discipline, out-of-process work, lint and self-test, and the boot crash guard. The residual risk is non-zero.
6. **Skipped core epilogue:** when the hook returns true, `legacy_interface_mtu`, `ngctl setautosrc` and the up-wait are skipped. The hook must set the MTU itself, and nothing else needs replicating for pppoe. The `mpd_<if>.conf` with the password is still written by core before the anchor; the hook should unlink it.
7. **A future core guard added after the anchor** would be bypassed. It is unlikely, since the anchor sits directly before the launch, but CI context checks catch any edit there anyway, because the context includes the launch line.
