# Engine tests

`src/opnsense/scripts/if_pppoe/engine` (installed at `/usr/local/opnsense/scripts/if_pppoe/engine`) plus `src/etc/devd/if_pppoe.conf`.

## Running

```sh
sh plugin/net/if-pppoe/tests/engine/run.sh               # local php >= 8.1 (and bash for the devd case)
sh plugin/net/if-pppoe/tests/engine/run.sh --docker      # php:8.2/8.3/8.4/8.5-cli images
sh plugin/net/if-pppoe/tests/engine/run.sh ineligible    # name filter
```

The engine prefixes every absolute path with `$IF_PPPOE_ROOT`. Each test builds a throw-away root with:
- a `config.xml` fixture from `fixtures/`, optionally edited through the DOM;
- `stubs/stub.php` installed as `ifconfig`, `sysctl`, `pppoectl`, `configctl`, `pgrep`, `logger`, `daemon`, `ppp-linkup.sh` and `ppp-linkdown.sh`. The stub records argv and stdin to `calls.jsonl` and simulates interfaces, sessions, sysctls and pppoectl settings (list-mode read-back) from `fake/`. `fake/fail.json` and `fake/hang.json` inject failures and hangs by argv prefix.

The credential assertions check every recorded argv and every state file for the username and the secret.

`test_integration.php` holds the cross-component contracts: the real `engine status --json` run through the GUI's `Support::mergeStatus()`, the real `engine notices --json` through `IfPppoeStatus` (core classes stubbed in `stubs/opnsense_status.php`), the model mount vs. the config path the engine reads, the pkg trigger directory, the cron entries vs. the configd actions, the shared `timeout(1)` path and the hasync fields.

## Interfaces the engine assumes

| What | Assumption | Evidence |
|---|---|---|
| pppoectl discovery | `pppoectl -e <parent> [-s <service>] <dev>` | `sbin/pppoectl/pppoectl.c:202-222` |
| pppoectl settings | `pppoectl -S -f <cfgfile> <dev>` (`Pppoectl::settingsArgv`). stdin is the secret line and nothing else: `-S` reads it with one `getline(3)`, strips a trailing LF then CR, and does no fparseln unescaping. `<cfgfile>` holds the other settings lines (`\` and `#` escaped for fparseln). The engine creates it as `/var/run/if_pppoe/pppoectl.<dev>.<random>.conf` (fopen `x`, umask 077, mode 0600, fsync), never writes the secret to it, and unlinks it in a `finally` on every path (`Pppoectl::withSettingsFile`). Stale files for the same device, left by a configure that was killed mid-call, are removed under the device lock. | It must be one invocation because SPPPSETAUTHCFG replaces name and secret together (`sys/net/if_spppsubr.c:6353-6364`). pppoectl at driver-finish rejects `-S -f /dev/stdin` with EX_USAGE 64, "-S cannot be combined with -f /dev/stdin (both read the secret from stdin)" (`sbin/pppoectl/pppoectl.c:229-232`), and `-S -e` likewise (`:227-228`). It also rejects a `myauthsecret=`/`myauthkey=` line after `-S` (`:553-556`). `-S` is read at `:302-314`, and `-f` is fopen+fparseln at `:386-405`. A missing `-f` file exits 66. The stub enforces all of these, and `fake/pppoectl-drop-f` makes it silently ignore the `-f` lines |
| pppoectl read-back | `pppoectl <dev>` (list mode) after the settings call must show `myauthproto=chap myauthname="<user>"`, no `hisauthproto=`, `max-auth-failure = 0`, and `ipcp:`/`ipv6cp:` (plus `mssfix:` when printed) as planned. Otherwise the configure fails with exit 2 and core runs mpd5 | `pppoectl.c` print_vals at p3-ctl-abi, `mssfix:` line at p3-mss 1f7d1b1 |
| pppoectl keys | `myauthproto=chap passiveauthproto myauthname= hisauthproto=none max-auth-failure=0 [no]ipcp [no]ipv6cp query-dns=` exist today; `mssfix`/`nomssfix` is **assumed** for p3-mss | `pppoectl.c:439-575` |
| clone ownership | clones are members of interface group `pppoe` (`ifconfig -g pppoe`); mpd5's ng(4) interfaces are not | not verified on a box |
| devd event | `system=PPPOE subsystem=<if> type=<T> local= remote= dns1= dns2= mtu=`; for IPv6CP, `local`/`remote` are a link-local address or a 64-bit ifid | shared contract |
| core scripts | mpd5 up/down-script argv: `inet <self>/32 <peer> <authname> 'dns1 X' 'dns2 Y' <peeraddr> <filter>`, down `inet <self>/32 <peer> <authname> <peeraddr> <filter>`, v6 `inet6 <self>%if <peer>%if <authname> <peeraddr> <filter>`. The engine passes `-` for authname, peeraddr and filter, and `''` for an address it does not know (never `0.0.0.0` or `::`) | mpd5 `src/iface.c` (sourceforge trunk); `ppp-linkup.sh` reads only $1 $2 $4 $6 $7 at 25.7.11, and turns any non-empty $4 into `ifctl -4rd/-6rd -a <router>` (lines 18-22, 28, 33) |
| devd dispatch | devd waits for each action. `engine linkevent` appends the event to `/var/run/if_pppoe/queue/<dev>.q` and runs `/usr/sbin/daemon -f engine drain <dev>`, then returns. The drain takes the device lock (up to 120 s) and replays the queue in devd order. Events older than the clone's `created_us` are dropped. Events a drain could not deliver are delivered by the next reconcile. If daemon(8) fails, the events are drained inline | devd.conf(5); ordering reasoning in `Engine::linkevent` |
| /var/run | wiped at boot, so the registry and the `effective.json` snapshot are per boot | core 25.7.11 `src/etc/rc.subr.d/var:66-76` |

## ctl-contract: engine argv/stdin/-f shapes replayed against the real pppoectl

Item 1 below is now automated end to end instead of a by-hand box session,
across PAP, CHAP, service-name, ac-name, mtu/mssfix and secrets with spaces,
tabs and unicode:

- `ctl_contract_fixtures.php`'s CHAP scenarios run the real `Engine::configure()`
  against a throw-away Sandbox and read the argv/stdin/-f-file content it
  handed the recording stub back off `calls.jsonl` -- so they cover
  `Engine::bringUp`'s glue (create/down/discovery/settings/verify-before-mtu/up,
  `Engine.php:195-234`), not just `lib/Pppoectl.php`'s helpers in isolation.
  PAP and ac-name are hand-built from the same `Env`/`Plan`/`escape()` the
  engine uses -- see its class docblock for why those two aren't things the
  Engine sends today, so there is no `configure()` path to generate them from.
- `gen_ctl_contract.php` dumps them to `../fixtures/ctl-contract.json` (for
  review/diffing) and to `../fixtures/ctl-contract/<name>/...` (one
  argv-token-per-line / raw-bytes file per scenario, for the sh replay
  script -- no JSON parser needed on the FreeBSD box), and removes any
  scenario directory from a previous run that no longer has a match.
  Regenerate both after any change to the fixtures or to the argv shapes above.
- `test_ctl_contract.php` (part of `run.sh`/`run.sh --docker`) checks both
  committed renders are still exactly what `CtlContract::scenarios()`
  produces, then replays each fixture through `stubs/stub.php` (in the same
  create/down/discovery/settings/verify/mtu order `Engine::bringUp` uses) and
  checks the read-back. `stubs/stub.php`'s `ifconfig ... mtu` also applies the
  same RFC 4638 parent-MTU rule the kernel does, so a fixture whose mtu the
  real box would refuse fails offline too, not only on the lab/CI replay.
- `ctl-contract-replay.sh` replays the same fixtures against the real
  `sbin/pppoectl` (create/discovery/settings/verify/mtu/destroy, no dial
  needed); `tests/functional/test_ctl_contract.py` runs it on the lab client
  via `lab.push_ctl_contract()` (fixtures + the replay script are staged on
  the lab host under `tests-functional/vendor-ctl-contract/` by
  `lab/Makefile`'s `test-func`, the same way vendored sppp headers are), and
  `.github/scripts/smoke-guest.sh`'s `ctl-contract` hook runs it in CI against
  an epair (the guest has no second NIC to use as a parent).
  argv[0] in every generated fixture is the placeholder `@POCTL@`/`@IFCONFIG@`,
  never a hardcoded path: CI runs its own freshly built `pppoectl`, not
  whatever (or nothing) is at `/usr/local/sbin/pppoectl` in the guest.
- **Accepted, not round-trip, checks:** `pppoectl` has no getter for the
  service-name or ac-name it was given (`PPPOEGETPARMS`,
  `sys/net/if_pppoe.c:3461`, is not exposed by `sbin/pppoectl`), and a secret
  with spaces, tabs or unicode cannot be read back either (`pppoectl` never
  prints it). For those three, `ctl-contract-replay.sh` only checks that
  discovery/settings exit 0, not that the value stuck.

## On-box tests (need a FreeBSD 14.3 / OPNsense 25.7.x VM with the kmod)

1. **pppoectl -S plus -f file round-trip:** now covered by ctl-contract above; kept here as the by-hand fallback. `ifconfig pppoe9 create`, then write the `-f` lines to a 0600 file and pipe only the secret, with the special-character passwords from `test_engine.php`, through the real driver-finish pppoectl (`umask 077; printf '%s\n' 'myauthproto=chap' 'passiveauthproto' 'myauthname=us\#er' 'hisauthproto=none' 'max-auth-failure=0' 'ipcp' 'ipv6cp' 'query-dns=3' 'mssfix' > /var/run/if_pppoe/t.conf; printf '%s\n' "$secret" | pppoectl -S -f /var/run/if_pppoe/t.conf pppoe9; rm /var/run/if_pppoe/t.conf`). Then `pppoectl pppoe9` must print `myauthproto=chap myauthname="us#er"`, `max-auth-failure = 0`, `ipcp: enable`, `ipv6cp: enable` and `mssfix: enable`. `printf 'x\n' | pppoectl -S -f /dev/stdin pppoe9` must exit 64. Finally, CHAP and PAP must authenticate against the lab mpd5 server that uses the same secret.
2. **`ifconfig -g pppoe`** lists kernel clones and not mpd5 `ng` interfaces.
3. **Claim path:** Interfaces → Apply on WAN. `ps` must show no mpd5, `/var/etc/mpd_wan.conf` must be gone, `/var/run/if_pppoe/reg/pppoe0.json` must exist, and `ps -axww` during configure must show no secret.
4. **Link events:** `devd -d` shows `PPPOE` events. `/tmp/pppoe0_router`, `/tmp/pppoe0_nameserver` and `/tmp/pppoe0_uptime` must appear, and the gateway WAN_PPPOE must come up.
5. **IPv6:** with `ipaddrv6=dhcp6`, IPV6CP_UP must start dhcp6c on pppoe0 (`ps | grep dhcp6c`), and a PD prefix must land on LAN.
6. **Lost events:** kill devd, drop and redial the session (`ifconfig pppoe0 down up`), restart devd, then run `engine reconcile`. It must replay linkup exactly once.
7. **Orphan:** `ifconfig pppoe7 create` then `engine reconcile` destroys it.
8. **Fallback:** make the hook not applied (`hookctl revert`), write `hook.json` `refused:context`, then run `engine reconcile --after-firmware`. The clone must be destroyed with a PADT seen on the server, and mpd5 must be redialled by core.
9. **Timeout:** temporarily replace `/usr/local/sbin/pppoectl` with a script that runs `sleep 60`. (A stub in PATH has no effect because the engine uses absolute paths.) The hook's `timeout 45` must kill the engine, and `/var/etc/mpd_wan.conf` must still exist. The next reconcile must remove the stale `configuring` record and the clone, then run `configctl interface reconfigure wan` once, and mpd5 must come up.
10. **Settings did not apply:** with a pppoectl that ignores `-f` (for example a1839bb, which drops the lines), Interfaces → Apply on WAN must log `kernel setup failed ... myauthproto/myauthname not applied`, leave no pppoe clone and start mpd5 with its conf.
11. **devd not blocked:** `devd -d` in the foreground, then drop and redial the session. Each `engine linkevent` must return in well under a second (`ktrace -i -p $(pgrep devd)` or timestamps in `devd -d`), and a `daemon: engine drain pppoe0` process must briefly appear. While a configure holds the device lock (`engine configure` with a sleeping pppoectl), link events for other interfaces must still reach their handlers at once.

## Contract deviations (all fail safe to mpd5)

These need the owner's sign-off. They are reported to the orchestrator but not yet folded into the shared contract.

| Deviation | Why |
|---|---|
| A custom `host-uniq` makes an interface ineligible | PPPOESETPARMS has no Host-Uniq field; the kmod always sends its own 64-bit value (`Eligibility.php`) |
| MRU must be empty or equal to the MTU | sppp derives the LCP MRU from if_mtu (`if_spppsubr.c:2774-2778`) |
| Extra exit codes: 2 = eligible but kernel setup failed or engine error, 64 = usage | The hook treats every non-zero exit as "use mpd5", so this changes nothing for core |
| The up/down scripts get authname `-` | argv is world-readable; `ppp-linkup.sh` never reads $5 |
| Extra state: `/var/run/if_pppoe/effective.json` (per-boot settings snapshot) and `/var/run/if_pppoe/queue/` (link events) | Reboot-to-apply for the exclude list; devd must not wait for core's scripts |
| A `pppoectl <dev>` read-back after the settings call, and an `engine drain <device>` subcommand | Catch silently dropped settings; the detached half of `linkevent` |
| A stale `configuring` record found by reconcile triggers `configctl interface reconfigure <if>` (at most once an hour) | A killed configure leaves core's mpd5 unable to take the device name |
