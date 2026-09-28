# os-if-pppoe hook tests

## Local (no OPNsense needed)

```
PHP=php sh tests/hook/run.sh          # PHP 8.3 is what OPNsense 25.7 ships
```

- `hook/hookctl_test.sh`: `hookctl.php` apply/revert/status/selftest against
  the real `interfaces.inc` from core tags 25.7, 25.7.11, 26.1, 26.1.11 (the
  latest 26.1.x release, matching `.github/versions.json`) and 26.7.4 (the
  latest 26.7.x release; see `docs/plugin/interfaces-inc-hook.md` for why
  this anchor set is expected to keep applying with zero fuzz on 26.7's
  FreeBSD 15.1 / PHP 8.5 base too). It checks
  2 lines added and 0 changed, `php -l`, idempotency and a byte-identical
  revert. It also covers these refusals: modified anchor, duplicate context,
  context outside the function, foreign marker, pkg checksum mismatch,
  pre-existing syntax error and HA config. It covers the revert fallbacks
  (hand-edited line, later unrelated edit, no backup) and reapply
  (same-version reinstall pauses, a version change re-applies, anchor drift
  refuses, a reverted hook is never re-armed). Backup pruning is covered too.
- `hook/harness.php`: runs the real `interface_ppps_reset()` and
  `interface_ppps_configure()` from the patched file with stubbed core
  helpers. Engine exit 0 skips mpd5. A non-zero exit, a timeout (124), a
  missing engine or a Throwable all start mpd5. Reset always reaches
  `killbypid`.
- `hook/syshook_test.sh`: early/start/update syshooks and `reapply.sh`
  against a fake `/conf` and `/var/run`, with kldload, kldstat, kldunload,
  sysctl, hookctl, configctl and ifconfig stubbed. It covers kern.build_id
  gating, the optional .ko sha256, each FEATURE flag, the strike counter,
  the latch and un-latch, and the update fallback to mpd5 (through
  `engine reconcile --after-firmware`, with the shell fallback only when the
  engine is missing or fails). It also covers the `uninstall.sh` order
  (revert, then reset and reconfigure each WAN). The final block runs the
  real hookctl (`REAL_PHP`).

`fixtures/interfaces.inc/<tag>` are verbatim copies of
`src/etc/inc/interfaces.inc` from https://github.com/opnsense/core
(BSD-2-Clause):

| tag | commit | sha256 |
|---|---|---|
| 25.7 | 17d0a22a05 | 10d1cda18a59f23d7f286dd21893a409ed3a83696478080af346b661cfd90be8 |
| 25.7.11 | 41587bb2d4 | fd2fbbdd7a66a290fcda73af5c0a82c7d4b74083d4ed1ca050858917b05879c3 |
| 26.1 | 659e22be72 | 0d16b4903b89b5bcec742f74337f7e01ca232b1fba6d7fde338a3b5665c2c4ab |
| 26.1.11 | c930ab586f | 8ae279391ca759c0429c8629e625ac16d4ecdf80f95de638553c9130a091fabf |
| 26.7.4 | ace3b5b5f8 | 98efe572989b3079b63304e7799698a356b81386c16641aee017f2265aea5096 |

## On-box (OPNsense 25.7.x VM, later)

1. `hookctl.php status --json` on a pristine box reports live `pristine`.
   `pkg check -s opnsense` is clean.
2. `hookctl.php apply --reason=manual`, then `hookctl.php selftest`, then
   `pkg check -s opnsense` lists only `interfaces.inc`. Next, `configctl
   interface reconfigure wan` with a stub engine that exits 1: the WAN
   comes up on mpd5, as on stock.
3. `hookctl.php revert`, then check `pkg check -s opnsense` is clean and
   `sha256` matches `pkg query '%Fs'`. This also confirms the `%Fs`
   encoding, which is unverified so far.
4. Boot with `desired=enabled`. `/var/run/if_pppoe/boot.json` shows
   `enabled:ok` and `kldstat -v` shows the module loaded from
   `/usr/local/lib/if_pppoe/<build_id>/`. `sysctl kern.build_id` must
   match. Confirm the sysctl exists on 14.3.
5. Strike drill: 3 power cuts during boot, after early/50 and before
   start/50. The 4th boot is `latched:strikes`, runs stock mpd5 and shows
   a notice. Re-save the settings, reboot, and the box is armed again.
6. Core update drill: `opnsense-update` / `pkg install -f opnsense` while
   enabled. A version change re-applies the hook from update/05. A
   same-version reinstall gives `paused:core-reinstall` and the WANs go to
   mpd5. Also check that the pkg trigger fires, and whether
   `pkg install -f` runs `+POST_INSTALL` (unverified).
7. Anchor-drift drill: install a core package with a modified
   `interface_ppps_configure`. Expect `refused:anchor`, clones destroyed
   (PADT seen on the peer) and the WAN re-dialled by mpd5.
8. HA refusal: add a CARP VIP. `hookctl apply` gives `refused:ha`.
