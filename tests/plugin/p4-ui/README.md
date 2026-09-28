# p4-ui tests (Services page)

Runs without a live OPNsense box. Needs `docker` (for `php:8.2-cli`,
`php:8.3-cli`, `php:8.4-cli`, `php:8.5-cli` — already pulled in this dev
environment) and `/bin/sh`.

```
./run.sh
```

What it covers:
- `php -l` on every plugin PHP file, on PHP 8.2/8.3/8.4/8.5 (OPNsense's own
  port build isn't pinned to one PHP minor — see `Mk/defaults.mk` in
  opnsense/core — so this checks the versions the interfaces.inc hook
  research already validated against, plus 8.5, which 26.7 ships
  (`opnsense/tools` `config/26.7/build.conf`: `PHP?= 85`); see
  `docs/plugin/interfaces-inc-hook.md`).
- XML well-formedness of the model, forms, Menu and ACL XML, via PHP's
  `DOMDocument` in place of `xmllint` (not installed, and this sandbox has no
  network to fetch it). These files have no DTD/XSD, so well-formedness is
  what `xmllint --noout` would have given us too.
- Structural sanity of `actions_if-pppoe.conf` (required keys per section,
  absolute command paths, the five expected actions present, `reconfigure`'s
  parameter quoted).
- Full behavioural test of `set-desired.php` as a real subprocess (valid
  enabled/disabled writes, atomic rename with no leftover temp file, 0600
  mode, invalid/missing argument rejected without touching an existing file).
- `OPNsense\IfPppoe\Support` (`test_support_lib.php`): the mapping of the
  engine's `status --json` onto the `Api\ServiceController::statusAction()`
  payload, and the CARP/hasync standalone-only guard behind
  `IfPppoe::performValidation()` and `Api\ServiceController::reconfigureAction()`.
  Covers engine-absent, key mapping (`desired`→`persisted`, `hook`→`hook_status`,
  interface map→list with `friendly`, session as a string), `reboot_required`/
  `apply_pending` taken from the engine rather than recomputed, latched vs.
  `refused:<reason>` vs. `paused:core-reinstall` advice, failed-boot advice and
  notices, and CARP VIP / hasync `pfsyncpeerip`/`pfsyncinterface`/
  `synchronizetoip` refusals.
  `Support` has zero `OPNsense\Base`/`OPNsense\Core` dependency (same
  rationale as `set-desired.php` below), so it needs no Phalcon stub either.

What it deliberately does **not** cover (needs a real OPNsense box, or at
least the Phalcon-based MVC framework, neither available in this sandbox):
- Instantiating the Api\SettingsController / Api\ServiceController classes
  themselves, or `IfPppoe`'s `parent::performValidation()`. They extend
  `OPNsense\Base\ApiControllerBase` / `OPNsense\Base\BaseModel`, which need a
  live Phalcon DI container (request/response/ACL/session) to construct —
  there's no vanilla-PHP stub for that here, and the OPNsense-patched Phalcon
  extension isn't available in a generic `php-cli` image. `set-desired.php`
  and `OPNsense\IfPppoe\Support` are deliberately written with zero
  `OPNsense\*`/Phalcon dependency so they *can* be tested this way instead;
  the model and the two Api controllers stay thin wrappers around them plus
  `Config::getInstance()`/`Backend::configdpRun()`/`configdRun()`.
- `engine status --json` / `engine reconcile` themselves — those are a
  different component (see the shared contract); this component only wires
  configd actions to their documented paths and degrades gracefully
  (`engine_available: false`) when they're not present yet.

## On-box tests to run once merged onto a real 25.7.11 box

1. Install the plugin, confirm it appears under System → Firmware → Plugins
   and installs cleanly (`pkg audit`/`pkg check -s` clean afterwards).
2. Services → Kernel PPPoE page loads, ACL `page-services-ifpppoe` gates
   both `ui/ifpppoe/*` and `api/ifpppoe/*` for a non-admin group.
3. Toggle Enable, add an excluded interface, Save and Apply:
   - `GET /api/ifpppoe/settings/get` reflects the saved value.
   - `/conf/if_pppoe/desired` now contains `enabled` (root-owned, 0600, from
     the correct configd-invoked `set-desired.php`, not the www process
     itself).
   - the reboot banner shows "Yes" until reboot; the Reboot button asks for
     confirmation, then matches what `/api/core/system/reboot` does
     elsewhere in the UI (and, tried from an account with this page's ACL
     but not `page-diagnostics-rebootsystem`, surfaces a failure message
     instead of doing nothing).
4. With a CARP VIP, `hasync.pfsyncpeerip`/`pfsyncinterface`, or
   `hasync.synchronizetoip` configured, confirm Save itself now reports a
   field error on `general.enabled` (`IfPppoe::performValidation()`) --
   `Support::standaloneViolation()`'s logic is unit-tested
   (`test_support_lib.php`), but wiring it through the live Phalcon
   model/validate path needs a real box. Also confirm
   `Api\ServiceController::reconfigureAction()`'s defense-in-depth copy of
   the same check still refuses a race (config.xml edited directly).
5. Confirm `service/status` shows real `hook_status`/`effective`/
   `interfaces[]`/`persisted`/`boot`/`notices`/`advice` data instead of
   `engine_available: false`. The JSON shape is fixed by
   `Support::mergeStatus()`'s doc comment, and
   `plugin/net/if-pppoe/tests/engine/test_integration.php` runs the real
   `engine status --json` through it. Confirm the Services widget's
   "if_pppoe" Restart button (mapped to the read-only `status` action) does
   nothing destructive, and that a latched box shows the "Save and Apply to
   retry" advice instead of a reboot prompt. With a notice file in
   `/var/run/if_pppoe/notice.d/`, System → Status shows a "Kernel PPPoE"
   entry (`IfPppoeStatus`).
6. `if_pppoe_cron()`'s jobs (`reapply` every 5 minutes, `reconcile` every
   minute) and the `if_pppoe_services()` widget row appear unconditionally
   (not gated on `general.enabled`); confirm both are cheap no-ops on a box
   that never enables the plugin.
