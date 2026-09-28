# tests/plugin — plugin install/enable/reboot round-trip

Tests the if-pppoe plugin end to end against a live OPNsense VM, over its
Firmware/IfPppoe API: register the signed repo, install `os-if-pppoe`,
enable, reboot, assert kernel backend + WAN_PPPOE gateway up + IPv4/IPv6
connectivity, disable, reboot, assert stock mpd5, uninstall, assert
`pkg check -s`-clean and config.xml unchanged.

**Draft only in this session** — written and locally verified at the level
these tools support (unit tests below), but never run against a real DUT:
there was no lab access here. See `lab/vm/README.md`'s "dut (plugin-test
DUT)" section for what's grounded in source vs. still assumed about the VM
itself, and this file's "Unverified against the real plugin" section below
for what's assumed about the plugin's own API shape.

## Running

```
cd tests/plugin
python3 -m pip install -r requirements.txt   # requests; defusedxml optional
python3 -m pytest .
```

With no live DUT configured, this runs everything **except**
`test_roundtrip.py`, which skips (not fails) and prints why:

```
test_config_diff.py .......                 # config.xml "identical" diff logic
test_dut_seed.py ........                   # seed render: locked root, API secret hash only, per-run values
test_plugin_contract.py ...                 # settings payload, model mount, status keys vs. plugin sources
test_repo_registration.py .........         # pkg repo .conf, fingerprint UCL, per-ABI <base>/${ABI} URL
test_roundtrip.py s                         # SKIPPED: no live DUT configured
../../lab/vm/test_console_driver.py .......  # (run separately, see its own file)
```

That split is deliberate: the logic that doesn't need a box (config
normalization, repo-file rendering) is exercised on every run, anywhere;
only the actual box-poking test needs the lab.

### Against a live DUT

There are no standing DUT credentials. `lab/vm/plugin-roundtrip.sh` is the
only entry point: per run it generates an ephemeral root ssh key (on tmpfs),
an API key+secret and a PPPoE account password, provisions `dut` with them
(root has no password; the seed embeds only the API secret's hash), runs
`pytest tests/plugin` with `IFPPPOE_DUT_*` set for that process only, then
removes the PPPoE account, scrubs the seed, shreds the key and deletes the
run's overlay. Nothing is written to `$HOME` or any disk.

```
export IFPPPOE_REPO_URL=http://lab-host.example:8080/if-pppoe
export IFPPPOE_REPO_SIGNING_PUBKEY_PATH=/path/to/signing-key.pub  # public key, kept outside this repo
../../lab/vm/plugin-roundtrip.sh -v -s          # extra args go to pytest
```

`IFPPPOE_REPO_URL` is the lab's own flat repo, served for the run, and is
used as-is. Published (CI/GitHub Pages) repos are one per FreeBSD ABI instead,
and a real box registers `repo_registration.repo_url(<base>)`, i.e.
`<base>/${ABI}` with pkg's `${ABI}` left literal and no series suffix (see
`docs/plugin/INSTALL.md`).

Each run boots `dut` from a throwaway qcow2 overlay on the lab host's
`/dev/shm`, deleted at teardown, so `images/dut.qcow2` stays the
never-provisioned install and needs no reset between runs.

## TLS

`OpnsenseApiClient` defaults to `verify_tls=False` because the lab DUT's
webConfigurator cert is self-signed and there's no lab CA bundle to point at
in this session. Before this runs unattended (CI-like), pin the DUT's actual
cert (`OpnsenseApiClient(..., verify_tls="/path/to/dut-cert.pem")` —
`requests`' `verify` parameter accepts a CA bundle path) instead of leaving
verification off.

## Config-identical check

The round trip reads `/conf/config.xml` live over ssh (`conftest.dut_live_config`), not
`OpnsenseApiClient.download_config_backup()` — that returns the newest
`/conf/backup/config-*.xml`, which can be empty/absent on a box never `write_config()`'d,
and is a snapshot from whenever the last backup happened, not necessarily "now".
`config_diff.py` also excludes the `<OPNsense><IfPppoe>` subtree by contract: removing the
package does not prune the plugin's own model data from `config.xml`, so its presence
after uninstall (absent before install) is expected, not a real mismatch — see that
module's docstring. Everything else, including element order (e.g. `<filter><rule>`,
where order is pf's evaluation order), is compared as a real difference.

## Firmware action polling

`install`/`remove`/`health` all run async, through `daemon -f .../launcher.sh`
(`actions_firmware.conf`), so the POST returns before the job starts, and
`upgradestatus`'s log can still be serving the PREVIOUS action's output (ending in its own
`***DONE***`) when the next one is posted — including when `launcher.sh`'s `flock -n`
silently drops a job posted while another is still running. `opnsense_api.py` guards
this: it waits for `running` to go idle before posting, records the log as it stood then,
and after posting requires either `running` to go busy or the log to visibly change
before trusting the poll — otherwise it raises instead of returning a stale result as
fresh. `firmware_health()` additionally checks the log looks like an actual `pkg check`
run (loosely — see that method's comment for why the exact expected text is unverified).

## Unverified against the real plugin

`opnsense_api.py`'s `IFPPPOE_*` action paths (`/api/ifpppoe/settings/get`,
`.../settings/set`, `.../service/status`, `.../service/reconfigure`) follow
the `ApiMutableModelControllerBase`/`ApiMutableServiceControllerBase`
convention other simple OPNsense plugins use (verified pattern: AcmeClient's
`accounts.volt` calls `/api/acmeclient/accounts/search`, opnsense/plugins
`security/acme-client` at core tag 25.7.11; ClamAV's `GeneralController`
extends `ApiMutableModelControllerBase` with no local get/set methods, i.e.
inherited from the base). Now pinned to the plugin sources and checked
offline by `test_plugin_contract.py`:
- `settings/set` posts `{"ifpppoe": {"general": ...}}` (the controller's
  `$internalModelName`; core reads `$_POST[internalModelName]`).
- `test_roundtrip.py` asserts real `service/status` keys
  (`reboot_required`, `persisted`, `hook_status`, `boot`, `interfaces[]`
  with `friendly`/`backend`), all returned by `Support::mergeStatus()`.

Still open:
- `pkg_name` if the actual plugin package name differs from `os-if-pppoe`
  (the OPNsense `os-*` naming convention applied to `if-pppoe`, as the
  best available guess).
- `OpnsenseApiClient.gateway_status()`'s path (`/api/routes/gateway/status`) and response
  shape are UNVERIFIED (no source fetch this session) — the round trip only substring-greps
  for `WAN_PPPOE` in the flattened response; confirm the real path/field names.

## What's NOT covered here (describe-for-later, per the task spec)

On-box-only checks that need a real box and can't be meaningfully faked:
- Actual PPPoE session establishment against the lab's accel-ppp server
  (this test currently checks for a default route via `pppoe0` and a couple
  of pings, which proves *a* session came up, not which backend dialed it
  beyond the plugin's own status field).
- DHCPv6-PD behavior downstream of the plugin's link-up path
  (`ppp-linkup.sh`-equivalent) — not exercised at all here; would need a LAN
  client behind the DUT requesting a delegated prefix.
- The boot-strike-counter latch (3 unclean boots in 24h) and the
  core-update re-apply syshook — both need multiple real reboots / a real
  package upgrade to trigger, not a single round-trip.
- MSS clamping in the RFC4638-eligible (parent MTU >= 1508) case — the seed
  config's WAN MTU is left default (1492 parent MTU on the lab's br-isp
  path), so this test never exercises the >1492 branch.

Left over after uninstall, and DOCUMENTED rather than asserted as a failure (the round
trip logs whether it finds it): `if-pppoe-kmod` (a `PLUGIN_DEPENDS`, never
reverse-removed by `pkg remove os-if-pppoe`). `/conf/if_pppoe` is asserted ABSENT:
`uninstall.sh` (run by `+PRE_DEINSTALL`) removes it once `hookctl revert` succeeded.
