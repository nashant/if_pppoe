# CI / build pipeline (GitHub Actions)

This repo does not have a GitHub remote yet. Nothing in the CI workflows
hard-codes an owner: they use `${{ github.repository }}`. Outside CI, the
owner-shaped strings (maintainer and WWW/URL fields) are set to
`nashant`/`nashant@users.noreply.github.com`; update them if the repo ends up
under a different owner. Fresh inventory (regenerate with
`grep -rn nashant plugin lab docs`):

- `plugin/maintainer.mk:5` -- the single `MAINTAINER` definition.
  `plugin/net/if-pppoe/Makefile:7` (`PLUGIN_MAINTAINER`) and
  `plugin/kmod/if-pppoe-kmod/Makefile:9` (`KMOD_MAINTAINER`) both read it via
  `.include`, and `lab/pkg/build-os-pppoe.sh:21` sources the same file, so
  changing the address means editing this one line.
- WWW/URL literals, still repeated per file: `plugin/net/if-pppoe/Makefile:8`,
  `plugin/kmod/if-pppoe-kmod/Makefile:10`, `plugin/net/if-pppoe/pkg-descr:17`,
  `plugin/kmod/if-pppoe-kmod/pkg-descr:12`, `lab/pkg/build-os-pppoe.sh:95`,
  and `docs/CI.md`'s own `IF_PPPOE_REPO_URL_BASE` GitHub Pages example in the
  "Secrets and variables" table below.

**Prerequisite:** the pipeline expects the *merged* layout, meaning
`driver-finish` plus `p4/plugin` (`plugin/`, `tests/plugin/`). Lint runs
`plugin/build/test-packaging.sh` and the p4-ui suite, the PHP job runs the
plugin engine/hook suites, and `freebsd-build.sh` stops with an error if
`plugin/kmod/if-pppoe-kmod` is missing. Merge `ci/github` after (or together
with) `p4/plugin`.

## Files

| Path | Role |
|---|---|
| `.github/versions.json` | One entry per OPNsense series: where its kernel sets are published, its FreeBSD ABI and toolchain |
| `.github/workflows/ci.yml` | push to `main`, PRs: lint, host unit tests, then build + smoke (newest kernel per series) for every ABI |
| `.github/workflows/build.yml` | Reusable: discover kernels, build the kmods per ABI in a FreeBSD VM, smoke (`smoke.yml`), package per ABI |
| `.github/workflows/smoke.yml` | Reusable: per-kernel KVM boot smoke, sharded; merges results into `compat.json` and per-ABI pass lists |
| `.github/workflows/nightly.yml` | Daily. New OPNsense kernel: kernel-only refresh release `v<ver>_<N>`. Otherwise: regression build of `main` against the latest tags. Opens an issue on failure and when a new series appears |
| `.github/workflows/release.yml` | Tag `v<ver>`: build every kernel, smoke the untested ones, publish one signed repo per ABI (`publish.yml`) |
| `.github/workflows/publish.yml` | Reusable: this run's artifacts to a GitHub Release (release.yml, nightly refresh) |
| `.github/workflows/pages.yml` | Opt-in (`ENABLE_PAGES=true`): publishes a release's repos to GitHub Pages as `<ABI>/` |
| `.github/workflows/renovate.yml` | Optional self-hosted Renovate. Leave it off if the Renovate GitHub App is installed |
| `renovate.json` | Renovate config: OPNsense pins, action SHAs, CI tool versions |
| `.github/scripts/matrix.sh` | versions.json to `{"include":[...]}`: `abi` mode (one row per FreeBSD ABI), `build` (one row per entry), `php` (one row per PHP version) |
| `.github/scripts/discover-kernels.sh` | CI wrapper around `plugin/build/discover-kernels.sh` (kernels.json, groups, the set-cache key) |
| `.github/scripts/resolve-latest.sh` | nightly: newest released core tag, plus the matching src tag that has a kernel set |
| `.github/scripts/freebsd-build.sh` | Runs inside the FreeBSD VM: `--phase kmods` (userland + `build-all.sh --phase kmods`) and `--phase package` (packages, signed `<ABI>/` repo) |
| `.github/scripts/smoke-plan.sh` / `compat.sh` | Which kernels to smoke, sharded; the `compat.json` result cache (lookup, merge, pass/fail lists) |
| `.github/scripts/smoke-vm.sh` / `smoke-guest.sh` | KVM smoke on the ubuntu runner (one guest per shard, one reboot per kernel), and the guest-side checks |
| `.github/scripts/release-assets.sh` | publish.yml: artifacts to release assets, `coverage.json`, `SHA256SUMS`, notes |
| `.github/scripts/pages-site.sh` | pages.yml: release assets to the Pages tree and index |
| `.github/scripts/refresh-plan.sh` | nightly: base version of a tag, next `_N`, new build_ids |
| `.github/scripts/lint-shell.sh` | shellcheck with two tiers (see below) |
| `plugin/build/discover-kernels.sh`, `build-all.sh` | Shared with local builds: kernel discovery, multi-kernel kmod + plugin packages (`docs/plugin/INSTALL.md`) |
| `tests/requirements-dev.txt` | Pinned pytest/scapy for the python job (Renovate-tracked) |
| `.yamllint.yml` | yamllint rules adjusted for Actions syntax |

## Pipeline

```
ci.yml ──┬─ setup   (matrix.sh → abi matrix + php matrix)
         ├─ lint    shellcheck · actionlint · yamllint · versions.json schema ·
         │          renovate-config-validator · plugin/build/test-packaging.sh ·
         │          tests/plugin/p4-ui (docker php 8.2–8.4)
         ├─ python  pytest tests/perf · tests/plugin · test_client_seam · lab/vm/test_console_driver
         ├─ php     per distinct php_version: engine + hook suites in php:<v>-cli
         └─ build ──► build.yml (smoke-scope latest-per-series)
                        discover  ubuntu: every kernel-<series>*.txz → kernels.json, groups.json
                        kmods     (per ABI) FreeBSD VM: one kernel build dir per config group,
                                  one .ko per build_id → kmods-<slug>/
                        smoke ──► smoke.yml
                                  plan   which build_ids to boot (scope + compat.json cache), shards of ≤5
                                  smoke  (per shard, max-parallel 4) ubuntu KVM: per build_id
                                         install set → nextboot -k → kldload / features / clone / kldunload
                                  merge  compat.json, pass-build-ids-<slug>
                        package   (per ABI) FreeBSD VM: kmod pkg with the passing build_ids,
                                  os-if-pppoe, signed <ABI>/ repo (sign=true only)
nightly.yml: resolve (latest tags; discovery at the latest release's tag; diff build_ids)
             ├─ no new build_id ─► build.yml (main, latest-per-series) ─► report
             └─ new build_id(s) ─► build.yml (ref=v<ver>, <ver>_<N>, sign, untested)
                                   ─► publish.yml (tag v<ver>_<N> at v<ver>'s commit) ─► pages.yml ─► report
release.yml: setup (tag == PLUGIN_VERSION, secrets present) ─► build.yml (sign, untested) ─► publish.yml
pages.yml:   workflow_run(release, success) | workflow_call(nightly) ─► <ABI>/ repos to GitHub Pages
```

An ABI's status is `supported` when any versions.json entry of that ABI is
supported, else `experimental` (`matrix.sh abi`). An experimental ABI has
`continue-on-error: true` on its build and smoke jobs, so it shows red and
still leaves the run green. A PHP version counts as experimental only when
every entry that uses it is experimental. Today `FreeBSD:14:amd64` (25.7
supported, 26.1 experimental) is supported and `FreeBSD:15:amd64` (26.7) is
experimental.

### Artifacts

One set per workflow run (a nightly run builds either the regression or
the refresh, never both). `<slug>` is the ABI with `:` replaced by `-`
(`FreeBSD-14-amd64`, `matrix.sh abi`'s `abi_slug`).

| Artifact | Contents |
|---|---|
| `kernels` | `kernels.json`, `groups.json` (discovery) |
| `kmods-<slug>` | `ko/<bid>/if_pppoe.ko`, `bin/{pppoectl,pppoeparms,spppauth,spppioctl,spppkeepalive}`, `build-info.json` (tags, per-kernel `{bid, group, ko_sha256}`, timings) |
| `smoke-plan` | the plan: `matrix.json`, `abis.json`, `planned.txt`, `kmod-src.txt`, the previous `compat.json` |
| `smoke-<slug>-<shard>` | `compat-part.json`, `set-gone.txt` (when a set was 404/410), serial log, per-kernel dmesg |
| `compat` | merged `compat.json`, `dropped.txt`, `set-gone.txt`, `report.md`, `pass/<slug>/` |
| `pass-build-ids-<slug>` | `pass-build-ids.txt` (what the package ships), `failed-build-ids.txt` |
| `pkg-<slug>` | `pkg/if-pppoe-kmod-<ver>.pkg` (one `.ko` per passing build_id under `/usr/local/lib/if_pppoe/<bid>/`, plus `/usr/local/share/if_pppoe/{build_ids,kernels.json}`), `pkg/os-if-pppoe-<ver>.pkg`, `build-info.json`, `kernels-shipped.json`, `dropped-build-ids.txt`; with `sign=true` also `repo-<slug>.tar.gz` (`<ABI>/` signed catalogue + `client-conf/`) |

### Release assets

`publish.yml` (`release-assets.sh`) attaches:

- `if_pppoe-repo-<slug>.tar.gz` per ABI: `<ABI>/` plus `client-conf/`
  (`IfPppoe.conf` with `url: "<IF_PPPOE_REPO_URL_BASE>/${ABI}"`, fingerprint,
  `IfPppoe.pub`). `client-conf/` is identical for every ABI.
- `<slug>-<pkgname>.pkg` per ABI, and `build-info-<slug>.json`.
- `kernels.json`: every discovered kernel, all ABIs (version <-> build_id).
  This is the nightly refresh's baseline.
- `compat.json`: the smoke cache, the next run's input.
- `coverage.json`: per ABI, the kernels the package covers and the ones it
  dropped (with the smoke result and reason).
- `SHA256SUMS`.

The release notes list the covered kernel versions per ABI and every
dropped build_id. A supported ABI without a signed repo or without a
single passing kernel fails the publish job; an experimental one is left
out with a warning.

## Kernel discovery

`plugin/build/discover-kernels.sh` (called by `.github/scripts/discover-kernels.sh
run` on the ubuntu runner, no VM; also usable locally, `docs/plugin/INSTALL.md`),
for each versions.json entry:

1. Reads the `kernel_sets_url` listing and takes every
   `kernel-<series>(.N)*-amd64.txz`. The prefix match matters: each sets
   directory also lists the **next** series' first kernel (the 25.7 directory
   has `kernel-26.1-amd64.txz`, and the FreeBSD:14 26.1 directory has the
   FreeBSD 15 `kernel-26.7-amd64.txz`; listings fetched 2026-09-28).
2. Downloads each set, cached by sha256 (`--cache`, kept in actions/cache
   under `kernel-sets-v1-<listing key>` with a `kernel-sets-v1-` restore
   prefix).
3. Extracts `boot/kernel/kernel` and reads its ELF build-id (`readelf -n`, or
   `elfdump -n` on FreeBSD), its `FreeBSD X.Y-…` version string (the ABI is
   `FreeBSD:<X>:amd64`, taken from the kernel, not from the directory), and
   its embedded config (the `kern_conf` ELF section that
   `options INCLUDE_CONFIG_FILE` in GENERIC puts there; `config -x` reads the
   same section, `usr.sbin/config/main.cc` `kernconfdump`).
4. Hashes the normalised config: leading `___` stripped, comments, blank
   lines, `ident` and `makeoptions DEBUG*` dropped, whitespace collapsed,
   `LC_ALL=C sort -u`. An empty config is an error, never silently grouped.

Output `kernels.json` is an array sorted by `abi`, `series`, `version`,
deduplicated by `build_id`:

```json
[{"series":"25.7","version":"25.7.8","abi":"FreeBSD:14:amd64","freebsd_version":"14.3",
  "src_tag":"25.7.8","url":"https://pkg.opnsense.org/FreeBSD:14:amd64/25.7/sets/kernel-25.7.8-amd64.txz",
  "sha256":"<64 hex>","build_id":"<40 hex>","config_hash":"<64 hex>"}]
```

`src_tag` equals `version`: opnsense/src is only re-tagged when the kernel
changes, and its tags match the published sets exactly (see "How latest is
resolved"). `--union PREV.json` keeps entries whose set has disappeared from
the mirror, so coverage never silently shrinks.

With per-kernel discovery, a versions.json entry's `opnsense_src_tag` and
`opnsense_core_tag` no longer decide which kernels get a `.ko`. They pick the
toolchain (opnsense/tools config, FreeBSD VM release) and the series'
default/newest kernel; pin drift is informational.

## versions.json

```json
{
  "opnsense_series": "25.7",          // version prefix discovery matches; opnsense/tools config dir; the lowest series of an ABI is plugins.mk PLUGIN_ABIS
  "status": "supported",              // supported | experimental (an ABI is supported if any of its entries is)
  "freebsd_version": "14.3",          // FreeBSD VM release (vmactions) + smoke cloud image (the ABI's newest is used); must equal the kernel's
  "freebsd_abi": "FreeBSD:14:amd64",  // groups entries into one package + one repo <base>/<ABI>/; must equal each discovered kernel's own ABI
  "php_version": "8.3",               // plugin PHP (PLUGIN_PHP=83) + php:<v>-cli test image
  "python_version": "3.11",           // PLUGIN_PYTHON (plain FreeBSD VM cannot probe it)
  "kernconf": "SMP",                  // opnsense/tools config/<series>/<kernconf>
  "opnsense_core_tag": "25.7.11",     // opnsense/core release; also the opnsense/tools tag
  "kernel_sets_url": "https://pkg.opnsense.org/FreeBSD:14:amd64/25.7/sets/", // discovery lists every kernel-<series>*.txz here
  "opnsense_src_tag": "25.7.11",      // newest kernel / toolchain default; kernel-<tag>-amd64.txz in kernel_sets_url
  "require_features": false,          // no longer read: smoke.yml's require-features input (default true) applies to every kernel
  "needs_port": false                 // optional: driver/lab not yet verified on this entry's FreeBSD base (informational; not read by any workflow yet)
}
```

`kernel_sets_url` must come **immediately before** `opnsense_src_tag`,
because one Renovate regex captures both.

Where the current values come from, as looked up when this pipeline was
written (2026-09-27) and re-verified 2026-09-28 (`g ls-remote --tags` against
opnsense/core, opnsense/src and opnsense/tools; the sets listings; and each
tag's `sys/conf/newvers.sh`):

- **25.7:** opnsense/core's last 25.7 tag is `25.7.11`. The kernel set
  listing `FreeBSD:14:amd64/25.7/sets/` has `kernel-25.7.11-amd64.txz` as
  its last 25.7 kernel. The `newvers.sh` for `25.7.11`/`25.7.14` reports
  FreeBSD 14.3. opnsense/src also has tags `25.7.12`, `25.7.13` and
  `25.7.14` (Feb–Mar 2026). They come after 26.1 shipped, no kernel set
  exists for them, and they are most likely Business Edition (25.10.x) src.
  They are deliberately **not** used.
- **26.1:** core `26.1.11`, src `26.1.11`. `26.1.12` and `26.1.13` are
  src-only tags with no kernel set (confirmed against the
  `FreeBSD:14:amd64/26.1/sets/` listing, 2026-09-28). `sys/conf/newvers.sh`
  at `26.1.11` reports `REVISION="14.3" BRANCH="RELEASE-p16"`. The CE 26.1
  release notes (docs.opnsense.org/releases/CE_26.1.html) show `ports: php
  8.3.30` (26.1.1) and `ports: python 3.13.12` (26.1.3) — PHP 8.3.x, Python
  3.13.x, matching this entry.
  - `opnsense/tools@26.1.11` `config/26.1/SMP` is **byte-identical** to
    `opnsense/tools@25.7.11` `config/25.7/SMP`: same `include GENERIC` plus
    the same `options`/`device`/`nodevice` lines (`GEOM_BDE`, `RSS`,
    `TCP_SAD_DETECTION`, the wireless/USB device list, `nodevice agp`, …).
    No SMP config change between 25.7 and 26.1.
- **26.7:** core `26.7.4`, src `26.7.4` (set present in
  `FreeBSD:15:amd64/26.7/sets/`, confirmed 2026-09-28: `kernel-26.7-amd64.txz`
  through `kernel-26.7.4-amd64.txz`, nothing newer). `sys/conf/newvers.sh` at
  `26.7.4` reports `REVISION="15.1" BRANCH="RELEASE-p3"`. The CE 26.7 release
  notes (docs.opnsense.org/releases/CE_26.7.html) show PHP 8.5 (`php
  8.5.10`/`8.5.9`) and Python 3.13 (`python 3.13.15`).
  - **`opnsense/tools@26.7.4` `config/26.7/SMP` differs from 25.7/26.1's**:
    it drops `options GEOM_BDE` and `options TCP_SAD_DETECTION`; everything
    else (RSS, the device/nodevice list) is unchanged. This isn't an
    OPNsense choice — FreeBSD's own `sys/conf/options` at `releng/15.1` no
    longer defines either option (both are still defined at `releng/14.3`),
    so upstream FreeBSD removed them between 14.3 and 15.1 and OPNsense's
    config followed. This is otherwise the same SMP config CI already builds
    against for 25.7/26.1: the `config -d`/`config -x` cross-check in
    "Kernel build dir" below needs no 26.7-specific handling for it, but see
    `needs_port` next.
  - **`needs_port: true`:** the driver itself has not been built or run
    against a FreeBSD 15.1 kernel. "Port the driver to 15.1 KPIs" remains
    open work, this CI has never executed the 26.7 leg ("Nothing
    FreeBSD-side has run" as of 2026-09-27), and a grep of `sys/` for
    `__FreeBSD_version` finds only the one comment in `if_pppoe.c:3585-3587`
    about build-id pinning, not an actual KPI compatibility gate. The field
    is purely informational today: `status: experimental` plus
    `continue-on-error` already keeps a 26.7 build/smoke failure from
    blocking CI, and no script reads `needs_port` yet. Flip it to `false`
    once a 26.7 build/smoke run (or the lab) has actually passed.
  - **Plugin PHP desk-check against 8.5** (2026-09-28, against
    php.net's [migration85.incompatible](https://www.php.net/manual/en/migration85.incompatible.php)
    and [migration85.deprecated](https://www.php.net/manual/en/migration85.deprecated.php)
    pages): a grep of `plugin/net/if-pppoe/src/**/*.php` for every listed
    break/deprecation (the backtick operator, non-canonical `(boolean)`/
    `(integer)`/`(double)`/`(binary)` casts, `array_key_exists()`/`[]` with a
    `null` key, `__sleep`/`__wakeup`, `curl_close`/`finfo_close`/
    `imagedestroy`/`mysqli_execute`, argument-less `readdir`/`rewinddir`/
    `closedir`, `setAccessible`, `$http_response_header`, `class_alias()`,
    `ArrayObject`/`ArrayIterator`) found nothing. The two
    `SimpleXMLElement::xpath()` calls (`hookctl.php:297,305`) query plain
    element paths (`/*/virtualip/vip`, `/*/hasync/<tag>`), which return
    node-sets, so the 8.5 change to non-node-set XPath results doesn't apply
    to them. `$argv` in the CLI scripts (`hookctl.php`, `set-desired.php`) is
    the native CLI argv, not the deprecated `$_SERVER['argc']`/`argv`
    query-string derivation (that deprecation is for non-CLI SAPIs only).
    Nothing found needs a code change. `plugin/net/if-pppoe/tests/hook/run.sh`
    (`hookctl_test.sh` + `syshook_test.sh`) was then actually run in
    `php:8.5-cli` (PHP 8.5.11): 168 + 89 passed, 0 failed — the same as
    8.2/8.3/8.4. `ci.yml`'s `php` job already covers this automatically: its
    matrix comes from `matrix.sh php`, which derives one row per distinct
    `php_version` in `versions.json` (now including `8.5`), so it pulls
    `php:8.5-cli` without any workflow change. `plugin/build/test-packaging.sh`
    and `tests/plugin/p4-ui/run.sh`, by contrast, hardcode `8.2 8.3 8.4` and
    are not versions.json-driven; they weren't extended to 8.5 here (out of
    scope for a desk-check with a minimal diff), but the p4-ui suite is
    plain view/advice-string logic, not PHP-version-sensitive per the check
    above.

### Adding a version

1. Add an entry with `status: experimental`. Fill it from the sets listing
   (`https://pkg.opnsense.org/FreeBSD:<major>:amd64/<series>/sets/`), the
   core tags, and the CE release notes for the PHP and Python versions.
   For a new FreeBSD major, `lab/syntax/kmod-syntax.sh <opnsense/src>/sys
   docker` shows header (KPI) breakage without a VM; that is how the 26.7
   (FreeBSD 15.1) entry's one break, `struct ifnet` no longer reaching
   `if_spppsubr.c` through `net/if_var.h`, was found.
2. Open a PR. CI builds and smokes the new entry's newest kernel, and a
   failure there never blocks the PR as long as its ABI is experimental. A
   new series of an existing, supported ABI (e.g. a 26.1 successor on
   FreeBSD 14) joins that ABI's package and repo, so its kernels gate like
   the others.
3. Once the driver builds and smokes cleanly on that series, change the
   entry to `supported`. From then on it gates PRs, and its ABI's repo is
   required in releases.
4. Remove an entry when the series is no longer supported. Its kernels then
   drop out of discovery and so out of the next release's package.

nightly.yml opens a "New OPNsense series available" issue when opnsense/core
has an `X.Y` tag newer than every entry. Renovate never proposes cross-series
bumps: major and minor updates are disabled for the OPNsense pins.

### How "latest" is resolved (nightly)

`resolve-latest.sh`, applied to each entry:

- **core:** the newest opnsense/core tag matching `^<series>(\.N)?$`. This
  skips `.a`, `.b` and `.r*` pre-release tags.
- **src:** the newest opnsense/src tag that is `<=` core and whose
  `kernel-<tag>-amd64.txz` exists under `kernel_sets_url`. opnsense/src is
  only re-tagged when the kernel changes: 25.7 has src tags `25.7`, `.2`,
  `.3`, `.5`, `.8`, `.10`, `.11`, which exactly match the published sets.
  The kernel-set check also excludes the Business Edition src tags.

The run summary lists every entry whose pins lag behind latest. That drift is
what Renovate should turn into a PR. It is no longer a coverage gap: a new
kernel of a known series is covered by discovery and the nightly kernel
refresh (see "Releases") whether or not the pin has moved; the pins only
choose the toolchain and the default kernel.

## Kernel build dir: config(8) plus the published kernel, not buildkernel

The lab runs a full `make buildkernel` (`lab/vm/build-kernel.sh`, which
estimates 30–90 minutes). CI avoids that. `build-all.sh --kernels-json`
(code shared with a local build in `plugin/build/lib/kbuild.sh`) groups the
kernels of one ABI by `config_hash`; kernels of a group share one kernel build
dir. Per group:

1. A blobless, depth-1, sparse clone of `opnsense/src@<src_tag>` of the
   group's newest member, with only `sys/` checked out.
2. `config/<series>/<kernconf>` fetched from `opnsense/tools@<src_tag>`
   (the tag the kernel set was built from, and the same tag
   `lab/vm/build-kernel.sh` uses; `<core_tag>` is only a fallback when tools
   has no such tag), with the `%%DEBUG%%` line stripped the same way the lab
   does. Then `config -d $KBD <kernconf>`. config(8) writes every
   `opt_*.h`. The kmod consumes those through `KERNBUILDDIR`: FreeBSD's
   `sys/conf/kmod.mk` adds `-include ${KERNBUILDDIR}/opt_global.h` and
   symlinks each `opt_*.h` in `SRCS` from `KERNBUILDDIR`. The module never
   links against kernel objects, so nothing has to be compiled. The script
   asserts that `opt_{global,inet,inet6,rss}.h` exist and that
   `opt_rss.h` defines `RSS` (the SMP config sets `options RSS`).
3. The member's own published `boot/kernel/kernel` is placed at
   `$KBD/kernel` (a per-build_id overlay dir). This is the kernel users
   actually run, so its ELF build-id is their `kern.build_id`.
   `plugin/kmod/if-pppoe-kmod` `stage-one` checks `BUILD_ID` against
   `${KERNBUILDDIR}/kernel`, and the boot hook keys the `.ko` directory on
   it. A locally built kernel would not match any user's kernel.
4. Cross-check, per member: `config -d` on the member's own embedded config
   must produce `opt_*.h` byte-identical to the group's from step 2. This is
   what catches a module silently built against the wrong options.
5. Header drift: `g diff --quiet <tagA> <tagB> -- <headers in the group's
   .depend>` between member src tags. If any header the module includes
   differs, the group is split by src tag. This measures the assumption that
   patch releases with the same config share headers, instead of trusting it.
6. The module is compiled once per group (stage-one on the representative
   build_id); the other members' build_ids get the same `.ko` through
   `stage-prebuilt`, after the checks above.

Not yet run on FreeBSD: check the first CI log for the "opt_*.h match" lines,
and compare a Linux and a FreeBSD extraction of one kernel's `kern_conf`
(whether it carries a `___` prefix or has `include GENERIC` expanded is not
verified; the normalisation handles both).

The lab's `SMPW` debug kernel is not built in CI (it needs a real
buildkernel with the lab's INVARIANTS patch); a `.ko` for SMPW must still
come from `lab/vm/build-module.sh`.

The prepared `src/` and kernel build dirs are cached with actions/cache per
ABI and group. The module builds with `WERROR=-Werror` (`kmod.mk` defaults to
`WERROR?=-Werror`, and CI makes it explicit). Userland builds with each
Makefile's `WARNS`. `bsd.sys.mk` adds `-Werror` when `WARNS >= 1` unless
`MK_WERROR=no`.

### Packages

The package phase (`build-all.sh --phase package`, per ABI) stages only the
build_ids in `pass-build-ids.txt`, ships `kernels.json` filtered to them at
`/usr/local/share/if_pppoe/kernels.json` next to `build_ids`, and builds
`os-if-pppoe` once for the whole ABI (its `PLUGIN_ABIS` is the ABI's series
list, lowest first). A `KMOD_VERSION` of `<ver>_<N>` gives both packages the
same `_N` (`PLUGIN_REVISION`). Then it runs a resolve check: in a private pkg
database, repo conf dir and root, `os-if-pppoe` from the freshly built repo
must resolve to exactly `if-pppoe-kmod-<KMOD_VERSION>`, so a refresh really
upgrades the kmod along with the plugin (whether pkg enforces a dependency's
version on its own is not verified).

## FreeBSD VM action: vmactions/freebsd-vm (v1.5.8)

This was compared against cross-platform-actions/action (v1.6.0). Both list
FreeBSD 14.3 and 15.1 on x86-64. vmactions/freebsd-vm was chosen for these
reasons:

- `release:` takes the FreeBSD version directly, so the VM matches
  `freebsd_version`. The build uses the host's `config(8)`, `/usr/share/mk`
  and toolchain, so the VM must match the target release.
- The workflow is a single step: `envs:` forwards named env vars (including
  the signing key on release), `prepare:` installs `git-lite`, and `run:`
  runs `freebsd-build.sh`. With `sync: rsync` and `copyback: true`, the
  workspace comes back with `out/` and the fresh `.ci-cache/` tarball, and
  actions/cache saves it in its post step.
- cross-platform-actions v1 deprecates `run:` in favour of `shell: cpa.sh {0}`
  steps. That is also workable. Its README (as read on 2026-09-27) documents
  no counterpart to vmactions' `cache-after-prepare`, which could be turned
  on later to skip the `pkg install` step.

## Smoke test (ubuntu KVM runner, per kernel)

`smoke.yml`'s `plan` job (`smoke-plan.sh`) picks the build_ids to boot:

| `smoke-scope` | Used by | Kernels |
|---|---|---|
| `latest-per-series` | ci.yml (PRs, `main`), nightly regression | the newest kernel of each series, always booted |
| `untested` | release.yml, nightly refresh | every build_id with no cached result for this code (`kmod_src`) |
| `all` | manual | every discovered build_id |

**The cache is `compat.json`** (a release asset; `smoke.yml` downloads it from
the latest release, and a missing one means nothing is cached). Each result
is keyed by `(build_id, kmod_src)`, where `kmod_src` is the sha256 of
`g ls-tree -r HEAD -- sys sbin/pppoectl plugin/kmod plugin/build
.github/scripts/freebsd-build.sh .github/versions.json` (`compat.sh
kmod-src`). The last three decide the kernel build dir, and so the
`opt_*.h`, each `.ko` is compiled against (`plugin/build/lib/kbuild.sh`,
`build-all.sh`), so a change there cannot reuse a pass earned by a
differently built `.ko`. A kernel-only refresh from the same tag hits the
cache for every old kernel and boots only the new ones; any driver,
packaging, build-dir or versions.json change (including a Renovate pin
bump) re-smokes everything. A cached fail stays failed until `kmod_src` changes.
Merging appends; the newest result per key wins.

```json
{"schema":1,"results":[
  {"build_id":"…","kmod_src":"<sha256>","version":"25.7.8","abi":"FreeBSD:14:amd64",
   "result":"pass|fail","detail":"kldload|clone|panic|…","ko_sha256":"…","run":"<run url>","at":"<iso8601>"}]}
```

The kernels to boot are split into shards of at most 5 per ABI, at most 4
shards at a time. Each shard (`smoke-vm.sh`):

1. Enables `/dev/kvm` with the `99-kvm4all.rules` udev rule from GitHub's
   2024-04-02 changelog, which covers hardware-accelerated virtualization on
   standard Linux runners. If `/dev/kvm` is still not writable, it falls back
   to TCG and prints a warning.
2. Downloads `FreeBSD-<ver>-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz` (the
   ABI's newest FreeBSD version), checks it against `CHECKSUM.SHA256`, and
   caches the `.xz`. It seeds cloud-init with an ssh key through a cidata
   ISO, in the same format as `lab/vm/run.sh`, and boots once, pushing the
   shard's kernel sets and `ko/<bid>/` modules. QEMU runs with a monitor
   socket. Each kernel is staged on its own (set fetched and checked
   against the `sha256` in `kernels.json`, `.ko` present): one that cannot
   be staged is left out and the rest of the shard still runs. A network
   or checksum failure, or a missing `.ko`, leaves that kernel without a
   result. A set the mirror answers 404/410 for (a kernel discovery's
   `--union` kept after the mirror dropped it) goes into `set-gone.txt`.
3. Per build_id (`smoke-vm.sh cycle <bid>`): installs that **official
   OPNsense kernel set** as `/boot/kernel.<bid>` (removing the previous one),
   runs `nextboot -k kernel.<bid>`, reboots, and asserts that
   `kern.build_id` equals `<bid>`. Then `smoke-guest.sh module`: `kldload`
   of that build_id's `.ko`, `kldstat`, the `kern.features.if_pppoe_*` list
   (required: the boot hook refuses a module without them), `ifconfig
   pppoe0 create`, `pppoectl pppoe0` (SPPP ioctl ABI), the ctl contract,
   destroy, `kldunload`. The result goes into `compat-part.json`.
4. A kernel that panics or hangs (ssh timeout) is hard-reset through the QEMU
   monitor. nextboot(8) is one-shot ("once the loader loads in the new
   kernel information from the /boot/nextboot.conf file, it is disabled"), so
   the guest comes back on GENERIC; the kernel is recorded as `fail/panic`
   and the shard continues.
5. `smoke-guest.sh dial` (continue-on-error) on the shard's newest kernel:
   installs mpd5 from pkg, starts a PPPoE server in a VNET jail on one end of
   an epair, sets up a PAP dial from `pppoe0` on the other end, waits for an
   IPCP address, and pings the peer. The PAP secret is generated per run;
   mpd5's `mpd.secret` lives on a tmpfs mounted over `/tmp/ci/mpd` (unmounted
   at exit) and `pppoectl -S` reads the secret from stdin, so it never
   reaches argv or the disk.

The `merge` job writes `compat.json` and, per ABI, `pass-build-ids.txt`
(what the package may ship) and `failed-build-ids.txt`. **A failed build_id
is dropped from the package's `build_ids`**, so on that kernel the boot hook
reports `kernel-not-supported` and the box stays on mpd5. It is reported in
the run summary, the release notes and `coverage.json`. The merge fails the
run (nothing is packaged) when a supported ABI has no passing kernel, when a
planned kernel of a supported ABI has no result at all (smoke
infrastructure), or, in `latest-per-series` scope, when any supported kernel
fails (on a PR that is the change under review breaking it). A planned
kernel whose set is gone from the mirror is dropped with reason `set-gone`
and a warning, never an error: its `.ko` is untested for this `kmod_src`, so
it is not shipped, and failing on it would block every later release. A
kernel that already has a cached pass for this `kmod_src` is not planned,
so it keeps that pass whether or not its set is still published.

Neither the per-kernel cycle nor the dial step has run yet: nothing here
could execute a FreeBSD guest. The dial stays best-effort until it has been
observed passing.

## Lint tiers

`lint-shell.sh` fails on any shellcheck finding under `.github/scripts/`.
Everywhere else it fails only on error-severity findings. Warnings in the
existing lab and plugin scripts are printed as `advisory:` lines. As
measured on the merged tree, lab/vm/common.sh has 22 warnings and a handful
of other files have 1–2 each. Move a directory into `STRICT_DIRS` once it is
clean. `docs/` is skipped because it holds verbatim reference snippets.

## Secrets and variables

| Name | Kind | Used by | Purpose |
|---|---|---|---|
| `IF_PPPOE_REPO_SIGNING_KEY` | secret | release.yml, nightly.yml (refresh) | PEM RSA private key used by `plugin/build/make-repo.sh` (`signing_command`). Generate it once with `make-repo.sh --gen-key --key repo.key` and paste `repo.key` into the secret. The public key is derived from it in CI and shipped in `client-conf/IfPppoe.pub` along with the fingerprint |
| `IF_PPPOE_REPO_URL_BASE` | variable | release.yml, nightly.yml (refresh) | Base URL where repos are served, e.g. `https://<host>/if_pppoe/repo`, without `${ABI}`. The client URL becomes `<base>/${ABI}` (no series segment) |
| `RENOVATE_TOKEN` | secret | renovate.yml | Only for self-hosted Renovate. Use a fine-grained PAT or GitHub App token with contents, pull-requests, issues and workflows write access. PRs opened with `GITHUB_TOKEN` do not trigger `ci.yml` |
| `ENABLE_PAGES` | variable | pages.yml | Set to `true` to publish release repos to GitHub Pages. Then set `IF_PPPOE_REPO_URL_BASE=https://nashant.github.io/if_pppoe` |
| `RENOVATE_SELF_HOSTED` | variable | renovate.yml | Set to `true` to enable the self-hosted job |

The signing key exists only as this Actions secret. It reaches exactly one
place: build.yml's per-ABI `package` job, which runs only when `sign=true`.
That job writes it to `.ci-secrets/repo.key` (mode 0600) in the workspace
that rsync copies into the VM, because vmactions' `envs` forwarding was not
verified to keep a multi-line PEM intact. `freebsd-build.sh` copies it into a
`mktemp -d` directory and deletes the original, and an `always()` step
removes `.ci-secrets/` on the runner afterwards. The key is never placed
under `out/`, never cached, never an artifact, and never in `compat.json`,
`kernels.json` or a log; the discover, kmods and smoke jobs never see it.

`GITHUB_TOKEN` permissions default to `contents: read` in every workflow.
Only nightly `report` (`issues: write`), the `publish.yml` job
(`contents: write`, from release.yml and from nightly's `refresh-publish`)
and pages `deploy` (`pages: write`, `id-token: write`) get more.
Checkouts use `persist-credentials: false`.
Every action is pinned by commit SHA with a version comment, and Renovate's
`helpers:pinGitHubActionDigests` keeps them updated.

## Releases

### Code release

Push tag `v<ver>`. release.yml fails early when the tag
does not equal `v<PLUGIN_VERSION>` from `plugin/net/if-pppoe/Makefile`, when
it has a `_N` suffix (those are nightly's), or when the key or URL base is
unset. Then:

- `build.yml` with the `matrix.sh abi supported,experimental` matrix,
  `kmod-version=<ver>`, `plugin-revision=0`, `sign=true` and
  `smoke-scope: untested`: every discovered kernel gets a `.ko`, and every
  build_id without a cached result for this code is booted.
- `publish.yml` creates the Release for the pushed tag with the assets
  above.

The package versions are `if-pppoe-kmod-<ver>` and `os-if-pppoe-<ver>`.

### Nightly refresh

When OPNsense publishes a new kernel
patch, its build_id is not in any `.ko` yet, and boxes that install it fall
back to mpd5 at the next boot. nightly.yml closes that gap without a code
change:

1. `resolve` finds the latest release (`gh release list`), its code release
   `v<ver>` (the tag without `_N`) and that tag's commit, and downloads the
   release's `kernels.json`. It checks out `v<ver>` and runs discovery from
   that tree (its versions.json and discovery code), with `--union` over the
   release's `kernels.json`.
2. New build_ids = discovered minus the release's `kernels.json`
   (`refresh-plan.sh new-build-ids`). None: the regression build runs as
   before. Some: a refresh.
3. `N` = 1 + the largest `_N` over the **git tags** `v<ver>_*` and the
   release tags (`refresh-plan.sh next-revision`), so a number is never
   reused, even after a release was deleted.
4. `build.yml` with `ref=v<ver>`, `kmod-version=<ver>_<N>`,
   `plugin-revision=<N>`, `sign=true`, `smoke-scope: untested`. The code is
   the release's, so `kmod_src` is too: every old kernel hits the
   `compat.json` cache and only the new build_ids boot. The workflow files
   come from `main` while the scripts come from `v<ver>`, so a change to
   build.yml's contract with its scripts (`freebsd-build.sh --phase`,
   `discover-kernels.sh`, `smoke-*.sh`) must keep working against the
   latest release tag, or the next refresh fails (and says so in the
   issue) until a new code release is tagged.
5. `publish.yml` with tag `v<ver>_<N>` created at `v<ver>`'s commit
   (`release-assets.sh` with `REQUIRE_BUILD_IDS` = the new build_ids). A new
   build_id that failed smoke is dropped exactly as in a code release: no
   `.ko` for it in the package, its fail result in the published
   `compat.json` (so no later run retries it until `kmod_src` changes), the
   kernel still in `kernels.json` (so the next nightly does not see it as
   new), and a "New kernels dropped by this refresh" section in the notes.
   The refresh publishes when at least one new build_id is covered, or when
   none is but they were all smoked (the release then records the failures).
   It publishes nothing only when a new build_id of a supported ABI has no
   smoke result at all (smoke infrastructure; smoke.yml's merge gate
   normally fails the run first) or when no new build_id was covered or
   smoked; the next night then tries again. An experimental ABI's new
   build_id with no result never blocks. Either way the `report` job opens
   or updates the `nightly-failure` issue: with the dropped kernels when it
   published, with the failure when it did not.
   Before `gh release create`, publish re-reads the latest release: if it is
   no longer a `v<ver>` release (a code release `v<newer>` finished while
   the refresh was building), the refresh is skipped (`published=false`, no
   Release, no Pages), so the newer code stays latest and the next nightly
   refreshes that release instead. The publish job runs in the
   `repo-publish` concurrency group (`queue: max`, so no waiting publish is
   cancelled), shared by release.yml and nightly.yml, so the check and the
   create cannot interleave with another publish.
6. `pages.yml` (workflow_call) republishes the site, only when step 5
   published.

Both packages move to `<ver>_<N>` together: `PORTREVISION`-style, which
pkg treats as an upgrade (Porter's Handbook, makefiles chapter:
`gtkmumble-0.10_1` is newer than `gtkmumble-0.10`, and "changes to
PORTREVISION are used by … pkg-version(8) to determine that a new package is
available"). No code-change review is needed for a refresh: the source is
the reviewed tag. Code changes still go through a normal `v<ver>` release.

The calls are explicit (`workflow_call`) because a Release or tag created
with `GITHUB_TOKEN` does not start other workflows. The refresh jobs need
the signing key and URL base; if new kernels exist and either is missing,
`resolve` fails and the issue says so. `workflow_dispatch` has a `refresh`
input to run the check without publishing.

## GitHub Pages

`pages.yml` runs on `workflow_run` of `release` (conclusion success), on
`release: published` (a Release a human publishes), on `workflow_call` from
nightly's refresh, and on `workflow_dispatch` (optional `tag`, default
latest). `pages-site.sh` downloads every `if_pppoe-repo-<slug>.tar.gz` asset
plus `kernels.json`, `compat.json` and `coverage.json`, and builds:

```
<ABI>/          one signed catalogue per FreeBSD ABI (FreeBSD:14:amd64/, FreeBSD:15:amd64/)
client-conf/    one set for all ABIs (IfPppoe.conf url <base>/${ABI}, fingerprint, IfPppoe.pub)
kernels.json  compat.json  coverage.json
index.html      the ABIs and the kernel versions each covers
```

It fails if two tarballs carry different `client-conf/` (key or URL
mismatch) or the same ABI. The site only ever holds the latest published
release. The `workflow_run` path is needed because release.yml creates the
Release with `GITHUB_TOKEN`, and events created with `GITHUB_TOKEN` do not
start other workflows; it also runs on the default branch, which the
`github-pages` environment's branch rules have to allow, as they must for
nightly's scheduled run on `main` (not checked against a real repo yet).
GitHub serves the `:` in `FreeBSD:14:amd64` paths as-is; this has not been
tried against a real Pages site yet.

There is no migration from the earlier `<ABI>/<series>/` layout: no public
release was ever made with it.

## Renovate

Renovate either runs as the GitHub App (recommended; nothing to configure
beyond installing it) or through `renovate.yml`.

- `opnsense/core` tags come from the `github-tags` datasource, filtered to
  `^X.Y(.Z)?$`.
- `opnsense-kernel` is a custom `html` datasource over `kernel_sets_url`,
  extracting `kernel-<v>-amd64.txz`. The src pin therefore only moves to a
  kernel that has actually been published.
- Both are limited to patch updates within their series and grouped into one
  "OPNsense pins" PR. The CI on that PR builds and smokes the new pins, and
  nightly has usually already reported whether they break.
- Python test pins (`tests/requirements-dev.txt`, `tests/plugin/requirements.txt`)
  are grouped into one "python test deps" PR.
- New *series* (e.g. 27.1) are not Renovate's job: a regex manager can only
  bump a value that already exists. nightly.yml opens an issue when a
  released `X.Y` core tag newer than every entry appears; add the entry by
  hand (see "Adding a version").
- Action SHAs are handled by the github-actions manager. `ACTIONLINT_VERSION`,
  `RENOVATE_VERSION` and `YAMLLINT_VERSION` in ci.yml are updated through
  their `# renovate:` comments.

## Runtimes and cost (estimates, not measured)

No run has happened yet. These numbers are estimates for 2-vCPU
`ubuntu-24.04` hosted runners. The real figures will show up in
`build-info.json` `timings_s` and in the job durations. The kernel counts are
from the sets listings (2026-09-28): 7 kernels for 25.7, 8 for 26.1 and 4 for
26.7, so about 19 build_ids.

| Job | Estimate |
|---|---|
| lint | 3–5 min, most of it the renovate npx install |
| python / php (each) | 1–2 min |
| discover | 1–2 min warm cache; cold, about 19 set downloads (set sizes not measured) |
| kmods, per ABI | 8–15 min: VM boot plus `pkg install` about 2–3, a sparse `sys/` clone and `config` per config group, one module build per group, userland 1–2 |
| smoke, per shard | about 1–2 min per kernel reboot cycle, ≤5 kernels, plus image and first boot |
| package, per ABI | 3–5 min |
| **ci.yml** (newest kernel per series: 3 kernels) | about 15–25 min wall clock |
| **release** (every untested build_id, ≤4 shards in parallel) | about 30–45 min wall clock on a cold cache |
| **nightly refresh** (only the new build_ids) | about 20–30 min |

A full `buildkernel` per kernel would add an estimated 40–90 min each, which
is why this pipeline avoids it. Public repos get hosted-runner minutes for
free. For a private repo, check GitHub's current Linux per-minute rate (I
haven't checked the current price). Cache use: the kernel-set cache is about
19 sets (an estimated 50 MB each, not measured, so about 1 GB), plus the
kernel build dirs and about 0.5–1 GB per FreeBSD image `.xz`, within the
default 10 GB repo cache; old keys are evicted.

## What CI does not cover (still lab-only)

`tests/functional` needs the QEMU lab on the lab VM host (`lab/vm/README.md`,
`make -C lab test-func`, about 12 min per run according to
`docs/TESTING.md`). CI does not cover any of the following:

- The full functional suites: discovery, LCP/IPCP/IPv6CP, PAP/CHAP live,
  reconnect, lifecycle, datapath, wire-safety, fuzz, soak, hardening probes.
  These run against accel-ppp and mpd5 servers on separate VMs over a real
  lab bridge network, sniffed with scapy.
- The SMPW (WITNESS/INVARIANTS) debug kernel. There is no published kernel
  set for it, so CI only builds against the release `SMP` config.
- Throughput and perf runs (`tests/perf` collectors and `run_matrix.py`).
  Only their parsers are unit-tested in CI.
- The plugin on a real OPNsense install (`tests/plugin/test_roundtrip.py`,
  which needs `IFPPPOE_DUT_*`), plus firmware-update and reboot flows
  (including an OPNsense kernel update followed by a refresh), and hardware
  NICs and VLAN tagging on the router under test.
- The smoke guest is FreeBSD userland with an OPNsense kernel, not an
  OPNsense install: it proves the `.ko` loads and clones on each exact
  kernel, not the plugin's boot hook on a real box.
- Kernel sets are trusted on first use (their sha256 is recorded, the `.sig`
  next to each set is not yet verified against OPNsense's fingerprints).

## Reproducing locally

```sh
sh .github/scripts/matrix.sh build supported      # the matrix CI will run
GH_TOKEN=$(gh auth token) sh .github/scripts/resolve-latest.sh /tmp/latest.json
sh .github/scripts/lint-shell.sh
actionlint -ignore 'unexpected key "queue" for "concurrency" section' && yamllint -s .github/
npx --yes --package renovate -- renovate-config-validator --strict
docker run --rm -v "$PWD:/r:ro" -w /r php:8.3-cli sh plugin/net/if-pppoe/tests/engine/run.sh
```

`freebsd-build.sh` runs in any FreeBSD VM of the right release, for example
the lab `build` VM. Export the fields of one versions.json entry in
upper-case (`OPNSENSE_SERIES=25.7 …`) and run it from the repo root.

