# Installing if-pppoe

## Which repo, which kernels

Published repos are **one per FreeBSD ABI**, not one per OPNsense series:

| OPNsense series | FreeBSD ABI | Repo path |
|---|---|---|
| 25.7, 26.1 | `FreeBSD:14:amd64` | `<base>/FreeBSD:14:amd64/` |
| 26.7 | `FreeBSD:15:amd64` | `<base>/FreeBSD:15:amd64/` |

The box registers `url: "<base>/${ABI}"` once. pkg expands `${ABI}` itself
(pkg.conf(5), freebsd/pkg `docs/pkg.conf.5`: "ABI: Expands to the ABI string
(e.g. FreeBSD:14:amd64)"; FreeBSD's own `usr.sbin/pkg/FreeBSD.conf.latest`
uses `pkg+https://pkg.FreeBSD.org/${ABI}/latest` the same way). So:

- **25.7 -> 26.1:** same ABI, same repo, same packages. Nothing to change.
- **26.1 -> 26.7:** the ABI switches to `FreeBSD:15:amd64`, and pkg follows it
  to the other repo by itself. A URL without a series segment also avoids
  the failure in https://github.com/opnsense/core/issues/10622, where the
  ABI was already `FreeBSD:15:amd64` while the release still said 26.1.

`os-if-pppoe` is the same package for every series of an ABI. What gates a
series is the plugin's `interfaces.inc` hook: `hookctl.php` refuses with
`refused:anchor` when the anchors don't match. The anchors are
fixture-tested for 25.7, 25.7.11, 26.1, 26.1.11 and 26.7.4
(`plugin/net/if-pppoe/tests/hook/hookctl_test.sh`).

**Supported kernels.** `if-pppoe-kmod` holds one `if_pppoe.ko` per OPNsense
kernel build (`kern.build_id`) of its ABI. That is every
`kernel-<version>-amd64.txz` published in the series' sets directory that
built and passed the CI smoke test. The list ships in the package as
`/usr/local/share/if_pppoe/kernels.json` (version <-> build_id), next to
`build_ids`. Services -> Kernel PPPoE shows it as "Supported kernels", and
says whether the running kernel and the installed kernel are covered. The
release notes, the `coverage.json` asset and the Pages index list the same
kernels. They also name any kernel that was dropped because its smoke test
failed.

**After an OPNsense kernel update.** A new OPNsense kernel patch has a new
build_id, which the installed `if-pppoe-kmod` does not cover until the
nightly refresh publishes `if-pppoe-kmod-<ver>_<N>`. That takes up to a day
after the kernel appears on pkg.opnsense.org, plus build time (an estimate:
nightly runs once a day). Until then:

- Before the reboot, Services -> Kernel PPPoE warns that the installed
  (pending reboot) kernel is not covered.
- After the reboot, the boot hook finds no `.ko` for the running build_id,
  reports `kernel-not-supported` and leaves every WAN on stock mpd5. PPPoE
  keeps working, just without the kernel driver.
- Once the refresh is published, System -> Firmware -> Updates offers it
  (pkg treats `<ver>_<N>` as newer than `<ver>`), and the next reboot uses
  the kernel driver again.

A kernel that fails the CI smoke test is left out of `build_ids` on purpose,
so boxes on that kernel stay on mpd5 instead of loading an untested module.
The refresh still publishes for the kernels that passed; the failed kernel
is named in the release notes ("New kernels dropped by this refresh") and is
not retried until the module source changes (`docs/CI.md#nightly-refresh`).

## 1. BUILD: produce the packages

CI builds and publishes the packages (`docs/CI.md`). This section is for a
local or lab build. `plugin/build/build-all.sh` builds if-pppoe-kmod (one
package, one `.ko` per kernel build-id) and os-if-pppoe, and optionally signs
a repo, in one command. It runs ON the FreeBSD `build` VM (or any FreeBSD
host with `pkg`/`bmake`/`config`), as non-root. CI runs the same script
(`.github/scripts/freebsd-build.sh` calls it), so CI and a local build share
one code path.

### Every published kernel of an ABI (`--kernels-json`)

```
plugin/build/discover-kernels.sh --versions .github/versions.json \
    --out kernels.json --cache /home/freebsd/kernel-sets
plugin/build/build-all.sh --kernels-json kernels.json --abi FreeBSD:14:amd64 \
    --version 0.4 --out /home/freebsd/out \
    --key /home/freebsd/.if_pppoe-repo-signing.key
```

`discover-kernels.sh` reads each series' `kernel_sets_url` listing,
downloads every `kernel-<series>*-amd64.txz` (cached by sha256), and records
its build-id, its FreeBSD ABI and a hash of its embedded kernel config.
`build-all.sh` then takes the kernels of `--abi` and groups them by config
hash. For each group it prepares one kernel build dir from that kernel's own
`opnsense/src` tag with `config(8)` (no `buildkernel`), checks each member's
`opt_*.h` against the group's, and stages one `.ko` per build-id.
`--pass-build-ids FILE` limits the package to those build-ids (CI passes the
ones that passed smoke). `--plugin-revision N` builds the `_N` package
revision that a kernel-only refresh uses.

### Lab kernels (`--target-kernel`)

**Prerequisite:** a lab-collected SMP kernel and src tree at `$LAB_HOME`
(default `$HOME/if_pppoe-lab`) -- `lab/vm/build-kernel.sh setup/start/collect`
produces `kernel/SMP/{kernel,KERNBUILDDIR}` and `src/sys`. `build-all.sh`
overlays each `--target-kernel` onto that SMP KERNBUILDDIR (symlinking
everything except the `kernel` file itself, which becomes the target's own)
and fails loudly if the target's embedded kernel config differs from the
lab SMP kernel's by anything beyond `makeoptions DEBUG`, or if either
config can't be extracted at all -- so `--target-kernel` must be a kernel
of the *same* options (e.g. an OPNsense box's running `/boot/kernel/kernel`,
or a published kernel-set `.txz` of the same series), not an arbitrary one.
If a target kernel's own `config -x` can't extract an embedded config
(stripped kernel, no `INCLUDE_CONFIG_FILE`), pass `--target-conftxt FILE`
right after its `--target-kernel` -- e.g. that box's own
`sysctl -n kern.conftxt`, which is what this process actually compared the
first time it was done by hand. `--skip-config-check` bypasses the check entirely; only
use it when neither is possible. See the script's own header comment for
the full contract.

```
plugin/build/build-all.sh \
    --target-kernel /home/freebsd/router-kernel \
    --version 0.3 \
    --out /home/freebsd/out \
    --key /home/freebsd/.if_pppoe-repo-signing.key
```

Repeat `--target-kernel` for every kernel build the package must cover (one
`if-pppoe-kmod` package, one `.ko` per build-id). Omit `--key`/`--pub` for
an unsigned repo (lab iteration only -- see step 4 below for what a real
install needs); `--pub` defaults the way `make-repo.sh` itself does when
omitted. A `--key` that doesn't exist yet is an error unless `--gen-key` is
also given, which generates a fresh keypair there. Either mode writes
`$OUT/pkg/*.pkg` and `$OUT/repo.tar.gz` (a flat catalogue).

**From your own machine** (not the build VM), `lab/vm/pkg-build.sh` wraps
the above: it syncs this tree to the build VM's own work dir (as
`lab/vm/build-check.sh` does), runs `build-all.sh` there, and fetches the
result back:

```
lab/vm/pkg-build.sh -- --target-kernel /home/freebsd/router-kernel --version 0.3 \
    --key /home/freebsd/.if_pppoe-repo-signing.key
```

(`--key`/`--pub` there name paths already on the build VM -- they must be
absolute paths there, e.g. under `/home/freebsd` (`VM_SSH_USER` in
`lab/vm/common.sh`), not a `~` this LOCAL shell would expand against the
wrong home before forwarding it; the key is never uploaded or downloaded
by this wrapper.) Output lands in `./pkg-build-out/`, relative to wherever
you run `pkg-build.sh` from (`--local-out` to change that).

**Publishing** what either of those produced, under the ABI it was built for:

```
plugin/build/publish-repo.sh --repo-dir <extracted repo.tar.gz dir, or the build VM's --out dir> \
    --remote-dir /usr/local/www/if_pppoe/repo --abi FreeBSD:14:amd64
```

`make-repo.sh`'s catalogue is flat, so `publish-repo.sh` puts it under
`<remote-dir>/<ABI>`. `--abi` is required, because the packages are
ABI-specific and there is no safe default. Use `--no-abi-subdir` only if
`--remote-dir` already ends in the ABI segment. Publish one catalogue per
ABI; 25.7 and 26.1 boxes share the `FreeBSD:14:amd64` one.

`gen-repo-conf.sh --pub` below runs on YOUR machine, but with `pkg-build.sh`
the signing keypair (`--key`/`--pub`, or `--gen-key`'s freshly generated
one) lives only on the build VM -- `pkg-build.sh` never uploads or
downloads key material (its own header), and the fetched `--local-out`
has no `.pub`. Fetch the public half back first (it's public, unlike the
`.key`):

```
scp <VM_SSH_USER>@<build VM>:/home/freebsd/.if_pppoe-repo-signing.pub ~/.if_pppoe-repo-signing.pub
plugin/build/gen-repo-conf.sh --url 'http://<LAB_HOST>/if_pppoe/repo/${ABI}' \
    --pub ~/.if_pppoe-repo-signing.pub --out-dir ./client-conf
```

`${ABI}` in the URL is pkg's own client-side substitution (the box's ABI
string, e.g. `FreeBSD:14:amd64`); the single quotes keep this shell from
expanding it. Never append a series (`.../${ABI}/25.7`): `gen-repo-conf.sh`
warns about that, because such a URL stops resolving after a series
upgrade. For a CI release, `client-conf/` is already inside every
`if_pppoe-repo-<ABI>.tar.gz` release asset and on the Pages site, with
`url: "<IF_PPPOE_REPO_URL_BASE>/${ABI}"`.

`gen-repo-conf.sh` produces, under `./client-conf/`:

- `repos/IfPppoe.conf`
- `fingerprints/IfPppoe/trusted/IfPppoe`

Copy both to the box (scp, or paste their contents) before step 2.

## 2. One-time registration, on the OPNsense box

```
mkdir -p /usr/local/etc/pkg/repos /usr/local/etc/pkg/fingerprints/IfPppoe/trusted
cp IfPppoe.conf /usr/local/etc/pkg/repos/IfPppoe.conf
cp IfPppoe        /usr/local/etc/pkg/fingerprints/IfPppoe/trusted/IfPppoe
pkg update
```

(`pkg.conf(5)`: repo `.conf` files are read from `/usr/local/etc/pkg/repos/`;
a `FINGERPRINTS`-signed repo's fingerprint files live under
`fingerprints/<tag>/trusted/`. Cloned pkg source, `docs/pkg.conf.5`, commit
`cd0a561ecc894f3c9811004490d59a5df26c94ad`, this session.)

The same two files work on every series and survive series upgrades, since
the URL carries `${ABI}` and no series (see "Which repo, which kernels").

## 3. Install from System -> Firmware -> Plugins

`os-if-pppoe` should now be listed (Firmware -> Plugins lists any `os-*`
package visible across all enabled repos, not just the official one —
`docs/plugin/research-opnsense-core.json`, key `packaging`). Installing it
pulls in `if-pppoe-kmod` automatically (`PLUGIN_DEPENDS`).

## 4. Enable and reboot

Services -> Kernel PPPoE. The model is one general toggle plus an
exclude list, not a per-interface enable:

- **Enable kernel PPPoE** (general.enabled) turns the driver on for every
  eligible PPPoE WAN.
- **Exclude** (general.exclude) lists friendly interface names to keep on
  stock mpd5 even while the toggle above is on.

Save, then **Apply** (Services -> Kernel PPPoE's Apply button): this
writes the desired state to `/conf/if_pppoe/desired` via configd and shows
a "reboot required" banner — nothing switches live. Use the page's
**Reboot** button (core's own reboot action) to apply it.

Check "Supported kernels" and the running/installed kernel rows on the same
page first: if the kernel is not covered, the reboot leaves every WAN on
mpd5 (see "After an OPNsense kernel update").

## Removing it

Uninstalling `os-if-pppoe` from Firmware -> Plugins (or `pkg delete
os-if-pppoe`) tears down every registered clone, then reverts the
`interfaces.inc` hook, synchronously in `+PRE_DEINSTALL` (not backgrounded
-- pkg SIGKILLs anything backgrounded from a pkg-script the instant it
returns; see `plugin/net/if-pppoe/src/opnsense/scripts/if_pppoe/uninstall.sh`'s
header and risk-register #9) before Firmware -> Plugins' own removal call
returns. It does not touch the `if_pppoe` kmod; that is `if-pppoe-kmod`'s
own `+PRE_DEINSTALL`, which runs afterward too (e.g. via the `pkg
autoremove` that follows removing `os-if-pppoe`) and by then finds nothing
registered, so it unloads cleanly. Uninstalling `if-pppoe-kmod` on its own
while a clone/session is still up leaves the module loaded (it refuses to
`kldunload` under a live session, see `+PRE_DEINSTALL` there) — reboot to
return fully to mpd5.

## What this session verified vs. did not

Verified (cited inline in the relevant files/commits): the `pkg repo`
signing/`FINGERPRINTS` flow, `pkg-script(5)`'s `PKG_UPGRADE` semantics and
script phase ordering, `pkg.conf(5)`'s repo `.conf` fields, `pkg-triggers(5)`
being Lua-script-based (not shell), and libpkg's reaper (`pkg_reaper_acquire`/
`pkg_reaper_release` in `libpkg/scripts.c`, SIGKILLing any process still a
descendant of a pkg-script once it returns) — all against a local clone of
`github.com/freebsd/pkg` at commit `cd0a561ecc894f3c9811004490d59a5df26c94ad`;
the `opnsense/plugins` packaging conventions against a local clone at commit
`b3f542633841ff9743262979630e5ee9c52d0c89`; and `kern.build_id`'s exact
byte-for-byte equality with the ELF `.note.gnu.build-id` note (FreeBSD
`sys/kern/kern_mib.c`'s `sysctl_build_id()`, `cgit.freebsd.org/src`) — the
one open question the kmod README previously flagged, now resolved.

**Not run this session** (no FreeBSD host, no access to the lab
`<LAB_HOST>` or `<ROUTER_HOST>` per this task's constraints):

- Any real `make`/`bmake` invocation of `plugin/kmod/if-pppoe-kmod/Makefile`
  or `plugin/net/if-pppoe/Makefile` (both are BSD-make syntax; this
  sandbox only has GNU make, and no `pkg(8)` binary at all — see
  `plugin/build/test-packaging.sh` for what was checked instead).
- `pkg repo` / `pkg create` / `pkg install` / `pkg delete` against real
  packages.
- `publish-repo.sh` against the real `<LAB_HOST>` — its target directory
  and web server were assumed from the shared contract's description, not
  confirmed to exist or be reachable.
- The full on-box flow above (repo registration through Firmware ->
  Plugins install through reboot).
- A box following `${ABI}` from the `FreeBSD:14:amd64` repo to the
  `FreeBSD:15:amd64` one across a 26.1 -> 26.7 upgrade (the expansion
  itself is documented pkg behaviour, cited above), and Firmware -> Updates
  offering a kernel-only refresh (`<ver>_<N>`).

See `plugin/kmod/if-pppoe-kmod/README.md`'s own "Not tested on-box" list
for the kmod-specific drills (build_id mismatch refusal, upgrade-without-
session-drop, standalone-removal-unloads).
