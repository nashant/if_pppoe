# if-pppoe-kmod packaging

Ships `if_pppoe.ko` (one copy per exact kernel build it was compiled
against) and `pppoectl(8)`. Not built through opnsense/plugins'
`Mk/plugins.mk` — that framework mirrors a GUI plugin's `src/` tree into
`/usr/local` (PHP/ABI-detected, `os-`-prefixed); it has no concept of "built
against a specific kernel". The one real opnsense/plugins precedent for
"a plugin that only ships glue and depends on a separately built
kernel-module package" is `net/realtek-re`, which depends on plain
`realtek-re-kmod` (no `os-` prefix) — that package itself is built outside
opnsense/plugins too, from `opnsense/ports/net/realtek-re-kmod`, a FreeBSD
ports-style `USES=kmod` port
(`docs/plugin/research-opnsense-core.json`, key `packaging`, confirmed via
`raw.githubusercontent.com/opnsense/ports/master/net/realtek-re-kmod/Makefile`).
We don't reuse `USES=kmod` either: it installs to `${KMODDIR}` (normally
`/boot/modules`) and expects `/boot/loader.conf.d` to `kldload` it
unconditionally at boot. This plugin needs conditional, exact-build-id-gated
loading instead (`docs/plugin/interfaces-inc-hook.md`, `risk-register.md` C9
and risks #2/#3/#25), so it installs under its own
`/usr/local/lib/if_pppoe/<build_id>/` tree and is `kldload`ed by explicit
path from `rc.syshook.d/early/50-if-pppoe`, never from `loader.conf`.

## BUILD_ID

`BUILD_ID` names the exact kernel build a `.ko` was compiled against; get it
from the actual target kernel (`sysctl -n kern.build_id` on a box running
the exact kernel `KERNBUILDDIR` was collected from). It is passed in on the
command line (from `kernels.conf`), but `stage-one` no longer trusts it on
its word: it re-derives the same value from `${KERNBUILDDIR}/kernel`'s own
`.note.gnu.build-id` ELF note (via `elfdump -n` or `readelf -n`) and
`.error`s out if the two disagree. This is a byte-for-byte match, not a
range check: `sysctl_build_id()` (FreeBSD `sys/kern/kern_mib.c`, the
`SYSCTL_PROC(_kern, OID_AUTO, build_id, ...)` handler around lines 750-771)
builds `kern.build_id` by hex-encoding the bytes of that exact same
`.note.gnu.build-id` section, past its 16-byte note header — there is no
`kern.osreldate`/`__FreeBSD_version` fuzziness involved (verified against
`cgit.freebsd.org/src/tree/sys/kern/kern_mib.c` this session; previously an
open question, `docs/plugin/research-opnsense-core.json` key `kmodabi`).
A mismatched manifest line now fails the build instead of silently shipping
a `.ko` the boot hook would trust. `stage-one` also writes the verified id
to a `build_id` file next to the `.ko` (`.../<BUILD_ID>/build_id`), so the
boot hook can re-check it without depending on the directory name alone.

## Features file

`/usr/local/share/if_pppoe/features` lists this package's `FEATURE(9)` names,
one per line, sorted. It's derived by `features-file` grepping
`^FEATURE(if_pppoe_...` out of `sys/net/*.c` -- a compile-time constant of
the driver source, not the built `.ko`. Unlike `build_ids`, this file is
not per-`BUILD_ID`: every kernel build this package stages comes from the
same driver revision, so one file covers all of them.

Caveat: `FEATURE(if_pppoe_ipv6, ...)` sits inside `#ifdef INET6`
(`sys/net/if_pppoe.c`), but the grep matches regardless of that `#ifdef`.
OPNsense kernels always build `INET6` (not verified against a real
`KERNCONF` this session), so this hasn't been an issue in practice, but a
kernel config without `INET6` would still get a `features` file claiming
`if_pppoe_ipv6`. Grepping the source is simpler than `readelf`/`strings` on
the built `.ko`, not strictly more robust; treat that trade-off as open if a
non-`INET6` kernel is ever supported.

The OPNsense plugin's `Kernel::missingInstalledFeatures()` reads it to know
which required features the *installed* package has, without needing the
module to be loaded first (`kern.features.*` sysctls only exist once a
`FEATURE()` module is `kldload`ed) -- this is what lets the Services page
answer "will enabling work after a reboot" before the first reboot.

## kernels.json

`/usr/local/share/if_pppoe/kernels.json` maps each staged `build_id` to the
OPNsense kernel version it came from: the entries of `KERNELS_JSON`
(`plugin/build/discover-kernels.sh` output, format in docs/CI.md "Kernel
discovery") whose `build_id` is staged, written by `kernels-json-file`
(needs `jq` on the build host). `package` fails if a staged `build_id` has
no entry, so the Services page can always name the kernels a package
covers. Without `KERNELS_JSON` (lab `--target-kernel` builds) the file is
`[]` and the plugin shows the covered kernels as unknown. `pkg-descr`'s
kernel line lists `version (build_id)` pairs from it, else the bare ids.

## stage-prebuilt

```
make -C plugin/kmod/if-pppoe-kmod BUILD_ID=<bid> KO=/path/if_pppoe.ko stage-prebuilt
```

Stages an already built `.ko` under `<bid>/` (plus its `build_id` file)
and builds `pppoectl` if not staged yet. Two users:

- kernels that share one kernel build dir with a `stage-one`'d kernel (same
  normalised config, no header drift between their src tags --
  `plugin/build/build-all.sh --kernels-json`): the module is compiled
  once and staged for every member. That rests on a module built from the
  same headers and options being valid for each of those kernels; it is
  not verified by construction, which is why CI smoke-loads every
  `build_id`'s `.ko` in its own kernel before it ships;
- the CI package phase, which stages the `.ko`s the kmods job built and
  the smoke passed.

It only checks the `BUILD_ID` shape (lowercase hex): the value came from
the kernel's own ELF note during discovery, and `stage-one` verified it
for the group's kernel. `KMOD_MAKE_ARGS` (e.g. `WERROR=-Werror`) is
passed to `stage-one`'s module build.

## Build flow (on a FreeBSD build host, e.g. the lab `build` VM)

```
make -C plugin/kmod/if-pppoe-kmod \
    BUILD_ID=$(sysctl -n kern.build_id) \
    KERNBUILDDIR=/path/to/collected/kernel/obj/.../SMP \
    SYSDIR=/path/to/opnsense-src/sys \
    stage-one
# ... repeat stage-one once per additional supported kernel build ...
make -C plugin/kmod/if-pppoe-kmod KMOD_VERSION=0.1 package
```

`stage-one` builds `if_pppoe.ko` (delegating to `sys/modules/if_pppoe`'s own
`bsd.kmod.mk` Makefile, the same `KERNBUILDDIR`/`SYSDIR` invocation
`lab/vm/build-module.sh` uses) and `pppoectl` (delegating to
`sbin/pppoectl`'s `bsd.prog.mk` Makefile), and stages both into
`work/src/usr/local/...`. It never wipes previously staged `BUILD_ID`s, so
one package can carry `.ko`s for several kernel builds (see risk #25: a new
release should ship kmods for every currently-supported kernel, not just
the newest one). `package`'s `build_ids` file is regenerated from whatever
is actually staged, so it can never drift from what the `.pkg` really ships.

`plugin/build/build-kmod.sh` wraps this loop from a small per-kernel
manifest file instead of hand-typed `make` invocations; see its own
`--help`.

Don't confuse the staged output tree above (never wiped, per-`BUILD_ID`)
with `sys/modules/if_pppoe`'s own compile object dir: `MAKEOBJDIRPREFIX`
does not relocate it (bmake's `.OBJDIR` resolves under `sys/modules/if_pppoe`
itself regardless -- `lab/vm/build-check.sh`'s header), so it is one shared
directory across every `stage-one` call. `stage-one` therefore runs `make
clean` there (and in `sbin/pppoectl`) before each build, so a second
`--target-kernel` never silently reuses the first's `.ko`, and no leftover
`PPPOE_TEST_REFLECT` object from a manual `build-module.sh` run survives
into a release package.

## Not tested on-box this session

This session had no FreeBSD host and could not touch a real lab build host
(`<LAB_HOST>`) or router (`<ROUTER_HOST>`). `plugin/build/test-packaging.sh`
does what's checkable without one: fabricates a fake staged tree and a
stub `pkg`(1), then runs this Makefile's `manifest`/`plist`/`build-ids-file`
targets against **GNU** make in a syntax-lint capacity only — **it cannot
run the real thing**, since this Makefile is BSD-make (`bmake`) syntax
(`.if`/`.error`/`!=` assignment), and neither `bmake` nor a FreeBSD `pkg`
was available in this sandbox (checked: `command -v bmake`, `command -v
pkg` both absent). On-box tests to run for real before shipping:

- `stage-one` + `package` against a real `KERNBUILDDIR`/`SYSDIR`, then
  `pkg install ./work/pkg/if-pppoe-kmod-*.pkg` and confirm
  `/usr/local/share/if_pppoe/build_ids` and the `.ko` path match, and that
  `/usr/local/share/if_pppoe/features` lists the same names `kldload`ing the
  `.ko` then exposes under `kern.features.if_pppoe_*`.
- `kldload -v /usr/local/lib/if_pppoe/$(sysctl -n kern.build_id)/if_pppoe.ko`
  succeeds; `kldload` of a deliberately wrong `BUILD_ID` dir's `.ko` (copy
  one built for a different `KERNBUILDDIR`) fails with the kernel's own
  version-mismatch message (confirms the FEATURE-flag/build_id gate in
  `rc.syshook.d/early/50-if-pppoe` isn't the only thing standing between a
  mismatched module and `kldload`).
- `pkg delete if-pppoe-kmod` standalone (if-pppoe not also being removed)
  with a clone/session up: confirm `+PRE_DEINSTALL`'s `ifconfig -g pppoe` /
  `/var/run/if_pppoe/reg` check finds it, refuses to `kldunload`, and the
  session survives (file unlink vs. resident module) until a reboot.
- `pkg remove os-if-pppoe` (which `pkg autoremove`s if-pppoe-kmod, core's
  `firmware/remove.sh` flow) with a session up: confirm if-pppoe's own
  `+PRE_DEINSTALL` tears the session down and reverts the hook *before*
  if-pppoe-kmod's `+PRE_DEINSTALL` runs, so the latter's busy-check is
  already clear and the module does unload.
- `pkg upgrade` from one `if-pppoe-kmod` version to the next with a session
  up: confirm no session drop (`+PRE_DEINSTALL`'s `PKG_UPGRADE` branch).
