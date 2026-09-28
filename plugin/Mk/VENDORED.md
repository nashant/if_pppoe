# Vendored from opnsense/plugins

`plugin/Mk/`, `plugin/Templates/` and `plugin/Scripts/version.sh` are a pinned,
byte-identical copy of the corresponding files from upstream
[opnsense/plugins](https://github.com/opnsense/plugins), so that
`plugin/net/if-pppoe/Makefile` can `.include "../../Mk/plugins.mk"` exactly as
every in-tree opnsense/plugins plugin does, without this repo living inside a
checkout of opnsense/plugins itself.

- **Pinned commit:** `b3f542633841ff9743262979630e5ee9c52d0c89` (branch head at
  clone time, 2026-09-25 11:32:33 +0200, "dns/ddclient: native porkbun script
  (#5599)").
- **License:** BSD-2-Clause, per each file's own header (Franco Fichtner and
  the opnsense/plugins contributors listed in upstream `LICENSE`). Headers are
  preserved unmodified; nothing here is relicensed.
- **What's vendored:** `Mk/*.mk` (minus `devel.mk`, see below), `Templates/*`
  (used by `plugins.mk`'s `scripts-auto` target to wire up `rc.syshook.d`,
  `actions.d`, MVC models/templates and `rc.loader.d` hooks when the plugin
  ships them), and `Scripts/version.sh` (used by the root-adjacent
  `PLUGIN_COMMIT!=` line in `plugins.mk` to embed a git-describe-based build
  string; falls back to `unknown 0 undefined` if this repo has no tags reachable
  from `g describe`, which is harmless).
- **Deliberately NOT vendored: `Mk/devel.mk`.** Upstream ships this file only
  on the plugins repo's development branch; it unconditionally sets
  `PLUGIN_DEVEL?=yes`, which makes `plugins.mk` build every plugin as a
  `-devel` package (PLUGIN_TIER=4, self-conflicting with the non-devel name).
  `plugins.mk` includes it with `.-include` (silently skipped if absent), so
  leaving it out is enough to get normal, non-devel packaging — which is what
  we want for a package meant to be installed on a real box, not opnsense's
  own plugins CI.
- **Not vendored at all:** `Mk/common.mk`'s one line
  (`.-include "${PLUGINSDIR}/../core/Mk/common.mk"`) optionally pulls in a file
  from an `opnsense/core` checkout living as a sibling of `opnsense/plugins`.
  That layout doesn't exist in this repo; the include is silently skipped
  (`.-include`), which upstream confirms is safe — that file exists solely to
  let plugins.mk read `${PLUGINSDIR}/../core`'s own git-derived version info
  when both repos are checked out side by side, which we do not need.

## Refreshing the pin

Run `plugin/build/vendor-mk.sh <path-to-opnsense-plugins-checkout>` to copy a
newer set of these files in and update the pinned commit above. The script
refuses to vendor `devel.mk` and prints a diff summary so a maintainer can
review upstream Makefile-logic changes before committing them.
