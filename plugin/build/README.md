# plugin/build/

Packaging and repo scripts. All of these (except `gen-repo-conf.sh` and
`vendor-mk.sh`) must run on a FreeBSD host with the target's `pkg(8)` and
`bmake` — this session had no such host and could not touch a real lab
build host (`<LAB_HOST>`) or router (`<ROUTER_HOST>`); see docs/plugin/INSTALL.md
for what that means for testing.

| Script | Purpose |
|---|---|
| `vendor-mk.sh` | Refresh the pinned `opnsense/plugins` `Mk/`/`Templates/`/`Scripts/version.sh` copy under `plugin/Mk`, `plugin/Templates`, `plugin/Scripts`. Local-checkout only, no pkg/bmake needed. |
| `discover-kernels.sh` | List every published OPNsense kernel set (`kernel-<series>*-amd64.txz`) of each `versions.json` series and write `kernels.json`: one entry per `kern.build_id` with version, ABI (from the kernel's own FreeBSD version), set URL/sha256 and `config_hash` (sha256 of the normalised embedded config). Runs on Linux (CI) or FreeBSD; sets are cached by sha256 (`--cache`). Format and normalisation: docs/CI.md "Kernel discovery". |
| `lib/kbuild.sh` | Sourced helpers shared by discovery, `build-all.sh` and `.github/scripts/freebsd-build.sh`: build-id / version / embedded-config extraction, config normalisation, kernel set download with sha256 check, the `config -d`-only kernel build dir (cached per src tag) with its `opt_*.h` cross-check, and the header-drift check. |
| `build-kmod.sh` | Build+package `if-pppoe-kmod` for every kernel listed in a manifest (`kernels.conf`, see `kernels.conf.example`). A line `<bid> prebuilt <path/if_pppoe.ko>` stages an already built `.ko` (`stage-prebuilt`); `--kernels-json` ships that file's entries as `share/if_pppoe/kernels.json`. |
| `build-plugin.sh` | Build+package `os-if-pppoe` via the vendored `Mk/plugins.mk`. |
| `make-repo.sh` | `pkg repo` a signed catalogue from built `.pkg`s (`--gen-key` to make a keypair first). |
| `gen-repo-conf.sh` | Emit the client-side one-time `repos/IfPppoe.conf` + `fingerprints/IfPppoe/trusted/IfPppoe`. Runs anywhere with `sha256`/`sha256sum` — no FreeBSD host needed. |
| `publish-repo.sh` | `rsync` a built repo dir to `$PUBLISH_HOST` (required env var, e.g. `<LAB_HOST>`). **Unverified this session** — the target directory and its web server were assumed, not confirmed reachable/serving. |
| `build-all.sh` | One command: kmod, plugin (private pkg db), optional signed repo, as a flat `repo.tar.gz`. `--kernels-json FILE --abi ABI` (the path CI uses too) builds a `.ko` for every discovered kernel of that ABI: one kernel build dir and one module build per `config_hash` group (split further when a header the module includes differs between src tags), `stage-prebuilt` for the other members; `--phase kmods\|package` splits that around the CI smoke, `--pass-build-ids` keeps only the smoke-passing kernels, and the package phase checks that pkg resolves `os-if-pppoe` to the new `if-pppoe-kmod`. `--target-kernel` (lab mode) instead overlays the lab's SMP KERNBUILDDIR. See docs/plugin/INSTALL.md's BUILD section. `lab/vm/pkg-build.sh` runs it on the build VM from your own machine. |
| `test-kernel-matrix.sh` | Offline test (Linux, no FreeBSD host) of `discover-kernels.sh` against synthetic kernel sets and of `build-all.sh --kernels-json` with `make`/`config`/`git`/`pkg` stubbed. Run by `test-packaging.sh`. |

## Why opnsense/plugins' `Mk/` is vendored, not referenced

`plugin/net/if-pppoe/Makefile` needs `.include "../../Mk/plugins.mk"` to
work exactly like every real opnsense/plugins plugin (so it stays a drop-in
if this ever moves into that repo). This repo is not a checkout of
opnsense/plugins, so that path has to resolve to something we ship. A git
submodule was the other option; a pinned copy was chosen instead so
`build-plugin.sh` needs nothing beyond this checkout (no submodule
init/network access on the build host), and so `devel.mk` can be
deliberately dropped (see `plugin/Mk/VENDORED.md`) without fighting
submodule semantics. The trade-off is a manual refresh (`vendor-mk.sh`)
instead of a `git submodule update`; given `Mk/plugins.mk` changes rarely
(see `docs/plugin/interfaces-inc-hook.md` §1.2's commit-churn numbers for
the sibling `interfaces.inc` file, for a sense of how slowly this kind of
core/plugins glue moves), that trade favors us.

## Why `if-pppoe-kmod` is not built via opnsense/plugins' `Mk/plugins.mk`

See `plugin/kmod/if-pppoe-kmod/README.md`.

## Why the repo is signed with `signing_command`, not local `rsa:keyfile`

Both are real `pkg repo` signing modes (`docs/pkg-repo.8` EXAMPLES, in the
pkg source clone this session used, at commit
`cd0a561ecc894f3c9811004490d59a5df26c94ad`). `signing_command` runs an
external script that receives the catalogue's SHA256 on stdin and never
has to load the private key into the `pkg repo` process's own address
space or config, so the key can live somewhere other than next to the
`.pkg` files it signs (contract: "signing key kept outside the repo").
`make-repo.sh` currently points that command at a local `openssl`
invocation reading the key by path — swap the one line for
`ssh signing-host /path/sign.sh` (shown as its own case in the man page's
EXAMPLES) to get a real separate signing host with no other change.

The paired client-side verification is `SIGNATURE_TYPE: FINGERPRINTS`
(a locally-stored SHA256 of the repo's public key, checked against the key
material the catalogue itself carries — no separate pubkey file needs to
reach the client), matching the shared contract's "one-time registration...
+ fingerprint" wording. `rsa:keyfile` local signing is documented as
pairing with client `SIGNATURE_TYPE: PUBKEY` instead (the client needs an
actual copy of the public key file); nothing in the man page says
`FINGERPRINTS` verification is unavailable for an `rsa:keyfile`-signed
repo, since both modes embed the same `CERT` block in the catalogue — but
that combination was not independently tried this session, so
`make-repo.sh` only offers the documented `signing_command` +
`FINGERPRINTS` pairing.

## Ordering

`if-pppoe-kmod` must be built (and installed/registered on the build host)
**before** `os-if-pppoe`: the plugin's `PLUGIN_DEPENDS=if-pppoe-kmod` makes
`plugins.mk`'s `manifest` target `pkg query` for it and hard-error
("Missing dependency") if it isn't already installed there
(`docs/plugin/research-opnsense-core.json`, key `packaging`, confirmed
against `Mk/plugins.mk` L140-150 in the vendored copy). `build-all.sh`
does this in order automatically.
