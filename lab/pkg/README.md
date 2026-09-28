# os-pppoe — OPNsense plugin package for the if_pppoe driver

`packages/os-pppoe-0.1.0.pkg` installs the in-kernel PPPoE client driver
(OpenBSD/NetBSD port) plus its control tool and an activate/de-activate
service on OPNsense 25.7 (FreeBSD 14.3 base, ABI `FreeBSD:14:*`).

## Contents

| path | what |
|------|------|
| `/boot/modules/if_pppoe.ko` | the driver kmod (built against the OPNsense SMP kernel build dir) |
| `/usr/local/sbin/pppoectl` | control tool (verbatim NetBSD port: setparms, auth cfg, counters) |
| `/usr/local/etc/rc.d/if_pppoe` | activate/de-activate service (`if_pppoe_enable` rcvar, defaults YES) |

The package origin is `opnsense/os-pppoe`, so OPNsense lists it as a plugin
under **System → Firmware → Plugins/Packages**.

## Install

```sh
pkg add -f ./os-pppoe-0.1.0.pkg
```

## Activate / de-activate

```sh
service if_pppoe start     # activate  (kldload; idempotent)
service if_pppoe stop      # deactivate (destroys pppoeN clones — PADT goes
                           # out per clone — then kldunload; clean dmesg)
service if_pppoe status    # loaded / not loaded
```

Auto-load at every boot: `sysrc if_pppoe_enable=YES` (default; set to `NO`
to keep it from loading at boot). Removing the package stops the service
first (pre-deinstall script), so `pkg remove os-pppoe` is safe with a live
session.

## Dial a session (after activation)

```sh
ifconfig pppoe0 create
pppoectl -e <parent-iface> pppoe0                    # parent bind + service
pppoectl pppoe0 myauthproto=pap myauthname=USER myauthsecret=PASS
pppoectl pppoe0 query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1
ifconfig pppoe0 up
```

Observability: `sysctl net.pppoe` (counters, `net.pppoe.parent_altq`),
`dmesg` (link-state changes, IPCP signals, one-shot ALTQ warning).

## Rebuild

```sh
# on any FreeBSD 14.3 host that has the target kernel build:
sh lab/pkg/build-os-pppoe.sh [/path/if_pppoe.ko] [/path/pppoectl]
```

The `.ko` must be built against the target machine's kernel build dir
(`lab/vm/build-module.sh`, `KERNEL_VARIANT=SMP` for OPNsense 25.7's
GENERIC+RSS+VIMAGE kernel).

## Lab verification (2026-09-25, client VM = FreeBSD 14.3-RELEASE-p7 + OPNsense SMP kernel)

- `pkg add -f os-pppoe-0.1.0.pkg` → files installed, module unloaded
- `service if_pppoe start` → `kldstat` loaded (`ACTIVATE_OK`)
- dial via packaged pppoectl → `inet 10.99.0.100 --> 10.99.0.1`, `net.pppoe.parent_altq: 0`
- `service if_pppoe stop` → clone destroyed with PADT, module unloaded, clean
  dmesg (`session closed: local shutdown` → link DOWN → IPCP layer down);
  `vmstat -m pppoe` at the known idle baseline
- re-activate/de-activate round-trip green; `pkg remove` clean

## Hosting (`<LAB_HOST>`)

The canonical plugin hosting is `<PKG_REPO_DIR>` on `<LAB_HOST>`, served by
`os-pppoe-repo.service` (python http.server, port 8765, `Restart=always`):

- `<PKG_REPO_URL>/os-if-pppoe-0.1.6.pkg` — full plugin (Services
  page + `if-pppoe-ctl` + kmod), **0.1.6 = 0.1.5 with the S03 driver kmod**
  (MEM068 reconnect fix + ALTQ detection) swapped in; kmod sha256
  `c059874f…` vs 0.1.5's pre-S03 `d23c15f9…`.
- `<PKG_REPO_URL>/os-if-pppoe-0.1.5.pkg` — kept for rollback.
- Repo metadata (`meta.conf`, `packagesite.pkg`, `data.pkg`) regenerated
  with `pkg repo` (run on the lab client VM — `<LAB_HOST>` is Linux, no pkg).

Router-side upgrade (OS on `<DUT>`):

```sh
pkg add -f <PKG_REPO_URL>/os-if-pppoe-0.1.6.pkg
# or, as a proper repo:
#   /usr/local/etc/pkg/repos/if-pppoe.conf:
#     if-pppoe: { url: "<PKG_REPO_URL>", enabled: yes }
#   pkg update && pkg upgrade
```

The Services page (`Services: In-kernel PPPoE (if_pppoe)`) is unchanged —
its Enable/Disable backend (`if-pppoe-ctl`) drives the module and the
S03 reconnect fixes ride along transparently (redial converges in ~5s
instead of the infinite ConfReq/ConfNak loop; `net.pppoe.parent_altq`
sysctl + one-shot dmesg ALTQ warning are new).

## Notes / limitations

- **No stock OPNsense page toggles kernel modules.** "Activate" here is the
  rc.d service start/stop above (or enable/disable at boot via rcvar). A
  dedicated web-UI toggle page requires an OPNsense PHP plugin (controllers,
  model, template) — currently a declared Phase-1 non-goal; the package is
  shaped so such a plugin can be layered on later without repacking the kmod.
- The kmod is kernel-build-specific: one package per kernel variant (SMP vs
  SMPW debug). Do not mix.