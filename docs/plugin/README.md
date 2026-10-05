# os-if-pppoe plugin design

v1 decisions (2026-09-27):

- **Integration: transparent hook.** The plugin adds 2 guarded lines to core's `interfaces.inc`, one at `interface_ppps_reset()` and one just before `/* fire up mpd */` in `interface_ppps_configure()`. Each line calls an out-of-process engine. When kernel mode is enabled and the interface is eligible, the kernel driver dials instead of mpd5. Config and GUI are unchanged: WAN stays `pppoe0` with type PPPoE.
- **Install and remove** from System → Firmware → Plugins, served from a signed pkg repo hosted on the LAN.
- **Services page** only enables or disables kernel mode, and a reboot applies the change.
- **Scope:**
  - all PPPoE WANs;
  - no CARP/HA (the plugin refuses);
  - manual fallback when there's no session;
  - automatic fallback to mpd5 on a kmod or kernel mismatch and on boot strikes;
  - re-apply immediately after core updates;
  - OPNsense 25.7.x / FreeBSD 14.3 only for now;
  - dual-stack IPv6;
  - in-kernel MSS clamp.

Cross-component contract (as built; checked by
`plugin/net/if-pppoe/tests/engine/test_integration.php`):

- Settings live at config.xml `OPNsense/IfPppoe/general` (model mount `//OPNsense/IfPppoe`), which is what the engine reads.
- `engine status --json` is the single source of the status: `reboot_required`, `apply_pending`, `latched`, `boot` (from `/var/run/if_pppoe/boot.json`) and `notices` (from `notice.d/`). `Support::mergeStatus()` only maps it for the Services page. `IfPppoeStatus` shows the notices in System → Status through `engine notices --json`.
- pkg trigger `path` is the directory `/usr/local/etc/inc`, because pkg matches the directory of each touched file.
- Cron: `configctl if-pppoe reapply` (hook) every 5 minutes, `configctl if-pppoe reconcile` (engine) every minute, `configctl if-pppoe abiheal cron` every 15 minutes.
- OPNsense major upgrade: the upgrade only reinstalls the OPNsense repo's packages, so ours keep the old ABI (`FreeBSD:14:amd64` on a 26.7 / `FreeBSD:15:amd64` box). The `upgrade` syshook prefetches the new ABI's packages before the reboot (`abi-heal.sh prefetch`, into `/var/cache/if_pppoe/prefetch/`), and the early syshook installs them offline on the first boot on the new ABI (`abi-heal.sh offline`), so kernel PPPoE comes up with no extra reboot. Without a prefetch, or if that install fails, the early syshook reports `kmod-abi-mismatch`, and `abi-heal.sh` (start syshook, cron, and the update syshook / pkg trigger via configd) runs `pkg install -f -y -U -r IfPppoe if-pppoe-kmod os-if-pppoe` once the repo offers the new ABI, then the page offers the reboot. By hand: `pkg install -f -r IfPppoe if-pppoe-kmod os-if-pppoe`, then reboot. Details: [INSTALL.md, "OPNsense major upgrades"](INSTALL.md#opnsense-major-upgrades-257261---267).
- When hookctl refuses to re-apply after a core change, `reapply.sh` runs `engine reconcile --after-firmware`. It falls back to its own shell teardown only if the engine is missing or fails.
- Uninstall order: collect the registry pairs, `hookctl revert`, `engine reset` each pair, then `configctl interface reconfigure` each friendly name.
- HA refusal uses the same three hasync fields everywhere: `pfsyncinterface`, `pfsyncpeerip` and `synchronizetoip`.

Documents:

- `interfaces-inc-hook.md`: the patch, anchors, per-tag stability evidence, and the apply/revert mechanism (hookctl). Reference implementation in `ref/`.
- `risk-register.md`: 26 risks with mitigations, confidence, residual risk and tests. Superseded where it conflicts with the v1 compromises above; for example, the live toggle is gone and the CARP rows no longer apply.
- `research-opnsense-core.json`: source-cited research on OPNsense core bring-up, the plugin API, packaging and kmod ABI.

Note: the research cites OPNsense 25.7.11, 26.1 and 26.7. The v1 target is the user's 25.7.x box.
