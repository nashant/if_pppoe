# if_pppoe

An in-kernel PPPoE driver for OPNsense: a port of NetBSD's `pppoe(4)` PPPoE
discovery/session layer and `sppp(4)` PPP state machine to FreeBSD, shipped as
a loadable kmod plugin. The goal is to replace userland `mpd5` as the PPPoE
client on OPNsense with a kernel driver, giving line-rate throughput without a
userland process in the packet path.

## Start here

New to this project? Read [docs/TESTING.md](docs/TESTING.md) first — it covers
the lab topology, pass criteria, and how to run each test tier. For the plugin
that ships the driver, see [docs/plugin/README.md](docs/plugin/README.md).

## Status

**Phase 0 (test lab): done, merged to `main`.** **Phase 1 (driver): design approved,
implementation not started.** No driver code exists yet. Phase 0 built the lab rig and
test harness that Phase 1 and later phases (baselines, functional correctness, interop,
performance, production trial) run against.

See [docs/TESTING.md](docs/TESTING.md) for the full test strategy: the lab
topology, pass criteria, and how to run each test tier.

Deploying on a router: [docs/DEPLOY.md](docs/DEPLOY.md) is the UI-first
runbook — package install and the kernel-variant rule, Tunables, the
Services → In-kernel PPPoE toggle page, shaping/ALTQ caveats, counters and
troubleshooting, and rollback to mpd5.

After an OPNsense major upgrade (for example 26.1 -> 26.7), the plugin's
packages stay on the old FreeBSD ABI until they are reinstalled. The plugin
does that by itself once the box is back online and then asks for a reboot.
By hand: `pkg install -f -r IfPppoe if-pppoe-kmod os-if-pppoe`, then reboot
(see [docs/plugin/INSTALL.md](docs/plugin/INSTALL.md#opnsense-major-upgrades-257261---267)).

## Layout

- `lab/` — Makefile and scripts to bring up the VM/netns test lab.
- `docs/` — operator documentation.
- `tests/` — functional and performance test suites.
