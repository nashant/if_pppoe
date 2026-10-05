# Lab VMs (Tasks 4-5)

FreeBSD 14.3-RELEASE VMs on `<LAB_HOST>`:

- `build` — builds the OPNsense 25.7.11 `SMP` kernel that the DUT (<DUT>) runs.
  QEMU user-mode networking only.
- `build15` — FreeBSD 15.1 twin of `build` for the OPNsense 26.7.4 (FreeBSD 15.1)
  kernel/objdir; see "FreeBSD 15.1 (OPNsense 26.7) build VM" below.
- `client` — boots the `SMP` kernel as an alternate kernel; runs mpd5 as a PPPoE client
  that dials either the isp VM's accel-ppp server (or the legacy isp-netns accel-ppp)
  or the `mpdsrv` VM.
- `mpdsrv` — stock kernel; runs mpd5 as a second PPPoE server (RFC4638 max-payload),
  for testing the SMP kernel/pppoe stack against a non-accel-ppp implementation too.
- `isp` — **Linux (Debian 12) VM: the lab's ISP side** — accel-ppp PPPoE server
  (same session semantics as the isp-netns server: service "lab", ac "isp-lab",
  10.99.0.x pool, gw 10.99.0.1) plus `iperf3 -s`. The dedicated VM removes the
  isp-netns server as a throughput bottleneck: the pppoe-tunnel ceiling went from
  ~1.5 Gbit/s (netns server) to ~2.5–2.9 Gbit/s. accel-pppd's log is written
  through a virtio-9p share to `<LAB_HOST>:$LAB_DIR/isp-share/accel-ppp.log`, with
  `/tmp/accel-ppp.log` symlinked to it so the functional suite's log reads
  (`tests/functional/lab.py` `AccelServer.LOG`) are unchanged. accel's CLI is
  driven by running `accel-cmd` inside the VM over ssh (`AccelServer._cli`
  tries VM-ssh, then the legacy netns path). Provisioning:
  `./run.sh isp up && ./provision-isp.sh` (fetch-image.sh isp for the base image;
  the Debian *generic* kernel is installed at provision time because the cloud
  kernel lacks the 9p module). The legacy netns server can still be brought up
  (`isp-netns/up.sh`) — stop the VM's accel-pppd first: two PPPoE servers on
  `br-isp` would double-answer PADI.

`client`/`mpdsrv` each also get a bridged NIC onto `br-isp` (task 2's isp-netns lab
bridge) alongside their user-mode ssh NIC — see "Networking" below.

- `dut` — **OPNsense 25.7.x VM: if-pppoe plugin round-trip testing** (`tests/plugin/`,
  p4-opnvm). Separate from `client`/`mpdsrv` above (which test the kernel driver
  directly, no plugin/GUI involved) so a plugin install/enable/reboot/uninstall cycle
  never disturbs their kernel-driver test sessions. See "dut (plugin-test DUT)" below —
  **draft only**: written and locally sanity-checked (config render, console driver —
  see their own tests) but never booted; there is no lab access in this session.

All scripts are run from anywhere with ssh access to `<LAB_HOST>`
(override with `VMHOST=...`); they drive <LAB_HOST> and the VMs over ssh rather
than needing to run on either host directly. State lives under
`<LAB_HOST>:~/if_pppoe-lab/` (override with `LAB_DIR=...`).

## Usage

```
./fetch-image.sh [name ...]   # download+checksum the base image once, create/verify
                               # each name's own overlay qcow2 (default: build client mpdsrv)
./run.sh <name> up            # boot the VM, wait for ssh (also attaches br-isp tap if any)
./run.sh <name> ssh -- uname -a
./run.sh <name> down          # graceful guest shutdown, then tap teardown if any

./build-kernel.sh setup       # (build only) pkg install git, clone opnsense/src@25.7.11
./build-kernel.sh start       # nohup'd `make buildkernel` inside build (background)
./build-kernel.sh status      # poll: RUNNING / DONE exit=N + log tail
./build-kernel.sh collect     # copy kernel+modules into build AND to the host,
                               # print evidence

./provision-client.sh         # requires `build` and `client` up: copies the SMP
                               # kernel into client:/boot/kernel.SMP, reboots onto
                               # it, asserts uname, installs+configures mpd5+iperf3
./provision-mpdsrv.sh         # requires `mpdsrv` up: installs+configures mpd5
                               # (PPPoE server) + starts iperf3 -s -D

./verify-lab.sh                # runs the task-5 checks, prints PASS/FAIL per check

./ssh-config.sh > /tmp/cfg      # print Host lab-<name> aliases (ProxyJump <LAB_HOST>)
                                 # for tools that build their own ssh argv, e.g. tests/perf's
                                 # run_matrix.py --ssh-config; see docs/PERF-FWD-DESIGN.md
./router-mode.sh enable raw     # WAN=vtnet1 static 192.168.99.2/24, no PPPoE -- the
                                 # phase-2 forwarded-harness no-PPPoE baseline
./provision-isp-raw.sh          # matching 192.168.99.1/24 on the isp VM's bridged NIC
```

## Fast lane: build-check

`build-check.sh` is a compile-only lane on the shared `build` VM: no lab
slot, no client/isp/mpdsrv VM touched. It builds the if_pppoe kmod against
both collected kernel variants (SMP, SMPW), the PPPOE_TEST_REFLECT variant
when the source's Makefile defines it, plus `sbin/pppoectl` and `tools/*`,
and prints PASS/FAIL per target with compiler output verbatim on failure.

```
./build-check.sh                  # this worktree, tracked files live off disk
./build-check.sh <commit-ish>      # `git archive` that commit
./build-check.sh /path/to/worktree # another worktree, same as the no-arg form
./build-check.sh --clean [...]     # force a full rebuild first
make -C lab build-check REV=<commit-ish or path>   # same, via the Makefile
```

It uses its own dirs, never the slot dirs `work`/`modobj`/`work-slotN`/...
that `build-module.sh` and verification runs use concurrently:
`$HOME/if_pppoe-lab/work-check/{SMP,SMPW,SMP-reflect,host}/` (one subdir per
kernel-ABI variant, since MAKEOBJDIRPREFIX doesn't redirect these
out-of-tree builds — build-module.sh's own header comment notes the same —
so physical separation is what actually keeps a debug-kernel object from
being linked into a release build or vice versa) and a
`build-check.lock/` mkdir-lock so two build-checks never clash (a lock
held >15min is treated as abandoned and reclaimed).

Warm reuse: each variant dir remembers the sha256 of the source tree last
synced into it; an unchanged re-run skips the tar-send/extract for that
variant entirely (mtimes untouched, so `make` itself no-ops). When the
source *has* changed, extraction always forces "now" mtimes
(`tar -m`) rather than trusting the archive's — `git archive` stamps every
entry with the commit's own timestamp, not monotonic across arbitrary
commits, so without this an older commit's files could land with an older
mtime than a `.o` already built here from a later commit and `make` would
silently keep the stale object (this is exactly how a real syntax error
in `sys/net/if_sppp.h` first passed instead of failing, before the fix).

Measured on <LAB_HOST>'s `build` VM (6 vCPU): cold (`--clean`, empty
work-check/) ~10-13s; warm (identical source re-run, sync skipped) ~4s.
`-Werror` is already the OPNsense src tree's default for WARNS>=1
(confirmed via `make -V CFLAGS -V MK_WERROR`) — build-check doesn't need to
add it.

## Slots and leases

`LAB_SLOT=N` (default 1) selects an independent copy of the per-test VMs, so
several verifiers can run the functional suite at once. Every script here,
`lab/Makefile` and `tests/functional/lab.py` honour it.

| | slot 1 (original, unchanged) | slot N (2..9) |
|---|---|---|
| VMs | `client` `isp` `mpdsrv` (+ `lan`) | `client<N>` `isp<N>` `mpdsrv<N>` (+ `lan<N>`) |
| ssh ports (client/isp/mpdsrv/lan) | 2223 / 2225 / 2224 / 2226 | +10·(N-1): slot 2 = 2233 / 2235 / 2234 / 2236 |
| accel CLI hostfwd | 2001 | 2001+10·(N-1) |
| bridge / taps | `br-isp`, `tap-client` ...; router-mode LAN `br-lan` (`tap-lan`, `tap-lan-vm`) | `br-isp<N>`, `tap-client<N>` ...; `br-lan<N>` (`tap-lan<N>`, `tap-lan-vm<N>`) |
| run dir | `~/if_pppoe-lab/run` | `~/if_pppoe-lab/run-slot<N>` |
| accel log (9p) | `isp-share/` (+ `/tmp/accel-ppp.log`) | `isp-share-slot<N>/accel-ppp.log` |
| build VM work dir | `work/`, `modobj/` | `work-slot<N>/`, `modobj-slot<N>/` |
| remote tests / log | `tests-functional/`, `last-func-<SERVER>.log` | `tests-functional-slot<N>/`, `last-func-slot<N>-<SERVER>.log` |

The `build` VM is shared by all slots (per-slot work dirs keep `sync` from
wiping another slot's tree). Bridged-NIC MACs are identical in every slot —
each slot is its own L2 segment. A role name resolves through `LAB_SLOT`
(`LAB_SLOT=2 ./run.sh client up` == `./run.sh client2 up`). Every slot has its
own `mpdsrv<N>`, so the `needs_mpdsrv` tests run in any slot, and may have
its own router-mode `lan<N>` (perf S06 / `make test-perf-fwd LAB_SLOT=N`):
`LAB_SLOT=N ./fetch-image.sh lan`, `./run.sh lanN up`, `LAB_SLOT=N
./provision-lan.sh`. `client<N>` gets its `br-lan<N>` NIC (vtnet2) at launch,
so a client started before this existed needs `./run.sh clientN down` + `up`.

Leases (`./slot.sh`, state on `<LAB_HOST>:~/if_pppoe-lab/leases/slot<N>/`,
atomic `mkdir`; `LAB_SLOTS` default `"1 2"`, `LAB_LEASE_TTL` default 3600s):

```
N=$(./slot.sh acquire --wait 1800 --owner "verifier X")   # prints the slot
trap "./slot.sh release $N" EXIT                          # release on failure too
./slot.sh renew $N          # heartbeat; a lease idle > TTL is reclaimable
LAB_SLOT=$N KERNEL_VARIANT=SMPW ./build-module.sh sync ... deploy ... load ...
make -C .. test-func LAB_SLOT=$N CLIENT=if_pppoe SERVER=accel
./slot.sh status            # who holds what; `hold <N> <reason>` pins a lease
```

Bringing up a new slot N: `LAB_SLOT=N ./fetch-image.sh client mpdsrv isp`,
`./run.sh {client,isp,mpdsrv}N up`, `LAB_SLOT=N ./provision-isp.sh`,
`LAB_SLOT=N ./provision-mpdsrv.sh`, `LAB_SLOT=N KERNEL_VARIANT=SMPW
./provision-client.sh` (kernel, netisr tunables, mpd5, pppoectl & tools),
then `./run.sh clientN snapshot-save`, and add N to `LAB_SLOTS`.
A fresh FreeBSD overlay's first boot (growfs, firstboot) can outlast
`run.sh up`'s ssh wait under host load; re-check with `./run.sh <vm> ssh --
true` before treating that as a failure.

Leases are advisory: a workflow that never calls `slot.sh` is invisible to
them, and `acquire` tries slots in `LAB_SLOTS` order — `hold` a slot you
use without a lease, or pass `LAB_SLOTS=2` to keep off slot 1.

## Console, monitor, snapshots

`run.sh up` launches every VM with a unix-socket serial console
(`<run>/<vm>.serial.sock`, everything also appended to `<vm>.serial.log`,
never truncated; a `=== run.sh: ... launched` line marks each boot) and a
QEMU HMP monitor (`<run>/<vm>.monitor.sock`).

```
./run.sh client2 console-cmd 'root' 4                     # raw typing: log in first at login:
./run.sh client2 console-cmd 'sysctl kern.ident' [wait]   # type + CR, print the reply
./run.sh client2 monitor 'info status'
./run.sh client2 reset-clean      # db> -> 'reset'; login: -> root + 'shutdown -r now'
./run.sh client2 shutdown         # ssh poweroff, then ACPI; never quits/kills
./run.sh client2 snapshot-save    # clean shutdown, current disk = known-good, boot on overlay
./run.sh client2 snapshot-revert  # monitor quit, drop overlay, fresh overlay, boot (~40s)
```

Client VMs, once `snapshot-save`d (`images/<vm>.golden` exists), always boot
from `images/<vm>-run.qcow2`, an overlay on the known-good `<vm>.qcow2`.
A later `snapshot-save` folds the overlay into the base (`qemu-img commit`).
`down` falls back to ACPI powerdown and then monitor `quit` — SIGTERM/SIGKILL
remain only for VMs launched without a monitor (older run.sh / by hand).
`migrate-slot1.sh` moves slot 1's client onto this scheme (one-time).

## Recovering a panicked VM

1. `./run.sh <vm> console-cmd '' 2` — see where it is (`db>`, `login:`).
2. At `db>`: `console-cmd 'bt'` / `'show locks'` for evidence (it is all in
   `<vm>.serial.log`), then `./run.sh <vm> reset-clean`.
3. Wedged with no usable console: `FORCE=1 ./run.sh <vm> reset-clean`
   (monitor `system_reset`).
4. Disk suspect (e.g. rc.conf truncated by a power cut): `snapshot-revert`.
Never `kill -9` qemu: a power cut is how rc.conf got truncated to 0 bytes once.

## Provisioning order

1. `fetch-image.sh` (creates all three overlays)
2. `run.sh build up`; `build-kernel.sh setup && start`; poll `status`; `collect`
3. `run.sh client up`, `run.sh mpdsrv up`
4. `provision-client.sh` (build must still be up — it tars the kernel out of it)
5. `provision-mpdsrv.sh`
6. `verify-lab.sh`

## FreeBSD 15.1 (OPNsense 26.7) build VM

`build15` holds the 26.7 objdir the kmod is compile-checked against. Same guest
layout as `build` (`~/if_pppoe-lab/{src,obj,kernel/SMP}`); the collected kernel
lands on <LAB_HOST> under `~/if_pppoe-lab/kernel-26.7/` so it never overwrites 25.7's.

```
./fetch-image.sh build15                      # FreeBSD 15.1 BASIC-CLOUDINIT + overlay
./run.sh build15 up
LAB_SERIES=26.7 ./build-kernel.sh setup       # opnsense/src@26.7.4, tools config/26.7/SMP
LAB_SERIES=26.7 ./build-kernel.sh start       # then poll `status`, then `collect`
BUILD_CHECK_VM=build15 ./build-check.sh       # kmod (SMP only) + pppoectl + tools
```

`KERNCONF=SMPW` works the same way (add `BUILD_CHECK_SMPW=1` to build-check it).
The 15.1 cloud image's nuageinit honours run.sh's cidata seed (hostname, user,
key, wheel, growpart) and `echo | su -m root` works as on 14.3 (verified on
the 15.1 client below, 2026-09-30).
`../syntax/kmod-syntax.sh` is a no-VM header check against any `sys/` tree.

## FreeBSD 15.1 client (OPNsense 26.7 live verification)

`LAB_CLIENT_IMAGE=15.1` gives a slot's client its own FreeBSD 15.1 disk
(`client<N>-fbsd15.qcow2`, own overlay and `.golden`) in place of the 14.3
one, which is left untouched. Everything else (name, ssh port, taps, MACs,
bridge, pidfile, serial log) is the slot client's, so the harness and job
scripts need no changes; run.sh records the booted disk in
`run<-slotN>/<name>.disk` and refuses `up`/snapshot ops for the other disk
while one is running. Export the variable for every run.sh/job call.

```
export LAB_SLOT=2
./run.sh client2 down                                     # the 14.3 disk
export LAB_CLIENT_IMAGE=15.1
./fetch-image.sh client                                   # 15.1 image + client2-fbsd15.qcow2
LAB_VHOST=1 LAB_NET_QUEUES=4 ./run.sh client2 up
KERNEL_SET_URL=https://pkg.opnsense.org/FreeBSD:15:amd64/26.7/sets/kernel-26.7.4-amd64.txz \
KERNEL_SET_SHA256=<sha256 from kernels.json> \
KERNEL_BUILD_ID=e3ff5e8976813d0dc02c740db36bb588fabc1fd9 ./provision-client.sh
./run.sh client2 snapshot-save                            # known-good for recovery
# CI's .ko (package /usr/local/lib/if_pppoe/<build_id>/) instead of a lab build:
./batch-suite.sh --slot 2 --rev HEAD --out /abs/out --prebuilt-ko /abs/<build_id>/if_pppoe.ko \
    --prebuilt-bin /abs/bin --k '...'
./run.sh client2 down; unset LAB_CLIENT_IMAGE             # then the 14.3 disk back:
LAB_VHOST=1 LAB_NET_QUEUES=4 ./run.sh client2 up
```

`provision-client.sh` in kernel-set mode installs the set as
`/boot/kernel.<build_id>` (loader.conf `kernel=`) and asserts `kern.build_id`.
A release .ko has no `PPPOE_TEST_REFLECT`, so deselect
`test_reflected_frame_comes_back_with_the_right_pppoe_header` with it.

## Networking

Every VM has a user-mode NIC (`n0`) with an ssh hostfwd — this is what `vm_ssh`/`run.sh
... ssh` always uses, unaffected by anything below. `client`/`mpdsrv` additionally get a
second NIC (`n1`) on a tap device (`tap-client`/`tap-mpdsrv`) bridged into `br-isp` (the
lab bridge from `lab/isp-netns`), so they can reach the accel-ppp server / each other over
PPPoE. `cmd_up` creates+attaches the tap, `cmd_down` detaches+deletes it.

**Give each VM's bridged NIC an explicit, distinct MAC** (`vm_config`'s `VM_BR_MAC`).
QEMU's auto-assigned default MAC for a same-shaped command line is deterministic, so two
VMs with an identical second-NIC setup (as `client`/`mpdsrv` are) collide on the shared
bridge without one — confirmed live: both got `52:54:00:12:34:57`, and PPPoE discovery
frames were silently dropped (`br-isp`'s FDB flip-flopping the address between ports,
same root cause `lab/isp-netns`'s README already documents for its own veth pair).

## Ports / names

| name     | ssh port | vCPU | RAM   | bridged NIC   |
|----------|----------|------|-------|---------------|
| build    | 2222     | 6    | 12GB  | none          |
| build15  | 2228     | 6    | 12GB  | none          |
| client   | 2223     | 2    | 2GB   | tap-client    |
| mpdsrv   | 2224     | 2    | 2GB   | tap-mpdsrv    |
| dut      | 2227*    | 2    | 2GB   | tap-dut-wan, tap-dut-lan |

\* dut's n0 hostfwd port is unused in the seed config (vtnet0 is left
unassigned) — reach dut over its LAN bridge IP instead, see below.

## Paths

On <LAB_HOST> itself (the host, not a VM guest):
- `~/if_pppoe-lab/images/` — base qcow2, per-VM overlay qcow2s, cloud-init seed ISOs
- `~/if_pppoe-lab/run/` — qemu pidfile + serial console log per VM name
- `~/if_pppoe-lab/kernel/SMP/` — built `kernel` + flat `*.ko` modules, copied out of
  the build VM's guest disk by `build-kernel.sh collect` (tar over the ssh hostfwd), so
  they're retrievable without booting the build VM.

Inside the `build` VM's guest disk (`freebsd` user's home, reached via `run.sh build ssh`):
- `~/if_pppoe-lab/src` — opnsense/src checkout
- `~/if_pppoe-lab/obj` — `MAKEOBJDIRPREFIX`
- `~/if_pppoe-lab/kernel/SMP/` — same build artifacts, pre-collection source of truth
  (note: `$kernbuilddir/modules` under `obj/` is a MAKEOBJDIRPREFIX-mirrored tree, not
  flat — `collect` flattens it to bare `*.ko` by basename when copying out of it)

## dut (plugin-test DUT)

An OPNsense 25.7.x VM for `tests/plugin/`'s round-trip harness (register repo, install
if-pppoe, enable, reboot, assert kernel backend + connectivity, disable, reboot, assert
mpd5, uninstall, assert clean). Run end to end against a real boot on 2026-09-28
(OPNsense 25.7 nano image, kernel set 25.7.11, os-if-pppoe 0.4: `tests/plugin`
24 passed). What that first real run established:

- The nano image boots to getty's `login:` on ttyu0, not to the menu. `provision-dut.sh`
  logs in as root with the factory default password `opnsense` (public, not a secret;
  the seed replaces it with a locked `*` and key-only ssh), then `8) Shell`.
- qemu's NIC order is run.sh's `-device` order: vtnet0 = n0 (user-mode), vtnet1 = n1
  (WAN, br-isp), vtnet2 = n2 (LAN, br-dut-lan). The factory default assigns
  LAN=vtnet0/WAN=vtnet1; the seed assigns WAN=pppoe0 on vtnet1 and LAN=vtnet2, and
  `provision-dut.sh` asserts both MACs before copying the seed.
- root's shell over ssh is opnsense-shell, which runs `ssh root@dut <cmd>` under
  `/bin/csh`: send sh scripts on stdin to `/bin/sh -s`.
- The lab isp has no upstream (no DNS, no internet), so `plugin-roundtrip.sh`
  disables the OPNsense pkg mirror for the run and step 4 pings the PPPoE peer
  10.99.0.1; the IPv6 ping is not run (accel never opens IPv6CP).

1. ~~Confirm the base image URL~~ Verified: `fetch-image.sh`'s `OPNSENSE_IMG_BASE_URL`
   (`https://pkg.opnsense.org/releases/<ver>`) and `OPNSENSE_IMG_BZ2`
   (`OPNsense-<ver>-nano-amd64.img.bz2`) both resolve, for `OPNSENSE_VERSION=25.7`
   and `26.1` (WebFetch on the `pkg.opnsense.org/releases/<ver>/` directory listings;
   488M/25.7 and 515M/26.1 for the nano image). "nano" (preinstalled headless) not
   "serial" (installer/live, needs an install-to-disk step) — matches
   `provision-dut.sh`'s assumption of booting straight to the console menu.
   The checksum is one combined `OPNsense-<ver>-checksums-amd64.sha256` per version
   (BSD-style `SHA256 (file) = hash` lines), not a co-located per-image file.
2. **`console_driver.py` connects with `sudo nc -U`**, the same as `run.sh`'s own
   console-cmd, since <LAB_HOST> has no socat and the console socket
   (`<run>/dut.serial.sock`) is created by qemu under sudo. Verified on the real
   console.
3. First boot reached `login:` within `provision-dut.sh`'s `--boot-timeout 300`
   (not timed more precisely). `--boot-nudge-after 20` sends a bare newline
   periodically, which redraws `login:` if it was printed before the driver connected.
4. The console transcript is `dut-console.log` in `plugin-roundtrip.sh`'s tmpfs run
   dir (last 40 lines printed on failure, then shredded); the serial log on the lab
   host keeps everything.

What's grounded in source (opnsense/core 25.7.11, `41587bb2d45af0181...c9541`), not guessed:
- The console menu text/option numbers (`8` = Shell, `6` = Reboot) — `src/sbin/opnsense-shell`.
- `dut-config.xml.tmpl` is modeled on core's own factory-default template
  (`src/etc/config.xml.sample`, installed as `/usr/local/etc/config.xml`), which is also
  the exact file `OPNsense\Core\Config::init()` restores from when `/conf/config.xml` is
  missing or invalid (`Config.php` init(), the `restoreBackup($app->application->configDefault)`
  path) — so a malformed hand-written config.xml is *not* a bricking risk, only a
  boot-with-defaults risk.
- `<ssh><enabled>1</enabled></ssh>` gates sshd (`filter.lib.inc:123`); the sample ships
  `<ssh><group>admins</group></ssh>` with no `<enabled>`, so sshd is off unless added.
  `<permitrootlogin>`/`<passwordauth>` absent write `PermitRootLogin no` /
  `PasswordAuthentication no` (`plugins.inc.d/openssh.inc:172-183`) — the seed sets
  `<permitrootlogin>1</permitrootlogin>` and seeds root's `<authorizedkeys>` (key auth,
  password auth stays off) so every ssh-based step actually has a way in.
- `<primaryconsole>serial</primaryconsole>`/`<serialspeed>` are required too: absent,
  `system.inc`'s console setup (L1215-1293) writes no comconsole to loader.conf and the
  console goes dark after the FIRST seeded reboot — the only out-of-band path if ssh or
  the API ever breaks, gone for good.
- The API key/secret config.xml shape and hashing (`ApiKeyField.php`) and the root
  password hash (`password_hash($p, PASSWORD_BCRYPT, ['cost' => 11])`, `auth.inc:448`) —
  see `make-dut-seed.py`'s docstring for exactly what was verified.
- The `<ppps><ppp>` shape (`ptpid`/`type`/`if`/`ports`/`username`/`password`(base64)/
  `provider`(service-name)) and the WAN interface's `<ipaddr>pppoe</ipaddr>` sentinel —
  `src/www/interfaces_ppps_edit.php` L108-271, corroborated by the `case 'pppoe':`
  switches throughout `interfaces.inc` keyed on that same field.
- qemu chardev-socket console redirection (`-chardev socket,...,server=on,wait=off` +
  `-serial chardev:ID`) — qemu's own invocation docs (fetched this session). Every
  run.sh VM gets it plus an HMP `-monitor unix:...` socket; `run.sh down`'s fallback
  sends `system_powerdown` over the monitor socket.
- pkg's `signature_type: fingerprints` directory layout (`trusted/`/`revoked/`, a
  `function`/`fingerprint` UCL pair per file) — `freebsd/pkg`'s `libpkg/pkg_repo.c`
  (fetched this session); used by `tests/plugin/`, not by this VM directly.

### Networking

- **WAN** (n1, vtnet1): bridged onto `br-isp`, the same broadcast domain as the
  isp-netns/`isp` VM's accel-ppp server and the `client`/`mpdsrv` VMs. **Its PADI
  broadcasts share that domain** — same caveat the `isp` section above already notes for
  two accel-ppp servers; here it's one more PPPoE *client* dialing the same server, which
  is fine (accel-ppp handles concurrent sessions) as long as it uses its own account
  (below), not `lab` or `mpdlab`.
- **LAN** (n2, vtnet2): its own bridge `br-dut-lan` (not `br-lan`, which `client`/`lan`
  already use for router-mode measurement — kept separate so plugin-test API/ssh traffic
  never crosses that path). <LAB_HOST> itself gets `192.168.90.1/24` on `br-dut-lan`
  (`run.sh`'s `VM_BRIDGE2_HOST_IP`); dut's LAN is the static `192.168.90.2/24`
  (`dut-config.xml.tmpl`). Reach it as `ssh -J <LAB_HOST> root@192.168.90.2`, or from
  <LAB_HOST> itself directly — this is also where `tests/plugin/` points its API client.
- **n0** (vtnet0, user-mode NIC): present because `run.sh` always adds it, but left
  unassigned in the seed config — it has no route and nothing listens on it.

### PPPoE account

dut dials slot 1's `isp` accel-ppp (its WAN is on `br-isp`; dut is not slotted) with an
account `plugin-roundtrip.sh` generates per run: user `dutrun-<8 hex>`, a random hex
password. It is written into `/run/accel-ppp/chap-secrets` (tmpfs, 0600, same file and
`flock` as `lab-creds.sh`, see `lab/isp-netns/README.md` "Lab accounts") over ssh stdin,
and removed at teardown. Add and remove match that exact user only; the `dutrun-` prefix
is disjoint from `lab-creds.sh`'s `labrun-`, so concurrent functional runs and dut runs
never remove each other's accounts.

- service-name `lab` (`make-dut-seed.py --pppoe-service-name`): the lab accel-ppp's
  `[pppoe]` section offers only `service-name=lab` (`lab/isp-netns/accel-ppp.conf`, same
  on the isp VM), so a PADI for any other name (an earlier seed asked for
  `if-pppoe-plugin`) gets no PADO and the WAN never comes up. The per-run `dutrun-`
  account, not the service name, keeps dut's sessions apart from the functional runs'.

### Usage

```
./fetch-image.sh dut                  # fetch+convert the OPNsense base image (once)
./plugin-roundtrip.sh -v -s           # one full run; extra args go to pytest

# optional, both consumed between provisioning and pytest -- see below:
DUT_KERNEL_SET=https://pkg.opnsense.org/FreeBSD:14:amd64/25.7/sets/kernel-25.7.11-amd64.txz \
IFPPPOE_REPO_TARBALL=/path/to/repo.tar.gz \
    ./plugin-roundtrip.sh -v -s
```

`plugin-roundtrip.sh` refuses if dut is already running. Per run it:

1. generates an ephemeral root ssh key (0700 local tmpfs dir), an API key+secret and the
   PPPoE account, held in shell variables and passed to children by per-command env,
   never argv;
2. creates `/dev/shm/<LAB_DIR>-dut-run.XXXXXX/dut-run.qcow2` on <LAB_HOST>, a qcow2
   overlay backed by `images/dut.qcow2`, and boots dut from it (`run.sh`'s
   `LAB_RUN_DRIVE`). `provision-dut.sh` refuses any drive that is not on tmpfs, so the
   seeded `config.xml` (API secret hash, PPPoE password, root's ssh pubkey) is only ever
   written to that overlay and the base stays the never-provisioned install;
3. runs `pytest tests/plugin`;
4. tears down with INT/TERM ignored, credentials first: removes the accel-ppp account,
   scrubs the seed ISO, shreds the local run dir, then `run.sh dut down` and deletes the
   overlay. Overlays left by a SIGKILLed run are deleted at the next run's start.

A `dut.qcow2` that was ever booted and provisioned directly (before this scheme) holds
old credentials in its clusters: re-fetch it with `./fetch-image.sh dut`.
`snapshot-dut.sh` is not part of the flow; never snapshot a provisioned disk.

#### Optional: installing a kernel set (`DUT_KERNEL_SET`)

`DUT_KERNEL_SET=<url or local path>` (e.g.
`https://pkg.opnsense.org/FreeBSD:14:amd64/25.7/sets/kernel-25.7.11-amd64.txz`) runs
between provisioning and pytest, so the plugin's kmod (built against 25.7.11) runs
against a matching kernel instead of the nano image's 25.7 RELEASE one:

1. fetched (`curl`, URL) or `scp`'d (local path) into a throwaway tmpfs dir on
   <LAB_HOST>; its sha256 is always logged, and checked against a published
   `<set>.sha256` if one exists. pkg.opnsense.org publishes only a per-set `.sig` (an RSA
   signature `opnsense-verify` checks), no sha256 file, next to kernel sets (confirmed by
   listing `.../sets/` this session) — so in practice this is log-only.
2. the expected `kern.build_id` is read off the set's own `boot/kernel/kernel` with
   `readelf -n` (falling back to `file -b`), or taken from `DUT_EXPECT_BUILD_ID`.
3. copied to dut and installed the way `opnsense-update -k` does — mirrors
   `install_kernel()` in opnsense/update's `src/update/opnsense-update.sh.in`: move
   `/boot/kernel` (+ its `/usr/lib/debug` twin, if present) to `.old`, `tar -C / -xpf` the
   set (`--exclude="^.abi_hint"`), `kldxref`. The set carries its own
   `/usr/local/opnsense/version/kernel` stamp itself — opnsense/tools's `build/kernel.sh`
   calls `setup_version ... kernel`, which `build/common.sh`'s `setup_version()` writes
   into the staged tree the set is built from — `opnsense-update.sh.in` never writes that
   path itself (only ever written for `pkgs`), so the plain tar extraction reproduces it.
4. dut is rebooted and polled for ssh the same way provisioning does.
5. `sysctl -n kern.build_id` on dut is asserted equal to the expected build id.

kernel.txz isn't treated as a secret (teardown just `rm -rf`s its tmpfs dir); the
ephemeral root key IS copied to <LAB_HOST> tmpfs transiently, to scp/ssh into dut
directly over `br-dut-lan` (no `-J` jump needed from there), and is shredded right after.

#### Optional: serving the plugin repo (`IFPPPOE_REPO_TARBALL`)

`IFPPPOE_REPO_TARBALL=<path to repo.tar.gz>` (a flat `./meta.conf`, `./packagesite.pkg`,
`./*.pkg` at its root — `plugin/build`'s output) is untarred into a throwaway tmpfs dir on
<LAB_HOST> and served with `python3 -m http.server --bind 192.168.90.1 $IFPPPOE_REPO_PORT`
(default port `8090`) for the run's lifetime — dut reaches <LAB_HOST> over `br-dut-lan`,
the same path it uses for the API/ssh. `IFPPPOE_REPO_URL` is exported for
`tests/plugin/test_roundtrip.py`'s `REPO_URL`; teardown kills the server and removes the
tmpfs dir.

A flat layout matches how `tests/plugin/repo_registration.py`'s `repo_conf()` uses its
`url` argument: verbatim, as the repo's `url:` in `pkg.conf(5)`. pkg's `pkg-repository.5`
says the catalogue files (`meta.conf`, `packagesite.pkg`, ...) live at the
`REPOSITORY_ROOT` the `url` names, with no `${ABI}` subpath appended unless the url
itself contains a literal `${ABI}` token — which `repo_conf()` doesn't add.

### plugin-upgrade.sh: the plugin across a real major upgrade

`plugin-upgrade.sh` runs a real OPNsense 26.1 -> 26.7 upgrade (FreeBSD:14 -> FreeBSD:15) on
`dut` with the plugin armed. It checks the upgrade prefetch: the `upgrade` syshook fetches
the FreeBSD:15 packages, and the first 26.7 boot installs them offline in the early syshook,
so kernel PPPoE is armed on that boot (`docs/plugin/INSTALL.md` "OPNsense major upgrades").
It shares `dut-lib.sh` with `plugin-roundtrip.sh`: the tmpfs overlay, the per-run key, API
key and PPPoE account, and the repo server on 192.168.90.1.

**Path.** System -> Firmware -> Upgrade and `configctl firmware upgrade` run core's
`upgrade.sh`, which calls `opnsense-update -u` without naming a release. opnsense-update then
reads the target from `UPGRADE_RELEASE` in `/usr/local/etc/opnsense-update.conf`
(opnsense/update `src/update/opnsense-update.sh.in`: `-u` implies `-R`). core ships that hint
only in the last releases of a series: stable/26.1 `src/etc/opnsense-update.conf.in` got
`UPGRADE_RELEASE="26.7"` and the 26.7 fingerprint on 2026-07-15 (8cc69b21e0f4), after the
26.1.11 tag. So a box must take the minor update to the latest 26.1 first. The driver runs it
the way the GUI does (`configctl firmware flush` + `configctl firmware update`), repeating it
until `opnsense-update -vR` prints 26.7. Then it runs `configctl firmware upgrade`. The 26.7
sets come from the box's own ABI tree: `FreeBSD:14:amd64/26.1/sets/` lists `kernel-26.7`,
`base-26.7` and `packages-26.7`. Plain amd64 nano gets no device suffix: opnsense-update adds
one only when `kern.ident` contains a `-`, and here the kernel is `SMP`.

**Start image.** By default (`UPGRADE_FROM=26.1`) the driver boots the official 26.1.6 nano
image. That is the newest 26.1 nano in `pkg.opnsense.org/releases/26.1/`, so its minor update
is the shortest. `UPGRADE_FROM=25.7` boots `dut.qcow2` (25.7 nano) instead and adds two legs:

1. 25.7 -> latest 25.7.x -> 26.1, with the plugin installed but not enabled. This leg checks
   that the prefetch is a no-op on a same-ABI upgrade: the hook runs, nothing is prefetched,
   and the packages stay FreeBSD:14.
2. 26.1 -> latest 26.1.x.

Starting from 26.1 is still faithful for the feature under test, because only the
FreeBSD:14 -> 15 step crosses ABIs, and it saves about 40 min. Prepare the image once:

```
OPNSENSE_VERSION=26.1.6 OPNSENSE_IMG_BASE_URL=https://pkg.opnsense.org/releases/26.1 ./fetch-image.sh dut
```

That produces `images/OPNsense-26.1.6-nano-amd64.img.qcow2`. An existing `dut.qcow2` is left
as it is. The driver overlays the new image directly, at `VM_OVERLAY_SIZE`.

The nano image's own config would put `/var` in RAM (opnsense/tools `config/*/extras.conf`
`nano_hook` sets `<use_mfs_var/>`). The seeded `config.xml` replaces that config and does not
set it, so the staged sets and `/var/cache/if_pppoe` survive the upgrade's reboots.

**Internet access (no change on `$VMHOST`).** The upgrade needs pkg.opnsense.org and
nashant.github.io. dut gets them over its own PPPoE WAN: the lab isp NATs dut's traffic out of
its qemu user-mode NIC, which already has internet (provision-isp.sh runs `apt-get` through
it). For the run:

- dut's PPPoE account is pinned to `UPGRADE_DUT_WAN_IP` (default `10.99.0.250`, outside accel's
  `10.99.0.100-199` pool). The pin is the 4th field of the accel secrets line, which accel
  1.14.0 makes the session's `peer_addr` (`accel-pppd/extra/chap-secrets.c`). The driver
  checks that pppoe0 really got that address.
- On `isp1` the driver adds one nftables table, `ip if_pppoe_upgrade`, with three parts:
  - masquerade for that source address out of the isp's default-route NIC;
  - DNAT of that source's DNS to 10.99.0.1 (accel's `dns1`) to the isp's own resolver (the
    one in `/etc/resolv.conf`, else slirp's 10.0.2.3);
  - a forward filter that lets only that address through. If `ip_forward` was 0, nothing
    else is forwarded. If it was 1, nothing else may use the uplink.
- It sets `net.ipv4.ip_forward=1` and saves the old value in `/run/if_pppoe-upgrade.forward`.
- If `nft` is missing, it installs the `nftables` package and leaves it installed.

Teardown runs on every exit path. It deletes the table, restores `ip_forward` from that file
and removes the account.

On `$VMHOST` the driver changes nothing beyond what the roundtrip already does: the tmpfs
overlay and repo dir, and the `http.server` bound to 192.168.90.1. That host is a
Cilium/Docker node whose iptables-nft tables say "do not touch", so a host-side NAT was ruled
out. This route also carries the upgrade's downloads over the plugin's own PPPoE WAN, which is
the kernel driver once it is armed, as on a real box.

After a SIGKILLed run, clean up on isp1 by hand:

```
sudo nft delete table ip if_pppoe_upgrade
sudo sysctl -w net.ipv4.ip_forward=$(cat /run/if_pppoe-upgrade.forward)
sudo rm /run/if_pppoe-upgrade.forward
```

Then delete the `dutrun-` line from `/run/accel-ppp/chap-secrets`.

**Packages under test.** The driver takes a FreeBSD:14 build of the branch that has a `.ko`
for the latest 26.1 kernel. It checks that coverage before enabling the plugin, and stops with
a message if the kernel is not covered. Pass the build in two variables:

- `IFPPPOE_REPO_TARBALL`: the flat repo, served the same way as the roundtrip's;
- `IFPPPOE_REPO_SIGNING_PUBKEY_PATH`: the `.pub` that signed it.

Build it on the `build` VM in kernels-json mode, from the release's `kernels.json`:

```
gh release download v0.5.1 -R nashant/if_pppoe -p kernels.json -O /tmp/kernels.json
jq '[.[] | select(.abi == "FreeBSD:14:amd64" and .series == "26.1")]' /tmp/kernels.json > /tmp/k14.json
#   (UPGRADE_FROM=25.7: drop the series filter so the 25.7 kernels are covered too)
bash -c 'source lab/vm/common.sh && vm_ssh build "cat > /home/freebsd/k14-upgrade.json"' < /tmp/k14.json
PLUGIN_ABIS="25.7 26.1" lab/vm/pkg-build.sh --local-out ./pkgout-upgrade14 <feat/upgrade-prefetch worktree> -- \
    --kernels-json /home/freebsd/k14-upgrade.json --abi FreeBSD:14:amd64 --version 0.5.1 \
    --key /home/freebsd/.if_pppoe-lab-upgrade.key --gen-key
bash -c 'source lab/vm/common.sh && vm_ssh build "cat /home/freebsd/.if_pppoe-lab-upgrade.pub"' > ./pkgout-upgrade14/lab-upgrade.pub
```

`PLUGIN_ABIS="25.7 26.1"` matches CI's FreeBSD:14 package (`.github/scripts/freebsd-build.sh`
`phase_package`).

**Version.** Build the branch as `--version 0.5.1`. That is the version of the published
FreeBSD:15 packages the prefetch fetches, so the downgrade guard never sees a newer installed
version (`pkg version -t` compares equal versions as `=`). Before the upgrade the driver stops
if the installed `os-if-pppoe` compares `>` to `PUBLISHED_VERSION` (default 0.5.1).

**Published repo.** Also before the upgrade, the driver points `IfPppoe` at the published
repo. It fetches two files from the Pages site: `client-conf/repos/IfPppoe.conf` (url
`https://nashant.github.io/if_pppoe/${ABI}`, as `gen-repo-conf.sh` writes it) and the release
fingerprint, which replaces the lab one. The prefetch therefore reads a real, signed
FreeBSD:15 catalogue. v0.5.1 covers the 26.7 kernel the upgrade installs.

**Run.** isp1 must be up and dut down. Expect about 60-80 min from 26.1 and about 2 h from
25.7 (estimates, not yet timed).

```
IFPPPOE_REPO_TARBALL=./pkgout-upgrade14/repo.tar.gz \
IFPPPOE_REPO_SIGNING_PUBKEY_PATH=./pkgout-upgrade14/lab-upgrade.pub \
    lab/vm/plugin-upgrade.sh
```

Optional variables:

- `UPGRADE_FROM`
- `UPGRADE_BASE_IMAGE`, a file under `images/`
- `UPGRADE_OUT_DIR`, default `./plugin-upgrade-out/<UTC stamp>`
- `UPGRADE_DUT_WAN_IP`, `UPGRADE_UPSTREAM_DNS`
- `PUBLISHED_REPO_BASE`, `PUBLISHED_VERSION`, `PREFETCH_READY_LINE`
- timeouts: `UPDATE_TIMEOUT`, `UPGRADE_STAGE_TIMEOUT`, `UPGRADE_REBOOT_TIMEOUT`,
  `BOOT_TIMEOUT`

**Assertions.** The driver checks these after the final 26.7 boot. It runs every check and
fails the run at the end if any of them failed:

- the upgrade's firmware log has
  `abi-heal: prefetch: ready in /var/cache/if_pppoe/prefetch/FreeBSD-15-amd64`;
- `pkg config abi` and the `%q` of both packages are `FreeBSD:15:amd64`;
- `/var/run/if_pppoe/boot.json` is `enabled`/`ok`, stamped on this boot;
- `/conf/if_pppoe/abi-heal.json` is `offline`/`healed`, from FreeBSD:14 to FreeBSD:15;
- the prefetch dir is gone;
- `pkg update -f -r IfPppoe` succeeds and offers `os-if-pppoe` for FreeBSD:15;
- `if_pppoe.ko` is loaded;
- the WAN is up on the pinned address, and the API reports `wan` on the `kernel` backend;
- the console capture shows exactly 3 boots after the upgrade's reboot (`-B`, `-P`, final),
  and `kern.boottime` stays the same afterwards (no extra reboot);
- the final boot's console section has no `>>> Error in` syshook line and no
  syslog-ng/devd/configd errors.

The driver also reports two things without asserting them:

- the early hook's duration: the console timestamps from `>>> Invoking early script
  'if-pppoe'` to the next line not starting with `if_pppoe:`, and the `abi-heal.json` and
  `boot.json` `at` stamps against `kern.boottime`;
- syslog-ng/devd/configd error lines in `/var/log/system/latest.log`.

`UPGRADE_OUT_DIR` holds no secrets. It keeps:

- the firmware logs: `*.progress.log`, plus the kept `.update.log` and `.upgrade.log`;
- the timestamped console: `console.log` and `final-boot-console.log`;
- the JSON state, `dmesg -a` and the system log.

The console capture is a second reader of the qemu chardev socket. It connects only after
provisioning's console step has finished.

Inside the `client` VM's guest disk:
- `/boot/kernel.SMP/` — the SMP kernel + flat modules, installed as an *alternate* boot
  kernel (`kernel="kernel.SMP"` in `/boot/loader.conf`). The stock kernel at `/boot/kernel/`
  is untouched and remains the fallback.
- `/usr/local/etc/mpd5/mpd.conf` — two labels, `lab` (dials isp-netns accel-ppp, service
  `lab`) and `mpdlab` (dials `mpdsrv`, service `mpdlab`, requests RFC4638 max-payload
  1500); `default:` picks whichever was loaded last. Switch with:
  `sed -i '' 's/load lab/load mpdlab/' mpd.conf && service mpd5 restart` (and back).

## Resetting a VM

```
./run.sh <name> down
ssh <LAB_HOST> 'rm -f ~/if_pppoe-lab/images/<name>.qcow2 ~/if_pppoe-lab/images/<name>-seed.iso'
./fetch-image.sh <name>
./run.sh <name> up
```

## Booting the stock kernel on `client` (fallback)

`/boot/loader.conf` has `autoboot_delay="-1"` (from the base cloud image) — to reach the
interactive loader prompt at all, first raise it: `sysrc -f /boot/loader.conf
autoboot_delay=10`, reboot, then at the loader prompt (any key during the countdown) run
`unset kernel` then `boot`, or `boot kernel`, per `loader(8)`. Not exercised in this task
(NEEDS_VERIFICATION if actually required — see task-5-report.md).

## Known issue: mpd5 RFC4638 max-payload does not reach 1500 on the wire

See `task-5-report.md`'s BLOCKED section. Summary: mpd5 5.9_19 (FreeBSD 14.3 pkg) accepts
`set pppoe max-payload 1500` (once `set link mru` is raised above 1500, e.g. 1501 — it
otherwise parse-errors "not in a range of 1492..1500" for both 1500 and 1499) and the
`mpdlab` PPPoE session still comes up correctly (right IP pool, PAP/CHAP auth), but a
packet capture of the PADI/PADR shows mpd5 never actually emits the RFC4638
PPP-Max-Payload PPPoE tag (0x0120) on the wire, so the peer never sees a request and
`ifconfig pppoe0` stays at the standard 1492 MTU. `verify-lab.sh` reports this as two
expected FAILs. `set pppoe max-payload` is documented client-only
(mpd.html doc chapter 49), so `mpdsrv`'s own `set pppoe max-payload 1500` line is
plausibly a no-op there too; its `set link mtu/mru 1500` is what would actually let the
server side accept a 1500-byte frame if the client ever sent one.
