# isp-netns — PPPoE server lab on `<LAB_HOST>`

Creates a self-contained PPPoE-server lab in a new network namespace on
`<LAB_HOST>`, without touching the host's own production trunk interface or
any of its other production networking. Everything lives in a new bridge (`br-isp`), a new netns
(`isp`), and one veth pair (`isp0` on the host / `eth0` inside `isp`).

## What it creates

- `br-isp` — a Linux bridge on the host (no IP; just a port for veth ends).
- netns `isp` — contains `eth0` (10.99.0.1/24), `accel-pppd`, and `iperf3 -s`.
- veth pair `isp0` (host, bridged to `br-isp`) / `eth0` (in `isp`).
- accel-pppd listens for PPPoE discovery on `eth0` inside `isp`, service-name
  `lab`, ac-name `isp-lab`, hands out addresses from `10.99.0.100-199` via
  CHAP-MD5/PAP against `/run/accel-ppp/chap-secrets` (tmpfs). There is no
  fixed account: see "Lab accounts" below.

## Lab accounts

No PPPoE account is committed or provisioned anywhere. Every run that dials
generates its own, installs it for the run's lifetime and removes it again:

- **Generated**: user `labrun-s<slot>-<8 hex>`, a 32-character random password
  (`secrets` in `tests/functional/labcreds.py`; `openssl rand` in
  `lab/vm/lab-creds.sh` and `smoke.sh`). Held only in the run's memory /
  shell variables.
- **accel-ppp**: one `user * secret *` line in `/run/accel-ppp/chap-secrets`
  (dir 0700, file 0600; `/run` is tmpfs), written over ssh **stdin**, never
  argv, under `flock`. Only the run's exact user is replaced or removed, so
  every other account (another slot's, another run's, `dutrun-`) survives.
  `accel-ppp.conf`'s `[chap-secrets] chap-secrets=` points there. No
  `accel-cmd reload` is needed: the chap-secrets module `fopen()`s and reads the file on every authentication (`create_pd()`,
  called from `get_passwd()`/`check_passwd()`, in
  <https://github.com/accel-ppp/accel-ppp/blob/1.14.0/accel-pppd/extra/chap-secrets.c>;
  its `EV_CONFIG_RELOAD` handler only re-reads the conf options).
- **mpd5** (the mpdsrv server and the client VM): a tmpfs is mounted over
  `/usr/local/etc/mpd5` (mpd5's config directory -- the default `mpd -d dir`
  overrides, <https://mpd.sourceforge.net/doc5/mpd10.html>), the on-disk
  `mpd.conf` (no secrets) is copied in, and the run's `mpd.secret` line
  (server; exact-user add/remove, unmounted once no account is left) or
  password-bearing `mpd.conf` (client) is written there 0600. Unmounting
  it brings back the untouched on-disk files. FreeBSD tmpfs(5): `mode` sets
  the root inode's mode.
- **Client**: `pppoectl -S` reads the secret from stdin; mpd5 gets it only
  via that tmpfs `mpd.conf`; `smoke.sh`'s pppd via a 0600 options `file` in
  `/run`.
- **Teardown**: pytest's session-scoped `lab_creds` fixture, the probes'
  `lab_session()`, and a `trap ... EXIT` in the shell scripts.
  `LAB_SLOT=N lab/vm/lab-creds.sh teardown` removes slot N's `labrun-sN-`
  accounts after an interrupted run (the only prefix match).
  `lab/vm/perf-backend.sh` removes the account as soon as `pppoe0` is up
  (accel-ppp only checks it at authentication), so a mid-run redial fails.
- **One account per run**: each pytest session and each probe script
  (`hardening_probe.py`, `unload_probe.py`) owns exactly one; the job
  harness (`job-common.sh`, `batch-suite.sh`, `verify-branch.sh`) generates
  none.
- **stdin through su(1)**: on the FreeBSD guests `su -m root -c CMD` reads
  no prompt line from a non-tty stdin, so the secret is sent as CMD's stdin
  with no leading blank line (one would become CMD's first line: an empty
  `pppoectl -S` secret, an empty `mpd.secret` line).

## Deploying to `<LAB_HOST>`

Deploys under the shared lab state root `~/if_pppoe-lab/` that `lab/vm/`
(task 1/4) already established on this host, alongside its `images/`/`run/`:

```
scp -r lab/isp-netns <LAB_USER>@<LAB_HOST>:~/if_pppoe-lab/isp-netns
```

(or `rsync -a lab/isp-netns/ <LAB_HOST>:~/if_pppoe-lab/isp-netns/`).

## Running

```
ssh <LAB_HOST> '~/if_pppoe-lab/isp-netns/install-accel-ppp.sh'   # once
ssh <LAB_HOST> '~/if_pppoe-lab/isp-netns/up.sh'
ssh <LAB_HOST> '~/if_pppoe-lab/isp-netns/smoke.sh'               # client test, self-cleaning
ssh <LAB_HOST> '~/if_pppoe-lab/isp-netns/down.sh'                # full teardown
```

`up.sh` and `down.sh` are idempotent: running either twice is a no-op the
second time (checks `ip link show`, `ip netns list`, `pgrep` before acting).

### PEER_VLAN (Task 11: hardware PPPoE peer)

`PEER_VLAN=<vid> ./up.sh` (optionally `PEER_TRUNK=<ifname>`, default
`bond0`, the host's own production trunk interface) creates an 802.1Q
subinterface `$PEER_TRUNK.$PEER_VLAN` (e.g. `bond0.<VID>`), never assigns it
a host IP, and attaches it as a port of `br-isp` -- so PPPoE frames from a
real router, reaching `<LAB_HOST>` tagged with that VLAN over the existing
LAN trunk, arrive at `accel-pppd` through the same bridge the VMs use. Its
MTU is 1508 only if `$PEER_TRUNK`'s MTU already allows it, else 1500 (a
VLAN subinterface's MTU cannot exceed its parent's; this task never changes
`$PEER_TRUNK`'s own MTU). `PEER_VLAN=<vid> ./down.sh` deletes the
subinterface (which also detaches it from the bridge). Unset (the
default), behaviour is unchanged. Never touches `$PEER_TRUNK`'s own
configuration, membership, or MTU. See `../peer/README.md` for the topology
and the router/switch side of this.

## Deployment directory / config rendering

`accel-ppp.conf` in this directory is a **template** (its `chap-secrets=` is
the fixed tmpfs path `/run/accel-ppp/chap-secrets`, see "Lab accounts"; no
line currently uses `@LABDIR@`). Every `up.sh` run does `sed s#@LABDIR@#$SCRIPT_DIR#g accel-ppp.conf >
accel-ppp.rendered.conf` (`$SCRIPT_DIR` = wherever this directory was
deployed to) and starts `accel-pppd -c accel-ppp.rendered.conf`. This means
the deployment path is no longer a single point of failure baked into a
committed file — moving the whole `isp-netns/` directory (as happened once,
see "Deviations from the brief") only requires re-running `up.sh`, not
editing `accel-ppp.conf`. `down.sh` removes the rendered file and the pidfile
on teardown; the template `accel-ppp.conf` is never modified in place.

## Verifying

```
sudo ip netns exec isp accel-cmd show stat
sudo ip netns exec isp accel-cmd show sessions
sudo ip netns exec isp ss -lntp        # iperf3 on :5201, accel-ppp cli on :2000/:2001
```

`smoke.sh` is the PPPoE client-side check: it creates a temporary `cli` netns
with its own veth into `br-isp`, runs `pppd plugin pppoe.so cli-eth0 file
<tmpfs options file> noauth nodetach debug` with a per-run account inside it for ~10s (client-side
interface named `cli-eth0`, not `eth0` — see "Deviations from brief"), and
greps the captured log for `local  IP address 10.99.0.1xx` (IPCP address assignment
from the pool). It tears `cli` down on exit (trap) regardless of pass/fail;
`isp` is left running.

## Persistent host changes (not reversed by down.sh)

`down.sh` only undoes what `up.sh` creates (bridge/netns/veth/processes).
`install-accel-ppp.sh` makes changes to <LAB_HOST> that persist across `down.sh`
and are **not** uninstalled by anything in this directory:

- apt packages: `build-essential cmake libpcre2-dev libssl-dev
  liblua5.1-0-dev git qemu-system-x86 qemu-utils bridge-utils iproute2
  iperf3 pppoe` (the last one pulls in `ppp` as a dependency).
- `accel-pppd`/`accel-cmd` and the accel-ppp module `.so`s, installed via
  `sudo make install` to `/usr/local/{sbin,bin,lib64/accel-ppp}` (also
  `/usr/local/share/man`, `/usr/local/etc/accel-ppp.conf.dist`,
  `/var/log/accel-ppp/`, `/usr/local/var/{log,lib}/accel-ppp/`).
- the `accel-ppp-src` git checkout under this directory (moves with it if
  the directory is redeployed elsewhere; harmless to leave, needed to
  rebuild without re-cloning).

## accel-ppp.conf option reference

All option names below are verified against `accel-ppp.conf(5)`:
<https://raw.githubusercontent.com/accel-ppp/accel-ppp/master/accel-pppd/accel-ppp.conf.5>
(fetched from the brief's URL), cross-checked against the shipped example
`accel-pppd/accel-ppp.conf` in the same repo (commit recorded in
`.accel-ppp-commit` after `install-accel-ppp.sh` runs) — none were guessed.

| Section | Option | Man page text (accel-ppp.conf(5)) |
|---|---|---|
| `[modules]` | `log_file` | "logs messages to files" |
| `[modules]` | `pppoe` | "PPPoE discovery stage handling module" |
| `[modules]` | `chap-secrets` | "Authentication and address assignment from a pppd-compatible chap-secrets file" |
| `[modules]` | `auth_pap`, `auth_chap_md5` | PAP / CHAP-MD5 authentication modules |
| `[modules]` | `ippool` | "IPv4 address assigning module" |
| `[modules]` | `ipv6pool` | "IPv6 address assigning module" |
| `[modules]` | `ipv6_nd` | "IPv6 Neighbor Discovery and Router Advertisement module" |
| `[modules]` | `ipv6_dhcp` | "IPv6 DHCP module" |
| `[pppoe]` | `interface=[re:]ifname` | "Specifies interface name to listen/send discovery packets" |
| `[pppoe]` | `service-name=` | "Specifies Service-Name to respond. If absent any Service-Name is acceptable" |
| `[pppoe]` | `ac-name=` | "Specifies AC-Name tag value. If absent tag will not be sent" |
| `[pppoe]` | `accept-blank-service=n` | "Allow answering on blank Service-Name even if Service-Name configured" |
| `[ppp]` | `mtu=n` | "MTU which will be negotiated if client's MRU will be not acceptable" |
| `[ppp]` | `mru=n` | "Prefered MRU" |
| `[ppp]` | `min-mtu=n` | "Minimum acceptable MTU" |
| `[ppp]` | `max-mtu=n` | "the absolute maximum MTU value that can be negotiated" (1500 allows RFC 4638 attempts) |
| `[ppp]` | `ipv4=require` | IPCP negotiation algorithm: deny\|allow\|prefer\|require |
| `[ppp]` | `ipv6=allow` | IPv6CP negotiation algorithm: deny\|allow\|prefer\|require |
| `[ppp]` | `lcp-echo-interval=n` | "send echo-request every n seconds" |
| `[ppp]` | `lcp-echo-failure=n` | "maximum number of echo-requests may be sent without valid echo-reply" |
| `[ip-pool]` | `gw-ip-address=x.x.x.x` | "single IP address to be used as local address of ppp interfaces" |
| `[ip-pool]` | `x.x.x.x-y` | pool range syntax, e.g. `192.168.0.2-255` in the shipped example conf |
| `[ipv6-pool]` | `ipv6prefix/mask,prefix_len` | pool range syntax, e.g. `fc00:0:1::/48,64` in the shipped example conf |
| `[chap-secrets]` | `chap-secrets=file` | "Specifies alternate chap-secrets file location (default is /etc/ppp/chap-secrets)" |
| `[chap-secrets]` | `gw-ip-address=` | also settable per-module in `[chap-secrets]` |
| `[cli]` | `telnet=host:port` | "Defines on which IP address and port the Telnet module will listen" |
| `[cli]` | `tcp=host:port` | "Defines on which IP address and port the TCP module will listen" |
| `[log]` | `log-file=file` | "Path to file to write general log" |

The `chap-secrets` *file* (not the `.conf` section) format — `user  service
secret  ip` — isn't documented in the man page; it was confirmed against the
project's own test fixture rather than guessed:
`tests/accel-pppd/pppoe/test_pppoe_session_chap_secrets.py` in
accel-ppp/accel-ppp uses `"loginCSAB     *           pass123   192.0.2.37"`.

`accel-pppd`'s CLI flags (`-c CONFIG -p PID -d`) come from
`accel-pppd/main.c` (`getopt_long` table), not a guess.

## Deviations from the brief

1. **Added `chap-secrets` to `[modules]`.** The brief's module list
   (`pppoe, auth_pap, auth_chap_md5, ippool, ipv6pool, ipv6_nd, ipv6_dhcp`)
   omits it, but `[chap-secrets] chap-secrets=<file>` (also requested by the
   brief) has no effect unless the `chap-secrets` module is loaded — it's the
   credential backend `auth_pap`/`auth_chap_md5` validate against. Without it
   every auth attempt fails (no pwdb source registered).
2. **Added `tcp=127.0.0.1:2001` to `[cli]`**, alongside the brief's
   `telnet=127.0.0.1:2000`. `accel-cmd` (used by the brief's own verification
   step: `accel-cmd show sessions`) speaks the raw TCP protocol on port 2001
   by default, not Telnet — see `accel-cmd(1)`: "-p PORT ... Defaults to
   2001." Telnet and TCP are documented as separate `[cli]` listeners in
   `accel-ppp.conf(5)`.
3. **`[ipv6-pool]` prefix** (`fc00:99:0:1::/64,64`) is not specified in the
   brief; chosen to satisfy `ipv6pool`/`ipv6_dhcp`/`ipv6_nd` being loaded
   without colliding with any routed prefix on <LAB_HOST>. Not exercised by
   `smoke.sh` (IPv4-only check, per the brief).
4. **`smoke.sh`'s client-side interface is named `cli-eth0`, not `eth0`**
   (the brief's smoke-test command uses `eth0`). Discovered during testing:
   naming both the `isp` netns's server interface and the `cli` netns's
   client interface `eth0` gave them the *identical* MAC address
   (`d6:b7:a8:62:a3:ab` on both, confirmed with `ip link show eth0` in each
   netns) — Ubuntu's persistent-MAC-by-name udev policy derives a veth's MAC
   from its ifname before the peer is moved into its target netns, so two
   same-named veth ends anywhere on the host collide. With identical MACs,
   `br-isp`'s FDB flip-flopped the address between the two ports and the
   bridge silently dropped accel-pppd's PADO instead of forwarding it back
   to the client (confirmed with `tcpdump -e` showing the PADO's src and dst
   MAC as the same address). Renaming the client-side interface avoids the
   collision; `smoke.sh` still runs
   `pppd plugin pppoe.so cli-eth0 file <tmpfs options file> noauth nodetach debug`.
5. **`smoke.sh`/`down.sh` scope process kills via `ip netns pids <ns> | xargs
   kill`, not `pkill`.** Discovered during testing: `ip netns exec <ns> pkill
   -f pppd` does not scope to that netns's processes — `ip netns exec` only
   changes the network (and mount) namespace, not the PID namespace, so `-f`
   substring-matched and killed the host-wide `accel-pppd` process too (comm
   `accel-pppd` contains `pppd`). Confirmed via `accel-ppp.log`:
   `terminate, sig = 15` fired at the exact moment `smoke.sh`'s cleanup trap
   ran. An interim fix used `pkill -x` (exact `comm` match), but review
   correctly flagged that `down.sh`'s own `pkill -x accel-pppd`/`pkill -x
   iperf3` have the same host-wide blast radius — `tests/perf` documents
   `--server HOST` as a standalone, non-netns `iperf3 -s` that could be
   running on <LAB_HOST> at teardown time. Both scripts now build the kill list
   from `ip netns pids <ns>` (network-namespace-scoped by construction, no
   name matching at all), SIGTERM, a bounded wait, then SIGKILL any
   stragglers.
6. **Deployment directory is `~/if_pppoe-lab/isp-netns/`, not
   `~/pppoe-lab/isp-netns/`.** The original deploy path didn't match the
   `~/if_pppoe-lab/` lab-root convention `lab/vm/README.md` (task 1/4)
   already established on this same host; moved for consistency (controller
   ruling) — see "Deployment directory / config rendering" above for how the
   `accel-ppp.conf` template avoids re-hardcoding the new path.
7. **Added `accept-blank-service=1` to `[pppoe]`.** Discovered during testing:
   a plain `pppd plugin pppoe.so` client (as the brief's own smoke-test
   command specifies) sends an empty Service-Name tag. With only
   `service-name=lab` set, accel-pppd discarded every PADI —
   `/tmp/accel-ppp.log` showed `warn: pppoe: discarding PADI packet
   (Service-Name mismatch)` (captured with `sudo tcpdump -i eth0 -e -n pppoed`
   confirming the PADI *did* arrive at the netns, so this was a config
   mismatch, not a bridging problem). `accel-ppp.conf(5)` [pppoe]:
   `accept-blank-service=n` — "Allow answering on blank Service-Name even if
   Service-Name configured." Fixes it while keeping `service-name=lab`.
8. **`up.sh`'s "already running" checks for `accel-pppd`/`iperf3` use a
   `netns_has_proc()` helper (walks `ip netns pids isp`, reads
   `/proc/$pid/comm`), not `ip netns exec isp pgrep -x NAME`.** Found while
   verifying fix round 1: with a standalone `iperf3 -s -p 5202` (simulating
   `tests/perf`'s use of <LAB_HOST> as a bare iperf3 host) already running
   outside any netns, `sudo ip netns exec isp pgrep -x iperf3` still matched
   it — same host-PID-namespace-sharing mechanism as item 5, just hitting an
   idempotency check instead of a kill. Result: `up.sh` silently skipped
   starting iperf3 *inside* `isp` (confirmed by `sudo ip netns pids isp`
   showing only accel-pppd's PID, and `ss -lntp` inside the netns missing
   port 5201).

## Sources

- accel-ppp.conf(5) (brief's URL): <https://raw.githubusercontent.com/accel-ppp/accel-ppp/master/accel-pppd/accel-ppp.conf.5>
- Shipped example config: <https://github.com/accel-ppp/accel-ppp/blob/master/accel-pppd/accel-ppp.conf>
- accel-cmd(1): <https://github.com/accel-ppp/accel-ppp/blob/master/accel-cmd/accel-cmd.1>
- chap-secrets file format test fixture: <https://github.com/accel-ppp/accel-ppp/blob/master/tests/accel-pppd/pppoe/test_pppoe_session_chap_secrets.py>
- `accel-pppd` CLI flags: <https://github.com/accel-ppp/accel-ppp/blob/master/accel-pppd/main.c>
