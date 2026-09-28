# lab/peer — `<LAB_HOST>` as the hardware PPPoE peer (Task 11)

The router-under-test's stock firmware turned out unusable as a PPPoE
server (task-9/task-10 reports), and a direct USB-NIC cable into a
production-trunk slave was ruled out in favor of a **VLAN sub-interface on
the existing LAN trunk** -- no change to the host's trunk config,
membership, or MTU, and no new cabling. The router reaches the same
`accel-pppd` that already serves the VMs by tagging PPPoE frames with a
dedicated VLAN over the trunk it's already connected on.

## Topology

```
<DUT>                                        <LAB_HOST>
+-------------+   existing LAN trunk    +------+   +--------------------------+
| router LAN  |------------------------>|switch|-->| bond0.<VID> (VLAN, no IP)  |
| port        |   VLAN <VID> tagged       +------+   |     |                    |
| PPPoE       |                                    |     v                   |
| client,     |                                    |  br-isp (bridge)         |
| service     |                                    |     |                   |
| "lab"       |                                    |     v                   |
+-------------+                                    |  isp0 (veth) -----------+---> netns isp
also on br-isp: tap-client, tap-mpdsrv (VMs)        |                          |  eth0 10.99.0.1/24
                                                    +--------------------------+  accel-pppd, iperf3
                                                                                   service "lab"

bond0 (the lab host's own production trunk, untouched): two NIC ports,
carries the host's other production traffic, MTU 1500.
```

`bond0.<VID>` is created and managed entirely by `lab/isp-netns/up.sh`
(`PEER_VLAN=<VID> ./up.sh`, `PEER_TRUNK` defaults to `bond0`) -- not the
host's own network config, so it never survives a reboot and carries no
host IP address; it exists only to hand tagged frames to `br-isp`.

## Switch requirement (not this task's to configure)

VLAN <VID> must be allowed, tagged, on both the router's LAN port and
`<LAB_HOST>`'s switch port -- neither side of this repo's scripts controls
the switch. Per the team's investigation (not independently re-verified in
this task): a tagged VLAN already passes over the same trunk to another
lab host's NIC, which is the evidence the trunk can carry tagged VLANs to
hosts at all; whether VLAN <VID> specifically is allowed to `<LAB_HOST>`'s
port still needs confirming against the switch config before the router
side can be wired up.

## Cabling

None needed -- this reuses the LAN trunk `<LAB_HOST>`'s `bond0` is already
cabled to (documented in `docs/TESTING.md` line 126: "LAN endpoint:
`<LAB_HOST>` `bond0`").

## MTU / RFC 4638

A VLAN subinterface's MTU can never exceed its parent's (kernel-enforced).
`bond0`'s current MTU is 1500 (confirmed: `cat /sys/class/net/bond0/mtu` ->
`1500`), so `bond0.<VID>` also comes up at MTU 1500, not 1508 -- there is no
headroom for a full RFC 4638 (PPPoE-tagged 1500-byte PPP payload) frame over
this path yet. `up.sh` checks `$PEER_TRUNK`'s MTU at run time and only sets
1508 if it's already >= 1508; **this task deliberately does not raise
bond0's MTU** (that would need coordinating with the host's other
production traffic and the switch, out of scope here). Until bond0's MTU is
raised (and the switch/router support the larger frame end to end), a
max-payload-1500 PPPoE test over this VLAN path (task-5's mpdsrv-style
RFC4638 check) will not be exercisable here -- same limitation already
logged for the VM-only lab in task-5's report.

## Capacity

Per the team's investigation (not independently re-verified in this task):
the router's LAN port supports roughly 2.3 Gbit/s full-duplex, comfortably
above the 2.5GbE link speeds already seen elsewhere in this lab, so this
path is not expected to be the throughput bottleneck for `tests/perf`'s
iperf3 matrix.

## Verifying

```
bridge link                              # confirm bond0.<VID> is a br-isp port
ip -br link show bond0.<VID>               # UP, no inet (host never assigns one)
ip -br addr show bond0                   # unchanged
cat /proc/net/bonding/bond0              # both slaves still up
../vm/verify-lab.sh                      # unchanged: 7 PASS / 2 FAIL
```

## Router-side steps (blocked on router root -- not part of this task)

1. Create VLAN <VID> on the router's LAN port.
2. Configure a PPPoE client on that VLAN interface.
3. Point it at service-name `lab`, credentials matching
   `../isp-netns/accel-ppp.conf` and `chap-secrets`.
4. Verify the router gets an address from the `10.99.0.100-199` pool.

## Rollback

```
PEER_VLAN=<VID> ../isp-netns/down.sh   # deletes bond0.<VID> (also detaches it from br-isp)
```

No netplan or bond0 state to restore -- nothing else in this design touches
either.
