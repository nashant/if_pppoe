# if_pppoe kmod: link events, link state and capability flags

The driver-side interface the plugin consumes to mirror mpd5's
`ppp-linkup` / `ppp-linkdown` scripts (risk register rows 4 and 16, C9).

## Capability flags

`kern.features.if_pppoe_<name>` reads `1` while a module that ships the
capability is loaded. A missing sysctl means the capability is absent. All
flags are declared together at the end of `sys/net/if_pppoe.c`.

| Flag | Meaning |
|---|---|
| `if_pppoe_linkevents` | the devctl records below, and link state driven only by the NCPs |

## Load gating

The module is declared with `DECLARE_MODULE_TIED`, so it depends on exactly
the kernel `__FreeBSD_version` it was built for, and `kldload` refuses any
other kernel. `__FreeBSD_version` stays the same across `-pN` patch
releases, so the plugin's per-`kern.build_id` module directories are still
needed. `MODULE_VERSION(if_pppoe, 1)`.

In the `.ko` this is a `MODULE_DEPEND(if_pppoe, kernel, V, V, V)` record,
where V is the build's `__FreeBSD_version`. The functional tests compare the
record in the deployed `.ko` with `kern.osreldate`. They also check that a
copy with V changed to V+1 fails `kldload` with the kernel linker's
`depends on kernel` message.

## devctl records

The driver emits these through devctl(4), so devd(8) matches them with
`system "PPPOE"`, `subsystem` set to the interface name and `type` set to the
event. Records are only emitted in the default vnet, the same rule the
kernel uses for its IFNET events.

| type | data | when |
|---|---|---|
| `SESSION_UP` | `session=N ac=xx:xx:xx:xx:xx:xx parent=IF` | PPPoE discovery reached SESSION (after PADS) |
| `SESSION_DOWN` | `session=N ac=xx:xx:xx:xx:xx:xx` | that session is gone (PADT received or sent, or clone destroyed) |
| `IPCP_UP` | `local=A remote=B dns1=C dns2=D mtu=M` | IPCP Opened and the negotiated address is on the interface (see Ordering); the addresses are the negotiated ones (`0.0.0.0` when none) |
| `IPCP_DOWN` | the same string the matching `IPCP_UP` carried | IPCP left Opened |
| `IPV6CP_UP` | `local=fe80::g:g:g:g remote=fe80::g:g:g:g mtu=M` | IPv6CP Opened and the link-local is on the interface. The groups are not compressed, so parse them rather than string-compare |
| `IPV6CP_DOWN` | the same string the matching `IPV6CP_UP` carried | IPv6CP left Opened |
| `AUTH_FAIL` | `proto=pap\|chap failures=N` | an authentication failure in the current LCP session: a rejection by the peer, or no answer at all (our request timing out, or the peer terminating LCP before it accepted us). Emitted when LCP goes down afterwards. A later PAP Ack or CHAP Success in the same session cancels it |

### Ordering

- `IPCP_UP` goes out only after the driver has put the negotiated address
  and peer on the interface (`SIOCAIFADDR`, from the driver's address task).
  A handler that runs core's `ppp-linkup.sh` from it can read the address
  back from the interface, the same as with mpd5, which runs its up-script
  after it has set the addresses. `IPV6CP_UP` likewise waits for the
  link-local, which the driver applies only once IPCP has an address. If
  `SIOCAIFADDR` fails, the driver logs the error and still sends the record.
- On the way up: `SESSION_UP`, then `IPCP_UP` / `IPV6CP_UP`.
- On the way down (PADT, a local disconnect, clone destroy): `SESSION_DOWN`
  can come **before** `IPCP_DOWN` / `IPV6CP_DOWN`. The session task sends
  `SESSION_DOWN` and then tells the PPP layer, whose NCP teardown runs later
  on its own workqueue. Do not treat `SESSION_DOWN` as the last record of a
  teardown.
- Each `*_DOWN` follows a matching `*_UP`. An NCP that opens and closes
  again before the driver's address task runs sends neither record.

devctl can drop records under memory pressure, so the plugin should
reconcile on the level (interface state and `pppoectl`), not rely on edges
alone.

## Link state

`LINK_STATE_UP` is set if and only if IPCP or IPv6CP is Opened. Only the sppp
layer writes it (`sppp_ncp_link()`), so each dial produces one IFNET
`LINK_UP` and each teardown one `LINK_DOWN`. Before this change the PADS
handler and every sppp phase change also wrote the link state, and a dial
went UP, DOWN, UP.
