# Lab kernel patches

`smpw-rss-invariants.patch` — applied to the build VM's opnsense/src
checkout by `build-kernel.sh setup` whenever KERNCONF != SMP (i.e. before
building the SMPW WITNESS/INVARIANTS debug kernel).

Without it, the SMPW kernel panics at every boot (~65s in, right after rc
completes): `panic: netisr_getqlimit(9): protocol not registered for
ip_direct`. Root cause: `net.inet.ip.intr_direct_queue_maxlen` (and the
ip6 equivalent) is a `#ifdef RSS` sysctl whose handler calls
netisr_getqlimit/netisr_setqlimit unconditionally, while `ip_direct` is
only registered `if (rss_get_enabled())` — which is false on the lab
client. On the release SMP kernel the KASSERT is compiled out and every
read/write of the oid silently no-ops, so nothing noticed; under
INVARIANTS the KASSERT panics. Any access (read or write) to the oid
panics the kernel — some boot-time rc service (identified empirically,
not pinned down) touches it on every boot. The patch mirrors the
`rss_get_enabled()` registration condition in the two handlers instead of
asserting, so the oid reads back 0 and writes no-op when RSS is disabled
at runtime — exactly the release kernel's observable behavior.

Idempotency: setup only applies it when the marker comment
("Lab SMPW (INVARIANTS) workaround") is absent, so re-running setup is
safe. Regenerate it from a patched build VM with:
`./vm/run.sh build ssh -- 'git -C ~/if_pppoe-lab/src diff -- \
sys/netinet/ip_input.c sys/netinet6/ip6_input.c'`
