# Spikes (throwaway)

Kept as evidence, never built by `sys/modules/if_pppoe`.

- `s1-netisr/` — proves a `PFIL_TYPE_ETHERNET` hook plus a private netisr
  protocol (`NETISR_POLICY_CPU`, `NETISR_DISPATCH_HYBRID`, `nh_m2cpuid`)
  spreads decapsulated PPPoE frames across CPUs in the client VM, with
  `net.isr.maxthreads=4` / `net.isr.bindthreads=1` and the global
  `net.isr.dispatch` left at `direct`. Spec §6.4, risk §11 row 1.
- `s2-inaddr/` — proves IPv4/IPv6 addresses can be set on an interface from
  kernel context on FreeBSD 14.3 via `in_control_ioctl`/`in6_control_ioctl`.
  Spec §8 "Addresses", risk §11 row 2.

Build with `lab/vm/build-module.sh deploy spikes/<name> <name>.ko`.
