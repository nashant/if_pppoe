#!/usr/bin/env bash
# perf-target.sh — print the data-plane IP `iperf3 -c` must target for a
# test-perf-fwd BACKEND. Not an ssh-config.sh `lab-<name>` alias: those
# resolve only on this machine (ProxyJump to each VM's mgmt port) and even
# then name the isp VM's mgmt address, not its data-plane one on br-isp.
# One place mapping BACKEND -> that address, so lab/Makefile and
# tests/perf/test_perf_target.py can't drift apart.
# Usage: ./perf-target.sh <if_pppoe|mpd5|raw>
set -euo pipefail

case "${1:-}" in
    if_pppoe|mpd5)
        echo "10.99.0.1"   # accel-ppp gw pool, see provision-isp.sh's accel-ppp.conf
        ;;
    raw)
        echo "192.168.99.1"   # provision-isp-raw.sh's alias on the same bridged NIC
        ;;
    *)
        echo "perf-target.sh: BACKEND must be if_pppoe, mpd5, or raw (got '${1:-}')" >&2
        exit 1
        ;;
esac
