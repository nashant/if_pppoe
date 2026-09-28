#!/usr/bin/env python3
"""iperf3 performance matrix runner for the if_pppoe Tier 0 / Tier 3 lab.

Runs, per --flows value: TCP download, TCP upload (-R), UDP 1400B download
and upload (both directions), and a UDP 64B PPS test (download only), each
for --duration seconds. Before/after each run it collects read-only DUT
metrics over ssh (no root needed); during each run it samples `top` on the
DUT across the whole run. Writes one JSON document per invocation to
tests/results/.

Any ssh/DUT-collector or iperf3-connection failure aborts the whole
matrix (prints the error and exits non-zero) rather than recording a
silently empty/fake-looking sample -- see ssh_collectors.py.

Usage:
    run_matrix.py --backend {mpd5,mpd5-tuned,if_pppoe,plain} \\
        --server HOST --client HOST [--duration 60] [--flows 1,4,8,16] \\
        [--out tests/results/<backend>-<UTCstamp>.json] --dut HOST \\
        [--dry-run]

See README.md for prerequisites and how results feed the pass criteria.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import parsers
import ssh_collectors as ssh

BACKENDS = ("mpd5", "mpd5-tuned", "if_pppoe", "plain", "raw")

# top -s <TOP_DELAY> is fixed; the iteration count is sized (via
# parsers.top_iterations_for) so the sample spans the whole run instead
# of only its first few seconds.
TOP_DELAY = 5


def build_run_specs(flows: list[int], server: str, duration: int) -> list[dict[str, Any]]:
    """Build the ordered list of iperf3 run specs for one flows value.

    Order per flows value: TCP download, TCP upload, UDP1400 download,
    UDP1400 upload, UDP64 download -- matching the brief's matrix
    definition verbatim.

    Direction is from the --client's (LAN side's) point of view: download =
    server -> client, which is iperf3's `-R` ("reverse the direction of a
    test, so that the server sends data to the client",
    https://software.es.net/iperf/invoking.html); upload = plain `-c`.
    Before this was fixed the two labels were swapped (plain `-c` was
    called "download"), so result files older than the fix have them
    inverted.
    """
    specs = []
    for n in flows:
        base = ["-c", server, "-P", str(n), "-t", str(duration), "-J"]
        specs.append({"flows": n, "proto": "tcp", "direction": "download", "pkt_len": None, "args": base + ["-R"]})
        specs.append({"flows": n, "proto": "tcp", "direction": "upload", "pkt_len": None, "args": base})
        udp_base = ["-c", server, "-u", "-l", "1400", "-b", "0", "-P", str(n), "-t", str(duration), "-J"]
        specs.append({"flows": n, "proto": "udp", "direction": "download", "pkt_len": 1400, "args": udp_base + ["-R"]})
        specs.append({"flows": n, "proto": "udp", "direction": "upload", "pkt_len": 1400, "args": udp_base})
        udp64_base = ["-c", server, "-u", "-l", "64", "-b", "0", "-P", str(n), "-t", str(duration), "-J"]
        specs.append({"flows": n, "proto": "udp", "direction": "download", "pkt_len": 64, "args": udp64_base + ["-R"]})
    return specs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", required=True, choices=BACKENDS)
    p.add_argument("--server", required=True, help="host where `iperf3 -s` is already listening")
    p.add_argument("--client", required=True, help="host that runs `iperf3 -c` over ssh")
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--flows", default="1,4,8,16", help="comma-separated flow counts")
    p.add_argument("--out", default=None, help="output JSON path (default: tests/results/<backend>-<UTCstamp>.json)")
    p.add_argument("--dut", required=True, help="device under test hostname (read-only metric collection)")
    p.add_argument(
        "--ssh-config", default=None,
        help="ssh client config file (`-F`) for --server/--client/--dut -- lets VM-lab "
             "host aliases (see lab/vm/ssh-config.sh) resolve through their ProxyJump",
    )
    p.add_argument("--dry-run", action="store_true", help="print the planned command list and exit")
    p.add_argument("--skip-udp64", action="store_true",
                   help="omit the UDP 64B PPS runs (they can stall a pf router "
                        "past any practical ssh report timeout at line rate)")
    p.add_argument("--skip-udp", action="store_true",
                   help="omit every UDP run (TCP download+upload only)")
    p.add_argument("--irq-prefix", default="igc",
                   help="vmstat -i label substring to diff per run (igc on the DUT, "
                        "virtio_pci in the VM lab)")
    p.add_argument("--root-cmd", default=None, metavar="TEMPLATE",
                   help="how to run a command as root on --dut, '{}' = the shell-quoted "
                        "command (e.g. 'sudo -n sh -c {}', or the lab client VM's "
                        "'echo | su -m root -c {}'). Enables the root-only collectors: "
                        "pfctl -si (pf enabled + NAT state count) and --lockstat.")
    p.add_argument("--lockstat", choices=("none", "max-flows", "all"), default="none",
                   help="sample lockstat(1) on --dut DURING runs (needs --root-cmd): "
                        "only the highest flow count's runs, or every run")
    args = p.parse_args(argv)
    if args.lockstat != "none" and not args.root_cmd:
        p.error("--lockstat needs --root-cmd (lockstat is superuser-only)")
    args.flows_list = [int(x) for x in args.flows.split(",") if x.strip()]
    if args.out is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        args.out = str(Path("tests/results") / f"{args.backend}-{stamp}.json")
    return args


def describe_run(spec: dict[str, Any], client: str, dut: str, top_iterations: int) -> list[str]:
    """Human-readable planned command list for one run (used by --dry-run)."""
    lines = []
    lines.append(
        f"[flows={spec['flows']} proto={spec['proto']} direction={spec['direction']} pkt_len={spec['pkt_len']}]"
    )
    lines.append(f"  ssh {dut} netstat -m | head -5            # before")
    lines.append(f"  ssh {dut} netstat -ibnd                    # before")
    lines.append(f"  ssh {dut} vmstat -i                        # before")
    lines.append(f"  ssh {dut} pfctl -si 2>/dev/null | grep -E 'current entries' || true   # before")
    lines.append(f"  ssh {dut} netstat -Q 2>/dev/null || true                    # before")
    lines.append(f"  ssh {dut} sysctl net.pppoe 2>/dev/null || true              # before")
    lines.append(f"  ssh {dut} vmstat -z 2>/dev/null | grep -iE '^(ITEM|mbuf)' || true   # before")
    lines.append(f"  ssh {dut} top -SHPn -d {top_iterations} -s {TOP_DELAY}       # during, spans the run")
    iperf_cmd = "iperf3 " + " ".join(spec["args"])
    lines.append(f"  ssh {client} {iperf_cmd}")
    lines.append(f"  ssh {dut} netstat -m | head -5            # after")
    lines.append(f"  ssh {dut} netstat -ibnd                    # after")
    lines.append(f"  ssh {dut} vmstat -i                        # after")
    lines.append(f"  ssh {dut} pfctl -si 2>/dev/null | grep -E 'current entries' || true   # after")
    lines.append(f"  ssh {dut} netstat -Q 2>/dev/null || true                    # after")
    lines.append(f"  ssh {dut} sysctl net.pppoe 2>/dev/null || true              # after")
    lines.append(f"  ssh {dut} vmstat -z 2>/dev/null | grep -iE '^(ITEM|mbuf)' || true   # after")
    return lines


def lockstat_window(duration: int) -> tuple[int, int]:
    """(delay, seconds) for a lockstat sample inside an iperf3 run of
    `duration` s: skip TCP slow start / the first top interval, and stop
    before iperf3's end-of-test teardown."""
    delay = min(5, max(1, duration // 6))
    return delay, max(1, duration - 2 * delay)


def _delayed_lockstat(dut: str, delay: int, seconds: int, root_cmd: str) -> str:
    import time
    time.sleep(delay)
    return ssh.run_lockstat_sample(dut, seconds, root_cmd=root_cmd, timeout=seconds + 120)


def execute_run(
    spec: dict[str, Any], client: str, dut: str, duration: int, backend: str,
    wan_iface: str | None = None, irq_prefix: str = "igc",
    root_cmd: str | None = None, lockstat: bool = False,
) -> dict[str, Any]:
    """Run one iperf3 test with before/during/after DUT metric collection."""
    before = ssh.collect_dut_snapshot(dut)
    pppoe_before = ssh.collect_dut_pppoe_snapshot(dut)
    vmstat_z_before = ssh.collect_vmstat_z_mbuf(dut)
    pf_before = ssh.collect_pf_info(dut, root_cmd) if root_cmd else ""

    top_iterations = parsers.top_iterations_for(duration, delay=TOP_DELAY)
    # Slack beyond the run's own span: on a saturated DUT (UDP-flood runs in
    # particular) the ssh setup and iperf3's post-run report can lag the
    # 30s test window by well over a minute (observed >90s through the
    # router-mode pf path at UDP 64B line rate); duration+30 aborted the S06
    # lab A/B mid-matrix, so give the report generation room to finish.
    top_timeout = top_iterations * TOP_DELAY + 60
    lockstat_raw = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        top_future = pool.submit(ssh.collect_top_sample, dut, top_iterations, TOP_DELAY, top_timeout)
        iperf_future = pool.submit(ssh.run_iperf3_client, client, spec["args"], duration + 240)
        lock_future = None
        if lockstat and root_cmd:
            delay, seconds = lockstat_window(duration)
            lock_future = pool.submit(_delayed_lockstat, dut, delay, seconds, root_cmd)
        top_raw = top_future.result()
        iperf_doc = iperf_future.result()
        if lock_future is not None:
            lockstat_raw = lock_future.result()

    after = ssh.collect_dut_snapshot(dut)
    pppoe_after = ssh.collect_dut_pppoe_snapshot(dut)
    vmstat_z_after = ssh.collect_vmstat_z_mbuf(dut)
    pf_after = ssh.collect_pf_info(dut, root_cmd) if root_cmd else ""

    netq_before = parsers.parse_netstat_Q(pppoe_before["netstat_Q"])
    netq_after = parsers.parse_netstat_Q(pppoe_after["netstat_Q"])
    pppoe_sysctls_before = parsers.parse_sysctl_pppoe(pppoe_before["sysctl_pppoe"])
    pppoe_sysctls_after = parsers.parse_sysctl_pppoe(pppoe_after["sysctl_pppoe"])
    cpu_hits_before = pppoe_sysctls_before.get("net.pppoe.cpu_hits", {})
    cpu_hits_after = pppoe_sysctls_after.get("net.pppoe.cpu_hits", {})

    mbuf_before = parsers.parse_netstat_m(before["netstat_m"])
    mbuf_after = parsers.parse_netstat_m(after["netstat_m"])
    if_before = parsers.parse_netstat_ibnd(before["netstat_ibnd"])
    if_after = parsers.parse_netstat_ibnd(after["netstat_ibnd"])
    if_errors_delta = parsers.diff_if_errors(if_before, if_after)
    vmstat_before = parsers.parse_vmstat_i(before["vmstat_i"])
    vmstat_after = parsers.parse_vmstat_i(after["vmstat_i"])
    irq_delta = parsers.diff_irq(vmstat_before, vmstat_after, prefix=irq_prefix)
    top_snapshots = parsers.parse_top(top_raw)
    top_reduced = parsers.reduce_top(top_snapshots)
    iperf_result = parsers.parse_iperf_result(iperf_doc, proto=spec["proto"])

    # Confirm the traffic actually went through the DUT's LAN+WAN interfaces,
    # not just that iperf3 reported a number (final-review major I8 follow-up).
    if wan_iface is not None:
        parsers.validate_forwarded_bytes(if_errors_delta, parsers.LAN_IFACE, wan_iface, iperf_result["bytes"])
    pf_info_after = parsers.parse_pfctl_info(pf_after) if root_cmd else None
    if pf_info_after is not None and pf_info_after.get("status") != "Enabled":
        raise RuntimeError(f"pf is not enabled on {dut} (pfctl -si status "
                           f"{pf_info_after.get('status')!r}): traffic was not measured through pf/NAT")

    return {
        "flows": spec["flows"],
        "proto": spec["proto"],
        "direction": spec["direction"],
        "pkt_len": spec["pkt_len"],
        "iperf": iperf_doc,
        "gbps": iperf_result["gbps"],
        "sent_gbps": iperf_result.get("sent_gbps"),
        "retransmits": iperf_result["retransmits"],
        "lost_percent": iperf_result["lost_percent"],
        "wan_iface": wan_iface,
        "dut": {
            "cpu_idle_per_core": top_reduced["cpu_idle_per_core"],
            "cpu_busy_peak_per_core": top_reduced["cpu_busy_peak_per_core"],
            "netisr_delta": parsers.diff_netisr_workstreams(netq_before, netq_after),
            "pf_info_before": parsers.parse_pfctl_info(pf_before) if root_cmd else None,
            "pf_info_after": pf_info_after,
            "lockstat_raw": lockstat_raw,
            "lockstat_top": parsers.parse_lockstat(lockstat_raw) if lockstat_raw else None,
            "top_threads": top_reduced["top_threads"],
            "top_raw": top_raw,
            "if_errors_delta": if_errors_delta,
            "irq_delta": irq_delta,
            "mbuf_before": mbuf_before,
            "mbuf_after": mbuf_after,
            "pf_current_entries_before": parsers.parse_pfctl_si(before["pfctl_si"]),
            "pf_current_entries_after": parsers.parse_pfctl_si(after["pfctl_si"]),
            "pppoe_netisr_delta": parsers.diff_pppoe_workstreams(netq_before, netq_after),
            "pppoe_cpu_hits_delta": parsers.diff_cpu_hits(cpu_hits_before, cpu_hits_after),
            "vmstat_z_mbuf_before": parsers.parse_vmstat_z_mbuf(vmstat_z_before),
            "vmstat_z_mbuf_after": parsers.parse_vmstat_z_mbuf(vmstat_z_after),
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ssh.configure(args.ssh_config)
    specs = build_run_specs(args.flows_list, args.server, args.duration)
    if args.skip_udp64:
        specs = [s for s in specs if s["pkt_len"] != 64]
    if args.skip_udp:
        specs = [s for s in specs if s["proto"] != "udp"]
    max_flows = max(args.flows_list) if args.flows_list else None
    top_iterations = parsers.top_iterations_for(args.duration, delay=TOP_DELAY)

    if args.dry_run:
        print(f"# planned run_matrix.py --backend {args.backend} --server {args.server} "
              f"--client {args.client} --dut {args.dut} --duration {args.duration} --flows {args.flows}")
        print(f"# once, before the matrix: ssh {args.dut} uname -a")
        print(f"# once, before the matrix: ssh {args.dut} sysctl net.isr.dispatch net.isr.maxthreads net.isr.bindthreads")
        print(f"# once, before the matrix: ssh {args.dut} netstat -ibnd")
        print(f"# once, before the matrix: ssh {args.dut} command -v lockstat  # availability probe, no root")
        print(f"# once, before the matrix: ssh {args.dut} command -v pmcstat; pmcstat -L  # availability probe, no root")
        if args.backend == "raw":
            print(f"# once, before the matrix: ssh {args.dut} ifconfig {parsers.RAW_WAN_IFACE}  # raw preflight: expects {parsers.RAW_WAN_ADDR}, no pppoe/ng up")
        print(f"# once, before the matrix: validate_backend_preflight({args.backend!r}, ...) -- abort if the DUT isn't actually configured for this backend")
        print(f"# once, before the matrix: ssh {args.dut} ifconfig -g pppoe  # tells an if_pppoe clone from mpd5's renamed ng_iface")
        print("# after each run: validate_forwarded_bytes(...) -- abort if LAN/WAN iface byte deltas don't track iperf3's reported bytes")
        if args.root_cmd:
            print(f"# before/after each run: ssh {args.dut} {ssh.as_root('pfctl -si', args.root_cmd)}  # abort unless pf Status: Enabled")
        for spec in specs:
            for line in describe_run(spec, args.client, args.dut, top_iterations):
                print(line)
            if args.lockstat == "all" or (args.lockstat == "max-flows" and spec["flows"] == max_flows):
                delay, seconds = lockstat_window(args.duration)
                print(f"  ssh {args.dut} {ssh.as_root(f'lockstat -P -s 10 sleep {seconds}', args.root_cmd)}"
                      f"   # during, from t+{delay}s")
        print(f"# output would be written to: {args.out}")
        return 0

    started = datetime.now(timezone.utc).isoformat()
    try:
        dut_static = ssh.collect_dut_static(args.dut)
    except Exception as exc:
        print(f"ERROR: aborting matrix, could not reach DUT {args.dut}: {exc}", file=sys.stderr)
        return 1
    dut_sysctls = parsers.parse_sysctl_isr(dut_static["sysctl_isr"])
    dut_ifaces = parsers.parse_netstat_ibnd(dut_static["netstat_ibnd"])
    # Cheap, root-free availability probes only -- actual lockstat/pmcstat
    # sampling needs root and is a separate opt-in step (sample_lockstat.py).
    lockstat_probe = parsers.parse_lockstat_probe(ssh.probe_lockstat_available(args.dut))
    pmcstat_probe = parsers.parse_pmcstat_probe(ssh.probe_pmcstat_available(args.dut))

    raw_wan_ifconfig = None
    if args.backend == "raw":
        raw_wan_ifconfig = ssh.collect_ifconfig(args.dut, parsers.RAW_WAN_IFACE)

    pppoe_group = parsers.parse_ifconfig_group(ssh.collect_ifconfig_group(args.dut, "pppoe"))

    try:
        wan_iface = parsers.validate_backend_preflight(
            args.backend, dut_sysctls, dut_ifaces, raw_wan_ifconfig, pppoe_group=pppoe_group)
    except RuntimeError as exc:
        print(f"ERROR: backend pre-flight failed: {exc}", file=sys.stderr)
        return 1

    runs = []
    for spec in specs:
        want_lockstat = args.lockstat == "all" or (args.lockstat == "max-flows" and spec["flows"] == max_flows)
        try:
            runs.append(execute_run(
                spec, args.client, args.dut, args.duration, args.backend,
                wan_iface=wan_iface, irq_prefix=args.irq_prefix,
                root_cmd=args.root_cmd, lockstat=want_lockstat,
            ))
        except Exception as exc:
            print(
                f"ERROR: aborting matrix during flows={spec['flows']} proto={spec['proto']} "
                f"direction={spec['direction']} pkt_len={spec['pkt_len']}: {exc}",
                file=sys.stderr,
            )
            return 1

    doc = {
        "meta": {
            "backend": args.backend,
            "server": args.server,
            "client": args.client,
            "dut": args.dut,
            "started": started,
            "duration": args.duration,
            "flows": args.flows_list,
            "dut_uname": dut_static["uname"],
            "dut_sysctls": dut_sysctls,
            # Binary-presence probes only (`command -v` / `pmcstat -L`), NOT a
            # check that DTrace/lockstat providers are loaded or that this
            # caller has root -- named accordingly so meta doesn't overstate
            # what was checked (review finding).
            "lockstat_binary_present": lockstat_probe["available"],
            "lockstat_sampled": any(r["dut"].get("lockstat_raw") for r in runs),
            "wan_iface": wan_iface,
            "pppoe_group": pppoe_group,
            "direction_semantics": "client-perspective: download = iperf3 -R (server->client)",
            "pmcstat_available": pmcstat_probe["available"],
        },
        "runs": runs,
    }
    parsers.validate_schema(doc)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
