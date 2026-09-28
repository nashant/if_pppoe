#!/usr/bin/env python3
"""Standalone, opt-in lock-contention sample: `lockstat -P -s <depth> sleep <duration>`
against one DUT, alongside an hwpmc(4)/pmcstat(8) availability probe.

Kept separate from run_matrix.py deliberately: unlike every other collector
in this package, lockstat(1) requires root on the DUT (restricted to the
superuser by default -- see lockstat(1)) and DTrace kernel support
(KDTRACE_HOOKS/options DTRACE); running it is a heavier, rarer, opt-in step,
not something to fire on every one of a matrix's ~15 runs. Use it once,
bracketing whichever run is the interesting one (typically the busiest --
highest flow count, both directions in parallel).

Neither lockstat's histogram/stack-trace output layout nor pmcstat's report
layout is parsed here beyond an availability check (parsers.parse_lockstat_probe
/ parse_pmcstat_probe) -- unverified against a real capture this session (no
lab access); see docs/PERF-FWD-DESIGN.md. Raw text is kept in full for manual
reading.

Usage:
    sample_lockstat.py --dut HOST --duration 10 [--stack-depth 10] \\
        [--ssh-config PATH] [--out tests/results/perf/lockstat-<stamp>.json]

Requires: passwordless (NOPASSWD) sudo on the DUT for the lockstat
invocation -- this script does not itself prepend sudo (every other
collector in this package is root-free by convention); wrap --dut's ssh
target or its sudoers config accordingly if lockstat needs it.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import parsers
import ssh_collectors as ssh


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dut", required=True)
    p.add_argument("--duration", type=int, default=10, help="wall-clock seconds to sample (default 10)")
    p.add_argument("--stack-depth", type=int, default=10, help="lockstat -s stack-trace depth (default 10)")
    p.add_argument("--ssh-config", default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--sudo", action="store_true",
        help="prepend `sudo -n` to the lockstat sampling command (lockstat requires "
             "root; without this, a non-root --dut user always hits its permission-"
             "denied error, not a usable sample). Requires passwordless sudo on --dut.",
    )
    p.add_argument(
        "--root-cmd", default=None, metavar="TEMPLATE",
        help="root wrapper template, '{}' = the shell-quoted command (overrides --sudo; "
             "the lab client VM has no sudo: 'echo | su -m root -c {}'). Also loads dtraceall.",
    )
    args = p.parse_args(argv)
    if args.out is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        args.out = str(Path("tests/results/perf") / f"lockstat-{stamp}.json")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ssh.configure(args.ssh_config)

    sudo_prefix = "sudo -n " if args.sudo else ""
    if args.dry_run:
        print(f"# once: ssh {args.dut} command -v lockstat  # binary-presence probe only, not a root/DTrace check")
        print(f"# once: ssh {args.dut} command -v pmcstat; pmcstat -L  # binary-presence probe only")
        cmd = f"lockstat -P -s {args.stack_depth} sleep {args.duration}"
        shown = ssh.as_root(cmd, args.root_cmd) if args.root_cmd else sudo_prefix + cmd
        print(f"  ssh {args.dut} {shown}   # requires root")
        print(f"# output would be written to: {args.out}")
        return 0

    # Binary presence only (`command -v`) -- NOT a check that DTrace/lockstat
    # providers are loaded or that this caller has root (review finding:
    # the old "lockstat_available" naming overstated what was checked).
    lockstat_probe = parsers.parse_lockstat_probe(ssh.probe_lockstat_available(args.dut))
    pmcstat_probe = parsers.parse_pmcstat_probe(ssh.probe_pmcstat_available(args.dut))

    lockstat_sample: dict[str, Any] = {"binary_present": lockstat_probe["available"], "sampled": False}
    if lockstat_probe["available"]:
        try:
            raw = ssh.run_lockstat_sample(args.dut, args.duration, args.stack_depth, sudo=args.sudo,
                                          root_cmd=args.root_cmd)
            lockstat_sample["raw"] = raw
            lockstat_sample["summary"] = parsers.parse_lockstat(raw)
            lockstat_sample["sampled"] = bool(lockstat_sample["summary"])
        except RuntimeError as exc:
            # Root/DTrace-permission failures surface here (not from the
            # cheap binary-presence probe) -- record, don't abort: this
            # script's whole point is best-effort. The likely cause without
            # --sudo: lockstat "restricted to the superuser by default".
            lockstat_sample["error"] = str(exc)
    else:
        lockstat_sample["reason"] = lockstat_probe["raw"].strip()

    doc = {
        "meta": {
            "dut": args.dut,
            "started": datetime.now(timezone.utc).isoformat(),
            "duration": args.duration,
            "stack_depth": args.stack_depth,
        },
        "lockstat": lockstat_sample,
        "pmcstat": {"available": pmcstat_probe["available"], "raw": pmcstat_probe["raw"]},
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    print(f"wrote {out_path}")
    if not lockstat_sample["sampled"]:
        reason = lockstat_sample.get("reason") or lockstat_sample.get("error")
        hint = " -- try --sudo?" if lockstat_sample["binary_present"] and not args.sudo else ""
        print(f"note: lockstat did not produce a sample on {args.dut} ({reason}){hint}", file=sys.stderr)
    if not pmcstat_probe["available"]:
        print(f"note: pmcstat/hwpmc unavailable on {args.dut} (expected in a KVM guest without vPMU passthrough)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
