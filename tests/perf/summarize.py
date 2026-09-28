#!/usr/bin/env python3
"""Print a table summarizing one or more run_matrix.py result JSON files.

Usage: summarize.py results.json [more.json ...]
       summarize.py --ratio-baseline raw results.json [more.json ...]

Columns: backend | flows | proto | dir | Gbit/s | retrans/loss | min core idle%
         | peak core busy% | netisr qdrops | top lock
"peak core busy%" is the worst single core in any top interval ("cpuN=X",
X >= ~95 means that core saturated); "netisr qdrops" sums every protocol's
queue-drop delta; "top lock" is the adaptive-mutex-spin lock with the most
wait time (ms waited per s sampled) when the run had a lockstat sample.
With --ratio-baseline BACKEND, an extra "ratio-to-BACKEND" column divides
each row's Gbit/s by the same-shaped (flows, proto, dir, pkt_len) row from
BACKEND, found across all the given files -- the phase-2 forwarded-harness
number that matters more than any absolute Gbit/s figure (see
docs/PERF-FWD-DESIGN.md): "no row is n/a" means every backend row had a
matching baseline row to divide by, not that the ratio itself is good.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BASE_COLUMNS = ["backend", "flows", "proto", "dir", "Gbit/s", "retrans/loss", "min core idle%",
                "peak core busy%", "netisr qdrops", "top lock"]


def peak_busy(dut: dict) -> str:
    peaks = dut.get("cpu_busy_peak_per_core") or []
    if not peaks:
        return "n/a"
    i = max(range(len(peaks)), key=lambda k: peaks[k])
    return f"cpu{i}={peaks[i]:.1f}"


def netisr_qdrops(dut: dict) -> str:
    delta = dut.get("netisr_delta")
    if delta is None:
        return "n/a"
    total = sum(v.get("qdrops", 0) for v in delta.values())
    worst = [f"{k}:{v['qdrops']}" for k, v in delta.items() if v.get("qdrops")]
    return str(total) + (f" ({','.join(worst)})" if worst else "")


def top_lock(dut: dict) -> str:
    spin = (dut.get("lockstat_top") or {}).get("Adaptive mutex spin")
    if not spin or not spin.get("top_locks"):
        return "n/a"
    t = spin["top_locks"][0]
    return f"{t['lock']} {t['wait_ms_per_s']}ms/s @{t['top_caller']}"


def runs_for_doc(doc: object, path: Path) -> list[dict]:
    """Extract the run dicts from a result JSON document.

    Two schemas exist in tests/results/:
    - run_matrix.py audit-trail files: {"meta": {...}, "runs": [run, ...]}
    - per-run files:                  {"meta": {...}, "run": run}
    """
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: top-level JSON is not an object")
    if isinstance(doc.get("runs"), list):
        return [r for r in doc["runs"] if isinstance(r, dict)]
    if isinstance(doc.get("run"), dict):
        return [doc["run"]]
    raise ValueError(f"{path}: no 'runs' list or single 'run' object found")


def records_for_file(path: Path) -> list[dict[str, Any]]:
    """Structured (not yet string-rendered) rows for one result file."""
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: malformed JSON ({exc})") from exc
    meta = doc.get("meta") if isinstance(doc, dict) else None
    backend = meta.get("backend") if isinstance(meta, dict) else None
    if not backend:
        raise ValueError(f"{path}: missing meta.backend")
    records = []
    for run in runs_for_doc(doc, path):
        idle = run["dut"].get("cpu_idle_per_core") or []
        records.append({
            "backend": backend,
            "flows": run["flows"],
            "proto": run["proto"],
            "dir": run["direction"],
            "pkt_len": run.get("pkt_len"),
            "gbps": run["gbps"],
            "retransmits": run["retransmits"],
            "lost_percent": run["lost_percent"],
            "min_idle": min(idle) if idle else None,
            "peak_busy": peak_busy(run["dut"]),
            "netisr_qdrops": netisr_qdrops(run["dut"]),
            "top_lock": top_lock(run["dut"]),
        })
    return records


def ratio_key(record: dict[str, Any]) -> tuple:
    return (record["flows"], record["proto"], record["dir"], record["pkt_len"])


def build_baseline_gbps(records: list[dict[str, Any]], baseline_backend: str) -> dict[tuple, float]:
    """{ratio_key: gbps} for every record of `baseline_backend`.

    A key present more than once (e.g. the same shape measured twice) keeps
    the LAST value seen -- callers pass files in the order they want that
    tie broken (a re-run superseding an earlier one, typically).
    """
    return {ratio_key(r): r["gbps"] for r in records if r["backend"] == baseline_backend}


def render_row(record: dict[str, Any], baseline_gbps: dict[tuple, float] | None) -> list[str]:
    if record["retransmits"] is not None:
        rl = str(record["retransmits"])
    elif record["lost_percent"] is not None:
        rl = f"{record['lost_percent']:.2f}%"
    else:
        rl = "n/a"
    min_idle = f"{record['min_idle']:.1f}" if record["min_idle"] is not None else "n/a"
    row = [
        record["backend"], str(record["flows"]), record["proto"], record["dir"],
        f"{record['gbps']:.3f}", rl, min_idle,
        record.get("peak_busy", "n/a"), record.get("netisr_qdrops", "n/a"), record.get("top_lock", "n/a"),
    ]
    if baseline_gbps is not None:
        base = baseline_gbps.get(ratio_key(record))
        row.append(f"{record['gbps'] / base:.3f}" if base else "n/a")
    return row


def render_table(rows: list[list[str]], columns: list[str]) -> str:
    widths = [len(c) for c in columns]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = [" | ".join(c.ljust(widths[i]) for i, c in enumerate(columns))]
    lines.append("-+-".join("-" * w for w in widths))
    for row in rows:
        lines.append(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("results", nargs="+", help="result JSON file(s)")
    p.add_argument(
        "--ratio-baseline", default=None, metavar="BACKEND",
        help="add a ratio-to-BACKEND column (e.g. 'raw' for the phase-2 forwarded matrix)",
    )
    args = p.parse_args(argv)

    all_records: list[dict[str, Any]] = []
    errors: list[str] = []
    for path_str in args.results:
        try:
            all_records.extend(records_for_file(Path(path_str)))
        except ValueError as exc:
            errors.append(str(exc))
        except OSError as exc:
            errors.append(f"{path_str}: {exc}")

    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if not all_records:
        print("no runs found", file=sys.stderr)
        return 1

    baseline_gbps = None
    columns = list(BASE_COLUMNS)
    if args.ratio_baseline:
        baseline_gbps = build_baseline_gbps(all_records, args.ratio_baseline)
        if not baseline_gbps:
            print(f"error: --ratio-baseline {args.ratio_baseline!r} matched no rows in the given files", file=sys.stderr)
            return 1
        columns.append(f"ratio-to-{args.ratio_baseline}")

    rows = [render_row(r, baseline_gbps) for r in all_records]
    print(render_table(rows, columns))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
