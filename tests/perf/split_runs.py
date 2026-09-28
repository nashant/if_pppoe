#!/usr/bin/env python3
"""Split a run_matrix.py matrix JSON into per-run files (S06 lab A/B layout).

The S06 lab A/B verification gates and verdict table read per-run files --
e.g. `mpd5-tcp-1-flow.json`, `if_pppoe-udp1400-4-flow.json`,
`if_pppoe-top-4-flow.txt` -- while run_matrix.py writes one document per
invocation (`meta` + `runs[]`). This splitter derives those per-run files
from the captured matrix document: byte-for-byte slices of real measured
data, no re-measurement, no fabrication. The full matrix document stays on
disk as the audit trail (it is what summarize.py consumes).

Naming (direction suffix only for upload, mirroring "download-first"
default naming):

  <backend>-tcp-<n>-flow.json               TCP download
  <backend>-tcp-<n>-flow-upload.json        TCP upload
  <backend>-udp1400-<n>-flow.json           UDP 1400B download
  <backend>-udp1400-<n>-flow-upload.json    UDP 1400B upload
  <backend>-udp64-<n>-flow.json             UDP 64B PPS (download only)
  <backend>-top-<n>-flow.txt                DUT top_raw of the download run
  <backend>-top-<n>-flow-upload.txt         DUT top_raw of the upload run

Malformed input (missing meta/runs, or a run missing the keys this layout
depends on) raises ValueError rather than writing partial files -- a
silently empty/fake-looking per-run file would be indistinguishable from
a real one.

Usage:
    split_runs.py tests/results/lab-ab/mpd5-matrix-<stamp>.json \
        --outdir tests/results/lab-ab
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_REQUIRED_RUN_KEYS = ("flows", "proto", "direction", "pkt_len", "iperf", "gbps", "dut")
_REQUIRED_META_KEYS = ("backend", "server", "client", "dut", "started", "duration",
                       "dut_uname", "dut_sysctls")
_META_SUBSET_KEYS = ("backend", "server", "client", "dut", "started", "duration")


def split_matrix_doc(doc: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Split one run_matrix.py document.

    Returns ({json filename: per-run JSON document}, {txt filename: top_raw}).
    Per-run documents carry a meta subset plus the run verbatim (iperf JSON,
    gbps, and the full dut dict with top_raw); top_raw is also emitted as a
    raw .txt named after its own run's stem so the per-run DUT top snapshot
    is directly greppable without re-serializing JSON.
    """
    if not isinstance(doc, dict) or "meta" not in doc or "runs" not in doc:
        raise ValueError("input is not a run_matrix.py document: missing meta/runs")
    meta = doc["meta"]
    for key in _REQUIRED_META_KEYS:
        if key not in meta:
            raise ValueError(f"matrix meta missing required key {key!r}")
    json_files: dict[str, dict[str, Any]] = {}
    txt_files: dict[str, str] = {}
    for run in doc["runs"]:
        for key in _REQUIRED_RUN_KEYS:
            if key not in run:
                raise ValueError(f"run missing required key {key!r}")
        proto = run["proto"]
        if proto == "udp":
            proto = f"udp{run['pkt_len']}"
        stem = f"{meta['backend']}-{proto}-{run['flows']}-flow"
        if run["direction"] != "download":
            stem += f"-{run['direction']}"
        json_files[f"{stem}.json"] = {
            "meta": {k: meta[k] for k in _META_SUBSET_KEYS},
            "run": run,
        }
        top_raw = run.get("dut", {}).get("top_raw")
        if top_raw:
            # The DUT top snapshot filename follows the slice gate's naming
            # (<backend>-top-<n>-flow.txt): the plain name is the headline
            # TCP download run's sample; upload keeps its direction suffix
            # and udp runs keep their pkt_len qualifier, so no later run
            # can overwrite the headline snapshot.
            top = f"{meta['backend']}-top-{run['flows']}-flow"
            if run["proto"] != "tcp":
                top = f"{meta['backend']}-udp{run['pkt_len']}-top-{run['flows']}-flow"
            if run["direction"] != "download":
                top += f"-{run['direction']}"
            txt_files[f"{top}.txt"] = top_raw
    return json_files, txt_files


def write_split(doc: dict[str, Any], outdir: Path) -> list[Path]:
    """Write the per-run JSON and top.txt files; return the paths written.

    top_raw's txt filename reuses the stem of its run: the top sample IS
    that run's sample, so `if_pppoe-top-4-flow.txt` is the top snapshot of
    `if_pppoe-tcp-4-flow.json`'s run.
    """
    json_files, txt_files = split_matrix_doc(doc)
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in json_files.items():
        path = outdir / name
        path.write_text(json.dumps(content, indent=2))
        written.append(path)
    for name, raw in txt_files.items():
        path = outdir / name
        path.write_text(raw)
        written.append(path)
    return sorted(written)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("matrix", help="run_matrix.py output JSON to split")
    p.add_argument("--outdir", default=None, help="output dir (default: the matrix file's directory)")
    args = p.parse_args(argv)
    doc = json.loads(Path(args.matrix).read_text())
    outdir = Path(args.outdir) if args.outdir else Path(args.matrix).parent
    for path in write_split(doc, outdir):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())