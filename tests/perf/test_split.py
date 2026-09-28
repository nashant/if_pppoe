"""Tests for split_runs.py (S06 lab A/B per-run file layout).

The fixture below is a synthetic miniature of a run_matrix.py document --
same schema shape (meta + runs[] with the keys execute_run emits, see
run_matrix.py execute_run and parsers.validate_schema), inline rather than
a real capture because the layout logic under test is filename mapping and
malformed-input rejection, not measurement.
"""
from __future__ import annotations

import json
import pytest

from split_runs import split_matrix_doc, write_split


def _meta(backend="if_pppoe"):
    return {
        "backend": backend,
        "server": "10.99.0.1",
        "client": "pppoe-client-vm",
        "dut": "pppoe-client-vm",
        "started": "2026-02-22T10:00:00+00:00",
        "duration": 30,
        "flows": [1],
        "dut_uname": "FreeBSD client 14.3-RELEASE",
        "dut_sysctls": {"net.isr.dispatch": "direct"},
    }


def _run(proto, direction, pkt_len, flows=4, top_raw="last pid: 1\nCPU: 10% user\n"):
    return {
        "flows": flows,
        "proto": proto,
        "direction": direction,
        "pkt_len": pkt_len,
        "iperf": {"end": {}},
        "gbps": 0.5,
        "retransmits": 3 if proto == "tcp" else None,
        "lost_percent": 0.01 if proto == "udp" else None,
        "dut": {"top_raw": top_raw, "cpu_idle_per_core": [90], "top_threads": []},
    }


def _doc(runs, backend="if_pppoe"):
    return {"meta": _meta(backend), "runs": runs}


def test_split_names_download_upload_and_udp_lengths(tmp_path):
    doc = _doc([
        _run("tcp", "download", None, flows=1),
        _run("tcp", "upload", None, flows=1),
        _run("tcp", "download", None, flows=4),
        _run("udp", "download", 1400, flows=4),
        _run("udp", "upload", 1400, flows=4),
        _run("udp", "download", 64, flows=4),
    ])
    json_files, txt_files = split_matrix_doc(doc)
    assert set(json_files) == {
        "if_pppoe-tcp-1-flow.json",
        "if_pppoe-tcp-1-flow-upload.json",
        "if_pppoe-tcp-4-flow.json",
        "if_pppoe-udp1400-4-flow.json",
        "if_pppoe-udp1400-4-flow-upload.json",
        "if_pppoe-udp64-4-flow.json",
    }
    # top_raw txt carries the run's own stem (download runs get the plain name)
    assert set(txt_files) == {
        "if_pppoe-top-1-flow.txt",
        "if_pppoe-top-1-flow-upload.txt",
        "if_pppoe-top-4-flow.txt",
        "if_pppoe-udp1400-top-4-flow.txt",
        "if_pppoe-udp1400-top-4-flow-upload.txt",
        "if_pppoe-udp64-top-4-flow.txt",
    }


def test_split_preserves_run_and_meta_subset(tmp_path):
    doc = _doc([_run("tcp", "download", None)])
    json_files, _ = split_matrix_doc(doc)
    per_run = json_files["if_pppoe-tcp-4-flow.json"]
    assert per_run["run"] == doc["runs"][0]
    assert per_run["meta"]["backend"] == "if_pppoe"
    assert per_run["meta"]["duration"] == 30
    # meta subset only: bulky per-invocation fields (flows list) stay in the
    # matrix document, not repeated per run.
    assert "flows" not in per_run["meta"]


def test_run_without_top_raw_gets_json_but_no_txt(tmp_path):
    doc = _doc([_run("tcp", "download", None, top_raw="")])
    json_files, txt_files = split_matrix_doc(doc)
    assert set(json_files) == {"if_pppoe-tcp-4-flow.json"}
    assert txt_files == {}


def test_write_split_writes_files(tmp_path):
    doc = _doc([_run("tcp", "download", None, flows=1)])
    written = write_split(doc, tmp_path)
    names = sorted(p.name for p in written)
    assert names == ["if_pppoe-tcp-1-flow.json", "if_pppoe-top-1-flow.txt"]
    per_run = json.loads((tmp_path / "if_pppoe-tcp-1-flow.json").read_text())
    assert per_run["run"]["gbps"] == 0.5
    assert "CPU: 10% user" in (tmp_path / "if_pppoe-top-1-flow.txt").read_text()


def test_malformed_inputs_rejected():
    with pytest.raises(ValueError, match="missing meta/runs"):
        split_matrix_doc({"runs": []})
    with pytest.raises(ValueError, match="missing meta/runs"):
        split_matrix_doc({"meta": _meta()})
    with pytest.raises(ValueError, match="missing required key 'dut_uname'"):
        meta = _meta()
        del meta["dut_uname"]
        split_matrix_doc({"meta": meta, "runs": [_run("tcp", "download", None)]})
    with pytest.raises(ValueError, match="run missing required key 'gbps'"):
        run = _run("tcp", "download", None)
        del run["gbps"]
        split_matrix_doc({"meta": _meta(), "runs": [run]})