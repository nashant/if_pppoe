"""Tests for tests/perf parsers, against real captured DUT/iperf3 output.

Fixtures under tests/perf/fixtures/ are real samples taken over ssh from
the DUT (FreeBSD 14.3) and the lab host (iperf3 JSON), not hand-typed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import parsers  # noqa: E402
import ssh_collectors  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def read(name: str) -> str:
    return (FIXTURES / name).read_text()


def read_json(name: str) -> dict:
    return json.loads(read(name))


# --- lockstat / pfctl -si (root collectors, real captures from the VM lab) ------


def test_parse_lockstat_real_capture():
    # `lockstat -P -s 10 sleep 8` on the slot-2 client VM (SMP kernel) while
    # 4 TCP flows were forwarded through pf/NAT onto if_pppoe's pppoe0.
    doc = parsers.parse_lockstat(read("lockstat_sample.txt"), top_n=3)
    spin = doc["Adaptive mutex spin"]
    assert spin["events"] == 22344 and spin["seconds"] == pytest.approx(8.083)
    top = spin["top_locks"][0]
    assert top["lock"] == "sppp"
    assert top["wait_ns"] == 5572 * 4545 + 2171 * 5394 + 684 * 12921  # its three caller rows
    assert top["top_caller"] == "sppp_input+0x4f0"
    # lock names with spaces survive
    assert doc["Spin lock spin"]["top_locks"][0]["lock"] == "sched lock 2"


def test_parse_pfctl_info():
    text = ("Status: Enabled for 0 days 00:00:38           Debug: Urgent\n\n"
            "State Table                          Total             Rate\n"
            "  current entries                       27               \n"
            "  searches                         5394097       141949.9/s\n")
    doc = parsers.parse_pfctl_info(text)
    assert doc == {"status": "Enabled", "current entries": 27, "searches": 5394097}
    assert parsers.parse_pfctl_info("pfctl: /dev/pf: Permission denied")["status"] is None


def test_build_run_specs_download_is_reverse():
    import run_matrix  # noqa: E402
    specs = run_matrix.build_run_specs([4], "srv", 10)
    by = {(s["proto"], s["direction"], s["pkt_len"]): s["args"] for s in specs}
    assert "-R" in by[("tcp", "download", None)]
    assert "-R" not in by[("tcp", "upload", None)]
    assert "-R" in by[("udp", "download", 1400)]
    assert "-R" not in by[("udp", "upload", 1400)]


def test_as_root_template_quotes_the_command():
    assert ssh_collectors.as_root("pfctl -si", "echo | su -m root -c {}") == "echo | su -m root -c 'pfctl -si'"
    assert ssh_collectors.as_root("pfctl -si", None) == "pfctl -si"


# --- netstat -m -----------------------------------------------------------


def test_parse_netstat_m():
    doc = parsers.parse_netstat_m(read("netstat_m_before.txt"))
    assert doc["mbufs_current"] == 17353
    assert doc["mbufs_cache"] == 13127
    assert doc["mbufs_total"] == 30480
    assert doc["mbuf_clusters_current"] == 12990
    assert doc["mbuf_clusters_cache"] == 8526
    assert doc["mbuf_clusters_total"] == 21516
    assert doc["mbuf_clusters_max"] == 1005094
    assert "raw" in doc and "mbufs in use" in doc["raw"]


# --- netstat -ibnd ----------------------------------------------------------


def test_parse_netstat_ibnd_default_interfaces():
    doc = parsers.parse_netstat_ibnd(read("netstat_ibnd_before.txt"))
    # default pattern matches igc*, vtnet*, pppoe*, ng* -- this DUT currently has igc0-3
    assert set(doc.keys()) == {"igc0", "igc1", "igc2", "igc3"}
    igc0 = doc["igc0"]
    assert igc0["ipkts"] == 4469755764
    assert igc0["ierrs"] == 133
    assert igc0["idrop"] == 0
    assert igc0["ibytes"] == 5226054423748
    assert igc0["opkts"] == 1765789405
    assert igc0["oerrs"] == 0
    assert igc0["obytes"] == 694191689464
    assert igc0["coll"] == 137
    assert igc0["drop"] == 0
    igc1 = doc["igc1"]
    assert igc1["ierrs"] == 2814


def test_parse_netstat_ibnd_default_pattern_matches_vtnet():
    # the VM lab's router-mode.sh NICs (vtnet1 WAN raw, vtnet2 LAN) -- needed
    # so validate_forwarded_bytes can see their byte deltas (final-review
    # major follow-up: nothing previously captured these at all).
    text = (
        "Name              Mtu Network              Address                          Ipkts      Ierrs      Idrop          Ibytes        Opkts      Oerrs          Obytes       Coll       Drop\n"
        "vtnet2           1500 <Link#2>             52:54:00:aa:00:05                  100          0          0           50000          200          0           95000          0          0 \n"
    )
    doc = parsers.parse_netstat_ibnd(text)
    assert set(doc.keys()) == {"vtnet2"}
    assert doc["vtnet2"]["obytes"] == 95000


def test_parse_netstat_ibnd_custom_pattern():
    doc = parsers.parse_netstat_ibnd(read("netstat_ibnd_before.txt"), iface_pattern=r"^lo0$")
    assert set(doc.keys()) == {"lo0"}


def test_diff_if_errors():
    before = parsers.parse_netstat_ibnd(read("netstat_ibnd_before.txt"))
    after = parsers.parse_netstat_ibnd(read("netstat_ibnd_after.txt"))
    delta = parsers.diff_if_errors(before, after)
    assert delta["igc0"]["ipkts"] == 4469756014 - 4469755764
    assert delta["igc0"]["ierrs"] == 0
    assert delta["igc1"]["ipkts"] == 26709776030 - 26709769326
    # unchanged interfaces should be all-zero, not absent
    assert delta["igc2"]["ipkts"] == 0


# --- sysctl net.isr.* --------------------------------------------------------


def test_parse_sysctl_isr():
    text = (
        "net.isr.dispatch: direct\n"
        "net.isr.maxthreads: 1\n"
        "net.isr.bindthreads: 0\n"
    )
    doc = parsers.parse_sysctl_isr(text)
    assert doc == {
        "net.isr.dispatch": "direct",
        "net.isr.maxthreads": 1,
        "net.isr.bindthreads": 0,
    }


# --- netstat -Q (netisr protocol table + per-workstream counters) -------------


def test_parse_netstat_Q_protocols_and_pppoe_workstreams():
    doc = parsers.parse_netstat_Q(read("netstat_Q_before.txt"))
    assert doc["protocols"]["pppoe"] == {
        "proto": 11, "qlimit": 1000, "policy": "cpu", "dispatch": "hybrid", "flags": "C--",
    }
    assert doc["protocols"]["ip"]["policy"] == "flow"
    pppoe_ws = parsers.pppoe_workstreams(doc)
    assert {w["cpu"] for w in pppoe_ws} == {0, 1, 2, 3}
    cpu0 = next(w for w in pppoe_ws if w["cpu"] == 0)
    assert cpu0 == {
        "wsid": 0, "cpu": 0, "name": "pppoe", "len": 0, "wmark": 5,
        "dispd": 0, "hdispd": 22243, "qdrops": 0, "queued": 5, "handled": 22248,
    }


def test_diff_pppoe_workstreams_matches_captured_evidence():
    before = parsers.parse_netstat_Q(read("netstat_Q_before.txt"))
    after = parsers.parse_netstat_Q(read("netstat_Q_after.txt"))
    delta = parsers.diff_pppoe_workstreams(before, after)
    # tests/results/lab-ab/verdict.md's T2 evidence: cpu2 +399276, cpu3 +165026
    assert delta[2]["handled"] == 399297 - 21
    assert delta[3]["handled"] == 165034 - 8
    assert delta[1]["handled"] == 0
    assert all(delta[cpu]["qdrops"] == 0 for cpu in delta)  # no netisr queue overflow


def test_diff_netisr_workstreams_covers_every_protocol():
    before = parsers.parse_netstat_Q(read("netstat_Q_before.txt"))
    after = parsers.parse_netstat_Q(read("netstat_Q_after.txt"))
    delta = parsers.diff_netisr_workstreams(before, after)
    per_cpu = parsers.diff_pppoe_workstreams(before, after)
    assert delta["pppoe"]["handled"] == sum(v["handled"] for v in per_cpu.values())
    assert delta["pppoe"]["handled_per_cpu"][2] == 399297 - 21
    assert all(v["qdrops"] >= 0 for v in delta.values())


def test_diff_netisr_workstreams_counts_ip_queue_drops():
    def q(ip_drops):
        return {"workstreams": [
            {"name": "ip", "cpu": 0, "qdrops": ip_drops, "queued": 10, "handled": 100},
            {"name": "arp", "cpu": 0, "qdrops": 0, "queued": 0, "handled": 0},
        ]}
    delta = parsers.diff_netisr_workstreams(q(3), q(10))
    assert delta == {"ip": {"qdrops": 7, "queued": 0, "handled": 0, "handled_per_cpu": {0: 0}}}


def test_parse_top_keeps_kernel_threads_sharing_one_pid():
    # Real `top -SHPn` from the slot-2 client VM under 16 forwarded TCP flows:
    # idle threads have NICE "ki31", intr/netisr threads "-", and all intr
    # threads share pid 12 -- each must survive as its own row.
    snaps = parsers.parse_top(read("top_sample_vm_threads.txt"))
    reduced = parsers.reduce_top(snaps, top_n=50)
    cmds = {t["command"] for t in reduced["top_threads"]}
    assert {"intr{swi1: netisr 0}", "intr{swi1: netisr 1}",
            "intr{swi1: netisr 2}", "intr{swi1: netisr 3}"} <= cmds
    assert not any(c.startswith("idle{") for c in cmds)  # idle threads are not "top"
    assert "lockstat" in cmds


def test_reduce_top_peak_busy_is_worst_snapshot_per_core():
    snaps = [
        {"cpu_idle": [0.0, 0.0], "threads": []},    # warm-up, dropped
        {"cpu_idle": [50.0, 90.0], "threads": []},
        {"cpu_idle": [2.5, 80.0], "threads": []},
    ]
    reduced = parsers.reduce_top(snaps)
    assert reduced["cpu_busy_peak_per_core"] == [97.5, 20.0]
    assert reduced["cpu_idle_per_core"] == pytest.approx([26.25, 85.0])


# --- sysctl net.pppoe.* ---------------------------------------------------------


def test_parse_cpu_hits():
    assert parsers.parse_cpu_hits("cpu0=22248 cpu1=0 cpu2=21 cpu3=8") == {
        "cpu0": 22248, "cpu1": 0, "cpu2": 21, "cpu3": 8,
    }


def test_parse_sysctl_pppoe_cpu_hits_special_case():
    doc = parsers.parse_sysctl_pppoe(read("sysctl_pppoe_before.txt"))
    assert doc["net.pppoe.cpu_hits"] == {"cpu0": 22248, "cpu1": 0, "cpu2": 21, "cpu3": 8}


def test_parse_sysctl_pppoe_generic_counters():
    text = "net.pppoe.data_in: 1234\nnet.pppoe.reflect: 0\n"
    doc = parsers.parse_sysctl_pppoe(text)
    assert doc == {"net.pppoe.data_in": 1234, "net.pppoe.reflect": 0}


def test_diff_cpu_hits_matches_captured_evidence():
    before = parsers.parse_sysctl_pppoe(read("sysctl_pppoe_before.txt"))["net.pppoe.cpu_hits"]
    after = parsers.parse_sysctl_pppoe(read("sysctl_pppoe_after.txt"))["net.pppoe.cpu_hits"]
    delta = parsers.diff_cpu_hits(before, after)
    assert delta == {"cpu0": 20, "cpu1": 0, "cpu2": 399276, "cpu3": 165026}


# --- vmstat -z (mbuf zones) ------------------------------------------------------


def test_parse_vmstat_z_mbuf():
    # 14.3's real 8-column layout (SIZE,LIMIT,USED,FREE,REQ,FAIL,SLEEP,XDOM) --
    # the fixture's "free" (728) and "req" (539089502) must land in separate
    # fields, not merge into one the way the old 7-column regex did.
    doc = parsers.parse_vmstat_z_mbuf(read("vmstat_z_mbuf.txt"))
    assert set(doc) == {
        "mbuf_packet", "mbuf", "mbuf_cluster", "mbuf_jumbo_page",
        "mbuf_jumbo_9k", "mbuf_jumbo_16k",
    }
    assert doc["mbuf_packet"] == {
        "size": 256, "limit": 0, "used": 2103, "free": 728,
        "req": 539089502, "fail": 0, "sleep": 0, "xdomain": 3,
    }
    assert doc["mbuf_cluster"] == {
        "size": 2048, "limit": 25600, "used": 2831, "free": 511,
        "req": 3053398, "fail": 0, "sleep": 0, "xdomain": 0,
    }
    assert doc["mbuf_jumbo_9k"]["used"] == 0


def test_parse_vmstat_z_mbuf_accepts_7_column_row_without_xdomain():
    # Older/differently-built vmstat without the XDOM column.
    text = (
        "ITEM                   SIZE  LIMIT     USED     FREE      REQ FAIL SLEEP\n"
        "mbuf_cluster:          2048,  25600,    2831,     511, 3053398,   0,   0\n"
    )
    doc = parsers.parse_vmstat_z_mbuf(text)
    assert doc["mbuf_cluster"] == {
        "size": 2048, "limit": 25600, "used": 2831, "free": 511,
        "req": 3053398, "fail": 0, "sleep": 0,
    }
    assert "xdomain" not in doc["mbuf_cluster"]


def test_parse_vmstat_z_mbuf_ignores_non_mbuf_rows():
    text = "ITEM                   SIZE  LIMIT     USED     FREE      REQ FAIL SLEEP\nUMA Kegs:               384,        0,       57,        7,         57,    0,    0\n"
    assert parsers.parse_vmstat_z_mbuf(text) == {}


# --- lockstat / pmcstat availability probes -------------------------------------


def test_parse_lockstat_probe_unavailable():
    doc = parsers.parse_lockstat_probe("lockstat: not found\n")
    assert doc == {"available": False, "raw": "lockstat: not found\n"}


def test_parse_lockstat_probe_empty_is_unavailable():
    assert parsers.parse_lockstat_probe("")["available"] is False


def test_parse_lockstat_probe_available():
    raw = "Adaptive mutex spin\n\nCount indv cuml rcnt     nsec Lock                   Caller\n"
    assert parsers.parse_lockstat_probe(raw) == {"available": True, "raw": raw}


def test_run_lockstat_sample_no_sudo_by_default(monkeypatch):
    seen = {}

    def fake_run_ssh(dut, remote_cmd, timeout=None, _runner=None):
        seen["cmd"] = remote_cmd
        return "raw lockstat output"

    monkeypatch.setattr(ssh_collectors, "run_ssh", fake_run_ssh)
    ssh_collectors.run_lockstat_sample("dut.example", duration=5, stack_depth=10)
    assert seen["cmd"] == "lockstat -P -s 10 sleep 5"


def test_run_lockstat_sample_prepends_sudo_n_when_requested(monkeypatch):
    # review finding: without this, a non-root --dut always hits lockstat's
    # own "restricted to the superuser" error, not a usable sample.
    seen = {}

    def fake_run_ssh(dut, remote_cmd, timeout=None, _runner=None):
        seen["cmd"] = remote_cmd
        return "raw lockstat output"

    monkeypatch.setattr(ssh_collectors, "run_ssh", fake_run_ssh)
    ssh_collectors.run_lockstat_sample("dut.example", duration=5, stack_depth=10, sudo=True)
    assert seen["cmd"] == "sudo -n lockstat -P -s 10 sleep 5"


def test_parse_pmcstat_probe_unavailable_in_vm():
    doc = parsers.parse_pmcstat_probe("pmcstat: ERROR: Cannot enable process 123: Device not configured\n")
    assert doc["available"] is False


# --- backend pre-flight (final-review I8) -------------------------------------


def test_preflight_if_pppoe_passes_with_pppoe_iface_up():
    ifaces = {"pppoe0": {"up": True}, "igc0": {"up": True}}
    parsers.validate_backend_preflight("if_pppoe", {}, ifaces)  # must not raise


def test_preflight_if_pppoe_rejects_missing_iface():
    ifaces = {"igc0": {"up": True}}
    with pytest.raises(RuntimeError, match="pppoe"):
        parsers.validate_backend_preflight("if_pppoe", {}, ifaces)


def test_preflight_if_pppoe_rejects_down_iface():
    ifaces = {"pppoe0": {"up": False}}
    with pytest.raises(RuntimeError, match="up"):
        parsers.validate_backend_preflight("if_pppoe", {}, ifaces)


def test_preflight_mpd5_tuned_rejects_mismatched_isr_sysctls():
    dut_sysctls = {"net.isr.dispatch": "direct", "net.isr.maxthreads": 1, "net.isr.bindthreads": 0}
    with pytest.raises(RuntimeError, match="net.isr"):
        parsers.validate_backend_preflight("mpd5-tuned", dut_sysctls, {"ng0": {"up": True}})


def test_preflight_mpd5_tuned_passes_with_matching_isr_sysctls():
    dut_sysctls = {"net.isr.dispatch": "deferred", "net.isr.maxthreads": -1, "net.isr.bindthreads": 1}
    parsers.validate_backend_preflight("mpd5-tuned", dut_sysctls, {"ng0": {"up": True}})  # must not raise


def test_preflight_plain_has_no_iface_requirement():
    assert parsers.validate_backend_preflight("plain", {}, {}) is None


def test_preflight_returns_the_wan_iface_it_found():
    ifaces = {"pppoe0": {"up": True}, "vtnet1": {"up": True}}
    assert parsers.validate_backend_preflight("if_pppoe", {}, ifaces) == "pppoe0"
    raw = {"vtnet1": {"up": True}}
    assert parsers.validate_backend_preflight("raw", {}, raw) == "vtnet1"


def test_preflight_mpd5_accepts_lab_pppoe0_named_ng_iface():
    # The lab's mpd.conf renames the ng_iface to pppoe0 (`set iface name`).
    ifaces = {"pppoe0": {"up": True}}
    assert parsers.validate_backend_preflight("mpd5", {}, ifaces, pppoe_group=[]) == "pppoe0"


def test_preflight_pppoe_group_tells_if_pppoe_from_mpd5():
    ifaces = {"pppoe0": {"up": True}}
    # pppoe0 IS an if_pppoe clone: mpd5 must reject, if_pppoe accept.
    with pytest.raises(RuntimeError, match="not in the if_pppoe group"):
        parsers.validate_backend_preflight("mpd5", {}, ifaces, pppoe_group=["pppoe0"])
    assert parsers.validate_backend_preflight("if_pppoe", {}, ifaces, pppoe_group=["pppoe0"]) == "pppoe0"
    # pppoe0 is mpd5's renamed ng_iface: if_pppoe must reject.
    with pytest.raises(RuntimeError, match="in the if_pppoe group"):
        parsers.validate_backend_preflight("if_pppoe", {}, ifaces, pppoe_group=[])


def test_parse_ifconfig_group():
    assert parsers.parse_ifconfig_group("pppoe0\npppoe1\n") == ["pppoe0", "pppoe1"]
    assert parsers.parse_ifconfig_group("") == []


# --- raw backend pre-flight (final-review major follow-up) ---------------------


def test_preflight_raw_passes_with_no_pppoe_iface_and_matching_addr():
    ifaces = {"vtnet1": {"up": True}, "vtnet2": {"up": True}}
    ifconfig = "vtnet1: flags=... mtu 1500\n\tinet 192.168.99.2 netmask 0xffffff00\n"
    parsers.validate_backend_preflight("raw", {}, ifaces, ifconfig)  # must not raise


def test_preflight_raw_rejects_leftover_pppoe_iface():
    ifaces = {"pppoe0": {"up": True}, "vtnet1": {"up": True}}
    with pytest.raises(RuntimeError, match="pppoe0"):
        parsers.validate_backend_preflight("raw", {}, ifaces)


def test_preflight_raw_rejects_leftover_ng_iface():
    ifaces = {"ng0": {"up": True}, "vtnet1": {"up": True}}
    with pytest.raises(RuntimeError, match="ng0"):
        parsers.validate_backend_preflight("raw", {}, ifaces)


def test_preflight_raw_ignores_down_pppoe_iface():
    # A destroyed/down leftover doesn't route real traffic -- only an UP one
    # is a real risk to the ratio (mirrors the if_pppoe/mpd5 "up" check).
    ifaces = {"pppoe0": {"up": False}, "vtnet1": {"up": True}}
    parsers.validate_backend_preflight("raw", {}, ifaces)  # must not raise


def test_preflight_raw_rejects_wrong_wan_address():
    ifaces = {"vtnet1": {"up": True}}
    ifconfig = "vtnet1: flags=... mtu 1500\n\tinet 10.0.0.5 netmask 0xffffff00\n"
    with pytest.raises(RuntimeError, match="192.168.99.2"):
        parsers.validate_backend_preflight("raw", {}, ifaces, ifconfig)


def test_preflight_raw_skips_address_check_when_ifconfig_not_given():
    ifaces = {"vtnet1": {"up": True}}
    parsers.validate_backend_preflight("raw", {}, ifaces)  # must not raise


def test_parse_ifconfig_inet():
    text = "vtnet1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\toptions=...\n\tinet 192.168.99.2 netmask 0xffffff00 broadcast 192.168.99.255\n"
    assert parsers.parse_ifconfig_inet(text) == "192.168.99.2"


def test_parse_ifconfig_inet_none_when_absent():
    assert parsers.parse_ifconfig_inet("") is None
    assert parsers.parse_ifconfig_inet("vtnet1: flags=... mtu 1500\n") is None


# --- forwarded-traffic byte check (final-review major I8 follow-up) ------------


def test_validate_forwarded_bytes_passes_when_both_ifaces_track_iperf():
    delta = {
        "vtnet2": {"ibytes": 100, "obytes": 950_000_000},
        "pppoe0": {"ibytes": 940_000_000, "obytes": 200},
    }
    parsers.validate_forwarded_bytes(delta, "vtnet2", "pppoe0", iperf_bytes=1_000_000_000)  # must not raise


def test_validate_forwarded_bytes_rejects_missing_iface():
    delta = {"vtnet2": {"ibytes": 0, "obytes": 950_000_000}}
    with pytest.raises(RuntimeError, match="pppoe0"):
        parsers.validate_forwarded_bytes(delta, "vtnet2", "pppoe0", iperf_bytes=1_000_000_000)


def test_validate_forwarded_bytes_rejects_low_wan_delta():
    # e.g. a stale route: LAN saw the traffic but it never reached the WAN
    # iface -- exactly the "correctly labelled but meaningless" failure mode.
    delta = {
        "vtnet2": {"ibytes": 0, "obytes": 950_000_000},
        "pppoe0": {"ibytes": 12_345, "obytes": 0},
    }
    with pytest.raises(RuntimeError, match="pppoe0"):
        parsers.validate_forwarded_bytes(delta, "vtnet2", "pppoe0", iperf_bytes=1_000_000_000)


def test_validate_forwarded_bytes_skips_when_iperf_bytes_unknown():
    parsers.validate_forwarded_bytes({}, "vtnet2", "pppoe0", iperf_bytes=0)  # must not raise


# --- pfctl -si (no-root path) -------------------------------------------------


def test_parse_pfctl_si_empty_is_na():
    # without root, `pfctl -si | grep current entries` produces no output
    assert parsers.parse_pfctl_si("") == "n/a"


def test_parse_pfctl_si_present():
    assert parsers.parse_pfctl_si("current entries     42\n") == 42


# --- vmstat -i ----------------------------------------------------------------


def test_parse_vmstat_i():
    doc = parsers.parse_vmstat_i(read("vmstat_i_before.txt"))
    assert doc["irq130: igc0:rxq0"]["total"] == 889032109
    assert doc["irq130: igc0:rxq0"]["rate"] == 103
    assert doc["Total"]["total"] == 60674045236


def test_diff_irq_igc_only():
    before = parsers.parse_vmstat_i(read("vmstat_i_before.txt"))
    after = parsers.parse_vmstat_i(read("vmstat_i_after.txt"))
    delta = parsers.diff_irq(before, after, prefix="igc")
    assert delta["irq130: igc0:rxq0"] == 889032238 - 889032109
    assert delta["irq135: igc1:rxq0"] == 14731514115 - 14731510450
    # non-igc irqs (ahci0, cpuN:timer, Total) must not appear
    assert all("igc" in k for k in delta)
    # admin-queue rows are not an RX/TX queue and must not be summed in
    assert not any(k.endswith(":aq") for k in delta)


# --- top -SHPn -d 3 -s 2 -------------------------------------------------------


def test_parse_top_snapshots():
    snapshots = parsers.parse_top(read("top_sample.txt"))
    assert len(snapshots) == 3
    first = snapshots[0]
    assert first["cpu_idle"] == pytest.approx([97.5, 97.6, 97.6, 97.6])
    assert any(t["command"] == "top" for t in first["threads"])
    last = snapshots[-1]
    assert last["cpu_idle"] == pytest.approx([98.0, 99.2, 97.3, 99.6])


def test_reduce_top_means_over_snapshots_after_the_first():
    # The first snapshot is discarded (FreeBSD top's first display can
    # reflect stats since last reset, not the sampling interval); the
    # per-core idle% reported is the MEAN over the remaining snapshots,
    # not just the last one -- see reduce_top's docstring.
    snapshots = parsers.parse_top(read("top_sample.txt"))
    reduced = parsers.reduce_top(snapshots)
    # snapshot[1].cpu_idle = [98.0, 99.2, 98.4, 98.8]
    # snapshot[2].cpu_idle = [98.0, 99.2, 97.3, 99.6]
    assert reduced["cpu_idle_per_core"] == pytest.approx([98.0, 99.2, 97.85, 99.2])
    assert len(reduced["top_threads"]) <= 5
    assert reduced["top_threads"][0]["wcpu"] >= reduced["top_threads"][-1]["wcpu"]


def test_reduce_top_single_snapshot_falls_back_to_it():
    snapshots = parsers.parse_top(read("top_sample.txt"))[:1]
    reduced = parsers.reduce_top(snapshots)
    assert reduced["cpu_idle_per_core"] == pytest.approx([97.5, 97.6, 97.6, 97.6])


def test_top_iterations_for_scales_with_duration():
    # delay fixed at 5s; iterations sized so iterations*delay ~= duration,
    # with a floor of 3 iterations for very short runs.
    assert parsers.top_iterations_for(60, delay=5) == 12
    assert parsers.top_iterations_for(3, delay=5) == 3  # floor, not 1
    assert parsers.top_iterations_for(600, delay=5) == 120


# --- iperf3 -J parsing ----------------------------------------------------------


def test_parse_iperf_tcp_forward():
    doc = read_json("iperf_tcp_forward.json")
    r = parsers.parse_iperf_result(doc, proto="tcp")
    assert r["gbps"] == pytest.approx(60515458186.76965 / 1e9)
    assert r["retransmits"] == 20
    assert r["lost_percent"] is None
    assert r["bytes"] == doc["end"]["sum_sent"]["bytes"]


def test_parse_iperf_tcp_reverse():
    doc = read_json("iperf_tcp_reverse.json")
    r = parsers.parse_iperf_result(doc, proto="tcp")
    assert r["gbps"] == pytest.approx(51541672511.2676 / 1e9)
    assert r["retransmits"] == 2
    assert r["lost_percent"] is None


def test_parse_iperf_udp_1400():
    doc = read_json("iperf_udp1400.json")
    r = parsers.parse_iperf_result(doc, proto="udp")
    # receiver-side rate/bytes (what was forwarded), sender rate kept too
    assert r["gbps"] == pytest.approx(3205849609.17009 / 1e9)
    assert r["sent_gbps"] == pytest.approx(3241139563.6755333 / 1e9)
    assert r["retransmits"] is None
    assert r["lost_percent"] == pytest.approx(1.083871413279928)
    assert r["bytes"] == doc["end"]["sum_received"]["bytes"]


def test_parse_iperf_udp_64():
    doc = read_json("iperf_udp64.json")
    r = parsers.parse_iperf_result(doc, proto="udp")
    assert r["lost_percent"] == pytest.approx(0.05958171206225681)


def test_parse_iperf_udp_1400_reverse():
    # end.sum.bits_per_second is send-side, lost_percent is receive-side,
    # in both directions -- confirmed via this real -R capture; gbps is
    # taken from end.sum_received.
    doc = read_json("iperf_udp1400_reverse.json")
    assert doc["start"]["test_start"]["reverse"] == 1
    r = parsers.parse_iperf_result(doc, proto="udp")
    assert r["gbps"] == pytest.approx(3571983950.6370192 / 1e9)
    assert r["sent_gbps"] == pytest.approx(3579393670.56487 / 1e9)
    assert r["retransmits"] is None
    assert r["lost_percent"] == pytest.approx(0.20725226633322913)


def test_parse_iperf_result_raises_on_error_json():
    # Real captured output of `iperf3 -c 127.0.0.1 -p 15299 -t 1 -J`
    # against a closed port.
    doc = read_json("iperf_error.json")
    assert "error" in doc
    with pytest.raises(ValueError, match="unable to connect to server"):
        parsers.parse_iperf_result(doc, proto="tcp")


def test_parse_iperf_result_raises_on_missing_end():
    with pytest.raises(ValueError, match="end"):
        parsers.parse_iperf_result({"start": {}}, proto="tcp")


# --- output JSON schema ----------------------------------------------------------


def test_validate_schema_accepts_well_formed_doc():
    doc = {
        "meta": {
            "backend": "plain",
            "server": "lab-host.example",
            "client": "lab-host.example",
            "dut": "dut.example",
            "started": "2026-09-12T00:00:00Z",
            "duration": 3,
            "flows": [1],
            "dut_uname": "FreeBSD dut.example 14.3-RELEASE-p7",
            "dut_sysctls": {"net.isr.dispatch": "direct"},
        },
        "runs": [
            {
                "flows": 1,
                "proto": "tcp",
                "direction": "download",
                "pkt_len": None,
                "iperf": {"end": {}},
                "gbps": 1.0,
                "retransmits": 0,
                "lost_percent": None,
                "dut": {
                    "cpu_idle_per_core": [99.0],
                    "top_threads": [],
                    "top_raw": "last pid: ...",
                    "if_errors_delta": {},
                    "irq_delta": {},
                    "mbuf_before": {},
                    "mbuf_after": {},
                },
            }
        ],
    }
    parsers.validate_schema(doc)  # must not raise


def test_validate_schema_rejects_missing_key():
    with pytest.raises(ValueError):
        parsers.validate_schema({"meta": {}})


def test_validate_schema_rejects_missing_top_raw():
    doc = {
        "meta": {
            "backend": "plain", "server": "s", "client": "c", "dut": "d",
            "started": "x", "duration": 1, "flows": [1], "dut_uname": "x",
            "dut_sysctls": {},
        },
        "runs": [
            {
                "flows": 1, "proto": "tcp", "direction": "download", "pkt_len": None,
                "iperf": {}, "gbps": 1.0, "retransmits": 0, "lost_percent": None,
                "dut": {
                    "cpu_idle_per_core": [99.0], "top_threads": [],
                    "if_errors_delta": {}, "irq_delta": {},
                    "mbuf_before": {}, "mbuf_after": {},
                    # top_raw deliberately omitted
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="top_raw"):
        parsers.validate_schema(doc)


# --- ssh_collectors.configure() / ssh -F wiring (VM-lab jump-host reachability) --


def test_ssh_command_default_has_no_dash_F():
    ssh_collectors.configure(None)
    argv = ssh_collectors.ssh_command("dut.example", "echo hi")
    assert "-F" not in argv


def test_ssh_command_uses_configured_ssh_config():
    try:
        ssh_collectors.configure("/tmp/lab-ssh-config")
        argv = ssh_collectors.ssh_command("lab-router", "echo hi")
        assert argv[:3] == ["ssh", "-F", "/tmp/lab-ssh-config"]
        assert argv[-2:] == ["lab-router", "echo hi"]
    finally:
        ssh_collectors.configure(None)  # other tests assume the default


# --- ssh_collectors error handling -----------------------------------------------


def test_run_ssh_raises_on_nonzero_exit():
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, returncode=255,
            stdout="",
            stderr="ssh: connect to host nonexistent.invalid port 22: Name or service not known\n",
        )

    with pytest.raises(RuntimeError, match="255"):
        ssh_collectors.run_ssh("nonexistent.invalid", "echo hi", _runner=fake_runner)


def test_run_ssh_raises_on_timeout():
    def fake_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))

    with pytest.raises(RuntimeError, match="timed out"):
        ssh_collectors.run_ssh("dut.example", "netstat -m", timeout=5, _runner=fake_runner)


def test_run_ssh_real_unreachable_host_raises():
    # No injection: a real ssh attempt against an address that cannot be
    # reached (TEST-NET-1, RFC 5737) with a short ConnectTimeout.
    with pytest.raises(RuntimeError):
        ssh_collectors.run_ssh("192.0.2.1", "echo hi", timeout=5)


def test_run_iperf3_client_raises_on_error_json():
    error_doc = read("iperf_error.json")

    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode=1, stdout=error_doc, stderr="")

    with pytest.raises(RuntimeError, match="unable to connect to server"):
        ssh_collectors.run_iperf3_client(
            "client.example", ["-c", "127.0.0.1", "-p", "15299", "-t", "1", "-J"],
            timeout=10, _runner=fake_runner,
        )


def test_run_iperf3_client_raises_on_no_output():
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode=255, stdout="", stderr="ssh: connection lost\n")

    with pytest.raises(RuntimeError, match="no output"):
        ssh_collectors.run_iperf3_client(
            "client.example", ["-c", "server", "-J"], timeout=10, _runner=fake_runner,
        )


# --- run_matrix.py --dry-run end-to-end ------------------------------------------


def test_dry_run_prints_planned_commands(tmp_path):
    script = Path(__file__).parent / "run_matrix.py"
    out_file = tmp_path / "out.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--backend",
            "plain",
            "--server",
            "server.example",
            "--client",
            "client.example",
            "--dut",
            "dut.example",
            "--flows",
            "1,4",
            "--duration",
            "5",
            "--out",
            str(out_file),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    # planned client-side iperf3 invocations
    assert "iperf3 -c server.example -P 1 -t 5 -J" in proc.stdout
    assert "iperf3 -c server.example -P 1 -t 5 -J -R" in proc.stdout
    assert "-u -l 1400 -b 0 -P 1" in proc.stdout
    assert "-u -l 64 -b 0 -P 1" in proc.stdout
    assert "-P 4" in proc.stdout
    # planned DUT collector invocations
    assert "ssh dut.example" in proc.stdout
    assert "netstat -m" in proc.stdout
    assert "netstat -ibnd" in proc.stdout
    assert "vmstat -i" in proc.stdout
    # duration=5, delay=5 -> top_iterations_for(5, delay=5) == 3 (floor)
    assert "top -SHPn -d 3 -s 5" in proc.stdout
    # new phase-2 collectors
    assert "netstat -Q" in proc.stdout
    assert "sysctl net.pppoe" in proc.stdout
    assert "vmstat -z" in proc.stdout
    assert "lockstat" in proc.stdout
    assert "pmcstat" in proc.stdout
    # dry-run must not create the output file or touch the network
    assert not out_file.exists()


def test_raw_is_an_accepted_backend_choice():
    script = Path(__file__).parent / "run_matrix.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--backend", "raw", "--server", "s", "--client", "c",
         "--dut", "d", "--flows", "1", "--dry-run"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_run_matrix_ssh_config_flag_is_wired_to_ssh_collectors(tmp_path, monkeypatch):
    # Unit-level (not subprocess): --ssh-config must reach ssh_collectors.configure()
    # before any ssh call, so VM-lab host aliases resolve through their ProxyJump.
    sys.path.insert(0, str(Path(__file__).parent))
    import run_matrix  # noqa: E402

    try:
        args = run_matrix.parse_args([
            "--backend", "plain", "--server", "s", "--client", "c", "--dut", "d",
            "--flows", "1", "--ssh-config", "/tmp/lab-ssh-config", "--dry-run",
            "--out", str(tmp_path / "out.json"),
        ])
        ssh_collectors.configure(None)
        assert args.ssh_config == "/tmp/lab-ssh-config"
        run_matrix.ssh.configure(args.ssh_config)
        assert ssh_collectors.ssh_command("lab-router", "echo hi")[:3] == [
            "ssh", "-F", "/tmp/lab-ssh-config",
        ]
    finally:
        ssh_collectors.configure(None)


def test_real_run_aborts_cleanly_on_unreachable_dut(tmp_path):
    # End-to-end: an unresolvable DUT hostname must abort the matrix
    # with a clear message and a non-zero exit, not a raw traceback and
    # not a silently-empty result file.
    script = Path(__file__).parent / "run_matrix.py"
    out_file = tmp_path / "out.json"
    proc = subprocess.run(
        [
            sys.executable, str(script),
            "--backend", "plain",
            "--server", "server.example",
            "--client", "client.example",
            "--dut", "nonexistent.invalid",
            "--flows", "1",
            "--duration", "3",
            "--out", str(out_file),
        ],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "nonexistent.invalid" in proc.stderr
    assert not out_file.exists()


# --- sample_lockstat.py --dry-run end-to-end -------------------------------------


def test_sample_lockstat_dry_run(tmp_path):
    script = Path(__file__).parent / "sample_lockstat.py"
    out_file = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, str(script), "--dut", "dut.example", "--duration", "10",
         "--stack-depth", "10", "--out", str(out_file), "--dry-run"],
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    assert "lockstat -P -s 10 sleep 10" in proc.stdout
    assert "pmcstat" in proc.stdout
    assert not out_file.exists()


# --- summarize.py -------------------------------------------------------------


def test_summarize_table(tmp_path):
    doc = {
        "meta": {
            "backend": "plain",
            "server": "s",
            "client": "c",
            "dut": "d",
            "started": "x",
            "duration": 3,
            "flows": [1],
            "dut_uname": "x",
            "dut_sysctls": {},
        },
        "runs": [
            {
                "flows": 1,
                "proto": "tcp",
                "direction": "download",
                "pkt_len": None,
                "iperf": {},
                "gbps": 2.345,
                "retransmits": 7,
                "lost_percent": None,
                "dut": {"cpu_idle_per_core": [95.0, 90.0], "top_threads": [],
                         "if_errors_delta": {}, "irq_delta": {},
                         "mbuf_before": {}, "mbuf_after": {}},
            },
            {
                "flows": 1,
                "proto": "udp",
                "direction": "download",
                "pkt_len": 64,
                "iperf": {},
                "gbps": 0.084,
                "retransmits": None,
                "lost_percent": 0.06,
                "dut": {"cpu_idle_per_core": [80.0], "top_threads": [],
                         "if_errors_delta": {}, "irq_delta": {},
                         "mbuf_before": {}, "mbuf_after": {}},
            },
        ],
    }
    json_path = tmp_path / "r.json"
    json_path.write_text(json.dumps(doc))
    script = Path(__file__).parent / "summarize.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(json_path)],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    assert "backend" in proc.stdout and "Gbit/s" in proc.stdout
    assert "2.345" in proc.stdout
    assert "90.0" in proc.stdout  # min core idle for the tcp row
    assert "0.06%" in proc.stdout


def _summarize(script: Path, *files: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *[str(f) for f in files]],
        capture_output=True, text=True, timeout=10,
    )


def test_summarize_single_run_schema(tmp_path):
    # Per-run audit-trail files use {"meta": {...}, "run": {...}} instead of
    # a top-level "runs" list (schema of tests/results/lab-ab/*-flow.json).
    doc = {
        "meta": {"backend": "mpd5", "server": "s", "client": "c",
                 "dut": "d", "started": "x", "duration": 30},
        "run": {
            "flows": 4, "proto": "tcp", "direction": "download",
            "pkt_len": None, "iperf": {}, "gbps": 1.412,
            "retransmits": None, "lost_percent": None,
            "dut": {"cpu_idle_per_core": [70.0], "top_threads": [],
                    "if_errors_delta": {}, "irq_delta": {},
                    "mbuf_before": {}, "mbuf_after": {}},
        },
    }
    json_path = tmp_path / "r.json"
    json_path.write_text(json.dumps(doc))
    script = Path(__file__).parent / "summarize.py"
    proc = _summarize(script, json_path)
    assert proc.returncode == 0, proc.stderr
    assert "mpd5" in proc.stdout and "1.412" in proc.stdout
    assert "70.0" in proc.stdout


def test_summarize_mixed_schemas(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    multi = tmp_path / "multi.json"
    multi.write_text(json.dumps({
        "meta": {"backend": "if_pppoe"},
        "runs": [{"flows": 1, "proto": "tcp", "direction": "upload",
                  "pkt_len": None, "iperf": {}, "gbps": 0.9,
                  "retransmits": 3, "lost_percent": None,
                  "dut": {"cpu_idle_per_core": [88.0]}}],
    }))
    single = tmp_path / "single.json"
    single.write_text(json.dumps({
        "meta": {"backend": "mpd5"},
        "run": {"flows": 1, "proto": "tcp", "direction": "upload",
                "pkt_len": None, "iperf": {}, "gbps": 0.85,
                "retransmits": 5, "lost_percent": None,
                "dut": {"cpu_idle_per_core": [80.0]}},
    }))
    proc = _summarize(script, multi, single)
    assert proc.returncode == 0, proc.stderr
    assert "if_pppoe" in proc.stdout and "mpd5" in proc.stdout
    assert "0.900" in proc.stdout and "0.850" in proc.stdout


def test_summarize_malformed_json_is_clean_error(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    proc = _summarize(script, bad)
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "malformed JSON" in proc.stderr


def test_summarize_missing_backend_is_clean_error(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    doc = {"meta": {}, "run": {"gbps": 1.0}}
    bad = tmp_path / "no-backend.json"
    bad.write_text(json.dumps(doc))
    proc = _summarize(script, bad)
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "meta.backend" in proc.stderr


def test_summarize_nonexistent_file_is_clean_error(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    proc = _summarize(script, tmp_path / "nonexistent.invalid")
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "no runs found" in proc.stderr


# --- summarize.py --ratio-baseline (phase-2 forwarded harness) -------------------


def _matrix_doc(backend: str, gbps: float, flows: int = 4, direction: str = "download") -> dict:
    return {
        "meta": {"backend": backend},
        "runs": [{
            "flows": flows, "proto": "tcp", "direction": direction, "pkt_len": None,
            "iperf": {}, "gbps": gbps, "retransmits": 3, "lost_percent": None,
            "dut": {"cpu_idle_per_core": [60.0]},
        }],
    }


def test_summarize_ratio_baseline_column(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(_matrix_doc("raw", 2.000)))
    pppoe = tmp_path / "if_pppoe.json"
    pppoe.write_text(json.dumps(_matrix_doc("if_pppoe", 1.500)))
    proc = subprocess.run(
        [sys.executable, str(script), "--ratio-baseline", "raw", str(raw), str(pppoe)],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ratio-to-raw" in proc.stdout
    lines = {line.split("|")[0].strip(): line for line in proc.stdout.splitlines()}
    assert lines["raw"].rstrip().endswith("1.000")
    assert lines["if_pppoe"].rstrip().endswith("0.750")  # 1.500 / 2.000


def test_summarize_ratio_baseline_no_match_for_shape_is_na(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(_matrix_doc("raw", 2.000, flows=1)))
    pppoe = tmp_path / "if_pppoe.json"
    pppoe.write_text(json.dumps(_matrix_doc("if_pppoe", 1.500, flows=16)))  # no flows=16 baseline row
    proc = subprocess.run(
        [sys.executable, str(script), "--ratio-baseline", "raw", str(raw), str(pppoe)],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    lines = {line.split("|")[0].strip(): line for line in proc.stdout.splitlines()}
    assert lines["if_pppoe"].rstrip().endswith("n/a")


def test_summarize_ratio_baseline_absent_entirely_is_clean_error(tmp_path):
    script = Path(__file__).parent / "summarize.py"
    pppoe = tmp_path / "if_pppoe.json"
    pppoe.write_text(json.dumps(_matrix_doc("if_pppoe", 1.500)))
    proc = subprocess.run(
        [sys.executable, str(script), "--ratio-baseline", "raw", str(pppoe)],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "matched no rows" in proc.stderr
