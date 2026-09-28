"""Pure, no-I/O parsers for DUT collector text and iperf3 -J JSON.

All functions here take strings/dicts already fetched by ssh_collectors.py
(or a test fixture) and return plain dicts. Kept dependency-free (stdlib
only) and side-effect-free so they're trivially unit-testable.
"""
from __future__ import annotations

import re
from typing import Any

# vtnet: the VM lab's NICs (lab/vm/router-mode.sh's vtnet1/vtnet2); igc: real
# hardware. Both must be captured for the forwarded-traffic byte check below.
DEFAULT_IFACE_PATTERN = r"^(igc\d+|vtnet\d+|pppoe\d+|ng\d+)$"


# --- netstat -m --------------------------------------------------------------

_NETSTAT_M_MBUFS_RE = re.compile(
    r"^(\d+)/(\d+)/(\d+) mbufs in use \(current/cache/total\)", re.MULTILINE
)
_NETSTAT_M_CLUSTERS_RE = re.compile(
    r"^(\d+)/(\d+)/(\d+)/(\d+) mbuf clusters in use \(current/cache/total/max\)",
    re.MULTILINE,
)


def parse_netstat_m(text: str) -> dict[str, Any]:
    """Parse `netstat -m | head -5` output.

    Returns current/cache/total mbuf counts and current/cache/total/max
    mbuf cluster counts, plus the raw text for audit trails.
    """
    doc: dict[str, Any] = {"raw": text}
    m = _NETSTAT_M_MBUFS_RE.search(text)
    if m:
        doc["mbufs_current"] = int(m.group(1))
        doc["mbufs_cache"] = int(m.group(2))
        doc["mbufs_total"] = int(m.group(3))
    c = _NETSTAT_M_CLUSTERS_RE.search(text)
    if c:
        doc["mbuf_clusters_current"] = int(c.group(1))
        doc["mbuf_clusters_cache"] = int(c.group(2))
        doc["mbuf_clusters_total"] = int(c.group(3))
        doc["mbuf_clusters_max"] = int(c.group(4))
    return doc


# --- netstat -ibnd -------------------------------------------------------------

_IF_FIELDS = ["ipkts", "ierrs", "idrop", "ibytes", "opkts", "oerrs", "obytes", "coll", "drop"]


def parse_netstat_ibnd(text: str, iface_pattern: str = DEFAULT_IFACE_PATTERN) -> dict[str, dict[str, int]]:
    """Parse `netstat -ibnd` output.

    Only the per-link (Link#N) row for each matching interface is kept --
    that's the row carrying real Ipkts/Ierrs/etc counters; the per-network
    address rows below it use '-' placeholders and are skipped.
    """
    pattern = re.compile(iface_pattern)
    result: dict[str, dict[str, int]] = {}
    lines = text.splitlines()
    if lines and lines[0].lstrip().startswith("Name"):
        lines = lines[1:]
    for line in lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 12:
            continue
        raw_name = parts[0]
        name = raw_name.rstrip("*")
        if "<Link#" not in line:
            continue
        if not pattern.match(name):
            continue
        # Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll Drop
        # parts[2] is "<Link#N>" (Network), parts[3] is Address (a MAC, may
        # contain no spaces) -- numeric fields start at parts[4].
        numeric = parts[4:4 + len(_IF_FIELDS)]
        if len(numeric) != len(_IF_FIELDS):
            continue
        try:
            values = [int(v) for v in numeric]
        except ValueError:
            continue
        entry = dict(zip(_IF_FIELDS, values))
        # netstat marks a down interface with a trailing '*' on the Name
        # column (verified against a live down `igc2*` row) -- surfaced here
        # so a caller (e.g. the backend pre-flight check) can tell "present"
        # from "present and up" without re-parsing the raw text.
        entry["up"] = not raw_name.endswith("*")
        result[name] = entry
    return result


def diff_if_errors(before: dict[str, dict[str, int]], after: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """Per-interface after-before delta for every counter field.

    Interfaces present in `before` but missing from `after` (or vice
    versa) are treated as all-zero on the missing side.
    """
    delta: dict[str, dict[str, int]] = {}
    for name in sorted(set(before) | set(after)):
        b = before.get(name, {})
        a = after.get(name, {})
        delta[name] = {f: a.get(f, 0) - b.get(f, 0) for f in _IF_FIELDS}
    return delta


# --- sysctl net.isr.* ----------------------------------------------------------

def parse_sysctl_isr(text: str) -> dict[str, Any]:
    """Parse `sysctl net.isr.dispatch net.isr.maxthreads net.isr.bindthreads`."""
    doc: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.lstrip("-").isdigit():
            doc[key] = int(value)
        else:
            doc[key] = value
    return doc


# --- backend pre-flight ---------------------------------------------------------
# A mislabeled run (DUT not actually configured the way --backend claims)
# produces a correctly-labelled but wrong result (final-review I8).

EXPECTED_ISR_SYSCTLS: dict[str, dict[str, Any]] = {
    "mpd5-tuned": {
        "net.isr.dispatch": "deferred",
        "net.isr.maxthreads": -1,
        "net.isr.bindthreads": 1,
    },
}

EXPECTED_IFACE_PATTERN: dict[str, str | None] = {
    "if_pppoe": r"^pppoe\d+$",
    # The lab's mpd.conf renames ngN to pppoe0 (`set iface name`); the
    # pppoe_group check in validate_backend_preflight tells it from if_pppoe.
    "mpd5": r"^(ng|pppoe)\d+$",
    "mpd5-tuned": r"^(ng|pppoe)\d+$",
    "plain": None,
}

# "raw" (the phase-2 forwarded-harness no-PPPoE baseline, docs/PERF-FWD-
# DESIGN.md) is handled separately below, not via EXPECTED_IFACE_PATTERN: it
# needs the OPPOSITE check (no PPPoE/netgraph interface up -- a leftover
# pppoe0/ng0 from a prior backend pass would route some frames through
# if_pppoe's or ng_ether's pfil hook and bias the ratio in PPPoE's favour;
# final-review minor "raw baseline measured while PPPoE still attached"),
# plus confirming vtnet1 actually carries the raw WAN address.
RAW_FORBIDDEN_IFACE_PATTERN = r"^(pppoe\d+|ng\d+)$"
RAW_WAN_IFACE = "vtnet1"
RAW_WAN_ADDR = "192.168.99.2"

_IFCONFIG_INET_RE = re.compile(r"^\s*inet (\d+\.\d+\.\d+\.\d+)\b", re.MULTILINE)


def parse_ifconfig_inet(text: str) -> str | None:
    """First IPv4 address in an `ifconfig <iface>` capture, or None."""
    m = _IFCONFIG_INET_RE.search(text)
    return m.group(1) if m else None


def validate_backend_preflight(
    backend: str,
    dut_sysctls: dict[str, Any],
    ibnd_ifaces: dict[str, dict[str, Any]],
    raw_wan_ifconfig: str | None = None,
    pppoe_group: list[str] | None = None,
) -> str | None:
    """Raise RuntimeError if the DUT doesn't match what `--backend` expects;
    return the WAN interface the check found (RAW_WAN_IFACE for raw, the up
    PPPoE interface otherwise, None for a backend with no iface check).

    Checks the net.isr.* sysctls `--backend` requires (if any). For
    if_pppoe/mpd5/mpd5-tuned, also checks that a matching PPPoE-ish
    interface is present *and* up in a `netstat -ibnd` snapshot
    (`entry["up"]`, from parse_netstat_ibnd) -- not just present, since a
    down interface would otherwise pass a naive membership check. For
    "raw", instead checks that NO PPPoE/netgraph interface is up (see
    lab/vm/teardown-nonraw.sh) and, when `raw_wan_ifconfig` (an
    `ifconfig vtnet1` capture) is given, that vtnet1 carries the raw
    baseline's static address.
    """
    expected_sysctls = EXPECTED_ISR_SYSCTLS.get(backend, {})
    mismatches = [
        f"{k}={dut_sysctls.get(k)!r} (expected {v!r})"
        for k, v in expected_sysctls.items()
        if dut_sysctls.get(k) != v
    ]
    if mismatches:
        raise RuntimeError(
            f"--backend {backend} requires DUT net.isr.* sysctls that don't match: "
            + ", ".join(mismatches)
        )

    if backend == "raw":
        forbidden = re.compile(RAW_FORBIDDEN_IFACE_PATTERN)
        up_forbidden = sorted(
            name for name, entry in ibnd_ifaces.items() if forbidden.match(name) and entry.get("up")
        )
        if up_forbidden:
            raise RuntimeError(
                f"--backend raw expects no PPPoE/netgraph interface up, found up: {up_forbidden} "
                "-- run lab/vm/teardown-nonraw.sh (stop mpd5, destroy pppoe0/ng0, kldunload if_pppoe) first"
            )
        if raw_wan_ifconfig is not None:
            addr = parse_ifconfig_inet(raw_wan_ifconfig)
            if addr != RAW_WAN_ADDR:
                raise RuntimeError(
                    f"--backend raw expects {RAW_WAN_IFACE} to carry {RAW_WAN_ADDR} "
                    f"(see provision-isp-raw.sh / router-mode.sh enable raw); got {addr!r}"
                )
        return RAW_WAN_IFACE

    pattern = EXPECTED_IFACE_PATTERN.get(backend)
    if pattern is not None:
        regex = re.compile(pattern)
        up_matches = [name for name, entry in ibnd_ifaces.items() if regex.match(name) and entry.get("up")]
        if pppoe_group is not None:
            # if_pppoe clones join the "pppoe" ifnet group; mpd5's ng_iface
            # renamed pppoeN does not -- the only name-independent tell.
            if backend == "if_pppoe":
                up_matches = [n for n in up_matches if n in pppoe_group]
            elif backend.startswith("mpd5"):
                up_matches = [n for n in up_matches if n not in pppoe_group]
        if not up_matches:
            seen = sorted(ibnd_ifaces)
            raise RuntimeError(
                f"--backend {backend} expects an interface matching {pattern!r} "
                f"up in `netstat -ibnd`"
                + ("" if pppoe_group is None else
                   f" ({'in' if backend == 'if_pppoe' else 'not in'} the if_pppoe "
                   f"group, members {sorted(pppoe_group)})")
                + f"; none found (interfaces seen: {seen})"
            )
        return sorted(up_matches)[0]
    return None


def parse_ifconfig_group(text: str) -> list[str]:
    """`ifconfig -g <group>` prints one member interface name per line."""
    return [ln.strip() for ln in text.splitlines() if re.match(r"^[a-z][a-z0-9_.]*\d+$", ln.strip())]


# --- pfctl -si (no root) --------------------------------------------------------

def parse_pfctl_si(text: str) -> Any:
    """Parse `pfctl -si | grep 'current entries'`.

    Without root this typically produces no output at all (pfctl fails);
    record "n/a" rather than a false zero.
    """
    text = text.strip()
    if not text:
        return "n/a"
    m = re.search(r"current entries\s+(\d+)", text)
    if m:
        return int(m.group(1))
    return "n/a"


_PFCTL_STATUS_RE = re.compile(r"^Status:\s+(\w+)", re.MULTILINE)
_PFCTL_COUNTER_RE = re.compile(r"^\s+(current entries|searches|inserts|removals)\s+(\d+)", re.MULTILINE)


def parse_pfctl_info(text: str) -> dict[str, Any]:
    """Parse a root `pfctl -si`: {"status": "Enabled"|"Disabled"|None,
    "current entries": n, "searches": n, "inserts": n, "removals": n}."""
    m = _PFCTL_STATUS_RE.search(text)
    doc: dict[str, Any] = {"status": m.group(1) if m else None}
    for cm in _PFCTL_COUNTER_RE.finditer(text):
        doc[cm.group(1)] = int(cm.group(2))
    return doc


# --- vmstat -i -------------------------------------------------------------------

_VMSTAT_I_RE = re.compile(r"^(.+?)\s+(\d+)\s+(\d+)\s*$")


def parse_vmstat_i(text: str) -> dict[str, dict[str, int]]:
    """Parse `vmstat -i` into {irq_label: {total, rate}}."""
    doc: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if line.strip().startswith("interrupt"):
            continue
        m = _VMSTAT_I_RE.match(line)
        if not m:
            continue
        label, total, rate = m.group(1).strip(), int(m.group(2)), int(m.group(3))
        doc[label] = {"total": total, "rate": rate}
    return doc


def diff_irq(
    before: dict[str, dict[str, int]],
    after: dict[str, dict[str, int]],
    prefix: str = "igc",
) -> dict[str, int]:
    """Delta of `total` interrupt counts for labels containing `prefix`.

    Excludes `:aq` (admin-queue) rows -- they aren't an RX/TX queue, so
    summing them in with rxq/txq rows would understate per-queue spread.
    """
    delta: dict[str, int] = {}
    for name in sorted(set(before) | set(after)):
        if prefix not in name or name.endswith(":aq"):
            continue
        b = before.get(name, {}).get("total", 0)
        a = after.get(name, {}).get("total", 0)
        delta[name] = a - b
    return delta


# --- top -SHPn -d N -s M --------------------------------------------------------

_TOP_CPU_RE = re.compile(r"^CPU (\d+):.*?([\d.]+)% idle\s*$")
_TOP_THREAD_RE = re.compile(
    # NICE is "ki31" for idle threads and "-" for interrupt/kernel threads.
    r"^\s*(\d+)\s+(\S+)\s+(-?\d+|RT)\s+(-?\d+|ki-?\d+|-)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+([\d:.]+)\s+([\d.]+)%\s+(.+?)\s*$"
)


def parse_top(text: str) -> list[dict[str, Any]]:
    """Parse one or more `top -SHPn -d N -s M` snapshots.

    Returns a list of snapshots, each {"cpu_idle": [core0, core1, ...],
    "threads": [{"pid", "username", "wcpu", "command"}, ...]}.
    """
    snapshots: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_thread_table = False
    for line in text.splitlines():
        if line.startswith("last pid:"):
            current = {"cpu_idle": [], "threads": []}
            snapshots.append(current)
            in_thread_table = False
            continue
        if current is None:
            continue
        cpu_m = _TOP_CPU_RE.match(line)
        if cpu_m:
            current["cpu_idle"].append(float(cpu_m.group(2)))
            continue
        if line.strip().startswith("PID USERNAME"):
            in_thread_table = True
            continue
        if in_thread_table and line.strip():
            t_m = _TOP_THREAD_RE.match(line)
            if t_m:
                current["threads"].append(
                    {
                        "pid": int(t_m.group(1)),
                        "username": t_m.group(2),
                        "wcpu": float(t_m.group(10)),
                        "command": t_m.group(11),
                    }
                )
    return snapshots


def reduce_top(snapshots: list[dict[str, Any]], top_n: int = 5) -> dict[str, Any]:
    """Reduce multiple top snapshots (spanning the whole run) to a summary.

    cpu_idle_per_core is the MEAN idle% per core over all snapshots
    except the first (FreeBSD top's first display can reflect stats
    since the last reset rather than the `-s` interval, so it's dropped
    as a warm-up sample when more than one snapshot is available).
    cpu_busy_peak_per_core is 100 - the LOWEST idle% each core showed in
    any (non-warm-up) snapshot: the saturation signal. A core pinned at
    ~100% busy for one `-s` interval is a serialisation point the mean
    dilutes (and a thread migrating between cores averages out to "all
    cores half busy").
    top_threads is the top-N threads by the MAX WCPU any thread reached
    in any (non-warm-up) snapshot, so a brief spike isn't averaged away.
    """
    if not snapshots:
        return {"cpu_idle_per_core": [], "cpu_busy_peak_per_core": [], "top_threads": []}
    used = snapshots[1:] if len(snapshots) > 1 else snapshots
    num_cores = min(len(s["cpu_idle"]) for s in used)
    cpu_idle_per_core = [
        sum(s["cpu_idle"][i] for s in used) / len(used) for i in range(num_cores)
    ]
    cpu_busy_peak_per_core = [
        round(100.0 - min(s["cpu_idle"][i] for s in used), 1) for i in range(num_cores)
    ]
    # Keyed by (pid, command): with -H every kernel thread (netisr, intr,
    # idle) shares one pid (intr=12, idle=11), told apart only by COMMAND.
    best_by_pid: dict[tuple, dict[str, Any]] = {}
    for snap in used:
        for t in snap["threads"]:
            if t["command"].startswith("idle{"):
                continue  # per-core idle is cpu_idle_per_core's job
            key = (t["pid"], t["command"])
            cur = best_by_pid.get(key)
            if cur is None or t["wcpu"] > cur["wcpu"]:
                best_by_pid[key] = t
    top_threads = sorted(best_by_pid.values(), key=lambda t: t["wcpu"], reverse=True)
    return {
        "cpu_idle_per_core": cpu_idle_per_core,
        "cpu_busy_peak_per_core": cpu_busy_peak_per_core,
        "top_threads": top_threads[:top_n],
    }


def top_iterations_for(duration: int, delay: int = 5, min_iterations: int = 3) -> int:
    """Number of `top -d` iterations so `iterations * delay` ~= duration.

    Floors at `min_iterations` so very short runs still get more than
    one post-warm-up sample.
    """
    return max(min_iterations, round(duration / delay))


# --- iperf3 -J -------------------------------------------------------------------

def parse_iperf_result(doc: dict[str, Any], proto: str) -> dict[str, Any]:
    """Extract {gbps, retransmits, lost_percent} from a parsed iperf3 -J doc.

    TCP: throughput and retransmits come from end.sum_sent, which is
    always the true TCP-sender's counters regardless of -R (iperf3
    reports it under sum_sent in both directions -- confirmed against
    fixtures/iperf_tcp_{forward,reverse}.json).
    UDP: end.sum carries both bits_per_second and lost_percent, in both
    directions (confirmed against fixtures/iperf_udp1400_reverse.json:
    end.sum.bits_per_second is the send-side count, end.sum.lost_percent
    the receive-side measurement, regardless of -R).

    Raises ValueError if `doc` is iperf3's failure shape (an "error"
    key, e.g. connection refused) or is missing "end" entirely -- a
    failed run must never be silently reported as gbps=0.0.
    """
    if "error" in doc:
        raise ValueError(f"iperf3 result contains an error: {doc['error']}")
    end = doc.get("end")
    if not end:
        raise ValueError("iperf3 result missing 'end' section (failed or truncated run?)")
    if proto == "udp":
        # Receiver-side (end.sum_received): a `-b 0` flood is mostly dropped
        # at a saturated router, and the far-side iface only sees what arrived.
        summ = end.get("sum", {})
        recv = end.get("sum_received") or summ
        return {
            "gbps": recv.get("bits_per_second", 0.0) / 1e9,
            "sent_gbps": summ.get("bits_per_second", 0.0) / 1e9,
            "retransmits": None,
            "lost_percent": summ.get("lost_percent"),
            "bytes": recv.get("bytes", 0),
        }
    # tcp
    sum_sent = end.get("sum_sent", {})
    bps = sum_sent.get("bits_per_second", 0.0)
    return {
        "gbps": bps / 1e9,
        "retransmits": sum_sent.get("retransmits"),
        "lost_percent": None,
        "bytes": sum_sent.get("bytes", 0),
    }


# --- forwarded-traffic check (final-review major I8 follow-up) ------------------
# Nothing previously compared measured traffic against the DUT's actual
# forwarding path: a wrong target IP, a stale route, or the lan VM leaving
# through its slirp NIC would produce a correctly-labelled but meaningless
# number. LAN_IFACE mirrors lab/vm/router-mode.sh's fixed topology; the WAN
# iface is whichever one validate_backend_preflight found up (pppoe0 for both
# if_pppoe and the lab's mpd5, vtnet1 for raw).

LAN_IFACE = "vtnet2"


def validate_forwarded_bytes(
    if_bytes_delta: dict[str, dict[str, int]],
    lan_iface: str,
    wan_iface: str,
    iperf_bytes: int,
    min_fraction: float = 0.9,
) -> None:
    """Raise RuntimeError unless both `lan_iface` and `wan_iface` carried at
    least `min_fraction` of iperf3's own reported transferred bytes.

    `if_bytes_delta` is a per-iface {"ibytes": int, "obytes": int, ...} delta
    (diff_if_errors's output over two `netstat -ibnd` snapshots taken
    before/after the run). Whichever direction the flow ran, one of ibytes/
    obytes on each iface should track iperf3's count -- so the check takes
    whichever of the two is larger, rather than assuming a direction.
    """
    if iperf_bytes <= 0:
        return  # nothing to compare against; parse_iperf_result already
        # raises on a genuinely failed run before this is ever called.
    threshold = iperf_bytes * min_fraction
    problems = []
    for iface in (lan_iface, wan_iface):
        entry = if_bytes_delta.get(iface)
        if entry is None:
            problems.append(f"{iface}: no netstat -ibnd row seen at all")
            continue
        seen = max(entry.get("ibytes", 0), entry.get("obytes", 0))
        if seen < threshold:
            problems.append(
                f"{iface}: byte delta {seen} < {min_fraction:.0%} of iperf3's {iperf_bytes} "
                "transferred bytes"
            )
    if problems:
        raise RuntimeError(
            "forwarded-traffic check failed (traffic may not have gone through the DUT's "
            "forwarding path): " + "; ".join(problems)
        )


# --- output schema (from task-7-brief.md) ---------------------------------------

_META_KEYS = {
    "backend", "server", "client", "dut", "started", "duration", "flows",
    "dut_uname", "dut_sysctls",
}
_RUN_KEYS = {
    "flows", "proto", "direction", "pkt_len", "iperf", "gbps",
    "retransmits", "lost_percent", "dut",
}
_RUN_DUT_KEYS = {
    "cpu_idle_per_core", "top_threads", "top_raw", "if_errors_delta", "irq_delta",
    "mbuf_before", "mbuf_after",
}


def validate_schema(doc: dict[str, Any]) -> None:
    """Validate a run_matrix.py output document against the brief's schema.

    Raises ValueError naming the first missing/malformed piece; returns
    None (does not raise) for a well-formed document.
    """
    if "meta" not in doc:
        raise ValueError("missing top-level 'meta'")
    if "runs" not in doc:
        raise ValueError("missing top-level 'runs'")
    meta = doc["meta"]
    missing = _META_KEYS - set(meta)
    if missing:
        raise ValueError(f"meta missing keys: {sorted(missing)}")
    if not isinstance(doc["runs"], list):
        raise ValueError("'runs' must be a list")
    for i, run in enumerate(doc["runs"]):
        missing = _RUN_KEYS - set(run)
        if missing:
            raise ValueError(f"runs[{i}] missing keys: {sorted(missing)}")
        dut = run["dut"]
        missing = _RUN_DUT_KEYS - set(dut)
        if missing:
            raise ValueError(f"runs[{i}].dut missing keys: {sorted(missing)}")


# --- netstat -Q (netisr protocol table + per-workstream counters) -----------------
# Real sample: tests/results/lab-ab/spread-netisr-q.txt (T2 evidence), sliced into
# fixtures/netstat_Q_{before,after}.txt.

_NETQ_PROTO_FIELDS = ["name", "proto", "qlimit", "policy", "dispatch", "flags"]
_NETQ_WS_FIELDS = ["wsid", "cpu", "name", "len", "wmark", "dispd", "hdispd", "qdrops", "queued", "handled"]
_NETQ_WS_INT_FIELDS = ["wsid", "cpu", "len", "wmark", "dispd", "hdispd", "qdrops", "queued", "handled"]


def parse_netstat_Q(text: str) -> dict[str, Any]:
    """Parse `netstat -Q`: {"protocols": {name: {...}}, "workstreams": [{...}, ...]}."""
    protocols: dict[str, dict[str, Any]] = {}
    workstreams: list[dict[str, Any]] = []
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "Protocols:":
            section = "protocols"; continue
        if stripped == "Workstreams:":
            section = "workstreams"; continue
        if stripped.startswith("Name") and "Proto" in stripped:
            continue
        if stripped.startswith("WSID"):
            continue
        parts = stripped.split()
        if section == "protocols" and len(parts) == len(_NETQ_PROTO_FIELDS):
            protocols[parts[0]] = {
                "proto": int(parts[1]), "qlimit": int(parts[2]),
                "policy": parts[3], "dispatch": parts[4], "flags": parts[5],
            }
        elif section == "workstreams" and len(parts) == len(_NETQ_WS_FIELDS):
            entry = dict(zip(_NETQ_WS_FIELDS, parts))
            for f in _NETQ_WS_INT_FIELDS:
                entry[f] = int(entry[f])
            workstreams.append(entry)
    return {"protocols": protocols, "workstreams": workstreams}


def pppoe_workstreams(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Filter parse_netstat_Q()'s workstreams to the 'pppoe' protocol rows."""
    return [w for w in parsed.get("workstreams", []) if w.get("name") == "pppoe"]


def diff_pppoe_workstreams(before: dict[str, Any], after: dict[str, Any]) -> dict[int, dict[str, int]]:
    """Per-CPU delta of handled/qdrops/queued for the pppoe netisr protocol.

    A non-zero qdrops delta on any CPU means the pppoe netisr queue
    overflowed under load (if_pppoe_netisr.c nh_qlimit) -- the regression
    this collector exists to catch (R023 follow-up).
    """
    b = {w["cpu"]: w for w in pppoe_workstreams(before)}
    a = {w["cpu"]: w for w in pppoe_workstreams(after)}
    return {
        cpu: {
            "handled": a.get(cpu, {}).get("handled", 0) - b.get(cpu, {}).get("handled", 0),
            "qdrops": a.get(cpu, {}).get("qdrops", 0) - b.get(cpu, {}).get("qdrops", 0),
            "queued": a.get(cpu, {}).get("queued", 0) - b.get(cpu, {}).get("queued", 0),
        }
        for cpu in sorted(set(b) | set(a))
    }


def diff_netisr_workstreams(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-PROTOCOL netisr delta over every protocol in `netstat -Q`
    (ip, ether, arp, ip6, pppoe, ...), not just pppoe: the raw baseline has
    no pppoe row at all, and a decapsulated if_pppoe frame goes on as ip --
    an overflowing ip queue drops traffic as surely as a pppoe one.

    {proto: {"qdrops": total, "queued": total, "handled": total,
             "handled_per_cpu": {cpu: n}}}; protocols whose delta is all
    zero are omitted.
    """
    def by_key(parsed: dict[str, Any]) -> dict[tuple, dict[str, Any]]:
        return {(w["name"], w["cpu"]): w for w in parsed.get("workstreams", [])}

    b, a = by_key(before), by_key(after)
    out: dict[str, dict[str, Any]] = {}
    for key in sorted(set(a) | set(b)):
        name, cpu = key
        entry = out.setdefault(name, {"qdrops": 0, "queued": 0, "handled": 0, "handled_per_cpu": {}})
        for f in ("qdrops", "queued", "handled"):
            entry[f] += a.get(key, {}).get(f, 0) - b.get(key, {}).get(f, 0)
        entry["handled_per_cpu"][cpu] = a.get(key, {}).get("handled", 0) - b.get(key, {}).get("handled", 0)
    return {k: v for k, v in out.items() if v["qdrops"] or v["queued"] or v["handled"]}


# --- sysctl net.pppoe.* ------------------------------------------------------------

_CPU_HITS_RE = re.compile(r"cpu(\d+)=(\d+)")


def parse_cpu_hits(value: str) -> dict[str, int]:
    """Parse a `net.pppoe.cpu_hits` value ("cpu0=22248 cpu1=0 ...")."""
    return {f"cpu{m.group(1)}": int(m.group(2)) for m in _CPU_HITS_RE.finditer(value)}


def parse_sysctl_pppoe(text: str) -> dict[str, Any]:
    """Parse `sysctl net.pppoe` (every net.pppoe.* counter/tunable).

    `net.pppoe.cpu_hits` is a PROC handler with its own "cpuN=count ..."
    shape (if_pppoe_netisr.c pppoe_sysctl_cpu_hits), special-cased via
    parse_cpu_hits; every other key is int-if-numeric else raw string.
    """
    doc: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "net.pppoe.cpu_hits":
            doc[key] = parse_cpu_hits(value)
        elif value.lstrip("-").isdigit():
            doc[key] = int(value)
        else:
            doc[key] = value
    return doc


def diff_cpu_hits(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """Per-CPU delta of a net.pppoe.cpu_hits dict between two samples."""
    return {cpu: after.get(cpu, 0) - before.get(cpu, 0) for cpu in sorted(set(before) | set(after))}


# --- vmstat -z (UMA zone stats, mbuf-related rows only) -----------------------------
# releng/14.3's domemstat_zone() prints 8 comma-separated plain integers
# (SIZE,LIMIT,USED,FREE,REQ,FAIL,SLEEP,XDOM; no thousands separators) --
# confirmed against https://cgit.freebsd.org/src/plain/usr.bin/vmstat/vmstat.c?h=releng/14.3.
# A 7-column row (no XDOM) is also accepted, for an older vmstat. Column
# *names* come from the collected header line when present (not a fixed
# count), so field order changes don't silently mis-assign values the way
# the old FreeBSD-9-forum-sample regex did (merged "728,539089502" into one
# "free" field against a real 8-column row).

_VMSTAT_Z_HEADER_ALIASES = {"req": "req", "requests": "req", "xdom": "xdomain", "xdomain": "xdomain"}
_VMSTAT_Z_DEFAULT_KEYS_8 = ["size", "limit", "used", "free", "req", "fail", "sleep", "xdomain"]
_VMSTAT_Z_DEFAULT_KEYS_7 = ["size", "limit", "used", "free", "req", "fail", "sleep"]


def parse_vmstat_z_mbuf(text: str) -> dict[str, dict[str, int]]:
    """Parse the mbuf*-prefixed rows of `vmstat -z`.

    Reads the "ITEM ..." header line (if present in `text`) to name columns
    positionally; falls back to the known 8- or 7-column mbuf-zone layout
    when there's no header line to key off, or its field count doesn't
    match a data row's.
    """
    header_keys: list[str] | None = None
    doc: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.upper().startswith("ITEM"):
            header_keys = [
                _VMSTAT_Z_HEADER_ALIASES.get(tok.lower(), tok.lower())
                for tok in stripped.split()[1:]
            ]
            continue
        if not stripped.lower().startswith("mbuf"):
            continue
        name, sep, rest = stripped.partition(":")
        if not sep:
            continue
        raw_fields = [f.strip() for f in rest.split(",") if f.strip() != ""]
        try:
            values = [int(f) for f in raw_fields]
        except ValueError:
            continue
        if header_keys is not None and len(header_keys) == len(values):
            keys = header_keys
        elif len(values) == 8:
            keys = _VMSTAT_Z_DEFAULT_KEYS_8
        elif len(values) == 7:
            keys = _VMSTAT_Z_DEFAULT_KEYS_7
        else:
            continue
        doc[name] = dict(zip(keys, values))
    return doc


# --- lockstat / pmcstat availability probes (best-effort, optional) ----------------
# Neither's report layout is parsed (unverified this session) -- just availability;
# see docs/PERF-FWD-DESIGN.md.

_UNAVAILABLE_MARKERS = (
    "not found", "no such file", "operation not permitted", "cannot",
    "command not found", "device not configured", "dtrace requires",
)


def _probe_available(text: str) -> bool:
    lowered = text.lower()
    return bool(text.strip()) and not any(m in lowered for m in _UNAVAILABLE_MARKERS)


_LOCKSTAT_SECTION_RE = re.compile(r"^(\S[^:]*): (\d+) events in ([\d.]+) seconds")
_LOCKSTAT_ROW_RE = re.compile(r"^\s*(\d+)\s+(\d+)%\s+(\d+)%\s+([\d.]+)\s+(\d+)\s+(.+?)\s+(\S+)\s*$")


def parse_lockstat(text: str, top_n: int = 8) -> dict[str, Any]:
    """Summarise `lockstat -P [-s N] sleep T` output (layout confirmed
    against a real FreeBSD 14.3 capture, fixtures/lockstat_sample.txt).

    Per section ("Adaptive mutex spin", "Adaptive mutex block", "Spin lock
    spin", ...): total events, seconds, and the top_n locks by total wait
    time (sum over that lock's caller rows of count * mean nsec), each with
    its busiest caller. Histogram/stack lines (-s) are skipped: they have
    a '|' where a row has its '%' columns.
    """
    sections: dict[str, Any] = {}
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        m = _LOCKSTAT_SECTION_RE.match(line)
        if m:
            cur = {"events": int(m.group(2)), "seconds": float(m.group(3)), "_locks": {}}
            sections[m.group(1)] = cur
            continue
        if cur is None or "|" in line:
            continue
        r = _LOCKSTAT_ROW_RE.match(line)
        if not r:
            continue
        count, nsec, lock, caller = int(r.group(1)), int(r.group(5)), r.group(6).strip(), r.group(7)
        entry = cur["_locks"].setdefault(lock, {"lock": lock, "count": 0, "wait_ns": 0, "top_caller": caller, "_best": 0})
        entry["count"] += count
        entry["wait_ns"] += count * nsec
        if count * nsec > entry["_best"]:
            entry["_best"], entry["top_caller"] = count * nsec, caller
    for sec in sections.values():
        locks = sorted(sec.pop("_locks").values(), key=lambda e: e["wait_ns"], reverse=True)
        for e in locks:
            e.pop("_best")
            e["wait_ms_per_s"] = round(e["wait_ns"] / 1e6 / sec["seconds"], 3) if sec["seconds"] else None
        sec["top_locks"] = locks[:top_n]
    return sections


def parse_lockstat_probe(text: str) -> dict[str, Any]:
    """Classify a lockstat(1) availability probe: {"available": bool, "raw": text}."""
    return {"available": _probe_available(text), "raw": text}


def parse_pmcstat_probe(text: str) -> dict[str, Any]:
    """Classify an hwpmc(4)/pmcstat(8) availability probe: {"available": bool, "raw": text}."""
    return {"available": _probe_available(text), "raw": text}
