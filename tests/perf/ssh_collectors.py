"""Read-only ssh wrappers to collect DUT and iperf3 raw text/JSON.

Every DUT command here is read-only and needs no root: netstat, sysctl
-r/-n reads, vmstat -i, top, and a best-effort pfctl -si that is expected
to fail (and is treated as such) when run without root -- that specific
expected failure is masked with `|| true` in the remote command string
itself (see run_matrix.py), so it never reaches run_ssh as a nonzero
exit; any nonzero exit that does reach run_ssh is a real ssh/connectivity
failure and must not be swallowed into fake-looking empty output.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any, Callable

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]

Runner = Callable[..., subprocess.CompletedProcess]

# Set by configure() so run_matrix.py can reach VM-lab hosts (only directly
# ssh-able through the lab host as a jump host, per-VM ports -- lab/vm/common.sh)
# by an alias name, via `ssh -F <config> <alias> ...`, instead of a bare hostname.
_SSH_CONFIG: str | None = None


def configure(ssh_config: str | None) -> None:
    """Set (or clear, with None) the ssh client config file every ssh_command
    build uses (`-F <ssh_config>`). Call once, before any collector runs."""
    global _SSH_CONFIG
    _SSH_CONFIG = ssh_config


def ssh_command(host: str, remote_cmd: str) -> list[str]:
    """Build the argv for `ssh host remote_cmd`."""
    config_opts = ["-F", _SSH_CONFIG] if _SSH_CONFIG else []
    return ["ssh", *config_opts, *SSH_OPTS, host, remote_cmd]


def run_ssh_raw(
    host: str, remote_cmd: str, timeout: float | None = None, _runner: Runner = subprocess.run
) -> subprocess.CompletedProcess:
    """Run `remote_cmd` on `host` over ssh; return the CompletedProcess as-is.

    Does not raise on a nonzero remote exit status -- callers that need
    that (run_ssh) or that need to inspect output even on failure
    (run_iperf3_client) build on this. `_runner` is a subprocess.run-alike
    injection point for tests.
    """
    return _runner(
        ssh_command(host, remote_cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_ssh(
    host: str, remote_cmd: str, timeout: float | None = None, _runner: Runner = subprocess.run
) -> str:
    """Run `remote_cmd` on `host` over ssh and return stdout.

    Raises RuntimeError on a nonzero exit (dead host, auth failure,
    dropped connection, ...) or a timeout -- a silent empty/partial
    result here would otherwise be indistinguishable from legitimate
    output and get recorded as a valid sample.
    """
    try:
        proc = run_ssh_raw(host, remote_cmd, timeout=timeout, _runner=_runner)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"ssh {host} timed out after {timeout}s running {remote_cmd!r}"
        ) from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh {host} exited {proc.returncode} running {remote_cmd!r}: "
            f"stderr={proc.stderr.strip()!r} stdout={proc.stdout.strip()!r}"
        )
    return proc.stdout


def collect_dut_snapshot(dut: str) -> dict[str, Any]:
    """One before/after snapshot: netstat -m, netstat -ibnd, vmstat -i, pfctl -si.

    Returns raw text for each, to be parsed by parsers.py.
    """
    return {
        "netstat_m": run_ssh(dut, "netstat -m | head -5", timeout=15),
        "netstat_ibnd": run_ssh(dut, "netstat -ibnd", timeout=15),
        "vmstat_i": run_ssh(dut, "vmstat -i", timeout=15),
        # pfctl -si fails without root; the remote `|| true` converts
        # that *expected* failure into ssh exit 0 with empty stdout,
        # which parsers.parse_pfctl_si turns into "n/a". Any other
        # (unmasked) nonzero exit here is a real ssh failure and raises.
        "pfctl_si": run_ssh(
            dut, "pfctl -si 2>/dev/null | grep -E 'current entries' || true", timeout=15
        ),
    }


def collect_dut_static(dut: str) -> dict[str, Any]:
    """One-time, run-independent DUT facts: uname, isr sysctls, netstat -ibnd
    (the last is also what the backend pre-flight check reads for interface
    presence/up state, so it doesn't need its own separate ssh round trip).
    """
    return {
        "uname": run_ssh(dut, "uname -a", timeout=15).strip(),
        "sysctl_isr": run_ssh(
            dut, "sysctl net.isr.dispatch net.isr.maxthreads net.isr.bindthreads", timeout=15
        ),
        "netstat_ibnd": run_ssh(dut, "netstat -ibnd", timeout=15),
    }


def collect_top_sample(dut: str, iterations: int, delay: int, timeout: float) -> str:
    """Run `top -SHPn -d <iterations> -s <delay>` on the DUT and return raw text."""
    return run_ssh(dut, f"top -SHPn -d {iterations} -s {delay}", timeout=timeout)


def collect_dut_pppoe_snapshot(dut: str) -> dict[str, Any]:
    """One before/after snapshot: `netstat -Q` and `sysctl net.pppoe`, both
    best-effort (`|| true`, same convention as pfctl_si) since a
    non-if_pppoe backend or an unloaded module makes the pppoe row/sysctl
    absent, not an ssh failure -- parsers.parse_netstat_Q/parse_sysctl_pppoe
    must tolerate that empty input rather than this collector raising.
    """
    return {
        "netstat_Q": run_ssh(dut, "netstat -Q 2>/dev/null || true", timeout=15),
        "sysctl_pppoe": run_ssh(dut, "sysctl net.pppoe 2>/dev/null || true", timeout=15),
    }


def collect_vmstat_z_mbuf(dut: str) -> str:
    """`vmstat -z` filtered to the header + mbuf*-prefixed zone rows."""
    return run_ssh(dut, "vmstat -z 2>/dev/null | grep -iE '^(ITEM|mbuf)' || true", timeout=15)


def collect_ifconfig(dut: str, iface: str) -> str:
    """`ifconfig <iface>`, best-effort (an absent iface is not an ssh
    failure -- parsers.parse_ifconfig_inet tolerates the empty/error text).
    """
    return run_ssh(dut, f"ifconfig {iface} 2>/dev/null || true", timeout=15)


def collect_ifconfig_group(dut: str, group: str) -> str:
    """`ifconfig -g <group>`: member iface names, one per line (empty if none)."""
    return run_ssh(dut, f"ifconfig -g {shlex.quote(group)} 2>/dev/null || true", timeout=15)


def as_root(cmd: str, root_cmd: str | None) -> str:
    """Wrap `cmd` for root execution with the `root_cmd` template, whose
    `{}` is replaced by the shell-quoted `cmd` -- e.g. "sudo -n sh -c {}",
    or the lab client VM's "echo | su -m root -c {}" (lab/vm/router-mode.sh's
    idiom: no sudo in the FreeBSD base system, root has no password).
    """
    if not root_cmd:
        return cmd
    return root_cmd.replace("{}", shlex.quote(cmd))


def collect_pf_info(dut: str, root_cmd: str) -> str:
    """`pfctl -si` as root: pf Status (Enabled/Disabled) + state-table counters,
    proof that the forwarded traffic actually went through pf (and its NAT)."""
    return run_ssh(dut, as_root("pfctl -si", root_cmd) + " 2>&1 || true", timeout=15)


def probe_lockstat_available(dut: str) -> str:
    """Cheap, root-free availability probe for lockstat(1) (needs DTrace
    kernel support). Does not sample -- see run_lockstat_sample.
    """
    return run_ssh(
        dut, "command -v lockstat >/dev/null 2>&1 && echo available || echo 'lockstat: not found'", timeout=10
    )


def probe_pmcstat_available(dut: str) -> str:
    """Cheap, root-free availability probe for hwpmc(4)/pmcstat(8). A KVM
    guest without vPMU passthrough is expected to report unavailable.
    """
    return run_ssh(
        dut,
        "command -v pmcstat >/dev/null 2>&1 || { echo 'pmcstat: not found'; exit 0; }; pmcstat -L 2>&1 | head -5",
        timeout=10,
    )


def run_lockstat_sample(
    dut: str, duration: int, stack_depth: int = 10, timeout: float | None = None, sudo: bool = False,
    root_cmd: str | None = None,
) -> str:
    """Sample system-wide lock contention for `duration` seconds via the
    documented lockstat(1) idiom ("gathers data until the specified
    command completes... to gather statistics for a fixed-time interval,
    use sleep(1) as the command"). Requires root on the DUT ("access to
    lockstat is restricted to the superuser by default"); every other
    collector here is root-free, so this one does not prepend sudo unless
    `sudo=True` -- as a non-root user without it, this always ends in
    lockstat's own permission-denied error, not a usable sample.
    """
    cmd = f"lockstat -P -s {stack_depth} sleep {duration}"
    if root_cmd:
        # dtraceall first: lockstat needs the lockstat DTrace provider loaded.
        cmd = as_root(f"kldstat -q -m dtraceall || kldload dtraceall; {cmd}", root_cmd)
    elif sudo:
        cmd = f"sudo -n {cmd}"
    return run_ssh(
        dut, cmd,
        timeout=timeout if timeout is not None else duration + 30,
    )


def run_iperf3_client(
    client_host: str, iperf_args: list[str], timeout: float, _runner: Runner = subprocess.run
) -> dict[str, Any]:
    """Run `iperf3 <iperf_args>` on client_host over ssh and parse the JSON.

    Does NOT go through run_ssh's strict nonzero-exit check: iperf3
    itself exits nonzero on a connection failure while still emitting a
    JSON body with an "error" key on stdout, and that message is more
    useful than a bare "ssh exited 1". Any nonzero exit that produced no
    parseable JSON at all (a real ssh-level failure) still raises.
    """
    remote_cmd = "iperf3 " + " ".join(iperf_args)
    proc = run_ssh_raw(client_host, remote_cmd, timeout=timeout, _runner=_runner)
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError(
            f"ssh {client_host} produced no output running {remote_cmd!r} "
            f"(exit {proc.returncode}): stderr={proc.stderr.strip()!r}"
        )
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"ssh {client_host} iperf3 output was not valid JSON "
            f"(exit {proc.returncode}): {stdout[:500]!r}"
        ) from exc
    if "error" in doc:
        raise RuntimeError(f"iperf3 on {client_host} reported an error: {doc['error']}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"ssh {client_host} exited {proc.returncode} running {remote_cmd!r} "
            f"(no 'error' key in JSON): stderr={proc.stderr.strip()!r}"
        )
    return doc
