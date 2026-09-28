"""Local-only unit tests for console_driver.Session: no ssh, no qemu, no
nc -- `cat` stands in as the remote process so expect()/send() and the
timeout path are exercised without any lab hardware. Run with:
    cd lab/vm && python3 -m pytest test_console_driver.py
"""
import io
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from console_driver import AbortMarker, ExpectTimeout, Session, _ssh_console_cmd

# Same VMHOST env var lab/vm/common.sh's scripts use; a placeholder here
# since this test never actually connects anywhere (see docstring above).
VMHOST = os.environ.get("VMHOST", "lab-host.example")


def test_ssh_console_cmd_uses_sudo_nc():
    # The console socket is created by qemu under sudo, and the lab host has
    # no socat -- run.sh's own console_send uses `sudo nc -U`, and the driver
    # must match it rather than shelling out to a socat that isn't there.
    cmd = _ssh_console_cmd(VMHOST, "/run/if_pppoe-lab/dut.serial.sock")
    assert cmd[:3] == ["ssh", "-o", "ConnectTimeout=8"]
    assert cmd[3] == VMHOST
    assert cmd[4] == "sudo nc -U -q 0 /run/if_pppoe-lab/dut.serial.sock"


@pytest.fixture
def cat_session():
    proc = subprocess.Popen(
        ["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
    )
    logf = io.BytesIO()
    # connect_timeout=0.2: `cat` produces nothing on its own, so the
    # constructor's idle-drain should return promptly rather than blocking
    # for the full default 60s.
    sess = Session(vmhost="unused", sock_path="unused", logf=logf, connect_timeout=0.2, proc=proc)
    yield sess, logf
    sess.close()


def test_send_is_echoed_and_matched(cat_session):
    sess, logf = cat_session
    sess.send("hello")
    seen = sess.expect("hello", timeout=5)
    assert "hello" in seen
    assert b">>> hello\n" in logf.getvalue()


def test_expect_consumes_only_up_to_marker(cat_session):
    sess, logf = cat_session
    sess.send("AAAmarkerBBB")
    sess.expect("marker", timeout=5)
    # "BBB" (after the marker) must still be pending for the next expect --
    # a real console session's later steps must not silently skip output
    # that arrived alongside an earlier marker.
    rest = sess.expect("BBB", timeout=5)
    assert rest == "BBB"


def test_expect_times_out_on_missing_marker(cat_session):
    sess, _ = cat_session
    sess.send("no marker here")
    with pytest.raises(ExpectTimeout):
        sess.expect("NEVER_APPEARS", timeout=1)


def test_multi_step_script_runs_in_order(cat_session):
    sess, _ = cat_session
    sess.send("step1-done")
    sess.expect("step1-done", timeout=5)
    sess.send("step2-done")
    sess.expect("step2-done", timeout=5)


def test_fail_marker_aborts_before_success_marker(cat_session):
    # Regression for the provision-dut.sh copy-check bug: the peer (`cat`
    # here stands in for a shell that echoes the command it was sent, same
    # as a real serial console tty) prints FAILED, not DONE -- expect() must
    # raise AbortMarker instead of hanging until its timeout.
    sess, _ = cat_session
    sess.send("mount failed; echo DUTSEED_COPY_FAILED")
    with pytest.raises(AbortMarker) as excinfo:
        sess.expect("DUTSEED_COPY_DONE", timeout=5, fail_markers=["DUTSEED_COPY_FAILED"])
    assert excinfo.value.marker == "DUTSEED_COPY_FAILED"


def test_success_marker_wins_when_fail_marker_is_only_in_the_echoed_command():
    # A split marker (printf '%s' A B, as provision-dut.sh now sends) must
    # not spuriously trip fail_markers just because the echo of the SENT
    # command contains both substrings non-contiguously. `cat` can't stand
    # in here (it never executes anything, so the real DONE would never
    # appear) -- a tty-like peer that echoes the line THEN runs it does.
    proc = subprocess.Popen(
        ["sh", "-c", "while IFS= read -r line; do echo \"$line\"; eval \"$line\"; done"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
    )
    logf = io.BytesIO()
    sess = Session(vmhost="unused", sock_path="unused", logf=logf, connect_timeout=0.2, proc=proc)
    try:
        sess.send("printf 'DUTSEED_%s\\n' COPY_DONE")
        seen = sess.expect("DUTSEED_COPY_DONE", timeout=5, fail_markers=["DUTSEED_COPY_FAILED"])
        assert "DUTSEED_COPY_DONE" in seen
    finally:
        sess.close()


def test_nudge_after_resends_on_missed_prompt(cat_session):
    # Simulates a chardev socket that dropped the initial prompt (qemu's
    # wait=off): nothing arrives until our own nudge (a bare newline) is
    # sent, and only THEN does the peer (a fake menu, not `cat`, so the
    # nudge produces a distinguishable reply) print the marker.
    sess, _ = cat_session
    sess.close()  # replace `cat` with a peer that replies to blank input
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys\n"
         "sys.stdin.readline()\n"
         "print('Enter an option:')\n"
         "sys.stdout.flush()\n"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
    )
    logf = io.BytesIO()
    nudge_sess = Session(vmhost="unused", sock_path="unused", logf=logf, connect_timeout=0.2, proc=proc)
    try:
        start = time.monotonic()
        seen = nudge_sess.expect("Enter an option:", timeout=5, nudge_after=0.3)
        elapsed = time.monotonic() - start
        assert "Enter an option:" in seen
        # must have actually waited for the nudge, not raced past it
        assert elapsed >= 0.25
    finally:
        nudge_sess.close()
