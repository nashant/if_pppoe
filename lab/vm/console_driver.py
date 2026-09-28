#!/usr/bin/env python3
"""console_driver.py -- a tiny expect(1)-alike for a qemu chardev serial
socket, reached over ssh (the socket itself is unix-domain, local to
VMHOST -- see run.sh's VM_CONSOLE_SOCK). Drives `opnsense-shell`'s console
menu (src/sbin/opnsense-shell, opnsense/core 25.7.11) for provision-dut.sh.

Not opnsense-specific: `Session` just does expect/send over a subprocess
pipe, so it's reusable for any VM_CONSOLE_SOCK console. Everything read and
sent is appended to --log, so a failed run leaves a full transcript.

Connects with `sudo nc -U` over ssh, the same as run.sh's console_send:
the lab VM host may have no socat, and the socket is created by qemu under
sudo, so a plain (non-sudo) nc can't open it.
"""
from __future__ import annotations

import argparse
import selectors
import shlex
import subprocess
import sys
import time


class ExpectTimeout(RuntimeError):
    pass


class AbortMarker(RuntimeError):
    """Raised when one of expect()'s fail_markers appears before the marker
    it was actually waiting for -- e.g. a peer that prints 'DONE' or 'FAILED'
    and only one of those means success. `marker`/`seen` let the caller
    report which one fired and what came with it."""
    def __init__(self, marker: str, seen: str):
        self.marker = marker
        self.seen = seen
        super().__init__(f"abort marker {marker!r} seen (last output: {seen[-500:]!r})")


def _ssh_console_cmd(vmhost: str, sock_path: str) -> list[str]:
    # -q 0: quit as soon as stdin hits EOF (Session.close()), instead of
    # lingering on the single-client qemu chardev until a later write
    # gets SIGPIPE and could block the next console_send/connect.
    return ["ssh", "-o", "ConnectTimeout=8", vmhost, f"sudo nc -U -q 0 {shlex.quote(sock_path)}"]


class Session:
    def __init__(self, vmhost: str, sock_path: str, logf, connect_timeout: float = 60.0,
                 proc: subprocess.Popen | None = None):
        # `proc` is an injection point for tests: pass any Popen with
        # stdin/stdout pipes in place of a real ssh+nc process.
        self.logf = logf
        self.proc = proc or subprocess.Popen(
            _ssh_console_cmd(vmhost, sock_path),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proc.stdout, selectors.EVENT_READ)
        self.buf = b""
        # give ssh+nc a moment to actually connect before the first expect
        self._drain(connect_timeout, until_idle=1.0)

    def _drain(self, timeout: float, until_idle: float | None = None) -> None:
        """Read whatever arrives for up to `timeout`s. If until_idle is set,
        return early once nothing new has arrived for that many seconds
        (used only to let the ssh+nc pipe settle at connect time)."""
        deadline = time.monotonic() + timeout
        last_data = time.monotonic()
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            for key, _ in self.sel.select(timeout=min(0.5, remaining)):
                chunk = key.fileobj.read(65536)
                if not chunk:
                    return
                self.buf += chunk
                self.logf.write(chunk)
                self.logf.flush()
                last_data = time.monotonic()
            if until_idle is not None and time.monotonic() - last_data >= until_idle:
                return

    def expect(self, marker: str, timeout: float = 60.0, fail_markers: list[str] | None = None,
               nudge_after: float | None = None, nudge: str = "") -> str:
        """Block until `marker` (plain substring) appears in the accumulated
        buffer, or raise ExpectTimeout. Returns + clears everything read so
        far up to and including whichever needle matched, so repeated
        expects don't re-match old output.

        fail_markers: if any of these substrings appears BEFORE `marker`
        does, raise AbortMarker instead of continuing to wait for `marker`
        (e.g. a peer that prints a FAILED marker instead of the expected
        DONE one) — checked on every poll, so whichever appears first wins.

        nudge_after: if set, send() `nudge` (default: a bare newline) every
        `nudge_after` seconds of no match, to make a menu that redraws on
        input reappear if the boot's first prompt was missed because the
        chardev socket had no listener yet (qemu's `wait=off` drops anything
        printed before a client connects)."""
        fail_markers = fail_markers or []
        needle = marker.encode()
        fail_needles = [(m, m.encode()) for m in fail_markers]
        deadline = time.monotonic() + timeout
        last_nudge = time.monotonic()
        while True:
            for fail_name, fail_needle in fail_needles:
                if fail_needle in self.buf:
                    idx = self.buf.index(fail_needle) + len(fail_needle)
                    seen, self.buf = self.buf[:idx], self.buf[idx:]
                    raise AbortMarker(fail_name, seen.decode(errors="replace"))
            if needle in self.buf:
                break
            now = time.monotonic()
            if now >= deadline:
                raise ExpectTimeout(f"timed out waiting for {marker!r}; last 2000B seen: {self.buf[-2000:]!r}")
            if nudge_after is not None and now - last_nudge >= nudge_after:
                self.send(nudge)
                last_nudge = now
            self._drain(min(1.0, deadline - now))
        idx = self.buf.index(needle) + len(needle)
        seen, self.buf = self.buf[:idx], self.buf[idx:]
        return seen.decode(errors="replace")

    def send(self, line: str) -> None:
        data = (line + "\n").encode()
        self.proc.stdin.write(data)
        self.proc.stdin.flush()
        self.logf.write(b">>> " + data)
        self.logf.flush()

    def close(self, grace: float = 10.0) -> None:
        # EOF, then let ssh+nc (-q 0) exit: an immediate terminate() drops
        # the last send() in flight (guest saw "/usr/local/etc/rc.reb", no reboot).
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.proc.terminate()


def run_script(vmhost: str, sock_path: str, steps: list[tuple[str, str]], log_path: str,
                connect_timeout: float = 60.0, proc: subprocess.Popen | None = None,
                boot_timeout: float | None = None, boot_nudge_after: float = 20.0,
                fail_markers: list[str] | None = None) -> None:
    """steps: [(expect_marker, send_line), ...]. An empty send_line means
    "expect only, send nothing" (used for the final wait).

    boot_timeout: if set, overrides the timeout for the FIRST step only (a
    real first boot can take much longer to reach the console menu than any
    later expect in the same script should ever need — see boot_nudge_after).
    boot_nudge_after: on the first step only, send a bare newline every this
    many seconds with no match, in case the menu was already printed (and
    lost — qemu's `wait=off` chardev drops output sent before a client
    connects) and needs a redraw to reappear.
    fail_markers: checked on every expect() in the script; if one appears,
    the whole script aborts with AbortMarker instead of hanging until its
    own timeout (e.g. a peer that prints a FAILED marker on error)."""
    with open(log_path, "ab") as logf:
        sess = Session(vmhost, sock_path, logf, connect_timeout=connect_timeout, proc=proc)
        try:
            for i, (marker, line) in enumerate(steps):
                if i == 0 and boot_timeout is not None:
                    sess.expect(marker, timeout=boot_timeout, fail_markers=fail_markers,
                                nudge_after=boot_nudge_after)
                else:
                    sess.expect(marker, fail_markers=fail_markers)
                if line:
                    sess.send(line)
        finally:
            sess.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vmhost", required=True)
    ap.add_argument("--sock", required=True, help="remote unix socket path (as seen on --vmhost)")
    ap.add_argument("--log", required=True)
    ap.add_argument("--connect-timeout", type=float, default=60.0,
                     help="how long to wait for ssh+nc to connect before the first expect")
    ap.add_argument("--boot-timeout", type=float, default=None,
                     help="timeout for the FIRST expect only (a real first boot can take much "
                          "longer to reach the console menu than any later step should ever need)")
    ap.add_argument("--boot-nudge-after", type=float, default=20.0,
                     help="on the first step only, send a bare newline every N idle seconds "
                          "(redraws a menu that was printed before we connected, and lost)")
    ap.add_argument("--fail-marker", action="append", default=[],
                     help="abort the whole script if this substring appears at any expect step "
                          "(repeatable)")
    ap.add_argument("step", nargs="*", help="alternating EXPECT SEND EXPECT SEND ... (SEND '' to expect-only)")
    args = ap.parse_args()
    if len(args.step) % 2 != 0:
        ap.error("steps must come in EXPECT SEND pairs")
    steps = list(zip(args.step[0::2], args.step[1::2]))
    try:
        run_script(args.vmhost, args.sock, steps, args.log, args.connect_timeout,
                   boot_timeout=args.boot_timeout, boot_nudge_after=args.boot_nudge_after,
                   fail_markers=args.fail_marker or None)
    except ExpectTimeout as e:
        print(f"console_driver: {e}", file=sys.stderr)
        return 1
    except AbortMarker as e:
        print(f"console_driver: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
