#!/usr/bin/env bash
# S02/T3: live CHAP-MD5 authentication against accel-ppp with secret redaction.
#
# Strictly ordered, evidence-terminating recipe (T3 plan step order):
#   1. bring up the S01 accel-ppp harness with CHAP-MD5 enabled via a
#      server-side chap-secrets file (file-based auth, no RADIUS)
#   2. client VM + in-kernel module, with unit-level CHAP-MD5 verification
#      (tests/sppp_chap_md5.c) inside the warm-up window: RFC 1321
#      known-answer digests + the known NetBSD CHAP challenge-response
#      vectors against BOTH MD5 providers (embedded RFC 1321 reference and
#      FreeBSD base libmd - the same API/lineage as the kernel's
#      sys/sys/md5.h that sys/net/if_spppsubr.c compiles against); the
#      CHAP authentication phase is confirmed in the client module log
#      (chap input -> chap output -> chap success, lcp opened, phase
#      network)
#   3. negative probe: a live dial configured with a WRONG secret must be
#      rejected (client module log: chap failure; server log: auth
#      failure; no session ever reaches SESSION)
#   4. run a live client session with a dedicated test user and a
#      run-time-generated test secret (never committed); assert the
#      session reaches and HOLDS the connected state (LCP + CHAP complete)
#   5. capture server-side and client-side logs AND a tcpdump of the
#      whole PPPoE/CHAP exchange to durable files
#   6. CHAP on the wire: tcpdump decode + structural pcap count + no
#      plaintext secret in the packet capture
#   7. secret-redaction assertion: fixed-string scans for the full test
#      secret and user:secret forms must return zero matches across all
#      captured logs, config dumps, process listings, and the packet
#      capture (CHAP is hash-only by construction, RFC 1994)
#   8. tear down the harness cleanly and record exit statuses
# (durable artifacts land under tests/results/chap-live/)
#
# Client is the in-kernel if_pppoe/sppp stack on the lab `client` VM
# (S01/S02-T1/T2 wiring).  The whole run is driven over ssh from this repo
# (any host with passwordless ssh to $VMHOST); the only local state
# produced is the durable evidence under tests/results/chap-live/.
#
# Secrets discipline (R011): the runtime-generated secret exists only in
# this process's environment and in tmpfs-only 0600 files on the
# lab hosts, which every path deletes.  It is NEVER echoed (no set -x),
# never appears in argv of any captured process, and is never committed.
# The server-side tmpfs credential file is the credential store (the only
# other copy, like /etc/ppp/chap-secrets) and is deliberately excluded
# from the redaction-scan corpus; every other capture - including the
# packet capture of the CHAP exchange - must match the secret or a
# user:secret form zero times.
#
# Usage: ./run-chap.sh        (needs the S01 lab + lab/vm tooling, VMHOST ssh)
#   REBUILD=0 skips the kmod rebuild if the deployed /tmp/if_pppoe.ko on
#   the client already carries the R011 redaction marker.
set -euo pipefail

VMHOST="${VMHOST:?set VMHOST in lab/local.env}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"
CLIENT_PORT=2223

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_DIR="$REPO_ROOT/tests/results/chap-live"
TRANSCRIPT="$RESULT_DIR/10-transcript.log"

PASS=0; FAIL=0
TEARDOWN_DONE=0
pass() { log "PASS: $*"; PASS=$((PASS+1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL+1)); }
log()  { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }

hssh() { ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" "$@"; }
cssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=8 -o LogLevel=ERROR -J "$VMHOST" -p "$CLIENT_PORT" freebsd@127.0.0.1 "$@"; }
# run a command as root on the client (freebsd su to a passwordless root;
# same pattern as lab/vm/build-module.sh's `echo | su -m root -c`).
croot() { cssh "echo | su -m root -c $(printf '%q' "$1")"; }
# shellcheck source=tests/integration/accel-ppp/creds.sh
. "$HARNESS_DIR/creds.sh"

teardown() {
    [ "$TEARDOWN_DONE" = "1" ] && return 0
    TEARDOWN_DONE=1
    [ "${KEEP_LAB:-0}" = "1" ] && { log "[teardown] KEEP_LAB=1: leaving the lab up for post-mortem"; return 0; }
    log ""
    log "[teardown] (trap) restoring clean lab state"
    hssh 'sudo pkill -x tcpdump 2>/dev/null || true' 2>/dev/null || true
    # mpd_enable/mpd5_enable were disabled for the run; restore them so
    # the next client boot auto-starts M001's mpd5 as expected.
    croot 'sysrc -f /etc/rc.conf mpd5_enable=YES mpd_enable=YES' 2>/dev/null || true
    croot 'ifconfig pppoe0 destroy 2>/dev/null || true' 2>/dev/null || true
    croot 'kldstat -q -n if_pppoe && kldunload if_pppoe || true' 2>/dev/null || true
    croot 'rm -f /var/run/if_pppoe-it/c /tmp/sppp_chap_md5 /tmp/sppp_chap_md5.c /tmp/spppauth.c' 2>/dev/null || true
    bash "$REPO_ROOT/lab/vm/run.sh" client down >/dev/null 2>&1 || true
    ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" \
        "bash ~/$LAB_DIR/isp-netns/down.sh >/dev/null 2>&1" || true
}
trap 'creds_cleanup; teardown' EXIT

# ---------------------------------------------------------------- 0. boot
rm -rf "$RESULT_DIR"; mkdir -p "$RESULT_DIR"
: > "$TRANSCRIPT"
log "== S02/T3 run-chap.sh $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
log "== host: $VMHOST  result dir: $RESULT_DIR"
log "NOTE: the runtime test secret exists only in this process's env and"
log "      tmpfs-only 0600 files on the lab hosts (deleted on exit);"
log "      the server-side tmpfs credential file is the credential store and"
log "      is EXCLUDED from the redaction-scan corpus by design (R011)."

# Runtime-generated dedicated test user + secret (never committed).  The
# wrong-secret (negative probe) value is ALSO runtime-generated.
CHAPUSER="t3chap$(date +%s)"
TESTSECRET="$(gen_secret)"
WRONGSECRET="$(gen_secret)"
log "dedicated test user: $CHAPUSER (secret generated, length ${#TESTSECRET}, not echoed)"

# ---------------------------------------------------------------- 1. server
log ""
log "[1/8] accel-ppp harness up with CHAP-MD5 via server-side chap-secrets"
# up.sh must run ON the VMHOST (accel-pppd is installed there), driven
# over ssh exactly like lab/Makefile's lab-up target: rsync the S01
# harness dir there, then execute up.sh remotely.  up.sh is idempotent.
if ! rsync -a --delete "$REPO_ROOT/lab/isp-netns/" "$VMHOST:$LAB_DIR/isp-netns/"; then
    fail "rsync lab/isp-netns to $VMHOST failed"
    exit 1
fi
if ! hssh "bash ~/$LAB_DIR/isp-netns/up.sh"; then
    fail "up.sh on $VMHOST failed (deploy prereqs: see lab/isp-netns/README.md)"
    exit 1
fi
pass "up.sh: harness up on $VMHOST (idempotent)"

# Deploy the T3 conf, then write the generated user to a tmpfs credential
# file on the VMHOST (creds.sh; stdin-only, never in any argv/ps).
scp -q "$HARNESS_DIR/accel-ppp.chap.conf" "$VMHOST:$LAB_DIR/isp-netns/accel-ppp.t3.conf"
if ! creds_server chap-t3 "$CHAPUSER" "$TESTSECRET"; then
    fail "staging T3 user in the server tmpfs credential file"
    exit 1
fi
pass "server tmpfs credential file carries $CHAPUSER (secret staged via stdin)"

# Render + restart accel-pppd with the T3 conf (chap-secrets backend,
# ipv4=allow for the LCP+CHAP hold, [log] copy=1 for the auth-success line).
if ! hssh bash -s <<EOF
set -euo pipefail
cd ~/$LAB_DIR/isp-netns
sed -e 's#@LABDIR@#'"\$PWD"'#g' -e 's#@CREDS_FILE@#$(creds_server_path chap-t3)#g' accel-ppp.t3.conf > accel-ppp.t3.rendered.conf
for p in \$(sudo ip netns pids isp 2>/dev/null || true); do
    [ "\$(cat /proc/\$p/comm 2>/dev/null)" = accel-pppd ] && sudo kill "\$p"
done
sleep 2
sudo truncate -s 0 /tmp/accel-ppp.log || true
sudo ip netns exec isp /usr/local/sbin/accel-pppd -c "\$PWD/accel-ppp.t3.rendered.conf" -p /run/accel-pppd-t3.pid -d
sleep 2
sudo ip netns exec isp ss -lnt 2>/dev/null | grep -cE ':(2000|2001)'
EOF
then
    fail "accel-pppd (T3 conf) restart"
    exit 1
fi
pass "accel-pppd restarted with chap-secrets backend (listeners 2000/2001 up)"

log "[1/8] brief settle for server listeners"
sleep 15

# ---------------------------------------------------------------- 2. client
log ""
log "[2/8] client VM + in-kernel module (LCP/CHAP + R011 redaction build)"
if bash "$REPO_ROOT/lab/vm/run.sh" client up >/dev/null 2>&1; then
    pass "client VM up (or already running)"
else
    fail "client VM bring-up"; exit 1
fi

# mpd5 must not run during the dial, and no stale netgraph pppoe/ppp
# node may keep dial-retrying behind it (see run-pap.sh header comment -
# the same dance is required for CHAP dials).  The mpd5 rc script's
# rcvar is `mpd_enable` (NOT mpd5_enable), so both knobs are set NO and
# the guest is REBOOTED so the next boot literally cannot start mpd5 and
# carries no leftover netgraph.  Both knobs are restored by teardown.
croot 'sysrc -f /etc/rc.conf mpd5_enable=NO mpd_enable=NO'
if cssh 'pgrep -x mpd5 >/dev/null'; then
    log "mpd5 is running -- rebooting the client for a clean, mpd5-free boot"
    cssh 'echo | su -m root -c "shutdown -r now"' || true
    CLIENT_UP=0
    for i in $(seq 1 90); do
        if cssh 'true' >/dev/null 2>&1; then CLIENT_UP=1; break; fi
        sleep 3
    done
    [ "$CLIENT_UP" = "1" ] && pass "client rebooted cleanly (waiting loop exited on ssh)" \
                            || { fail "client did not come back after reboot"; exit 1; }
fi
if cssh 'pgrep -x mpd5 >/dev/null'; then
    fail "mpd5 still running (rc-enabled elsewhere?)"
    exit 1
else
    pass "no mpd5 process (mpd_enable=NO honoured)"
fi
if cssh 'ifconfig pppoe0 >/dev/null 2>&1'; then
    log "stale pppoe0 present -- destroying before dial"
    croot 'ifconfig pppoe0 destroy 2>/dev/null || true'
    sleep 1
fi
if cssh 'ifconfig pppoe0 >/dev/null 2>&1'; then
    fail "pppoe0 persists on the boot"
    exit 1
else
    pass "pppoe0 name free"
fi

# Wait for the guest's bridged NIC to be really active before dialing
# (see run-pap.sh: PADIs sent before vtnet1 reaches active go nowhere).
VT1_UP=0
for i in $(seq 1 30); do
    if cssh 'ifconfig vtnet1 2>/dev/null | grep -q "status: active"'; then VT1_UP=1; break; fi
    sleep 2
done
[ "$VT1_UP" = "1" ] && pass "guest vtnet1 link is active (ready to dial)" \
                        || { fail "vtnet1 never reported status: active"; exit 1; }

# The bridged tap must be present and attached to br-isp (same repair as
# run-pap.sh).
hssh 'ip link show tap-client >/dev/null 2>&1 || sudo ip tuntap add dev tap-client mode tap'
hssh 'ip -o link show tap-client | grep -q "master br-isp" || sudo ip link set tap-client master br-isp'
hssh 'sudo ip link set tap-client up'
if hssh 'ip -o link show tap-client 2>/dev/null | grep -q "master br-isp"'; then
    pass "tap-client present and attached to br-isp"
else
    fail "tap-client not attached to br-isp"
fi

if [ "${REBUILD:-1}" != "0" ]; then
    log "building + deploying if_pppoe.ko (clean -Werror kmod build)"
    bash "$REPO_ROOT/lab/vm/build-module.sh" sync >/dev/null 2>&1 || { fail "module sync"; exit 1; }
    bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
        || { fail "module build/deploy"; exit 1; }
fi
if cssh 'strings /tmp/if_pppoe.ko 2>/dev/null | grep -qF "secret=<redacted>"'; then
    pass "client /tmp/if_pppoe.ko carries the R011 redaction marker"
else
    log "redaction marker absent on client .ko -- deploying now"
    bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
        || { fail "module deploy"; exit 1; }
    cssh 'strings /tmp/if_pppoe.ko | grep -qF "secret=<redacted>"' \
        || { fail "post-deploy redaction marker check"; exit 1; }
fi
croot 'kldstat -q -n if_pppoe && kldunload if_pppoe' || true
croot 'kldload /tmp/if_pppoe.ko' || { fail "kldload"; exit 1; }
cssh 'kldstat -q -n if_pppoe.ko' && pass "fresh module loaded on client"

# Empirical driver warm-up after kldload (see run-pap.sh): dials issued
# within ~90s of the load fail to start discovery.  Wait it out.
log "[2/8] settle 170s for driver warm-up after kldload"
sleep 170

# --- unit-level CHAP-MD5 vector checks (embedded + libmd providers), ---
# --- run inside the warm-up window; captured to 00-unit-chap-md5.txt ---
cssh 'test -e /usr/include/md5.h' || { fail "client lacks /usr/include/md5.h (FreeBSD base)"; exit 1; }
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tests/sppp_chap_md5.c" freebsd@127.0.0.1:/tmp/sppp_chap_md5.c
# provider 1: embedded RFC 1321 reference implementation
if cssh 'cc -O2 -Wall -Wextra -o /tmp/sppp_chap_md5 /tmp/sppp_chap_md5.c && /tmp/sppp_chap_md5' \
        > "$RESULT_DIR/00-unit-chap-md5.txt" 2>&1; then
    :
else
    fail "unit harness build/run (embedded provider)"; exit 1
fi
grep -q "13/13 checks passed" "$RESULT_DIR/00-unit-chap-md5.txt" \
    && pass "unit: embedded provider 13/13 (RFC 1321 KATs + CHAP vectors + negative + R011 self)" \
    || { fail "embedded provider unit checks incomplete"; exit 1; }
# provider 2: FreeBSD base libmd (same API and implementation lineage as
# the kernel's sys/sys/md5.h); libmd merged into libc in 14.x, so try
# with and without -lmd.
if ! cssh 'cc -O2 -Wall -DSPPP_CHAP_USE_LIBMD -o /tmp/sppp_chap_md5 /tmp/sppp_chap_md5.c -lmd && /tmp/sppp_chap_md5' \
        >> "$RESULT_DIR/00-unit-chap-md5.txt" 2>&1; then
    echo "[libmd -lmd failed] retrying without -lmd (libmd merged into libc on 14.x)" \
        >> "$RESULT_DIR/00-unit-chap-md5.txt"
    if ! cssh 'cc -O2 -Wall -DSPPP_CHAP_USE_LIBMD -o /tmp/sppp_chap_md5 /tmp/sppp_chap_md5.c && /tmp/sppp_chap_md5' \
            >> "$RESULT_DIR/00-unit-chap-md5.txt" 2>&1; then
        fail "unit harness build/run (libmd provider) - see 00-unit-chap-md5.txt"
        exit 1
    fi
fi
grep -c "13/13 checks passed" "$RESULT_DIR/00-unit-chap-md5.txt" | grep -q '^2$' \
    && pass "unit: libmd provider 13/13 as well (two independent MD5 providers agree)" \
    || { fail "expected two 13/13 results in unit log"; exit 1; }
rm -f /tmp/sppp_chap_md5.c

# spppauth helper (SPPPSETAUTHCFG ioctl driver; never prints a secret).
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppauth/spppauth.c" freebsd@127.0.0.1:/tmp/spppauth.c
croot 'cc -O2 -Wall -o /usr/local/sbin/spppauth /tmp/spppauth.c && rm -f /tmp/spppauth.c' \
    && pass "spppauth helper compiled on client" || { fail "spppauth compile"; exit 1; }
cssh 'test -x /usr/local/sbin/pppoeparms' \
    && pass "pppoeparms present (S01 artifact)" || { fail "pppoeparms missing"; exit 1; }

# -------------------------------------------------- 3. negative probe
log ""
log "[3/8] negative probe: wrong CHAP secret must be rejected"
# Start the packet capture BEFORE the probe so the failed exchange and the
# successful exchange are both on the wire (one capture, no dead time).
hssh 'sudo pkill -x tcpdump 2>/dev/null || true'
hssh "sudo nohup timeout 300 tcpdump -i tap-client -s 96 -nn -w $LAB_DIR/isp-netns/chap-live.pcap >/tmp/chap-tcpdump.out 2>&1 &"
sleep 2
hssh "ls -l $LAB_DIR/isp-netns/chap-live.pcap 2>/dev/null" >/dev/null 2>&1 \
    && pass "tcpdump capturing PPPoE on tap-client" || { fail "tcpdump did not start"; exit 1; }

printf '%s\n%s\n' "$CHAPUSER" "$WRONGSECRET" \
    | creds_client_stage || exit 13
croot 'ifconfig pppoe0 destroy 2>/dev/null; ifconfig pppoe0 create; /usr/local/sbin/pppoeparms -e vtnet1 -s lab -a isp-lab pppoe0; ifconfig pppoe0 debug; tail -1 /var/run/if_pppoe-it/c | /usr/local/sbin/spppauth -m chap -n "$(head -1 /var/run/if_pppoe-it/c)" -S pppoe0; dmesg -c >/dev/null 2>&1 || true; ifconfig pppoe0 up' \
    || true
croot 'rm -f /var/run/if_pppoe-it/c'
# The wrong-secret session must NEVER reach SESSION; the reconnect loop
# (PADT auto-redial) hammers until we destroy the interface, so the
# window is a bounded absence check.
NEG_OK=1
for i in $(seq 1 24); do
    st="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^state=" | cut -d= -f2')"
    [ "$st" = "3" ] && NEG_OK=0
    sleep 0.5
done
if [ "$NEG_OK" = "1" ]; then
    pass "negative probe: wrong-secret client never reached SESSION"
else
    fail "negative probe: wrong-secret dial reached SESSION (server accepted bad secret!)"
fi
# Module log must show the client-side CHAP failure path.  accel-ppp
# sends CHAP-Failure and IMMEDIATELY closes LCP; sppp's CHAP_FAILURE
# handler logs "chap failure" but its documented stance is "await LCP
# shutdown by authenticator", so the observable tail is usually
# "chap down/close/tlf" right after the response (the line appears only
# if the failure packet is processed before the LCP shutdown completes).
# The wire-level CHAP-Failure packet is asserted separately in step 6's
# structural pcap count (code 4 >= 1); here we accept either log shape.
croot 'dmesg | grep "pppoe0:" | grep -E "chap" | tail -30' > "$RESULT_DIR/09-negative-probe.log" 2>&1 || true
if grep -qE "chap failure|chap down" "$RESULT_DIR/09-negative-probe.log"; then
    pass "module log: CHAP failure path seen (chap failure or chap down after response)"
else
    fail "module log lacks the CHAP failure path (see 09-negative-probe.log)"
fi
# Server side: some auth-failure record for the user (tolerant match).
hssh 'sudo tail -n 2000 /tmp/accel-ppp.log | grep -aiE "authenticat.*fail|chap.*fail" | tail -10' \
    > "$RESULT_DIR/09b-server-auth-fail.log" 2>&1 || true
if grep -qiE "fail" "$RESULT_DIR/09b-server-auth-fail.log"; then
    pass "server log: auth failure recorded for the wrong secret"
else
    fail "server log shows no auth failure (see 09b-server-auth-fail.log)"
fi
croot 'ifconfig pppoe0 destroy 2>/dev/null || true'
log "negative probe done -- 10s stillness before the good dial"
sleep 10

# ---------------------------------------------------------------- 4. dial
log ""
log "[4/8] live dial: create pppoe0, set CHAP auth (myauth only), bring up"

# One full dial attempt; callers retry if a straggler session swallows it.
dial_once() {
    # BATCHED single-su shape (the ONLY reliable shape - see run-pap.sh).
    # NOTE: no `-p chap` advertisement.  accel-ppp's auth LCP option
    # handler (ppp_auth.c auth_recv_conf_req) returns LCP_OPT_REJ
    # UNCONDITIONALLY: it rejects any auth option the peer advertises and
    # selects the auth protocol ITSELF (first loaded auth module,
    # advertised in ITS OWN ConfReq).  Advertising CHAP made sppp treat
    # the guaranteed ConfRej as "access denied" and close LCP (observed in
    # S02/T3 development: conf-rej -> term-req -> PADT).  The T3 dial sets
    # myauth=chap only (same no-advertise shape as the T2 PAP dial); the
    # CHAP-MD5-only server conf makes accel-ppp propose CHAP.
    printf '%s\n%s\n' "$CHAPUSER" "$TESTSECRET" \
        | creds_client_stage || return 13
    croot 'ifconfig pppoe0 destroy 2>/dev/null; ifconfig pppoe0 create; /usr/local/sbin/pppoeparms -e vtnet1 -s lab -a isp-lab pppoe0; ifconfig pppoe0 debug; tail -1 /var/run/if_pppoe-it/c | /usr/local/sbin/spppauth -m chap -n "$(head -1 /var/run/if_pppoe-it/c)" -S pppoe0; dmesg -c >/dev/null 2>&1 || true; ifconfig pppoe0 up' \
        || { croot 'rm -f /var/run/if_pppoe-it/c'; return 11; }
    croot 'rm -f /var/run/if_pppoe-it/c'
    log "[dial] auth config readback: $(croot '/usr/local/sbin/spppauth -g pppoe0 2>&1 || true') "
    for i in $(seq 1 60); do
        st="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^state=" | cut -d= -f2')"
        [ "$st" = "3" ] && return 0
        sleep 0.5
    done
    {
        echo "[dial-debug] pppoe0 parms:"
        croot '/usr/local/sbin/pppoeparms -d pppoe0 2>&1 || true' 2>/dev/null || true
        echo "[dial-debug] client pppoe dmesg (last 30):"
        croot 'dmesg | grep -E "pppoe0|sppp" | tail -30' 2>/dev/null || true
        echo "[dial-debug] client vtnet1/tap state:"
        cssh 'ifconfig vtnet1 | head -1' 2>/dev/null || true
        echo "[dial-debug] server sessions:"
        hssh 'sudo ip netns exec isp accel-cmd show sessions' 2>/dev/null || true
    } | tee -a "$TRANSCRIPT" > "$RESULT_DIR/03-dial-debug.log" 2>/dev/null || true
    return 16
}

DIAL_RC=-1
for attempt in 1 2 3; do
    if dial_once; then
        DIAL_RC=0
        break
    else
        DIAL_RC=$?
        log "dial attempt $attempt failed (rc=$DIAL_RC) -- tearing down and retrying"
        croot 'ifconfig pppoe0 destroy 2>/dev/null || true' || true
        sleep 10
    fi
done
[ "$DIAL_RC" = "0" ] && pass "live dial: discovery reached SESSION + CHAP auth configured for $CHAPUSER" \
                        || { fail "dial failed after retries (last rc=$DIAL_RC)"; exit 1; }

# Module log: the whole LCP -> CHAP chain (no plaintext secret possible:
# CHAP packets carry only the digest; R011 by construction).
CHAP_OK=0
for i in $(seq 1 40); do
    L="$(croot 'dmesg | grep "pppoe0:" | grep -E "chap (input|output|success)"')"
    if printf '%s' "$L" | grep -q 'chap input <cha' \
       && printf '%s' "$L" | grep -q 'chap output <res' \
       && printf '%s' "$L" | grep -q 'chap success'; then
        CHAP_OK=1
        MODLOG_CHAP="$L"
        break
    fi
    sleep 0.5
done
if [ "$CHAP_OK" = "1" ]; then
    pass "module log: chap challenge input + response output + success"
    log "---- module log CHAP lines (digest-only, no secret material) ----"
    printf '%s\n' "$MODLOG_CHAP" | tee -a "$TRANSCRIPT"
else
    fail "module log never showed the full CHAP exchange + success"
fi
if croot 'dmesg | grep "pppoe0:" | grep -qE "lcp input\(opened\)|got lcp echo req|phase network|chap tlu"'; then
    pass "LCP OPENED + CHAP completed (tlu / phase network in the module log)"
else
    fail "no LCP opened / phase network evidence in module log"
fi

# ---------------------------------------------------------------- 5. hold
log ""
log "[5/8] hold: connected state (LCP + CHAP complete) for 35s"
SID="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^session=" | cut -d= -f2' | head -1)"
log "baseline session id: $SID"
HOLD_OK=1
for i in 1 2 3 4 5 6 7; do
    sleep 5
    P="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^(state|session)=" | tr "\n" " "')"
    log "  hold sample $i: $P"
    printf '%s\n' "hold sample $i: $P" >> "$RESULT_DIR/04-client-state-samples.log"
    if ! printf '%s' "$P" | grep -q 'state=3' || ! printf '%s' "$P" | grep -q "session=$SID"; then
        HOLD_OK=0
    fi
done
[ "$HOLD_OK" = "1" ] && pass "session held: state=SESSION, session id stable at every 5s sample" \
                      || fail "session dropped/re-dialed during the hold window"

# Server side: the session table must show the dedicated user.
hssh "sudo ip netns exec isp accel-cmd show sessions" > "$RESULT_DIR/05-accel-cmd-sessions.txt" 2>&1
if grep -q "$CHAPUSER" "$RESULT_DIR/05-accel-cmd-sessions.txt"; then
    pass "accel-ppp session table shows $CHAPUSER bound to a live session"
else
    fail "accel-ppp session table lacks user $CHAPUSER"
fi
hssh "sudo ip netns exec isp accel-cmd show stat" > "$RESULT_DIR/05b-accel-cmd-stat.txt" 2>&1

# Stop the capture (it covered the negative probe through the hold).
hssh 'sudo pkill -x tcpdump 2>/dev/null || true'
sleep 3
hssh "sudo chmod 644 $LAB_DIR/isp-netns/chap-live.pcap" 2>/dev/null || true

# ---------------------------------------------------------------- 6. wire
log ""
log "[6/8] CHAP on the wire: tcpdump decode + plaintext-secret absence"
hssh "sudo tcpdump -r $LAB_DIR/isp-netns/chap-live.pcap -nn -vv 2>&1" \
    > "$RESULT_DIR/05-chap-wire-decodes.log" 2>&1 || true
# (a) tcpdump's own dissector must have decoded CHAP packets
if grep -qic "chap" "$RESULT_DIR/05-chap-wire-decodes.log"; then
    pass "tcpdump decoded CHAP packets on the wire (decode log 05)"
else
    fail "tcpdump decode log has no CHAP lines"
fi
# (b) the raw pcap bytes must contain no plaintext secret (hash-only by
#     construction, RFC 1994) -- checked here and again in the redaction
#     scan (step 7) against both the runtime secret and the wrong secret.
scp -q "$VMHOST:$LAB_DIR/isp-netns/chap-live.pcap" "$RESULT_DIR/05-chap-live.pcap"
if grep -aFq -- "$TESTSECRET" "$RESULT_DIR/05-chap-live.pcap"; then
    fail "WIRE LEAK: plaintext test secret found in the packet capture"
else
    pass "pcap contains no plaintext test secret"
fi
if grep -aFq -- "$WRONGSECRET" "$RESULT_DIR/05-chap-live.pcap"; then
    fail "WIRE LEAK: plaintext wrong secret found in the packet capture"
else
    pass "pcap contains no plaintext wrong secret"
fi
# (c) independent structural count of the CHAP exchange (pure-stdlib pcap
#     parse: ethertype 0x8864, PPP proto 0xc223, CHAP codes 1/2/3/4)
python3 - "$RESULT_DIR/05-chap-live.pcap" > "$RESULT_DIR/05b-chap-pcap-count.txt" 2>&1 <<'PYEOF' || true
import struct, sys
p = sys.argv[1]
data = open(p, 'rb').read()
assert data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'), 'bad pcap magic'
LE = data[:4] == b'\xd4\xc3\xb2\xa1'
off = 24
frames = 0
chap = {1: 0, 2: 0, 3: 0, 4: 0}
while off + 16 <= len(data):
    if LE:
        incl, = struct.unpack_from('<I', data, off + 8)
    else:
        incl, = struct.unpack_from('>I', data, off + 8)
    fr = data[off + 16: off + 16 + incl]
    frames += 1
    if len(fr) >= 22 and fr[12:14] == b'\x88\x64':
        ppp = fr[20:22]
        if ppp == b'\xc2\x23' and len(fr) >= 23:
            code = fr[22]
            if code in chap:
                chap[code] += 1
    off += 16 + incl
print('frames captured:', frames)
for k, n in sorted(chap.items()):
    print('CHAP code %d count: %d' % (k, n))
ok = chap[1] >= 1 and chap[2] >= 1 and chap[3] >= 1 and chap[4] >= 1
print('has challenge+response+success+failure packets:', ok)
sys.exit(0 if ok else 1)
PYEOF
if grep -q "has challenge+response+success+failure packets: True" "$RESULT_DIR/05b-chap-pcap-count.txt"; then
    pass "pcap structure: CHAP challenge/response/success/failure all present on the wire"
else
    fail "pcap structural count missing CHAP packet kinds (see 05b-chap-pcap-count.txt)"
fi

# ---------------------------------------------------------------- 7. capture
log ""
log "[7/8] capture durable artifacts under $RESULT_DIR"
hssh 'sudo tail -n 2000 /tmp/accel-ppp.log' > "$RESULT_DIR/01-server-accel-ppp.log" 2>&1
croot 'dmesg | grep "pppoe0:"' > "$RESULT_DIR/02-client-module.log" 2>&1 || true
cssh 'grep -aiE "pppoe0|chap|sppp" /var/log/messages 2>/dev/null | tail -n 400' \
    > "$RESULT_DIR/02b-client-syslog.log" 2>&1 || true
hssh "cat ~/$LAB_DIR/run/client.serial.log" > "$RESULT_DIR/03-client-serial.log" 2>&1
hssh "cat ~/$LAB_DIR/isp-netns/accel-ppp.t3.rendered.conf" > "$RESULT_DIR/06-config-rendered-dump.conf" 2>&1
{
    echo "== host: accel-pppd cmdline =="
    hssh 'pgrep -a accel-pppd || true' 2>&1
    echo "== host: netns isp pids =="
    hssh 'sudo ip netns pids isp 2>/dev/null || true' 2>&1
    echo "== host: tcpdump proc (must be gone) =="
    hssh 'pgrep -a tcpdump || true' 2>&1
    echo "== client: pppoe/sppp/mpd-related procs =="
    cssh 'ps ax -o pid,comm,args | grep -iE "spppauth|pppoe|pppd|mpd" | grep -v grep || true' 2>&1
} > "$RESULT_DIR/07-process-listings.txt" 2>&1
scp -q "$VMHOST:$LAB_DIR/isp-netns/chap-live.pcap" "$RESULT_DIR/05-chap-live.pcap"
pass "artifacts captured: server log, client module log, serial, sessions, config dump, ps, pcap"

# ---------------------------------------------------------------- 8. redact
log ""
log "[8/8] secret-redaction assertion across every captured artifact"
SCAN_LOG="$RESULT_DIR/08-redaction-scan.log"
: > "$SCAN_LOG"
SCAN_BAD=0
log "fixed-string scans over: 01 server log, 02 client module log, 02b syslog, 03 serial,"
log "04 state samples, 05 pcap + 05b counts + 05-chap-wire-decodes, 06 config dump,"
log "07 ps, 09 negative-probe logs, 00 unit log, 10 transcript"

corpus() {
    for f in "$RESULT_DIR"/00*.txt "$RESULT_DIR"/01*.log "$RESULT_DIR"/02*.log \
             "$RESULT_DIR"/02b*.log "$RESULT_DIR"/03*.log "$RESULT_DIR"/04*.log \
             "$RESULT_DIR"/05*.log "$RESULT_DIR"/05*.txt "$RESULT_DIR"/05b*.txt \
             "$RESULT_DIR"/05-chap-live.pcap "$RESULT_DIR"/06*.conf \
             "$RESULT_DIR"/07*.txt "$RESULT_DIR"/09*.log \
             "$TRANSCRIPT"; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

# (a) fixed-string grep per pattern -- record every command + its exit code
# (zero matches required: grep -F must exit 1 on every file).
for pat_name in "full-secret" "user:secret" "user-space-secret" "user-tab-secret" \
                "wrong-secret" "wronguser:wrong"; do
    case "$pat_name" in
        full-secret)       pat="$TESTSECRET" ;;
        user:secret)       pat="$CHAPUSER:$TESTSECRET" ;;
        user-space-secret) pat="$CHAPUSER $TESTSECRET" ;;
        user-tab-secret)   pat="$(printf '%s\t%s' "$CHAPUSER" "$TESTSECRET")" ;;
        wrong-secret)      pat="$WRONGSECRET" ;;
        wronguser:wrong)   pat="$CHAPUSER:$WRONGSECRET" ;;
    esac
    for f in $(corpus); do
        if grep -aFq -- "$pat" "$f"; then
            echo "RC=0 (MATCH!): grep -F $pat_name in $(basename "$f")" >> "$SCAN_LOG"
            SCAN_BAD=1
        else
            echo "RC=1 (no match, good): grep -F $pat_name in $(basename "$f")" >> "$SCAN_LOG"
        fi
    done
done
if [ "$SCAN_BAD" = "0" ]; then
    pass "zero matches for the full secret and user:secret forms across ALL captures (incl. pcap)"
else
    fail "SECRET LEAK: matches found (see 08-redaction-scan.log)"
fi

# ---------------------------------------------------------------- 9. teardown
log ""
log "[9/9] teardown, exit statuses recorded"
creds_cleanup
TEARDOWN_DONE=1
{
    echo "== teardown exit statuses =="
    echo "client: restore mpd5 mpd_enable=YES:"
    croot 'sysrc -f /etc/rc.conf mpd5_enable=YES mpd_enable=YES' 2>&1; echo "  rc=$?"
    echo "client: pppoe0 destroy:"
    croot 'ifconfig pppoe0 destroy' 2>&1; echo "  rc=$?"
    echo "client: kldunload if_pppoe:"
    croot 'kldstat -q -n if_pppoe && kldunload if_pppoe' 2>&1; echo "  rc=$?"
    echo "client VM power down (lab/vm/run.sh client down):"
    bash "$REPO_ROOT/lab/vm/run.sh" client down 2>&1 | tail -1; echo "  rc=$?"
    echo "server: isp-netns down.sh:"
    ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" \
        "bash ~/$LAB_DIR/isp-netns/down.sh" 2>&1 | tail -1; echo "  rc=$?"
} | tee -a "$TRANSCRIPT" "$RESULT_DIR/08-exit-statuses.txt" >/dev/null

# orphan check: no netns isp / br-isp / tap-client / accel-pppd / client qemu / tcpdump
NO_ORPHANS=1
hssh 'ip netns list 2>/dev/null | grep -qx isp' && NO_ORPHANS=0
hssh 'ip link show br-isp >/dev/null 2>&1' && NO_ORPHANS=0
hssh 'ip link show tap-client >/dev/null 2>&1' && NO_ORPHANS=0
if hssh 'pgrep -f "[q]uemu-system.*-name client " >/dev/null'; then
    NO_ORPHANS=0
fi
hssh 'pgrep -x accel-pppd >/dev/null' && NO_ORPHANS=0
hssh 'pgrep -x tcpdump >/dev/null' && NO_ORPHANS=0
[ "$NO_ORPHANS" = "1" ] && pass "teardown clean: no isp netns / br-isp / tap-client / accel-pppd / client VM / tcpdump" \
                        || fail "orphans remain after teardown"

log ""
log "== summary: PASS=$PASS FAIL=$FAIL =="
log "== artifacts: $RESULT_DIR =="
[ "$FAIL" = "0" ] && exit 0 || exit 1