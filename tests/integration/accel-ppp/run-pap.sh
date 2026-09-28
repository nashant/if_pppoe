#!/usr/bin/env bash
# S02/T2: live PAP authentication against accel-ppp with secret redaction.
#
# Strictly ordered, evidence-terminating recipe (plan step order):
#   1. bring up the S01 accel-ppp harness with PAP enabled via a
#      server-side tmpfs credential file (file-based auth, no RADIUS)
#   2. confirm the PPPoE client's LCP phase advances into the PAP
#      authentication phase (client module log: lcp opened -> phase
#      authenticate -> pap output)
#   3. run a live client session with a dedicated test user and a
#      run-time-generated test secret (never committed)
#   4. assert the session reaches and HOLDS the PPPoE connected state
#      (LCP + PAP complete) for the duration of the run
#   5. capture server-side and client-side logs to durable files under
#      tests/results/pap-live/
#   6. secret-redaction assertion: fixed-string scans for the full test
#      secret and for user:secret forms must return zero matches across
#      all captured logs, config dumps, and process listings
#   7. tear down the harness cleanly and record exit statuses
#
# Client is the in-kernel if_pppoe/sppp stack on the lab `client` VM
# (S01/S02-T1 wiring).  The whole run is driven over ssh from this repo
# (any host with passwordless ssh to $VMHOST); the only local state
# produced is the durable evidence under tests/results/pap-live/.
#
# Secrets discipline (R011): the runtime-generated secret exists only in
# this process's environment and in tmpfs-only 0600 files on the
# lab hosts, which every path deletes.  It is NEVER echoed (no set -x),
# never appears in argv of any captured process, and is never committed.
# The server-side tmpfs credential file is the credential store (the only
# other copy, like /etc/ppp/pap-secrets) and is deliberately excluded
# from the redaction-scan corpus; every other capture must match the
# secret or a user:secret form zero times.
#
# Usage: ./run-pap.sh        (needs the S01 lab + lab/vm tooling, VMHOST ssh)
#   REBUILD=0 skips the kmod rebuild if the deployed /tmp/if_pppoe.ko on
#   the client already carries the R011 redaction marker.
set -euo pipefail

VMHOST="${VMHOST:?set VMHOST in lab/local.env}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"
CLIENT_PORT=2223

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_DIR="$REPO_ROOT/tests/results/pap-live"
TRANSCRIPT="$RESULT_DIR/09-transcript.log"

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
    # mpd_enable/mpd5_enable were disabled for the run; restore them so
    # the next client boot auto-starts M001's mpd5 as expected.
    croot 'sysrc -f /etc/rc.conf mpd5_enable=YES mpd_enable=YES' 2>/dev/null || true
    croot 'ifconfig pppoe0 destroy 2>/dev/null || true' 2>/dev/null || true
    croot 'kldstat -q -n if_pppoe && kldunload if_pppoe || true' 2>/dev/null || true
    croot 'rm -f /var/run/if_pppoe-it/c' 2>/dev/null || true
    bash "$REPO_ROOT/lab/vm/run.sh" client down >/dev/null 2>&1 || true
    ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" \
        "bash ~/$LAB_DIR/isp-netns/down.sh >/dev/null 2>&1" || true
}
trap 'creds_cleanup; teardown' EXIT

# ---------------------------------------------------------------- 0. boot
rm -rf "$RESULT_DIR"; mkdir -p "$RESULT_DIR"
: > "$TRANSCRIPT"
log "== S02/T2 run-pap.sh $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
log "== host: $VMHOST  result dir: $RESULT_DIR"
log "NOTE: the runtime test secret exists only in this process's env and"
log "      tmpfs-only 0600 files on the lab hosts (deleted on exit);"
log "      the server-side tmpfs credential file is the credential store and is"
log "      EXCLUDED from the redaction-scan corpus by design (R011)."

# Runtime-generated dedicated test user + secret (never committed).
T2USER="t2pap$(date +%s)"
TESTSECRET="$(gen_secret)"
log "dedicated test user: $T2USER (secret generated, length ${#TESTSECRET}, not echoed)"

# ---------------------------------------------------------------- 1. server
log ""
log "[1/7] accel-ppp harness up with PAP via server-side pap-secrets"
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

# Deploy the T2 conf, then write the generated user to a tmpfs credential
# file on the VMHOST (creds.sh; stdin-only, never in any argv/ps).
scp -q "$HARNESS_DIR/accel-ppp.conf" "$VMHOST:$LAB_DIR/isp-netns/accel-ppp.t2.conf"
if ! creds_server pap "$T2USER" "$TESTSECRET"; then
    fail "staging T2 user in the server tmpfs credential file"
    exit 1
fi
pass "server tmpfs credential file carries $T2USER (secret staged via stdin)"

# Render + restart accel-pppd with the T2 conf (pap-secrets backend,
# ipv4=allow for the LCP+PAP hold, [log] copy=1 for the auth-success line).
if ! hssh bash -s <<EOF
set -euo pipefail
cd ~/$LAB_DIR/isp-netns
sed -e 's#@LABDIR@#'"\$PWD"'#g' -e 's#@CREDS_FILE@#$(creds_server_path pap)#g' accel-ppp.t2.conf > accel-ppp.t2.rendered.conf
for p in \$(sudo ip netns pids isp 2>/dev/null || true); do
    [ "\$(cat /proc/\$p/comm 2>/dev/null)" = accel-pppd ] && sudo kill "\$p"
done
sleep 2
sudo truncate -s 0 /tmp/accel-ppp.log || true
sudo ip netns exec isp /usr/local/sbin/accel-pppd -c "\$PWD/accel-ppp.t2.rendered.conf" -p /run/accel-pppd-t2.pid -d
sleep 2
sudo ip netns exec isp ss -lnt 2>/dev/null | grep -cE ':(2000|2001)'
EOF
then
    fail "accel-pppd (T2 conf) restart"
    exit 1
fi
pass "accel-pppd restarted with pap-secrets backend (listeners 2000/2001 up)"

log "[1/7] brief settle for server listeners"
sleep 15

# ---------------------------------------------------------------- 2. client
log ""
log "[2/7] client VM + in-kernel module (LCP/PAP + R011 redaction build)"
if bash "$REPO_ROOT/lab/vm/run.sh" client up >/dev/null 2>&1; then
    pass "client VM up (or already running)"
else
    fail "client VM bring-up"; exit 1
fi

# mpd5 must not run during the dial, and no stale netgraph pppoe/ppp
# node may keep dial-retrying behind it (a stopped mpd5 leaves its
# netgraph nodes mid-connection: they keep contesting the shared vtnet1
# MAC on br-isp and swallow the server's pppoe session slot -- observed
# live during S02/T2 development: 'lab: authentication succeeded' while
# the mpd5 process was dead).  The mpd5 rc script's rcvar is
# `mpd_enable` (NOT mpd5_enable -- an unused key the script never
# reads), so both knobs are set NO and the guest is REBOOTED so the
# next boot literally cannot start mpd5 and carries no leftover
# netgraph.  Both knobs are restored by teardown before the guest
# shuts down.
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

# Wait for the guest's bridged NIC to be really active before dialing:
# ssh returns during early boot; PADIs sent before vtnet1 reaches link
# state active go nowhere (observed as a silent state=1 stall in S02/T2
# development -- the fix is this explicit readiness poll, not a fixed
# sleep).
VT1_UP=0
for i in $(seq 1 30); do
    if cssh 'ifconfig vtnet1 2>/dev/null | grep -q "status: active"'; then VT1_UP=1; break; fi
    sleep 2
done
[ "$VT1_UP" = "1" ] && pass "guest vtnet1 link is active (ready to dial)" \
                        || { fail "vtnet1 never reported status: active"; exit 1; }

# The bridged tap must be present and attached to br-isp.  'client up'
# fast-paths out when the pidfile is live and will NOT re-attach a tap
# that was deleted while the guest was up -- assert and repair it here.
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

# Empirical driver warm-up (S02/T2 development): dials issued within
# ~90s of the if_pppoe kldload fail to start discovery (client shows
# state=0 padi_retries=0; LCP never opens on up), while the identical
# dial ~2.5-4 min after load succeeds on the first try -- reproduced
# across four independent PASS dials and seven FAIL runs.  Wait out the
# warm-up here; the underlying cause (module-load registration settle)
# is tracked as a known issue for T3.
log "[2/7] settle 170s for driver warm-up after kldload"
sleep 170

# spppauth helper (SPPPSETAUTHCFG ioctl driver; never prints a secret).
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppauth/spppauth.c" freebsd@127.0.0.1:/tmp/spppauth.c
croot 'cc -O2 -Wall -o /usr/local/sbin/spppauth /tmp/spppauth.c && rm -f /tmp/spppauth.c' \
    && pass "spppauth helper compiled on client" || { fail "spppauth compile"; exit 1; }
cssh 'test -x /usr/local/sbin/pppoeparms' \
    && pass "pppoeparms present (S01 artifact)" || { fail "pppoeparms missing"; exit 1; }

# ---------------------------------------------------------------- 3. dial
log ""
log "[3/7] live dial: create pppoe0, set PAP auth, bring up"

# One full dial attempt; callers retry if a straggler session (mpd5
# leftovers on the shared vtnet1 MAC) swallows the discovery.
dial_once() {
    # BATCHED single-su shape (empirically the ONLY reliable shape in
    # S02/T2 development): create/parms/debug/spppauth/clear/up as one
    # `su -m root -c ";"` sequence.  Splitting each ioctl into its own
    # su session (the recipe's first shape) intermittently leaves the
    # interface never starting discovery on `up` (state=0 padi_retries=0)
    # even though SPPPSETAUTHCFG readback is correct -- reproduced
    # head-to-head on the same lab: split=state 0/session 0, batched=
    # state 3/session N, seconds apart.  Root cause tracked to T3.
    printf '%s\n%s\n' "$T2USER" "$TESTSECRET" \
        | creds_client_stage || return 13
    croot 'ifconfig pppoe0 destroy 2>/dev/null; ifconfig pppoe0 create; /usr/local/sbin/pppoeparms -e vtnet1 -s lab -a isp-lab pppoe0; ifconfig pppoe0 debug; tail -1 /var/run/if_pppoe-it/c | /usr/local/sbin/spppauth -m pap -n "$(head -1 /var/run/if_pppoe-it/c)" -S pppoe0; dmesg -c >/dev/null 2>&1 || true; ifconfig pppoe0 up' \
        || { croot 'rm -f /var/run/if_pppoe-it/c'; return 11; }
    croot 'rm -f /var/run/if_pppoe-it/c'
    log "[dial] auth config readback: $(croot '/usr/local/sbin/spppauth -g pppoe0 2>&1 || true') "
    # Poll for SESSION.  The window is generous: a first LCP round that
    # the server rejects on the auth option PADTs, and the driver's
    # reconnect (PADT auto-redial, M001 semantics) takes a few seconds.
    for i in $(seq 1 60); do
        st="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^state=" | cut -d= -f2')"
        [ "$st" = "3" ] && return 0
        sleep 0.5
    done
    # Durable: dump everything a failure could hide (the interface rests at
    # state<=1 when LCP/discovery never completes; the captures say where).
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
[ "$DIAL_RC" = "0" ] && pass "live dial: discovery reached SESSION + PAP auth configured for $T2USER" \
                        || { fail "dial failed after retries (last rc=$DIAL_RC)"; exit 1; }

# Module log: the whole LCP -> PAP chain, with the secret redacted.
PAP_OK=0
for i in $(seq 1 40); do
    L="$(croot 'dmesg | grep "pppoe0:" | grep -E "pap (output|success)"')"
    if printf '%s' "$L" | grep -qF 'secret=<redacted>' \
       && printf '%s' "$L" | grep -qF 'pap success: Authentication succeeded'; then
        PAP_OK=1
        MODLOG_DIAL="$L"
        break
    fi
    sleep 0.5
done
if [ "$PAP_OK" = "1" ]; then
    pass "module log: PAP AuthReq with secret=<redacted> + pap success: Authentication succeeded"
    log "---- module log PAP lines ----"
    printf '%s\n' "$MODLOG_DIAL" | tee -a "$TRANSCRIPT"
else
    fail "module log never showed the redacted PAP exchange + success"
fi
if croot 'dmesg | grep "pppoe0:" | grep -qE "lcp input\(opened\)|got lcp echo req|phase network"'; then
    pass "LCP OPENED (echo keepalive / auth-run evidence in the module log)"
else
    fail "no LCP opened evidence in module log"
fi

# ---------------------------------------------------------------- 4. hold
log ""
log "[4/7] hold: connected state (LCP + PAP complete) for 35s"
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
if grep -q "$T2USER" "$RESULT_DIR/05-accel-cmd-sessions.txt"; then
    pass "accel-ppp session table shows $T2USER bound to a live session"
else
    fail "accel-ppp session table lacks user $T2USER"
fi
hssh "sudo ip netns exec isp accel-cmd show stat" > "$RESULT_DIR/05b-accel-cmd-stat.txt" 2>&1

# ---------------------------------------------------------------- 5. capture
log ""
log "[5/7] capture durable artifacts under $RESULT_DIR"
hssh 'sudo tail -n 2000 /tmp/accel-ppp.log' > "$RESULT_DIR/01-server-accel-ppp.log" 2>&1
croot 'dmesg | grep "pppoe0:"' > "$RESULT_DIR/02-client-module.log" 2>&1 || true
cssh 'grep -aiE "pppoe0|pap|sppp" /var/log/messages 2>/dev/null | tail -n 400' \
    > "$RESULT_DIR/02b-client-syslog.log" 2>&1 || true
hssh "cat ~/$LAB_DIR/run/client.serial.log" > "$RESULT_DIR/03-client-serial.log" 2>&1
# config dump = the rendered server conf (never contains a secret: the
# credential store is the separate tmpfs file, excluded by design).
hssh "cat ~/$LAB_DIR/isp-netns/accel-ppp.t2.rendered.conf" > "$RESULT_DIR/06-config-rendered-dump.conf" 2>&1
# process listings (host + client) captured while the session is live.
{
    echo "== host: accel-pppd cmdline =="
    hssh 'pgrep -a accel-pppd || true' 2>&1
    echo "== host: netns isp pids =="
    hssh 'sudo ip netns pids isp 2>/dev/null || true' 2>&1
    echo "== client: pppoe/sppp/mpd-related procs =="
    cssh 'ps ax -o pid,comm,args | grep -iE "spppauth|pppoe|pppd|mpd" | grep -v grep || true' 2>&1
} > "$RESULT_DIR/07-process-listings.txt" 2>&1
pass "artifacts captured: server log, client module log, serial, sessions, config dump, ps"

# ---------------------------------------------------------------- 6. redact
log ""
log "[6/7] secret-redaction assertion across every captured artifact"
SCAN_LOG="$RESULT_DIR/08-redaction-scan.log"
: > "$SCAN_LOG"
SCAN_BAD=0
log "fixed-string scans over: 01 server log, 02 client module log, 02b syslog,"
log "03 serial, 04 state samples, 05 accel-cmd, 06 config dump, 07 ps, 09 transcript"

corpus() {
    for f in "$RESULT_DIR"/01*.log "$RESULT_DIR"/02*.log "$RESULT_DIR"/02b*.log \
             "$RESULT_DIR"/03*.log "$RESULT_DIR"/04*.log "$RESULT_DIR"/05*.txt \
             "$RESULT_DIR"/05b*.txt "$RESULT_DIR"/06*.conf "$RESULT_DIR"/07*.txt \
             "$TRANSCRIPT"; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

# (a) fixed-string grep per pattern -- record every command + its exit code
# (zero matches required: grep -F must exit 1 on every file).
for pat_name in "full-secret" "user:secret" "user-space-secret" "user-tab-secret"; do
    case "$pat_name" in
        full-secret)        pat="$TESTSECRET" ;;
        user:secret)        pat="$T2USER:$TESTSECRET" ;;
        user-space-secret)  pat="$T2USER $TESTSECRET" ;;
        user-tab-secret)    pat="$(printf '%s\t%s' "$T2USER" "$TESTSECRET")" ;;
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
    pass "zero matches for the full secret and user:secret forms across ALL captures"
else
    fail "SECRET LEAK: matches found (see 08-redaction-scan.log)"
fi

# ---------------------------------------------------------------- 7. teardown
log ""
log "[7/7] teardown, exit statuses recorded"
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

# orphan check: no netns isp / br-isp / tap-client / accel-pppd / client qemu
NO_ORPHANS=1
hssh 'ip netns list 2>/dev/null | grep -qx isp' && NO_ORPHANS=0
hssh 'ip link show br-isp >/dev/null 2>&1' && NO_ORPHANS=0
hssh 'ip link show tap-client >/dev/null 2>&1' && NO_ORPHANS=0
if hssh 'pgrep -f "[q]uemu-system.*-name client " >/dev/null'; then
    NO_ORPHANS=0
fi
hssh 'pgrep -x accel-pppd >/dev/null' && NO_ORPHANS=0
[ "$NO_ORPHANS" = "1" ] && pass "teardown clean: no isp netns / br-isp / tap-client / accel-pppd / client VM" \
                        || fail "orphans remain after teardown"

log ""
log "== summary: PASS=$PASS FAIL=$FAIL =="
log "== artifacts: $RESULT_DIR =="
[ "$FAIL" = "0" ] && exit 0 || exit 1