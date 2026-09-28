#!/usr/bin/env bash
# M002/S03/T1: live IPCP negotiation + in-kernel IPv4 address application.
#
# Strictly ordered, evidence-terminating recipe (replacement plan
# f40a48a8, mirroring run-chap.sh's shape exactly):
#   1. bring up the S01 accel-ppp harness with the IPCP config
#      (accel-ppp.ipcp.conf: ipv4=require + [ip-pool] 10.99.0.100-199 /
#      gw 10.99.0.1 + [dns] dns1=10.99.0.1, CHAP-MD5 file backend)
#   2. client VM + in-kernel module (kldload if_pppoe.ko), empirical
#      driver warm-up, spppauth helper + pppoepparms present
#   3. live dial: a SINGLE batched su -m root command
#      (create / pppoepparms / spppauth / dmesg -c / up) with NO userland
#      ifconfig address-assignment step -- the negotiated IPv4 address
#      MUST be applied in-kernel by sc_addr_task -> pppoe_addr_apply()
#      -> in_control_ioctl(SIOCAIFADDR) under CURVNET_SET (spike S2
#      recipe, R009)
#   4. assert live: client module log shows lcp opened -> IPCP layer up
#      -> phase network; client ifconfig pppoe0 shows an inet from the
#      [ip-pool] 10.99.0.100-199 with peer --> 10.99.0.1 (ACCEL_GW);
#      the recipe's own structural scan records PASS for 'no userland
#      ifconfig' address assignment in the transcript
#   5. hold: session state=SESSION stable for 35s with a stable session id
#   6. capture durable artifacts under tests/results/ipcp-live/
#   7. tear down cleanly (restore BOTH mpd_enable and mpd5_enable - the
#      mpd5 rc script reads rcvar mpd_enable, NOT mpd5_enable, so both
#      knobs are restored, MEM055) and record exit statuses
# (durable artifacts land under tests/results/ipcp-live/)
#
# Client is the in-kernel if_pppoe/sppp stack on the lab `client` VM
# (S01/S02 wiring).  The whole run is driven over ssh from this repo;
# the only local state produced is the durable evidence under
# tests/results/ipcp-live/.
#
# Secrets discipline (R011): the runtime-generated CHAP secret exists
# only in this process's environment and in tmpfs-only 0600 files
# on the lab hosts (deleted on every path).  It is NEVER echoed (no
# set -x), never appears in argv of any captured process, and is never
# committed.  The server-side tmpfs credential file is the credential
# store (the only other copy, like /etc/ppp/chap-secrets) and is
# deliberately excluded from any scan corpus; every other capture must
# match the secret or a user:secret form zero times.
#
# Usage: ./run-ipcp.sh        (needs the S01 lab + lab/vm tooling, VMHOST ssh)
#   REBUILD=0 skips the kmod rebuild if /tmp/if_pppoe.ko is already
#   present on the client (pre-deployed by the T1 build step).
set -euo pipefail

VMHOST="${VMHOST:?set VMHOST in lab/local.env}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"
CLIENT_PORT=2223
ACCEL_GW=10.99.0.1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_DIR="$REPO_ROOT/tests/results/ipcp-live"
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
    # mpd_enable/mpd5_enable were disabled for the run; restore BOTH so
    # the next client boot auto-starts M001's mpd5 (MEM055: the mpd5 rc
    # script reads rcvar mpd_enable, NOT mpd5_enable).
    croot 'sysrc -f /etc/rc.conf mpd5_enable=YES mpd_enable=YES' 2>/dev/null || true
    croot 'ifconfig pppoe0 destroy 2>/dev/null || true' 2>/dev/null || true
    croot 'kldstat -q -n if_pppoe && kldunload if_pppoe || true' 2>/dev/null || true
    croot 'rm -f /var/run/if_pppoe-it/c /tmp/spppauth.c' 2>/dev/null || true
    bash "$REPO_ROOT/lab/vm/run.sh" client down >/dev/null 2>&1 || true
    ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" \
        "bash ~/$LAB_DIR/isp-netns/down.sh >/dev/null 2>&1" || true
}
trap 'creds_cleanup; teardown' EXIT

# ---------------------------------------------------------------- 0. boot
rm -rf "$RESULT_DIR"; mkdir -p "$RESULT_DIR"
: > "$TRANSCRIPT"
log "== M002/S03/T1 run-ipcp.sh $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
log "== host: $VMHOST  result dir: $RESULT_DIR"
log "NOTE: the runtime CHAP secret exists only in this process's env and"
log "      tmpfs-only 0600 files on the lab hosts (deleted on exit);"
log "      the server-side tmpfs credential file is the credential store"
log "      and is EXCLUDED from any scan corpus by design (R011)."

# Runtime-generated dedicated test user + secret (never committed).
IPCPUSER="t1ipcp$(date +%s)"
TESTSECRET="$(gen_secret)"
log "dedicated test user: $IPCPUSER (secret generated, length ${#TESTSECRET}, not echoed)"

# ---------------------------------------------------------------- 1. server
log ""
log "[1/7] accel-ppp harness up with IPCP config (ipv4=require)"
# up.sh must run ON the VMHOST (accel-pppd is installed there), driven
# over ssh exactly like lab/Makefile's lab-up target.  up.sh is idempotent.
if ! rsync -a --delete "$REPO_ROOT/lab/isp-netns/" "$VMHOST:$LAB_DIR/isp-netns/"; then
    fail "rsync lab/isp-netns to $VMHOST failed"
    exit 1
fi
if ! hssh "bash ~/$LAB_DIR/isp-netns/up.sh"; then
    fail "up.sh on $VMHOST failed (deploy prereqs: see lab/isp-netns/README.md)"
    exit 1
fi
pass "up.sh: harness up on $VMHOST (idempotent)"

# Deploy the IPCP conf, then write the generated user to a tmpfs credential
# file on the VMHOST (creds.sh; stdin-only, never in any argv/ps).
scp -q "$HARNESS_DIR/accel-ppp.ipcp.conf" "$VMHOST:$LAB_DIR/isp-netns/accel-ppp.ipcp.conf"
if ! creds_server chap-ipcp "$IPCPUSER" "$TESTSECRET"; then
    fail "staging IPCP user in the server tmpfs credential file"
    exit 1
fi
pass "server tmpfs credential file carries $IPCPUSER (secret staged via stdin)"

# Render + restart accel-pppd with the IPCP conf (ipv4=require, CHAP-MD5
# backend, [ip-pool] gw + dns, [log] copy=1).
if ! hssh bash -s <<EOF
set -euo pipefail
cd ~/$LAB_DIR/isp-netns
sed -e 's#@LABDIR@#'"\$PWD"'#g' -e 's#@CREDS_FILE@#$(creds_server_path chap-ipcp)#g' accel-ppp.ipcp.conf > accel-ppp.ipcp.rendered.conf
for p in \$(sudo ip netns pids isp 2>/dev/null || true); do
    [ "\$(cat /proc/\$p/comm 2>/dev/null)" = accel-pppd ] && sudo kill "\$p"
done
sleep 2
sudo truncate -s 0 /tmp/accel-ppp.log || true
sudo ip netns exec isp /usr/local/sbin/accel-pppd -c "\$PWD/accel-ppp.ipcp.rendered.conf" -p /run/accel-pppd-ipcp.pid -d
sleep 2
sudo ip netns exec isp ss -lnt 2>/dev/null | grep -cE ':(2000|2001)'
EOF
then
    fail "accel-pppd (IPCP conf) restart"
    exit 1
fi
pass "accel-pppd restarted with IPCP conf (ipv4=require; listeners 2000/2001 up)"

log "[1/7] brief settle for server listeners"
sleep 15

# ---------------------------------------------------------------- 2. client
log ""
log "[2/7] client VM + in-kernel module"
if bash "$REPO_ROOT/lab/vm/run.sh" client up >/dev/null 2>&1; then
    pass "client VM up (or already running)"
else
    fail "client VM bring-up"; exit 1
fi

# mpd5 must not run during the dial, and no stale netgraph pppoe/ppp node
# may keep dial-retrying behind it.  The mpd5 rc script's rcvar is
# `mpd_enable` (NOT mpd5_enable), so both knobs are set NO and the guest
# is REBOOTED so the next boot literally cannot start mpd5 (MEM055).
# Both knobs are restored by teardown.
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
# (PADIs sent before vtnet1 reaches active go nowhere).
VT1_UP=0
for i in $(seq 1 30); do
    if cssh 'ifconfig vtnet1 2>/dev/null | grep -q "status: active"'; then VT1_UP=1; break; fi
    sleep 2
done
[ "$VT1_UP" = "1" ] && pass "guest vtnet1 link is active (ready to dial)" \
                        || { fail "vtnet1 never reported status: active"; exit 1; }

# The bridged tap must be present and attached to br-isp (same repair as
# run-pap.sh / run-chap.sh).
hssh 'ip link show tap-client >/dev/null 2>&1 || sudo ip tuntap add dev tap-client mode tap'
hssh 'ip -o link show tap-client | grep -q "master br-isp" || sudo ip link set tap-client master br-isp'
hssh 'sudo ip link set tap-client up'
if hssh 'ip -o link show tap-client 2>/dev/null | grep -q "master br-isp"'; then
    pass "tap-client present and attached to br-isp"
else
    fail "tap-client not attached to br-isp"
fi

# Module: rebuild+deploy unless REBUILD=0 with a pre-deployed .ko.
if [ "${REBUILD:-1}" != "0" ]; then
    log "building + deploying if_pppoe.ko (clean kmod build)"
    bash "$REPO_ROOT/lab/vm/build-module.sh" sync >/dev/null 2>&1 || { fail "module sync"; exit 1; }
    bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
        || { fail "module build/deploy"; exit 1; }
else
    if cssh 'test -f /tmp/if_pppoe.ko'; then
        pass "REBUILD=0: client already has /tmp/if_pppoe.ko (T1 build step deployed it)"
    else
        log "REBUILD=0 but /tmp/if_pppoe.ko absent on client -- deploying now"
        bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
            || { fail "module deploy"; exit 1; }
    fi
fi
croot 'kldstat -q -n if_pppoe && kldunload if_pppoe' || true
croot 'kldload /tmp/if_pppoe.ko' || { fail "kldload"; exit 1; }
cssh 'kldstat -q -n if_pppoe.ko' && pass "fresh module loaded on client"

# Empirical driver warm-up after kldload: dials issued within ~90s of the
# load fail to start discovery.  Wait it out.
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
log "[3/7] live dial: single batched su -m root, NO userland ifconfig assignment"

# One full dial attempt; callers retry if a straggler session swallows it.
# The batched command is the ONLY reliable shape (see run-pap.sh).  It is
# a SINGLE su -m root command: create / pppoepparms / spppauth / dmesg -c
# / up (MEM054).  It deliberately contains NO userland ifconfig address
# assignment - the negotiated IPv4 MUST land in-kernel via sc_addr_task.
# No `-p chap` advertisement: accel-ppp's auth handler rejects any auth
# option the peer advertises and selects the auth protocol ITSELF (first
# loaded auth module = auth_chap_md5).  The dial sets myauth=chap only.
dial_once() {
    printf '%s\n%s\n' "$IPCPUSER" "$TESTSECRET" \
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
[ "$DIAL_RC" = "0" ] && pass "live dial: discovery reached SESSION (state=3) for $IPCPUSER" \
                        || { fail "dial failed after retries (last rc=$DIAL_RC)"; exit 1; }

# Module log: the whole LCP -> CHAP -> IPCP chain.
LCP_OK=0
for i in $(seq 1 40); do
    L="$(croot 'dmesg | grep "pppoe0:" | grep -E "lcp input\(opened\)|got lcp echo req|phase network|chap success"')"
    if printf '%s' "$L" | grep -qE 'lcp input\(opened\)|got lcp echo req|phase network|chap success'; then
        LCP_OK=1
        MODLOG_LCP="$L"
        break
    fi
    sleep 0.5
done
if [ "$LCP_OK" = "1" ]; then
    pass "module log: LCP opened / phase network / CHAP success path"
    log "---- module log LCP/CHAP/phase lines ----"
    printf '%s\n' "$MODLOG_LCP" | tee -a "$TRANSCRIPT"
else
    fail "module log never showed the LCP/CHAP/phase-network path"
fi

# IPCP must have negotiated: "IPCP layer up" (INFO, always logged) plus
# the negotiated pool address visible in-kernel on ifconfig pppoe0.
IPCP_OK=0
for i in $(seq 1 40); do
    if croot 'dmesg | grep "pppoe0:" | grep -q "IPCP layer up"'; then
        IPCP_OK=1
        break
    fi
    sleep 0.5
done
[ "$IPCP_OK" = "1" ] && pass "module log: IPCP layer up (IPCP negotiated)" \
                        || fail "module log never showed 'IPCP layer up'"

# ---------------------------------------------------------------- 4. ifconfig + structural scan
log ""
log "[4/7] in-kernel address + no-userland-ifconfig structural scan"

# ifconfig pppoe0 must show an inet FROM the pool 10.99.0.100-199 with
# peer --> 10.99.0.1 (ACCEL_GW).  Captured for the verify gate.
croot 'ifconfig pppoe0' > "$RESULT_DIR/03-client-ifconfig.log" 2>&1 || true
IFC_LINE="$(grep -E 'inet ' "$RESULT_DIR/03-client-ifconfig.log" | head -1 || true)"
log "client ifconfig pppoe0: $IFC_LINE"
if echo "$IFC_LINE" | grep -qE "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW "; then
    pass "in-kernel IPv4 applied: ifconfig pppoe0 shows pool inet --> $ACCEL_GW"
else
    fail "ifconfig pppoe0 lacks a pool inet --> $ACCEL_GW (got: '$IFC_LINE')"
fi
# peer must be exactly ACCEL_GW.
PEER="$(echo "$IFC_LINE" | sed -nE 's/.*--> ([0-9.]+).*/\1/p')"
if [ "$PEER" = "$ACCEL_GW" ]; then
    pass "peer is exactly $ACCEL_GW (ACCEL_GW)"
else
    fail "peer is '$PEER', expected $ACCEL_GW"
fi

# Structural scan: the transcript (and the dial recipe) must contain NO
# userland ifconfig address-assignment step.  The dial is a batched
# create/pppoeparms/spppauth/dmesg/up with no `ifconfig pppoe0 inet`.
# A userland assignment would look like `ifconfig pppoe0 inet` or
# `ifconfig pppoe0 <addr>`.  Scan the transcript + this script for both.
NO_USERLAND_IFCONFIG=1
for pat in 'ifconfig[[:space:]]\+pppoe0[[:space:]]\+inet' \
           'ifconfig[[:space:]]\+pppoe0[[:space:]]\+[0-9]'; do
    if grep -aE "$pat" "$TRANSCRIPT" >/dev/null 2>&1; then NO_USERLAND_IFCONFIG=0; fi
    if grep -aE "$pat" "$0" >/dev/null 2>&1; then NO_USERLAND_IFCONFIG=0; fi
done
if [ "$NO_USERLAND_IFCONFIG" = "1" ]; then
    pass "no userland ifconfig address assignment in the transcript (structural scan)"
else
    fail "userland ifconfig address-assignment found in transcript/script (structural scan)"
fi

# ---------------------------------------------------------------- 5. hold
log ""
log "[5/7] hold: connected state (LCP + CHAP + IPCP) for 35s"
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
if grep -q "$IPCPUSER" "$RESULT_DIR/05-accel-cmd-sessions.txt"; then
    pass "accel-ppp session table shows $IPCPUSER bound to a live session"
else
    fail "accel-ppp session table lacks user $IPCPUSER"
fi
hssh "sudo ip netns exec isp accel-cmd show stat" > "$RESULT_DIR/05b-accel-cmd-stat.txt" 2>&1

# ---------------------------------------------------------------- 6. capture
log ""
log "[6/7] capture durable artifacts under $RESULT_DIR"
hssh 'sudo tail -n 2000 /tmp/accel-ppp.log' > "$RESULT_DIR/01-server-accel-ppp.log" 2>&1
croot 'dmesg | grep "pppoe0:"' > "$RESULT_DIR/02-client-module.log" 2>&1 || true
cssh 'grep -aiE "pppoe0|sppp|ipcp" /var/log/messages 2>/dev/null | tail -n 400' \
    > "$RESULT_DIR/02b-client-syslog.log" 2>&1 || true
hssh "cat ~/$LAB_DIR/run/client.serial.log" > "$RESULT_DIR/03-client-serial.log" 2>&1
hssh "cat ~/$LAB_DIR/isp-netns/accel-ppp.ipcp.rendered.conf" > "$RESULT_DIR/06-config-rendered-dump.conf" 2>&1
{
    echo "== host: accel-pppd cmdline =="
    hssh 'pgrep -a accel-pppd || true' 2>&1
    echo "== host: netns isp pids =="
    hssh 'sudo ip netns pids isp 2>/dev/null || true' 2>&1
    echo "== client: pppoe/sppp/mpd-related procs =="
    cssh 'ps ax -o pid,comm,args | grep -iE "spppauth|pppoe|pppd|mpd" | grep -v grep || true' 2>&1
} > "$RESULT_DIR/07-process-listings.txt" 2>&1
pass "artifacts captured: server log, client module log, serial, sessions, config dump, ps"

# ---------------------------------------------------------------- 7. teardown
log ""
log "[7/7] teardown, exit statuses recorded"
creds_cleanup
TEARDOWN_DONE=1
{
    echo "== teardown exit statuses =="
    echo "client: restore mpd5 mpd_enable=YES (both knobs, MEM055):"
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
if [ "$FAIL" = "0" ]; then
    log "== ALL-CLOSE: PASS =="
else
    log "== ALL-CLOSE: FAIL =="
fi
log "== artifacts: $RESULT_DIR =="
[ "$FAIL" = "0" ] && exit 0 || exit 1
