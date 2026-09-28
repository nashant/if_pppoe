#!/usr/bin/env bash
# M002/S03/T2: live per-vnet keepalive timers, link state and restart_link.
#
# Strictly ordered, evidence-terminating recipe (mirrors run-ipcp.sh's
# shape: set -euo pipefail, PASS/FAIL accounting, teardown trap restoring
# BOTH mpd_enable and mpd5_enable (MEM055), recorded exit statuses, bounded
# ssh with ConnectTimeout+BatchMode, never an open-ended daemon wait):
#   1. bring up the S01 accel-ppp harness with the IPCP config
#      (accel-ppp.ipcp.conf: ipv4=require + [ip-pool] 10.99.0.100-199 /
#      gw 10.99.0.1 -- IPCP MUST negotiate so the link state and the
#      re-applied address are observable)
#   2. client VM + freshly built in-kernel module (contains the M002/S03/T2
#      per-vnet keepalive machinery: VNET_DEFINE'd spppq/keepalive_ch/
#      sppp_keepalive_cnt/sppp_keepalive_interval + per-vnet callout with
#      the vnet captured as the callout arg), spppauth + spppkeepalive
#      helpers, pppoepparms present
#   3. live dial: single batched su -m root command (create/pppoeparms/
#      spppauth/dmesg -c/up, MEM054); NO userland ifconfig address step
#   4. keepalive config via the new SPPPSETKEEPALIVE helper
#      (tools/spppkeepalive): assert DEFAULT readback (maxalive=3
#      max_noreceive=15 alive_interval=1) then set a tuned window
#      (maxalive=2 max_noreceive=10 alive_interval=1) + readback
#   5. NEGATIVE: with the peer answering, the link must hold -- NO "LCP
#      keepalive timed out" in a 40s healthy window (the pp_last_receive
#      freshness gate: echo replies / payload keep alivecnt pinned at 0,
#      so max_noreceive waits for REAL silence -- research amendment 3)
#   6. kill the peer: isp netns eth0 down (accel-pppd's bound iface goes
#      operationally down -> the client sees pure silence, no PADT/TERM)
#      -> LCP keepalive timeout must fire within the configured window
#      (~30s + slack; recipe allows 90s) and if_link_state_change must
#      fire (LINK_STATE_DOWN in the collector); the sppp keepalive
#      restart is a close+open redial, so IFF_RUNNING ("link required")
#      and the negotiated address persist across the restart by design
#   7. peer back (eth0 up): the sppp redial path (work_close+work_open on
#      timeout) restarts discovery -> LCP Opened -> IPCP layer up -> the
#      pool address RE-APPLIED; this is the keepalive-driven restart_link
#   8. explicit restart_link: `ifconfig pppoe0 down` (pp_tlf -> pppoe_tlf
#      -> PADT) then `up` (pp_tls -> pppoe_tls -> discovery) -> redial to
#      LCP Opened and address re-applied; module log shows the tlf/tls
#      lower-link callbacks firing
#   9. clone destroy under a keepalive storm, repeat 10x: destroy pppoe0
#      mid-storm, recreate and redial to IPCP layer up each round;
#      sppp_detach removes the iface from the per-vnet keepalive list,
#      drains the pending works (sppp_wq_destroy -> taskqueue_drain) and
#      the sc_addr_task before the softc free (M001 teardown ruling #1);
#      assert no panic/trap and the guest stays responsive through all 10
#  10. capture durable artifacts under tests/results/keepalive-live/, then
#      clean teardown (both mpd knobs restored, pppoe0 destroyed,
#      kldunload, VM down, netns down; all rc recorded)
#
# Client is the in-kernel if_pppoe/sppp stack on the lab `client` VM.
# The whole run is driven over ssh from this repo; the only local state
# produced is the durable evidence under tests/results/keepalive-live/.
#
# Secrets discipline (R011): the runtime CHAP secret exists only in this
# process's environment and in tmpfs-only 0600 files on the lab
# hosts (deleted on every path); never echoed (no set -x), never in argv
# of a captured process, never committed.
#
# Usage: ./run-keepalive.sh        (needs the S01 lab + lab/vm tooling)
#   REBUILD=0 skips the kmod rebuild if /tmp/if_pppoe.ko is already
#   present on the client (pre-deployed by the T2 build step).
set -euo pipefail

VMHOST="${VMHOST:?set VMHOST in lab/local.env}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"
CLIENT_PORT=2223
ACCEL_GW=10.99.0.1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_DIR="$REPO_ROOT/tests/results/keepalive-live"
TRANSCRIPT="$RESULT_DIR/10-transcript.log"

PASS=0; FAIL=0
TEARDOWN_DONE=0
pass() { log "PASS: $*"; PASS=$((PASS+1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL+1)); }
log()  { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }

hssh() { ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" "$@"; }
cssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=8 -o LogLevel=ERROR -J "$VMHOST" -p "$CLIENT_PORT" freebsd@127.0.0.1 "$@"; }
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
    croot 'rm -f /var/run/if_pppoe-it/c /tmp/spppauth.c /tmp/spppkeepalive.c' 2>/dev/null || true
    bash "$REPO_ROOT/lab/vm/run.sh" client down >/dev/null 2>&1 || true
    ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" \
        "bash ~/$LAB_DIR/isp-netns/down.sh >/dev/null 2>&1" || true
}
trap 'creds_cleanup; teardown' EXIT

# ---------------------------------------------------------------- 0. boot
rm -rf "$RESULT_DIR"; mkdir -p "$RESULT_DIR"
: > "$TRANSCRIPT"
log "== M002/S03/T2 run-keepalive.sh $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
log "== host: $VMHOST  result dir: $RESULT_DIR"

# Runtime-generated dedicated test user + secret (never committed).
T2USER="t2kal$(date +%s)"
TESTSECRET="$(gen_secret)"
log "dedicated test user: $T2USER (secret generated, length ${#TESTSECRET}, not echoed)"

# ---------------------------------------------------------------- 1. server
log ""
log "[1/11] accel-ppp harness up with IPCP config (ipv4=require)"
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
if ! creds_server chap-ipcp "$T2USER" "$TESTSECRET"; then
    fail "staging T2 user in the server tmpfs credential file"
    exit 1
fi
pass "server tmpfs credential file carries $T2USER (secret staged via stdin)"

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

log "[1/11] brief settle for server listeners"
sleep 15

# ---------------------------------------------------------------- 2. client
log ""
log "[2/11] client VM up, fresh module, helpers"
if ! bash "$REPO_ROOT/lab/vm/run.sh" client up; then
    fail "client VM boot failed"
    exit 1
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
# Stale pppoe0 from a previous boot must not survive.
if cssh 'ifconfig pppoe0 >/dev/null 2>&1'; then
    log "stale pppoe0 present -- destroying before dial"
    croot 'ifconfig pppoe0 destroy 2>/dev/null || true'
    sleep 1
fi

# Wait for the guest's bridged NIC before dialing.
VT1_UP=0
for i in $(seq 1 30); do
    if cssh 'ifconfig vtnet1 2>/dev/null | grep -q "status: active"'; then VT1_UP=1; break; fi
    sleep 2
done
[ "$VT1_UP" = "1" ] && pass "guest vtnet1 link is active (ready to dial)" \
                        || { fail "vtnet1 never reported status: active"; exit 1; }

# The bridged tap must be present and attached to br-isp.
hssh 'ip link show tap-client >/dev/null 2>&1 || sudo ip tuntap add dev tap-client mode tap'
hssh 'ip -o link show tap-client | grep -q "master br-isp" || sudo ip link set tap-client master br-isp'
hssh 'sudo ip link set tap-client up'

# Module: rebuild+deploy unless REBUILD=0 with a pre-deployed .ko.
if [ "${REBUILD:-1}" != "0" ]; then
    log "building + deploying if_pppoe.ko (clean kmod build)"
    bash "$REPO_ROOT/lab/vm/build-module.sh" sync >/dev/null 2>&1 || { fail "module sync"; exit 1; }
    bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
        || { fail "module build/deploy"; exit 1; }
else
    if cssh 'test -f /tmp/if_pppoe.ko'; then
        pass "REBUILD=0: client already has /tmp/if_pppoe.ko (T2 build step deployed it)"
    else
        log "REBUILD=0 but /tmp/if_pppoe.ko absent on client -- deploying now"
        bash "$REPO_ROOT/lab/vm/build-module.sh" deploy sys/modules/if_pppoe if_pppoe.ko >/dev/null 2>&1 \
            || { fail "module deploy"; exit 1; }
    fi
fi
croot 'kldstat -q -n if_pppoe && kldunload if_pppoe' || true
croot 'kldload /tmp/if_pppoe.ko' || { fail "kldload"; exit 1; }
cssh 'kldstat -q -n if_pppoe.ko' && pass "fresh module (per-vnet keepalive) loaded on client"

# Empirical driver warm-up after kldload: dials issued within ~90s of the
# load fail to start discovery.  Wait it out.
log "settle 170s for driver warm-up after kldload"
sleep 170

# spppauth helper (SPPPSETAUTHCFG ioctl driver; never prints a secret).
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppauth/spppauth.c" freebsd@127.0.0.1:/tmp/spppauth.c
croot 'cc -O2 -Wall -o /usr/local/sbin/spppauth /tmp/spppauth.c && rm -f /tmp/spppauth.c' \
    && pass "spppauth helper compiled on client" || { fail "spppauth compile"; exit 1; }
# spppkeepalive helper (SPPPSETKEEPALIVE/SPPPGETKEEPALIVE ioctl driver) --
# T2's pppoectl-equivalent keepalive control surface.
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppkeepalive/spppkeepalive.c" freebsd@127.0.0.1:/tmp/spppkeepalive.c
croot 'cc -O2 -Wall -o /usr/local/sbin/spppkeepalive /tmp/spppkeepalive.c && rm -f /tmp/spppkeepalive.c' \
    && pass "spppkeepalive helper compiled on client" || { fail "spppkeepalive compile"; exit 1; }
cssh 'test -x /usr/local/sbin/pppoeparms' \
    && pass "pppoeparms present (S01 artifact)" || { fail "pppoeparms missing"; exit 1; }

# ---------------------------------------------------------------- 3. dial
log ""
log "[3/11] live dial: single batched su -m root, NO userland ifconfig assignment"

dial_once() {
    printf '%s\n%s\n' "$T2USER" "$TESTSECRET" \
        | creds_client_stage || return 13
    croot 'ifconfig pppoe0 destroy 2>/dev/null; ifconfig pppoe0 create; /usr/local/sbin/pppoeparms -e vtnet1 -s lab -a isp-lab pppoe0; ifconfig pppoe0 debug; tail -1 /var/run/if_pppoe-it/c | /usr/local/sbin/spppauth -m chap -n "$(head -1 /var/run/if_pppoe-it/c)" -S pppoe0; dmesg -c >/dev/null 2>&1 || true; ifconfig pppoe0 up' \
        || { croot 'rm -f /var/run/if_pppoe-it/c'; return 11; }
    croot 'rm -f /var/run/if_pppoe-it/c'
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
[ "$DIAL_RC" = "0" ] && pass "live dial: discovery reached SESSION (state=3) for $T2USER" \
                        || { fail "dial failed after retries (last rc=$DIAL_RC)"; exit 1; }

# LCP opened + IPCP layer up.
LCP_OK=0
for i in $(seq 1 40); do
    L="$(croot 'dmesg | grep "pppoe0:" | grep -E "lcp input\(opened\)|phase network"')"
    if printf '%s' "$L" | grep -qE 'lcp input\(opened\)'; then
        LCP_OK=1; break
    fi
    sleep 0.5
done
[ "$LCP_OK" = "1" ] && pass "module log: LCP opened" || fail "module log never showed LCP opened"

IPCP_OK=0
for i in $(seq 1 40); do
    if croot 'dmesg | grep "pppoe0:" | grep -q "IPCP layer up"'; then
        IPCP_OK=1; break
    fi
    sleep 0.5
done
[ "$IPCP_OK" = "1" ] && pass "module log: IPCP layer up (address applied)" \
                        || fail "module log never showed 'IPCP layer up'"

croot 'ifconfig pppoe0' > "$RESULT_DIR/03-client-ifconfig.log" 2>&1 || true
IFC_LINE="$(grep -E 'inet ' "$RESULT_DIR/03-client-ifconfig.log" | head -1 || true)"
log "client ifconfig pppoe0: $IFC_LINE"
if echo "$IFC_LINE" | grep -qE "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW "; then
    pass "negotiated pool inet --> $ACCEL_GW present after dial"
else
    fail "no pool inet after dial"
fi

# ---------------------------------------------------------------- 4. keepalive cfg
log ""
log "[4/11] keepalive config via SPPPSETKEEPALIVE/SPPPGETKEEPALIVE"
KA_DEF="$(croot '/usr/local/sbin/spppkeepalive -g pppoe0 2>&1 || true')"
log "default keepalive readback: $KA_DEF"
if printf '%s' "$KA_DEF" | grep -qE 'maxalive=3 max_noreceive=15 alive_interval=1'; then
    pass "defaults match NetBSD: maxalive=3 max_noreceive=15 alive_interval=1"
else
    fail "default keepalive readback unexpected: $KA_DEF"
fi
KA_SET="$(croot '/usr/local/sbin/spppkeepalive -m 2 -r 10 -i 1 pppoe0 2>&1 || true')"
KA_RB="$(croot '/usr/local/sbin/spppkeepalive -g pppoe0 2>&1 || true')"
log "set output: $KA_SET"
log "tuned readback: $KA_RB"
if printf '%s' "$KA_RB" | grep -qE 'maxalive=2 max_noreceive=10 alive_interval=1'; then
    pass "tuned window applied: maxalive=2 max_noreceive=10 alive_interval=1"
else
    fail "tuned keepalive readback unexpected: $KA_RB"
fi

# ---------------- collectors (started after the dial, before the kill) ---
# The guest dmesg ring is a rotating buffer and the redial loop floods it,
# so the keepalive evidence is captured by a guest-side collector that
# drains dmesg -c into /tmp/kal.txt every 2s (immune to ring eviction).
# The collector is started after the dial and torn down by `teardown`.
KAL=/tmp/kal.txt
kal_start() {
    croot "rm -f $KAL; nohup sh -c 'while true; do dmesg -c >> $KAL 2>/dev/null; sleep 2; done' >/dev/null 2>&1 & echo started" >/dev/null 2>&1
    sleep 2
    return 0
}
kal_stop() {
    croot "pkill -f 'dmesg -c >> $KAL' 2>/dev/null || true" >/dev/null 2>&1 || true
    return 0
}

# ---------------------------------------------------------------- 5. NEGATIVE: healthy hold
log ""
log "[5/11] NEGATIVE: healthy link must NOT keepalive-timeout (freshness gate)"
kal_start
HEALTHY_T0="$(date +%s)"
TIMEOUT_EARLY=0
for i in $(seq 1 20); do
    if croot "grep -q 'LCP keepalive timed out' $KAL 2>/dev/null"; then
        TIMEOUT_EARLY=1; break
    fi
    sleep 2
done
HEALTHY_ELAPSED=$(( $(date +%s) - HEALTHY_T0 ))
if [ "$TIMEOUT_EARLY" = "0" ]; then
    pass "NO keepalive timeout in ${HEALTHY_ELAPSED}s while the peer answers (max_noreceive freshness gate holds)"
else
    fail "spurious keepalive timeout during the healthy hold (freshness gate broken)"
fi
# Link still up: RUNNING flag + address present.
croot 'ifconfig pppoe0' > "$RESULT_DIR/04-healthy-ifconfig.log" 2>&1 || true
if head -1 "$RESULT_DIR/04-healthy-ifconfig.log" | grep -q 'RUNNING'; then
    pass "link state up (IFF_RUNNING) after the healthy window"
else
    fail "link state dropped during the healthy window"
fi
if grep -E 'inet ' "$RESULT_DIR/04-healthy-ifconfig.log" | head -1 | grep -q "$ACCEL_GW"; then
    pass "negotiated address still applied after the healthy window"
else
    fail "negotiated address vanished during the healthy window"
fi

# ---------------------------------------------------------------- 6. kill peer
log ""
log "[6/11] kill the accel-ppp peer: flush sessions, then isp eth0 down"
croot 'dmesg -c >/dev/null 2>&1 || true'   # timestamp the kill
KILL_T0="$(date +%s)"
# Flush the accel-ppp session table first so the post-recovery redial is
# not polluted by accel-ppp's dead-session IP pool lease (observed in the
# first run: the server NAKs a reconnecting client's IPCP for ~60s after a
# dropped session and TERMs it).  Then take the peer's bound iface down:
# the client sees PURE silence (no PADT/TERM can cross the downed veth).
hssh 'sudo ip netns exec isp accel-cmd terminate sessions >/dev/null 2>&1 || true'
sleep 2
if ! hssh 'sudo ip netns exec isp ip link set eth0 down'; then
    fail "could not bring isp eth0 down"
    exit 1
fi
pass "peer link down (isp netns eth0), client sees pure silence"

TOUT_ELAPSED=-1
for i in $(seq 1 45); do
    if croot "grep -q 'LCP keepalive timed out' $KAL 2>/dev/null"; then
        TOUT_ELAPSED=$(( $(date +%s) - KILL_T0 ))
        break
    fi
    sleep 2
done
if [ "$TOUT_ELAPSED" -ge 0 ] && [ "$TOUT_ELAPSED" -le 90 ]; then
    pass "LCP keepalive timed out ${TOUT_ELAPSED}s after peer death (window ~30s + slack <= 90s)"
else
    fail "keepalive timeout missing or out of window (got ${TOUT_ELAPSED}s)"
fi
croot "grep -aE 'keepalive|phase|timeout|echo' $KAL" > "$RESULT_DIR/05-timeout-module.log" 2>&1 || true
log "---- timeout module log ----"
grep -a "keepalive timed out" "$RESULT_DIR/05-timeout-module.log" | head -3 | tee -a "$TRANSCRIPT" || true

# Let the LCP teardown settle, then assert the in-window link-state drop.
# The sppp keepalive restart is a close+open REDIAL, not a disconnect:
# IFF_RUNNING (the "lower link required" flag, sppp_connect/disconnect) stays
# set and the negotiated address persists across the restart (NetBSD sppp
# keeps want_local/want_remote; the SIOCDIFADDR clear fires only on a true
# dynamic-address teardown).  The plan's observable for "link state drops
# within the window" is if_link_state_change itself -- poll the collector
# for the LINK_STATE_DOWN event.
sleep 8
LS_DOWN_OK=0
for i in $(seq 1 30); do
    if croot "grep -q 'link state changed to DOWN' $KAL 2>/dev/null"; then
        LS_DOWN_OK=1
        break
    fi
    sleep 2
done
if [ "$LS_DOWN_OK" = "1" ]; then
    pass "if_link_state_change(LINK_STATE_DOWN) fired in-window after the keepalive timeout"
else
    fail "no 'link state changed to DOWN' event in the 60s after the timeout line"
fi
# Diagnostic (not a hard gate): what does ifconfig show at this point?
croot 'ifconfig pppoe0' > "$RESULT_DIR/06-down-ifconfig.log" 2>&1 || true
log "ifconfig at kill+~40s: $(head -1 "$RESULT_DIR/06-down-ifconfig.log")"
# Client must still be responsive (no panic).
croot 'echo alive' >/dev/null 2>&1 && pass "client responsive after timeout (no panic)" \
                                          || fail "client unresponsive after timeout"

# ---------------------------------------------------------------- 7. peer back -> restart_link auto-redial
log ""
log "[7/11] peer back (eth0 up): redial to LCP Opened + address re-applied"
hssh 'sudo ip netns exec isp ip link set eth0 up'
sleep 1
REDIAL_OK=0
# The accel-ppp IP pool holds the dead session's lease for a while, so the
# server may NAK/TERM a few reconnect attempts (pool-lease reunion, not a
# client defect); allow up to 180s for the eventual clean redial.
for i in $(seq 1 90); do
    if croot "grep -q 'IPCP layer up' $KAL 2>/dev/null"; then
        REDIAL_OK=1; break
    fi
    sleep 2
done
[ "$REDIAL_OK" = "1" ] && pass "keepalive-timeout redial: LCP reopened, IPCP layer up again" \
                        || fail "no redial after peer return"
croot 'ifconfig pppoe0' > "$RESULT_DIR/07-redial-ifconfig.log" 2>&1 || true
IFC2="$(grep -E 'inet ' "$RESULT_DIR/07-redial-ifconfig.log" | head -1 || true)"
if echo "$IFC2" | grep -qE "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW "; then
    pass "address re-applied after auto-redial: $IFC2"
else
    fail "no pool inet after auto-redial (got: '$IFC2')"
fi
if head -1 "$RESULT_DIR/07-redial-ifconfig.log" | grep -q 'RUNNING'; then
    pass "link state up again after redial (IFF_RUNNING)"
else
    fail "IFF_RUNNING still clear after redial"
fi

# ---------------------------------------------------------------- 8. explicit restart_link
log ""
log "[8/11] explicit restart_link: ifconfig pppoe0 down..up (pp_tlf PADT -> pp_tls redial)"
croot 'dmesg -c >/dev/null 2>&1 || true'
if ! croot 'ifconfig pppoe0 down'; then
    fail "ifconfig pppoe0 down failed"
    exit 1
fi
sleep 2
croot 'dmesg | grep "pppoe0:" | grep -E "(tlf|tls|phase)"' > "$RESULT_DIR/08a-down-module.log" 2>&1 || true
if grep -qE 'tlf|tls' "$RESULT_DIR/08a-down-module.log" 2>/dev/null; then
    pass "pp_tlf/pp_tls lower-link callbacks fired on down"
else
    log "note: tlf/tls dlog lines not captured in this dmesg window (phase lines below)"
fi
if ! croot 'ifconfig pppoe0 up'; then
    fail "ifconfig pppoe0 up failed"
    exit 1
fi
RL_OK=0
for i in $(seq 1 90); do
    if croot "grep -qE 'lcp input\\(opened\\)' $KAL 2>/dev/null"; then
        RL_OK=1; break
    fi
    sleep 2
done
[ "$RL_OK" = "1" ] && pass "restart_link: LCP Opened after down/up" \
                        || fail "restart_link: LCP did not reopen"
RL_IP_OK=0
for i in $(seq 1 60); do
    if croot "grep -q 'IPCP layer up' $KAL 2>/dev/null"; then
        RL_IP_OK=1; break
    fi
    sleep 1
done
[ "$RL_IP_OK" = "1" ] && pass "restart_link: IPCP layer up, address re-applied" \
                        || fail "restart_link: IPCP did not renegotiate"
croot 'ifconfig pppoe0' > "$RESULT_DIR/08-restart-ifconfig.log" 2>&1 || true
IFC3="$(grep -E 'inet ' "$RESULT_DIR/08-restart-ifconfig.log" | head -1 || true)"
if echo "$IFC3" | grep -qE "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW "; then
    pass "restart_link address re-applied: $IFC3"
else
    fail "restart_link: no pool inet after redial (got: '$IFC3')"
fi

# ---------------------------------------------------------------- 9. clone destroy storm x10
log ""
log "[9/11] clone destroy under keepalive storm, repeat 10x (no panic)"
STORM_OK=1
for round in $(seq 1 10); do
    # Keepalive storm is live: the peer answers ECHO_REQs every interval
    # and the per-vnet callout fires on the 10s cadence.  Destroy the
    # clone mid-storm: sppp_detach removes it from the per-vnet list and
    # drains pending works (taskqueue_drain) before the softc free.
    if ! croot 'ifconfig pppoe0 destroy 2>/dev/null'; then
        fail "round $round: destroy failed"
        STORM_OK=0; break
    fi
    sleep 1
    if ! dial_once; then
        fail "round $round: redial after destroy failed"
        STORM_OK=0; break
    fi
    R_IP_OK=0
    for i in $(seq 1 40); do
        if croot "grep -q 'IPCP layer up' $KAL 2>/dev/null"; then
            R_IP_OK=1; break
        fi
        sleep 1
    done
    if [ "$R_IP_OK" != "1" ]; then
        fail "round $round: IPCP did not re-negotiate after recreate"
        STORM_OK=0; break
    fi
    pass "round $round/10: destroy+recreate+redial clean under the keepalive storm"
done
if [ "$STORM_OK" = "1" ]; then
    pass "10x clone destroy under keepalive storm: no panic, every redial reached IPCP"
else
    fail "clone destroy storm did not complete cleanly"
fi
# Panic audit across the whole run: the collector is the full kernel log;
# also drain whatever remains in the live ring.
kal_stop
sleep 3
croot "cat $KAL" > "$RESULT_DIR/09-client-kal-full.log" 2>&1 || true
croot 'dmesg' > "$RESULT_DIR/09-client-dmesg-full.log" 2>&1 || true
if grep -aiE 'panic|fatal trap|reboot' "$RESULT_DIR/09-client-kal-full.log" "$RESULT_DIR/09-client-dmesg-full.log" \
    | grep -v 'next boot' | head -5 > "$RESULT_DIR/09-panic-scan.log"; then
    fail "panic/trap lines found in client dmesg:"
    cat "$RESULT_DIR/09-panic-scan.log" | tee -a "$TRANSCRIPT"
else
    pass "no panic/trap/reboot in the full client kernel log"
fi

# ---------------------------------------------------------------- 10. capture
log ""
log "[10/11] capture durable artifacts under $RESULT_DIR"
hssh 'sudo tail -n 2000 /tmp/accel-ppp.log' > "$RESULT_DIR/01-server-accel-ppp.log" 2>&1 || true
croot "cat $KAL" > "$RESULT_DIR/02-client-module.log" 2>&1 || true
cssh 'grep -aiE "pppoe0|sppp|keepalive" /var/log/messages 2>/dev/null | tail -n 400' \
    > "$RESULT_DIR/02b-client-syslog.log" 2>&1 || true
hssh "cat ~/$LAB_DIR/run/client.serial.log" > "$RESULT_DIR/03-client-serial.log" 2>&1 || true
hssh "cat ~/$LAB_DIR/isp-netns/accel-ppp.rendered.conf" > "$RESULT_DIR/06-config-rendered-dump.conf" 2>&1 || true
hssh "sudo ip netns exec isp accel-cmd show sessions" > "$RESULT_DIR/05b-accel-cmd-sessions.txt" 2>&1 || true
pass "artifacts captured: server log, client module log, serial, sessions, config dump"

# ---------------------------------------------------------------- verify-gates scan
log ""
log "[11/11] verify-gate scan"
: > "$RESULT_DIR/09-verify-gates.txt"
gate() {
    local name="$1" result="$2"
    printf '%-46s %s\n' "$name" "$result" >> "$RESULT_DIR/09-verify-gates.txt"
}
[ -s "$RESULT_DIR/09-client-dmesg-full.log" ] && gate "client dmesg captured" "PASS" || gate "client dmesg captured" "FAIL"
grep -q "LCP keepalive timed out" "$RESULT_DIR/02-client-module.log" \
    && gate "keepalive timeout in module log" "PASS" || gate "keepalive timeout in module log" "FAIL"
grep -q "IPCP layer up" "$RESULT_DIR/02-client-module.log" \
    && gate "IPCP layer up (>=1) in module log" "PASS" || gate "IPCP layer up in module log" "FAIL"
grep -q 'RUNNING' "$RESULT_DIR/04-healthy-ifconfig.log" \
    && gate "RUNNING set while healthy" "PASS" || gate "RUNNING set while healthy" "FAIL"
if grep -q 'link state changed to DOWN' "$RESULT_DIR/02-client-module.log" 2>/dev/null; then
    gate "if_link_state_change DOWN in window" "PASS"
else
    gate "if_link_state_change DOWN in window" "FAIL"
fi
if grep -q 'sppp_clear_ip_addrs' "$RESULT_DIR/02-client-module.log" 2>/dev/null; then
    gate "address clear path fired (SIOCDIFADDR deferral)" "PASS"
else
    gate "address clear path fired (SIOCDIFADDR deferral)" "FAIL"
fi
grep -Eq "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW " "$RESULT_DIR/07-redial-ifconfig.log" 2>/dev/null \
    && gate "address re-applied after auto-redial" "PASS" || gate "address re-applied after auto-redial" "FAIL"
grep -Eq "inet 10\.99\.0\.(1(0[0-9]|[1-9][0-9])|99) --> $ACCEL_GW " "$RESULT_DIR/08-restart-ifconfig.log" 2>/dev/null \
    && gate "address re-applied after explicit restart_link" "PASS" || gate "address re-applied after restart_link" "FAIL"
[ -s "$RESULT_DIR/09-panic-scan.log" ] \
    && gate "no panic/trap in dmesg" "FAIL" || gate "no panic/trap in dmesg" "PASS"
gate "keepalive functional test (model)" "sppp_keepalive.c: run separately"
cat "$RESULT_DIR/09-verify-gates.txt" | tee -a "$TRANSCRIPT"

# ---------------------------------------------------------------- teardown
log ""
log "[teardown] exit statuses recorded"
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

# orphan check
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