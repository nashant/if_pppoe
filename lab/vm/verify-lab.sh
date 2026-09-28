#!/usr/bin/env bash
# verify-lab.sh — Task 5 lab verification. Prints PASS/FAIL per check and a
# final summary. Assumes: `run.sh {build,client,mpdsrv} up`, and both
# provision-client.sh / provision-mpdsrv.sh already run. Dials with a PPPoE
# account generated for this run (lab-creds.sh), removed again on exit, so
# the client is left on its provisioned (account-less) mpd.conf.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
source ./lab-creds.sh
set +e   # common.sh sets -e; this script deliberately keeps going past a
         # failing check (e.g. the ping -D test is *expected* to fail when
         # RFC4638 negotiation didn't happen) so every check gets a verdict.

NAME=client
vm_config "$NAME"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

lab_creds_generate
trap lab_creds_teardown EXIT
lab_creds_install_accel || { echo "FAIL: installing the run's accel-ppp account"; exit 1; }
lab_creds_install_mpdsrv || { echo "FAIL: installing the run's mpdsrv account"; exit 1; }
lab_creds_mount_client || { echo "FAIL: client mpd5 tmpfs mount"; exit 1; }
# provision-client.sh's two labels plus this run's account, tmpfs only.
lab_mpd_label() {  # $1 label, $2 service, $3 mtu/mru/max-payload lines
    printf '%s:\n\tcreate bundle static wan\n\tset iface name pppoe0\n' "$1"
    printf '\tset ipcp ranges 0.0.0.0/0 0.0.0.0/0\n\tset ipcp enable req-pri-dns\n\n'
    printf '\tcreate link static wan pppoe\n\tset link action bundle wan\n'
    printf '\tset link keep-alive 10 60\n\tset link disable chap pap\n\tset link accept chap pap eap\n'
    printf '%b' "$3"
    printf '\tset auth authname %s\n\tset auth password %s\n' "$LAB_PPPOE_USER" "$LAB_PPPOE_PASSWORD"
    printf '\tset pppoe iface vtnet1\n\tset pppoe service "%s"\n' "$2"
}
{
    printf 'startup:\n\ndefault:\n\tload lab\n\n'
    lab_mpd_label lab lab '\tset link mtu 1492\n'
    printf '\topen\n\n'
    lab_mpd_label mpdlab mpdlab '\tset link mtu 1500\n\tset link mru 1501\n'
    printf '\tset pppoe max-payload 1500\n\topen\n'
} | lab_creds_client_mpd5_conf || { echo "FAIL: writing the client's mpd.conf"; exit 1; }

echo "###### (a) client dials accel-ppp (isp-netns, service \"lab\") ######"
vm_ssh "$NAME" 'echo | su -m root -c "sed -i \"\" \"s/load mpdlab/load lab/\" /usr/local/etc/mpd5/mpd.conf; service mpd5 restart"' >/dev/null
sleep 6

IFCONFIG_A="$(vm_ssh "$NAME" ifconfig pppoe0)"
echo "$IFCONFIG_A"
case "$IFCONFIG_A" in
    *"inet 10.99.0.1"[0-9][0-9]*) pass "(a) pppoe0 has an inet in 10.99.0.100-199" ;;
    *) fail "(a) pppoe0 does not have an inet in 10.99.0.100-199" ;;
esac

PING_A_OUT="$(vm_ssh "$NAME" ping -c3 10.99.0.1 2>&1)"; PING_A_RC=$?
echo "$PING_A_OUT"
[ "$PING_A_RC" -eq 0 ] && pass "(a) ping -c3 10.99.0.1" || fail "(a) ping -c3 10.99.0.1"

IPERF_A_OUT="$(vm_ssh "$NAME" iperf3 -c 10.99.0.1 -t 3 2>&1)"; IPERF_A_RC=$?
echo "$IPERF_A_OUT"
[ "$IPERF_A_RC" -eq 0 ] && pass "(a) iperf3 -c 10.99.0.1 -t 3" || fail "(a) iperf3 -c 10.99.0.1 -t 3"

SESSIONS="$(host_ssh sudo ip netns exec isp accel-cmd -H 127.0.0.1 -P 2001 show sessions)"
echo "$SESSIONS"
case "$SESSIONS" in
    *"| lab "*"| active"*) pass "(a) accel-cmd show sessions lists an active 'lab' session" ;;
    *) fail "(a) accel-cmd show sessions does not list an active 'lab' session" ;;
esac

echo
echo "###### (b) client dials mpdsrv (service \"mpdlab\", RFC4638 max-payload 1500) ######"
vm_ssh "$NAME" 'echo | su -m root -c "sed -i \"\" \"s/load lab/load mpdlab/\" /usr/local/etc/mpd5/mpd.conf && service mpd5 restart"' >/dev/null
sleep 6

IFCONFIG_B="$(vm_ssh "$NAME" ifconfig pppoe0)"
echo "$IFCONFIG_B"
case "$IFCONFIG_B" in
    *"inet 10.99.2.1"[0-9][0-9]*) pass "(b) pppoe0 has an inet in 10.99.2.100-... pool" ;;
    *) fail "(b) pppoe0 does not have an inet in the 10.99.2.x pool" ;;
esac

case "$IFCONFIG_B" in
    *"mtu 1500"*) pass "(b) pppoe0 negotiated MTU is 1500" ;;
    *)
        fail "(b) pppoe0 negotiated MTU is NOT 1500 (RFC4638 tag not observed on the wire — see task-5-report.md BLOCKED section)"
        ;;
esac

PING_B_OUT="$(vm_ssh "$NAME" 'echo | su -m root -c "ping -D -s 1472 -c3 10.99.2.1"' 2>&1)"; PING_B_RC=$?
echo "$PING_B_OUT"
if [ "$PING_B_RC" -eq 0 ] && ! echo "$PING_B_OUT" | grep -q "too long\|100.0% packet loss"; then
    pass "(b) ping -D -s 1472 -c3 10.99.2.1 (no fragmentation)"
else
    fail "(b) ping -D -s 1472 -c3 10.99.2.1 (no fragmentation) — see task-5-report.md BLOCKED section"
fi

echo
echo "###### (c) kldstat: SMP kernel modules load ######"
KLD_GIF="$(vm_ssh "$NAME" 'echo | su -m root -c "kldload if_gif" 2>&1; kldstat | grep -i gif; echo | su -m root -c "kldunload if_gif" 2>&1')"
echo "$KLD_GIF"
case "$KLD_GIF" in
    *"already loaded or in kernel"*)
        pass "(c) if_gif: statically built into this SMP kernel (GENERIC has 'device gif'); kernel/config consistent"
        ;;
    *)
        fail "(c) if_gif: unexpected kldload/kldunload result"
        ;;
esac

KLDLOAD_OUT="$(mktemp)"
vm_ssh "$NAME" 'echo | su -m root -c "kldload if_bridge"' >"$KLDLOAD_OUT" 2>&1
LOAD_RC=$?
AFTER_LOAD="$(vm_ssh "$NAME" kldstat | grep -i bridge || true)"
vm_ssh "$NAME" 'echo | su -m root -c "kldunload if_bridge"' >/dev/null 2>&1
AFTER_UNLOAD="$(vm_ssh "$NAME" kldstat | grep -i bridge || true)"
echo "kldload rc=$LOAD_RC; after load: $AFTER_LOAD; after unload: [${AFTER_UNLOAD:-empty}]"
cat "$KLDLOAD_OUT"; rm -f "$KLDLOAD_OUT"
if [ "$LOAD_RC" -eq 0 ] && [ -n "$AFTER_LOAD" ] && [ -z "$AFTER_UNLOAD" ]; then
    pass "(c) kldload if_bridge (from /boot/kernel.SMP) then kldunload: genuine dynamic load/unload works"
else
    fail "(c) kldload/kldunload if_bridge did not behave as expected"
fi

echo
echo "###### back to the \"lab\" label (the account is removed on exit) ######"
vm_ssh "$NAME" 'echo | su -m root -c "sed -i \"\" \"s/load mpdlab/load lab/\" /usr/local/etc/mpd5/mpd.conf && service mpd5 restart"' >/dev/null
sleep 4
vm_ssh "$NAME" ifconfig pppoe0

echo
echo "###### SUMMARY: $PASS PASS, $FAIL FAIL ######"
[ "$FAIL" -eq 0 ]
