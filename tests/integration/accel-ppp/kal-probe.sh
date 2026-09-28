#!/usr/bin/env bash
# DIAGNOSTIC probe (M002/S03/T2) -- wire truth for the keepalive timeout.
# Not a shipped test: folds its findings into run-keepalive.sh.
set -u
VMHOST="${VMHOST:?set VMHOST in lab/local.env}"
LAB_DIR="${LAB_DIR:-if_pppoe-lab}"
CLIENT_PORT=2223
ACCEL_GW=10.99.0.1
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

hssh() { ssh -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR "$VMHOST" "$@"; }
cssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=8 -o LogLevel=ERROR -J "$VMHOST" -p "$CLIENT_PORT" freebsd@127.0.0.1 "$@"; }
croot() { cssh "echo | su -m root -c $(printf '%q' "$1")"; }
# shellcheck source=tests/integration/accel-ppp/creds.sh
. "$HARNESS_DIR/creds.sh"
trap creds_cleanup EXIT

TZUSER="t2probe$(date +%s)"
TZSECRET="$(gen_secret)"

echo "== server up =="
hssh 'bash ~/if_pppoe-lab/isp-netns/up.sh' >/dev/null 2>&1 || exit 1
scp -q "$HARNESS_DIR/accel-ppp.ipcp.conf" "$VMHOST:$LAB_DIR/isp-netns/accel-ppp.ipcp.conf"
creds_server chap-ipcp "$TZUSER" "$TZSECRET" || exit 1
hssh "CREDS_FILE=$(creds_server_path chap-ipcp) bash -s" <<'EOF' >/dev/null
set -e
cd ~/if_pppoe-lab/isp-netns
sed -e 's#@LABDIR@#'"$PWD"'#g' -e 's#@CREDS_FILE@#'"$CREDS_FILE"'#g' accel-ppp.ipcp.conf > accel-ppp.ipcp.rendered.conf
for p in $(sudo ip netns pids isp 2>/dev/null || true); do
    [ "$(cat /proc/$p/comm 2>/dev/null)" = accel-pppd ] && sudo kill "$p"
done
sleep 2
sudo truncate -s 0 /tmp/accel-ppp.log || true
sudo ip netns exec isp /usr/local/sbin/accel-pppd -c "$PWD/accel-ppp.ipcp.rendered.conf" -p /run/accel-pppd-ipcp.pid -d
sleep 2
EOF
echo "== client up =="
bash "$REPO_ROOT/lab/vm/run.sh" client up >/dev/null 2>&1 || exit 1
croot 'sysrc -f /etc/rc.conf mpd5_enable=NO mpd_enable=NO' 2>/dev/null
if cssh 'pgrep -x mpd5 >/dev/null'; then
    cssh 'echo | su -m root -c "shutdown -r now"' || true
    sleep 30; cssh 'true' 2>/dev/null || sleep 20
fi
for i in $(seq 1 30); do cssh 'ifconfig vtnet1 2>/dev/null | grep -q "status: active"' && break; sleep 2; done

echo "== module (reuse deployed ko) =="
croot 'kldstat -q -n if_pppoe && kldunload if_pppoe' 2>/dev/null
croot 'kldload /tmp/if_pppoe.ko' || exit 1
echo "== warmup 150s =="; sleep 150

scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppauth/spppauth.c" freebsd@127.0.0.1:/tmp/spppauth.c
scp -q -J "$VMHOST" -P "$CLIENT_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$REPO_ROOT/tools/spppkeepalive/spppkeepalive.c" freebsd@127.0.0.1:/tmp/spppkeepalive.c
croot 'cc -O2 -Wall -o /usr/local/sbin/spppauth /tmp/spppauth.c'
croot 'cc -O2 -Wall -o /usr/local/sbin/spppkeepalive /tmp/spppkeepalive.c'

echo "== dial =="
printf '%s\n%s\n' "$TZUSER" "$TZSECRET" | creds_client_stage || exit 1
croot 'ifconfig pppoe0 destroy 2>/dev/null; ifconfig pppoe0 create; /usr/local/sbin/pppoeparms -e vtnet1 -s lab -a isp-lab pppoe0; ifconfig pppoe0 debug; tail -1 /var/run/if_pppoe-it/c | /usr/local/sbin/spppauth -m chap -n "$(head -1 /var/run/if_pppoe-it/c)" -S pppoe0; dmesg -c >/dev/null 2>&1 || true; ifconfig pppoe0 up'
croot 'rm -f /var/run/if_pppoe-it/c'
for i in $(seq 1 60); do
    st="$(croot '/usr/local/sbin/pppoeparms -d pppoe0 2>/dev/null | tr " " "\n" | grep -E "^state=" | cut -d= -f2')"
    [ "$st" = "3" ] && break; sleep 0.5
done
IPCP=0
for i in $(seq 1 40); do
    croot 'dmesg | grep "pppoe0:" | grep -q "IPCP layer up"' && { IPCP=1; break; }; sleep 1
done
echo "IPCP after dial: $IPCP"
croot 'ifconfig pppoe0'
croot '/usr/local/sbin/spppkeepalive -m 2 -r 10 -i 1 pppoe0'
croot '/usr/local/sbin/spppkeepalive -g pppoe0'

echo "== arm collectors =="
croot 'rm -f /tmp/kal.txt; nohup sh -c "while true; do dmesg -c >> /tmp/kal.txt 2>&1; sleep 2; done" >/dev/null 2>&1 & echo started'
hssh 'sudo timeout 130 tcpdump -i br-isp -s 0 -w /tmp/kal.pcap "ether proto 0x8863 or ether proto 0x8864" >/dev/null 2>&1 & echo started'
sleep 3
echo "== T0: flush accel sessions, then kill peer (pure silence) =="
T0="$(date +%s)"; echo "T0=$T0"
croot 'dmesg -c >/dev/null 2>&1'
hssh 'sudo ip netns exec isp accel-cmd terminate sessions >/dev/null 2>&1 || true'
sleep 2
hssh 'sudo ip netns exec isp ip link set eth0 down'
echo "killed at $(date +%s)"
for i in $(seq 1 16); do
    sleep 5
    if croot 'grep -q "LCP keepalive timed out" /tmp/kal.txt 2>/dev/null'; then
        echo "TIMEOUT-OBSERVED at $(date +%s) (elapsed $(( $(date +%s) - T0 ))s)"
        croot 'grep -n "keepalive\|phase\|echo\|timeout" /tmp/kal.txt | tail -25'
        break
    fi
done
[ "$i" = "16" ] && echo "TIMEOUT-NOT-OBSERVED in 80s -- see kal.txt"
echo "== state at kill+~60s =="
sleep 25
croot 'ifconfig pppoe0'
echo "--- kal.txt (killed-window tail) ---"
croot 'tail -50 /tmp/kal.txt'

echo "== peer back =="
hssh 'sudo ip netns exec isp ip link set eth0 up'
sleep 40
echo "--- kal.txt (recovery window) ---"
croot 'grep -E "IPCP layer up|phase network|keepalive timed out|session" /tmp/kal.txt | tail -15'
croot 'ifconfig pppoe0'
echo "== artifacts =="
croot 'cp /tmp/kal.txt /tmp/kal-final.txt'
hssh 'cp /tmp/kal.pcap /tmp/kal-final.pcap 2>/dev/null'
cssh 'cat /tmp/kal-final.txt' > /tmp/kal-client-final.txt 2>/dev/null
hssh 'ls -la /tmp/kal-final.pcap'
echo "collector-lines: $(wc -l < /tmp/kal-client-final.txt 2>/dev/null)"