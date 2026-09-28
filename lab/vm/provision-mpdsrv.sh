#!/usr/bin/env bash
# Installs/configures mpd5 as a PPPoE server (service "mpdlab", RFC4638
# max-payload 1500) + iperf3 -s on the "mpdsrv" VM. Stock kernel — no kernel
# swap needed here. Requires `run.sh mpdsrv up` first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

NAME=mpdsrv
vm_config "$NAME"
remote() { vm_ssh "$NAME" sh -s; }

echo "=== [1/3] pkg install mpd5 iperf3 ==="
remote <<'EOF'
set -eu
asroot() { echo | su -m root -c "$*"; }
asroot pkg install -y mpd5 iperf3
EOF

echo "=== [2/3] writing mpd.conf (PPPoE server, service mpdlab) ==="
# No mpd.secret: there is no fixed lab account.  Each run mounts a tmpfs over
# /usr/local/etc/mpd5 with this mpd.conf plus its own generated mpd.secret
# (tests/functional/labcreds.py, lab/vm/lab-creds.sh) and unmounts it after.
# Modeled on the shipped mpd.conf.sample's "pppoe_server:" section (bundle +
# link templates, so each incoming call gets its own instance) plus mpd49's
# documented caveat that "set pppoe max-payload" only takes effect on the
# client side — the server's actual willingness to negotiate a 1500-byte PPP
# frame over PPPoE comes from "set link mtu/mru 1500" on this side; both are
# set here (max-payload per the brief, mtu/mru for it to actually take).
MPD_CONF='startup:

default:
	load mpdlab

mpdlab:
	create bundle template B
	# IPv6CP is a bundle-layer option, off by default (mpd5 manual, IPv6CP
	# chapter mpd27.html: "ipv6cp option should be enabled at the bundle
	# layer"), so it must be set here in the bundle context: after
	# `create link template` the context is the link and `set bundle` is
	# rejected.  The IPv6CP layer has no other options, so the tunnel
	# interface identifier cannot be pinned; tests read it off the live ngN
	# (tests/functional/lab.py mpdsrv_tunnel()).
	set bundle enable ipv6cp
	set ipcp ranges 10.99.2.1/32 10.99.2.100/24
	set iface enable tcpmssfix

	create link template L1 pppoe
	set link action bundle B
	set link disable eap
	set link enable pap chap
	set link keep-alive 10 60
	set link max-children 8
	set link mtu 1500
	set link mru 1500
	set auth enable internal
	set pppoe iface vtnet1
	set pppoe service "mpdlab"
	set pppoe max-payload 1500
	set link enable incoming
'
printf '%s\n' "$MPD_CONF" | ./run.sh mpdsrv ssh -- 'cat > /tmp/mpd.conf.new'
remote <<'EOF'
set -eu
echo | su -m root -c "cp /tmp/mpd.conf.new /usr/local/etc/mpd5/mpd.conf && rm -f /tmp/mpd.conf.new /tmp/mpd.secret.new /usr/local/etc/mpd5/mpd.secret"
asroot() { echo | su -m root -c "$*"; }
asroot sysrc mpd_enable=YES
asroot service mpd5 restart
sleep 2
cat /usr/local/etc/mpd5/mpd.conf
EOF

echo "=== [3/3] starting iperf3 -s -D ==="
remote <<'EOF'
set -eu
asroot() { echo | su -m root -c "$*"; }
if pgrep -x iperf3 >/dev/null 2>&1; then
    echo "iperf3 already running."
else
    asroot iperf3 -s -D
    sleep 1
    pgrep -x iperf3 >/dev/null 2>&1 && echo "iperf3 -s -D started." || { echo "iperf3 failed to start" >&2; exit 1; }
fi
EOF

echo "=== provision-mpdsrv.sh done ==="
