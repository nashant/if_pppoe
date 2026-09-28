#!/usr/bin/env bash
# perf-backend.sh <if_pppoe|mpd5|raw> — bring LAB_SLOT's client VM WAN up as
# that test-perf-fwd BACKEND (if_pppoe: IfPppoeClient.dial's pppoectl sequence
# on /tmp/if_pppoe.ko; mpd5: its "lab" label, also named pppoe0; raw: none).
#
# The PPPoE account is generated for this invocation (lab-creds.sh), used to
# authenticate, and removed again once pppoe0 is up: accel-ppp only checks
# chap-secrets at authentication time and the client keeps the secret in
# kernel/mpd5 memory, so the established session runs on with no secret left
# on any disk or tmpfs.  A redial (session loss mid-run) therefore fails
# authentication -- rerun perf-backend.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
source ./lab-creds.sh

BACKEND="${1:-}"
case "$BACKEND" in
    raw) exec ./teardown-nonraw.sh ;;
    if_pppoe|mpd5) ;;
    *) echo "perf-backend.sh: BACKEND must be if_pppoe, mpd5, or raw (got '$BACKEND')" >&2; exit 1 ;;
esac

lab_creds_generate
trap 'lab_creds_remove_accel || true; lab_creds_unmount_client_live || true' EXIT
lab_creds_install_accel

if [ "$BACKEND" = mpd5 ]; then
    # mpd5's "lab" label (provision-client.sh) plus this run's account, on
    # the client's tmpfs conf dir only.
    lab_creds_mount_client
    lab_creds_client_mpd5_conf <<CONF
startup:

default:
	load lab

lab:
	create bundle static wan
	set iface name pppoe0
	set ipcp ranges 0.0.0.0/0 0.0.0.0/0
	set ipcp enable req-pri-dns

	create link static wan pppoe
	set link action bundle wan
	set link keep-alive 10 60
	set link disable chap pap
	set link accept chap pap eap
	set link mtu 1492
	set auth authname $LAB_PPPOE_USER
	set auth password $LAB_PPPOE_PASSWORD
	set pppoe iface vtnet1
	set pppoe service "lab"
	open
CONF
fi

# The if_pppoe secret is part of the script text below, which reaches the
# guest's sh on ssh stdin; there it is a shell variable piped to
# pppoectl -S's stdin -- no argv, no file.
vm_ssh client sh -s <<EOF
LAB_SECRET='$LAB_PPPOE_PASSWORD'
set -eu
asroot() { echo | su -m root -c "\$*"; }
if [ "$BACKEND" = if_pppoe ]; then
    asroot 'service mpd5 onestop' >/dev/null 2>&1 || true
    ifconfig ng0 >/dev/null 2>&1 && asroot 'ifconfig ng0 destroy' || true
    # mpd5's renamed ng_iface may linger as pppoe0 briefly after stop
    if ifconfig pppoe0 >/dev/null 2>&1 && ! ifconfig -g pppoe | grep -qx pppoe0; then
        sleep 2
        ifconfig pppoe0 >/dev/null 2>&1 && ! ifconfig -g pppoe | grep -qx pppoe0 && \
            { echo "perf-backend: pppoe0 still exists and is not an if_pppoe clone" >&2; exit 1; }
    fi
    kldstat -q -n if_pppoe || asroot 'kldload /tmp/if_pppoe.ko'
    ifconfig pppoe0 >/dev/null 2>&1 && asroot 'ifconfig pppoe0 destroy'
    asroot 'ifconfig pppoe0 create'
    asroot '/usr/local/sbin/pppoectl -e vtnet1 -s lab pppoe0'
    printf '%s\n' "\$LAB_SECRET" | su -m root -c '/usr/local/sbin/pppoectl -S pppoe0 myauthproto=pap passiveauthproto myauthname=$LAB_PPPOE_USER query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1'
    unset LAB_SECRET
    asroot 'ifconfig pppoe0 up'
else
    if ifconfig -g pppoe 2>/dev/null | grep -qx pppoe0; then asroot 'ifconfig pppoe0 destroy'; fi
    asroot 'service mpd5 onerestart' >/dev/null
fi
i=0
until ifconfig pppoe0 2>/dev/null | grep -q '^[[:space:]]*inet '; do
    i=\$((i + 1))
    [ \$i -le 60 ] || { echo "perf-backend: pppoe0 has no IPv4 address after 60s" >&2; ifconfig pppoe0 >&2 || true; exit 1; }
    sleep 1
done
echo "perf-backend: $BACKEND up: \$(ifconfig pppoe0 | grep '^[[:space:]]*inet ') (if_pppoe clones: \$(ifconfig -g pppoe 2>/dev/null | tr '\n' ' '))"
EOF
