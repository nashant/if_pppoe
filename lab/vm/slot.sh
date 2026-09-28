#!/usr/bin/env bash
# slot.sh — lab slot leases on $VMHOST, so concurrent verifiers never share
# a slot's client/isp/mpdsrv VMs.
#
#   ./slot.sh acquire [--wait SECS] [--owner TEXT]   # stdout: the slot number
#   ./slot.sh renew <N>                              # heartbeat (call < TTL apart)
#   ./slot.sh release <N>
#   ./slot.sh hold <N> <reason>                      # never-expiring lease (manual)
#   ./slot.sh status
#
# A lease is the directory $LAB_DIR/leases/slot<N> on $VMHOST: `mkdir` is
# atomic, so exactly one acquirer wins. Inside: `owner` (who/pid/host/time)
# and `heartbeat` (mtime = last acquire/renew). A lease whose heartbeat is
# older than LAB_LEASE_TTL seconds (default 3600) is stale and is reclaimed
# by the next acquire: renamed away first (rename is atomic too, so two
# reclaimers cannot both win), then re-created. A `hold` lease has a `pinned`
# file and is never reclaimed — release it explicitly.
#
# LAB_SLOTS (default "1 2") lists the slots that exist; acquire tries them in
# order. Env: VMHOST, LAB_DIR, LAB_LEASE_TTL, LAB_SLOTS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./common.sh

LAB_SLOTS="${LAB_SLOTS:-1 2}"
LAB_LEASE_TTL="${LAB_LEASE_TTL:-3600}"

# $0 no longer resolves once relative (see SCRIPT_DIR above): read the
# comment block from the script's own known, absolute path instead.
usage() { sed -n '5,9p' "$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")" | sed 's/^# \{0,1\}//' >&2; exit 1; }

# remote <action> <slot> <owner>: the lease logic runs on $VMHOST in one ssh
# round trip, so the check-and-mkdir is local to the lease filesystem.
remote() {
    local action="$1" slot="${2:-}" owner="${3:-}" b64
    b64="$(printf '%s' "$owner" | base64 -w0)"
    host_ssh bash -s <<EOF
set -euo pipefail
L="\$HOME/$LAB_DIR/leases"; mkdir -p "\$L"
ttl=$LAB_LEASE_TTL; now=\$(date +%s)
owner="\$(echo "$b64" | base64 -d)"
age() { echo \$(( now - \$(stat -c %Y "\$1/heartbeat" 2>/dev/null || stat -c %Y "\$1") )); }
stale() { [ ! -f "\$1/pinned" ] && [ "\$(age "\$1")" -gt "\$ttl" ]; }
take() {  # take <slot>: 0 if we now own it
    local d="\$L/slot\$1"
    if [ -d "\$d" ] && stale "\$d"; then
        mv "\$d" "\$d.stale.\$\$" 2>/dev/null && {
            echo "slot.sh: reclaimed stale lease on slot \$1 (\$(head -1 "\$d.stale.\$\$/owner" 2>/dev/null))" >&2
            rm -rf "\$d.stale.\$\$"; }
    fi
    mkdir "\$d" 2>/dev/null || return 1
    printf '%s\n' "\$owner" "acquired \$(date -u +%FT%TZ)" > "\$d/owner"
    touch "\$d/heartbeat"
}
case "$action" in
    acquire)
        for s in $LAB_SLOTS; do
            if take "\$s"; then echo "\$s"; exit 0; fi
        done
        exit 3 ;;
    renew)
        d="\$L/slot$slot"
        [ -d "\$d" ] || { echo "slot.sh: no lease on slot $slot (expired and reclaimed?)" >&2; exit 1; }
        touch "\$d/heartbeat"; echo "slot $slot renewed" >&2 ;;
    release)
        d="\$L/slot$slot"
        if [ -d "\$d" ]; then mv "\$d" "\$d.rel.\$\$" && rm -rf "\$d.rel.\$\$"; echo "slot $slot released" >&2
        else echo "slot $slot was not leased" >&2; fi ;;
    hold)
        take "$slot" || { echo "slot.sh: slot $slot is leased: \$(head -1 "\$L/slot$slot/owner")" >&2; exit 1; }
        touch "\$L/slot$slot/pinned"; echo "slot $slot held (pinned)" >&2 ;;
    status)
        for s in $LAB_SLOTS; do
            d="\$L/slot\$s"
            if [ ! -d "\$d" ]; then echo "slot \$s: free"; continue; fi
            a=\$(age "\$d"); st=""
            if [ -f "\$d/pinned" ]; then st=" PINNED"; elif [ "\$a" -gt "\$ttl" ]; then st=" STALE(>\${ttl}s, reclaimable)"; fi
            echo "slot \$s: leased by \$(head -1 "\$d/owner") | \$(sed -n 2p "\$d/owner") | heartbeat \${a}s ago\$st"
        done ;;
esac
EOF
}

[ $# -ge 1 ] || usage
action="$1"; shift
case "$action" in
    acquire)
        wait_s=0; owner="${USER:-?}@$(hostname -s) pid=$PPID ${LAB_LEASE_OWNER:-}"
        while [ $# -gt 0 ]; do
            case "$1" in
                --wait)  wait_s="$2"; shift 2 ;;
                --owner) owner="$2 (${USER:-?}@$(hostname -s) pid=$PPID)"; shift 2 ;;
                *) usage ;;
            esac
        done
        deadline=$(( $(date +%s) + wait_s ))
        while :; do
            rc=0; slot="$(remote acquire "" "$owner")" || rc=$?
            if [ "$rc" -eq 0 ]; then echo "$slot"; exit 0; fi
            [ "$rc" -eq 3 ] || { echo "slot.sh: acquire failed (rc=$rc)" >&2; exit "$rc"; }
            if [ "$(date +%s)" -ge "$deadline" ]; then
                echo "slot.sh: no free slot among '$LAB_SLOTS' (waited ${wait_s}s)" >&2
                remote status >&2
                exit 1
            fi
            sleep 15
        done ;;
    renew|release) [ $# -eq 1 ] || usage; remote "$action" "$1" ;;
    hold)    [ $# -eq 2 ] || usage; remote hold "$1" "HOLD: $2 (${USER:-?}@$(hostname -s))" ;;
    status)  remote status ;;
    *)       usage ;;
esac
