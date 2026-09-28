#!/usr/bin/env bash
# throttle.sh — CPU-throttle a lab VM's qemu process, to emulate a J4105-class
# CPU budget for the DUT. Two composable knobs:
#   width:  pin ALL qemu threads to a cpulist (e.g. 0,1,2,3 = 4 threads on 4
#           distinct cores) — caps how many cores the DUT can use at once
#   speed:  optional aggregate quota via a systemd CPUQuota service — caps how
#           fast the DUT's cores run in total. ("4 slow cores" J4105 proxy =
#           width 0,1,2,3 + quota ~180: 4 J4105 cores are roughly 1.6-2.0
#           i7-core equivalents.)
# SAFETY: qemu is moved OUT of the unit's cgroup BEFORE the unit is ever
# stopped — stopping a unit SIGTERMs its cgroup contents and would kill the
# VM (this killed a router VM once; do not reorder).
# Usage: ./throttle.sh <name> off
#        ./throttle.sh <name> 0               # 1-core pin, no quota
#        ./throttle.sh <name> 0,1,2,3 180     # 4-core pin at 180% aggregate
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

vm_config "$1"; NAME="$VM_NAME"; TARGET="$2"; QUOTA_PCT="${3:-}"
UNIT="lab-throttle-$NAME"
CGDIR="/sys/fs/cgroup/system.slice/${UNIT}.service"
host_ssh bash -s <<EOF
set -euo pipefail
pid=\$(sudo cat "\$HOME/$LAB_DIR/$VM_RUN_DIR/$NAME.pid")
if [ "$TARGET" = "off" ]; then
    sudo sh -c "echo \$pid > /sys/fs/cgroup/system.slice/cgroup.procs" 2>/dev/null || true
    sudo systemctl stop "$UNIT.service" 2>/dev/null || true
    sudo taskset -a -pc 0-11 \$pid >/dev/null
    echo "throttle: off for $NAME (pid \$pid, affinity 0-11)"
    exit 0
fi
if [ -n "$QUOTA_PCT" ]; then
    sudo sh -c "echo \$pid > /sys/fs/cgroup/system.slice/cgroup.procs" 2>/dev/null || true
    sudo systemctl stop "$UNIT.service" 2>/dev/null || true
    sudo systemd-run --unit="$UNIT" --property=CPUQuota="${QUOTA_PCT}%" sleep infinity >/dev/null
    for i in \$(seq 1 20); do
        [ -d "$CGDIR" ] && break
        sleep 0.5
    done
    sudo sh -c "echo \$pid > $CGDIR/cgroup.procs"
    echo "throttle: $NAME (pid \$pid) pinned to [$TARGET] with ${QUOTA_PCT}% aggregate CPU quota"
else
    sudo taskset -a -pc "$TARGET" \$pid >/dev/null
    echo "throttle: $NAME (pid \$pid) pinned to [$TARGET] (no quota)"
fi
EOF