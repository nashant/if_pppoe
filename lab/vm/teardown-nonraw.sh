#!/usr/bin/env bash
# teardown-nonraw.sh — best-effort: stop mpd5, destroy any pppoe0/ng0, and
# kldunload if_pppoe on the client VM, before measuring the "raw" baseline
# (otherwise every raw frame still passes if_pppoe's or ng_ether's pfil
# hook, biasing the PPPoE/raw ratio in PPPoE's favour -- final-review
# minor). Real enforcement is validate_backend_preflight("raw", ...); this
# is the cleanup that should make that preflight pass.
# Usage (from anywhere with ssh to VMHOST): ./teardown-nonraw.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

vm_ssh client sh -s <<'EOF'   # FreeBSD guest: no bash
set -u
asroot() { echo | su -m root -c "$*"; }
asroot 'service mpd5 stop' 2>/dev/null || true
for ifc in pppoe0 pppoe1 pppoe2 pppoe3 ng0; do
    asroot "ifconfig $ifc destroy" 2>/dev/null || true
done
asroot 'kldunload if_pppoe' 2>/dev/null || true
echo "teardown-nonraw: mpd5 stopped, pppoe0-3/ng0 destroyed, if_pppoe unloaded (best-effort)"
ifconfig -l
kldstat -q -m if_pppoe && echo "note: if_pppoe still loaded (compiled into kernel, or busy)" || true
EOF
echo "teardown-nonraw.sh: done"
