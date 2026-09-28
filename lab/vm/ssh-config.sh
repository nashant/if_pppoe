#!/usr/bin/env bash
# ssh-config.sh — print one `Host lab-<name>` block per lab VM, so tests/perf's
# ssh_collectors.configure() (a bare `ssh host cmd` argv, no common.sh) can
# reach them via $VMHOST ProxyJump like vm_ssh() does. See docs/PERF-FWD-DESIGN.md.
# Usage: ./ssh-config.sh > /path/to/config ; run_matrix.py --ssh-config /path/to/config --dut lab-client ...
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

for name in build client lan mpdsrv isp; do
    vm_config "$name"
    cat <<EOF
Host lab-$name
    HostName 127.0.0.1
    Port $VM_SSH_PORT
    User $VM_SSH_USER
    ProxyJump $VMHOST
    BatchMode yes
    ConnectTimeout 10
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

EOF
done
