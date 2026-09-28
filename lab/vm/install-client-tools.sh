#!/usr/bin/env bash
# install-client-tools.sh — build this checkout's driver userland on the
# client VM (LAB_SLOT selects which) and install it to /usr/local/sbin:
# pppoectl (sbin/pppoectl), pppoeparms, spppioctl (tools/), and spppauth.
# The functional suite calls /usr/local/sbin/pppoectl and pppoeparms
# directly (tests/functional/lab.py), and /usr/local/sbin/spppauth as the
# positional `spppauth NAME SECRET IFNAME` PAP helper (test_ipv6cp.py) that
# test_pap_live.py compiles from its embedded _SPPPAUTH_C — so that helper,
# not tools/spppauth's flag interface, is what gets installed under that
# name (the accel-ppp integration scripts compile tools/spppauth themselves).
# Built on the client itself — FreeBSD base ships cc + bsd.prog.mk — against
# this repo's sys/net headers, so the ioctl ABI matches the module built
# from the same tree. Called by provision-client.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

# TOOLS_SRC_ROOT: build from another tree (a lab job's exported rev) instead
# of this checkout, so the tools' ioctl ABI matches the module under test.
REPO_ROOT="${TOOLS_SRC_ROOT:-$(cd ../.. && pwd)}"
TOOLS=(sbin/pppoectl tools/pppoeparms tools/spppioctl)
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/spppauth"
python3 - "$REPO_ROOT/tests/functional/test_pap_live.py" > "$STAGE/spppauth/spppauth.c" <<'PY'
import ast, sys
for node in ast.parse(open(sys.argv[1]).read()).body:
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_SPPPAUTH_C" for t in node.targets):
        sys.stdout.write(node.value.value); break
else:
    sys.exit("install-client-tools.sh: _SPPPAUTH_C not found in test_pap_live.py")
PY

{ tar -C "$REPO_ROOT" -cf - sys/net "${TOOLS[@]}"; } \
    | vm_ssh client 'rm -rf /tmp/lab-tools && mkdir -p /tmp/lab-tools && tar -C /tmp/lab-tools -xf -'
tar -C "$STAGE" -cf - spppauth | vm_ssh client 'tar -C /tmp/lab-tools -xf -'

vm_ssh client sh -s <<EOF
set -eu
for d in ${TOOLS[*]}; do
    make -C /tmp/lab-tools/\$d MK_MAN=no WITHOUT_MAN=yes >/dev/null
done
cc -O2 -Wall -I/tmp/lab-tools/sys -o /tmp/lab-tools/spppauth/spppauth /tmp/lab-tools/spppauth/spppauth.c
echo | su -m root -c 'for d in ${TOOLS[*]} spppauth; do install -m 0555 /tmp/lab-tools/\$d/\$(basename \$d) /usr/local/sbin/; done'
rm -rf /tmp/lab-tools
ls -la /usr/local/sbin/pppoectl /usr/local/sbin/pppoeparms /usr/local/sbin/spppauth /usr/local/sbin/spppioctl
rc=0; /usr/local/sbin/spppauth >/dev/null 2>&1 || rc=\$?
[ "\$rc" -eq 2 ] || { echo "spppauth: expected usage exit 2, got \$rc" >&2; exit 1; }
EOF
