#!/usr/bin/env bash
# build-kernel.sh setup|start|status|collect — drives the OPNsense 25.7.11
# kernel build inside the "build" VM, or with LAB_SERIES=26.7 the 26.7.4
# (FreeBSD 15.1) kernel inside "build15". KERNCONF selects the kernel config
# (default SMP, the release kernel; SMPW is the locally-authored
# WITNESS/INVARIANTS debug variant). `start` nohup's the actual
# buildkernel so no ssh session sits open for the ~30-90 min build; poll
# with `status`, then `collect` once it reports done.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./common.sh

# LAB_SERIES picks the OPNsense series (src tag == the published kernel set's,
# as in .github/versions.json). HOST_KDIR keeps each series' collected
# kernels apart on the lab host; 25.7's stays the original kernel/.
LAB_SERIES="${LAB_SERIES:-25.7}"
case "$LAB_SERIES" in
    25.7) NAME=build;   SRC_TAG="25.7.11"; FBSD_REL="14.3"; HOST_KDIR="kernel" ;;
    26.7) NAME=build15; SRC_TAG="26.7.4";  FBSD_REL="15.1"; HOST_KDIR="kernel-26.7" ;;
    *) echo "LAB_SERIES must be 25.7 or 26.7 (got '$LAB_SERIES')" >&2; exit 1 ;;
esac
vm_config "$NAME"
SRC_REPO="https://github.com/opnsense/src"
SMP_URL="https://raw.githubusercontent.com/opnsense/tools/${SRC_TAG}/config/${LAB_SERIES}/SMP"
# KERNCONF=SMP (default) builds the release kernel. KERNCONF=SMPW authors a
# debug variant config locally (see cmd_setup): there is no public
# config/25.7/DEBUG to copy, and no DEADLKRES (its periodic lock-order
# diagnostics would pollute witness-noise triage) and no bare KDB (KDB alone
# stalls at db> and kills the serial panic oracle — KDB_TRACE only, see D023).
KERNCONF="${KERNCONF:-SMP}"

ACTION="${1:-}"
[ -n "$ACTION" ] || { echo "usage: $0 setup|start|status|collect" >&2; exit 1; }

# FreeBSD base has no bash, only /bin/sh (ash) — all remote heredocs below
# must stay POSIX sh (no pipefail, no disown, no bashisms).
remote() { vm_ssh "$NAME" sh -s; }

cmd_setup() {
    # The INVARIANTS-workaround patch is fetched into the build VM before the
    # heredoc (patch(1) reads it from a file, and setup's heredoc is
    # unquoted so embedding it inline would need escaping).
    PATCH_FILE="$SCRIPT_DIR/patches/smpw-rss-invariants.patch"
    if [ -f "$PATCH_FILE" ]; then
        vm_ssh "$NAME" 'cat > /tmp/smpw-rss-invariants.patch' < "$PATCH_FILE"
    fi
    # No sudo/doas in the base FreeBSD image; root has no password, so
    # `echo | su -m root -c ...` is the only privileged-command path here.
    remote <<EOF
set -eu
mkdir -p "\$HOME/if_pppoe-lab"
asroot() { echo | su -m root -c "\$*"; }
asroot pkg bootstrap -y >/dev/null 2>&1 || true
asroot pkg install -y git

cd "\$HOME/if_pppoe-lab"
if [ -d src/.git ]; then
    echo "src already cloned, skipping clone."
else
    git clone --branch "$SRC_TAG" --depth 1 "$SRC_REPO" src
fi

cd src
git rev-parse HEAD
fetch -o /tmp/SMP.config "$SMP_URL"
sed -i '' '/%%DEBUG%%/d' /tmp/SMP.config
mv /tmp/SMP.config sys/amd64/conf/SMP
grep -c DEBUG sys/amd64/conf/SMP || true
if [ "$KERNCONF" != "SMP" ]; then
    # Author sys/amd64/conf/$KERNCONF (e.g. SMPW) locally from the pristine
    # SMP config: replace the bare %%DEBUG%% placeholder line with the debug
    # options block and set ident to $KERNCONF (kern.version/uname -v carry
    # the ident, which provision-client.sh's boot assertion relies on).
    fetch -o /tmp/SMP.raw "$SMP_URL"
    : > sys/amd64/conf/$KERNCONF
    while IFS= read -r line; do
        case "\$line" in
        %%DEBUG%%)
            printf 'options\t%s\n' WITNESS WITNESS_SKIPSPIN INVARIANTS \
                INVARIANT_SUPPORT DIAGNOSTIC KDB KDB_TRACE \
                >> sys/amd64/conf/$KERNCONF
            ;;
        ident*)
            printf 'ident\t\t%s\n' "$KERNCONF" >> sys/amd64/conf/$KERNCONF
            ;;
        *)
            printf '%s\n' "\$line" >> sys/amd64/conf/$KERNCONF
            ;;
        esac
    done < /tmp/SMP.raw
    rm -f /tmp/SMP.raw
    # INVARIANTS boot panic workaround (see lab/vm/patches/README.md):
    # guard the RSS-only intr_direct sysctl handlers in ip_input.c /
    # ip6_input.c; without it the $KERNCONF kernel panics on every boot
    # (netisr_getqlimit/netisr_setqlimit KASSERT on the unregistered
    # ip_direct protocol, which only registers when rss_get_enabled()).
    # Idempotent: only applied while the marker comment is absent.
    if ! grep -q 'Lab SMPW (INVARIANTS) workaround' \
            sys/netinet/ip_input.c sys/netinet6/ip6_input.c; then
        patch -d . -p1 --quiet < /tmp/smpw-rss-invariants.patch
        echo "applied smpw-rss-invariants.patch"
    fi
    echo "--- sys/amd64/conf/$KERNCONF head ---"
    sed -n '1,18p' sys/amd64/conf/$KERNCONF
fi
echo "setup done."
EOF
}

cmd_start() {
    remote <<EOF
set -eu
if pgrep -f 'make .*buildkernel' >/dev/null 2>&1; then
    echo "a build is already running (pgrep matched make .*buildkernel); refusing to start a second one" >&2
    exit 1
fi
cd "\$HOME/if_pppoe-lab/src"
mkdir -p "\$HOME/if_pppoe-lab/obj"
rm -f "\$HOME/if_pppoe-lab/build.log" "\$HOME/if_pppoe-lab/build.exit"
nohup env MAKEOBJDIRPREFIX="\$HOME/if_pppoe-lab/obj" \
    sh -c 'make -j$VM_VCPUS buildkernel KERNCONF=$KERNCONF; echo \$? > "\$HOME/if_pppoe-lab/build.exit"' \
    > "\$HOME/if_pppoe-lab/build.log" 2>&1 < /dev/null &
echo "started pid \$!"
EOF
}

cmd_status() {
    echo "polling status (KERNCONF=$KERNCONF)"
    remote <<'EOF'
set -eu
cd "$HOME/if_pppoe-lab"
if [ -f build.exit ]; then
    code="$(cat build.exit)"
    echo "DONE exit=$code"
else
    if pgrep -f 'make .*buildkernel' >/dev/null 2>&1; then
        echo "RUNNING"
    else
        echo "NOT-RUNNING (no build.exit yet, no make process found)"
    fi
fi
echo "--- tail build.log ---"
tail -n 20 build.log 2>/dev/null || echo "(no log yet)"
EOF
}

cmd_collect() {
    # KERNCONF is passed as a positional arg ($1) so the heredoc can stay
    # fully quoted.
    vm_ssh "$NAME" sh -s "$KERNCONF" "$FBSD_REL" <<'EOF'
set -eu
KERNCONF="$1"
FBSD_REL="$2"
cd "$HOME/if_pppoe-lab"
[ -f build.exit ] && [ "$(cat build.exit)" = "0" ] || { echo "build not successfully finished" >&2; exit 1; }

kernbuilddir="$(find "$HOME/if_pppoe-lab/obj" -type d -name "$KERNCONF" -path '*/sys/*' | head -1)"
[ -n "$kernbuilddir" ] || { echo "could not locate KERNBUILDDIR under obj/" >&2; exit 1; }

rm -rf "$HOME/if_pppoe-lab/kernel/$KERNCONF"
mkdir -p "$HOME/if_pppoe-lab/kernel/$KERNCONF/modules"
cp -a "$kernbuilddir/kernel" "$HOME/if_pppoe-lab/kernel/$KERNCONF/kernel"
# $kernbuilddir/modules is FreeBSD's MAKEOBJDIRPREFIX-mirrored obj tree, not a
# flat module directory: each .ko lives many directories deep (mirroring the
# full source path), and the tree is present twice over (an inner "modules/"
# re-mirror duplicates every .ko once more) - real /boot/kernel[.NAME]
# directories are flat (kernel + bare *.ko), so flatten by basename here
# rather than shipping ~4GB of duplicated obj-tree scaffolding as "modules".
# Verified no basename collisions across the full 848-module SMP build.
find "$kernbuilddir/modules" -name '*.ko' -exec cp -a {} "$HOME/if_pppoe-lab/kernel/$KERNCONF/modules/" \;
echo "$kernbuilddir" > "$HOME/if_pppoe-lab/kernel/$KERNCONF/KERNBUILDDIR"

echo "--- newvers.sh BRANCH/REVISION ---"
grep -E '^(BRANCH|REVISION)=' src/sys/conf/newvers.sh

echo "--- ls -la kernel/$KERNCONF ---"
ls -la "$HOME/if_pppoe-lab/kernel/$KERNCONF/"

echo "--- strings kernel | grep FreeBSD $FBSD_REL ---"
strings "$HOME/if_pppoe-lab/kernel/$KERNCONF/kernel" | grep -m1 "FreeBSD $FBSD_REL"
echo "--- strings kernel | grep kern ident ---"
strings "$HOME/if_pppoe-lab/kernel/$KERNCONF/kernel" | grep -m1 "$KERNCONF" || true
EOF

    # Also land the artifacts on the lab host itself, not just inside the
    # ephemeral VM's guest disk (task-4-review Important #1) — tar over the
    # ssh hostfwd, guest -> host, so a later task can retrieve/flash them
    # without booting the build VM.
    echo "--- copying kernel/$KERNCONF to $VMHOST:$LAB_DIR/$HOST_KDIR/$KERNCONF ---"
    host_ssh mkdir -p "\$HOME/$LAB_DIR/$HOST_KDIR"
    vm_ssh "$NAME" tar -C /home/freebsd/if_pppoe-lab/kernel -cf - "$KERNCONF" \
        | host_ssh tar -C "\$HOME/$LAB_DIR/$HOST_KDIR" -xf -
    host_ssh ls -la "\$HOME/$LAB_DIR/$HOST_KDIR/$KERNCONF"
}

case "$ACTION" in
    setup)   cmd_setup ;;
    start)   cmd_start ;;
    status)  cmd_status ;;
    collect) cmd_collect ;;
    *) echo "usage: $0 setup|start|status|collect" >&2; exit 1 ;;
esac
