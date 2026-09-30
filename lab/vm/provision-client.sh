#!/usr/bin/env bash
# provision-client.sh — installs a lab-built kernel as an alternate boot
# kernel on "client" (KERNEL_VARIANT selects which: default SMP, the release
# kernel; SMPW is the WITNESS/INVARIANTS debug variant built via
# KERNCONF=SMPW in build-kernel.sh), then installs/configures mpd5 as a
# PPPoE client (labels: lab -> accel-ppp, mpdlab -> mpdsrv), plus the
# driver's userland tools. Requires `run.sh build up` and `run.sh client up`
# first. LAB_SLOT=N provisions that slot's client<N>.
#
# KERNEL_SET_URL + KERNEL_SET_SHA256 + KERNEL_BUILD_ID: instead of a
# lab-built kernel, install an official OPNsense kernel set (e.g.
# https://pkg.opnsense.org/FreeBSD:15:amd64/26.7/sets/kernel-26.7.4-amd64.txz)
# as /boot/kernel.<build_id> and assert kern.build_id after the reboot --
# the LAB_CLIENT_IMAGE=15.1 client (README "FreeBSD 15.1 client"). No build
# VM needed. The set is fetched once to $VMHOST:$LAB_DIR/kernel-sets/.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

KERNEL_VARIANT="${KERNEL_VARIANT:-SMP}"
NAME=client
vm_config "$NAME"
remote() { vm_ssh "$NAME" sh -s; }

# write_loader_conf <kernel-dir-name>: boot that /boot/<name> (stock /boot/kernel stays the fallback).
write_loader_conf() {
    remote <<EOF
set -eu
asroot() { echo | su -m root -c "\$*"; }
asroot sysrc -f /boot/loader.conf kernel=$1
# netisr: one bound thread per vCPU, as on the DUT (client-repair.md notes;
# boot-time tunables, so they take effect with the reboot below).
# (sysrc rejects dotted names, so edit loader.conf directly, idempotently.)
asroot "sed -i '' -e '/^net\.isr\.maxthreads=/d' -e '/^net\.isr\.bindthreads=/d' /boot/loader.conf && printf 'net.isr.maxthreads=\"%s\"\nnet.isr.bindthreads=\"1\"\n' $VM_VCPUS >> /boot/loader.conf"
# Pin the rc.conf settings ssh reachability depends on: a power-cut once
# truncated rc.conf to 0 bytes and the VM came back with no sshd/no vtnet0 IP.
# vtnet1 is raw PPPoE only: "up", never DHCP (ifconfig_DEFAULT) on the lab bridge.
asroot sysrc ifconfig_vtnet0=DHCP sshd_enable=YES ifconfig_vtnet1=up
cat /boot/loader.conf
EOF
}

reboot_client() {
    remote <<'EOF'
set -eu
echo | su -m root -c "shutdown -r now" >/dev/null 2>&1 || true
EOF
    echo -n "Waiting for client to come back up "
    sleep 5
    local tries=0
    until vm_ssh "$NAME" true 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 150 ]; then
            echo
            echo "Timed out waiting for client ssh after reboot." >&2
            exit 1
        fi
        echo -n "."
        sleep 2
    done
    echo " up."
}

if [ -z "${KERNEL_SET_URL:-}" ]; then
echo "=== [1/6] $KERNEL_VARIANT kernel -> client:/boot/kernel.$KERNEL_VARIANT ==="
# Compares a sha256 of the build VM's kernel binary against a marker left
# on the client at copy time (existence alone can't detect a rebuild); set
# FORCE=1 to re-copy regardless.
SRC_SHA="$(./run.sh build ssh -- sha256 -q /home/freebsd/if_pppoe-lab/kernel/$KERNEL_VARIANT/kernel)"
[ -n "$SRC_SHA" ] || { echo "could not compute sha256 of the build VM's kernel" >&2; exit 1; }
INSTALLED_SHA="$(remote <<EOF
cat /boot/kernel.$KERNEL_VARIANT/.source-sha256 2>/dev/null || true
EOF
)"
if [ -n "${FORCE:-}" ] || [ "$SRC_SHA" != "$INSTALLED_SHA" ]; then
    echo "source kernel sha256 $SRC_SHA != installed kernel.$KERNEL_VARIANT marker '${INSTALLED_SHA:-<none>}' (or FORCE=1 set); copying."
    # $kernbuilddir/modules on the build VM is already flattened to bare *.ko
    # by build-kernel.sh's collect step, but the tar still lands them under a
    # modules/ subdir here (kernel + modules/ are separate top-level tar
    # entries) — real /boot/kernel[.NAME] dirs are flat, so move them up.
    ./run.sh build ssh -- tar -C /home/freebsd/if_pppoe-lab/kernel/$KERNEL_VARIANT -cf - kernel modules \
        | ./run.sh client ssh -- 'su -m root -c "mkdir -p /boot/kernel.'"$KERNEL_VARIANT"' && tar -C /boot/kernel.'"$KERNEL_VARIANT"' -xf - && if [ -d /boot/kernel.'"$KERNEL_VARIANT"'/modules ]; then mv /boot/kernel.'"$KERNEL_VARIANT"'/modules/*.ko /boot/kernel.'"$KERNEL_VARIANT"'/ && rmdir /boot/kernel.'"$KERNEL_VARIANT"'/modules; fi"'
    # Marker write follows the repo's own established idiom for writing a
    # root-owned file (see the mpd.conf write below): stage in /tmp as the
    # unprivileged user, then `su -m root -c cp` into place.
    printf '%s\n' "$SRC_SHA" | ./run.sh client ssh -- 'cat > /tmp/source-sha256.new'
    remote <<EOF
set -eu
echo | su -m root -c "cp /tmp/source-sha256.new /boot/kernel.$KERNEL_VARIANT/.source-sha256 && rm -f /tmp/source-sha256.new"
EOF
else
    echo "kernel.$KERNEL_VARIANT up to date (sha256 $SRC_SHA), skipping copy. Set FORCE=1 to force a re-copy."
fi
remote <<EOF
set -eu
echo "kernel.$KERNEL_VARIANT: \$(ls /boot/kernel.$KERNEL_VARIANT/*.ko | wc -l | tr -d ' ') modules, kernel binary \$(ls -la /boot/kernel.$KERNEL_VARIANT/kernel | awk '{print \$5}') bytes"
EOF

echo "=== [2/6] /boot/loader.conf: kernel=kernel.$KERNEL_VARIANT (stock /boot/kernel kept as fallback) ==="
write_loader_conf "kernel.$KERNEL_VARIANT"
echo "  (fallback to stock kernel: at the loader prompt — interrupt autoboot,"
echo "  e.g. first 'sysrc -f /boot/loader.conf autoboot_delay=10' — run"
echo "  'unset kernel' then 'boot', or 'boot kernel', per loader(8). Not"
echo "  exercised in this task: NEEDS_VERIFICATION if actually required.)"

ALREADY_IDENT="$(vm_ssh "$NAME" sysctl -n kern.ident 2>/dev/null || true)"
ALREADY_ISR="$(vm_ssh "$NAME" sysctl -n net.isr.maxthreads 2>/dev/null || true)"
case "$ALREADY_IDENT:$ALREADY_ISR" in
    "$KERNEL_VARIANT:$VM_VCPUS")
        echo "=== [3/6] already booted on kernel.$KERNEL_VARIANT (kern.ident=$ALREADY_IDENT), skipping reboot ==="
        ;;
    *)
        echo "=== [3/6] rebooting client onto kernel.$KERNEL_VARIANT ==="
        reboot_client
        ;;
esac

echo "=== asserting the booted kernel matches the $KERNEL_VARIANT build ==="
# Variant-precise: kern.ident IS the kernel ident (e.g. 'SMPW') and is the
# authoritative check; uname -v / kern.version's first line carry the ident
# too, but its position depends on whether newvers included build metadata
# ('... 98ad27755186 SMPW' vs '... 98ad27755186-dirty: <objdir>/sys/SMPW'),
# so they are only checked for the git hash and a variant-suffix match.
# (In the metadata form the ident sits on kern.version's SECOND line — the
# newvers VERSTR is '<info>\n    <user>@<host>:<objdir-path-ends-in-ident>' —
# so the whole banner is matched, not just its first line.)
UNAME_V="$(vm_ssh "$NAME" uname -v)"
KERN_IDENT="$(vm_ssh "$NAME" sysctl -n kern.ident)"
KERN_VERSION="$(vm_ssh "$NAME" sysctl -n kern.version)"
echo "uname -v: $UNAME_V"
echo "kern.ident: $KERN_IDENT"
echo "kern.version tail: $(printf '%s' "$KERN_VERSION" | tail -1)"
case "$KERN_IDENT" in
    "$KERNEL_VARIANT") echo "OK: kern.ident matches the $KERNEL_VARIANT build" ;;
    *) echo "FAIL: kern.ident '$KERN_IDENT' is not '$KERNEL_VARIANT'" >&2; exit 1 ;;
esac
case "$UNAME_V" in
    *98ad27755186*"$KERNEL_VARIANT") echo "OK: uname -v carries the $KERNEL_VARIANT ident and the OPNsense git hash" ;;
    *) echo "FAIL: uname -v does not match expected $KERNEL_VARIANT build identity" >&2; exit 1 ;;
esac
case "$KERN_VERSION" in
    *"$KERNEL_VARIANT") echo "OK: kern.version names the $KERNEL_VARIANT ident" ;;
    *) echo "FAIL: kern.version does not name the $KERNEL_VARIANT ident" >&2; exit 1 ;;
esac
if [ "$KERNEL_VARIANT" != "SMP" ]; then
    # Debug-kernel sanity: a WITNESS/INVARIANTS variant must expose the
    # witness sysctls the release kernel does not have. (debug.locks is a
    # FreeBSD 15+ oid — on 14.3 witness exposes debug.witness.watch/trace.)
    vm_ssh "$NAME" sysctl -n debug.witness.watch debug.witness.trace >/dev/null || {
        echo "FAIL: debug.witness.watch / debug.witness.trace sysctls missing on the $KERNEL_VARIANT kernel" >&2
        exit 1
    }
    echo "OK: debug.witness.watch and debug.witness.trace present"
fi
else
KSET_NAME="kernel.$KERNEL_BUILD_ID"
echo "=== [1/6] OPNsense kernel set $KERNEL_SET_URL -> client:/boot/$KSET_NAME ==="
case "$KERNEL_BUILD_ID" in *[!0-9a-f]*|"") echo "KERNEL_BUILD_ID must be a hex build_id" >&2; exit 1 ;; esac
[ -n "${KERNEL_SET_SHA256:-}" ] || { echo "KERNEL_SET_SHA256 is required with KERNEL_SET_URL" >&2; exit 1; }
R_SET="\$HOME/$LAB_DIR/kernel-sets/$KERNEL_BUILD_ID.txz"
host_ssh bash -s <<EOF
set -euo pipefail
mkdir -p "\$HOME/$LAB_DIR/kernel-sets"
f="$R_SET"
if [ ! -f "\$f" ] || [ "\$(sha256sum "\$f" | awk '{print \$1}')" != "$KERNEL_SET_SHA256" ]; then
    curl -fSL --retry 3 -o "\$f.part" "$KERNEL_SET_URL"
    mv "\$f.part" "\$f"
fi
got=\$(sha256sum "\$f" | awk '{print \$1}')
[ "\$got" = "$KERNEL_SET_SHA256" ] || { echo "kernel set sha256 \$got != $KERNEL_SET_SHA256" >&2; rm -f "\$f"; exit 1; }
echo "kernel set OK: \$got"
EOF
if [ -n "${FORCE:-}" ] || ! vm_ssh "$NAME" "test -f /boot/$KSET_NAME/kernel"; then
    host_ssh "cat $R_SET" | vm_ssh "$NAME" 'cat > /tmp/kset.txz'
    remote <<EOF
set -eu
echo | su -m root -c "rm -rf /tmp/kset /boot/$KSET_NAME && mkdir -p /tmp/kset && tar -xf /tmp/kset.txz -C /tmp/kset && mv /tmp/kset/boot/kernel /boot/$KSET_NAME && rm -rf /tmp/kset /tmp/kset.txz"
EOF
else
    echo "/boot/$KSET_NAME present, skipping copy. Set FORCE=1 to re-copy."
fi

echo "=== [2/6] /boot/loader.conf: kernel=$KSET_NAME (stock /boot/kernel kept as fallback) ==="
write_loader_conf "$KSET_NAME"

if [ "$(vm_ssh "$NAME" 'echo "$(sysctl -n kern.build_id):$(sysctl -n net.isr.maxthreads)"' 2>/dev/null || true)" = "$KERNEL_BUILD_ID:$VM_VCPUS" ]; then
    echo "=== [3/6] already booted on $KSET_NAME, skipping reboot ==="
else
    echo "=== [3/6] rebooting client onto $KSET_NAME ==="
    reboot_client
fi
echo "=== asserting the booted kernel is build_id $KERNEL_BUILD_ID ==="
vm_ssh "$NAME" 'echo "uname -v: $(uname -v)"; echo "kern.bootfile: $(sysctl -n kern.bootfile)"'
HAVE_BID="$(vm_ssh "$NAME" sysctl -n kern.build_id)"
[ "$HAVE_BID" = "$KERNEL_BUILD_ID" ] || { echo "FAIL: kern.build_id $HAVE_BID != $KERNEL_BUILD_ID" >&2; exit 1; }
echo "OK: kern.build_id = $HAVE_BID"
fi

echo "=== [4/6] pkg install mpd5 iperf3 ==="
remote <<'EOF'
set -eu
asroot() { echo | su -m root -c "$*"; }
asroot pkg install -y mpd5 iperf3
EOF

echo "=== [5/6] writing mpd.conf (labels: lab -> accel-ppp, mpdlab -> mpdsrv) ==="
# No `set auth authname/password`: there is no fixed lab account.  Whatever
# dials (the functional suite, perf-backend.sh, verify-lab.sh) generates one
# per run and writes its own password-bearing mpd.conf onto a tmpfs mounted
# over /usr/local/etc/mpd5 for that run (lab-creds.sh, tests/functional/
# labcreds.py); this on-disk file stays secret-free and cannot authenticate.
MPD_CONF='startup:

default:
	load lab

# Dials the isp-netns accel-ppp server (task 2), service-name "lab".
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
	set pppoe iface vtnet1
	set pppoe service "lab"
	open

# Dials the mpdsrv VMs mpd5 server, service-name "mpdlab", requesting the
# RFC4638 jumbo PPPoE payload (1500 vs the usual 1492).
mpdlab:
	create bundle static wan
	set iface name pppoe0
	set ipcp ranges 0.0.0.0/0 0.0.0.0/0
	set ipcp enable req-pri-dns

	create link static wan pppoe
	set link action bundle wan
	set link keep-alive 10 60
	set link disable chap pap
	set link accept chap pap eap
	# mru 1501, not 1500: mpd5 rejects "set pppoe max-payload" at config
	# parse time unless it is strictly LESS THAN the link mru (empirically
	# verified: with mru 1500, max-payload 1499 and 1500 both parse-error
	# "not in a range of 1492..1500"; 1498 parses fine; mru 1501 is the
	# minimal mru that allows the RFC4638-standard value of 1500).
	set link mtu 1500
	set link mru 1501
	set pppoe iface vtnet1
	set pppoe service "mpdlab"
	set pppoe max-payload 1500
	open
'
printf '%s\n' "$MPD_CONF" | ./run.sh client ssh -- 'cat > /tmp/mpd.conf.new'
remote <<'EOF'
set -eu
asroot() { echo | su -m root -c "$*"; }
echo | su -m root -c "cp /tmp/mpd.conf.new /usr/local/etc/mpd5/mpd.conf && rm -f /tmp/mpd.conf.new"
asroot sysrc mpd_enable=YES
asroot service mpd5 restart
sleep 2
cat /usr/local/etc/mpd5/mpd.conf
EOF

echo "=== keep devd/rc autoconfiguration off the test suite's interfaces ==="
# Mirrors tests/functional/lab.py RC_AUTOCONF_EXEMPT (conftest applies the
# same list per pytest session): without NOAUTO, devd's pccard_ether brings
# every fresh pppoe0 clone up and DHCPs it behind the tests' backs, and its
# DETACH-time ifconfig autoloads if_pppoe right after a kldunload.
remote <<'EOF'
set -eu
echo | su -m root -c "sysrc ifconfig_pppoe0=NOAUTO ifconfig_pppoe1=NOAUTO \
    ifconfig_pppoe2=NOAUTO ifconfig_pppoe3=NOAUTO \
    ifconfig_epair76a=NOAUTO ifconfig_epair76b=NOAUTO ifconfig_bridge76=NOAUTO \
    ifconfig_epair77a=NOAUTO ifconfig_epair77b=NOAUTO ifconfig_bridge77=NOAUTO \
    ifconfig_vlan77=NOAUTO ifconfig_vlan78=NOAUTO \
    ifconfig_epair79a=NOAUTO ifconfig_epair79b=NOAUTO"
EOF

echo "=== [6/6] pppoectl + test tools -> /usr/local/sbin ==="
./install-client-tools.sh

echo "=== provision-client.sh done ==="
