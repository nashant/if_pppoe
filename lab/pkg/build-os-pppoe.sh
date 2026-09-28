#!/bin/sh
# build-os-pppoe.sh — build the OPNsense plugin package for the if_pppoe
# driver on the TARGET FreeBSD 14.3 machine (OPNsense 25.7 base, pkg 2.7+).
#
# usage (on the OPNsense/FreeBSD host, as root):
#   sh build-os-pppoe.sh [ /path/to/if_pppoe.ko ]
#     default .ko: /boot/modules/if_pppoe.ko if present, else
#     /home/<user>/if_pppoe-lab/if_pppoe.ko (lab deploy path)
#
# produces: os-pppoe-<version>.pkg in the current directory, installable
# with  `pkg add -f ./os-pppoe-<version>.pkg`.
#
# NOTE: the .ko must be the build produced against the target machine's
# kernel build dir (lab/vm/build-module.sh with KERNEL_VARIANT matching the
# installed OPNsense kernel — SMP for OPNsense 25.7's GENERIC+RSS+VIMAGE
# build).  A release-built kmod cannot load on a debug (SMPW) kernel and
# vice versa.
set -eu

# shellcheck disable=SC1091 # dynamic path, present in any checkout of this repo
. "$(dirname "$0")/../../plugin/maintainer.mk"

VERSION="0.1.0"
NAME="os-pppoe"
PKGDIR="$(mktemp -d "${TMPDIR:-/tmp}/pkgbuild.XXXXXX")"
trap 'rm -rf "$PKGDIR"' EXIT
mkdir -p "$PKGDIR/root/boot/modules" \
         "$PKGDIR/root/usr/local/etc/rc.d" \
         "$PKGDIR/manifest"

# ---- locate the module -----------------------------------------------------
KO="${1:-}"
if [ -z "$KO" ]; then
    for _c in /boot/modules/if_pppoe.ko \
              "$HOME/if_pppoe-lab/if_pppoe.ko"; do
        if [ -f "$_c" ]; then KO="$_c"; break; fi
    done
fi
[ -n "$KO" ] && [ -f "$KO" ] || { echo "if_pppoe.ko not found" >&2; exit 1; }
echo "using module: $KO"

# ---- locate the control tool (pppoectl, verbatim NetBSD port) -------------
POCTL="${2:-}"
if [ -z "$POCTL" ]; then
    for _c in /usr/local/sbin/pppoectl \
              "$HOME/if_pppoe-lab/pppoectl"; do
        if [ -f "$_c" ]; then POCTL="$_c"; break; fi
    done
fi
if [ -n "$POCTL" ] && [ -f "$POCTL" ]; then
    HAVE_POCTL=1
    echo "using control tool: $POCTL"
else
    HAVE_POCTL=0
    echo "pppoectl not found -- package will ship module + service only" >&2
fi

# ---- module + rc.d script --------------------------------------------------
cp "$KO" "$PKGDIR/root/boot/modules/if_pppoe.ko"
if [ "$HAVE_POCTL" = 1 ]; then
    mkdir -p "$PKGDIR/root/usr/local/sbin"
    cp "$POCTL" "$PKGDIR/root/usr/local/sbin/pppoectl"
    chmod 555 "$PKGDIR/root/usr/local/sbin/pppoectl"
fi

# The rc.d script is shipped next to this script by the repo (lab/pkg/).
RC_SRC="$(dirname "$0")/if_pppoe.rc.d"
[ -f "$RC_SRC" ] || { echo "if_pppoe.rc.d not found next to $0" >&2; exit 1; }
cp "$RC_SRC" "$PKGDIR/root/usr/local/etc/rc.d/if_pppoe"
chmod 555 "$PKGDIR/root/usr/local/etc/rc.d/if_pppoe"

# ---- hashes for the manifest ----------------------------------------------
KO_HASH="$(sha256 -q "$PKGDIR/root/boot/modules/if_pppoe.ko")"
RC_HASH="$(sha256 -q "$PKGDIR/root/usr/local/etc/rc.d/if_pppoe")"

FILES_FRAGMENT="\"/boot/modules/if_pppoe.ko\": \"${KO_HASH}\",
        \"/usr/local/etc/rc.d/if_pppoe\": \"${RC_HASH}\""
if [ "$HAVE_POCTL" = 1 ]; then
    POCTL_HASH="$(sha256 -q "$PKGDIR/root/usr/local/sbin/pppoectl")"
    FILES_FRAGMENT="${FILES_FRAGMENT},
        \"/usr/local/sbin/pppoectl\": \"${POCTL_HASH}\""
fi

# ---- +MANIFEST (pkg manifest mode; ABI must match the OPNsense base) ------
cat > "$PKGDIR/manifest/+MANIFEST" <<EOF
{
    "abi": "FreeBSD:14:*",
    "arch": "freebsd:14:x86:64",
    "name": "${NAME}",
    "version": "${VERSION}",
    "origin": "opnsense/${NAME}",
    "comment": "In-kernel PPPoE client driver for OPNsense (OpenBSD/NetBSD port)",
    "desc": "Loads the if_pppoe kernel module: a netgraph-free, pfil/epoch based\\nPPPoE client with in-kernel sppp control plane (replaces userland mpd5).\\n\\nActivate:      service if_pppoe start\\nDeactivate:    service if_pppoe stop   (destroyes pppoeN clones with PADT, then unloads)\\nStatus:        service if_pppoe status\\nAuto-load at boot: sysrc if_pppoe_enable=YES   (default YES)\\n\\nDial a session after activation:\\n  ifconfig pppoe0 create\\n  pppoectl -e <parent-iface> pppoe0\\n  pppoectl pppoe0 myauthproto=pap myauthname=USER myauthsecret=PASS\\n  pppoectl pppoe0 query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1\\n  ifconfig pppoe0 up\\n\\nObservability: sysctl net.pppoe (counters, net.pppoe.parent_altq), dmesg\\n(link-state changes, IPCP signals, one-shot ALTQ warning).",
    "maintainer": "${MAINTAINER}",
    "www": "https://github.com/nashant/if_pppoe",
    "prefix": "/usr/local",
    "categories": ["drivers"],
    "licenselogic": "single",
    "licenses": ["BSD2CLAUSE"],
    "files": {
        ${FILES_FRAGMENT}
    },
    "scripts": {
        "pre-deinstall": {
            "script": "/usr/local/etc/rc.d/if_pppoe stop 2>/dev/null || true"
        },
        "post-install": {
            "script": "echo 'os-pppoe installed. Activate: service if_pppoe start'; echo 'Auto-load at boot: sysrc if_pppoe_enable=YES (default)'"
        }
    }
}
EOF

# ---- create ----------------------------------------------------------------
pkg create -m "$PKGDIR/manifest" -r "$PKGDIR/root" -o "$PKGDIR/out"
OUT="$(ls "$PKGDIR/out"/*.pkg | head -1)"
cp "$OUT" "$PWD/"
echo "created: $PWD/$(basename "$OUT")"