#!/bin/sh
# Refresh the pinned opnsense/plugins Mk/Templates/Scripts copy (see
# plugin/Mk/VENDORED.md). Usage: vendor-mk.sh <opnsense-plugins-checkout>.
# Copies only; never commits. Update VENDORED.md's pinned-commit line by hand.
set -eu

usage() {
    echo "usage: $0 <path-to-opnsense-plugins-checkout>" >&2
    exit 1
}

[ $# -eq 1 ] || usage
SRC=$1
if [ ! -d "$SRC/Mk" ] || [ ! -d "$SRC/Templates" ] || [ ! -f "$SRC/Scripts/version.sh" ]; then
    echo "$0: '$SRC' does not look like an opnsense/plugins checkout (missing Mk/, Templates/ or Scripts/version.sh)" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DEST_MK="$REPO_ROOT/plugin/Mk"
DEST_TEMPLATES="$REPO_ROOT/plugin/Templates"
DEST_SCRIPTS="$REPO_ROOT/plugin/Scripts"

if [ -d "$SRC/.git" ]; then
    SHA=$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || echo unknown)
    WHEN=$(cd "$SRC" && git log -1 --format='%ci' 2>/dev/null || echo unknown)
    SUBJECT=$(cd "$SRC" && git log -1 --format='%s' 2>/dev/null || echo unknown)
else
    SHA=unknown
    WHEN=unknown
    SUBJECT=unknown
fi

echo ">>> Vendoring Mk/*.mk (excluding devel.mk) from $SRC"
mkdir -p "$DEST_MK"
for f in "$SRC"/Mk/*.mk; do
    base=$(basename -- "$f")
    [ "$base" = "devel.mk" ] && { echo "    skip $base (see plugin/Mk/VENDORED.md)"; continue; }
    cp -f -- "$f" "$DEST_MK/$base"
    echo "    copied $base"
done

echo ">>> Vendoring Templates/* from $SRC"
mkdir -p "$DEST_TEMPLATES"
for f in "$SRC"/Templates/*; do
    [ -f "$f" ] || continue
    base=$(basename -- "$f")
    cp -f -- "$f" "$DEST_TEMPLATES/$base"
    echo "    copied $base"
done

echo ">>> Vendoring Scripts/version.sh from $SRC"
mkdir -p "$DEST_SCRIPTS"
cp -f -- "$SRC/Scripts/version.sh" "$DEST_SCRIPTS/version.sh"
chmod +x "$DEST_SCRIPTS/version.sh"

cat <<EOF

>>> Done. Source commit: $SHA
    ($WHEN, "$SUBJECT")

Next steps:
  1. g -C "$REPO_ROOT" diff -- plugin/Mk plugin/Templates plugin/Scripts
  2. Review the diff for Makefile-logic changes (not just cosmetics).
  3. Update the "Pinned commit" line in plugin/Mk/VENDORED.md by hand.
  4. Re-run plugin/build/build-plugin.sh --dry-run to sanity-check the
     vendored make logic still evaluates cleanly against our Makefile.
EOF
