#!/bin/sh
# lint-shell.sh [ROOT] -- shellcheck every shell script in the tree.
# STRICT_DIRS fail on any finding; everything else fails only on
# error-severity findings (warnings printed as advisories) so CI can gate
# before the legacy lab/plugin scripts are cleaned up.
set -eu

ROOT=$(cd "${1:-$(dirname "$0")/../..}" && pwd)
STRICT_DIRS=".github/scripts"
# docs/ holds verbatim reference snippets, not shipped scripts.
SKIP_DIRS="docs"
command -v shellcheck >/dev/null 2>&1 || { echo "lint-shell.sh: shellcheck not installed" >&2; exit 1; }

list=$(mktemp)
trap 'rm -f "$list"' EXIT
# *.sh plus extensionless files with a sh/bash shebang (pkg +PRE_DEINSTALL
# hooks, rc.syshook.d entries, the engine wrapper, ...).
find "$ROOT" \( -name .git -o -name .claude -o -name node_modules -o -name work \) -prune -o \
	-type f -print | while IFS= read -r f; do
	case "$f" in
	*.sh) echo "$f" ;;
	*.*) ;;
	*) head -n 1 "$f" 2>/dev/null | grep -Eq '^#!.*(/|env )(ba)?sh( |$)' && echo "$f" ;;
	esac
done | sort > "$list"

rc=0
n=0
while IFS= read -r f; do
	rel=${f#"$ROOT"/}
	skip=0
	for d in $SKIP_DIRS; do
		case "$rel" in "$d"/*) skip=1 ;; esac
	done
	[ "$skip" -eq 0 ] || continue
	n=$((n + 1))
	sev=error
	for d in $STRICT_DIRS; do
		case "$rel" in "$d"/*) sev=style ;; esac
	done
	if ! shellcheck -x -P "$(dirname "$f")" -S "$sev" "$f"; then
		echo "::error file=$rel::shellcheck (severity>=$sev) failed" >&2
		rc=1
	fi
	if [ "$sev" = error ]; then
		shellcheck -x -P "$(dirname "$f")" -S warning -f gcc "$f" 2>/dev/null |
			sed 's/^/advisory: /' || true
	fi
done < "$list"
echo "lint-shell.sh: checked $n scripts under $ROOT (rc=$rc)"
exit "$rc"
