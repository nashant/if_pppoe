# shellcheck shell=sh
# Tiny assertion helpers shared by the hook tests.

: "${PHP:=php}"
HERE=$(cd "$(dirname "$0")" && pwd)
PLUGIN=$(cd "${HERE}/../.." && pwd)
SRC="${PLUGIN}/src"
FIX="${PLUGIN}/tests/fixtures/interfaces.inc"
HOOKCTL="${SRC}/opnsense/scripts/if_pppoe/hookctl.php"

if [ -z "${IF_PPPOE_TEST_TMP:-}" ]; then
	IF_PPPOE_TEST_TMP=$(mktemp -d)
	trap 'rm -rf "${IF_PPPOE_TEST_TMP}"' EXIT
fi
mkdir -p "${IF_PPPOE_TEST_TMP}"

PASS=0
FAIL=0

ok()
{
	PASS=$((PASS + 1))
	echo "ok   - $1"
}

not_ok()
{
	FAIL=$((FAIL + 1))
	echo "FAIL - $1"
}

check()
{
	# check <description> <command...>
	_d="$1"
	shift
	if "$@"; then ok "${_d}"; else not_ok "${_d}"; fi
}

eq()
{
	# eq <description> <got> <want>
	if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1: got [$2] want [$3]"; fi
}

contains()
{
	case "$2" in
	*"$3"*) ok "$1" ;;
	*) not_ok "$1: [$2] lacks [$3]" ;;
	esac
}

sha()
{
	sha256sum "$1" | cut -d' ' -f1
}

finish()
{
	echo "# pass=${PASS} fail=${FAIL}"
	[ "${FAIL}" -eq 0 ]
}
