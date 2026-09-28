#!/bin/sh
# Run all hook tests.  PHP selects the php CLI (default: php in PATH).
# OPNsense 25.7.x ships PHP 8.3, 26.7 ships PHP 8.5; run under 8.3 and
# 8.5 at least (opnsense/tools config/26.7/build.conf: PHP?=85).
set -u
here=$(cd "$(dirname "$0")" && pwd)
rc=0
: "${PHP:=php}"
export PHP
echo "# hookctl_test.sh ($(${PHP} -r 'echo PHP_VERSION;'))"
sh "${here}/hookctl_test.sh" || rc=1
echo "# syshook_test.sh"
REAL_PHP="${REAL_PHP:-${PHP}}" sh "${here}/syshook_test.sh" || rc=1
exit ${rc}
