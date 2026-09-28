#!/bin/sh
# Lint every engine PHP file and run the engine test suite.
# Local:  sh plugin/net/if-pppoe/tests/engine/run.sh [filter]     (php >= 8.1, bash)
# Docker: sh plugin/net/if-pppoe/tests/engine/run.sh --docker [8.2 8.3 8.4 8.5]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PLUGIN=$(cd "$HERE/../.." && pwd)

if [ "${1:-}" = "--docker" ]; then
	shift
	versions=${*:-"8.2 8.3 8.4 8.5"}
	rc=0
	for v in $versions; do
		echo "=== php:$v-cli"
		docker run --rm -v "$PLUGIN:/p:ro" -w /p "php:$v-cli" sh tests/engine/run.sh || rc=1
	done
	exit $rc
fi

cd "$PLUGIN"
php -l src/opnsense/scripts/if_pppoe/engine >/dev/null
for f in src/opnsense/scripts/if_pppoe/lib/*.php tests/engine/*.php tests/engine/stubs/*.php; do
	php -l "$f" >/dev/null
done
echo "lint ok"
exec php tests/engine/run.php "$@"
