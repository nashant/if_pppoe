#!/bin/sh
# Runs every p4-ui (Services page) test that works without a live OPNsense box.
# Needs: docker (for php:8.2-cli/8.3-cli/8.4-cli/8.5-cli, already pulled in dev) and /bin/sh.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
plugin="$here/../../../plugin/net/if-pppoe"
fail=0

echo "== php -l (8.2, 8.3, 8.4, 8.5) =="
for v in 8.2 8.3 8.4 8.5; do
    if ! docker run --rm -v "$plugin":/w:ro "php:$v-cli" sh -c \
        'st=0; for f in $(find /w -iname "*.php"); do php -l "$f" || st=1; done; exit $st'; then
        echo "php $v lint FAILED"
        fail=1
    fi
done

echo "== XML well-formedness (model/forms/menu/acl) =="
if ! docker run --rm -v "$plugin":/w:ro -v "$here":/t:ro php:8.2-cli \
    find /w -iname "*.xml" -exec php /t/xml_wellformed_check.php {} + ; then
    fail=1
fi

echo "== actions_if-pppoe.conf sanity =="
if ! docker run --rm -v "$plugin":/w:ro -v "$here":/t:ro php:8.2-cli \
    php /t/test_actions_conf.php /w/src/opnsense/service/conf/actions.d/actions_if-pppoe.conf; then
    fail=1
fi

echo "== set-desired.php behaviour =="
if ! docker run --rm -v "$plugin":/w:ro -v "$here":/t:ro php:8.2-cli \
    php /t/test_set_desired.php /w/src/opnsense/scripts/if_pppoe/set-desired.php; then
    fail=1
fi

echo "== Support library (status merge / standalone-violation logic) =="
if ! docker run --rm -v "$plugin":/w:ro -v "$here":/t:ro php:8.2-cli \
    php /t/test_support_lib.php /w/src/opnsense/mvc/app/library/OPNsense/IfPppoe/Support.php; then
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ALL OK"
