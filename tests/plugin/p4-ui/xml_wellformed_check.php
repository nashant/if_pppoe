<?php
// Stands in for `xmllint --noout` (not installed, no network in this sandbox to fetch
// it — see docs/plugin/README.md substitution note). Checks well-formedness only;
// OPNsense's model/forms/menu/acl XML files have no DTD/XSD to validate against anyway.
$failed = false;
foreach (array_slice($argv, 1) as $file) {
    libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    if (!$doc->load($file)) {
        $failed = true;
        echo "MALFORMED: $file\n";
        foreach (libxml_get_errors() as $error) {
            echo '  ' . trim($error->message) . "\n";
        }
        libxml_clear_errors();
    } else {
        echo "OK: $file\n";
    }
}
exit($failed ? 1 : 0);
