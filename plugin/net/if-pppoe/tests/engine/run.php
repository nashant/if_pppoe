<?php

/* php tests/engine/run.php [filter] */

namespace IfPppoe\Test;

error_reporting(E_ALL);
set_error_handler(function (int $no, string $str, string $file, int $line) {
    if (!(error_reporting() & $no)) {
        return false; /* @-suppressed */
    }
    throw new \ErrorException($str, 0, $no, $file, $line);
});

require __DIR__ . '/harness.php';
require __DIR__ . '/test_eligibility.php';
require __DIR__ . '/test_pppoectl.php';
require __DIR__ . '/test_engine.php';
require __DIR__ . '/test_integration.php';
require __DIR__ . '/test_ctl_contract.php';

exit(T::run($argv[1] ?? null));
