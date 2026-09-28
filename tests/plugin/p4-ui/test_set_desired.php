<?php
// Exercises set-desired.php as a real subprocess (no OPNsense/Phalcon deps to stub),
// redirecting its write target via IF_PPPOE_STATE_DIR.
// Usage: test_set_desired.php <path-to-set-desired.php>

function run(string $script, string $stateDir, string $arg): array
{
    $cmd = sprintf(
        'IF_PPPOE_STATE_DIR=%s php %s %s 2>&1',
        escapeshellarg($stateDir),
        escapeshellarg($script),
        escapeshellarg($arg)
    );
    exec($cmd, $out, $status);
    return [$status, implode("\n", $out)];
}

function check(bool $cond, string $label, array &$failures): void
{
    echo ($cond ? 'ok' : 'FAIL') . " - $label\n";
    if (!$cond) {
        $failures[] = $label;
    }
}

$script = $argv[1] ?? null;
if ($script === null || !is_file($script)) {
    fwrite(STDERR, "no such file: " . var_export($script, true) . "\n");
    exit(1);
}

$failures = [];
$tmp = sys_get_temp_dir() . '/if_pppoe_test_' . bin2hex(random_bytes(4));

// 1. valid 'enabled' creates the state dir and the desired file, mode 0600.
[$status, $out] = run($script, $tmp, 'enabled');
check($status === 0, 'exit 0 on valid arg', $failures);
$target = $tmp . '/desired';
check(is_file($target), 'desired file created', $failures);
check(trim((string)@file_get_contents($target)) === 'enabled', 'file contains "enabled"', $failures);
$perms = @fileperms($target) & 0777;
check($perms === 0600, 'file mode is 0600, got ' . decoct($perms), $failures);
$decoded = json_decode($out, true);
check(is_array($decoded) && ($decoded['result'] ?? null) === 'ok', 'stdout is {"result":"ok",...}', $failures);

// 2. flips to 'disabled' cleanly (overwrite, not append).
[$status, $out] = run($script, $tmp, 'disabled');
check($status === 0, 'exit 0 on second valid call', $failures);
check(trim((string)@file_get_contents($target)) === 'disabled', 'file now contains "disabled"', $failures);

// 3. no leftover .tmp.* files after a successful run (atomic rename cleaned up).
$leftovers = glob($tmp . '/desired.tmp.*');
check($leftovers === [], 'no leftover temp files, found: ' . implode(',', $leftovers), $failures);

// 4. rejects an invalid argument and does not touch an existing file.
file_put_contents($target, "disabled\n");
[$status, $out] = run($script, $tmp, 'maybe');
check($status !== 0, 'non-zero exit on invalid arg', $failures);
check(trim((string)@file_get_contents($target)) === 'disabled', 'existing file left untouched on failure', $failures);

// 5. rejects a missing argument.
[$status, $out] = run($script, $tmp, '');
check($status !== 0, 'non-zero exit on missing arg', $failures);

// cleanup
foreach (glob($tmp . '/*') as $f) {
    @unlink($f);
}
@rmdir($tmp);

if (!empty($failures)) {
    fwrite(STDERR, "\n" . count($failures) . " failure(s):\n - " . implode("\n - ", $failures) . "\n");
    exit(1);
}
echo "ALL OK\n";
exit(0);
