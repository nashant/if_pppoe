<?php
// Structural checks only (not a real configd parser, which lives elsewhere).
// Usage: test_actions_conf.php <path-to-actions_if-pppoe.conf>

function fail(string $msg): never
{
    fwrite(STDERR, "FAIL: $msg\n");
    exit(1);
}

$path = $argv[1] ?? null;
if ($path === null || !is_file($path)) {
    fail("no such file: " . var_export($path, true));
}

$required_keys = ['command', 'parameters', 'type', 'message'];
$sections = [];
$current = null;

foreach (file($path, FILE_IGNORE_NEW_LINES) as $lineno => $line) {
    $trimmed = trim($line);
    if ($trimmed === '' || str_starts_with($trimmed, ';')) {
        continue;
    }
    if (preg_match('/^\[([a-zA-Z0-9_.-]+)\]$/', $trimmed, $m)) {
        $current = $m[1];
        if (isset($sections[$current])) {
            fail("duplicate section [$current] at line " . ($lineno + 1));
        }
        $sections[$current] = [];
        continue;
    }
    if ($current === null) {
        fail("key/value before any [section] at line " . ($lineno + 1) . ": $line");
    }
    if (!str_contains($line, ':')) {
        fail("line without a ':' inside [$current] at line " . ($lineno + 1) . ": $line");
    }
    [$key, $value] = explode(':', $line, 2);
    $sections[$current][trim($key)] = $value;
}

if (empty($sections)) {
    fail('no [section]s found');
}

foreach (['status', 'reconfigure', 'reconcile', 'reapply', 'notices'] as $expected) {
    if (!isset($sections[$expected])) {
        fail("expected section [$expected] is missing");
    }
}

foreach ($sections as $name => $kv) {
    foreach ($required_keys as $key) {
        if (!array_key_exists($key, $kv)) {
            // 'message' is documentation-only in some core actions files, so only
            // command/parameters/type are load-bearing enough to hard fail on.
            if ($key === 'message') {
                continue;
            }
            fail("[$name] is missing required key '$key'");
        }
    }
    if (!str_starts_with(ltrim($kv['command']), '/')) {
        fail("[$name] command is not an absolute path: {$kv['command']}");
    }
}

// The reconfigure action takes exactly one parameter (the desired state).
// It must be a BARE %s: configd's action runner already single-quotes and
// escapes each substituted parameter itself (opnsense/core
// src/opnsense/service/modules/actions/base.py:94-96), and
// Backend::configdpRun() escapeshellarg()s it again first (Backend.php:
// 200-202). A literal '%s' here would double-quote the value so it reaches
// the shell unescaped -- no core actions file does this (core always uses a
// bare %s, e.g. actions_service.conf's `list` action).
$reconfigureParams = trim($sections['reconfigure']['parameters']);
if ($reconfigureParams !== '%s') {
    fail("[reconfigure] parameters must be a bare %s (configd already quotes/escapes it), got: $reconfigureParams");
}

echo "OK: " . count($sections) . " section(s) in $path\n";
exit(0);
