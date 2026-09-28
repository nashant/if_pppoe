<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * php tests/engine/gen_ctl_contract.php
 *
 * Regenerates the checked-in ctl-contract fixtures (see
 * ctl_contract_fixtures.php's docblock) from CtlContract::scenarios():
 *   tests/fixtures/ctl-contract.json           -- one JSON dump, for review
 *   tests/fixtures/ctl-contract/<name>/...     -- the same data flattened to
 *     one-argv-token-per-line / raw-bytes files, for ctl-contract-replay.sh
 *     (no JSON parser needed on the FreeBSD box that runs it)
 * Run this and commit the result whenever ctl_contract_fixtures.php,
 * lib/Pppoectl.php or lib/Engine.php's pppoectl argv shapes change.
 */

namespace IfPppoe\Test;

require __DIR__ . '/harness.php';
require __DIR__ . '/ctl_contract_fixtures.php';

function write_file(string $path, string $data): void
{
    if (!is_dir(dirname($path))) {
        mkdir(dirname($path), 0755, true);
    }
    if (file_put_contents($path, $data) === false) {
        fwrite(STDERR, "gen_ctl_contract: cannot write {$path}\n");
        exit(1);
    }
}

/** recursively remove a directory the previous run left behind for a scenario that no longer exists */
function remove_dir(string $dir): void
{
    foreach (scandir($dir) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = "{$dir}/{$entry}";
        is_dir($path) ? remove_dir($path) : unlink($path);
    }
    rmdir($dir);
}

$fixturesDir = __DIR__ . '/../fixtures';
$scenarios = CtlContract::scenarios();

write_file(
    "{$fixturesDir}/ctl-contract.json",
    json_encode($scenarios, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"
);

/* drop any scenario directory from a previous run that no longer has a matching
 * scenario: ctl-contract-replay.sh replays every subdirectory it finds, so a
 * renamed scenario would otherwise leave an orphan that is replayed forever
 * and never drift-checked against CtlContract::scenarios() */
$ctlContractDir = "{$fixturesDir}/ctl-contract";
$wanted = array_flip(array_map(fn($fx) => $fx['name'], $scenarios));
foreach (is_dir($ctlContractDir) ? scandir($ctlContractDir) : [] as $entry) {
    if ($entry === '.' || $entry === '..' || isset($wanted[$entry])) {
        continue;
    }
    $stale = "{$ctlContractDir}/{$entry}";
    if (is_dir($stale)) {
        remove_dir($stale);
        fwrite(STDERR, "gen_ctl_contract: removed stale scenario dir {$stale}\n");
    }
}

foreach ($scenarios as $fx) {
    $dir = "{$fixturesDir}/ctl-contract/{$fx['name']}";
    foreach (['mtu' => 'mtu_argv', 'discovery' => 'discovery_argv', 'settings' => 'settings_argv', 'verify' => 'verify_argv'] as $stem => $key) {
        write_file("{$dir}/argv.{$stem}", implode("\n", $fx[$key]) . "\n");
    }
    write_file("{$dir}/settings.conf", $fx['settings_file']);
    write_file("{$dir}/stdin", $fx['settings_stdin']);
    write_file("{$dir}/expect", CtlContract::renderExpect($fx['expect']));
}

fwrite(STDERR, 'gen_ctl_contract: wrote ' . count($scenarios) . " scenarios\n");
