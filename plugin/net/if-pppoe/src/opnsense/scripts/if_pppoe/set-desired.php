#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Anthony Nash
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Usage: set-desired.php <enabled|disabled>. Atomically writes /conf/if_pppoe/desired
 * for rc.syshook.d/early/50-if-pppoe to read with /bin/sh only, no PHP config parsing.
 * No OPNsense\* dependency (runs out of process via configd); the caller
 * (Api\ServiceController::reconfigureAction) already whitelists the argument.
 * IF_PPPOE_STATE_DIR overrides the write target for tests.
 */

function ifpppoe_fail(string $message): never
{
    fwrite(STDERR, $message . "\n");
    echo json_encode(['result' => 'failed', 'message' => $message]) . "\n";
    exit(1);
}

$stateDir = getenv('IF_PPPOE_STATE_DIR');
if ($stateDir === false || $stateDir === '') {
    $stateDir = '/conf/if_pppoe';
}

$desired = $argv[1] ?? '';
if ($desired !== 'enabled' && $desired !== 'disabled') {
    ifpppoe_fail("expected 'enabled' or 'disabled', got: " . var_export($desired, true));
}

if (!is_dir($stateDir) && !@mkdir($stateDir, 0700, true) && !is_dir($stateDir)) {
    ifpppoe_fail("cannot create state directory: $stateDir");
}

$target = $stateDir . '/desired';
$tmp = $target . '.tmp.' . getmypid();

if (@file_put_contents($tmp, $desired . "\n") === false) {
    ifpppoe_fail("cannot write temp file: $tmp");
}
@chmod($tmp, 0600);

if (!@rename($tmp, $target)) {
    @unlink($tmp);
    ifpppoe_fail("cannot rename $tmp to $target");
}

echo json_encode(['result' => 'ok', 'desired' => $desired]) . "\n";
exit(0);
