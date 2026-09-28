<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Test;

use IfPppoe\Engine\Proc;

require_once __DIR__ . '/ctl_contract_fixtures.php';

/** @PARENT@/@DEV@/@CFGFILE@/@POCTL@/@IFCONFIG@ substituted for the Sandbox's fake
 * interface, a real temp path and the stub binaries under the Sandbox's own root */
function ctlContractResolve($v, string $dev, string $parent, string $cfgFile, string $poctl, string $ifconfig)
{
    if (is_string($v)) {
        return str_replace(
            ['@DEV@', '@PARENT@', '@CFGFILE@', '@POCTL@', '@IFCONFIG@'],
            [$dev, $parent, $cfgFile, $poctl, $ifconfig],
            $v
        );
    }
    if (is_array($v)) {
        return array_map(fn($x) => ctlContractResolve($x, $dev, $parent, $cfgFile, $poctl, $ifconfig), $v);
    }
    return $v;
}

/* Regenerating drops fixtures out of step with lib/Pppoectl.php silently
 * (the round trip below only compares in-memory to in-memory); this is the
 * guard that a `git diff` on tests/fixtures/ctl-contract{,.json} is the only
 * way the checked-in copy can move. */
T::test('ctl-contract: tests/fixtures/ctl-contract.json matches CtlContract::scenarios() (regenerate with gen_ctl_contract.php)', function () {
    $fresh = json_decode(json_encode(CtlContract::scenarios()), true);
    $path = __DIR__ . '/../fixtures/ctl-contract.json';
    $stored = json_decode((string)@file_get_contents($path), true);
    T::eq($fresh, $stored, "stale {$path}; regenerate with: php tests/engine/gen_ctl_contract.php");
});

T::test('ctl-contract: the flat per-scenario files replayed on the lab/CI box match CtlContract::scenarios()', function () {
    foreach (CtlContract::scenarios() as $fx) {
        $dir = __DIR__ . "/../fixtures/ctl-contract/{$fx['name']}";
        foreach (['mtu' => 'mtu_argv', 'discovery' => 'discovery_argv', 'settings' => 'settings_argv', 'verify' => 'verify_argv'] as $stem => $key) {
            $lines = explode("\n", rtrim((string)@file_get_contents("{$dir}/argv.{$stem}"), "\n"));
            T::eq($fx[$key], $lines, "{$fx['name']} argv.{$stem}");
        }
        T::eq($fx['settings_file'], (string)@file_get_contents("{$dir}/settings.conf"), "{$fx['name']} settings.conf");
        T::eq($fx['settings_stdin'], (string)@file_get_contents("{$dir}/stdin"), "{$fx['name']} stdin");
        T::eq(CtlContract::renderExpect($fx['expect']), (string)@file_get_contents("{$dir}/expect"), "{$fx['name']} expect");
    }
});

foreach (CtlContract::scenarios() as $fx) {
    T::test("ctl-contract: {$fx['name']} -- the recording stub's model of pppoectl matches the fixture", function () use ($fx) {
        $s = new Sandbox();
        $dev = 'pppoe8';
        $parent = 'igb2';
        $cfgFile = $s->root . '/var/run/if_pppoe/ctl-contract.' . bin2hex(random_bytes(8)) . '.conf';
        $poctl = $s->root . '/usr/local/sbin/pppoectl';
        $ifconfig = $s->root . '/sbin/ifconfig';
        $r = ctlContractResolve($fx, $dev, $parent, $cfgFile, $poctl, $ifconfig);
        $s->iface($dev, ['ether' => false, 'mtu' => 1492, 'groups' => ['pppoe']]);

        $proc = new Proc();
        $res = $proc->run($r['discovery_argv']);
        T::eq(0, $res->rc, "discovery: {$res->err}");

        @mkdir(dirname($cfgFile), 0700, true);
        file_put_contents($cfgFile, $r['settings_file']);
        chmod($cfgFile, 0600);
        $res = $proc->run($r['settings_argv'], $r['settings_stdin']);
        T::eq(0, $res->rc, "settings: {$res->err}");
        @unlink($cfgFile);

        /* Engine::bringUp runs the read-back (verify) before the mtu ifconfig call
         * (Engine.php:223-232); replayed in the same order here */
        $res = $proc->run($r['verify_argv']);
        T::eq(0, $res->rc, "verify: {$res->err}");
        $out = $res->out;
        $exp = $fx['expect'];
        T::contains("myauthproto={$exp['myauthproto']} myauthname=\"{$exp['myauthname']}\"", $out);
        if ($exp['hisauthproto_absent']) {
            T::ok(!preg_match('/^\s*hisauthproto=/m', $out), 'hisauthproto present');
        }
        T::contains("max-auth-failure = {$exp['max_auth_failure']}", $out);
        T::contains('ipcp: ' . ($exp['ipcp'] ? 'enable' : 'disable'), $out);
        T::contains('ipv6cp: ' . ($exp['ipv6cp'] ? 'enable' : 'disable'), $out);
        T::contains('mssfix: ' . ($exp['mssfix'] ? 'enable' : 'disable'), $out);

        $res = $proc->run($r['mtu_argv']);
        T::eq(0, $res->rc, "mtu: {$res->err}");
        T::eq((int)$fx['mtu_argv'][3], $s->ifaceState($dev)['mtu']);

        /* allArgv() only ever carries path+argv (never stdin, Sandbox::allArgv()), so
         * checking it against settings_stdin (which always ends in "\n", never present
         * in any argv) could never fail either way; check the raw secret text instead */
        T::ok(!str_contains($s->allArgv(), rtrim($fx['settings_stdin'], "\n")), 'secret on argv');
    });
}

/* The tests above call Proc::run() on argv arrays, never ctl-contract-replay.sh itself,
 * so a break in its own sh control flow is only ever caught on the lab/CI replay. This
 * runs the real script under sh/dash/bash --posix against the Sandbox's fake binaries. */
T::test('ctl-contract: ctl-contract-replay.sh itself (not just its argv shapes) replays clean under sh', function () {
    $s = new Sandbox();
    $dev = 'pppoe8';
    $parent = 'igb2'; // created by Sandbox::__construct() with mtu 1500, >= every fixture's mtu + 8
    $script = __DIR__ . '/ctl-contract-replay.sh';
    $fixtures = __DIR__ . '/../fixtures/ctl-contract';
    $poctl = $s->root . '/usr/local/sbin/pppoectl';
    $ifconfig = $s->root . '/sbin/ifconfig';

    foreach (['/bin/sh', '/bin/dash', '/bin/bash'] as $sh) {
        if (!is_executable($sh)) {
            continue;
        }
        $argv = $sh === '/bin/bash'
            ? [$sh, '--posix', $script, $fixtures, $parent, $dev, $poctl, $ifconfig]
            : [$sh, $script, $fixtures, $parent, $dev, $poctl, $ifconfig];
        $res = (new Proc())->run($argv, null, 60);
        T::eq(0, $res->rc, "$sh ctl-contract-replay.sh: rc={$res->rc}\nstdout:\n{$res->out}\nstderr:\n{$res->err}");
        $n = count(CtlContract::scenarios());
        T::contains("$n scenario(s) passed", $res->out, "$sh: {$res->out}{$res->err}");
    }
});
