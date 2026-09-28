<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Test;

use IfPppoe\Engine\Engine;
use IfPppoe\Engine\Env;
use IfPppoe\Engine\Plan;
use IfPppoe\Engine\Pppoectl;

/**
 * The engine-vs-real-pppoectl contract ("ctl-contract"): argv/stdin/-f
 * shapes lib/Pppoectl.php + Engine.php can hand to sbin/pppoectl. See
 * README.md's "ctl-contract" section for the consumers and how to
 * regenerate tests/fixtures/ctl-contract{,.json}.
 *
 * chap() does NOT build fixtures from Pppoectl's helpers by hand (that
 * tests only the helpers, not the create/down/discovery/settings/verify-
 * before-mtu/up glue in Engine::bringUp, Engine.php:195-234 -- how the
 * "-S -f /dev/stdin" bug shipped in 0.2 unnoticed). It runs the real
 * Engine::configure() against a throw-away Sandbox and reads back what it
 * handed the recording stub, from calls.jsonl (stubs/stub.php:15-27), then
 * normalises the sandbox's device/parent/binary paths and the random -f
 * path to placeholder tokens (`@DEV@`, `@PARENT@`, `@CFGFILE@`, `@POCTL@`,
 * `@IFCONFIG@` -- substituted at replay time; CI uses its own freshly built
 * `pppoectl`, hence `@POCTL@` rather than a hardcoded path).
 *
 * PAP and ac-name are pppoectl(8) ABI this driver must keep stable
 * (pppoectl.c:250-256 ac_name, :540 myauthproto=pap) that the Engine itself
 * never sends (Pppoectl::settingsLines() is hardwired to chap), so there is
 * no Engine::configure() path to generate them from; handBuilt() builds
 * them from Pppoectl::escape() instead.
 */
final class CtlContract
{
    /** literal placeholder tokens; see the class docblock */
    private const DEVICE = '@DEV@';
    private const PARENT = '@PARENT@';
    private const CFGFILE = '@CFGFILE@';
    private const POCTL = '@POCTL@';
    private const IFCONFIG = '@IFCONFIG@';

    /* the Sandbox's own real values, substituted for the placeholders above */
    private const SANDBOX_DEVICE = 'pppoe0';
    private const SANDBOX_PARENT = 'igb1';

    /** @return list<array<string,mixed>> one rendered fixture per scenario, in a stable order */
    public static function scenarios(): array
    {
        return [
            self::chap('chap-basic', 'user@isp.example', 's3cr3t-Pa55', [
                'service' => 'ISP-SVC', 'mtu' => 1492, 'ipv6cp' => true, 'queryDns' => false, 'mssfix' => true,
            ]),
            self::chap('chap-service-mtu-mssfix-off', 'wan-user', 'anotherPW9', [
                'service' => 'svc with space', 'mtu' => 1480, 'ipv6cp' => false, 'queryDns' => true, 'mssfix' => false,
            ]),
            self::chap('chap-no-service-username-escaped', 'us#er\\name', 'plainpass', [
                'service' => '', 'mtu' => 1492, 'ipv6cp' => true, 'queryDns' => false, 'mssfix' => true,
            ]),
            self::chap('chap-secret-spaces-and-tabs', 'tabuser', "  lead\ttrail\tsecret  ", [
                'service' => 'lab', 'mtu' => 1492, 'ipv6cp' => false, 'queryDns' => false, 'mssfix' => true,
            ]),
            /* mtu kept <= PPPOE_MAXMTU (1492, if_pppoe.h:111): a bigger dev MTU needs a parent
             * MTU >= dev+8 (RFC 4638, if_pppoe.c:3414-3430); the sandbox's parents are 1500, and
             * chap() runs the same check Eligibility.php:366-372 does, so Engine::configure() would
             * refuse a bigger value as ineligible anyway */
            self::chap('chap-secret-unicode', 'unicodeuser', 'pâsswörd_ünïcødé_密码', [
                'service' => 'lab', 'mtu' => 1492, 'ipv6cp' => true, 'queryDns' => false, 'mssfix' => false,
            ]),
            self::pap('pap-basic', 'pap-user', 'pappw-123', [
                'service' => 'pap-svc', 'mtu' => 1492, 'ipcp' => true, 'ipv6cp' => false,
                'mssfix' => true,
            ]),
            self::acname('ac-name-set', 'acuser', 'acpassword', [
                'service' => 'svc-for-ac', 'acname' => 'AC-Concentrator #1', 'mtu' => 1492,
                'ipcp' => true, 'ipv6cp' => true, 'mssfix' => true,
            ]),
        ];
    }

    /** @return array{myauthproto:string,myauthname:string,hisauthproto_absent:bool,max_auth_failure:int,ipcp:bool,ipv6cp:bool,mssfix:bool} */
    private static function expect(string $username, string $authproto, bool $ipcp, bool $ipv6cp, bool $mssfix): array
    {
        return [
            'myauthproto' => $authproto,
            'myauthname' => $username,
            'hisauthproto_absent' => true,
            'max_auth_failure' => 0,
            'ipcp' => $ipcp,
            'ipv6cp' => $ipv6cp,
            'mssfix' => $mssfix,
        ];
    }

    /** single-quote a value for a POSIX sh `KEY='value'` assignment */
    private static function shQuote(string $v): string
    {
        return "'" . str_replace("'", "'\\''", $v) . "'";
    }

    /** the flat `expect` file's content for one fixture's expect array; shared by
     * gen_ctl_contract.php (writes it) and test_ctl_contract.php (drift-checks it) */
    public static function renderExpect(array $expect): string
    {
        $out = '';
        foreach ($expect as $k => $v) {
            $out .= $k . '=' . (is_bool($v) ? ($v ? 1 : 0) : self::shQuote((string)$v)) . "\n";
        }
        return $out;
    }

    /**
     * Run lib/Pppoectl.php + lib/Engine.php for real: build a Sandbox whose
     * config.xml carries this scenario's settings, run Engine::configure(),
     * and read the argv/stdin/-f-file content it actually handed the
     * recording stub back off calls.jsonl. This is what makes the CHAP
     * fixtures cover Engine::bringUp's glue (order, the private -f file,
     * the secret-only-on-stdin split) and not just Pppoectl's helpers.
     */
    private static function chap(string $name, string $username, string $password, array $o): array
    {
        $service = $o['service'] ?? '';
        $mtu = (int)($o['mtu'] ?? 1492);
        $ipv6cp = (bool)($o['ipv6cp'] ?? false);
        $queryDns = (bool)($o['queryDns'] ?? false);
        $mssfix = (bool)($o['mssfix'] ?? true);

        $s = new Sandbox();
        $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) use ($username, $password, $service, $ipv6cp, $queryDns, $mssfix): void {
            $x->query('//ppps/ppp/username')->item(0)->textContent = $username;
            $x->query('//ppps/ppp/password')->item(0)->nodeValue = base64_encode($password);
            $x->query('//ppps/ppp/provider')->item(0)->textContent = $service;
            $x->query('//interfaces/wan/ipaddrv6')->item(0)->textContent = $ipv6cp ? 'dhcp6' : 'none';

            $dns = $x->query('//system/dnsallowoverride')->item(0);
            if ($dns !== null) {
                $dns->parentNode->removeChild($dns);
            }
            if ($queryDns) {
                $x->query('//system')->item(0)->appendChild($d->createElement('dnsallowoverride', '1'));
            }
            if (!$mssfix) {
                $x->query('//ppps/ppp')->item(0)->appendChild($d->createElement('tcpmssfix', '1'));
            }
        });

        $e = $s->engine();
        $rc = $e->configure('wan', self::SANDBOX_DEVICE, self::SANDBOX_PARENT, (string)$mtu, '');
        if ($rc !== Engine::EXIT_CLAIMED) {
            throw new \RuntimeException(
                "ctl-contract fixture '{$name}': configure() did not claim " . self::SANDBOX_DEVICE
                . " (rc={$rc}): " . implode('; ', $s->logs)
            );
        }

        $pppoectlCalls = $s->calls('pppoectl');
        if (count($pppoectlCalls) !== 3) {
            throw new \RuntimeException("ctl-contract fixture '{$name}': expected 3 pppoectl calls (discovery, settings, verify), got " . count($pppoectlCalls));
        }
        [$discovery, $settings, $verify] = $pppoectlCalls;

        $mtuCall = null;
        foreach ($s->calls('ifconfig') as $c) {
            if (($c['argv'][1] ?? null) === 'mtu') {
                $mtuCall = $c;
            }
        }
        if ($mtuCall === null) {
            throw new \RuntimeException("ctl-contract fixture '{$name}': no 'ifconfig ... mtu ...' call recorded");
        }

        $cfgfile = $settings['argv'][2] ?? '';
        $norm = fn(string $tok): string => self::normalizeToken($tok, $cfgfile);

        return [
            'name' => $name,
            'device' => self::DEVICE,
            'discovery_argv' => array_map($norm, array_merge([$discovery['path']], $discovery['argv'])),
            'settings_argv' => array_map($norm, array_merge([$settings['path']], $settings['argv'])),
            'settings_stdin' => (string)$settings['stdin'],
            'settings_file' => (string)$settings['ffile']['content'],
            /* Engine::bringUp runs the read-back (verify) BEFORE the mtu ifconfig call
             * (Engine.php:223-232); the replay/offline suites preserve that order */
            'verify_argv' => array_map($norm, array_merge([$verify['path']], $verify['argv'])),
            'mtu_argv' => array_map($norm, array_merge([$mtuCall['path']], $mtuCall['argv'])),
            'expect' => self::expect($username, 'chap', true, $ipv6cp, $mssfix),
        ];
    }

    /**
     * $tok is either a bare argument or one of the two paths stubs/stub.php records
     * in calls.jsonl: the recording stub strips $IF_PPPOE_ROOT off argv[0] before
     * logging it (stub.php: `$self = substr($argv[0], strlen($root));`), so the
     * binary paths below are root-relative already -- unlike $cfgfile, a real
     * filesystem path under the sandbox root that Pppoectl::writeSettingsFile()
     * (not the stub) created.
     */
    private static function normalizeToken(string $tok, string $cfgfile): string
    {
        if ($cfgfile !== '' && $tok === $cfgfile) {
            return self::CFGFILE;
        }
        if ($tok === '/usr/local/sbin/pppoectl') {
            return self::POCTL;
        }
        if ($tok === '/sbin/ifconfig') {
            return self::IFCONFIG;
        }
        if ($tok === self::SANDBOX_DEVICE) {
            return self::DEVICE;
        }
        if ($tok === self::SANDBOX_PARENT) {
            return self::PARENT;
        }
        return $tok;
    }

    private static function env(): Env
    {
        return new Env('');
    }

    private static function ctl(): Pppoectl
    {
        return new Pppoectl(self::env());
    }

    private static function plan(string $username, string $password, array $o): Plan
    {
        $p = new Plan();
        $p->friendly = 'wan';
        $p->device = self::DEVICE;
        $p->parent = self::PARENT;
        $p->username = $username;
        $p->password = $password;
        $p->service = $o['service'] ?? '';
        $p->mtu = $o['mtu'] ?? 1492;
        $p->ipcp = $o['ipcp'] ?? true;
        $p->ipv6cp = $o['ipv6cp'] ?? false;
        $p->queryDns = $o['queryDns'] ?? false;
        $p->mssfix = $o['mssfix'] ?? true;
        return $p;
    }

    /**
     * pppoectl also accepts myauthproto=pap (pppoectl.c:540): the Engine never
     * sends this today, but the ABI must hold for it too. Built from the same
     * settings-line shape as Pppoectl::settingsLines(), with "passiveauthproto"
     * dropped (a PAP-only line has nothing to be passive about) and
     * myauthproto=pap in its place.
     */
    private static function pap(string $name, string $username, string $password, array $o): array
    {
        $ctl = self::ctl();
        $p = self::plan($username, $password, $o);
        $lines = [
            'myauthproto=pap',
            'myauthname=' . Pppoectl::escape($p->username),
            'hisauthproto=none',
            'max-auth-failure=0',
            $p->ipcp ? 'ipcp' : 'noipcp',
            $p->ipv6cp ? 'ipv6cp' : 'noipv6cp',
            'query-dns=' . ($p->queryDns ? '3' : '0'),
            $p->mssfix ? 'mssfix' : 'nomssfix',
        ];
        return self::handBuilt($name, $ctl, $p, implode("\n", $lines) . "\n", $ctl->discoveryArgv($p), 'pap');
    }

    /**
     * pppoectl -e <parent> -a <ac-name> -s <service> <dev> (pppoectl.c:250-256):
     * Pppoectl::discoveryArgv() has no -a today; built by hand from the same
     * Env::bin()/Plan the engine uses. ac-name is never fparseln-escaped --
     * PPPOESETPARMS takes it as a plain C string, unlike the -f file -- so no
     * Pppoectl::escape() call belongs here.
     */
    private static function acname(string $name, string $username, string $password, array $o): array
    {
        $ctl = self::ctl();
        $env = self::env();
        $p = self::plan($username, $password, $o);
        $argv = [$env->bin('pppoectl'), '-e', $p->parent];
        if ($p->service !== '') {
            $argv[] = '-s';
            $argv[] = $p->service;
        }
        $argv[] = '-a';
        $argv[] = (string)$o['acname'];
        $argv[] = $p->device;
        return self::handBuilt($name, $ctl, $p, $ctl->settingsFile($p), $argv, 'chap');
    }

    /** replace a hand-built argv[0] (a real Env('')::bin() path) with its placeholder token */
    private static function withPlaceholderArgv0(array $argv, string $token): array
    {
        $argv[0] = $token;
        return $argv;
    }

    /** shared shape for the hand-built (never-sent-by-Engine) pap/ac-name fixtures */
    private static function handBuilt(string $name, Pppoectl $ctl, Plan $p, string $settingsFile, array $discoveryArgv, string $authproto): array
    {
        return [
            'name' => $name,
            'device' => self::DEVICE,
            'discovery_argv' => self::withPlaceholderArgv0($discoveryArgv, self::POCTL),
            'settings_argv' => self::withPlaceholderArgv0($ctl->settingsArgv($p, self::CFGFILE), self::POCTL),
            'settings_stdin' => $ctl->settingsStdin($p),
            'settings_file' => $settingsFile,
            /* matches Engine::bringUp's order (verify before mtu, Engine.php:223-232),
             * even though these two scenarios never actually run through the Engine */
            'verify_argv' => self::withPlaceholderArgv0($ctl->verifyArgv($p), self::POCTL),
            /* Env::bin('ifconfig') mtu call: not part of the pppoectl ABI, but it is
             * part of what Engine::bringUp sends between the read-back and 'up'
             * (if_pppoe.c:2258-2277 needs the parent attached first, hence -e before
             * this); replayed for completeness, not asserted against pppoectl output */
            'mtu_argv' => [self::IFCONFIG, self::DEVICE, 'mtu', (string)$p->mtu],
            'expect' => self::expect($p->username, $authproto, $p->ipcp, $p->ipv6cp, $p->mssfix),
        ];
    }
}
