<?php

namespace IfPppoe\Test;

use IfPppoe\Engine\Env;
use IfPppoe\Engine\Plan;
use IfPppoe\Engine\Pppoectl;

function plan(string $user, string $pw, string $svc = ''): Plan
{
    $p = new Plan();
    $p->friendly = 'wan';
    $p->device = 'pppoe0';
    $p->parent = 'igb1';
    $p->username = $user;
    $p->password = $pw;
    $p->service = $svc;
    return $p;
}

/** what fparseln(3) with FPARSELN_UNESCALL and the default "\\\\#" delimiters yields for one line */
function fparselnLine(string $line): string
{
    $out = '';
    $n = strlen($line);
    for ($i = 0; $i < $n; $i++) {
        $c = $line[$i];
        if ($c === '\\' && $i + 1 < $n) {
            $out .= $line[++$i];
        } elseif ($c === '#') {
            break;
        } else {
            $out .= $c;
        }
    }
    return $out;
}

T::test('pppoectl: escape round-trips through an fparseln model', function () {
    foreach (['plain', 'a#b', 'a\\b', 'ends\\', '#lead', ' spaced out ', "quote'\"`\$(x)", 'ünïcødé', 'a=b=c', '\\#\\\\#'] as $v) {
        $line = 'myauthname=' . Pppoectl::escape($v);
        T::eq('myauthname=' . $v, fparselnLine($line), "value " . json_encode($v));
    }
});

T::test('pppoectl: escape rejects NUL/CR/LF', function () {
    foreach (["a\nb", "a\rb", "a\0b"] as $v) {
        $threw = false;
        try {
            Pppoectl::escape($v);
        } catch (\InvalidArgumentException $e) {
            $threw = true;
        }
        T::ok($threw, json_encode($v));
    }
});

T::test('pppoectl: argv carries no credentials; stdin is the verbatim secret line only; the -f file never holds it', function () {
    $ctl = new Pppoectl(new Env('/r'));
    $secrets = ['s3cr3t', 'p#ss\\w0rd', "  lead and trail  ", '-S x', 'myauthname=evil', "\$(reboot)`id`'\""];
    foreach ($secrets as $pw) {
        $p = plan('u#ser\\name', $pw, 'svc name');
        $argv = array_merge($ctl->discoveryArgv($p), $ctl->settingsArgv($p, '/r/var/run/if_pppoe/pppoectl.pppoe0.x.conf'));
        T::ok(!in_array($pw, $argv, true), 'secret on argv');
        foreach ($argv as $a) {
            T::ok(!str_contains($a, 'u#ser'), 'username on argv');
        }
        T::eq($pw . "\n", $ctl->settingsStdin($p), 'stdin is exactly the raw secret line');
        $file = $ctl->settingsFile($p);
        T::ok(!str_contains($file, $pw), 'secret in the -f file');
        $lines = explode("\n", rtrim($file, "\n"));
        T::eq($ctl->settingsLines($p), $lines);
        T::ok(in_array('myauthname=u\\#ser\\\\name', $lines, true), 'escaped username line');
        T::eq('myauthname=u#ser\\name', fparselnLine('myauthname=u\\#ser\\\\name'));
    }
    $p = plan('u', 'p', 'svc name');
    T::eq(['/r/usr/local/sbin/pppoectl', '-e', 'igb1', '-s', 'svc name', 'pppoe0'], $ctl->discoveryArgv($p));
    T::eq(['/r/usr/local/sbin/pppoectl', '-e', 'igb1', 'pppoe0'], $ctl->discoveryArgv(plan('u', 'p', '')));
    T::eq(['/r/usr/local/sbin/pppoectl', '-S', '-f', '/r/c.conf', 'pppoe0'], $ctl->settingsArgv($p, '/r/c.conf'));
});

T::test('pppoectl: settings file is a fresh 0600 file under the run dir, unlinked on every path', function () {
    $s = new Sandbox();
    $ctl = new Pppoectl($s->env());
    $p = plan('u#ser', 'pw-XYZZY');
    $s->write('/var/run/if_pppoe/pppoectl.pppoe0.0123456789abcdef.conf', 'stale');
    $seen = $ctl->withSettingsFile($p, function (string $f) use ($ctl, $p) {
        clearstatcache();
        return [$f, fileperms($f) & 07777, file_get_contents($f), glob(dirname($f) . '/pppoectl.pppoe0.*.conf')];
    });
    [$f, $mode, $content, $all] = $seen;
    T::ok(str_starts_with($f, $s->root . '/var/run/if_pppoe/pppoectl.pppoe0.'), $f);
    T::eq(0600, $mode, sprintf('mode %04o', $mode));
    T::eq($ctl->settingsFile($p), $content);
    T::ok(!str_contains($content, 'XYZZY'), 'secret in the -f file');
    T::eq([$f], $all, 'stale file from a killed configure removed');
    T::ok(!file_exists($f), 'unlinked after success');
    $f2 = null;
    try {
        $ctl->withSettingsFile($p, function (string $f) use (&$f2) {
            $f2 = $f;
            throw new \RuntimeException('boom');
        });
    } catch (\RuntimeException $e) {
        T::eq('boom', $e->getMessage());
    }
    T::ok($f2 !== null && $f2 !== $f && !file_exists($f2), 'unlinked after an exception');
});

T::test('pppoectl: settings lines follow the plan', function () {
    $ctl = new Pppoectl(new Env('/r'));
    $p = plan('u', 'p');
    $p->ipcp = true;
    $p->ipv6cp = false;
    $p->queryDns = true;
    $p->mssfix = true;
    T::eq(['myauthproto=chap', 'passiveauthproto', 'myauthname=u', 'hisauthproto=none', 'max-auth-failure=0',
        'ipcp', 'noipv6cp', 'query-dns=3', 'mssfix'], $ctl->settingsLines($p));
    $p->ipcp = false;
    $p->ipv6cp = true;
    $p->queryDns = false;
    $p->mssfix = false;
    $l = $ctl->settingsLines($p);
    T::ok(in_array('noipcp', $l, true) && in_array('ipv6cp', $l, true) && in_array('query-dns=0', $l, true) && in_array('nomssfix', $l, true));
});

/** `pppoectl <dev>` list output as print_vals() (pppoectl.c at p3-ctl-abi / p3-mss) formats it */
function listOut(?string $proto, string $name, int $maf = 0, bool $ipcp = true, bool $ipv6cp = true, ?bool $mss = true, ?string $his = null): string
{
    $o = "pppoe0:\tphase=dead\n";
    if ($proto !== null) {
        $o .= "\tmyauthproto={$proto} myauthname=\"{$name}\"\n";
    }
    if ($his !== null) {
        $o .= "\thisauthproto={$his} hisauthname=\"\"\n";
    }
    $o .= "\tlcp timeout: 3.000 s\n\tidle timeout = disabled\n\tmax-auth-failure = {$maf}\n\tmax-noreceive = 90 seconds\n"
        . "\tipcp: " . ($ipcp ? 'enable' : 'disable') . "\n\tipv6cp: " . ($ipv6cp ? 'enable' : 'disable') . "\n";
    if ($mss !== null) {
        $o .= "\tmssfix: " . ($mss ? 'enable' : 'disable') . "\n";
    }
    return $o;
}

T::test('pppoectl: read-back verification accepts exactly the plan', function () {
    $p = plan('u"ser #1\\x', 'p');
    $p->ipcp = true;
    $p->ipv6cp = true;
    $p->mssfix = true;
    T::eq(null, Pppoectl::verify($p, listOut('chap', 'u"ser #1\\x')));
    T::eq(null, Pppoectl::verify($p, listOut('chap', 'u"ser #1\\x', 0, true, true, null)), 'pppoectl without the mssfix line');
    $bad = [
        'auth lost (-f lines dropped)' => listOut(null, ''),
        'pap' => listOut('pap', 'u"ser #1\\x'),
        'other user' => listOut('chap', 'u"ser #1'),
        'max-auth-failure' => listOut('chap', 'u"ser #1\\x', 5),
        'ipv6cp' => listOut('chap', 'u"ser #1\\x', 0, true, false),
        'ipcp' => listOut('chap', 'u"ser #1\\x', 0, false, true),
        'mssfix' => listOut('chap', 'u"ser #1\\x', 0, true, true, false),
        'hisauth' => listOut('chap', 'u"ser #1\\x', 0, true, true, true, 'chap'),
    ];
    foreach ($bad as $what => $out) {
        T::ok(Pppoectl::verify($p, $out) !== null, $what);
    }
    T::eq(['/r/usr/local/sbin/pppoectl', 'pppoe0'], (new Pppoectl(new Env('/r')))->verifyArgv($p));
});
