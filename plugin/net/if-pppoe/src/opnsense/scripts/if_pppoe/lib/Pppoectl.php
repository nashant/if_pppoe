<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

/**
 * The only place encoding the pppoectl(8) ABI (see tests/engine/README.md):
 *  1. pppoectl -e <parent> [-s <service>] <dev>   (no credentials)
 *  2. pppoectl -S -f <cfgfile> <dev>, stdin = the secret line and nothing else (-S reads it
 *     verbatim with one getline(3), trailing LF then CR stripped, no fparseln unescaping);
 *     <cfgfile> = the escaped non-secret settings lines, a private 0600 file under the run
 *     dir, unlinked right after the call.  pppoectl refuses `-S -f /dev/stdin` with
 *     EX_USAGE (64) because both would read stdin.
 *  3. pppoectl <dev>   (list mode read-back; prints myauthname but never a secret; pppoectl.c print_vals)
 * Step 3 catches a silently partial step 2 (settings lines not applied) so the interface
 * falls back to mpd5 instead of dialling without auth.
 */
final class Pppoectl
{
    public function __construct(private Env $env)
    {
    }

    /** escape a value for a pppoectl -f line (fparseln with default "\\\\#" delimiters) */
    public static function escape(string $v): string
    {
        if (strpbrk($v, "\0\n\r") !== false) {
            throw new \InvalidArgumentException('value contains NUL, CR or LF');
        }
        return strtr($v, ['\\' => '\\\\', '#' => '\\#']);
    }

    public function discoveryArgv(Plan $p): array
    {
        $argv = [$this->env->bin('pppoectl'), '-e', $p->parent];
        if ($p->service !== '') {
            $argv[] = '-s';
            $argv[] = $p->service;
        }
        $argv[] = $p->device;
        return $argv;
    }

    /** @param string $configFile a file from writeSettingsFile(); never /dev/stdin, which carries the secret */
    public function settingsArgv(Plan $p, string $configFile): array
    {
        return [$this->env->bin('pppoectl'), '-S', '-f', $configFile, $p->device];
    }

    /** the -f file content: the settings lines, never the secret */
    public function settingsFile(Plan $p): string
    {
        return implode("\n", $this->settingsLines($p)) . "\n";
    }

    /** new 0600 -f file (O_EXCL, random name, umask 077); caller holds the device lock and unlinks it */
    public function writeSettingsFile(Plan $p): string
    {
        $dir = $this->env->runDir();
        Fs::ensureDir($dir, 0700);
        /* leftovers of a configure killed mid-call (the hook's timeout); we hold the device lock */
        foreach (glob("{$dir}/pppoectl.{$p->device}.*.conf") ?: [] as $stale) {
            @unlink($stale);
        }
        $data = $this->settingsFile($p);
        $fh = false;
        $file = '';
        $old = umask(0077);
        try {
            for ($i = 0; $i < 5 && $fh === false; $i++) {
                $file = "{$dir}/pppoectl.{$p->device}." . bin2hex(random_bytes(8)) . '.conf';
                $fh = @fopen($file, 'x');
            }
        } finally {
            umask($old);
        }
        if ($fh === false) {
            throw new \RuntimeException("cannot create a pppoectl settings file in {$dir}");
        }
        $ok = @chmod($file, 0600) && @fwrite($fh, $data) === strlen($data) && @fflush($fh) && @fsync($fh);
        $ok = @fclose($fh) && $ok;
        if (!$ok) {
            @unlink($file);
            throw new \RuntimeException("cannot write the pppoectl settings file {$file}");
        }
        return $file;
    }

    /** $fn(string $configFile) with a settings file that is unlinked on every path */
    public function withSettingsFile(Plan $p, callable $fn): mixed
    {
        $file = $this->writeSettingsFile($p);
        try {
            return $fn($file);
        } finally {
            @unlink($file);
        }
    }

    /** config lines (without the secret line) */
    public function settingsLines(Plan $p): array
    {
        return [
            /* accept whichever of PAP/CHAP the AC asks for, like mpd5 "accept chap pap" */
            'myauthproto=chap',
            'passiveauthproto',
            'myauthname=' . self::escape($p->username),
            /* we never authenticate the AC (mpd5 "disable chap pap") */
            'hisauthproto=none',
            /* never stop redialling after auth failures (mpd5 "max-redial 0") */
            'max-auth-failure=0',
            $p->ipcp ? 'ipcp' : 'noipcp',
            $p->ipv6cp ? 'ipv6cp' : 'noipv6cp',
            'query-dns=' . ($p->queryDns ? '3' : '0'),
            /* in-kernel TCP MSS clamp (p3-mss); off only when core's <tcpmssfix/> asks for it */
            $p->mssfix ? 'mssfix' : 'nomssfix',
        ];
    }

    public function verifyArgv(Plan $p): array
    {
        return [$this->env->bin('pppoectl'), $p->device];
    }

    /**
     * Check `pppoectl <dev>` list output against the plan.
     * @return string|null what did not stick, or null when everything did
     */
    public static function verify(Plan $p, string $out): ?string
    {
        if (!preg_match('/^\s*myauthproto=(\S+) myauthname="(.*)"$/m', $out, $m)) {
            return 'myauthproto/myauthname not applied';
        }
        if ($m[1] !== 'chap') {
            return "myauthproto is {$m[1]}, expected chap";
        }
        if ($m[2] !== $p->username) {
            return 'myauthname does not match the configured username';
        }
        if (preg_match('/^\s*hisauthproto=/m', $out)) {
            return 'hisauthproto is set, expected none';
        }
        if (!preg_match('/^\s*max-auth-failure = ([0-9]+)$/m', $out, $m) || $m[1] !== '0') {
            return 'max-auth-failure is not 0';
        }
        foreach (['ipcp' => $p->ipcp, 'ipv6cp' => $p->ipv6cp] as $ncp => $want) {
            if (!preg_match("/^\\s*{$ncp}: (enable|disable)$/m", $out, $m) || ($m[1] === 'enable') !== $want) {
                return "{$ncp} is not " . ($want ? 'enabled' : 'disabled');
            }
        }
        /* the "mssfix:" line exists only when pppoectl was built with PPPOEGETMSSFIX (p3-mss) */
        if (preg_match('/^\s*mssfix: (enable|disable)$/m', $out, $m) && ($m[1] === 'enable') !== $p->mssfix) {
            return 'mssfix is not ' . ($p->mssfix ? 'enabled' : 'disabled');
        }
        return null;
    }

    /** step 2 stdin: the secret line and nothing else */
    public function settingsStdin(Plan $p): string
    {
        if (strpbrk($p->password, "\0\n\r") !== false) {
            throw new \InvalidArgumentException('secret contains NUL, CR or LF');
        }
        return $p->password . "\n";
    }
}
