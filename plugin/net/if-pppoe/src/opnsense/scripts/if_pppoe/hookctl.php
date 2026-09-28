#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 os-if-pppoe authors
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

/*
 * hookctl: insert / remove the two os-if-pppoe hook lines in core's
 * /usr/local/etc/inc/interfaces.inc.
 *
 *   hookctl.php apply    [--reapply] [--reason=R] [--target=F]
 *   hookctl.php revert   [--reason=R] [--target=F]
 *   hookctl.php status   [--json] [--target=F]
 *   hookctl.php selftest [--target=F]
 *
 * Exit codes: 0 done / nothing to do, 2 refused (see status), 3 I/O
 * failure, 64 usage.
 *
 * This script is only ever run as its own process (early/update syshooks,
 * pkg trigger, configd, cron).  It is never included by core code.  It
 * needs no PHP extension beyond what OPNsense core depends on (no
 * tokenizer: core does not depend on php-tokenizer).
 *
 * Test/relocation knobs (environment, defaults are the production paths):
 *   IF_PPPOE_CONF_DIR   /conf/if_pppoe
 *   IF_PPPOE_RUN_DIR    /var/run/if_pppoe
 *   IF_PPPOE_TARGET     /usr/local/etc/inc/interfaces.inc
 *   IF_PPPOE_CORE_META  /usr/local/opnsense/version/core
 *   IF_PPPOE_CONFIG_XML /conf/config.xml
 *   IF_PPPOE_PKG        /usr/local/sbin/pkg   ("" disables the pkg checksum probe)
 *   IF_PPPOE_PKG_FILE   /usr/local/etc/inc/interfaces.inc (path looked up in pkg query)
 */

const HOOK_VERSION = 'v1';
const MARK = '/* os-if-pppoe:v1 */';
const MARK_ANY = 'os-if-pppoe:';
const ENGINE = '/usr/local/opnsense/scripts/if_pppoe/engine';
const KEEP_BACKUPS = 3;

const RC_OK = 0;
const RC_REFUSED = 2;
const RC_IO = 3;
const RC_USAGE = 64;

function env_or($name, $default)
{
    $v = getenv($name);
    return ($v === false) ? $default : $v;
}

function conf_dir()
{
    return env_or('IF_PPPOE_CONF_DIR', '/conf/if_pppoe');
}

function run_dir()
{
    return env_or('IF_PPPOE_RUN_DIR', '/var/run/if_pppoe');
}

/*
 * The two canonical hook lines.  They are the whole contract with core:
 * byte-for-byte what apply inserts and what revert removes.
 *
 * - configure: engine exit 0 means "claimed": return before mpd5 is
 *   started.  Anything else (ineligible, error, timeout, engine missing,
 *   any Throwable) falls through to stock mpd5.
 * - reset: result ignored; core's killbypid() always runs afterwards.
 * - mute=true: a non-zero engine exit is the normal "not ours" answer and
 *   must not spam the system log; the engine logs its own reasons.
 * - Only non-secret scalars travel on argv.
 */
function hook_line($verb)
{
    if ($verb === 'reset') {
        return '    ' . MARK . " try { if (is_executable('" . ENGINE . "')) { mwexecf('/bin/timeout -k 5 45 " . ENGINE .
            " reset %s %s', [\$interface, \$ifcfg['if'] ?? ''], true); } } catch (\\Throwable \$if_pppoe_e) { }\n";
    }
    return '    ' . MARK . " try { if (is_executable('" . ENGINE . "') && mwexecf('/bin/timeout -k 5 45 " . ENGINE .
        " configure %s %s %s %s %s', [\$interface, \$ifcfg['if'] ?? '', implode(',', (array)(\$ports ?? [])), " .
        "(string)(\$mtus[0] ?? ''), (string)(\$mrus[0] ?? '')], true) === 0) { return; } } catch (\\Throwable \$if_pppoe_e) { }\n";
}

/* [function, context-before, context-after]; the hook line goes between them */
function sites()
{
    return [
        'reset' => [
            'interface_ppps_reset',
            "function interface_ppps_reset(\$interface, \$suspend, \$ifcfg, \$ppps)\n{\n",
            "    if (!interface_ppps_capable(\$ifcfg, \$ppps)) {\n",
        ],
        'configure' => [
            'interface_ppps_configure',
            "    legacy_interface_flags(\$ifcfg['if'], 'down', false);\n\n",
            "    /* fire up mpd */\n    mwexecf(\n        '/usr/local/sbin/mpd5 -b -d /var/etc -f %s -p %s -s ppp %s',\n",
        ],
    ];
}

/* byte span of "\nfunction fn(" .. first "\n}\n"; null if absent or declared twice */
function fn_span($s, $fn)
{
    $needle = "\nfunction $fn(";
    $a = strpos($s, $needle);
    if ($a === false || strpos($s, $needle, $a + 1) !== false) {
        return null;
    }
    $b = strpos($s, "\n}\n", $a);
    return $b === false ? null : [$a, $b];
}

function apply_str($s, &$err)
{
    if (strpos($s, MARK_ANY) !== false) {
        $err = 'marker-present';
        return null;
    }
    foreach (sites() as $verb => [$fn, $pre, $post]) {
        $ctx = $pre . $post;
        if (substr_count($s, $ctx) !== 1) {
            $err = "anchor:$verb";
            return null;
        }
        $at = strpos($s, $ctx);
        $span = fn_span($s, $fn);
        if ($span === null || $at < $span[0] || $at > $span[1]) {
            $err = "anchor:$verb";
            return null;
        }
        $s = substr($s, 0, $at) . $pre . hook_line($verb) . $post . substr($s, $at + strlen($ctx));
    }
    return $s;
}

function revert_str($s, &$err)
{
    foreach (array_keys(sites()) as $verb) {
        $l = hook_line($verb);
        if (substr_count($s, $l) !== 1) {
            $err = "line:$verb";
            return null;
        }
        $s = str_replace($l, '', $s);
    }
    if (strpos($s, MARK_ANY) !== false) {
        $err = 'marker-left';
        return null;
    }
    return $s;
}

/*
 * Classify file content:
 *   applied     both canonical lines exactly once, each at its anchor,
 *               nothing else of ours, and revert(x) is applicable again
 *   pristine    no marker, both anchors present exactly once in-function
 *   anchor      no marker, anchors do not match (unsupported core)
 *   foreign     some os-if-pppoe marker, but not exactly our v1 lines
 */
function classify($s, &$detail = null)
{
    $detail = '';
    if (strpos($s, MARK_ANY) === false) {
        $err = '';
        if (apply_str($s, $err) !== null) {
            return 'pristine';
        }
        $detail = $err;
        return 'anchor';
    }
    $err = '';
    $r = revert_str($s, $err);
    if ($r === null) {
        $detail = $err;
        return 'foreign';
    }
    $e2 = '';
    if (apply_str($r, $e2) !== $s) {
        /* our lines exist but not at the anchors */
        $detail = 'misplaced';
        return 'foreign';
    }
    return 'applied';
}

function core_version()
{
    $meta = env_or('IF_PPPOE_CORE_META', '/usr/local/opnsense/version/core');
    $raw = @file_get_contents($meta);
    if ($raw !== false) {
        $j = json_decode($raw, true);
        if (is_array($j)) {
            foreach (['product_version', 'CORE_PKGVERSION'] as $k) {
                if (!empty($j[$k]) && is_string($j[$k])) {
                    return $j[$k];
                }
            }
        }
    }
    return 'unknown';
}

function safe_token($v)
{
    return preg_replace('/[^A-Za-z0-9._+-]/', '_', $v);
}

function state_path()
{
    return conf_dir() . '/hook.json';
}

function state_load()
{
    $raw = @file_get_contents(state_path());
    $j = $raw === false ? null : json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function write_file_atomic($path, $data, $mode)
{
    $tmp = dirname($path) . '/.' . basename($path) . '.tmp.' . getmypid();
    $fh = @fopen($tmp, 'xb');
    if ($fh === false) {
        return false;
    }
    $ok = fwrite($fh, $data) === strlen($data);
    if ($ok && function_exists('fsync')) {
        $ok = fsync($fh);
    }
    $ok = fclose($fh) && $ok;
    $ok = $ok && chmod($tmp, $mode) && rename($tmp, $path);
    if (!$ok) {
        @unlink($tmp);
    }
    return $ok;
}

function state_save(array $st)
{
    @mkdir(conf_dir(), 0700, true);
    $st['hook_version'] = HOOK_VERSION;
    $st['updated_at'] = time();
    return write_file_atomic(state_path(), json_encode($st, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n", 0600);
}

function logmsg($msg, $prio = LOG_NOTICE)
{
    if (getenv('IF_PPPOE_NO_SYSLOG') === false) {
        openlog('if_pppoe-hookctl', LOG_PID, LOG_USER);
        syslog($prio, $msg);
        closelog();
    }
    fwrite(STDERR, "hookctl: $msg\n");
}

/*
 * Hook refusal on HA boxes (contract: standalone only).  Reads config.xml
 * directly; a missing/unreadable file is not treated as HA.
 */
function ha_configured(&$why)
{
    $path = env_or('IF_PPPOE_CONFIG_XML', '/conf/config.xml');
    if (!is_readable($path) || !function_exists('simplexml_load_file')) {
        return false;
    }
    $prev = libxml_use_internal_errors(true);
    $x = simplexml_load_file($path);
    libxml_use_internal_errors($prev);
    if ($x === false) {
        return false;
    }
    foreach ($x->xpath('/*/virtualip/vip') ?: [] as $vip) {
        if (trim((string)$vip->mode) === 'carp') {
            $why = 'carp-vip';
            return true;
        }
    }
    /* same three fields as the engine (Config::haReason) and the GUI (Support::standaloneViolation) */
    foreach (['synchronizetoip', 'pfsyncinterface', 'pfsyncpeerip'] as $k) {
        $n = $x->xpath("/*/hasync/$k");
        if (!empty($n) && trim((string)$n[0]) !== '') {
            $why = "hasync-$k";
            return true;
        }
    }
    return false;
}

/*
 * Optional pristine proof against the pkg database.  pkg-query(8) %Fs is
 * the stored checksum; its exact encoding is not documented, so the last
 * 64 hex digits are compared.  Returns true (matches), false (differs) or
 * null (could not determine; the caller then relies on the anchors).
 */
function pkg_says_pristine($sha)
{
    $target = env_or('IF_PPPOE_PKG_FILE', '/usr/local/etc/inc/interfaces.inc');
    $pkg = env_or('IF_PPPOE_PKG', '/usr/local/sbin/pkg');
    if ($pkg === '' || !is_executable($pkg)) {
        return null;
    }
    $out = [];
    $rc = 1;
    exec('/bin/timeout 20 ' . escapeshellarg($pkg) . " query '%Fp %Fs' opnsense 2>/dev/null", $out, $rc);
    if ($rc !== 0) {
        return null;
    }
    foreach ($out as $line) {
        $p = strrpos($line, ' ');
        if ($p !== false && substr($line, 0, $p) === $target) {
            if (preg_match('/([0-9a-f]{64})$/i', substr($line, $p + 1), $m)) {
                return strtolower($m[1]) === $sha;
            }
            return null;
        }
    }
    return null;
}

function php_lint($file, &$out)
{
    $o = [];
    $rc = 1;
    exec(escapeshellarg(PHP_BINARY) . ' -n -l ' . escapeshellarg($file) . ' 2>&1', $o, $rc);
    $out = implode("\n", $o);
    return $rc === 0;
}

/*
 * Atomic replace of the target: temp file in the same directory, copy
 * mode/owner, php -l, compare-and-swap against the content we planned
 * from, rename.
 */
function atomic_replace($path, $expect_sha, $data, &$err)
{
    $st = @stat($path);
    if ($st === false) {
        $err = 'write:stat';
        return false;
    }
    $tmp = dirname($path) . '/.' . basename($path) . '.if_pppoe.' . getmypid();
    @unlink($tmp);
    $fh = @fopen($tmp, 'xb');
    if ($fh === false) {
        $err = 'write:open';
        return false;
    }
    $ok = fwrite($fh, $data) === strlen($data);
    if ($ok && function_exists('fsync')) {
        $ok = fsync($fh);
    }
    $ok = fclose($fh) && $ok;
    if (!$ok) {
        @unlink($tmp);
        $err = 'write:data';
        return false;
    }
    @chmod($tmp, $st['mode'] & 07777);
    @chown($tmp, $st['uid']);
    @chgrp($tmp, $st['gid']);
    $lint = '';
    if (!php_lint($tmp, $lint)) {
        @unlink($tmp);
        $err = 'lint';
        logmsg("php -l failed on candidate: $lint", LOG_ERR);
        return false;
    }
    clearstatcache();
    $now = @file_get_contents($path);
    if ($now === false || hash('sha256', $now) !== $expect_sha) {
        @unlink($tmp);
        $err = 'write:concurrent-change';
        return false;
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        $err = 'write:rename';
        return false;
    }
    return true;
}

function backup_dir()
{
    return conf_dir() . '/pristine';
}

function backup_path($ver, $sha)
{
    return backup_dir() . '/interfaces.inc.' . safe_token($ver) . '.' . $sha;
}

function backup_store($ver, $sha, $data)
{
    @mkdir(backup_dir(), 0700, true);
    $p = backup_path($ver, $sha);
    if (!is_file($p) || hash_file('sha256', $p) !== $sha) {
        if (!write_file_atomic($p, $data, 0600)) {
            return false;
        }
    } else {
        @touch($p);
    }
    $all = glob(backup_dir() . '/interfaces.inc.*') ?: [];
    usort($all, function ($a, $b) {
        return filemtime($b) <=> filemtime($a);
    });
    foreach (array_slice($all, KEEP_BACKUPS) as $old) {
        @unlink($old);
    }
    return true;
}

function lock_acquire()
{
    $d = run_dir() . '/lock';
    @mkdir($d, 0700, true);
    $fh = @fopen("$d/hookctl", 'c');
    if ($fh === false || !flock($fh, LOCK_EX)) {
        return null;
    }
    return $fh;
}

/* ---------------------------------------------------------------------- */

function parse_args(array $argv)
{
    $o = ['cmd' => $argv[1] ?? '', 'reapply' => false, 'json' => false, 'reason' => 'manual',
          'target' => env_or('IF_PPPOE_TARGET', '/usr/local/etc/inc/interfaces.inc')];
    foreach (array_slice($argv, 2) as $a) {
        if ($a === '--reapply') {
            $o['reapply'] = true;
        } elseif ($a === '--json') {
            $o['json'] = true;
        } elseif (strpos($a, '--reason=') === 0) {
            $o['reason'] = safe_token(substr($a, 9));
        } elseif (strpos($a, '--target=') === 0) {
            $o['target'] = substr($a, 9);
        } else {
            return null;
        }
    }
    return $o;
}

function finish(array $st, $status, $rc, $detail = '')
{
    $st['status'] = $status;
    $st['detail'] = $detail;
    if (!state_save($st)) {
        logmsg('could not write ' . state_path(), LOG_ERR);
    }
    echo $status . ($detail !== '' ? " ($detail)" : '') . "\n";
    return $rc;
}

function cmd_apply(array $o)
{
    $target = $o['target'];
    $st = state_load();
    $st['reason'] = $o['reason'];
    $s = @file_get_contents($target);
    if ($s === false) {
        return finish($st, 'refused:read', RC_IO, $target);
    }
    $sha = hash('sha256', $s);
    $ver = core_version();
    $detail = '';
    $live = classify($s, $detail);
    $prev = $st['status'] ?? '';

    if ($live === 'applied') {
        $st['patched_sha256'] = $sha;
        $st['core_version'] = $ver;
        return finish($st, 'applied', RC_OK);
    }

    if ($o['reapply']) {
        /*
         * Post-update paths (update syshook, pkg trigger, cron): only put
         * the hook back where it was meant to be.  Never turn a reverted,
         * refused or paused state into applied.
         */
        if ($prev !== 'applied') {
            echo ($prev === '' ? 'reverted' : $prev) . " (reapply: nothing to do)\n";
            return $prev === '' || $prev === 'reverted' ? RC_OK : RC_REFUSED;
        }
        if ($live === 'pristine' && ($st['core_version'] ?? '') === $ver && ($st['pristine_sha256'] ?? '') === $sha) {
            /* same core version, same pristine file: a deliberate core reinstall (repair) */
            logmsg("core $ver reinstalled; hook paused until kernel mode is re-applied", LOG_WARNING);
            $st['paused_at'] = time();
            return finish($st, 'paused:core-reinstall', RC_REFUSED, $ver);
        }
    } elseif ($prev === 'paused:core-reinstall') {
        /* boot/manual: the pause is lifted by re-applying in the GUI, which rewrites 'desired' */
        $desired = conf_dir() . '/desired';
        clearstatcache();
        $dm = @filemtime($desired);
        if ($dm === false || $dm <= (int)($st['paused_at'] ?? PHP_INT_MAX)) {
            echo "paused:core-reinstall (re-apply in Services to resume)\n";
            return RC_REFUSED;
        }
    }

    if ($live === 'foreign') {
        return finish($st, 'foreign', RC_REFUSED, $detail);
    }
    if ($live === 'anchor') {
        logmsg("interfaces.inc of core $ver does not match the v1 anchors ($detail)", LOG_WARNING);
        return finish($st, 'refused:anchor', RC_REFUSED, $detail);
    }

    $why = '';
    if (ha_configured($why)) {
        return finish($st, 'refused:ha', RC_REFUSED, $why);
    }

    if ($o['reason'] !== 'update' && $o['reason'] !== 'trigger') {
        /* pkg DB may be locked while core's +POST_INSTALL runs: skip there */
        if (pkg_says_pristine($sha) === false) {
            return finish($st, 'foreign', RC_REFUSED, 'pkg-checksum');
        }
    }

    $err = '';
    $n = apply_str($s, $err);
    if ($n === null) {
        return finish($st, 'refused:anchor', RC_REFUSED, $err);
    }
    $e2 = '';
    if (revert_str($n, $e2) !== $s) {
        return finish($st, 'refused:roundtrip', RC_REFUSED);
    }
    if (!backup_store($ver, $sha, $s)) {
        return finish($st, 'refused:backup', RC_IO, backup_dir());
    }
    if (!atomic_replace($target, $sha, $n, $err)) {
        return finish($st, "refused:$err", $err === 'lint' ? RC_REFUSED : RC_IO);
    }
    $stout = '';
    if (!selftest_file($target, $stout)) {
        $e3 = '';
        if (!atomic_replace($target, hash('sha256', $n), $s, $e3)) {
            logmsg("selftest failed AND restore failed ($e3); run 'hookctl revert'", LOG_ERR);
        }
        return finish($st, 'refused:selftest', RC_REFUSED, $stout);
    }
    $st['core_version'] = $ver;
    $st['pristine_sha256'] = $sha;
    $st['patched_sha256'] = hash('sha256', $n);
    $st['applied_at'] = time();
    unset($st['paused_at']);
    logmsg("hook applied to $target (core $ver, reason {$o['reason']})");
    return finish($st, 'applied', RC_OK);
}

function cmd_revert(array $o)
{
    $target = $o['target'];
    $st = state_load();
    $st['reason'] = $o['reason'];
    $s = @file_get_contents($target);
    if ($s === false) {
        return finish($st, 'refused:read', RC_IO, $target);
    }
    $sha = hash('sha256', $s);
    $ver = core_version();

    if (strpos($s, MARK_ANY) === false) {
        unset($st['paused_at']);
        return finish($st, 'reverted', RC_OK, 'nothing to revert');
    }

    $want = ($st['core_version'] ?? null) === $ver ? ($st['pristine_sha256'] ?? null) : null;
    $err = '';
    $n = revert_str($s, $err);
    if ($n !== null && $want !== null && hash('sha256', $n) !== $want) {
        $err = 'sha-mismatch';
        $n = null;
    }
    if ($n === null && $want !== null) {
        /* line removal impossible or inexact: fall back to the pristine copy of this very core */
        $b = backup_path($ver, $want);
        $data = @file_get_contents($b);
        if ($data !== false && hash('sha256', $data) === $want) {
            logmsg("line removal failed ($err); restoring pristine backup $b", LOG_WARNING);
            $n = $data;
        }
    }
    if ($n === null) {
        return finish($st, 'refused:revert', RC_REFUSED, $err);
    }
    if (!atomic_replace($target, $sha, $n, $err)) {
        return finish($st, "refused:$err", $err === 'lint' ? RC_REFUSED : RC_IO);
    }
    unset($st['paused_at']);
    logmsg("hook reverted in $target (reason {$o['reason']})");
    return finish($st, 'reverted', RC_OK);
}

function cmd_status(array $o)
{
    $st = state_load();
    $s = @file_get_contents($o['target']);
    $detail = '';
    $live = $s === false ? 'unreadable' : classify($s, $detail);
    $stored = $st['status'] ?? ($live === 'applied' ? 'applied' : 'reverted');
    if ($o['json']) {
        $st['status'] = $stored;
        $st['live'] = $live;
        $st['live_detail'] = $detail;
        $st['consistent'] = ($stored === 'applied') === ($live === 'applied');
        $st['current_core_version'] = core_version();
        echo json_encode($st, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo "$stored\n";
    }
    return RC_OK;
}

/*
 * Self-test of a patched file, in a child PHP process so that nothing it
 * evaluates can hurt the caller:
 *   1. php -l
 *   2. classify() == applied (each line once, at its anchor, in-function)
 *   3. the exact bytes of both lines are evaluated inside stub functions
 *      in a private namespace (is_executable/mwexecf shadowed) to prove
 *      the control flow: configure returns only on engine exit 0; reset
 *      never returns early; exceptions and a missing engine fall through.
 */
function selftest_file($file, &$out)
{
    $o = [];
    $rc = 1;
    exec(escapeshellarg(PHP_BINARY) . ' -n ' . escapeshellarg(__FILE__) . ' __selftest-child ' .
        escapeshellarg($file) . ' 2>&1', $o, $rc);
    $out = implode(' ', $o);
    return $rc === 0;
}

function selftest_child($file)
{
    $s = @file_get_contents($file);
    if ($s === false) {
        echo "unreadable\n";
        return 1;
    }
    $lint = '';
    if (!php_lint($file, $lint)) {
        echo "lint: $lint\n";
        return 1;
    }
    $d = '';
    if (($c = classify($s, $d)) !== 'applied') {
        echo "classify: $c $d\n";
        return 1;
    }
    $ns = 'IfPppoeSelftest' . getmypid();
    $code = "namespace $ns;\n" .
        "class R { public static \$calls = []; public static \$rc = 0; public static \$exe = true; public static \$throw = false; }\n" .
        "function is_executable(\$p) { R::\$calls[] = ['exe', \$p]; return R::\$exe; }\n" .
        "function mwexecf(\$f, \$a = [], \$m = false) { R::\$calls[] = ['run', \$f, \$a, \$m]; " .
        "if (R::\$throw) { throw new \\RuntimeException('boom'); } return R::\$rc; }\n" .
        "function reset_fn(\$interface, \$suspend, \$ifcfg, \$ppps) {\n" . hook_line('reset') . "    return 'fell';\n}\n" .
        "function configure_fn(\$interface, \$ifcfg, \$ports, \$mtus, \$mrus) {\n" . hook_line('configure') . "    return 'fell';\n}\n";
    /* prove the evaluated bytes are the bytes in the file */
    foreach (['reset', 'configure'] as $v) {
        if (substr_count($s, hook_line($v)) !== 1) {
            echo "line $v not in file\n";
            return 1;
        }
    }
    try {
        /* $code is built only from this script's constants (hook_line()), never from file content */
        eval($code);
    } catch (\Throwable $e) {
        echo 'eval: ' . $e->getMessage() . "\n";
        return 1;
    }
    $R = "\\$ns\\R";
    $cfg = "\\$ns\\configure_fn";
    $rst = "\\$ns\\reset_fn";
    $cases = [
        /* [exe, rc, throw, expect configure, expect reset] */
        [true, 0, false, null, 'fell'],
        [true, 1, false, 'fell', 'fell'],
        [true, 124, false, 'fell', 'fell'],
        [true, 0, true, 'fell', 'fell'],
        [false, 0, false, 'fell', 'fell'],
    ];
    foreach ($cases as $i => [$exe, $rc, $throw, $ec, $er]) {
        $R::$exe = $exe;
        $R::$rc = $rc;
        $R::$throw = $throw;
        $R::$calls = [];
        $got = $cfg('wan', ['if' => 'pppoe0'], ['igb0'], [1492], null);
        if ($got !== $ec) {
            echo "case $i: configure returned " . var_export($got, true) . "\n";
            return 1;
        }
        if ($exe && !$throw) {
            $call = $R::$calls[1] ?? null;
            $want = ['run', '/bin/timeout -k 5 45 ' . ENGINE . ' configure %s %s %s %s %s',
                     ['wan', 'pppoe0', 'igb0', '1492', ''], true];
            if ($call !== $want) {
                echo "case $i: configure argv " . json_encode($call) . "\n";
                return 1;
            }
        }
        $R::$calls = [];
        $got = $rst('wan', false, ['if' => 'pppoe0'], []);
        if ($got !== $er) {
            echo "case $i: reset returned " . var_export($got, true) . "\n";
            return 1;
        }
        if ($exe && !$throw) {
            $call = $R::$calls[1] ?? null;
            $want = ['run', '/bin/timeout -k 5 45 ' . ENGINE . ' reset %s %s', ['wan', 'pppoe0'], true];
            if ($call !== $want) {
                echo "case $i: reset argv " . json_encode($call) . "\n";
                return 1;
            }
        }
    }
    /* null ifcfg / missing locals must not escape as errors */
    $R::$exe = true;
    $R::$rc = 1;
    $R::$throw = false;
    if ($rst('wan', false, null, null) !== 'fell' || $cfg('wan', null, null, [], null) !== 'fell') {
        echo "null-arguments case failed\n";
        return 1;
    }
    echo "ok\n";
    return 0;
}

function cmd_selftest(array $o)
{
    $out = '';
    $ok = selftest_file($o['target'], $out);
    echo ($ok ? 'ok' : "failed: $out") . "\n";
    return $ok ? RC_OK : RC_REFUSED;
}

function main(array $argv)
{
    if (($argv[1] ?? '') === '__selftest-child') {
        return selftest_child($argv[2] ?? '');
    }
    $o = parse_args($argv);
    if ($o === null || !in_array($o['cmd'], ['apply', 'revert', 'status', 'selftest'], true)) {
        fwrite(STDERR, "usage: hookctl.php apply [--reapply] [--reason=R] | revert [--reason=R] | status [--json] | selftest  [--target=F]\n");
        return RC_USAGE;
    }
    if ($o['cmd'] === 'status') {
        return cmd_status($o);
    }
    if ($o['cmd'] === 'selftest') {
        return cmd_selftest($o);
    }
    $lock = lock_acquire();
    if ($lock === null) {
        fwrite(STDERR, "hookctl: cannot take lock\n");
        return RC_IO;
    }
    umask(077);
    return $o['cmd'] === 'apply' ? cmd_apply($o) : cmd_revert($o);
}

exit(main($argv));
