<?php

/*
 * Functional harness: runs the real interface_ppps_reset() and
 * interface_ppps_configure() from an (optionally patched) interfaces.inc
 * against stubbed core helpers, and prints one JSON line per scenario.
 *
 *   php harness.php <interfaces.inc>
 *
 * The two functions are evaluated inside a private namespace, where
 * unqualified calls resolve to the stubs below before PHP's globals, so
 * nothing touches the host (no mpd5, no /var/etc writes).
 */

$file = $argv[1] ?? '';
$s = file_get_contents($file);
if ($s === false) {
    fwrite(STDERR, "cannot read $file\n");
    exit(2);
}

function extract_fn($s, $fn)
{
    $a = strpos($s, "\nfunction $fn(");
    $b = strpos($s, "\n}\n", $a);
    return substr($s, $a + 1, $b - $a + 2);
}

$stubs = <<<'PHP'
namespace H;
class R {
    public static $calls = [];
    public static $engine_rc = 0;
    public static $engine_exe = true;
    public static $engine_throw = false;
}
function rec(...$a) { R::$calls[] = $a; }
function is_executable($p) { rec('is_executable', $p); return R::$engine_exe; }
function mwexecf($f, $a = [], $m = false) {
    rec('mwexecf', $f, $a, $m);
    if (strpos($f, '/if_pppoe/engine ') !== false) {
        if (R::$engine_throw) { throw new \Error('engine boom'); }
        return R::$engine_rc;
    }
    return 0;
}
function mwexecfb($f, $a = [], $p = null, $l = null) { rec('mwexecfb', $f, $a); return 0; }
function shell_safe($f, $a = []) { rec('shell_safe', $f, $a); return ''; }
function killbypid($p) { rec('killbypid', $p); }
function configdp_run($c, $a = [], $d = false) { rec('configdp_run', $c, $a); }
function legacy_interface_flags($i, $f, $r = true) { rec('legacy_interface_flags', $i, $f); }
function legacy_interface_mtu($i, $m) { rec('legacy_interface_mtu', $i, $m); }
function legacy_interface_setaddress($i, $a) { rec('legacy_interface_setaddress', $i, $a); }
function get_real_interface($p) { return $p === 'wanport' ? 'igb0' : $p; }
function get_interface_ip($i) { return '192.0.2.1'; }
function is_ipaddr($a) { return true; }
function interface_ppps_capable($ifcfg, $ppps) { return is_array($ifcfg) && isset($ifcfg['if']) && strpos($ifcfg['if'], 'pppoe') === 0; }
function does_interface_exist($i) { return true; }
function file_put_contents($f, $d, $fl = 0) { rec('file_put_contents', $f); return strlen($d); }
function file_exists($f) { return false; }
function copy($a, $b) { return true; }
function touch($f) { return true; }
function unlink($f) { rec('unlink', $f); return true; }
function sleep($n) { return 0; }
function log_msg($m, $p = 0) { rec('log_msg', $m); }
PHP;

eval($stubs . "\n" . extract_fn($s, 'interface_ppps_reset') . "\n" . extract_fn($s, 'interface_ppps_configure'));

function scenario($name, $ppp, $rc, $exe = true, $throw = false)
{
    global $config;
    $config = [
        'interfaces' => ['wan' => ['if' => 'pppoe0', 'enable' => '1', 'ipaddr' => 'pppoe', 'descr' => 'WAN']],
        'ppps' => ['ppp' => [array_merge(['if' => 'pppoe0', 'type' => 'pppoe', 'ports' => 'wanport',
            'username' => 'u', 'password' => base64_encode('p'), 'ptpid' => '0'], $ppp)]],
        'system' => [],
    ];
    \H\R::$calls = [];
    \H\R::$engine_rc = $rc;
    \H\R::$engine_exe = $exe;
    \H\R::$engine_throw = $throw;
    \H\interface_ppps_reset('wan', false, $config['interfaces']['wan'], $config['ppps']['ppp']);
    \H\interface_ppps_configure('wan');
    $engine = [];
    $mpd5 = 0;
    $kill = 0;
    foreach (\H\R::$calls as $c) {
        if ($c[0] === 'mwexecf' && strpos($c[1], '/if_pppoe/engine ') !== false) {
            $engine[] = preg_replace('/^.*engine (\w+).*$/', '$1', $c[1]) . ':' . implode('|', $c[2]) . ($c[3] === true ? ':mute' : ':loud');
        }
        if ($c[0] === 'mwexecf' && strpos($c[1], '/usr/local/sbin/mpd5') !== false) {
            $mpd5++;
        }
        if ($c[0] === 'killbypid') {
            $kill++;
        }
    }
    echo json_encode(['scenario' => $name, 'engine' => $engine, 'mpd5' => $mpd5, 'killbypid' => $kill]) . "\n";
}

scenario('claimed', [], 0);
scenario('ineligible', [], 1);
scenario('timeout', [], 124);
scenario('no-engine', [], 0, false);
scenario('engine-throws', [], 0, true, true);
scenario('mtu-mru', ['mtu' => '1500', 'mru' => '1492'], 0);
