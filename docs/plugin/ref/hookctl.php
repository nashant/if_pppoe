<?php
/* os-if-pppoe reference hookctl: apply | revert | status  [target]  (exact-context, unique, in-function) */
const MARK = '/* os-if-pppoe:v1 */';
const HOOK = "'/usr/local/opnsense/scripts/if_pppoe/hook.inc'";
function hook_line($verb) {
    $call = $verb == 'configure'
        ? "&& if_pppoe_hook('configure', get_defined_vars())) { return; }"
        : ") { if_pppoe_hook('reset', get_defined_vars()); }";
    $msg = $verb == 'configure' ? 'configure hook failed, using mpd5: ' : 'reset hook failed: ';
    return '    ' . MARK . ' try { if (is_file(' . HOOK . ') && (include_once ' . HOOK . ") && function_exists('if_pppoe_hook')" . ($verb == 'configure' ? ' ' : '') . "$call } catch (\\Throwable \$if_pppoe_e) { log_msg('os-if-pppoe: $msg' . \$if_pppoe_e->getMessage(), LOG_ERR); }\n";
}
/* [function, context-before, context-after]; the hook line goes between them */
function sites() { return [
  'reset' => ['interface_ppps_reset',
     "function interface_ppps_reset(\$interface, \$suspend, \$ifcfg, \$ppps)\n{\n",
     "    if (!interface_ppps_capable(\$ifcfg, \$ppps)) {\n"],
  'configure' => ['interface_ppps_configure',
     "    legacy_interface_flags(\$ifcfg['if'], 'down', false);\n\n",
     "    /* fire up mpd */\n    mwexecf(\n        '/usr/local/sbin/mpd5 -b -d /var/etc -f %s -p %s -s ppp %s',\n"],
]; }
function fn_span($s, $fn) {            /* byte span of "function fn(" .. first "\n}\n" */
    $a = strpos($s, "\nfunction $fn(");
    if ($a === false || strpos($s, "\nfunction $fn(", $a + 1) !== false) return null;
    $b = strpos($s, "\n}\n", $a); return $b === false ? null : [$a, $b];
}
function apply_str($s, &$err) {
    if (strpos($s, MARK) !== false) { $err = 'already'; return null; }
    if (strpos($s, 'os-if-pppoe:') !== false) { $err = 'foreign/old marker present'; return null; }
    foreach (sites() as $verb => [$fn, $pre, $post]) {
        $ctx = $pre . $post;
        if (substr_count($s, $ctx) !== 1) { $err = "$verb: context not found exactly once"; return null; }
        $at = strpos($s, $ctx); $span = fn_span($s, $fn);
        if (!$span || $at < $span[0] || $at > $span[1]) { $err = "$verb: context outside $fn()"; return null; }
        $s = substr($s, 0, $at) . $pre . hook_line($verb) . $post . substr($s, $at + strlen($ctx));
    }
    return $s;
}
function revert_str($s, &$err) {
    foreach (['reset', 'configure'] as $verb) {
        $l = hook_line($verb);
        if (substr_count($s, $l) !== 1) { $err = "$verb: our exact line not found once"; return null; }
        $s = str_replace($l, '', $s);
    }
    if (strpos($s, 'os-if-pppoe:') !== false) { $err = 'marker still present'; return null; }
    return $s;
}
function atomic_write($path, $data) {
    $tmp = dirname($path) . '/.' . basename($path) . '.if_pppoe.' . getmypid();
    if (file_put_contents($tmp, $data) !== strlen($data)) { @unlink($tmp); return false; }
    $st = stat($path); chmod($tmp, $st['mode'] & 07777); @chown($tmp, $st['uid']); @chgrp($tmp, $st['gid']);
    exec('/usr/bin/env php -l ' . escapeshellarg($tmp) . ' 2>&1', $o, $rc);
    if ($rc !== 0) { @unlink($tmp); fwrite(STDERR, implode("\n", $o) . "\n"); return false; }
    return rename($tmp, $path);   /* same directory => atomic */
}
[$_, $cmd, $target] = $argv + [null, 'status', '/usr/local/etc/inc/interfaces.inc'];
$s = file_get_contents($target); $err = '';
switch ($cmd) {
case 'status': echo strpos($s, MARK) !== false ? "applied\n" : (apply_str($s, $err) !== null ? "pristine-applicable\n" : "incompatible: $err\n"); exit(0);
case 'apply':  $n = apply_str($s, $err); if ($n === null) { echo "refused: $err\n"; exit($err == 'already' ? 0 : 2); }
               if (revert_str($n, $e2) !== $s) { echo "refused: round-trip check failed\n"; exit(2); }
               @mkdir('/tmp/bk', 0700, true); file_put_contents('/tmp/bk/interfaces.inc.' . hash('sha256', $s), $s);
               exit(atomic_write($target, $n) ? 0 : 3);
case 'revert': if (strpos($s, MARK) === false) { echo "nothing to revert\n"; exit(0); }
               $n = revert_str($s, $err); if ($n === null) { echo "refused: $err\n"; exit(2); }
               exit(atomic_write($target, $n) ? 0 : 3);
}
