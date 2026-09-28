<?php

/* Recording stand-in for every binary the engine runs (see README.md); state in $IF_PPPOE_ROOT/fake. */

$root = getenv('IF_PPPOE_ROOT');
if ($root === false || $root === '') {
    fwrite(STDERR, "stub: IF_PPPOE_ROOT unset\n");
    exit(99);
}
$self = substr($argv[0], strlen($root));
$cmd = basename($self);
$args = array_slice($argv, 1);
$fake = "$root/fake";

$stdin = stream_get_contents(STDIN);
if ($stdin === '' || $stdin === false) {
    $stdin = null;
}
/* pppoectl -f <file>: record what the file held (and its mode) while pppoectl ran */
$ffile = null;
if ($cmd === 'pppoectl' && ($k = array_search('-f', $args, true)) !== false && isset($args[$k + 1])) {
    $fp = $args[$k + 1];
    clearstatcache();
    $ffile = ['path' => $fp, 'exists' => is_file($fp), 'mode' => is_file($fp) ? sprintf('%04o', fileperms($fp) & 07777) : null,
        'content' => is_file($fp) ? file_get_contents($fp) : null];
}
file_put_contents("$root/calls.jsonl", json_encode(['cmd' => $cmd, 'path' => $self, 'argv' => $args, 'stdin' => $stdin, 'ffile' => $ffile]) . "\n", FILE_APPEND | LOCK_EX);

/* failure injection: fake/fail.json = [["pppoectl","-S"], ...] argv prefixes (cmd first) */
$fails = json_decode((string)@file_get_contents("$fake/fail.json"), true) ?: [];
foreach ($fails as $prefix) {
    if (array_slice(array_merge([$cmd], $args), 0, count($prefix)) === $prefix) {
        fwrite(STDERR, "stub: injected failure\n");
        exit(1);
    }
}

/* hang injection: fake/hang.json = argv prefixes that sleep (for timeout(1) kill tests) */
$hangs = json_decode((string)@file_get_contents("$fake/hang.json"), true) ?: [];
foreach ($hangs as $prefix) {
    if (array_slice(array_merge([$cmd], $args), 0, count($prefix)) === $prefix) {
        sleep(60);
        exit(1);
    }
}

/* fparseln(3) with FPARSELN_UNESCALL and the default "\\\\#" delimiters, one line */
function fparseln_line(string $line): string
{
    $out = '';
    $n = strlen($line);
    for ($i = 0; $i < $n; $i++) {
        if ($line[$i] === '\\' && $i + 1 < $n) {
            $out .= $line[++$i];
        } elseif ($line[$i] === '#') {
            break;
        } else {
            $out .= $line[$i];
        }
    }
    return $out;
}

function ifpath($fake, $n) { return "$fake/ifaces/$n.json"; }
function ifget($fake, $n) { $f = ifpath($fake, $n); return is_file($f) ? json_decode(file_get_contents($f), true) : null; }
function ifput($fake, $n, $v) { @mkdir("$fake/ifaces", 0700, true); file_put_contents(ifpath($fake, $n), json_encode($v)); }

switch ($cmd) {
    case 'ifconfig':
        if (($args[0] ?? '') === '-g') {
            foreach (glob("$fake/ifaces/*.json") as $f) {
                $i = json_decode(file_get_contents($f), true);
                if (in_array($args[1], $i['groups'] ?? [], true)) {
                    echo basename($f, '.json') . "\n";
                }
            }
            exit(0);
        }
        $n = $args[0] ?? '';
        $op = $args[1] ?? null;
        $i = ifget($fake, $n);
        if ($op === 'create') {
            if ($i !== null) { fwrite(STDERR, "ifconfig: SIOCIFCREATE2: File exists\n"); exit(1); }
            ifput($fake, $n, ['flags' => ['UP', 'POINTOPOINT', 'MULTICAST'], 'mtu' => 1492, 'groups' => ['pppoe'], 'ether' => false]);
            echo "$n\n";
            exit(0);
        }
        if ($i === null) { fwrite(STDERR, "ifconfig: interface $n does not exist\n"); exit(1); }
        switch ($op) {
            case null:
                printf("%s: flags=8051<%s> metric 0 mtu %d\n", $n, implode(',', $i['flags']), $i['mtu']);
                if (!empty($i['ether'])) { echo "\tether 00:11:22:33:44:55\n"; }
                if (!empty($i['inet'])) { printf("\tinet %s --> %s netmask 0xffffffff\n", $i['inet'], $i['dest'] ?? '0.0.0.0'); }
                if (!empty($i['inet6_ll'])) { printf("\tinet6 %s%%%s prefixlen 64 scopeid 0x9\n", $i['inet6_ll'], $n); }
                if (!empty($i['vlan'])) { echo "\tvlan: 100 vlanproto: 802.1q vlanpcp: 0 parent interface: igb0\n"; }
                if (!empty($i['groups'])) { echo "\tgroups: " . implode(' ', $i['groups']) . "\n"; }
                exit(0);
            case 'destroy':
                unlink(ifpath($fake, $n));
                @unlink("$fake/ctl/$n.json");
                exit(0);
            case 'up':
                $i['flags'] = array_values(array_unique(array_merge(['UP'], $i['flags'])));
                ifput($fake, $n, $i);
                exit(0);
            case 'down':
                $i['flags'] = array_values(array_diff($i['flags'], ['UP', 'RUNNING']));
                ifput($fake, $n, $i);
                exit(0);
            case 'mtu':
                $mtu = (int)$args[2];
                /* RFC 4638 / if_pppoe.c pppoe_ioctl SIOCSIFMTU (sys/net/if_pppoe.h:111
                 * PPPOE_MAXMTU=1492, if_pppoe.c:3414-3430 PPPOE_OVERHEAD=8): a bigger
                 * payload needs a parent (set by a prior `pppoectl -e`) with MTU >= mtu+8 */
                if ($mtu > 1492) {
                    $ctlf = "$fake/ctl/$n.json";
                    $st = json_decode((string)@file_get_contents($ctlf), true) ?: [];
                    $parent = is_string($st['parent'] ?? null) ? ifget($fake, $st['parent']) : null;
                    if ($parent === null || ($parent['mtu'] ?? 0) < $mtu + 8) {
                        fwrite(STDERR, "ifconfig: ioctl (SIOCSIFMTU): Invalid argument\n");
                        exit(1);
                    }
                }
                $i['mtu'] = $mtu;
                ifput($fake, $n, $i);
                exit(0);
        }
        exit(1);
    case 'sysctl':
        $vals = json_decode((string)@file_get_contents("$fake/sysctl.json"), true) ?: [];
        if (($args[0] ?? '') === '-n') {
            if (!array_key_exists($args[1], $vals)) { fwrite(STDERR, "sysctl: unknown oid '{$args[1]}'\n"); exit(1); }
            echo $vals[$args[1]] . "\n";
            exit(0);
        }
        foreach ($vals as $k => $v) {
            if (str_starts_with($k, $args[0] . '.')) { echo "$k: $v\n"; }
        }
        exit(0);
    case 'pppoectl':
        if (($args[0] ?? '') === '-dd') {
            $f = "$fake/sessions/{$args[1]}.txt";
            if (ifget($fake, $args[1]) === null) { fwrite(STDERR, "{$args[1]}: interface not found\n"); exit(1); }
            echo is_file($f) ? file_get_contents($f) : "{$args[1]}:\tPPPoE state: initial\n\tSession ID: 0x0\n\tLCP state: initial\n\tIPCP state: initial\n\tIPv6CP state: initial\n";
            exit(0);
        }
        /* settings (-S / -f <file>) or list mode, modelled on sbin/pppoectl/pppoectl.c at driver-finish */
        $opts = [];
        while ($args !== [] && in_array($args[0], ['-S', '-f', '-e', '-s', '-a'], true)) {
            $o = array_shift($args);
            $opts[$o] = $o === '-S' ? true : array_shift($args);
        }
        $dev = array_shift($args) ?? '';
        /* pppoectl.c:227-232 (driver-finish): checked before anything else is done */
        if (isset($opts['-S']) && isset($opts['-e'])) {
            fwrite(STDERR, "pppoectl: -S cannot be combined with -e\n");
            exit(64);
        }
        if (isset($opts['-S']) && ($opts['-f'] ?? null) === '/dev/stdin') {
            fwrite(STDERR, "pppoectl: -S cannot be combined with -f /dev/stdin (both read the secret from stdin)\n");
            exit(64);
        }
        $defaultCtl = ['myauthproto' => null, 'myauthname' => '', 'hisauthproto' => null, 'maf' => 5, 'ipcp' => true, 'ipv6cp' => false, 'mssfix' => true];
        if (isset($opts['-e'])) {
            /* PPPOESETPARMS on a missing device: ENXIO -> print_error() -> EX_DATAERR (pppoectl.c:930-937) */
            if (ifget($fake, $dev) === null) {
                fwrite(STDERR, "$dev: interface not found\n");
                exit(65);
            }
            /* record the parent so a later `ifconfig $dev mtu` can apply the RFC 4638 check */
            $ctlf = "$fake/ctl/$dev.json";
            $st = json_decode((string)@file_get_contents($ctlf), true) ?: $defaultCtl;
            $st['parent'] = $opts['-e'];
            @mkdir("$fake/ctl", 0700, true);
            file_put_contents($ctlf, json_encode($st));
            exit(0);
        }
        if (ifget($fake, $dev) === null) { fwrite(STDERR, "pppoectl: $dev: no such interface\n"); exit(71); }
        $ctlf = "$fake/ctl/$dev.json";
        $st = json_decode((string)@file_get_contents($ctlf), true) ?: $defaultCtl;
        if ($opts === [] && $args === []) {
            echo "$dev:\tphase=dead\n";
            if ($st['myauthproto'] !== null && $st['myauthproto'] !== 'none') {
                printf("\tmyauthproto=%s myauthname=\"%s\"\n", $st['myauthproto'], $st['myauthname']);
            }
            if ($st['hisauthproto'] !== null && $st['hisauthproto'] !== 'none') {
                printf("\thisauthproto=%s hisauthname=\"\"\n", $st['hisauthproto']);
            }
            echo "\tlcp timeout: 3.000 s\n\tidle timeout = disabled\n\tmax-auth-failure = {$st['maf']}\n";
            echo "\tipcp: " . ($st['ipcp'] ? 'enable' : 'disable') . "\n\tipv6cp: " . ($st['ipv6cp'] ? 'enable' : 'disable') . "\n";
            echo "\tmssfix: " . ($st['mssfix'] ? 'enable' : 'disable') . "\n";
            exit(0);
        }
        /* -S: one getline(stdin), trailing LF then CR stripped, verbatim; the rest of stdin is never read */
        if (isset($opts['-S'])) {
            if ($stdin === null) { fwrite(STDERR, "pppoectl: -S: reading secret from stdin\n"); exit(66); }
            $sec = explode("\n", $stdin, 2)[0];
            if (str_ends_with($sec, "\r")) { $sec = substr($sec, 0, -1); }
            $st['secret_len'] = strlen($sec);
        }
        /* -f: fopen(path) + fparseln; a missing file is an error */
        $lines = [];
        if (isset($opts['-f'])) {
            $f = $opts['-f'];
            $body = $f === '/dev/stdin' ? (string)$stdin : (is_file($f) ? file_get_contents($f) : false);
            if ($body === false) { fwrite(STDERR, "pppoectl: $f: No such file or directory\n"); exit(66); }
            $lines = explode("\n", rtrim($body, "\n"));
            /* fake/pppoectl-drop-f: pppoectl that silently applies none of the -f lines */
            if (is_file("$fake/pppoectl-drop-f")) {
                $lines = [];
            }
        }
        foreach (array_merge($lines, $args) as $l) {
            $l = fparseln_line($l);
            if ($l === '') { continue; }
            if (isset($opts['-S']) && preg_match('/^my(authsecret|authkey)=/', $l)) {
                fwrite(STDERR, "pppoectl: myauthsecret/myauthkey given after -S already set the secret\n");
                exit(64);
            }
            if (preg_match('/^(myauthproto|hisauthproto)=(pap|chap|none)$/', $l, $m)) { $st[$m[1]] = $m[2]; }
            elseif (str_starts_with($l, 'myauthname=')) { $st['myauthname'] = substr($l, 11); }
            elseif (preg_match('/^max-auth-failure=([0-9]+)$/', $l, $m)) { $st['maf'] = (int)$m[1]; }
            elseif (in_array($l, ['ipcp', 'noipcp', 'ipv6cp', 'noipv6cp', 'mssfix', 'nomssfix'], true)) { $k = preg_replace('/^no/', '', $l); $st[$k] = $l === $k; }
            elseif ($l === 'passiveauthproto' || str_starts_with($l, 'query-dns=')) { }
            else { fwrite(STDERR, "pppoectl: bad parameter: $l\n"); exit(65); }
        }
        @mkdir("$fake/ctl", 0700, true);
        file_put_contents($ctlf, json_encode($st));
        exit(0);
    case 'pgrep':
        /* -F pidfile: alive when the pidfile says "alive" */
        exit(trim((string)@file_get_contents($args[1] ?? '')) === 'alive' ? 0 : 1);
    default:
        /* configctl, logger, ppp-linkup.sh, ppp-linkdown.sh, ... */
        exit(0);
}
