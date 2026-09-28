<?php

namespace IfPppoe\Test;

use IfPppoe\Engine\Engine;

const SESSION_UP = "pppoe0:\tPPPoE state: session\n\tSession ID: 0x1234\n\tPADI retries: 0\n\tPADR retries: 0\n"
    . "\tLCP state: opened\n\tIPCP state: opened\n\tIPv6CP state: opened\n\tLCP negotiated options:\n\t\tmru 1492\n"
    . "\t\tmagic number 0x1\n\tIPCP negotiated options:\n\t\taddress 100.64.1.2\n\tprimary dns address 9.9.9.9\n"
    . "\tsecondary dns address 149.112.112.112\n\tIPv6CP negotiated options:\n"
    . "\t\tifid: my_ifid=0x0211223344556677, his_ifid=0x02aabbccddeeff00\n";

function cmds(Sandbox $s, ?string $cmd = null): array
{
    return array_map(fn($c) => array_merge([$c['cmd']], $c['argv']), $s->calls($cmd));
}

function pwWithSpecials(): string
{
    return "p@ss w#rd\\\"'\$(reboot)`id`;|&<>é";
}

T::test('configure: claims an eligible WAN with the exact command sequence', function () {
    $s = new Sandbox();
    $s->write('/var/etc/mpd_wan.conf', "set auth password s3cr3t-Pa55\n");
    $rc = $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    T::eq(Engine::EXIT_CLAIMED, $rc, implode("\n", $s->logs));
    $seq = array_values(array_filter(cmds($s), fn($c) => $c[0] !== 'sysctl' && !($c[0] === 'ifconfig' && count($c) === 2)));
    $call = $s->calls('pppoectl')[1];
    $cfg = $call['argv'][2] ?? '';
    T::ok((bool)preg_match('#^' . preg_quote($s->root, '#') . '/var/run/if_pppoe/pppoectl\.pppoe0\.[0-9a-f]{16}\.conf$#', $cfg), $cfg);
    T::eq([
        ['ifconfig', 'pppoe0', 'create'],
        ['ifconfig', 'pppoe0', 'down'],
        ['pppoectl', '-e', 'igb1', '-s', 'ISP-SVC', 'pppoe0'],
        ['pppoectl', '-S', '-f', $cfg, 'pppoe0'],
        ['pppoectl', 'pppoe0'],
        ['ifconfig', 'pppoe0', 'mtu', '1492'],
        ['ifconfig', 'pppoe0', 'up'],
    ], $seq);
    T::eq("s3cr3t-Pa55\n", $call['stdin'], 'stdin is the secret line only');
    T::eq(['path' => $cfg, 'exists' => true, 'mode' => '0600',
        'content' => "myauthproto=chap\npassiveauthproto\nmyauthname=user@isp.example\nhisauthproto=none\n"
            . "max-auth-failure=0\nipcp\nipv6cp\nquery-dns=3\nmssfix\n"], $call['ffile'], '-f file while pppoectl ran');
    T::ok(!file_exists($cfg), '-f file removed after success');
    T::eq(strlen('s3cr3t-Pa55'), json_decode(file_get_contents($s->root . '/fake/ctl/pppoe0.json'), true)['secret_len']);
    T::ok(!is_file($s->root . '/var/etc/mpd_wan.conf'), 'mpd_wan.conf (with the password) removed');
    $reg = $s->registry('pppoe0');
    T::eq('wan', $reg['friendly']);
    T::eq('dialing', $reg['state']);
    T::eq('igb1', $reg['plan']['parent']);
    T::eq(1492, $s->ifaceState('pppoe0')['mtu']);
    T::ok(in_array('UP', $s->ifaceState('pppoe0')['flags'], true));
    $st = json_decode(file_get_contents($s->root . '/var/run/if_pppoe/status.json'), true);
    T::eq('kernel', $st['interfaces']['wan']['backend']);
    T::ok(!str_contains($s->allArgv(), 's3cr3t'), 'secret on argv');
    T::ok(!str_contains($s->allArgv(), 'user@isp'), 'username on argv');
    T::ok(!str_contains($s->stateFiles(), 's3cr3t'), 'secret persisted in state files');
    T::ok(!str_contains($s->stateFiles(), 'user@isp'), 'username persisted in state files');
});

T::test('configure: special-character password reaches pppoectl stdin verbatim and nowhere else', function () {
    $s = new Sandbox();
    $pw = pwWithSpecials();
    $user = "us#er\\name 'q'";
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) use ($pw, $user) {
        $x->query('//ppps/ppp/password')->item(0)->nodeValue = base64_encode($pw);
        $x->query('//ppps/ppp/username')->item(0)->textContent = $user;
    });
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), implode("\n", $s->logs));
    $call = $s->calls('pppoectl')[1];
    T::eq($pw . "\n", $call['stdin']);
    T::ok(str_contains($call['ffile']['content'], "\nmyauthname=us\\#er\\\\name 'q'\n"), 'escaped username');
    T::ok(!str_contains($call['ffile']['content'], 'w#rd'), 'secret in the -f file');
    T::eq("us#er\\name 'q'", json_decode(file_get_contents($s->root . '/fake/ctl/pppoe0.json'), true)['myauthname']);
    T::ok(!str_contains($s->allArgv(), 'w#rd'), 'secret on argv');
    T::ok(!str_contains($s->allArgv(), 'us#er'), 'username on argv');
    T::ok(!str_contains($s->stateFiles(), 'w#rd'), 'secret in state');
});

T::test('configure: -S never shares stdin with -f (argv never names /dev/stdin; settings stick)', function () {
    $s = new Sandbox();
    T::eq(Engine::EXIT_CLAIMED, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), implode("\n", $s->logs));
    foreach ($s->calls('pppoectl') as $c) {
        if (in_array('-S', $c['argv'], true)) {
            T::ok(!in_array('/dev/stdin', $c['argv'], true) && !in_array('-', $c['argv'], true), json_encode($c['argv']));
        }
    }
    T::ok(!str_contains($s->allArgv(), '/dev/stdin'), 'no /dev/stdin anywhere on argv');
});

T::test('stub pppoectl enforces the driver-finish contract: -S with -f /dev/stdin -> rc 64', function () {
    $s = new Sandbox();
    $s->iface('pppoe0', ['groups' => ['pppoe']]);
    $bin = $s->root . '/usr/local/sbin/pppoectl';
    $r = (new \IfPppoe\Engine\Proc())->run([$bin, '-S', '-f', '/dev/stdin', 'pppoe0'], "pw\nmyauthproto=chap\n", 10);
    T::eq(64, $r->rc);
    T::contains('-S cannot be combined with -f /dev/stdin (both read the secret from stdin)', $r->err);
    $r = (new \IfPppoe\Engine\Proc())->run([$bin, '-S', '-e', 'igb1', 'pppoe0'], "pw\n", 10);
    T::eq(64, $r->rc, '-S with -e');
    $s->write('/cfg', "myauthsecret=x\n");
    $r = (new \IfPppoe\Engine\Proc())->run([$bin, '-S', '-f', $s->root . '/cfg', 'pppoe0'], "pw\n", 10);
    T::eq(64, $r->rc, 'secret in -f after -S');
    $r = (new \IfPppoe\Engine\Proc())->run([$bin, '-S', '-f', $s->root . '/missing', 'pppoe0'], "pw\n", 10);
    T::eq(66, $r->rc, 'missing -f file');
    $s->write('/cfg', "myauthproto=chap\nmyauthname=u\\#1\n");
    $r = (new \IfPppoe\Engine\Proc())->run([$bin, '-S', '-f', $s->root . '/cfg', 'pppoe0'], "p w#\\x\r\nignored\n", 10);
    T::eq(0, $r->rc, $r->err);
    $st = json_decode(file_get_contents($s->root . '/fake/ctl/pppoe0.json'), true);
    T::eq(['chap', 'u#1', 6], [$st['myauthproto'], $st['myauthname'], $st['secret_len']], 'secret = first line minus CR LF, config from the file');
});

T::test('configure: ineligible interface exits 1, records the reason, touches nothing', function () {
    $s = new Sandbox();
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $x->query('//ppps/ppp')->item(0)->appendChild($d->createElement('ondemand', '1'));
    });
    $s->write('/var/etc/mpd_wan.conf', "x\n");
    T::eq(Engine::EXIT_INELIGIBLE, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::eq([], cmds($s, 'pppoectl'));
    T::ok(!in_array(['ifconfig', 'pppoe0', 'create'], cmds($s, 'ifconfig'), true));
    T::ok(is_file($s->root . '/var/etc/mpd_wan.conf'), 'mpd5 still needs its conf');
    $st = json_decode(file_get_contents($s->root . '/var/run/if_pppoe/status.json'), true)['interfaces']['wan'];
    T::eq('mpd5', $st['backend']);
    T::contains('dial-on-demand', $st['reason']);
    T::eq('ineligible: dial-on-demand is not supported', $st['fields']['ondemand']);
});

T::test('configure: hook not applied or features missing -> ineligible', function () {
    $s = new Sandbox('config-base.xml', false);
    T::eq(1, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s = new Sandbox('config-base.xml', true, false);
    T::eq(1, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s = new Sandbox();
    $s->write('/usr/local/etc/inc/interfaces.inc', "<?php\n/* pristine */\n");
    T::eq(1, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), 'hook.json says applied but markers are gone');
});

T::test('configure: failure mid-setup destroys the clone, exits 2 and keeps mpd5\'s conf', function () {
    $s = new Sandbox();
    $s->write('/var/etc/mpd_wan.conf', "set auth password s3cr3t-Pa55\n");
    $s->fail([['pppoectl', '-S']]);
    T::eq(Engine::EXIT_FAILED, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $call = $s->calls('pppoectl')[1];
    T::eq('0600', $call['ffile']['mode'], '-f file existed, 0600, while pppoectl ran');
    T::ok(!file_exists($call['argv'][2]), '-f file removed after pppoectl failed');
    T::eq(null, $s->ifaceState('pppoe0'), 'clone destroyed');
    T::eq(null, $s->registry('pppoe0'), 'registry cleared');
    T::ok($s->exists('/var/etc/mpd_wan.conf'), 'core falls through to mpd5 -f mpd_wan.conf');
    $st = json_decode(file_get_contents($s->root . '/var/run/if_pppoe/status.json'), true)['interfaces']['wan'];
    T::eq('mpd5', $st['backend']);
    T::eq('failed', $st['result']);
});

T::test('configure: a foreign pppoe0 (mpd5 ng leftover) that does not go away -> exit 2, conf kept', function () {
    $s = new Sandbox();
    $s->write('/var/etc/mpd_wan.conf', "x\n");
    $s->iface('pppoe0', ['groups' => ['ng']]);
    $t = microtime(true);
    T::eq(Engine::EXIT_FAILED, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::ok(microtime(true) - $t < 15, 'bounded wait');
    T::ok(!in_array(['ifconfig', 'pppoe0', 'create'], cmds($s, 'ifconfig'), true));
    T::ok($s->ifaceState('pppoe0') !== null, 'did not destroy what is not ours');
    T::ok($s->exists('/var/etc/mpd_wan.conf'), 'mpd5 still needs its conf');
});

T::test('configure: pppoectl silently not applying the -f lines -> exit 2, mpd5 fallback, -f file removed', function () {
    $s = new Sandbox();
    $s->write('/var/etc/mpd_wan.conf', "x\n");
    $s->write('/fake/pppoectl-drop-f', '');
    T::eq(Engine::EXIT_FAILED, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $call = $s->calls('pppoectl')[1];
    T::eq('0600', $call['ffile']['mode']);
    T::ok(!file_exists($call['argv'][2]), '-f file removed after the read-back mismatch');
    T::eq(null, $s->ifaceState('pppoe0'), 'clone destroyed');
    T::ok($s->exists('/var/etc/mpd_wan.conf'));
    T::ok(!in_array(['ifconfig', 'pppoe0', 'up'], cmds($s, 'ifconfig'), true), 'never dialled without auth');
    $st = json_decode(file_get_contents($s->root . '/var/run/if_pppoe/status.json'), true)['interfaces']['wan'];
    T::contains('did not apply: myauthproto/myauthname not applied', $st['reason']);
});

T::test('configure: killed by the hook timeout mid-setup -> conf intact; reconcile cleans up and redoes the WAN', function () {
    $s = new Sandbox();
    $s->write('/var/etc/mpd_wan.conf', "set auth password s3cr3t-Pa55\n");
    $s->fakeJson('hang.json', [['pppoectl', '-S']]);
    $r = (new \IfPppoe\Engine\Proc())->run(['timeout', '-k', '1', '2', PHP_BINARY, SRC . '/engine', 'configure', 'wan', 'pppoe0', 'igb1', '1492', ''], null, 30);
    T::ok($r->rc !== 0, 'not claimed (rc ' . $r->rc . ')');
    T::ok($s->exists('/var/etc/mpd_wan.conf'), 'core\'s mpd5 fallback still has its conf');
    T::eq('configuring', $s->registry('pppoe0')['state'] ?? null, 'stale record left behind');
    $s->fakeJson('hang.json', []);
    $s->clearCalls();
    T::eq(0, $s->engine()->reconcile());
    T::eq(null, $s->ifaceState('pppoe0'), 'stale clone destroyed');
    T::eq(null, $s->registry('pppoe0'));
    T::ok($s->exists('/var/etc/mpd_wan.conf'), 'reconcile does not touch the conf');
    T::eq([['configctl', 'interface', 'reconfigure', 'wan']], cmds($s, 'configctl'), 'core redoes the WAN');
});

T::test('configure: reconfigure tears the old session down first (down path, then destroy)', function () {
    $s = new Sandbox();
    $e = $s->engine();
    T::eq(0, $e->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::eq(0, $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1', 'dns1=9.9.9.9', 'dns2=', 'mtu=1492']));
    $s->clearCalls();
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1480', ''));
    $c = array_values(array_filter(cmds($s), fn($c) => in_array($c[0], ['ppp-linkdown.sh', 'ifconfig'], true) && count($c) > 2));
    T::eq(['ppp-linkdown.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '-', '-'], $c[0]);
    T::eq(['ifconfig', 'pppoe0', 'down'], $c[1]);
    T::eq(['ifconfig', 'pppoe0', 'destroy'], $c[2]);
    T::eq(['ifconfig', 'pppoe0', 'create'], $c[3]);
    T::eq(1480, $s->ifaceState('pppoe0')['mtu']);
    T::eq('down', $s->registry('pppoe0')['v4']);
});

T::test('configure: becoming ineligible tears down an existing kernel session', function () {
    $s = new Sandbox();
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $x->query('//ppps/ppp')->item(0)->appendChild($d->createElement('hostuniq', 'abc'));
    });
    T::eq(1, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::eq(null, $s->ifaceState('pppoe0'));
    T::eq(null, $s->registry('pppoe0'));
});

T::test('configure: invalid arguments are refused', function () {
    $s = new Sandbox();
    T::eq(Engine::EXIT_USAGE, $s->engine()->configure('wan;x', 'pppoe0'));
    T::eq(Engine::EXIT_USAGE, $s->engine()->configure('wan', 'pppoe0 destroy'));
    T::eq([], $s->calls('ifconfig'));
});

T::test('reset: tears down the registered clone; unknown device is a no-op', function () {
    $s = new Sandbox();
    $e = $s->engine();
    T::eq(0, $e->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::eq(0, $e->linkevent('pppoe0', 'IPV6CP_UP', ['local=fe80::211:22ff:fe33:4455', 'remote=0x02aabbccddeeff00']));
    $s->clearCalls();
    T::eq(0, $s->engine()->reset('wan', 'pppoe0'));
    T::eq([
        ['ppp-linkdown.sh', 'pppoe0', 'inet6', 'fe80::211:22ff:fe33:4455%pppoe0', 'fe80::2aa:bbcc:ddee:ff00%pppoe0', '-', '-', '-'],
        ['ifconfig', 'pppoe0', 'down'],
        ['ifconfig', 'pppoe0', 'destroy'],
    ], array_values(array_filter(cmds($s), fn($c) => count($c) > 2)));
    T::eq(null, $s->registry('pppoe0'));
    $s->clearCalls();
    T::eq(0, $s->engine()->reset('opt5', 'pppoe7'));
    T::eq([], array_values(array_filter(cmds($s), fn($c) => count($c) > 2)));
});

T::test('reset: finds the clone by friendly name when the device changed', function () {
    $s = new Sandbox();
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::eq(0, $s->engine()->reset('wan', 'pppoe3'));
    T::eq(null, $s->ifaceState('pppoe0'));
});

T::test('linkevent: IPCP up/down call core scripts with mpd5 argv', function () {
    $s = new Sandbox();
    $e = $s->engine();
    T::eq(0, $e->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s->clearCalls();
    T::eq(0, $e->linkevent('pppoe0', 'SESSION_UP', ['local=', 'remote=']));
    T::eq(0, $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1', 'dns1=9.9.9.9', 'dns2=149.112.112.112', 'mtu=1492']));
    T::eq(0, $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1', 'dns1=9.9.9.9', 'dns2=149.112.112.112', 'mtu=1492']));
    T::eq(0, $e->linkevent('pppoe0', 'IPCP_DOWN', []));
    T::eq(0, $e->linkevent('pppoe0', 'IPCP_DOWN', []));
    T::eq([
        ['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', 'dns1 9.9.9.9', 'dns2 149.112.112.112', '-', '-'],
        ['ppp-linkdown.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '-', '-'],
    ], array_merge(cmds($s, 'ppp-linkup.sh'), cmds($s, 'ppp-linkdown.sh')));
    $up = $s->calls('ppp-linkup.sh')[0];
    T::eq('/usr/local/opnsense/scripts/interfaces/ppp-linkup.sh', $up['path']);
});

T::test('linkevent: no DNS offered -> empty $6/$7 like mpd5', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2/32', 'remote=100.64.0.1', 'dns1=', 'dns2=']);
    T::eq([['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '', '', '-', '-']], cmds($s, 'ppp-linkup.sh'));
});

T::test('linkevent: address change while up = down then up', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.9.9', 'remote=100.64.0.1']);
    T::eq(2, count($s->calls('ppp-linkup.sh')));
    T::eq(1, count($s->calls('ppp-linkdown.sh')));
    T::eq('100.64.9.9', $s->registry('pppoe0')['local']);
});

T::test('linkevent: IPv6CP up uses the inet6 argv that makes core start dhcp6c', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    T::eq(0, $e->linkevent('pppoe0', 'IPV6CP_UP', ['local=0x0211223344556677', 'remote=fe80::2aa:bbcc:ddee:ff00%pppoe0']));
    T::eq([['ppp-linkup.sh', 'pppoe0', 'inet6', 'fe80::211:2233:4455:6677%pppoe0', 'fe80::2aa:bbcc:ddee:ff00%pppoe0', '-', '-', '-']], cmds($s, 'ppp-linkup.sh'));
    T::eq(0, $e->linkevent('pppoe0', 'IPV6CP_DOWN', []));
    T::eq([['ppp-linkdown.sh', 'pppoe0', 'inet6', 'fe80::211:2233:4455:6677%pppoe0', 'fe80::2aa:bbcc:ddee:ff00%pppoe0', '-', '-', '-']], cmds($s, 'ppp-linkdown.sh'));
});

T::test('linkevent: IPv6CP up without a local id falls back to the interface link-local', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $st = $s->ifaceState('pppoe0');
    $st['inet6_ll'] = 'fe80::1:2:3:4';
    $s->iface('pppoe0', $st);
    $e->linkevent('pppoe0', 'IPV6CP_UP', ['local=', 'remote=junk']);
    T::eq(['ppp-linkup.sh', 'pppoe0', 'inet6', 'fe80::1:2:3:4%pppoe0', '', '-', '-', '-'], cmds($s, 'ppp-linkup.sh')[0]);
});

T::test('linkevent: SESSION_DOWN covers lost NCP downs; AUTH_FAIL counted', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    $e->linkevent('pppoe0', 'IPV6CP_UP', ['local=fe80::1', 'remote=fe80::2']);
    $s->clearCalls();
    $e->linkevent('pppoe0', 'SESSION_DOWN', []);
    T::eq(['inet6', 'inet'], array_map(fn($c) => $c[2], cmds($s, 'ppp-linkdown.sh')));
    $e->linkevent('pppoe0', 'AUTH_FAIL', []);
    $e->linkevent('pppoe0', 'AUTH_FAIL', []);
    T::eq(2, $s->registry('pppoe0')['auth_failures']);
    T::eq('down', $s->registry('pppoe0')['session']);
    T::ok(in_array('pppoe0: PPP authentication failed', $s->logs, true));
});

T::test('linkevent: unmanaged device, bad type and bad device are ignored', function () {
    $s = new Sandbox();
    $e = $s->engine();
    T::eq(0, $e->linkevent('pppoe4', 'IPCP_UP', ['local=1.2.3.4']));
    T::eq(Engine::EXIT_USAGE, $e->linkevent('pppoe0', 'REBOOT', []));
    T::eq(Engine::EXIT_USAGE, $e->linkevent('pppoe0;id', 'IPCP_UP', []));
    T::eq([], $s->calls('ppp-linkup.sh'));
});

T::test('linkevent: garbage addresses are dropped, never passed to core', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=1.2.3.4;reboot', 'remote=$(id)', 'dns1=9.9.9.9 x']);
    T::eq(['ppp-linkup.sh', 'pppoe0', 'inet', '', '', '-', '', '', '-', '-'], cmds($s, 'ppp-linkup.sh')[0], 'no placeholder router for core');
});

T::test('reconcile: destroys orphan clones not in the registry', function () {
    $s = new Sandbox();
    $s->iface('pppoe5', ['groups' => ['pppoe'], 'flags' => ['UP']]);
    T::eq(0, $s->engine()->reconcile());
    T::eq(null, $s->ifaceState('pppoe5'));
    T::ok($s->ifaceState('igb1') !== null);
});

T::test('reconcile: vanished clone -> lost downs delivered, registry cleared', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    unlink($s->root . '/fake/ifaces/pppoe0.json');
    $s->clearCalls();
    $s->engine()->reconcile();
    T::eq([['ppp-linkdown.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '-', '-']], cmds($s, 'ppp-linkdown.sh'));
    T::eq(null, $s->registry('pppoe0'));
});

T::test('reconcile: replays a lost IPCP_UP and IPV6CP_UP from kernel state', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $st = $s->ifaceState('pppoe0');
    $st['inet'] = '100.64.1.2';
    $st['dest'] = '100.64.0.1';
    $s->iface('pppoe0', $st);
    $s->session('pppoe0', SESSION_UP);
    $s->clearCalls();
    $s->engine()->reconcile();
    T::eq([
        ['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', 'dns1 9.9.9.9', 'dns2 149.112.112.112', '-', '-'],
        ['ppp-linkup.sh', 'pppoe0', 'inet6', 'fe80::211:2233:4455:6677%pppoe0', 'fe80::2aa:bbcc:ddee:ff00%pppoe0', '-', '-', '-'],
    ], cmds($s, 'ppp-linkup.sh'));
    $s->clearCalls();
    $s->engine()->reconcile();
    T::eq([], cmds($s, 'ppp-linkup.sh'), 'level-triggered: nothing to do the second time');
});

T::test('reconcile: replays a lost IPCP_DOWN', function () {
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    $s->clearCalls();
    $s->engine()->reconcile();
    T::eq(1, count($s->calls('ppp-linkdown.sh')));
    T::eq('down', $s->registry('pppoe0')['v4']);
});

T::test('reconcile: eligible interface found on mpd5 -> one reconfigure, then backoff', function () {
    $s = new Sandbox();
    $s->write('/var/run/pppoe_wan.pid', "alive\n");
    $s->engine()->reconcile();
    T::eq([['configctl', 'interface', 'reconfigure', 'wan']], cmds($s, 'configctl'));
    $s->clearCalls();
    $s->engine()->reconcile();
    T::eq([], cmds($s, 'configctl'), 'backoff');
});

T::test('reconcile: ineligible interface on mpd5 is left alone', function () {
    $s = new Sandbox();
    $s->write('/var/run/pppoe_wan.pid', "alive\n");
    $s->write('/var/run/if_pppoe/effective.json', json_encode(['enabled' => true, 'exclude' => ['wan']]));
    $s->engine()->reconcile();
    T::eq([], cmds($s, 'configctl'));
});

T::test('reconcile: interface removed from config -> torn down', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $p = $x->query('//ppps/ppp')->item(0);
        $p->parentNode->removeChild($p);
    });
    $s->engine()->reconcile();
    T::eq(null, $s->ifaceState('pppoe0'));
});

T::test('reconcile --after-firmware: hook refused -> clones destroyed, core reconfigures to mpd5', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'refused:context']));
    $s->clearCalls();
    $s->engine()->reconcile(true);
    T::eq(null, $s->ifaceState('pppoe0'));
    T::eq([['configctl', 'interface', 'reconfigure', 'wan']], cmds($s, 'configctl'));
    $st = json_decode(file_get_contents($s->root . '/var/run/if_pppoe/status.json'), true)['interfaces']['wan'];
    T::eq('fallback', $st['result']);
});

T::test('reconcile: hook paused during a core reinstall does not trigger the fallback', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'paused:core-reinstall']));
    $s->engine()->reconcile();
    T::ok($s->ifaceState('pppoe0') !== null);
});

T::test('reconcile: markers missing while hook.json says applied (core reinstall window) is not terminal', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->write('/usr/local/etc/inc/interfaces.inc', "<?php\n/* freshly reinstalled */\n");
    $s->clearCalls();
    $s->engine()->reconcile();
    T::ok($s->ifaceState('pppoe0') !== null);
    T::eq([], cmds($s, 'configctl'));
    $s->engine()->reconcile(true);
    T::eq(null, $s->ifaceState('pppoe0'), '--after-firmware does fall back');
});

T::test('reconcile: a configure killed mid-setup (stale "configuring") is cleaned up', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $rec = $s->registry('pppoe0');
    $rec['state'] = 'configuring';
    $s->write('/var/run/if_pppoe/reg/pppoe0.json', json_encode($rec));
    $s->engine()->reconcile();
    T::eq(null, $s->ifaceState('pppoe0'));
    T::eq(null, $s->registry('pppoe0'));
});

T::test('effective settings are snapshotted per boot (reboot-to-apply)', function () {
    $s = new Sandbox();
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $x->query('//OPNsense/IfPppoe/general/exclude')->item(0)->nodeValue = 'wan';
    });
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), 'exclude takes effect only after reboot');
    $r = $s->engine()->statusReport();
    T::ok($r['reboot_required']);
    unlink($s->root . '/var/run/if_pppoe/effective.json');
    T::eq(1, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), 'after "reboot"');
});

T::test('status --json via the CLI: shape and no credentials', function () {
    $s = new Sandbox('config-multi.xml');
    $e = $s->engine();
    T::eq(0, $e->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    $s->session('pppoe0', SESSION_UP);
    $s->write('/var/run/pppoe_opt1.pid', "alive\n");
    T::eq(0, $s->cli(['status', '--json'], $out), $out);
    $j = json_decode($out, true);
    T::ok(is_array($j), $out);
    T::eq('applied', $j['hook']);
    T::eq('enabled', $j['desired']);
    T::eq([], $j['features_missing']);
    T::eq(42, $j['counters']['sess_in']);
    T::eq('kernel', $j['interfaces']['wan']['backend']);
    T::eq('up', $j['interfaces']['wan']['registry']['v4']);
    T::eq('opened', $j['interfaces']['wan']['session']['ipcp']);
    T::eq('mpd5', $j['interfaces']['opt1']['backend']);
    T::ok($j['interfaces']['opt1']['eligible']);
    T::eq(false, $j['interfaces']['opt2']['enabled']);
    T::contains('dial-on-demand', $j['interfaces']['opt2']['eligibility']);
    foreach (['s3cr3t', 'other#pw', 'user@isp', 'second', 'third'] as $secret) {
        T::ok(!str_contains($out, $secret), "status leaks $secret");
    }
});

T::test('CLI: configure exit codes and usage', function () {
    $s = new Sandbox();
    T::eq(0, $s->cli(['configure', 'wan', 'pppoe0', 'igb1', '1492', '']), 'claimed');
    T::eq(1, $s->cli(['configure', 'lan', 'pppoe0', 'igb1', '1492', '']), 'wrong friendly');
    T::eq(64, $s->cli(['bogus']));
    T::eq(0, $s->cli(['reset', 'wan', 'pppoe0']));
    $s->setConfig('<not xml');
    T::eq(2, $s->cli(['configure', 'wan', 'pppoe0', 'igb1', '1492', '']), 'broken config -> never claimed');
});

T::test('devd: action expands to a well-formed linkevent call', function () {
    $conf = file_get_contents(__DIR__ . '/../../src/etc/devd/if_pppoe.conf');
    T::ok(preg_match('/action "([^"]+)";/', $conf, $m) === 1);
    $action = $m[1];
    T::contains('match "system"		"PPPOE";', $conf);
    foreach (Engine::EVENTS as $ev) {
        T::contains($ev, $conf);
    }
    /* expand like devd.cc: $var -> $'value' with ' escaped; unknown -> '' */
    $vars = ['subsystem' => 'pppoe0', 'type' => 'IPCP_UP', 'local' => '100.64.1.2', 'remote' => "10.0.0.1'x", 'dns1' => '9.9.9.9'];
    $cmd = preg_replace_callback('/\$([a-z0-9_]+)/', function ($mm) use ($vars) {
        return "\$'" . str_replace("'", "\\'", $vars[$mm[1]] ?? '') . "'";
    }, $action);
    $s = new Sandbox();
    $rec = $s->root . '/rec.sh';
    file_put_contents($rec, "#!/bin/sh\nfor a in \"\$@\"; do printf '%s\\n' \"\$a\"; done\n");
    chmod($rec, 0755);
    $cmd = str_replace('/usr/local/opnsense/scripts/if_pppoe/engine', $rec, $cmd);
    $r = (new \IfPppoe\Engine\Proc())->run(['/bin/bash', '-c', $cmd]);
    T::eq("linkevent\npppoe0\nIPCP_UP\nlocal=100.64.1.2\nremote=10.0.0.1'x\ndns1=9.9.9.9\ndns2=\nmtu=\n", $r->out, $r->err);
});

T::test('linkevent (devd path): only queues and starts a detached drain; drain runs events in order', function () {
    $s = new Sandbox();
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s->clearCalls();
    T::eq(0, $s->cli(['linkevent', 'pppoe0', 'IPCP_UP', 'local=100.64.1.2', 'remote=100.64.0.1', 'dns1=', 'dns2=', 'mtu=1492', 'bogus=1']));
    T::eq(0, $s->cli(['linkevent', 'pppoe0', 'IPCP_DOWN', 'local=', 'remote=']));
    T::eq([], $s->calls('ppp-linkup.sh'), 'devd is not held up by core scripts');
    $d = $s->calls('daemon');
    T::eq(2, count($d));
    T::eq(['-f', $s->root . '/usr/local/opnsense/scripts/if_pppoe/engine', 'drain', 'pppoe0'], $d[0]['argv']);
    $q = $s->queued('pppoe0');
    T::eq(['IPCP_UP', 'IPCP_DOWN'], array_column($q, 'type'));
    T::eq(['local' => '100.64.1.2', 'remote' => '100.64.0.1', 'dns1' => '', 'dns2' => '', 'mtu' => '1492'], $q[0]['kv'], 'unknown keys dropped');
    T::eq(0, $s->cli(['drain', 'pppoe0']));
    T::eq([['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '', '', '-', '-'],
        ['ppp-linkdown.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', '-', '-']],
        array_values(array_filter(cmds($s), fn($c) => str_starts_with($c[0], 'ppp-link'))), 'devd order kept');
    T::eq([], $s->queued('pppoe0'));
});

T::test('linkevent: daemon(8) unavailable -> drained inline', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->fail([['daemon']]);
    T::eq(0, $s->engine(false)->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']));
    T::eq(1, count($s->calls('ppp-linkup.sh')));
});

T::test('linkevent: events from a previous clone are not applied to the new one', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->engine(false)->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    usleep(20000);
    T::eq(0, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $s->engine()->drain('pppoe0');
    T::eq([], $s->calls('ppp-linkup.sh'));
    T::eq('down', $s->registry('pppoe0')['v4']);
});

T::test('linkevent: drain that cannot get the lock leaves events for reconcile', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $st = $s->ifaceState('pppoe0');
    $st['inet'] = '100.64.1.2';
    $st['dest'] = '100.64.0.1';
    $s->iface('pppoe0', $st);
    $s->session('pppoe0', str_replace("\tIPv6CP state: opened", "\tIPv6CP state: initial", SESSION_UP));
    $e = $s->engine(false);
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1', 'dns1=9.9.9.9']);
    $held = \IfPppoe\Engine\Lock::acquire($s->env(), 'pppoe0', 1.0);
    T::eq(0, $e->drain('pppoe0', 0.2));
    T::eq([], $s->calls('ppp-linkup.sh'));
    $held->release();
    $s->engine()->reconcile();
    T::eq([['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '100.64.0.1', '-', 'dns1 9.9.9.9', '', '-', '-']], cmds($s, 'ppp-linkup.sh'),
        'queued event delivered once, level sync then finds nothing to do');
});

T::test('reconcile: a device lock held elsewhere skips that device, the pass goes on', function () {
    $s = new Sandbox();
    $s->iface('pppoe5', ['groups' => ['pppoe'], 'flags' => ['UP']]);
    $s->iface('pppoe6', ['groups' => ['pppoe'], 'flags' => ['UP']]);
    $s->write('/var/run/pppoe_wan.pid', "alive\n");
    $held = \IfPppoe\Engine\Lock::acquire($s->env(), 'pppoe5', 1.0);
    T::eq(0, $s->engine()->reconcile());
    $held->release();
    T::ok($s->ifaceState('pppoe5') !== null, 'locked device skipped');
    T::eq(null, $s->ifaceState('pppoe6'), 'others still reaped');
    T::eq([['configctl', 'interface', 'reconfigure', 'wan']], cmds($s, 'configctl'), 'rest of the pass ran');
    T::ok((bool)preg_grep('/pppoe5: timed out waiting for lock/', $s->logs));
});

T::test('status: reboot_required without an effective.json snapshot (plugin was off at boot)', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $r = $s->engine()->statusReport();
    T::eq(null, $r['effective']);
    T::ok($r['reboot_required'], 'enabled + applied, hook still reverted');
    $s->write('/conf/if_pppoe/desired', "disabled\n");
    T::ok(!$s->engine()->statusReport()['reboot_required']);
    T::ok($s->engine()->statusReport()['apply_pending'], 'model says enabled, desired says disabled');
    T::ok(Engine::rebootRequired('disabled', 'applied', false, null, null), 'disabled + applied');
    T::ok(!Engine::rebootRequired('enabled', 'refused:context', false, null, null), 'a reboot would not help');
    T::ok(!Engine::rebootRequired('enabled', 'reverted', true, null, null), 'latched');
    T::ok(!Engine::rebootRequired('enabled', 'applied', false, null, ['enabled' => true, 'exclude' => []]));
});

T::test('status: reboot_required also fires when the loaded kmod is stale, even with a matching exclude list', function () {
    $eff = ['exclude' => []];
    $settings = ['enabled' => true, 'exclude' => []];
    T::ok(!Engine::rebootRequired('enabled', 'applied', false, $eff, $settings, null, null, null, false), 'sanity: matching exclude, nothing pending');
    T::ok(Engine::rebootRequired('enabled', 'applied', false, $eff, $settings, null, null, null, true));
});

T::test('Kernel: installed-features/build-id checks work before the module is ever loaded', function () {
    $s = new Sandbox();
    $k = $s->kernel();
    T::eq([], $k->missingInstalledFeatures(), 'default fixture ships every required feature');
    T::ok($k->installedKmodMatchesKernel(), 'default fixture matches the running kern.build_id');
    T::ok(!$k->kmodUpgradePending(), 'nothing recorded as loaded yet: not our call to make');

    $s2 = new Sandbox();
    $s2->installedFeatures(['if_pppoe_ipv6', 'if_pppoe_mssfix']);
    T::eq(
        ['if_pppoe_linkevents', 'if_pppoe_pfil_pass_foreign', 'if_pppoe_single_bytecount'],
        $s2->kernel()->missingInstalledFeatures()
    );

    $s3 = new Sandbox();
    $s3->noInstalledBuildIds();
    T::ok(!$s3->kernel()->installedKmodMatchesKernel(), 'no build_ids line for the running kernel');
});

T::test('Kernel: a missing features file is "unknown", not "every feature missing"', function () {
    $s = new Sandbox();
    $s->noInstalledFeaturesFile();
    T::eq(null, $s->kernel()->missingInstalledFeatures(), 'no file to fail closed against');
});

T::test('status: an installed features file predating this check does not claim ineligibility', function () {
    /* an existing install (e.g. <ROUTER_HOST> before this fix) keeps its old
     * if-pppoe-kmod package, which has no features file at all */
    $s = new Sandbox();
    $s->noInstalledFeaturesFile();
    $r = $s->engine()->statusReport();
    T::ok($r['installed_eligible'], 'unknown features must not read as ineligible');
    T::eq('', $r['installed_reason']);
});

T::test('Kernel: kmodUpgradePending() compares the loaded identity to what is installed now', function () {
    $s = new Sandbox();
    $s->recordLoadedKmod(); /* matches the installed .ko */
    T::ok(!$s->kernel()->kmodUpgradePending());

    $s->recordLoadedKmod(Sandbox::BUILD_ID, 'not-the-real-sha256');
    T::ok($s->kernel()->kmodUpgradePending(), 'installed .ko has since changed for this build_id');

    $s2 = new Sandbox();
    $s2->recordLoadedKmod('some-other-build-id', 'whatever');
    T::ok(!$s2->kernel()->kmodUpgradePending(), 'recorded load is for a kernel we are not running now');
});

T::test('status: an ineligible reason is recomputed live, not cached from the last dial', function () {
    $s = new Sandbox();
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $x->query('//ppps/ppp')->item(0)->appendChild($d->createElement('ondemand', '1'));
    });
    T::eq(Engine::EXIT_INELIGIBLE, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    T::contains('dial-on-demand', $s->engine()->statusReport()['interfaces']['wan']['reason']);
    /* the underlying fact changes without a new dial (e.g. the admin fixed the config
     * directly); the stale "dial-on-demand" text must not linger */
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        foreach ($x->query('//ppps/ppp[1]/ondemand') as $n) {
            $n->parentNode->removeChild($n);
        }
    });
    T::eq('eligible', $s->engine()->statusReport()['interfaces']['wan']['reason']);
});

T::test('status: an event-based reason is not overwritten by a stale recompute flag', function () {
    $s = new Sandbox();
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        $x->query('//ppps/ppp')->item(0)->appendChild($d->createElement('ondemand', '1'));
    });
    T::eq(Engine::EXIT_INELIGIBLE, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), 'first dial: ineligible, reason_recompute set');
    /* admin fixes the config and redials, but this dial fails in the kernel setup itself */
    $s->editConfig(function (\DOMDocument $d, \DOMXPath $x) {
        foreach ($x->query('//ppps/ppp[1]/ondemand') as $n) {
            $n->parentNode->removeChild($n);
        }
    });
    $s->fail([['pppoectl', '-S']]);
    T::eq(Engine::EXIT_FAILED, $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', ''), 'now eligible, but bringUp fails');
    /* the ineligible dial's reason_recompute flag must not survive to mask this
     * event-based reason with the (now eligible) live Eligibility verdict */
    T::contains('kernel setup failed', $s->engine()->statusReport()['interfaces']['wan']['reason']);
});

/* ------------------------------------------------ kernel matrix: coverage */

T::test('Kernel: elfBuildId() reads the GNU build-id note from sections, else PT_NOTE', function () {
    $s = new Sandbox();
    $s->installedKernel(Sandbox::NEW_BUILD_ID);
    T::eq(Sandbox::NEW_BUILD_ID, \IfPppoe\Engine\Kernel::elfBuildId($s->root . '/boot/kernel/kernel'), 'SHT_NOTE');
    $s->installedKernel(Sandbox::NEW_BUILD_ID, false);
    T::eq(Sandbox::NEW_BUILD_ID, \IfPppoe\Engine\Kernel::elfBuildId($s->root . '/boot/kernel/kernel'), 'PT_NOTE');
});

T::test('Kernel: a malformed or foreign kernel file yields no build-id, never a throw', function () {
    $s = new Sandbox();
    $good = Sandbox::elf(Sandbox::NEW_BUILD_ID);
    $cases = [
        'empty' => '',
        'not ELF' => str_repeat('x', 256),
        'truncated header' => substr($good, 0, 40),
        'ELF32' => substr_replace($good, chr(1), 4, 1),
        'big-endian' => substr_replace($good, chr(2), 5, 1),
        'section table past EOF' => substr($good, 0, strlen($good) - 10),
        'note sizes lie' => str_replace(pack('VVV', 4, 20, 3), pack('VVV', 4, 0x7fffffff, 3), $good),
    ];
    foreach ($cases as $what => $raw) {
        $s->installedKernel(null, true, $raw);
        T::eq(null, \IfPppoe\Engine\Kernel::elfBuildId($s->root . '/boot/kernel/kernel'), $what);
    }
    T::eq(null, \IfPppoe\Engine\Kernel::elfBuildId($s->root . '/no/such/file'), 'absent');
});

T::test('Kernel: installedKmodMatchesKernel() answers for the installed (next-boot) kernel', function () {
    /* an OPNsense kernel update installed, not rebooted yet; the kmod covers only the running one */
    $s = new Sandbox();
    $s->installedKernel(Sandbox::NEW_BUILD_ID);
    $k = $s->kernel();
    T::eq(Sandbox::NEW_BUILD_ID, $k->installedKernelBuildId());
    T::ok($k->runningKmodCovers(), 'running kernel still covered');
    T::ok(!$k->installedKmodMatchesKernel(), 'the kernel the next boot loads is not');

    /* an if-pppoe-kmod that covers only the new kernel: fine after the reboot */
    $s2 = new Sandbox();
    $s2->noInstalledBuildIds();
    $s2->installKoFor(Sandbox::NEW_BUILD_ID);
    $s2->installedKernel(Sandbox::NEW_BUILD_ID);
    T::ok(!$s2->kernel()->runningKmodCovers());
    T::ok($s2->kernel()->installedKmodMatchesKernel());
});

T::test('Kernel: an unreadable installed kernel falls back to the running kern.build_id', function () {
    $s = new Sandbox();
    $s->installedKernel(null, true, "not an ELF file\n");
    $k = $s->kernel();
    T::eq(null, $k->installedKernelBuildId());
    T::ok($k->installedKmodMatchesKernel(), 'running kernel is covered, so is the fallback');
});

T::test('Kernel: supportedKernels() parses kernels.json; absent or malformed is null (unknown)', function () {
    $s = new Sandbox();
    $s->kernelsJson([
        ['series' => '26.1', 'version' => '26.1.3', 'build_id' => strtoupper(Sandbox::NEW_BUILD_ID)],
        ['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID],
        ['version' => '<script>', 'build_id' => Sandbox::BUILD_ID],
        ['version' => '25.7.9', 'build_id' => 'not-hex'],
        'junk',
    ]);
    T::eq([
        ['version' => '26.1.3', 'series' => '26.1', 'build_id' => Sandbox::NEW_BUILD_ID],
        ['version' => '25.7.8', 'series' => '25.7', 'build_id' => Sandbox::BUILD_ID],
    ], $s->kernel()->supportedKernels());
    T::eq('26.1.3', $s->kernel()->kernelVersion(Sandbox::NEW_BUILD_ID));
    T::eq(null, $s->kernel()->kernelVersion('abcdef'));
    $s->noKernelsJson();
    T::eq(null, $s->kernel()->supportedKernels());
    $s->write('/usr/local/share/if_pppoe/kernels.json', '{"not": "a list"}');
    T::eq(null, $s->kernel()->supportedKernels());
    $s->kernelsJson([]);
    T::eq(null, $s->kernel()->supportedKernels(), 'a lab build ships []: names nothing, unknown');
});

T::test('status: kernels reports supported, running and installed coverage', function () {
    $s = new Sandbox();
    $r = $s->engine()->statusReport();
    T::eq([['version' => '25.7.8', 'series' => '25.7', 'build_id' => Sandbox::BUILD_ID]], $r['kernels']['supported']);
    T::eq(['build_id' => Sandbox::BUILD_ID, 'version' => '25.7.8', 'covered' => true], $r['kernels']['running']);
    T::eq(['build_id' => Sandbox::BUILD_ID, 'version' => '25.7.8', 'covered' => true, 'pending_reboot' => false],
        $r['kernels']['installed'], 'no /boot/kernel/kernel: installed = running');
    T::eq(null, $r['kernels']['upgrade']);
    T::ok($r['installed_eligible']);
});

T::test('status: an installed-but-not-booted kernel the kmod does not cover makes enabling ineligible, by name', function () {
    $s = new Sandbox();
    $s->kernelsJson([['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID]]);
    $s->installedKernel(Sandbox::NEW_BUILD_ID);
    $r = $s->engine()->statusReport();
    T::eq(['build_id' => Sandbox::NEW_BUILD_ID, 'version' => null, 'covered' => false, 'pending_reboot' => true], $r['kernels']['installed']);
    T::eq(true, $r['kernels']['running']['covered']);
    T::eq(false, $r['installed_eligible']);
    T::contains('the installed kernel build-id ' . substr(Sandbox::NEW_BUILD_ID, 0, 12) . ' (pending reboot) is not covered', $r['installed_reason']);

    /* named when kernels.json knows it; covered once the kmod ships its .ko */
    $s->kernelsJson([['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID], ['version' => '25.7.10', 'build_id' => Sandbox::NEW_BUILD_ID]]);
    T::contains('the installed kernel 25.7.10 (pending reboot)', $s->engine()->statusReport()['installed_reason']);
    $s->installKoFor(Sandbox::NEW_BUILD_ID);
    $r = $s->engine()->statusReport();
    T::eq(true, $r['kernels']['installed']['covered']);
    T::eq(true, $r['installed_eligible']);
    T::eq('', $r['installed_reason']);
});

T::test('status: the running kernel not covered, installed = running, keeps the old reason', function () {
    $s = new Sandbox();
    $s->noInstalledBuildIds();
    $r = $s->engine()->statusReport();
    T::eq(false, $r['kernels']['running']['covered']);
    T::eq(false, $r['kernels']['installed']['pending_reboot']);
    T::eq('no installed kernel module matches the running kernel', $r['installed_reason']);
});

T::test('status: no kernels.json (older kmod) is unknown, not ineligible', function () {
    $s = new Sandbox();
    $s->noKernelsJson();
    $r = $s->engine()->statusReport();
    T::eq(null, $r['kernels']['supported']);
    T::eq(null, $r['kernels']['running']['version']);
    T::eq(true, $r['kernels']['running']['covered'], 'build_ids still decides coverage');
    T::ok($r['installed_eligible']);
});

T::test('status: a deferred major upgrade is reported; unlisted means "decided by the upgrade", not "not covered"', function () {
    $s = new Sandbox();
    $s->write('/var/cache/opnsense-update/.kernel.pending', "26.7\n");
    $r = $s->engine()->statusReport();
    T::eq(['version' => '26.7', 'covered' => null], $r['kernels']['upgrade']);
    T::ok($r['installed_eligible'], 'a staged upgrade alone never makes enabling ineligible');
    $s->kernelsJson([['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID], ['version' => '26.7', 'build_id' => Sandbox::NEW_BUILD_ID]]);
    $s->installKoFor(Sandbox::NEW_BUILD_ID);
    T::eq(['version' => '26.7', 'covered' => true], $s->engine()->statusReport()['kernels']['upgrade']);
    $s->write('/var/cache/opnsense-update/.kernel.pending', "../../etc\n");
    T::eq(null, $s->engine()->statusReport()['kernels']['upgrade'], 'junk release ignored');
});
