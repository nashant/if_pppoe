<?php

namespace IfPppoe\Test;

use IfPppoe\Engine\Config;
use IfPppoe\Engine\Eligibility;
use IfPppoe\Engine\SystemFacts;

final class FakeFacts implements SystemFacts
{
    public bool $hook = true;
    public bool $latch = false;
    public array $missing = [];
    public array $parents = [
        'igb1' => ['exists' => true, 'ether' => true, 'mtu' => 1500, 'why' => ''],
        'igb2' => ['exists' => true, 'ether' => true, 'mtu' => 1500, 'why' => ''],
        'vlan0.100' => ['exists' => true, 'ether' => true, 'mtu' => 1508, 'why' => ''],
        'bridge0' => ['exists' => true, 'ether' => false, 'mtu' => 1500, 'why' => 'interface type not supported'],
    ];

    public function hookApplied(): bool
    {
        return $this->hook;
    }

    public function latched(): bool
    {
        return $this->latch;
    }

    public function missingFeatures(): array
    {
        return $this->missing;
    }

    public function parentInfo(string $ifname): array
    {
        return $this->parents[$ifname] ?? ['exists' => false, 'ether' => false, 'mtu' => 0, 'why' => ''];
    }
}

function fixture(string $name): string
{
    return file_get_contents(__DIR__ . "/fixtures/$name");
}

/** base fixture with the first <ppp> edited: $set = [field => value|null(remove)] */
function pppVariant(array $set, array $ifset = [], string $fixture = 'config-base.xml'): Config
{
    $dom = new \DOMDocument();
    $dom->loadXML(fixture($fixture));
    $xp = new \DOMXPath($dom);
    $ppp = $xp->query('/opnsense/ppps/ppp')->item(0);
    $wan = $xp->query('/opnsense/interfaces/wan')->item(0);
    foreach ([[$ppp, $set], [$wan, $ifset]] as [$node, $changes]) {
        foreach ($changes as $k => $v) {
            foreach ($xp->query($k, $node) as $old) {
                $node->removeChild($old);
            }
            if ($v !== null) {
                $el = $dom->createElement($k);
                $el->appendChild($dom->createTextNode($v));
                $node->appendChild($el);
            }
        }
    }
    return Config::fromString($dom->saveXML());
}

function decide(Config $c, ?FakeFacts $f = null, array $exclude = [], array $hookArgs = [], string $friendly = 'wan', string $dev = 'pppoe0')
{
    return (new Eligibility($c, $f ?? new FakeFacts()))->evaluate($friendly, $dev, $exclude, $hookArgs);
}

T::test('config: parses single and repeated <ppp>, presence booleans', function () {
    $c = Config::fromString(fixture('config-multi.xml'));
    T::eq(3, count($c->ppps()));
    T::eq('vlan0.100', $c->pppByDevice('pppoe1')['ports']);
    T::eq('opt1', $c->friendlyForDevice('pppoe1'));
    T::ok(isset($c->pppByDevice('pppoe2')['ondemand']));
    T::ok(!isset($c->pppByDevice('pppoe0')['ondemand']));
    T::eq(1, count(Config::fromString(fixture('config-base.xml'))->ppps()));
    T::eq(['enabled' => true, 'exclude' => []], $c->pluginSettings());
    T::ok($c->dnsAllowOverride());
    T::eq(null, $c->haReason());
    T::ok(Config::fromString(fixture('config-ha.xml'))->haReason() !== null);
});

T::test('eligibility: base fixture is eligible with the expected plan', function () {
    $d = decide(Config::fromString(fixture('config-base.xml')));
    T::eq('eligible', $d->reason());
    T::ok($d->eligible());
    $p = $d->plan;
    T::eq('igb1', $p->parent);
    T::eq('ISP-SVC', $p->service);
    T::eq('user@isp.example', $p->username);
    T::eq('s3cr3t-Pa55', $p->password);
    T::eq(1492, $p->mtu);
    T::ok($p->ipcp && $p->ipv6cp && $p->queryDns && $p->mssfix);
    foreach (['type', 'if', 'ports', 'username', 'password', 'provider', 'uptime', 'ptpid', 'descr', 'mtu'] as $f) {
        T::eq('supported', $d->fields[$f] ?? null, "field $f");
    }
    T::eq('ignored: multilink only', $d->fields['mrru']);
    T::ok(!str_contains(json_encode($p->publicView()), 's3cr3t'), 'public view has no secret');
});

T::test('eligibility: every <ppp> field known to core 25.7.11 is mapped', function () {
    /* interfaces_ppps_edit.php at 25.7.11 writes exactly these keys */
    $keys = ['ptpid', 'type', 'if', 'ports', 'username', 'password', 'ondemand', 'idletimeout', 'uptime', 'descr',
        'initstr', 'simpin', 'pin-wait', 'apn', 'apnum', 'phone', 'localip', 'gateway', 'connect-timeout', 'provider',
        'hostuniq', 'subnet', 'shortseq', 'acfcomp', 'protocomp', 'vjcomp', 'tcpmssfix', 'bandwidth', 'mtu', 'mru', 'mrru'];
    $set = array_fill_keys($keys, '');
    $set['type'] = 'pppoe';
    $set['if'] = 'pppoe0';
    $set['ports'] = 'igb1';
    $set['username'] = 'u';
    $set['password'] = base64_encode('p');
    unset($set['ondemand'], $set['idletimeout']);
    $d = decide(pppVariant($set));
    foreach ($keys as $k) {
        if (isset($set[$k])) {
            T::ok(isset($d->fields[$k]), "field $k not mapped");
            T::ok(!str_starts_with($d->fields[$k], 'ineligible: unknown'), "field $k unknown");
        }
    }
    T::ok($d->eligible(), $d->reason());
});

T::test('eligibility: ineligible matrix', function () {
    $cases = [
        'ondemand' => [['ondemand' => '1'], [], 'dial-on-demand'],
        'idle timeout' => [['idletimeout' => '300'], [], 'idle timeout'],
        'MLPPP' => [['ports' => 'igb1,igb2'], [], 'multiple ports'],
        'no ports' => [['ports' => ''], [], 'no parent port'],
        'hostuniq' => [['hostuniq' => 'abc'], [], 'Host-Uniq'],
        'static localip' => [['localip' => '10.0.0.1'], [], 'static local IP'],
        'static gateway' => [['gateway' => '10.0.0.2'], [], 'static gateway'],
        'mtu too big' => [['mtu' => '1501'], [], 'outside 128..1500'],
        'rfc4638 parent too small' => [['mtu' => '1500'], [], 'needs parent igb1 MTU >= 1508'],
        'mtu garbage' => [['mtu' => '15x0'], [], 'not a number'],
        'mru differs' => [['mru' => '1400'], [], 'differs from MTU'],
        'mru too big' => [['mru' => '1600'], [], 'above 1500'],
        'bad base64' => [['password' => '***not base64***'], [], 'not valid base64'],
        'empty password' => [['password' => ''], [], 'password: empty'],
        'newline in password' => [['password' => base64_encode("a\nb")], [], 'NUL, CR or LF'],
        'NUL in password' => [['password' => base64_encode("a\0b")], [], 'NUL, CR or LF'],
        'long password' => [['password' => base64_encode(str_repeat('x', 256))], [], 'longer than 255'],
        'empty username' => [['username' => ''], [], 'username: empty'],
        'CR in username' => [['username' => "u\rx"], [], 'NUL, CR or LF'],
        'long service' => [['provider' => str_repeat('s', 257)], [], 'longer than 256'],
        'pptp' => [['type' => 'pptp'], [], 'not pppoe'],
        'unknown field' => [['futurefield' => '1'], [], 'unsupported <ppp> field futurefield'],
        'parent missing' => [['ports' => 'igb9'], [], 'does not exist'],
        'parent bridge' => [['ports' => 'bridge0'], [], 'not an Ethernet or VLAN'],
        'bad parent name' => [['ports' => 'igb1;reboot'], [], 'not a valid interface name'],
        'interface disabled' => [[], ['enable' => null], 'is disabled'],
        'no PPP family' => [[], ['ipaddr' => 'dhcp', 'ipaddrv6' => 'none'], 'neither IPv4 nor IPv6'],
    ];
    foreach ($cases as $name => [$set, $ifset, $expect]) {
        $d = decide(pppVariant($set, $ifset));
        T::ok(!$d->eligible(), "$name should be ineligible");
        T::contains($expect, $d->reason(), $name);
    }
});

T::test('eligibility: eligible variants', function () {
    $d = decide(pppVariant(['idletimeout' => '0']));
    T::ok($d->eligible(), 'idletimeout 0: ' . $d->reason());
    $d = decide(pppVariant(['hostuniq' => '']));
    T::ok($d->eligible(), 'empty hostuniq: ' . $d->reason());
    $d = decide(pppVariant(['mtu' => '1500', 'ports' => 'vlan0.100', 'mru' => '1500']));
    T::ok($d->eligible(), 'RFC4638 on 1508 parent: ' . $d->reason());
    T::eq(1500, $d->plan->mtu);
    $d = decide(pppVariant(['tcpmssfix' => '1', 'vjcomp' => '1', 'acfcomp' => '1', 'protocomp' => '1', 'shortseq' => '1']));
    T::ok($d->eligible(), $d->reason());
    T::ok(!$d->plan->mssfix, 'tcpmssfix present disables the clamp');
    $d = decide(pppVariant([], ['ipaddr' => 'none', 'ipaddrv6' => 'pppoev6']));
    T::ok($d->eligible() && !$d->plan->ipcp && $d->plan->ipv6cp, 'IPv6-only');
    T::ok(!$d->plan->queryDns, 'no DNS query without IPCP');
    $d = decide(pppVariant([], ['mtu' => '1500']));
    T::eq(1492, $d->plan->mtu, 'interface MTU - 8');
    $d = decide(pppVariant(['mtu' => '1480,1400']));
    T::eq(1480, $d->plan->mtu, 'first csv value');
    $d = decide(pppVariant(['ports' => 'lan']));
    T::contains('igb0', $d->reason(), 'friendly port resolves to its device');
});

T::test('eligibility: hook args override config values (core already resolved them)', function () {
    $d = decide(pppVariant(['ports' => 'igbX']), null, [], ['ports' => 'igb1', 'mtu' => '1480', 'mru' => '']);
    T::ok($d->eligible(), $d->reason());
    T::eq('igb1', $d->plan->parent);
    T::eq(1480, $d->plan->mtu);
});

T::test('eligibility: plugin-level refusals', function () {
    $c = Config::fromString(fixture('config-base.xml'));
    $f = new FakeFacts();
    $f->hook = false;
    T::contains('hook is not applied', decide($c, $f)->reason());
    $f = new FakeFacts();
    $f->latch = true;
    T::contains('latched', decide($c, $f)->reason());
    $f = new FakeFacts();
    $f->missing = ['if_pppoe_mssfix'];
    T::contains('features missing: if_pppoe_mssfix', decide($c, $f)->reason());
    T::contains('excluded', decide($c, null, ['wan'])->reason());
    T::contains('CARP', decide(Config::fromString(fixture('config-ha.xml')))->reason());
    T::contains('not a pppoeN name', decide($c, null, [], [], 'wan', 'ng0')->reason());
    T::contains('not assigned', decide($c, null, [], [], 'opt9', 'pppoe0')->reason());
    T::contains('assigned to pppoe0, not pppoe1', decide($c, null, [], [], 'wan', 'pppoe1')->reason());
});

T::test('eligibility: multi-WAN fixture', function () {
    $c = Config::fromString(fixture('config-multi.xml'));
    T::ok(decide($c)->eligible(), 'wan');
    $d = decide($c, null, [], [], 'opt1', 'pppoe1');
    T::ok($d->eligible(), 'opt1: ' . $d->reason());
    T::eq('other#pw\\x', $d->plan->password);
    T::ok(!$d->plan->ipv6cp);
    $d = decide($c, null, [], [], 'opt2', 'pppoe2');
    T::contains('disabled', $d->reason());
    T::contains('dial-on-demand', $d->reason());
});
