<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

/** What the kernel backend would do for one interface, or why it won't. */
final class Plan
{
    public string $friendly = '';
    public string $device = '';
    public string $parent = '';
    public string $service = '';
    public string $username = '';
    public string $password = '';
    public int $mtu = 1492;
    public bool $ipcp = true;
    public bool $ipv6cp = false;
    public bool $queryDns = false;
    public bool $mssfix = true;

    /** everything except the credentials, for the registry and status page */
    public function publicView(): array
    {
        return [
            'friendly' => $this->friendly,
            'device' => $this->device,
            'parent' => $this->parent,
            'service' => $this->service,
            'mtu' => $this->mtu,
            'ipcp' => $this->ipcp,
            'ipv6cp' => $this->ipv6cp,
            'query_dns' => $this->queryDns,
            'mssfix' => $this->mssfix,
        ];
    }

    /** stable digest of the dial parameters; the secret is folded in hashed */
    public function fingerprint(): string
    {
        return hash('sha256', json_encode($this->publicView()) . "\0" . hash('sha256', $this->username . "\0" . $this->password));
    }
}

final class Decision
{
    /** @var array<string,string> <ppp> field => 'supported' | 'ignored: ...' | 'ineligible: ...' */
    public array $fields = [];
    public array $reasons = [];
    public ?Plan $plan = null;

    public function eligible(): bool
    {
        return $this->reasons === [] && $this->plan !== null;
    }

    public function reason(): string
    {
        return $this->reasons === [] ? 'eligible' : implode('; ', $this->reasons);
    }

    public function refuse(string $why): void
    {
        $this->reasons[] = $why;
    }
}

/** Facts about the running system that eligibility depends on. */
interface SystemFacts
{
    public function hookApplied(): bool;

    public function latched(): bool;

    /** @return string[] missing kern.features names */
    public function missingFeatures(): array;

    /** ['exists'=>bool, 'ether'=>bool, 'mtu'=>int, 'why'=>string] */
    public function parentInfo(string $ifname): array;
}

final class Eligibility
{
    public const MAX_AUTH_LEN = 255;     /* SPPP_AUTH_BUFMAX - 1, if_spppsubr.c:6219 */
    public const MAX_SERVICE_LEN = 256;  /* PPPOE_MAX_NAMELEN, if_pppoe.c:1949 */

    private const FIELD_RULES = [
        'type' => 'check',
        'if' => 'check',
        'ptpid' => 'supported',
        'descr' => 'supported',
        'ports' => 'check',
        'username' => 'check',
        'password' => 'check',
        'provider' => 'check',
        'hostuniq' => 'check',
        'ondemand' => 'check',
        'idletimeout' => 'check',
        'uptime' => 'supported',
        'tcpmssfix' => 'supported',
        'vjcomp' => 'ignored: the kernel never negotiates VJ compression',
        'acfcomp' => 'ignored: the kernel never negotiates ACFC',
        'protocomp' => 'ignored: the kernel never negotiates PFC',
        'shortseq' => 'ignored: multilink only',
        'mrru' => 'ignored: multilink only',
        'bandwidth' => 'ignored: multilink only',
        'mtu' => 'check',
        'mru' => 'check',
        'localip' => 'check',
        'gateway' => 'check',
        'subnet' => 'check',
        'phone' => 'ignored: modem only',
        'apn' => 'ignored: modem only',
        'apnum' => 'ignored: modem only',
        'initstr' => 'ignored: modem only',
        'simpin' => 'ignored: modem only',
        'pin-wait' => 'ignored: modem only',
        'connect-timeout' => 'ignored: modem only',
    ];

    public function __construct(private Config $config, private SystemFacts $sys)
    {
    }

    /**
     * @param string[] $exclude friendly names the plugin must leave to mpd5
     * @param array $hookArgs optional ['ports'=>csv, 'mtu'=>string, 'mru'=>string] from the hook
     */
    public function evaluate(string $friendly, string $device, array $exclude, array $hookArgs = []): Decision
    {
        $d = new Decision();

        if (!$this->sys->hookApplied()) {
            $d->refuse('interfaces.inc hook is not applied');
        }
        if ($this->sys->latched()) {
            $d->refuse('kernel mode latched off after repeated unclean boots');
        }
        $missing = $this->sys->missingFeatures();
        if ($missing !== []) {
            $d->refuse('kernel module features missing: ' . implode(',', $missing));
        }
        $ha = $this->config->haReason();
        if ($ha !== null) {
            $d->refuse($ha);
        }
        if (in_array($friendly, $exclude, true)) {
            $d->refuse("{$friendly} is excluded in the plugin settings");
        }
        if (!preg_match('/^pppoe[0-9]{1,4}$/', $device)) {
            $d->refuse("device {$device} is not a pppoeN name");
            return $d;
        }

        $ifcfg = $this->config->iface($friendly);
        if ($ifcfg === null) {
            $d->refuse("interface {$friendly} is not assigned");
            return $d;
        }
        if (($ifcfg['if'] ?? '') !== $device) {
            $d->refuse("interface {$friendly} is assigned to " . ($ifcfg['if'] ?? '?') . ", not {$device}");
            return $d;
        }
        if (!isset($ifcfg['enable'])) {
            $d->refuse("interface {$friendly} is disabled");
        }
        $ppp = $this->config->pppByDevice($device);
        if ($ppp === null) {
            $d->refuse("no <ppp> entry for {$device}");
            return $d;
        }

        $plan = new Plan();
        $plan->friendly = $friendly;
        $plan->device = $device;

        /* interfaces.inc:1047-1070 at 25.7.11 */
        $plan->ipcp = in_array($ifcfg['ipaddr'] ?? 'none', ['ppp', 'pppoe', 'pptp', 'l2tp'], true);
        $plan->ipv6cp = in_array($ifcfg['ipaddrv6'] ?? 'none', ['dhcp6', 'pppoev6', 'slaac'], true);
        if (!$plan->ipcp && !$plan->ipv6cp) {
            $d->refuse('neither IPv4 nor IPv6 is set to PPP on this interface');
        }
        /* interfaces.inc:1193: DNS is requested only when "allow DNS override" is set */
        $plan->queryDns = $plan->ipcp && $this->config->dnsAllowOverride();

        foreach ($ppp as $k => $v) {
            $rule = self::FIELD_RULES[$k] ?? null;
            if ($rule === null) {
                $d->fields[$k] = 'ineligible: unknown field';
                $d->refuse("unsupported <ppp> field {$k}");
            } elseif ($rule !== 'check') {
                $d->fields[$k] = $rule;
            }
        }

        $this->checkType($ppp, $d);
        $this->checkPorts($ppp, $plan, $d, $hookArgs);
        $this->checkAuth($ppp, $plan, $d);
        $this->checkService($ppp, $plan, $d);
        $this->checkDialMode($ppp, $d);
        $this->checkStatic($ppp, $d);
        $this->checkMtu($ppp, $ifcfg, $plan, $d, $hookArgs);

        /* interfaces.inc:1171-1175: <tcpmssfix/> present means mpd5 "disable tcpmssfix" */
        $plan->mssfix = !isset($ppp['tcpmssfix']);

        $d->plan = $plan;
        return $d;
    }

    private function mark(Decision $d, string $field, ?string $problem, bool $present = true): void
    {
        if ($problem === null) {
            if ($present) {
                $d->fields[$field] = 'supported';
            }
            return;
        }
        $d->fields[$field] = "ineligible: {$problem}";
        $d->refuse("{$field}: {$problem}");
    }

    private function checkType(array $ppp, Decision $d): void
    {
        $type = (string)($ppp['type'] ?? '');
        $this->mark($d, 'type', $type === 'pppoe' ? null : "type {$type} is not pppoe");
        $this->mark($d, 'if', null);
    }

    private function checkPorts(array $ppp, Plan $plan, Decision $d, array $hookArgs): void
    {
        $csv = isset($hookArgs['ports']) && $hookArgs['ports'] !== '' ? $hookArgs['ports'] : (string)($ppp['ports'] ?? '');
        $ports = array_values(array_filter(array_map('trim', explode(',', $csv)), fn($p) => $p !== ''));
        if (count($ports) !== 1) {
            $this->mark($d, 'ports', count($ports) === 0 ? 'no parent port' : 'multiple ports (MLPPP) are not supported');
            return;
        }
        $parent = $this->config->realInterface($ports[0]);
        if (!preg_match('/^[A-Za-z0-9_.]{1,15}$/', $parent)) {
            $this->mark($d, 'ports', "parent name {$parent} is not a valid interface name");
            return;
        }
        $info = $this->sys->parentInfo($parent);
        if (!$info['exists']) {
            $this->mark($d, 'ports', "parent {$parent} does not exist");
            return;
        }
        if (!$info['ether']) {
            $this->mark($d, 'ports', "parent {$parent} is not an Ethernet or VLAN interface" . ($info['why'] !== '' ? " ({$info['why']})" : ''));
            return;
        }
        $plan->parent = $parent;
        $this->mark($d, 'ports', null);
    }

    private static function badChars(string $s): ?string
    {
        if (strpbrk($s, "\0\n\r") !== false) {
            return 'contains NUL, CR or LF';
        }
        return null;
    }

    private function checkAuth(array $ppp, Plan $plan, Decision $d): void
    {
        $user = (string)($ppp['username'] ?? '');
        $problem = null;
        if ($user === '') {
            $problem = 'empty';
        } elseif (strlen($user) > self::MAX_AUTH_LEN) {
            $problem = 'longer than ' . self::MAX_AUTH_LEN . ' bytes';
        } else {
            $problem = self::badChars($user);
        }
        $this->mark($d, 'username', $problem);
        $plan->username = $user;

        /* interfaces_ppps_edit.php:220 stores base64_encode($password) */
        $raw = (string)($ppp['password'] ?? '');
        $pw = base64_decode($raw, true);
        $problem = null;
        if ($pw === false) {
            $problem = 'not valid base64';
            $pw = '';
        } elseif ($pw === '') {
            $problem = 'empty';
        } elseif (strlen($pw) > self::MAX_AUTH_LEN) {
            $problem = 'longer than ' . self::MAX_AUTH_LEN . ' bytes';
        } else {
            $problem = self::badChars($pw);
        }
        $this->mark($d, 'password', $problem);
        $plan->password = $pw;
    }

    private function checkService(array $ppp, Plan $plan, Decision $d): void
    {
        $svc = (string)($ppp['provider'] ?? '');
        $problem = null;
        if (strlen($svc) > self::MAX_SERVICE_LEN) {
            $problem = 'longer than ' . self::MAX_SERVICE_LEN . ' bytes';
        } elseif ($svc !== '') {
            $problem = self::badChars($svc);
        }
        $this->mark($d, 'provider', $problem, array_key_exists('provider', $ppp));
        $plan->service = $svc;

        if (array_key_exists('hostuniq', $ppp)) {
            /* the kmod always sends its own 64-bit Host-Uniq; PPPOESETPARMS has no field for one */
            $this->mark($d, 'hostuniq', (string)$ppp['hostuniq'] === '' ? null : 'custom Host-Uniq is not supported by the kernel driver');
        }
    }

    private function checkDialMode(array $ppp, Decision $d): void
    {
        if (array_key_exists('ondemand', $ppp)) {
            $this->mark($d, 'ondemand', 'dial-on-demand is not supported');
        }
        if (array_key_exists('idletimeout', $ppp)) {
            $v = trim((string)$ppp['idletimeout']);
            $this->mark($d, 'idletimeout', ($v === '' || $v === '0') ? null : 'idle timeout is not supported');
        }
    }

    private function checkStatic(array $ppp, Decision $d): void
    {
        foreach (['localip' => 'static local IP', 'gateway' => 'static gateway', 'subnet' => 'static subnet'] as $k => $what) {
            if (array_key_exists($k, $ppp)) {
                $v = trim(str_replace(',', '', (string)$ppp[$k]));
                $this->mark($d, $k, $v === '' ? null : "{$what} is not supported");
            }
        }
    }

    private static function firstCsv($v): string
    {
        $parts = explode(',', (string)$v);
        return trim($parts[0]);
    }

    private function checkMtu(array $ppp, array $ifcfg, Plan $plan, Decision $d, array $hookArgs): void
    {
        /* interfaces.inc:1096 and 1232-1235: <ppp><mtu>, else interface MTU - 8, else 1492 */
        $mtu = null;
        $src = 'mtu';
        if (isset($hookArgs['mtu']) && $hookArgs['mtu'] !== '') {
            $mtu = $hookArgs['mtu'];
        } elseif (self::firstCsv($ppp['mtu'] ?? '') !== '') {
            $mtu = self::firstCsv($ppp['mtu']);
        } elseif (!empty($ifcfg['mtu'])) {
            $mtu = (string)((int)$ifcfg['mtu'] - 8);
        } else {
            $mtu = '1492';
        }
        $problem = null;
        if (!ctype_digit((string)$mtu)) {
            $problem = "MTU {$mtu} is not a number";
        } else {
            $mtu = (int)$mtu;
            if ($mtu < 128 || $mtu > 1500) {
                $problem = "MTU {$mtu} outside 128..1500 (PPP_MINMRU..PP_MTU)";
            } elseif ($mtu > 1492 && $plan->parent !== '') {
                /* RFC 4638: the parent must carry mtu + 8 (the kmod enforces the same, if_pppoe.c:2258-2277) */
                $pmtu = $this->sys->parentInfo($plan->parent)['mtu'];
                if ($pmtu < $mtu + 8) {
                    $problem = "MTU {$mtu} needs parent {$plan->parent} MTU >= " . ($mtu + 8) . " (is {$pmtu})";
                }
            }
        }
        $this->mark($d, $src, $problem, true);
        if ($problem === null) {
            $plan->mtu = $mtu;
        }

        $mru = isset($hookArgs['mru']) && $hookArgs['mru'] !== '' ? $hookArgs['mru'] : self::firstCsv($ppp['mru'] ?? '');
        if ($mru !== '' || array_key_exists('mru', $ppp)) {
            $problem = null;
            if ($mru !== '') {
                if (!ctype_digit($mru)) {
                    $problem = "MRU {$mru} is not a number";
                } elseif ((int)$mru > 1500) {
                    $problem = "MRU {$mru} above 1500";
                } elseif ((int)$mru !== $plan->mtu) {
                    /* sppp derives the LCP MRU from if_mtu (if_spppsubr.c:2774-2778) */
                    $problem = "MRU {$mru} differs from MTU {$plan->mtu}; the kernel advertises MRU = MTU";
                }
            }
            $this->mark($d, 'mru', $problem);
        }
    }
}
