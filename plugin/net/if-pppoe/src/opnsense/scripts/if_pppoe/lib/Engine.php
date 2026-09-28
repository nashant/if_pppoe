<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

final class Engine
{
    public const EXIT_CLAIMED = 0;
    public const EXIT_INELIGIBLE = 1;
    public const EXIT_FAILED = 2;
    public const EXIT_USAGE = 64;

    public const EVENTS = ['IPCP_UP', 'IPCP_DOWN', 'IPV6CP_UP', 'IPV6CP_DOWN', 'SESSION_UP', 'SESSION_DOWN', 'AUTH_FAIL'];

    /* reconcile: do not ask core to re-run configure for the same interface more often than this */
    public const RECONFIGURE_BACKOFF = 3600;

    /* configure must finish inside the hook's `timeout 45` */
    public const CONFIGURE_LOCK_WAIT = 20.0;

    private Registry $reg;
    private StatusStore $status;
    private Pppoectl $ctl;
    private ?Config $config = null;
    /* linkevent: how long a detached drain waits for the device lock (configure holds it for up to ~45s) */
    public const DRAIN_LOCK_WAIT = 120.0;

    /* per-device locks taken by reconcile: skip the device on timeout, retry next pass */
    public const RECONCILE_LOCK_WAIT = 5.0;

    /** @var callable(int,string):void */
    private $logger;
    /** @var callable(string):void|null */
    private $dispatcher;

    /**
     * @param callable(string):void|null $dispatcher starts `engine drain <device>` detached from
     *        devd; tests pass a synchronous one
     */
    public function __construct(private Env $env, private Kernel $k, ?callable $logger = null, ?callable $dispatcher = null)
    {
        $this->reg = new Registry($env);
        $this->status = new StatusStore($env);
        $this->ctl = new Pppoectl($env);
        $this->logger = $logger ?? static function (int $prio, string $msg): void {
            openlog('if_pppoe', LOG_PID, LOG_DAEMON);
            syslog($prio, $msg);
            closelog();
        };
        $this->dispatcher = $dispatcher;
    }

    /** device lock for a reconcile step, or null (logged) when someone else holds it */
    private function tryLock(string $device, float $wait): ?Lock
    {
        try {
            return Lock::acquire($this->env, $device, $wait);
        } catch (\RuntimeException $e) {
            $this->log(LOG_WARNING, "{$device}: " . $e->getMessage() . '; skipped this pass');
            return null;
        }
    }

    private function log(int $prio, string $msg): void
    {
        ($this->logger)($prio, $msg);
    }

    private function config(): Config
    {
        if ($this->config === null) {
            $this->config = Config::fromFile($this->env->configXml());
        }
        return $this->config;
    }

    private function run(array $argv, ?string $stdin = null, int $timeout = 30): ProcResult
    {
        return $this->k->proc()->run($argv, $stdin, $timeout);
    }

    private function must(array $argv, string $what, ?string $stdin = null): void
    {
        $r = $this->run($argv, $stdin);
        if (!$r->ok()) {
            throw new \RuntimeException("{$what} failed (rc={$r->rc}): " . trim($r->err));
        }
    }

    /**
     * Plugin settings as they were on the first engine run of this boot:
     * changes on the Services page only take effect after a reboot.
     */
    public function effective(): array
    {
        $file = $this->env->effectiveJson();
        $eff = Fs::readJson($file);
        if ($eff !== null) {
            return $eff;
        }
        $lock = Lock::acquire($this->env, 'effective', 10.0);
        try {
            $eff = Fs::readJson($file);
            if ($eff === null) {
                $s = $this->config()->pluginSettings();
                $eff = ['enabled' => $s['enabled'], 'exclude' => $s['exclude'], 'since' => time()];
                Fs::writeJson($file, $eff);
            }
        } finally {
            $lock->release();
        }
        return $eff;
    }

    public static function validFriendly(string $f): bool
    {
        return (bool)preg_match('/^[a-z][a-z0-9_]{0,31}$/', $f);
    }

    public static function validDevice(string $d): bool
    {
        return (bool)preg_match('/^pppoe[0-9]{1,4}$/', $d);
    }

    /* ------------------------------------------------------------ configure */

    public function configure(string $friendly, string $device, string $ports = '', string $mtu = '', string $mru = ''): int
    {
        if (!self::validFriendly($friendly) || !self::validDevice($device)) {
            $this->log(LOG_ERR, "configure: invalid arguments '{$friendly}' '{$device}'");
            return self::EXIT_USAGE;
        }
        $elig = new Eligibility($this->config(), $this->k);
        $decision = $elig->evaluate($friendly, $device, $this->effective()['exclude'] ?? [], [
            'ports' => $ports, 'mtu' => $mtu, 'mru' => $mru,
        ]);

        $lock = Lock::acquire($this->env, $device, self::CONFIGURE_LOCK_WAIT);
        try {
            $existing = $this->reg->get($device);
            if (!$decision->eligible()) {
                if ($existing !== null || $this->k->isClone($device)) {
                    $this->teardown($device, $existing, 'now ineligible');
                }
                $this->status->record($friendly, [
                    'device' => $device, 'backend' => 'mpd5', 'reason' => $decision->reason(),
                    'fields' => $decision->fields, 'result' => 'ineligible',
                    /* statusReport() recomputes this reason live on every read instead of
                     * showing this dial's snapshot, which would go stale as soon as the
                     * underlying fact changes (e.g. a kmod upgrade fixes a missing feature). */
                    'reason_recompute' => true,
                ]);
                $this->log(LOG_NOTICE, "{$friendly} ({$device}): using mpd5: " . $decision->reason());
                return self::EXIT_INELIGIBLE;
            }

            $plan = $decision->plan;
            /* full restart: an existing session is always torn down first */
            if ($existing !== null || $this->k->isClone($device)) {
                $this->teardown($device, $existing, 'reconfigure');
            }

            try {
                $this->bringUp($plan);
            } catch (\Throwable $e) {
                $this->k->forget($device);
                if ($this->k->isClone($device)) {
                    $this->destroyQuiet($device);
                }
                $this->reg->remove($device);
                $this->status->record($friendly, [
                    'device' => $device, 'backend' => 'mpd5', 'reason' => 'kernel setup failed: ' . $e->getMessage(),
                    'fields' => $decision->fields, 'result' => 'failed', 'failed_at' => time(),
                ]);
                $this->log(LOG_ERR, "{$friendly} ({$device}): kernel setup failed, falling back to mpd5: " . $e->getMessage());
                return self::EXIT_FAILED;
            }

            /* last step: core runs mpd5 -f on this file (with the password, interfaces.inc:1319) on any non-zero exit or kill */
            @unlink($this->env->mpdConf($friendly));
            $this->reg->update($device, ['state' => 'dialing']);

            $this->status->record($friendly, [
                'device' => $device, 'backend' => 'kernel', 'reason' => 'eligible',
                'fields' => $decision->fields, 'result' => 'claimed',
            ]);
            $this->log(LOG_NOTICE, "{$friendly} ({$device}): dialling with the kernel driver on {$plan->parent}");
            return self::EXIT_CLAIMED;
        } finally {
            $lock->release();
        }
    }

    private function bringUp(Plan $p): void
    {
        $dev = $p->device;
        $ifconfig = $this->env->bin('ifconfig');

        /* mpd5 was killed by core just before the hook; its ng(4) iface of the same name may linger briefly */
        for ($i = 0; $i < 50 && $this->k->ifInfo($dev) !== null; $i++) {
            usleep(100000);
            $this->k->forget($dev);
        }
        if ($this->k->ifInfo($dev) !== null) {
            throw new \RuntimeException("{$dev} still exists and is not ours (mpd5 leftover?)");
        }

        $this->must([$ifconfig, $dev, 'create'], 'clone create');
        $this->k->forget($dev);
        $this->reg->put($dev, [
            'friendly' => $p->friendly, 'state' => 'configuring', 'created' => time(), 'created_us' => microtime(true),
            'plan' => $p->publicView(), 'fingerprint' => $p->fingerprint(),
            'v4' => 'down', 'v6' => 'down', 'session' => 'down',
        ]);
        /* a fresh clone may be born IFF_UP; sppp only opens LCP on a real down->up edge */
        $this->must([$ifconfig, $dev, 'down'], 'ifconfig down');
        $this->must($this->ctl->discoveryArgv($p), 'pppoectl discovery');
        /* secret on stdin (-S), the other settings in a private temp file (-f); never both on stdin */
        $this->ctl->withSettingsFile($p, function (string $cfg) use ($p): void {
            $this->must($this->ctl->settingsArgv($p, $cfg), 'pppoectl settings', $this->ctl->settingsStdin($p));
        });
        $r = $this->run($this->ctl->verifyArgv($p));
        if (!$r->ok()) {
            throw new \RuntimeException("pppoectl read-back failed (rc={$r->rc}): " . trim($r->err));
        }
        $problem = Pppoectl::verify($p, $r->out);
        if ($problem !== null) {
            throw new \RuntimeException("pppoectl settings did not apply: {$problem}");
        }
        /* after -e: SIOCSIFMTU > 1492 needs the parent attached (if_pppoe.c:2258-2277) */
        $this->must([$ifconfig, $dev, 'mtu', (string)$p->mtu], 'ifconfig mtu');
        $this->must([$ifconfig, $dev, 'up'], 'ifconfig up');
    }

    private function destroyQuiet(string $device): void
    {
        $ifconfig = $this->env->bin('ifconfig');
        $this->run([$ifconfig, $device, 'down'], null, 10);
        $this->run([$ifconfig, $device, 'destroy'], null, 10);
        $this->k->forget($device);
    }

    /**
     * Down path then destroy: tell core the link went away (as mpd5's
     * down-script does when it is killed), ifconfig down (LCP TermReq +
     * PADT), destroy.  Caller holds the device lock.
     */
    private function teardown(string $device, ?array $rec, string $why): void
    {
        if ($rec !== null) {
            $rec = $this->reg->update($device, ['state' => 'teardown']) ?? $rec;
            $this->runDown($device, $rec, 'inet6');
            $this->runDown($device, $rec, 'inet');
        }
        if ($this->k->isClone($device)) {
            $this->destroyQuiet($device);
        }
        $this->reg->remove($device);
        $this->log(LOG_NOTICE, "{$device}: kernel session torn down ({$why})");
    }

    /* ---------------------------------------------------------------- reset */

    public function reset(string $friendly, string $device): int
    {
        if (!self::validDevice($device)) {
            $rec = self::validFriendly($friendly) ? $this->reg->findByFriendly($friendly) : null;
            if ($rec === null) {
                return 0;
            }
            $device = $rec['device'];
        }
        $lock = Lock::acquire($this->env, $device, 30.0);
        try {
            $rec = $this->reg->get($device);
            if ($rec === null && self::validFriendly($friendly)) {
                $alt = $this->reg->findByFriendly($friendly);
                if ($alt !== null && $alt['device'] !== $device) {
                    $lock->release();
                    return $this->reset($friendly, $alt['device']);
                }
            }
            if ($rec !== null || $this->k->isClone($device)) {
                $this->teardown($device, $rec, 'reset');
                if (self::validFriendly($friendly)) {
                    $this->status->record($friendly, ['device' => $device, 'backend' => 'none', 'result' => 'reset']);
                }
            }
        } finally {
            $lock->release();
        }
        return 0;
    }

    /* ------------------------------------------------------------ linkevent */

    /**
     * mpd5 up/down-script argv (mpd5 iface.c IfaceIpIfaceUp/Down, IfaceIpv6IfaceUp/Down).
     * An unknown address is passed as '': ppp-linkup.sh (25.7.11:18-22) records any
     * non-empty $4 as the router, and never reads $3.
     */
    public function scriptArgv(string $which, string $device, string $af, array $rec): array
    {
        $script = $this->env->bin($which === 'up' ? 'linkup' : 'linkdown');
        if ($af === 'inet') {
            $local = ($rec['local'] ?? '') !== '' ? $rec['local'] . '/32' : '';
            $remote = (string)($rec['remote'] ?? '');
            if ($which === 'up') {
                /* authname is '-' on purpose: ppp-linkup.sh never reads $5 and argv is world-readable */
                return [$script, $device, 'inet', $local, $remote, '-',
                    ($rec['dns1'] ?? '') !== '' ? "dns1 {$rec['dns1']}" : '',
                    ($rec['dns2'] ?? '') !== '' ? "dns2 {$rec['dns2']}" : '',
                    '-', '-'];
            }
            return [$script, $device, 'inet', $local, $remote, '-', '-', '-'];
        }
        $l6 = ($rec['local6'] ?? '') !== '' ? "{$rec['local6']}%{$device}" : '';
        $r6 = ($rec['remote6'] ?? '') !== '' ? "{$rec['remote6']}%{$device}" : '';
        return [$script, $device, 'inet6', $l6, $r6, '-', '-', '-'];
    }

    private function runScript(string $which, string $device, string $af, array $rec): void
    {
        $r = $this->run($this->scriptArgv($which, $device, $af, $rec), null, 120);
        if (!$r->ok()) {
            $this->log(LOG_WARNING, "{$device}: ppp-link{$which}.sh {$af} exited {$r->rc}");
        }
    }

    private function runDown(string $device, array $rec, string $af): void
    {
        $key = $af === 'inet' ? 'v4' : 'v6';
        if (($rec[$key] ?? 'down') === 'up') {
            $this->runScript('down', $device, $af, $rec);
            $this->reg->update($device, [$key => 'down']);
        }
    }

    /** "local=1.2.3.4" style devd arguments => map */
    public static function parseKv(array $args): array
    {
        $out = [];
        foreach ($args as $a) {
            $pos = strpos($a, '=');
            if ($pos !== false) {
                $out[substr($a, 0, $pos)] = substr($a, $pos + 1);
            }
        }
        return $out;
    }

    /* usable IPv4 or '': the kmod sends 0.0.0.0 for anything not negotiated, which
       ppp-linkup.sh would record as a nameserver or router */
    public static function ipv4(?string $v): string
    {
        $v = preg_replace('#/[0-9]{1,2}$#', '', trim((string)$v));
        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || ip2long($v) === 0) {
            return '';
        }
        return $v;
    }

    /** IPv6CP value (link-local address or 64-bit interface id) => fe80:: address without scope */
    public static function linkLocal(?string $v): string
    {
        $v = strtolower(trim((string)$v));
        $v = preg_replace('/%.*$/', '', $v);
        if (preg_match('/^(?:0x)?([0-9a-f]{16})$/', $v, $m)) {
            $v = 'fe80::' . implode(':', str_split($m[1], 4));
        }
        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false || !str_starts_with($v, 'fe80:')) {
            return '';
        }
        return inet_ntop(inet_pton($v));
    }

    /**
     * devd entry point.  devd runs actions synchronously, so this only appends the
     * event to the device's FIFO queue and starts a detached `engine drain`.
     * Queue order is devd order; whoever holds the device lock drains it.
     */
    public function linkevent(string $device, string $type, array $args): int
    {
        if (!self::validDevice($device) || !in_array($type, self::EVENTS, true)) {
            $this->log(LOG_ERR, "linkevent: ignoring '{$device}' '{$type}'");
            return self::EXIT_USAGE;
        }
        $kv = array_intersect_key(self::parseKv($args), array_flip(['local', 'remote', 'dns1', 'dns2', 'mtu']));
        if (!$this->queue($device)->push(['type' => $type, 'kv' => $kv, 'ts' => microtime(true)])) {
            $this->log(LOG_WARNING, "{$device}: event queue full, {$type} dropped (reconcile resyncs)");
        }
        if ($this->dispatcher !== null) {
            ($this->dispatcher)($device);
            return 0;
        }
        $r = $this->run([$this->env->bin('daemon'), '-f', $this->env->bin('engine'), 'drain', $device], null, 10);
        if (!$r->ok()) {
            $this->log(LOG_WARNING, "{$device}: cannot start a detached drain (rc={$r->rc}); draining inline");
            return $this->drain($device);
        }
        return 0;
    }

    private function queue(string $device): EventQueue
    {
        return new EventQueue($this->env, $device);
    }

    /** process every queued event for the device, in order */
    public function drain(string $device, float $wait = self::DRAIN_LOCK_WAIT): int
    {
        if (!self::validDevice($device)) {
            return self::EXIT_USAGE;
        }
        $lock = $this->tryLock($device, $wait);
        if ($lock === null) {
            /* the holder, a later drain or the next reconcile picks the events up */
            return 0;
        }
        try {
            $this->drainLocked($device);
        } finally {
            $lock->release();
        }
        return 0;
    }

    /** caller holds the device lock */
    private function drainLocked(string $device): void
    {
        $q = $this->queue($device);
        while (($events = $q->take()) !== []) {
            foreach ($events as $ev) {
                $this->handleEvent($device, (string)($ev['type'] ?? ''), (array)($ev['kv'] ?? []), (float)($ev['ts'] ?? 0));
            }
        }
    }

    /** one link event; caller holds the device lock */
    private function handleEvent(string $device, string $type, array $kv, float $ts): void
    {
        if (!in_array($type, self::EVENTS, true)) {
            return;
        }
        $rec = $this->reg->get($device);
        if ($rec === null || ($rec['state'] ?? '') === 'teardown') {
            $this->log(LOG_INFO, "{$device}: {$type} for an unmanaged or departing interface, ignored");
            return;
        }
        if ($ts < (float)($rec['created_us'] ?? 0)) {
            $this->log(LOG_INFO, "{$device}: {$type} from a previous clone, ignored");
            return;
        }
        $friendly = (string)($rec['friendly'] ?? '');
        $now = time();
        $rec = $this->reg->update($device, ['last_event' => $type, 'last_event_at' => $now]);

        switch ($type) {
            case 'SESSION_UP':
                $this->reg->update($device, ['session' => 'up', 'state' => 'session']);
                break;
            case 'AUTH_FAIL':
                $this->reg->update($device, ['auth_failures' => (int)($rec['auth_failures'] ?? 0) + 1]);
                $this->log(LOG_WARNING, "{$device}: PPP authentication failed");
                break;
            case 'IPCP_UP':
                $new = [
                    'local' => self::ipv4($kv['local'] ?? ''), 'remote' => self::ipv4($kv['remote'] ?? ''),
                    'dns1' => self::ipv4($kv['dns1'] ?? ''), 'dns2' => self::ipv4($kv['dns2'] ?? ''),
                ];
                $same = ($rec['v4'] ?? 'down') === 'up' && ($rec['local'] ?? '') === $new['local']
                    && ($rec['remote'] ?? '') === $new['remote'];
                if ($same) {
                    break;
                }
                if (($rec['v4'] ?? 'down') === 'up') {
                    $this->runDown($device, $rec, 'inet');
                }
                $rec = $this->reg->update($device, $new + ['v4' => 'up', 'v4_since' => $now, 'state' => 'up']);
                $this->runScript('up', $device, 'inet', $rec);
                break;
            case 'IPCP_DOWN':
                $this->runDown($device, $rec, 'inet');
                break;
            case 'IPV6CP_UP':
                $new = [
                    'local6' => self::linkLocal($kv['local'] ?? ''),
                    'remote6' => self::linkLocal($kv['remote'] ?? ''),
                ];
                if ($new['local6'] === '') {
                    $info = $this->k->ifInfo($device);
                    $new['local6'] = self::linkLocal($info['inet6_ll'] ?? '');
                }
                if (($rec['v6'] ?? 'down') === 'up' && ($rec['remote6'] ?? '') === $new['remote6']) {
                    break;
                }
                $rec = $this->reg->update($device, $new + ['v6' => 'up', 'v6_since' => $now, 'state' => 'up']);
                $this->runScript('up', $device, 'inet6', $rec);
                break;
            case 'IPV6CP_DOWN':
                $this->runDown($device, $rec, 'inet6');
                break;
            case 'SESSION_DOWN':
                /* the NCP downs normally precede this; cover a lost one */
                $this->runDown($device, $rec, 'inet6');
                $this->runDown($device, $this->reg->get($device) ?? $rec, 'inet');
                $this->reg->update($device, ['session' => 'down', 'state' => 'dialing']);
                break;
        }
        if ($friendly !== '') {
            $cur = $this->reg->get($device) ?? [];
            $this->status->record($friendly, [
                'device' => $device, 'backend' => 'kernel', 'session' => $cur['session'] ?? 'down',
                'v4' => $cur['v4'] ?? 'down', 'v6' => $cur['v6'] ?? 'down', 'last_event' => $type,
            ]);
        }
    }

    /* ------------------------------------------------------------ reconcile */

    /* reconcile --after-firmware waits this long for a running (cron) reconcile to finish */
    public const AFTER_FIRMWARE_LOCK_WAIT = 60.0;

    /* --after-firmware (reapply.sh, hook refused after a core change): non-zero means some
       managed WAN was not handed back, and reapply.sh runs its shell fallback for the rest */
    public function reconcile(bool $afterFirmware = false): int
    {
        try {
            $lock = Lock::acquire($this->env, 'reconcile', $afterFirmware ? self::AFTER_FIRMWARE_LOCK_WAIT : 0.0);
        } catch (\RuntimeException $e) {
            if ($afterFirmware) {
                $this->log(LOG_WARNING, 'reconcile --after-firmware: ' . $e->getMessage());
                return self::EXIT_FAILED;
            }
            return 0;
        }
        $rc = 0;
        try {
            $hook = $this->k->hookStatus();
            /* "missing" (markers gone, state says applied) is the core-reinstall window: the update syshook re-applies */
            $terminal = $hook !== 'applied' && ($afterFirmware || str_starts_with($hook, 'refused') || $hook === 'foreign');
            if ($terminal && $this->reg->all() !== []) {
                if ($this->fallbackToMpd5($hook) > 0 && $afterFirmware) {
                    $rc = self::EXIT_FAILED;
                }
            }
            $this->reapOrphans();
            $this->reconcileRegistry();
            if ($hook === 'applied') {
                $this->kickMpd5Interfaces();
            }
        } finally {
            $lock->release();
        }
        return $rc;
    }

    /**
     * hook gone (core update changed the anchors): hand every managed WAN back to mpd5
     * @return int devices left behind (device lock busy)
     */
    private function fallbackToMpd5(string $hook): int
    {
        $skipped = 0;
        foreach ($this->reg->all() as $dev => $rec) {
            $friendly = (string)($rec['friendly'] ?? '');
            $l = $this->tryLock($dev, 30.0);
            if ($l === null) {
                $skipped++;
                continue;
            }
            try {
                $this->teardown($dev, $this->reg->get($dev), "hook {$hook}");
            } finally {
                $l->release();
            }
            if (self::validFriendly($friendly)) {
                $this->status->record($friendly, ['device' => $dev, 'backend' => 'mpd5',
                    'reason' => "interfaces.inc hook {$hook}; handed back to mpd5", 'result' => 'fallback']);
                $this->run([$this->env->bin('configctl'), 'interface', 'reconfigure', $friendly], null, 60);
            }
        }
        $this->log(LOG_WARNING, "interfaces.inc hook is {$hook}: managed PPPoE interfaces handed back to mpd5");
        return $skipped;
    }

    private function reapOrphans(): void
    {
        foreach (EventQueue::devices($this->env) as $dev) {
            if ($this->reg->get($dev) === null && ($l = $this->tryLock($dev, 0.0)) !== null) {
                /* events for an interface we do not manage (any more) */
                $this->queue($dev)->take();
                $l->release();
            }
        }
        foreach ($this->k->clones() as $dev) {
            if ($this->reg->get($dev) !== null) {
                continue;
            }
            $l = $this->tryLock($dev, self::RECONCILE_LOCK_WAIT);
            if ($l === null) {
                continue;
            }
            try {
                if ($this->reg->get($dev) === null) {
                    $this->destroyQuiet($dev);
                    $this->log(LOG_NOTICE, "{$dev}: destroyed orphan kernel clone (not in registry)");
                }
            } finally {
                $l->release();
            }
        }
    }

    private function reconcileRegistry(): void
    {
        $cfg = null;
        try {
            $cfg = $this->config();
        } catch (\Throwable $e) {
            $this->log(LOG_WARNING, 'reconcile: ' . $e->getMessage());
        }
        foreach (array_keys($this->reg->all()) as $dev) {
            $l = $this->tryLock($dev, self::RECONCILE_LOCK_WAIT);
            if ($l === null) {
                continue;
            }
            try {
                $rec = $this->reg->get($dev);
                if ($rec === null) {
                    continue;
                }
                if (in_array($rec['state'] ?? '', ['configuring', 'teardown'], true)) {
                    /* both run entirely under this lock: seeing it here means the owner died (e.g. timeout(1)) */
                    $this->teardown($dev, $rec, 'stale ' . $rec['state']);
                    if ($rec['state'] === 'configuring' && self::validFriendly((string)($rec['friendly'] ?? ''))) {
                        /* core fell through to mpd5 while our clone still held the name: redo the interface */
                        $this->requestReconfigure($rec['friendly'], $dev, 'kernel setup was interrupted');
                    }
                    continue;
                }
                /* events a drain could not deliver (lock timeout) */
                $this->drainLocked($dev);
                $rec = $this->reg->get($dev) ?? $rec;
                $friendly = (string)($rec['friendly'] ?? '');
                $this->k->forget($dev);
                if (!$this->k->isClone($dev)) {
                    /* clone vanished underneath us: deliver the downs core never saw */
                    $this->runDown($dev, $rec, 'inet6');
                    $this->runDown($dev, $this->reg->get($dev) ?? $rec, 'inet');
                    $this->reg->remove($dev);
                    if (self::validFriendly($friendly)) {
                        $this->status->record($friendly, ['device' => $dev, 'backend' => 'none', 'reason' => 'kernel clone disappeared']);
                    }
                    $this->log(LOG_WARNING, "{$dev}: kernel clone disappeared; registry cleared");
                    continue;
                }
                if ($cfg !== null && ($cfg->pppByDevice($dev) === null || $cfg->friendlyForDevice($dev) !== $friendly)) {
                    $this->teardown($dev, $rec, 'no longer configured');
                    continue;
                }
                $this->levelSync($dev, $rec);
            } finally {
                $l->release();
            }
        }
    }

    /** replay link transitions whose devd events were lost */
    private function levelSync(string $dev, array $rec): void
    {
        $s = $this->k->session($dev);
        if ($s === null) {
            return;
        }
        $info = $this->k->ifInfo($dev) ?? [];
        $v4 = $s['ipcp'] === 'opened' && ($info['inet'] ?? null) !== null && $info['inet'] !== '0.0.0.0';
        $v6 = $s['ipv6cp'] === 'opened';
        $now = time();

        if (($rec['v4'] ?? 'down') === 'up' && !$v4) {
            $this->runDown($dev, $rec, 'inet');
            $this->log(LOG_NOTICE, "{$dev}: replayed lost IPCP_DOWN");
        } elseif (($rec['v4'] ?? 'down') !== 'up' && $v4) {
            $rec = $this->reg->update($dev, [
                'v4' => 'up', 'v4_since' => $now, 'state' => 'up', 'session' => 'up',
                'local' => self::ipv4($s['address'] ?? $info['inet']), 'remote' => self::ipv4($info['inet_dest'] ?? ''),
                'dns1' => self::ipv4($s['dns1'] ?? ''), 'dns2' => self::ipv4($s['dns2'] ?? ''),
            ]);
            $this->runScript('up', $dev, 'inet', $rec);
            $this->log(LOG_NOTICE, "{$dev}: replayed lost IPCP_UP");
        }
        $rec = $this->reg->get($dev) ?? $rec;
        if (($rec['v6'] ?? 'down') === 'up' && !$v6) {
            $this->runDown($dev, $rec, 'inet6');
            $this->log(LOG_NOTICE, "{$dev}: replayed lost IPV6CP_DOWN");
        } elseif (($rec['v6'] ?? 'down') !== 'up' && $v6 && ($rec['plan']['ipv6cp'] ?? false)) {
            $rec = $this->reg->update($dev, [
                'v6' => 'up', 'v6_since' => $now, 'state' => 'up', 'session' => 'up',
                'local6' => self::linkLocal($s['my_ifid'] ?? ($info['inet6_ll'] ?? '')),
                'remote6' => self::linkLocal($s['his_ifid'] ?? ''),
            ]);
            $this->runScript('up', $dev, 'inet6', $rec);
            $this->log(LOG_NOTICE, "{$dev}: replayed lost IPV6CP_UP");
        }
    }

    /**
     * An eligible interface running mpd5 means core configured it while the
     * hook was absent (e.g. mid core update): ask core to reconfigure it.
     */
    private function kickMpd5Interfaces(): void
    {
        $cfg = $this->config();
        $elig = new Eligibility($cfg, $this->k);
        $exclude = $this->effective()['exclude'] ?? [];
        $st = $this->status->read()['interfaces'] ?? [];
        foreach ($this->pppoeInterfaces($cfg) as $friendly => $dev) {
            if ($this->reg->get($dev) !== null || !$this->k->pidfileAlive($this->env->mpdPidfile($friendly))) {
                continue;
            }
            if (!$elig->evaluate($friendly, $dev, $exclude)->eligible()) {
                continue;
            }
            /* a configure that failed (exit 2) left mpd5 running on purpose: back off from it too */
            if ((int)($st[$friendly]['failed_at'] ?? 0) > time() - self::RECONFIGURE_BACKOFF) {
                continue;
            }
            $this->requestReconfigure($friendly, $dev, 'mpd5 found running on an eligible interface');
        }
    }

    /** ask core to redo the interface (reset + configure hooks), at most once per RECONFIGURE_BACKOFF */
    private function requestReconfigure(string $friendly, string $dev, string $why): void
    {
        $prev = $this->status->read()['interfaces'][$friendly] ?? [];
        if ((int)($prev['kicked_at'] ?? 0) > time() - self::RECONFIGURE_BACKOFF) {
            return;
        }
        $this->status->record($friendly, ['device' => $dev, 'backend' => 'mpd5', 'kicked_at' => time(),
            'reason' => "{$why}; reconfigure requested"]);
        $this->log(LOG_NOTICE, "{$friendly} ({$dev}): {$why}, requesting reconfigure");
        $this->run([$this->env->bin('configctl'), 'interface', 'reconfigure', $friendly], null, 60);
    }

    /** friendly => device for every enabled interface bound to a <ppp type=pppoe> */
    private function pppoeInterfaces(Config $cfg): array
    {
        $out = [];
        foreach ($cfg->ppps() as $ppp) {
            if (($ppp['type'] ?? '') !== 'pppoe' || !self::validDevice((string)($ppp['if'] ?? ''))) {
                continue;
            }
            $friendly = $cfg->friendlyForDevice($ppp['if']);
            if ($friendly !== null && self::validFriendly($friendly)) {
                $out[$friendly] = $ppp['if'];
            }
        }
        return $out;
    }

    /* --------------------------------------------------------------- status */

    /**
     * Boot applies the hook iff desired says enabled and the box is not latched; the per-boot
     * effective.json covers the exclude list.  Never true where a reboot cannot help: latched,
     * refused:*, foreign, or this boot already failed with the same desired state (boot.json) --
     * *unless* $kmodFixedSinceBoot: the failure was kmod/feature related, the installed package
     * is eligible now *and* it changed since that boot in a way that addresses the failure
     * (kmodFixedSinceBoot()); otherwise a kmod fix after a failed boot never gets offered,
     * while an unchanged package keeps saying no.
     * paused:core-reinstall resumes at the next boot only once desired is newer than paused_at.
     * $kmodUpgradePending forces it true regardless of exclude: the loaded .ko is stale.
     */
    public static function rebootRequired(
        string $desired,
        string $hook,
        bool $latched,
        ?array $eff,
        ?array $settings,
        ?array $boot = null,
        ?int $desiredMtime = null,
        ?int $pausedAt = null,
        bool $kmodUpgradePending = false,
        bool $kmodFixedSinceBoot = false
    ): bool {
        $hookOn = in_array($hook, ['applied', 'missing'], true);
        if ($desired === 'disabled') {
            return $hookOn;
        }
        if ($desired !== 'enabled' || $latched) {
            return false;
        }
        if (in_array($hook, ['reverted', 'unknown'], true)) {
            $failedThisBoot = $boot !== null && ($boot['desired'] ?? '') === 'enabled' && ($boot['result'] ?? '') === 'failed'
                && $desiredMtime !== null && isset($boot['at']) && $desiredMtime <= (int)$boot['at'];
            if ($failedThisBoot && $kmodFixedSinceBoot) {
                return true;
            }
            return !$failedThisBoot;
        }
        if ($hook === 'paused:core-reinstall') {
            return $desiredMtime !== null && $pausedAt !== null && $desiredMtime > $pausedAt;
        }
        if ($hookOn) {
            $excludeChanged = $eff !== null && $settings !== null && ($eff['exclude'] ?? []) !== $settings['exclude'];
            return $excludeChanged || $kmodUpgradePending;
        }
        return false;
    }

    /**
     * Evidence that the installed if-pppoe-kmod changed after the failed boot in $boot, in a
     * way that can fix its reason (lib.sh ifp_kmod_path()/ifp_kmod_features()/'kldload').
     * installed_eligible alone cannot see a kldload rejection, a feature a features-less
     * older kmod lacks, or a features file that overstates the .ko -- so without a change
     * the answer stays no, whatever installed_eligible says.
     *  - kldload, feature-X: only a different .ko can help; feature-X also needs the features
     *    file to exist and list if_pppoe_X.
     *  - no-build-id, kernel-not-supported, kmod-missing, kmod-checksum: build_ids or the .ko.
     *  - anything else (hook, unknown): never.
     * "Changed" compares boot.json's "kmod" identity (lib.sh ifp_kmod_identity()) with the
     * installed files; a boot.json without one (older syshook) falls back to mtime > at.
     */
    private function kmodFixedSinceBoot(?array $boot, $recorded): bool
    {
        $reason = (string)($boot['reason'] ?? '');
        if (($boot['result'] ?? '') !== 'failed' || !is_int($boot['at'] ?? null)) {
            return false;
        }
        if ($reason === 'kldload') {
            $parts = ['ko'];
        } elseif (preg_match('/^feature-([a-z0-9_]+)$/', $reason, $m)) {
            if (!$this->k->installedFeatureListed("if_pppoe_{$m[1]}")) {
                return false;
            }
            $parts = ['ko'];
        } elseif (in_array($reason, ['no-build-id', 'kernel-not-supported', 'kmod-missing', 'kmod-checksum'], true)) {
            $parts = ['build_ids', 'ko'];
        } else {
            return false;
        }
        $valid = is_array($recorded);
        foreach (['build_ids', 'features', 'ko'] as $p) {
            $valid = $valid && is_string($recorded[$p] ?? null) && preg_match('/^[0-9a-f]*$/', $recorded[$p]) === 1;
        }
        if ($valid) {
            $now = $this->k->installedKmodIdentity();
            foreach ($parts as $p) {
                if ($now[$p] !== $recorded[$p]) {
                    return true;
                }
            }
            return false;
        }
        $mtimes = $this->k->installedKmodMtimes();
        foreach ($parts as $p) {
            if ($mtimes[$p] !== null && $mtimes[$p] > $boot['at']) {
                return true;
            }
        }
        return false;
    }

    /**
     * This boot's gate outcome (boot.json) and the syshooks' notice.d files.  Messages are
     * cut down to printable ASCII so the GUI can show them verbatim.
     *
     * @return array{boot: ?array, notices: array<string, array{message: string, at: ?int}>}
     */
    public function notices(): array
    {
        $boot = Fs::readJson($this->env->bootJson());
        if (is_array($boot)) {
            $boot = [
                'desired' => is_string($boot['desired'] ?? null) ? $boot['desired'] : null,
                'result' => is_string($boot['result'] ?? null) ? $boot['result'] : null,
                'reason' => is_string($boot['reason'] ?? null) ? $boot['reason'] : null,
                'at' => is_int($boot['at'] ?? null) ? $boot['at'] : null,
            ];
        } else {
            $boot = null;
        }
        $notices = [];
        foreach (glob($this->env->noticeDir() . '/*') ?: [] as $f) {
            $key = basename($f);
            if (!is_file($f) || !preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/', $key)) {
                continue;
            }
            $msg = (string)@file_get_contents($f, false, null, 0, 4096);
            $msg = trim(preg_replace('/[^\x20-\x7e]+/', ' ', $msg));
            $mtime = @filemtime($f);
            $notices[$key] = ['message' => substr($msg, 0, 512), 'at' => $mtime === false ? null : $mtime];
        }
        ksort($notices);
        return ['boot' => $boot, 'notices' => $notices];
    }

    /**
     * Which OPNsense kernels the installed if-pppoe-kmod covers (its shipped kernels.json)
     * and whether the running and the installed (next-boot) kernel are among them.
     * covered comes from build_ids and the .ko itself (Kernel::kmodCovers(), the boot
     * gate's own test), never from kernels.json alone; supported is null for an
     * if-pppoe-kmod without kernels.json ("unknown"). installed falls back to the running
     * kernel when /boot/kernel/kernel is unreadable; pending_reboot = the two differ.
     * upgrade: a deferred major upgrade (opnsense-update -u) and whether the installed
     * kmod lists its release -- null, not false, when it does not: that upgrade also
     * installs the if-pppoe-kmod which then decides.
     *
     * @return array{supported: ?list<array{version: string, series: string, build_id: string}>,
     *               running: array{build_id: ?string, version: ?string, covered: bool},
     *               installed: array{build_id: ?string, version: ?string, covered: bool, pending_reboot: bool},
     *               upgrade: ?array{version: string, covered: ?bool}}
     */
    public function kernelCoverage(): array
    {
        $supported = $this->k->supportedKernels();
        $run = $this->k->runningBuildId();
        $file = $this->k->installedKernelBuildId();
        $inst = $file ?? $run;
        $upgrade = null;
        $release = $this->k->pendingKernelRelease();
        if ($release !== null) {
            $covered = null;
            foreach ($supported ?? [] as $k) {
                if ($k['version'] === $release) {
                    $covered = $this->k->kmodCovers($k['build_id']) ? true : null;
                    break;
                }
            }
            $upgrade = ['version' => $release, 'covered' => $covered];
        }
        return [
            'supported' => $supported,
            'running' => ['build_id' => $run, 'version' => $this->k->kernelVersion($run), 'covered' => $this->k->runningKmodCovers()],
            'installed' => [
                'build_id' => $inst,
                'version' => $this->k->kernelVersion($inst),
                'covered' => $this->k->installedKmodMatchesKernel(),
                'pending_reboot' => $file !== null && $run !== null && $file !== $run,
            ],
            'upgrade' => $upgrade,
        ];
    }

    /** "25.7.8", or "build-id 0123456789ab" when kernels.json does not name it */
    private static function kernelLabel(array $k): string
    {
        if (is_string($k['version'] ?? null)) {
            return $k['version'];
        }
        return is_string($k['build_id'] ?? null) ? 'build-id ' . substr($k['build_id'], 0, 12) : 'of unknown build-id';
    }

    public function statusReport(): array
    {
        $cfg = null;
        $cfgError = null;
        try {
            $cfg = $this->config();
        } catch (\Throwable $e) {
            $cfgError = $e->getMessage();
        }
        $eff = Fs::readJson($this->env->effectiveJson());
        $stored = $this->status->read()['interfaces'] ?? [];
        $hookState = Fs::readJson($this->env->hookJson());
        clearstatcache();
        $desiredMtime = @filemtime($this->env->desiredFile());
        $desiredMtime = $desiredMtime === false ? null : $desiredMtime;
        $latchMtime = @filemtime($this->env->latchFile());
        /* the early syshook drops a latch older than desired (re-applied in the GUI) */
        $latchClears = $latchMtime !== false && $desiredMtime !== null && $desiredMtime > $latchMtime;
        $n = $this->notices();
        $rawBoot = Fs::readJson($this->env->bootJson());
        $rawBoot = is_array($rawBoot) ? $rawBoot : [];
        $installedMissing = $this->k->missingInstalledFeatures();
        $installedKmodOk = $this->k->installedKmodMatchesKernel();
        $installedReasons = [];
        /* null = features file unreadable (older kmod package): unknown, not ineligible */
        if ($installedMissing !== null && $installedMissing !== []) {
            $installedReasons[] = 'installed kernel module is missing features: ' . implode(',', $installedMissing);
        }
        $kernels = $this->kernelCoverage();
        if (!$installedKmodOk) {
            $inst = $kernels['installed'];
            $installedReasons[] = $inst['pending_reboot']
                ? 'the installed kernel ' . self::kernelLabel($inst) . ' (pending reboot) is not covered by the installed kernel module'
                : 'no installed kernel module matches the running kernel';
        }
        $kmodUpgradePending = $this->k->kmodUpgradePending();
        $report = [
            'desired' => $this->k->desired(),
            'hook' => $this->k->hookStatus(),
            'hook_detail' => is_array($hookState) && is_string($hookState['detail'] ?? null) ? $hookState['detail'] : '',
            'latched' => $this->k->latched() && !$latchClears,
            'latch_clears_on_reboot' => $latchClears,
            'boot' => $n['boot'],
            'notices' => $n['notices'],
            'features_missing' => $this->k->missingFeatures(),
            /* whether *enabling* would work after a reboot, from the installed (not necessarily
             * loaded) kmod package -- see Kernel::missingInstalledFeatures()/installedKmodMatchesKernel() */
            'installed_eligible' => $installedReasons === [],
            'installed_reason' => implode('; ', $installedReasons),
            'kmod_upgrade_pending' => $kmodUpgradePending,
            'kernels' => $kernels,
            'effective' => $eff,
            'settings' => $cfg?->pluginSettings(),
            'ha' => $cfg?->haReason(),
            'config_error' => $cfgError,
            'counters' => $this->k->counters(),
            'interfaces' => [],
        ];
        $pausedAt = is_array($hookState) && isset($hookState['paused_at']) ? (int)$hookState['paused_at'] : null;
        $report['reboot_required'] = self::rebootRequired(
            $report['desired'],
            $report['hook'],
            $report['latched'],
            $eff,
            $report['settings'],
            $report['boot'],
            $desiredMtime,
            $pausedAt,
            $kmodUpgradePending,
            $report['installed_eligible'] && $this->kmodFixedSinceBoot($n['boot'], $rawBoot['kmod'] ?? null)
        );
        /* saved on the Services page but not yet applied (desired not written) */
        $report['apply_pending'] = $report['settings'] !== null && in_array($report['desired'], ['enabled', 'disabled', 'unset'], true)
            && $report['settings']['enabled'] !== ($report['desired'] === 'enabled');

        $devices = $cfg !== null ? $this->pppoeInterfaces($cfg) : [];
        foreach ($this->reg->all() as $dev => $rec) {
            $f = (string)($rec['friendly'] ?? $dev);
            $devices[$f] = $devices[$f] ?? $dev;
        }
        $elig = $cfg !== null ? new Eligibility($cfg, $this->k) : null;
        foreach ($devices as $friendly => $dev) {
            $rec = $this->reg->get($dev);
            $entry = [
                'device' => $dev,
                'enabled' => $cfg !== null && isset($cfg->iface($friendly)['enable']),
                'backend' => 'none',
                'reason' => $stored[$friendly]['reason'] ?? '',
                'last_result' => $stored[$friendly]['result'] ?? null,
                'updated' => $stored[$friendly]['updated'] ?? null,
            ];
            if ($rec !== null && $this->k->isClone($dev)) {
                $entry['backend'] = 'kernel';
                $entry['registry'] = array_intersect_key($rec, array_flip([
                    'state', 'session', 'v4', 'v6', 'local', 'remote', 'dns1', 'dns2', 'local6', 'remote6',
                    'created', 'v4_since', 'v6_since', 'last_event', 'last_event_at', 'auth_failures', 'plan',
                ]));
                $entry['session'] = $this->k->session($dev);
            } elseif ($this->k->pidfileAlive($this->env->mpdPidfile($friendly))) {
                $entry['backend'] = 'mpd5';
            }
            if ($elig !== null) {
                $d = $elig->evaluate($friendly, $dev, $eff['exclude'] ?? ($report['settings']['exclude'] ?? []));
                $entry['eligible'] = $d->eligible();
                $entry['eligibility'] = $d->reason();
                $entry['fields'] = $d->fields;
                /* an ineligibility reason is a snapshot of the facts at the last dial and goes
                 * stale as soon as they change (e.g. a kmod upgrade fixes a missing feature);
                 * recompute it every read instead of showing what configure() recorded then. */
                $recompute = ($stored[$friendly]['reason_recompute'] ?? false) === true;
                if ($entry['reason'] === '' || $recompute) {
                    $entry['reason'] = $d->reason();
                    /* still on mpd5: the fix is real but nothing acts on it until the next dial */
                    if ($recompute && $d->eligible() && $entry['backend'] === 'mpd5') {
                        $entry['reason'] .= ' (redial to switch)';
                    }
                }
            }
            $report['interfaces'][$friendly] = $entry;
        }
        return $report;
    }
}
