<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

/** Queries against the running system (ifconfig, sysctl, pppoectl -dd, plugin state files). */
class Kernel implements SystemFacts
{
    private array $ifCache = [];
    private ?array $features = null;
    private ?array $installedFeatures = null;
    private ?bool $installedKmodOk = null;
    /** false = not read yet; null = unknown (no usable kernels.json) */
    private array|null|false $supported = false;
    /** path+inode+mtime+size => build-id, see installedKernelBuildId() */
    private static array $elfBuildIds = [];

    public function __construct(private Env $env, private Proc $proc)
    {
    }

    public function proc(): Proc
    {
        return $this->proc;
    }

    public function forget(?string $ifname = null): void
    {
        if ($ifname === null) {
            $this->ifCache = [];
        } else {
            unset($this->ifCache[$ifname]);
        }
    }

    /** parsed `ifconfig <if>` or null when it does not exist */
    public function ifInfo(string $ifname): ?array
    {
        if (!array_key_exists($ifname, $this->ifCache)) {
            $r = $this->proc->run([$this->env->bin('ifconfig'), $ifname], null, 10);
            $this->ifCache[$ifname] = $r->ok() ? self::parseIfconfig($r->out) : null;
        }
        return $this->ifCache[$ifname];
    }

    public static function parseIfconfig(string $out): array
    {
        $info = [
            'flags' => [], 'mtu' => 0, 'ether' => false, 'vlan' => false, 'groups' => [],
            'inet' => null, 'inet_dest' => null, 'inet6_ll' => null,
        ];
        foreach (explode("\n", $out) as $i => $line) {
            if ($i === 0) {
                if (preg_match('/flags=[0-9a-f]+<([^>]*)>/', $line, $m)) {
                    $info['flags'] = $m[1] === '' ? [] : explode(',', $m[1]);
                }
                if (preg_match('/\bmtu ([0-9]+)/', $line, $m)) {
                    $info['mtu'] = (int)$m[1];
                }
                continue;
            }
            $line = trim($line);
            if (preg_match('/^ether ([0-9a-f:]{17})/', $line)) {
                $info['ether'] = true;
            } elseif (preg_match('/^vlan: [0-9]+/', $line)) {
                $info['vlan'] = true;
            } elseif (preg_match('/^groups: (.*)$/', $line, $m)) {
                $info['groups'] = preg_split('/\s+/', trim($m[1]));
            } elseif ($info['inet'] === null && preg_match('/^inet ([0-9.]+)(?: --> ([0-9.]+))?/', $line, $m)) {
                $info['inet'] = $m[1];
                $info['inet_dest'] = $m[2] ?? null;
            } elseif ($info['inet6_ll'] === null && preg_match('/^inet6 (fe80:[0-9a-f:]+)/i', $line, $m)) {
                $info['inet6_ll'] = strtolower($m[1]);
            }
        }
        return $info;
    }

    /** members of the "pppoe" interface group = clones of our driver (mpd5's ng(4) ifaces are not in it) */
    public function clones(): array
    {
        $r = $this->proc->run([$this->env->bin('ifconfig'), '-g', 'pppoe'], null, 10);
        if (!$r->ok()) {
            return [];
        }
        $out = [];
        foreach (preg_split('/\s+/', trim($r->out)) as $n) {
            if (preg_match('/^pppoe[0-9]{1,4}$/', $n)) {
                $out[] = $n;
            }
        }
        sort($out, SORT_NATURAL);
        return $out;
    }

    public function isClone(string $device): bool
    {
        $info = $this->ifInfo($device);
        return $info !== null && in_array('pppoe', $info['groups'], true);
    }

    public function sysctl(string $name): ?string
    {
        $r = $this->proc->run([$this->env->bin('sysctl'), '-n', $name], null, 10);
        return $r->ok() ? trim($r->out) : null;
    }

    public function missingFeatures(): array
    {
        if ($this->features === null) {
            $this->features = [];
            foreach (Env::REQUIRED_FEATURES as $f) {
                if ($this->sysctl("kern.features.{$f}") !== '1') {
                    $this->features[] = $f;
                }
            }
        }
        return $this->features;
    }

    /**
     * Like missingFeatures(), but against the shipped features file, so it
     * works before the kmod is ever kldloaded. Returns null ("unknown"), not
     * [] ("all present") or every name ("all missing"), when the file itself
     * is unreadable -- an older if-pppoe-kmod predating this file cannot
     * prove either way, so failing closed here would tell a working install
     * a reboot won't enable kernel PPPoE.
     */
    public function missingInstalledFeatures(): ?array
    {
        if ($this->installedFeatures === null) {
            $raw = @file_get_contents($this->env->installedFeaturesFile());
            if ($raw === false) {
                return null;
            }
            $have = [];
            foreach (explode("\n", $raw) as $line) {
                $line = trim($line);
                if ($line !== '') {
                    $have[$line] = true;
                }
            }
            $this->installedFeatures = [];
            foreach (Env::REQUIRED_FEATURES as $f) {
                if (!isset($have[$f])) {
                    $this->installedFeatures[] = $f;
                }
            }
        }
        return $this->installedFeatures;
    }

    /** kern.build_id of the running kernel, lowercase hex, or null when unreadable */
    public function runningBuildId(): ?string
    {
        return self::normBuildId($this->sysctl('kern.build_id'));
    }

    private static function normBuildId(?string $bid): ?string
    {
        if ($bid === null) {
            return null;
        }
        $bid = strtolower(trim($bid));
        return $bid !== '' && strlen($bid) <= 128 && ctype_xdigit($bid) ? $bid : null;
    }

    /**
     * The kernels the installed if-pppoe-kmod ships a .ko for, from its kernels.json
     * (Env::installedKernelsJsonFile()): [{version, series, build_id}] in file order,
     * entries without a usable build_id/version dropped. null ("unknown") when the file
     * is absent, unparseable or names no kernel -- an if-pppoe-kmod predating the kernel
     * matrix, or a lab build (the kmod Makefile's kernels-json-file writes []) -- which
     * callers must not read as "nothing supported"; build_ids stays authoritative for
     * coverage (kmodCovers()), this only names the kernels.
     *
     * @return list<array{version: string, series: string, build_id: string}>|null
     */
    public function supportedKernels(): ?array
    {
        if ($this->supported === false) {
            $this->supported = null;
            $j = Fs::readJson($this->env->installedKernelsJsonFile());
            if (is_array($j) && array_is_list($j)) {
                $out = [];
                foreach ($j as $e) {
                    if (!is_array($e) || !is_string($e['build_id'] ?? null) || !is_string($e['version'] ?? null)) {
                        continue;
                    }
                    $bid = self::normBuildId($e['build_id']);
                    $ver = $e['version'];
                    if ($bid === null || !preg_match('/^[0-9][0-9A-Za-z._-]{0,31}$/', $ver)) {
                        continue;
                    }
                    $series = is_string($e['series'] ?? null) && preg_match('/^[0-9]{1,4}\.[0-9]{1,4}$/', $e['series'])
                        ? $e['series'] : implode('.', array_slice(preg_split('/[._-]/', $ver), 0, 2));
                    $out[] = ['version' => $ver, 'series' => $series, 'build_id' => $bid];
                }
                /* [] is what a lab (--target-kernel) build ships: it names nothing, so unknown */
                $this->supported = $out === [] ? null : $out;
            }
        }
        return $this->supported;
    }

    /** OPNsense kernel version for $bid from the shipped kernels.json, null when not listed */
    public function kernelVersion(?string $bid): ?string
    {
        $bid = self::normBuildId($bid);
        foreach ($bid !== null ? ($this->supportedKernels() ?? []) : [] as $k) {
            if ($k['build_id'] === $bid) {
                return $k['version'];
            }
        }
        return null;
    }

    /**
     * Build-id of the kernel the next boot loads (Env::installedKernelFile()), read from
     * its ELF NT_GNU_BUILD_ID note in plain PHP (readelf/elfdump need not be on the box),
     * lowercase hex like kern.build_id; null when absent or not an ELF64 LE file with one.
     * Cached per process by path, inode, mtime and size (the kernel is ~30 MB but only the
     * headers and note sections are read).
     */
    public function installedKernelBuildId(): ?string
    {
        $path = $this->env->installedKernelFile();
        clearstatcache(true, $path);
        $st = @stat($path);
        if ($st === false) {
            return null;
        }
        $key = "{$path}\0{$st['ino']}\0{$st['mtime']}\0{$st['size']}";
        if (!array_key_exists($key, self::$elfBuildIds)) {
            self::$elfBuildIds = [$key => self::elfBuildId($path)];
        }
        return self::$elfBuildIds[$key];
    }

    /** NT_GNU_BUILD_ID of an ELF64 little-endian file (amd64), from SHT_NOTE sections, else PT_NOTE segments */
    public static function elfBuildId(string $path): ?string
    {
        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            return null;
        }
        try {
            $st = fstat($fh);
            $size = is_array($st) ? (int)$st['size'] : 0;
            $read = function (int $off, int $len) use ($fh, $size): ?string {
                if ($off < 0 || $len <= 0 || $len > $size || $off > $size - $len || fseek($fh, $off) !== 0) {
                    return null;
                }
                $d = '';
                while (strlen($d) < $len) {
                    $chunk = fread($fh, $len - strlen($d));
                    if ($chunk === false || $chunk === '') {
                        return null;
                    }
                    $d .= $chunk;
                }
                return $d;
            };
            $eh = $read(0, 64);
            /* EI_CLASS 2 = ELFCLASS64, EI_DATA 1 = ELFDATA2LSB */
            if ($eh === null || substr($eh, 0, 4) !== "\x7fELF" || ord($eh[4]) !== 2 || ord($eh[5]) !== 1) {
                return null;
            }
            $o = unpack('Pphoff/Pshoff', $eh, 0x20);
            $n = unpack('vphentsize/vphnum/vshentsize/vshnum', $eh, 0x36);
            $notes = [];
            if ($o['shoff'] > 0 && $n['shentsize'] >= 64 && $n['shnum'] > 0 && $n['shnum'] <= 4096) {
                $tab = $read($o['shoff'], $n['shentsize'] * $n['shnum']);
                for ($i = 0; $tab !== null && $i < $n['shnum']; $i++) {
                    $sh = unpack('Vname/Vtype/Pflags/Paddr/Poffset/Psize', $tab, $i * $n['shentsize']);
                    if ($sh['type'] === 7) { /* SHT_NOTE */
                        $notes[] = [$sh['offset'], $sh['size']];
                    }
                }
            }
            if ($notes === [] && $o['phoff'] > 0 && $n['phentsize'] >= 56 && $n['phnum'] > 0 && $n['phnum'] <= 4096) {
                $tab = $read($o['phoff'], $n['phentsize'] * $n['phnum']);
                for ($i = 0; $tab !== null && $i < $n['phnum']; $i++) {
                    $ph = unpack('Vtype/Vflags/Poffset/Pvaddr/Ppaddr/Pfilesz', $tab, $i * $n['phentsize']);
                    if ($ph['type'] === 4) { /* PT_NOTE */
                        $notes[] = [$ph['offset'], $ph['filesz']];
                    }
                }
            }
            foreach ($notes as [$off, $len]) {
                if ($len > 65536) {
                    continue;
                }
                $d = $read($off, $len);
                $bid = $d === null ? null : self::noteBuildId($d);
                if ($bid !== null) {
                    return $bid;
                }
            }
            return null;
        } finally {
            fclose($fh);
        }
    }

    private static function noteBuildId(string $d): ?string
    {
        $n = strlen($d);
        $p = 0;
        while ($p + 12 <= $n) {
            $h = unpack('Vnamesz/Vdescsz/Vtype', $d, $p);
            $p += 12;
            $nl = ($h['namesz'] + 3) & ~3;
            $dl = ($h['descsz'] + 3) & ~3;
            if ($h['namesz'] > $n || $h['descsz'] > $n || $p + $nl + $dl > $n) {
                return null;
            }
            /* NT_GNU_BUILD_ID = 3, owner "GNU" */
            if ($h['type'] === 3 && substr($d, $p, $h['namesz']) === "GNU\0" && $h['descsz'] >= 8 && $h['descsz'] <= 64) {
                return bin2hex(substr($d, $p + $nl, $h['descsz']));
            }
            $p += $nl + $dl;
        }
        return null;
    }

    /**
     * Release a deferred major upgrade will boot into (Env::pendingKernelFile()), or null.
     * Its kernel set is not on disk as /boot/kernel yet, so there is no build-id to check;
     * the if-pppoe-kmod that upgrade installs decides coverage.
     */
    public function pendingKernelRelease(): ?string
    {
        $v = @file_get_contents($this->env->pendingKernelFile(), false, null, 0, 64);
        if ($v === false) {
            return null;
        }
        $v = trim($v);
        return preg_match('/^[0-9][0-9A-Za-z._-]{0,31}$/', $v) ? $v : null;
    }

    /**
     * Whether a reboot would load the installed kmod: lib.sh's ifp_kmod_path() in PHP, for
     * the *installed* kernel (Env::installedKernelFile(), what the next boot runs) when its
     * build-id is readable, else the running kern.build_id. So right after an OPNsense
     * kernel update that has not been rebooted yet, this answers for the new kernel.
     */
    public function installedKmodMatchesKernel(): bool
    {
        if ($this->installedKmodOk === null) {
            $this->installedKmodOk = $this->kmodCovers($this->installedKernelBuildId() ?? $this->runningBuildId());
        }
        return $this->installedKmodOk;
    }

    /** the installed kmod has a (checksum-valid) .ko for the running kernel */
    public function runningKmodCovers(): bool
    {
        return $this->kmodCovers($this->runningBuildId());
    }

    /** build_ids lists $bid and its .ko is present (and matches the recorded sha256, if any) */
    public function kmodCovers(?string $bid): bool
    {
        if ($bid === null || $bid === '' || !ctype_xdigit($bid)) {
            return false;
        }
        $lines = @file($this->env->installedBuildIdsFile(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return false;
        }
        foreach ($lines as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if ($fields === [] || strcasecmp($fields[0], $bid) !== 0 || !ctype_xdigit($fields[0])) {
                continue;
            }
            $ko = $this->env->kmodDir() . "/{$fields[0]}/if_pppoe.ko";
            if (!is_file($ko)) {
                return false;
            }
            if (!isset($fields[1]) || $fields[1] === '') {
                return true;
            }
            $have = @hash_file('sha256', $ko);
            return $have !== false && strcasecmp($have, $fields[1]) === 0;
        }
        return false;
    }

    /**
     * The if-pppoe-kmod files the early boot gate reads, keyed like boot.json's "kmod"
     * member (lib.sh ifp_kmod_identity()); 'ko' is the .ko for the *running* kern.build_id,
     * null when that is unusable.
     *
     * @return array{build_ids: string, features: string, ko: ?string}
     */
    private function installedKmodPaths(): array
    {
        $bid = $this->sysctl('kern.build_id');
        $ok = $bid !== null && $bid !== '' && ctype_xdigit($bid);
        return [
            'build_ids' => $this->env->installedBuildIdsFile(),
            'features' => $this->env->installedFeaturesFile(),
            'ko' => $ok ? $this->env->kmodDir() . "/{$bid}/if_pppoe.ko" : null,
        ];
    }

    /**
     * Same identity lib.sh ifp_kmod_identity() records into boot.json on a failed boot:
     * lowercase sha256 per file, '' where the file is absent.
     *
     * @return array{build_ids: string, features: string, ko: string}
     */
    public function installedKmodIdentity(): array
    {
        $out = [];
        foreach ($this->installedKmodPaths() as $part => $path) {
            $h = $path !== null && is_file($path) ? @hash_file('sha256', $path) : false;
            $out[$part] = $h === false ? '' : strtolower($h);
        }
        return $out;
    }

    /**
     * mtime per installedKmodPaths() entry, null where the file is absent. Fallback for a
     * boot.json written by a syshook that predates ifp_kmod_identity().
     *
     * @return array{build_ids: ?int, features: ?int, ko: ?int}
     */
    public function installedKmodMtimes(): array
    {
        $out = [];
        foreach ($this->installedKmodPaths() as $part => $path) {
            $m = $path !== null ? @filemtime($path) : false;
            $out[$part] = $m === false ? null : $m;
        }
        return $out;
    }

    /** IF_PPPOE_PACKAGES in lib.sh: what the IfPppoe repository installs */
    public const PACKAGES = ['if-pppoe-kmod', 'os-if-pppoe'];

    /**
     * An installed plugin package built for another ABI than this system's (`pkg config abi`
     * vs `pkg query %q`, as lib.sh ifp_abi_mismatch()), e.g. FreeBSD:14:amd64 builds left
     * behind by a major upgrade to FreeBSD:15. null when they match or pkg cannot say.
     *
     * @return ?array{package: string, installed: string, system: string}
     */
    public function packageAbiMismatch(): ?array
    {
        $valid = fn(string $abi): bool => preg_match('/^[A-Za-z0-9:_.*-]+$/', $abi) === 1;
        $sys = $this->proc->run([$this->env->bin('pkg'), 'config', 'abi'], null, 10);
        $system = trim($sys->out);
        if (!$sys->ok() || !$valid($system) || str_contains($system, '*')) {
            return null;
        }
        foreach (self::PACKAGES as $p) {
            $q = $this->proc->run([$this->env->bin('pkg'), 'query', '%q', $p], null, 10);
            $abi = trim($q->out);
            if ($q->ok() && $valid($abi) && !fnmatch($abi, $system)) {
                return ['package' => $p, 'installed' => $abi, 'system' => $system];
            }
        }
        return null;
    }

    /** The shipped features file exists and lists $feature (full kern.features name). */
    public function installedFeatureListed(string $feature): bool
    {
        $missing = $this->missingInstalledFeatures();
        if ($missing === null) {
            return false;
        }
        return in_array($feature, Env::REQUIRED_FEATURES, true) && !in_array($feature, $missing, true);
    }

    /* True when the .ko resident in the kernel (Env::loadedKmodFile(), written by the
     * boot syshook) is stale vs. what's now installed, e.g. a kmod upgrade with no
     * reboot yet. No sysctl exposes the loaded module's build identity, so this
     * compares file identity instead. */
    public function kmodUpgradePending(): bool
    {
        $loaded = Fs::readJson($this->env->loadedKmodFile());
        if (!is_array($loaded) || !is_string($loaded['build_id'] ?? null) || !is_string($loaded['sha256'] ?? null)) {
            return false;
        }
        if (!ctype_xdigit($loaded['build_id'])) {
            /* root-owned file, but kmodCovers() validates the same way before building a path */
            return false;
        }
        $bid = $this->sysctl('kern.build_id');
        if ($bid === null || strcasecmp($bid, $loaded['build_id']) !== 0) {
            return false;
        }
        $ko = $this->env->kmodDir() . "/{$loaded['build_id']}/if_pppoe.ko";
        $have = is_file($ko) ? @hash_file('sha256', $ko) : false;
        return $have !== false && strcasecmp($have, $loaded['sha256']) !== 0;
    }

    /** hook.json says applied AND both marker lines are really in interfaces.inc */
    public function hookApplied(): bool
    {
        return $this->hookStatus() === 'applied';
    }

    public function hookStatus(): string
    {
        $j = Fs::readJson($this->env->hookJson());
        $status = is_array($j) && isset($j['status']) ? (string)$j['status'] : 'unknown';
        if ($status === 'applied') {
            $src = @file_get_contents($this->env->interfacesInc());
            if ($src === false || substr_count($src, Env::HOOK_MARKER) !== 2) {
                return 'missing';
            }
        }
        return $status;
    }

    public function latched(): bool
    {
        return is_file($this->env->latchFile());
    }

    public function desired(): string
    {
        $v = @file_get_contents($this->env->desiredFile());
        return $v === false ? 'unset' : trim($v);
    }

    public function parentInfo(string $ifname): array
    {
        $info = $this->ifInfo($ifname);
        if ($info === null) {
            return ['exists' => false, 'ether' => false, 'mtu' => 0, 'why' => ''];
        }
        $why = '';
        $ether = $info['ether'];
        if (!$ether) {
            $why = 'no Ethernet address';
        } elseif (preg_match('/^(bridge|pppoe|ng|gif|gre|lo|enc|pflog|pfsync|ovpn|wg|tun|ipsec)[0-9]/', $ifname)) {
            /* the kmod only attaches to IFT_ETHER / IFT_L2VLAN parents */
            $ether = false;
            $why = 'interface type not supported';
        }
        return ['exists' => true, 'ether' => $ether, 'mtu' => $info['mtu'], 'why' => $why];
    }

    /** parsed `pppoectl -dd <dev>` */
    public function session(string $device): ?array
    {
        $r = $this->proc->run([$this->env->bin('pppoectl'), '-dd', $device], null, 10);
        if (!$r->ok()) {
            return null;
        }
        return self::parseSession($r->out);
    }

    public static function parseSession(string $out): array
    {
        $s = ['pppoe' => null, 'session_id' => null, 'lcp' => null, 'ipcp' => null, 'ipv6cp' => null,
            'address' => null, 'dns1' => null, 'dns2' => null, 'my_ifid' => null, 'his_ifid' => null];
        foreach (explode("\n", $out) as $line) {
            $line = trim($line);
            if (preg_match('/(?:PPPoE state:|state =) (\S+)/', $line, $m)) {
                $s['pppoe'] = $m[1];
            } elseif (preg_match('/^Session ID: (0x[0-9a-f]+)/i', $line, $m)) {
                $s['session_id'] = $m[1];
            } elseif (preg_match('/^LCP state: (\S+)/', $line, $m)) {
                $s['lcp'] = $m[1];
            } elseif (preg_match('/^IPCP state: (\S+)/', $line, $m)) {
                $s['ipcp'] = $m[1];
            } elseif (preg_match('/^IPv6CP state: (\S+)/', $line, $m)) {
                $s['ipv6cp'] = $m[1];
            } elseif (preg_match('/^address ([0-9.]+)/', $line, $m)) {
                $s['address'] = $m[1];
            } elseif (preg_match('/^primary dns address ([0-9.]+)/', $line, $m)) {
                $s['dns1'] = $m[1];
            } elseif (preg_match('/^secondary dns address ([0-9.]+)/', $line, $m)) {
                $s['dns2'] = $m[1];
            } elseif (preg_match('/my_ifid=0x([0-9a-f]{16}), his_ifid=0x([0-9a-f]{16})/i', $line, $m)) {
                $s['my_ifid'] = strtolower($m[1]);
                $s['his_ifid'] = strtolower($m[2]);
            }
        }
        return $s;
    }

    /** net.pppoe.* counters (vnet-global) */
    public function counters(): array
    {
        $r = $this->proc->run([$this->env->bin('sysctl'), 'net.pppoe'], null, 10);
        $out = [];
        if ($r->ok()) {
            foreach (explode("\n", $r->out) as $line) {
                if (preg_match('/^net\.pppoe\.([A-Za-z0-9_]+): (-?[0-9]+)$/', trim($line), $m)) {
                    $out[$m[1]] = (int)$m[2];
                }
            }
        }
        return $out;
    }

    /** true when the pidfile names a live process (pgrep -F) */
    public function pidfileAlive(string $pidfile): bool
    {
        if (!is_file($pidfile)) {
            return false;
        }
        return $this->proc->run([$this->env->bin('pgrep'), '-F', $pidfile], null, 5)->ok();
    }
}
