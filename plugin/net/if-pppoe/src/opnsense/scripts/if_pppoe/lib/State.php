<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

final class Fs
{
    public static function ensureDir(string $dir, int $mode = 0700): void
    {
        if (!is_dir($dir) && !@mkdir($dir, $mode, true) && !is_dir($dir)) {
            throw new \RuntimeException("cannot create {$dir}");
        }
    }

    /** write via temp file + rename so readers never see a partial file */
    public static function writeAtomic(string $file, string $data, int $mode = 0600): void
    {
        self::ensureDir(dirname($file));
        $tmp = $file . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, $data) !== strlen($data)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot write {$tmp}");
        }
        @chmod($tmp, $mode);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot rename {$tmp}");
        }
    }

    public static function readJson(string $file): ?array
    {
        if (!is_file($file)) {
            return null;
        }
        $j = json_decode((string)@file_get_contents($file), true);
        return is_array($j) ? $j : null;
    }

    public static function writeJson(string $file, array $data): void
    {
        self::writeAtomic($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    }
}

/** flock(2)-based lock on a file under /var/run/if_pppoe/lock */
final class Lock
{
    /** @var resource|null */
    private $fh = null;

    private function __construct(private string $file)
    {
    }

    public static function acquire(Env $env, string $name, float $wait = 20.0): self
    {
        if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $name)) {
            throw new \InvalidArgumentException("bad lock name {$name}");
        }
        Fs::ensureDir($env->lockDir());
        $l = new self($env->lockDir() . '/' . $name);
        $fh = @fopen($l->file, 'c');
        if ($fh === false) {
            throw new \RuntimeException("cannot open lock {$l->file}");
        }
        $deadline = microtime(true) + $wait;
        while (!flock($fh, LOCK_EX | LOCK_NB)) {
            if (microtime(true) >= $deadline) {
                fclose($fh);
                throw new \RuntimeException("timed out waiting for lock {$name}");
            }
            usleep(100000);
        }
        $l->fh = $fh;
        return $l;
    }

    public function release(): void
    {
        if ($this->fh !== null) {
            flock($this->fh, LOCK_UN);
            fclose($this->fh);
            $this->fh = null;
        }
    }

    public function __destruct()
    {
        $this->release();
    }
}

/**
 * /var/run/if_pppoe/reg/<device>.json: one record per kernel clone the
 * engine created.  Never holds credentials.
 */
final class Registry
{
    public function __construct(private Env $env)
    {
    }

    private function file(string $device): string
    {
        if (!preg_match('/^pppoe[0-9]{1,4}$/', $device)) {
            throw new \InvalidArgumentException("bad device {$device}");
        }
        return $this->env->regDir() . "/{$device}.json";
    }

    public function get(string $device): ?array
    {
        return Fs::readJson($this->file($device));
    }

    public function put(string $device, array $rec): void
    {
        $rec['device'] = $device;
        Fs::writeJson($this->file($device), $rec);
    }

    public function update(string $device, array $changes): ?array
    {
        $rec = $this->get($device);
        if ($rec === null) {
            return null;
        }
        $rec = array_replace($rec, $changes);
        $this->put($device, $rec);
        return $rec;
    }

    public function remove(string $device): void
    {
        @unlink($this->file($device));
    }

    /** @return array<string,array> device => record */
    public function all(): array
    {
        $out = [];
        foreach (glob($this->env->regDir() . '/pppoe*.json') ?: [] as $f) {
            $dev = basename($f, '.json');
            if (preg_match('/^pppoe[0-9]{1,4}$/', $dev)) {
                $rec = Fs::readJson($f);
                if ($rec !== null) {
                    $out[$dev] = $rec;
                }
            }
        }
        ksort($out, SORT_NATURAL);
        return $out;
    }

    public function findByFriendly(string $friendly): ?array
    {
        foreach ($this->all() as $rec) {
            if (($rec['friendly'] ?? null) === $friendly) {
                return $rec;
            }
        }
        return null;
    }
}

/** /var/run/if_pppoe/status.json: last backend decision per interface, for the UI */
final class StatusStore
{
    public function __construct(private Env $env)
    {
    }

    public function read(): array
    {
        return Fs::readJson($this->env->statusJson()) ?? ['interfaces' => []];
    }

    public function record(string $friendly, array $entry): void
    {
        $lock = Lock::acquire($this->env, 'status', 10.0);
        try {
            $st = $this->read();
            /* 'reason_recompute' (see Engine::configure()'s ineligible branch) must never
             * outlive the dial that set it: default it to false here so any later record()
             * that omits the key clears a stale true, instead of array_replace() leaving it
             * set forever because no caller happened to pass it explicitly. */
            $entry += ['reason_recompute' => false];
            $st['interfaces'][$friendly] = array_replace($st['interfaces'][$friendly] ?? [], $entry, ['updated' => time()]);
            Fs::writeJson($this->env->statusJson(), $st);
        } finally {
            $lock->release();
        }
    }

    public function forget(string $friendly): void
    {
        $lock = Lock::acquire($this->env, 'status', 10.0);
        try {
            $st = $this->read();
            unset($st['interfaces'][$friendly]);
            Fs::writeJson($this->env->statusJson(), $st);
        } finally {
            $lock->release();
        }
    }
}

/**
 * /var/run/if_pppoe/queue/<device>.q: link events in devd order, one JSON line
 * each, appended by `engine linkevent` and consumed under the device lock.
 */
final class EventQueue
{
    /* a drain that never runs must not fill /var/run; reconcile's level sync covers dropped events */
    public const MAX_BYTES = 262144;

    public function __construct(private Env $env, private string $device)
    {
        if (!preg_match('/^pppoe[0-9]{1,4}$/', $device)) {
            throw new \InvalidArgumentException("bad device {$device}");
        }
    }

    private function file(): string
    {
        return $this->env->queueDir() . "/{$this->device}.q";
    }

    public function push(array $event): bool
    {
        Fs::ensureDir($this->env->queueDir());
        $fh = @fopen($this->file(), 'a');
        if ($fh === false) {
            throw new \RuntimeException("cannot open {$this->file()}");
        }
        try {
            flock($fh, LOCK_EX);
            if (fstat($fh)['size'] >= self::MAX_BYTES) {
                return false;
            }
            fwrite($fh, json_encode($event, JSON_UNESCAPED_SLASHES) . "\n");
            fflush($fh);
            return true;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /** remove and return every queued event, oldest first */
    public function take(): array
    {
        if (!is_file($this->file())) {
            return [];
        }
        $fh = @fopen($this->file(), 'c+');
        if ($fh === false) {
            return [];
        }
        try {
            flock($fh, LOCK_EX);
            $data = (string)stream_get_contents($fh);
            ftruncate($fh, 0);
            fflush($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
        $out = [];
        foreach (explode("\n", $data) as $line) {
            $ev = $line === '' ? null : json_decode($line, true);
            if (is_array($ev)) {
                $out[] = $ev;
            }
        }
        return $out;
    }

    /** devices that have a queue file */
    public static function devices(Env $env): array
    {
        $out = [];
        foreach (glob($env->queueDir() . '/pppoe*.q') ?: [] as $f) {
            $dev = basename($f, '.q');
            if (preg_match('/^pppoe[0-9]{1,4}$/', $dev)) {
                $out[] = $dev;
            }
        }
        return $out;
    }
}
