<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

final class ProcResult
{
    public function __construct(
        public int $rc,
        public string $out,
        public string $err
    ) {
    }

    public function ok(): bool
    {
        return $this->rc === 0;
    }
}

/**
 * Runs external commands without a shell: argv is passed as an array to
 * proc_open(), so no value is ever re-parsed by sh.  Secrets go through
 * $stdin only; argv is visible in ps(1) and in process accounting.
 */
class Proc
{
    public function run(array $argv, ?string $stdin = null, int $timeout = 30): ProcResult
    {
        $argv = array_map('strval', array_values($argv));
        $spec = [
            0 => $stdin === null ? ['file', '/dev/null', 'r'] : ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $p = @proc_open($argv, $spec, $pipes);
        if (!is_resource($p)) {
            return new ProcResult(127, '', "cannot execute {$argv[0]}");
        }
        if ($stdin !== null) {
            $len = strlen($stdin);
            for ($off = 0; $off < $len;) {
                $n = @fwrite($pipes[0], substr($stdin, $off));
                if ($n === false || $n === 0) {
                    break;
                }
                $off += $n;
            }
            fclose($pipes[0]);
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $deadline = microtime(true) + $timeout;
        $rc = -1;
        while (true) {
            $r = [$pipes[1], $pipes[2]];
            $w = $e = null;
            if (@stream_select($r, $w, $e, 0, 100000) > 0) {
                foreach ($r as $fd) {
                    $chunk = fread($fd, 65536);
                    if ($chunk !== false) {
                        if ($fd === $pipes[1]) {
                            $out .= $chunk;
                        } else {
                            $err .= $chunk;
                        }
                    }
                }
            }
            $st = proc_get_status($p);
            if (!$st['running']) {
                $rc = $st['exitcode'];
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($p, 9);
                $rc = 124;
                $err .= "timeout after {$timeout}s";
                break;
            }
        }
        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $closed = proc_close($p);
        if ($rc === -1) {
            $rc = $closed;
        }
        return new ProcResult((int)$rc, $out, $err);
    }
}
