<?php

/* Minimal dependency-free test harness for the engine (no phpunit on the build host or the box). */

namespace IfPppoe\Test;

use IfPppoe\Engine\Env;
use IfPppoe\Engine\Engine;
use IfPppoe\Engine\Kernel;
use IfPppoe\Engine\Proc;

const SRC = __DIR__ . '/../../src/opnsense/scripts/if_pppoe';

require_once SRC . '/lib/Env.php';
require_once SRC . '/lib/Proc.php';
require_once SRC . '/lib/Config.php';
require_once SRC . '/lib/State.php';
require_once SRC . '/lib/Eligibility.php';
require_once SRC . '/lib/Pppoectl.php';
require_once SRC . '/lib/Kernel.php';
require_once SRC . '/lib/Engine.php';

final class AssertionFailed extends \Exception
{
}

final class T
{
    private static array $tests = [];

    public static function test(string $name, callable $fn): void
    {
        self::$tests[$name] = $fn;
    }

    public static function ok($cond, string $msg = 'assertion failed'): void
    {
        if (!$cond) {
            throw new AssertionFailed($msg);
        }
    }

    public static function eq($expected, $actual, string $msg = ''): void
    {
        if ($expected !== $actual) {
            throw new AssertionFailed(($msg !== '' ? "$msg: " : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
        }
    }

    public static function contains(string $needle, string $hay, string $msg = ''): void
    {
        self::ok(str_contains($hay, $needle), ($msg !== '' ? "$msg: " : '') . "'" . $needle . "' not found in '" . $hay . "'");
    }

    public static function run(?string $filter): int
    {
        $pass = $fail = 0;
        foreach (self::$tests as $name => $fn) {
            if ($filter !== null && !str_contains($name, $filter)) {
                continue;
            }
            try {
                $fn();
                $pass++;
                echo "ok   $name\n";
            } catch (\Throwable $e) {
                $fail++;
                echo "FAIL $name\n     " . get_class($e) . ': ' . $e->getMessage() . "\n     at " . $e->getFile() . ':' . $e->getLine() . "\n";
            }
        }
        echo "\n$pass passed, $fail failed (PHP " . PHP_VERSION . ")\n";
        return $fail === 0 ? 0 : 1;
    }
}

/** A throw-away IF_PPPOE_ROOT with recording stubs, a config.xml fixture and fake kernel state. */
final class Sandbox
{
    public const BINS = [
        '/sbin/ifconfig', '/sbin/sysctl', '/usr/local/sbin/pppoectl', '/usr/local/sbin/configctl',
        '/usr/bin/logger', '/bin/pgrep', '/usr/sbin/daemon',
        '/usr/local/opnsense/scripts/interfaces/ppp-linkup.sh',
        '/usr/local/opnsense/scripts/interfaces/ppp-linkdown.sh',
    ];

    /* a fake kern.build_id: what the box is "currently running", matched by
     * the default installed build_ids fixture below (installedKmodOk()) */
    public const BUILD_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f900112233';

    public string $root;
    public array $logs = [];

    public function __construct(string $fixture = 'config-base.xml', bool $hook = true, bool $features = true)
    {
        $this->root = sys_get_temp_dir() . '/ifpppoe-test-' . bin2hex(random_bytes(6));
        mkdir($this->root, 0700, true);
        putenv('IF_PPPOE_ROOT=' . $this->root);
        $stub = "#!/usr/bin/env php\n" . file_get_contents(__DIR__ . '/stubs/stub.php');
        foreach (self::BINS as $b) {
            $this->write($b, $stub, 0755);
        }
        $this->write('/conf/config.xml', file_get_contents(__DIR__ . "/fixtures/{$fixture}"));
        $inc = "<?php\nfunction interface_ppps_reset() {\n    " . Env::HOOK_MARKER . " x;\n}\nfunction interface_ppps_configure() {\n    " . Env::HOOK_MARKER . " y;\n}\n";
        $this->write('/usr/local/etc/inc/interfaces.inc', $inc);
        if ($hook) {
            $this->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'applied', 'hook_version' => 'v1']));
        }
        $this->write('/conf/if_pppoe/desired', "enabled\n");
        $sysctl = ['net.pppoe.padt_tx' => '0', 'net.pppoe.sess_in' => '42', 'kern.build_id' => self::BUILD_ID];
        if ($features) {
            foreach (Env::REQUIRED_FEATURES as $f) {
                $sysctl["kern.features.$f"] = '1';
            }
        }
        $this->fakeJson('sysctl.json', $sysctl);
        $this->iface('igb0', ['ether' => true, 'mtu' => 1500]);
        $this->iface('igb1', ['ether' => true, 'mtu' => 1500]);
        $this->iface('igb2', ['ether' => true, 'mtu' => 1500]);
        $this->iface('vlan0.100', ['ether' => true, 'mtu' => 1508, 'vlan' => true, 'groups' => ['vlan']]);
        $this->iface('bridge0', ['ether' => true, 'mtu' => 1500, 'groups' => ['bridge']]);
        /* if-pppoe-kmod package data: matches BUILD_ID and all REQUIRED_FEATURES by
         * default, so Kernel::installedKmodMatchesKernel()/missingInstalledFeatures()
         * read as a healthy install unless a test breaks them deliberately. */
        $this->write('/usr/local/lib/if_pppoe/' . self::BUILD_ID . '/if_pppoe.ko', "fake .ko\n");
        $this->write('/usr/local/share/if_pppoe/build_ids', self::BUILD_ID . "\n");
        $this->write('/usr/local/share/if_pppoe/features', implode("\n", Env::REQUIRED_FEATURES) . "\n");
        $this->kernelsJson([['series' => '25.7', 'version' => '25.7.8', 'abi' => 'FreeBSD:14:amd64', 'build_id' => self::BUILD_ID]]);
        /* no /boot/kernel/kernel: Kernel::installedKernelBuildId() is null and every check
         * falls back to the running kern.build_id unless a test calls installedKernel() */
    }

    /** a second kernel build-id (even length, so it fits in a synthetic ELF note) */
    public const NEW_BUILD_ID = '0f1e2d3c4b5a69788796a5b4c3d2e1f00112233a';

    /** sets one fake sysctl value (e.g. kern.build_id) */
    public function sysctl(string $name, string $value): void
    {
        $vals = json_decode((string)file_get_contents($this->root . '/fake/sysctl.json'), true) ?: [];
        $vals[$name] = $value;
        $this->fakeJson('sysctl.json', $vals);
    }

    /** replaces the shipped kernels.json ([{version, series?, build_id}, ...]) */
    public function kernelsJson(array $entries): void
    {
        $this->write('/usr/local/share/if_pppoe/kernels.json', json_encode($entries));
    }

    /** an if-pppoe-kmod predating kernels.json */
    public function noKernelsJson(): void
    {
        @unlink($this->root . '/usr/local/share/if_pppoe/kernels.json');
    }

    /** adds $bid to the installed if-pppoe-kmod: its .ko plus a build_ids line */
    public function installKoFor(string $bid): void
    {
        $this->write("/usr/local/lib/if_pppoe/{$bid}/if_pppoe.ko", "fake .ko for {$bid}\n");
        $ids = (string)@file_get_contents($this->root . '/usr/local/share/if_pppoe/build_ids');
        $this->write('/usr/local/share/if_pppoe/build_ids', $ids . $bid . "\n");
    }

    /** writes /boot/kernel/kernel as a tiny ELF64 LE file whose GNU build-id note is $bid
     * (hex, even length), or $raw bytes verbatim; the next-boot kernel for Kernel::installedKernelBuildId() */
    public function installedKernel(?string $bid, bool $sections = true, ?string $raw = null): void
    {
        $this->write('/boot/kernel/kernel', $raw ?? self::elf((string)$bid, $sections));
    }

    /**
     * Minimal ELF64 little-endian image: header, one note blob (a FreeBSD ABI-tag note, then
     * NT_GNU_BUILD_ID), and either a section table (null + SHT_NOTE) or one PT_NOTE
     * program header -- the two places Kernel::elfBuildId() looks.
     */
    public static function elf(string $bidHex, bool $sections = true): string
    {
        $note = function (string $name, int $type, string $desc): string {
            $pad = fn(string $b): string => $b . str_repeat("\0", (4 - strlen($b) % 4) % 4);
            return pack('VVV', strlen($name), strlen($desc), $type) . $pad($name) . $pad($desc);
        };
        $notes = $note("FreeBSD\0", 1, pack('V', 1403000)) . $note("GNU\0", 3, hex2bin($bidHex));
        $noteOff = 64;
        $tabOff = $noteOff + strlen($notes);
        $tabOff += (8 - $tabOff % 8) % 8;
        if ($sections) {
            $tab = str_repeat("\0", 64)
                . pack('VVPPPPVVPP', 1, 7, 2, 0, $noteOff, strlen($notes), 0, 0, 4, 0);
            $phoff = 0; $shoff = $tabOff; $phnum = 0; $shnum = 2;
        } else {
            $tab = pack('VVPPPPPP', 4, 4, $noteOff, 0, 0, strlen($notes), strlen($notes), 4);
            $phoff = $tabOff; $shoff = 0; $phnum = 1; $shnum = 0;
        }
        $hdr = "\x7fELF" . chr(2) . chr(1) . chr(1) . chr(9) . str_repeat("\0", 8)
            . pack('vvV', 2, 62, 1) . pack('PPP', 0, $phoff, $shoff)
            . pack('Vvvvvvv', 0, 64, 56, $phnum, 64, $shnum, 0);
        return $hdr . $notes . str_repeat("\0", $tabOff - $noteOff - strlen($notes)) . $tab;
    }

    /** replaces the shipped features file, to test missingInstalledFeatures() */
    public function installedFeatures(array $names): void
    {
        $this->write('/usr/local/share/if_pppoe/features', implode("\n", $names) . "\n");
    }

    /** removes the shipped features file entirely, to test the "unknown" (not
     * "all missing") case: an if-pppoe-kmod predating this file */
    public function noInstalledFeaturesFile(): void
    {
        @unlink($this->root . '/usr/local/share/if_pppoe/features');
    }

    /** empties the shipped build_ids file, to test installedKmodMatchesKernel() */
    public function noInstalledBuildIds(): void
    {
        $this->write('/usr/local/share/if_pppoe/build_ids', '');
    }

    /** boot.json for a boot that failed with $reason at time()-10, as early/50-if-pppoe's
     * fail() writes it: with the kmod identity of the files installed *now* (lib.sh
     * ifp_kmod_identity()), or, with $identity=false, the older format without one and
     * every installed kmod file backdated before the boot (nothing installed since). */
    public function bootFailed(string $reason, bool $identity = true): int
    {
        $at = time() - 10;
        $boot = ['desired' => 'enabled', 'result' => 'failed', 'reason' => $reason, 'at' => $at];
        if ($identity) {
            $boot['kmod'] = (new Kernel($this->env(), new Proc()))->installedKmodIdentity();
        } else {
            foreach (['/usr/local/share/if_pppoe/build_ids', '/usr/local/share/if_pppoe/features',
                '/usr/local/lib/if_pppoe/' . self::BUILD_ID . '/if_pppoe.ko'] as $f) {
                if (is_file($this->root . $f)) {
                    touch($this->root . $f, $at - 100);
                }
            }
        }
        $this->write('/var/run/if_pppoe/boot.json', json_encode($boot));
        return $at;
    }

    /** replaces the installed .ko for BUILD_ID, as a new if-pppoe-kmod package would */
    public function installKo(string $data = "fixed .ko\n"): void
    {
        $this->write('/usr/local/lib/if_pppoe/' . self::BUILD_ID . '/if_pppoe.ko', $data);
    }

    /** records the currently loaded .ko's identity (lib.sh ifp_kmod_record_loaded);
     * pass $sha256 to simulate a stale load (installed .ko since changed) */
    public function recordLoadedKmod(?string $buildId = null, ?string $sha256 = null): void
    {
        $buildId ??= self::BUILD_ID;
        $sha256 ??= hash_file('sha256', "{$this->root}/usr/local/lib/if_pppoe/{$buildId}/if_pppoe.ko");
        $this->write('/var/run/if_pppoe/loaded.json', json_encode(['build_id' => $buildId, 'sha256' => $sha256]));
    }

    public function write(string $abs, string $data, int $mode = 0600): void
    {
        $f = $this->root . $abs;
        if (!is_dir(dirname($f))) {
            mkdir(dirname($f), 0700, true);
        }
        file_put_contents($f, $data);
        chmod($f, $mode);
    }

    public function fakeJson(string $name, $data): void
    {
        $this->write("/fake/$name", json_encode($data));
    }

    public function iface(string $name, array $spec): void
    {
        $spec += ['flags' => ['UP', 'BROADCAST', 'RUNNING', 'SIMPLEX', 'MULTICAST'], 'mtu' => 1500, 'groups' => [], 'ether' => false];
        $this->write("/fake/ifaces/$name.json", json_encode($spec));
    }

    public function ifaceState(string $name): ?array
    {
        $f = "{$this->root}/fake/ifaces/$name.json";
        return is_file($f) ? json_decode(file_get_contents($f), true) : null;
    }

    public function session(string $dev, string $text): void
    {
        $this->write("/fake/sessions/$dev.txt", $text);
    }

    public function fail(array $prefixes): void
    {
        $this->fakeJson('fail.json', $prefixes);
    }

    public function setConfig(string $xml): void
    {
        $this->write('/conf/config.xml', $xml);
    }

    /** mutate the current config.xml with a DOM callback */
    public function editConfig(callable $fn): void
    {
        $dom = new \DOMDocument();
        $dom->preserveWhiteSpace = false;
        $dom->load($this->root . '/conf/config.xml');
        $fn($dom, new \DOMXPath($dom));
        $this->setConfig($dom->saveXML());
    }

    public function env(): Env
    {
        return new Env($this->root);
    }

    /** @param bool $syncDrain run the linkevent drain inline (true) or leave it to the daemon stub (false) */
    public function engine(bool $syncDrain = true): Engine
    {
        $env = $this->env();
        $e = null;
        $e = new Engine($env, new Kernel($env, new Proc()), function (int $p, string $m): void {
            $this->logs[] = $m;
        }, $syncDrain ? function (string $dev) use (&$e): void {
            $e->drain($dev);
        } : null);
        return $e;
    }

    public function exists(string $abs): bool
    {
        return is_file($this->root . $abs);
    }

    /** queued, not yet drained link events */
    public function queued(string $dev): array
    {
        $f = "{$this->root}/var/run/if_pppoe/queue/$dev.q";
        return is_file($f) ? array_map(fn($l) => json_decode($l, true), file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : [];
    }

    public function kernel(): Kernel
    {
        return new Kernel($this->env(), new Proc());
    }

    /** @return list<array{cmd:string,path:string,argv:array,stdin:?string}> */
    public function calls(?string $cmd = null): array
    {
        $f = $this->root . '/calls.jsonl';
        $out = [];
        if (is_file($f)) {
            foreach (file($f, FILE_IGNORE_NEW_LINES) as $l) {
                $c = json_decode($l, true);
                if ($cmd === null || $c['cmd'] === $cmd) {
                    $out[] = $c;
                }
            }
        }
        return $out;
    }

    public function clearCalls(): void
    {
        @unlink($this->root . '/calls.jsonl');
    }

    /** every recorded argv flattened to strings (for "secret never on argv" checks) */
    public function allArgv(): string
    {
        $s = '';
        foreach ($this->calls() as $c) {
            $s .= implode("\x1f", array_merge([$c['path']], $c['argv'])) . "\n";
        }
        return $s;
    }

    /** every file the engine left under the state directories, concatenated */
    public function stateFiles(): string
    {
        $s = '';
        foreach (['/var/run/if_pppoe', '/conf/if_pppoe'] as $d) {
            $dir = $this->root . $d;
            if (!is_dir($dir)) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f->isFile()) {
                    $s .= file_get_contents($f->getPathname());
                }
            }
        }
        return $s;
    }

    public function registry(string $dev): ?array
    {
        $f = "{$this->root}/var/run/if_pppoe/reg/$dev.json";
        return is_file($f) ? json_decode(file_get_contents($f), true) : null;
    }

    /** run the real CLI entry point */
    public function cli(array $args, ?string &$out = null): int
    {
        $r = (new Proc())->run(array_merge([PHP_BINARY, SRC . '/engine'], $args), null, 60);
        $out = $r->out . $r->err;
        return $r->rc;
    }

    public function __destruct()
    {
        if (getenv('KEEP_SANDBOX') === false) {
            exec('rm -rf ' . escapeshellarg($this->root));
        }
    }
}
