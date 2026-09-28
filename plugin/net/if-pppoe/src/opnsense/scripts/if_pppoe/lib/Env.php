<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

/** Every absolute path the engine touches; IF_PPPOE_ROOT prefixes them all (tests only). */
final class Env
{
    /* kernel features the engine requires (kern.features.<name>) */
    public const REQUIRED_FEATURES = [
        'if_pppoe_linkevents',
        'if_pppoe_ipv6',
        'if_pppoe_mssfix',
        'if_pppoe_pfil_pass_foreign',
        'if_pppoe_single_bytecount',
    ];

    public const HOOK_MARKER = '/* os-if-pppoe:v1 */';

    private string $root;

    public function __construct(?string $root = null)
    {
        if ($root === null) {
            $root = getenv('IF_PPPOE_ROOT');
            $root = $root === false ? '' : rtrim($root, '/');
        }
        $this->root = $root;
    }

    public function root(): string
    {
        return $this->root;
    }

    public function path(string $abs): string
    {
        return $this->root . $abs;
    }

    /* inputs owned by core */
    public function configXml(): string
    {
        return $this->path('/conf/config.xml');
    }

    public function interfacesInc(): string
    {
        return $this->path('/usr/local/etc/inc/interfaces.inc');
    }

    public function mpdConf(string $friendly): string
    {
        return $this->path("/var/etc/mpd_{$friendly}.conf");
    }

    public function mpdPidfile(string $friendly): string
    {
        /* interfaces.inc:1313 killbypid("/var/run/{$ppp['type']}_{$interface}.pid") */
        return $this->path("/var/run/pppoe_{$friendly}.pid");
    }

    /* persistent plugin state (owned by hookctl / boot scripts, read here) */
    public function confDir(): string
    {
        return $this->path('/conf/if_pppoe');
    }

    public function hookJson(): string
    {
        return $this->confDir() . '/hook.json';
    }

    public function desiredFile(): string
    {
        return $this->confDir() . '/desired';
    }

    public function latchFile(): string
    {
        return $this->confDir() . '/latch';
    }

    /* if-pppoe-kmod package data: what this box has installed, independent of
     * whether a module is actually loaded right now (see Kernel::installedFeatures()
     * and Kernel::installedKmodMatchesKernel()). Written at package build time
     * (plugin/kmod/if-pppoe-kmod/Makefile's build-ids-file/features-file/kernels-json-file). */
    public function installedBuildIdsFile(): string
    {
        return $this->path('/usr/local/share/if_pppoe/build_ids');
    }

    public function installedFeaturesFile(): string
    {
        return $this->path('/usr/local/share/if_pppoe/features');
    }

    public function kmodDir(): string
    {
        return $this->path('/usr/local/lib/if_pppoe');
    }

    /* [{series, version, abi, build_id, ...}] for every kernel the installed if-pppoe-kmod
     * ships a .ko for (the Makefile's kernels-json-file, filtered to build_ids). Absent in
     * an if-pppoe-kmod predating the kernel matrix. */
    public function installedKernelsJsonFile(): string
    {
        return $this->path('/usr/local/share/if_pppoe/kernels.json');
    }

    /* the kernel the next boot loads: opnsense-update -k moves /boot/kernel to
     * /boot/kernel.old and extracts the new set over / (opnsense/update
     * src/update/opnsense-update.sh.in install_kernel(), KERNELDIR="/boot/kernel") */
    public function installedKernelFile(): string
    {
        return $this->path('/boot/kernel/kernel');
    }

    /* a major upgrade (opnsense-update -u -k) defers the kernel set instead: it writes
     * the target release here and installs it on the next boot (opnsense-update.sh.in
     * PENDING_KERNEL="${WORKPREFIX}/.kernel.pending", WORKPREFIX="/var/cache/opnsense-update") */
    public function pendingKernelFile(): string
    {
        return $this->path('/var/cache/opnsense-update/.kernel.pending');
    }

    /* volatile engine state */
    public function runDir(): string
    {
        return $this->path('/var/run/if_pppoe');
    }

    public function regDir(): string
    {
        return $this->runDir() . '/reg';
    }

    public function lockDir(): string
    {
        return $this->runDir() . '/lock';
    }

    public function queueDir(): string
    {
        return $this->runDir() . '/queue';
    }

    public function statusJson(): string
    {
        return $this->runDir() . '/status.json';
    }

    /* written by the early boot syshook (lib.sh ifp_boot_state): {desired,result,reason,at} */
    public function bootJson(): string
    {
        return $this->runDir() . '/boot.json';
    }

    /* written by the early boot syshook once it has confirmed a .ko is loaded
     * (lib.sh ifp_kmod_record_loaded): {build_id,sha256} of the .ko file that
     * is actually resident in the running kernel. Absent whenever nothing is
     * known to be loaded (kmod unloaded, or a boot predating this file). */
    public function loadedKmodFile(): string
    {
        return $this->runDir() . '/loaded.json';
    }

    /* one file per notice, written by the syshooks (lib.sh ifp_notice) */
    public function noticeDir(): string
    {
        return $this->runDir() . '/notice.d';
    }

    /* snapshot of the plugin settings taken on the first engine run of a boot */
    public function effectiveJson(): string
    {
        return $this->runDir() . '/effective.json';
    }

    /* binaries */
    public function bin(string $name): string
    {
        static $map = [
            'ifconfig' => '/sbin/ifconfig',
            'sysctl' => '/sbin/sysctl',
            'pppoectl' => '/usr/local/sbin/pppoectl',
            'configctl' => '/usr/local/sbin/configctl',
            'logger' => '/usr/bin/logger',
            'timeout' => '/bin/timeout', /* same path as the hook line and lib.sh; 14.3 keeps /usr/bin/timeout as a symlink */
            'pgrep' => '/bin/pgrep',
            'daemon' => '/usr/sbin/daemon',
            'engine' => '/usr/local/opnsense/scripts/if_pppoe/engine',
            'linkup' => '/usr/local/opnsense/scripts/interfaces/ppp-linkup.sh',
            'linkdown' => '/usr/local/opnsense/scripts/interfaces/ppp-linkdown.sh',
            'hookctl' => '/usr/local/opnsense/scripts/if_pppoe/hookctl.php',
            'php' => '/usr/local/bin/php',
        ];
        if (!isset($map[$name])) {
            throw new \InvalidArgumentException("unknown binary {$name}");
        }
        return $this->path($map[$name]);
    }
}
