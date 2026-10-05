<?php

/*
 * Copyright (C) 2026 Anthony Nash
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\IfPppoe;

/**
 * Pure logic shared by the model (IfPppoe::performValidation()) and the API
 * controllers (Api\ServiceController). Deliberately has no OPNsense\Base or
 * OPNsense\Core dependency -- same rationale as
 * scripts/if_pppoe/set-desired.php: everything here takes plain PHP types
 * (SimpleXMLElement, arrays, strings, nullables) instead of Config/Backend,
 * so it's unit-testable with plain php-cli and no live Phalcon DI container
 * (see tests/plugin/p4-ui/test_support_lib.php). Nothing here calls
 * gettext(): callers apply that themselves, since gettext() needs the
 * php-gettext extension that a bare php-cli test image doesn't ship.
 * @package OPNsense\IfPppoe
 */
class Support
{
    /**
     * Standalone-only guard: kernel PPPoE is refused when CARP VIPs or
     * hasync (including hasync's XMLRPC config sync, `synchronizetoip`) are
     * configured. Takes config.xml's root element directly, exactly as
     * OPNsense\Core\Config::getInstance()->object() returns it, so this
     * needs no Config/Phalcon dependency to call or to test.
     *
     * @param \SimpleXMLElement $cfg config.xml root
     * @return string|null an untranslated, user-facing reason (wrap with
     *                      gettext() at the call site), or null when
     *                      standalone-safe
     */
    public static function standaloneViolation(\SimpleXMLElement $cfg): ?string
    {
        if (!empty($cfg->virtualip) && !empty($cfg->virtualip->vip)) {
            foreach ($cfg->virtualip->vip as $vip) {
                if ((string)($vip->mode ?? '') === 'carp') {
                    return 'Kernel PPPoE is not supported alongside CARP. Remove all CARP VIPs first.';
                }
            }
        }

        if (
            !empty($cfg->hasync) && (
                !empty($cfg->hasync->pfsyncpeerip) ||
                !empty($cfg->hasync->pfsyncinterface) ||
                !empty($cfg->hasync->synchronizetoip)
            )
        ) {
            return 'Kernel PPPoE is not supported on an HA-synced (hasync) box. Disable HA sync first.';
        }

        return null;
    }

    /**
     * Maps the engine's `status --json` (Engine::statusReport(), the source of
     * truth) onto the Api\ServiceController::statusAction() payload the
     * Services page renders. Pure function: no Backend/Config dependency.
     *
     * Engine keys read (see Engine::statusReport()):
     *   desired      'enabled'|'disabled'|'unset'   /conf/if_pppoe/desired
     *   hook         'applied'|'reverted'|'unknown'|'missing'|'foreign'|
     *                'paused:core-reinstall'|'refused:<reason>'  (hookctl)
     *   hook_detail  string
     *   latched      bool (boot-strike latch that the next boot keeps)
     *   boot         {desired, result: enabled|disabled|failed|latched, reason, at}|null
     *   notices      {<key>: {message, at}}   /var/run/if_pppoe/notice.d
     *   settings     {enabled, exclude}|null  config.xml OPNsense/IfPppoe/general
     *   reboot_required, apply_pending   bool, computed by the engine only
     *   installed_eligible, installed_reason   whether *enabling* would work
     *                        after a reboot, from the installed (not necessarily loaded) kmod
     *   package_abi  {package, installed, system}|null: an installed plugin package built
     *                 for another ABI (left behind by a major upgrade, Kernel::packageAbiMismatch())
     *   kernels      {supported: [{version, series, build_id}]|null, running: {build_id,
     *                 version, covered}, installed: {build_id, version, covered,
     *                 pending_reboot}, upgrade: {version, covered: bool|null}|null}
     *                        (Engine::kernelCoverage(): the installed kmod's kernels.json)
     *   interfaces   {<friendly>: {device, backend: kernel|mpd5|none, reason,
     *                 eligible, registry: {state, session, v4, v6, local, ...}}}
     *
     * reboot_required and apply_pending are taken from the engine as-is; this
     * never recomputes them (the engine knows the latch, the pause and this
     * boot's outcome). When the engine could not read config.xml, apply_pending
     * falls back to comparing the saved model with /conf/if_pppoe/desired.
     *
     * @param string $desiredModel 'enabled'|'disabled', from the saved model
     * @param array|null $engine decoded `engine status --json`, or null when
     *                           the engine is missing or its output is unparseable
     * @return array the Api\ServiceController::statusAction() payload
     */
    public static function mergeStatus(string $desiredModel, ?array $engine): array
    {
        $out = [
            'engine_available' => $engine !== null,
            'desired' => $desiredModel,
            'persisted' => null,
            'effective' => null,
            'hook_status' => null,
            'hook_detail' => '',
            'boot' => ['result' => null, 'reason' => null, 'desired' => null, 'at' => null],
            'latched' => false,
            'refused' => null,
            'paused' => false,
            'reboot_required' => false,
            'installed_eligible' => true,
            'installed_reason' => '',
            'package_abi' => null,
            'apply_pending' => false,
            'supported_kernels' => null,
            'running_kernel' => null,
            'installed_kernel' => null,
            'kernel_upgrade' => null,
            'notices' => [],
            'advice' => null,
            'interfaces' => [],
        ];
        if ($engine === null) {
            return $out;
        }

        $persisted = $engine['desired'] ?? null;
        $out['persisted'] = in_array($persisted, ['enabled', 'disabled'], true) ? $persisted : null;
        $hook = is_string($engine['hook'] ?? null) ? $engine['hook'] : null;
        $out['hook_status'] = $hook;
        $out['hook_detail'] = is_string($engine['hook_detail'] ?? null) ? $engine['hook_detail'] : '';
        if (is_array($engine['boot'] ?? null)) {
            foreach (['result', 'reason', 'desired', 'at'] as $k) {
                $out['boot'][$k] = $engine['boot'][$k] ?? null;
            }
        }
        $out['latched'] = ($engine['latched'] ?? false) === true;
        if ($hook === 'foreign') {
            $out['refused'] = 'foreign';
        } elseif ($hook !== null && str_starts_with($hook, 'refused:')) {
            $out['refused'] = substr($hook, strlen('refused:'));
        }
        $out['paused'] = $hook === 'paused:core-reinstall';
        $out['reboot_required'] = ($engine['reboot_required'] ?? false) === true;
        $out['installed_eligible'] = ($engine['installed_eligible'] ?? true) === true;
        $out['installed_reason'] = (string)($engine['installed_reason'] ?? '');
        $abi = $engine['package_abi'] ?? null;
        if (is_array($abi) && is_string($abi['package'] ?? null) && is_string($abi['installed'] ?? null) && is_string($abi['system'] ?? null)) {
            $out['package_abi'] = ['package' => $abi['package'], 'installed' => $abi['installed'], 'system' => $abi['system']];
        }
        if (is_array($engine['settings'] ?? null)) {
            $out['apply_pending'] = ($engine['apply_pending'] ?? false) === true;
        } else {
            $out['apply_pending'] = ($out['persisted'] ?? 'disabled') !== $desiredModel;
        }
        self::mergeKernels($out, is_array($engine['kernels'] ?? null) ? $engine['kernels'] : []);
        foreach ((array)($engine['notices'] ?? []) as $key => $n) {
            if (is_array($n) && is_string($n['message'] ?? null)) {
                $out['notices'][] = ['key' => (string)$key, 'message' => $n['message'], 'at' => $n['at'] ?? null];
            }
        }

        $backends = [];
        foreach ((array)($engine['interfaces'] ?? []) as $friendly => $i) {
            if (!is_array($i)) {
                continue;
            }
            $backend = is_string($i['backend'] ?? null) ? $i['backend'] : 'none';
            if ($backend !== 'none') {
                $backends[$backend] = true;
            }
            $out['interfaces'][] = [
                'friendly' => (string)$friendly,
                'device' => (string)($i['device'] ?? ''),
                'backend' => $backend,
                'eligible' => $i['eligible'] ?? null,
                'reason' => (string)($i['reason'] ?? ''),
                'session' => self::sessionText($backend, is_array($i['registry'] ?? null) ? $i['registry'] : []),
            ];
        }
        if (count($backends) > 1) {
            $out['effective'] = 'mixed';
        } elseif (count($backends) === 1) {
            $out['effective'] = array_key_first($backends);
        }

        $out['advice'] = self::advice($out);
        return $out;
    }

    /**
     * kernels -> supported_kernels (version strings, the view groups them by series; null =
     * unknown, an if-pppoe-kmod without kernels.json), running_kernel / installed_kernel
     * ({version, build_id, covered, pending_reboot}; null when the engine sent none) and
     * kernel_upgrade ({version, covered: bool|null}|null).
     */
    private static function mergeKernels(array &$out, array $k): void
    {
        $str = fn($v): ?string => is_string($v) && $v !== '' ? $v : null;
        if (is_array($k['supported'] ?? null)) {
            $out['supported_kernels'] = [];
            foreach ($k['supported'] as $e) {
                if (is_array($e) && ($v = $str($e['version'] ?? null)) !== null && !in_array($v, $out['supported_kernels'], true)) {
                    $out['supported_kernels'][] = $v;
                }
            }
            usort($out['supported_kernels'], 'strnatcmp');
        }
        foreach (['running' => 'running_kernel', 'installed' => 'installed_kernel'] as $from => $to) {
            if (is_array($k[$from] ?? null)) {
                $out[$to] = [
                    'version' => $str($k[$from]['version'] ?? null),
                    'build_id' => $str($k[$from]['build_id'] ?? null),
                    'covered' => ($k[$from]['covered'] ?? false) === true,
                    'pending_reboot' => ($k[$from]['pending_reboot'] ?? false) === true,
                ];
            }
        }
        if (is_array($k['upgrade'] ?? null) && ($v = $str($k['upgrade']['version'] ?? null)) !== null) {
            $c = $k['upgrade']['covered'] ?? null;
            $out['kernel_upgrade'] = ['version' => $v, 'covered' => is_bool($c) ? $c : null];
        }
    }

    /** one line for the Session column */
    private static function sessionText(string $backend, array $reg): string
    {
        if ($backend !== 'kernel') {
            return '';
        }
        if (($reg['session'] ?? 'down') !== 'up') {
            return (string)($reg['state'] ?? 'down');
        }
        $parts = ['up'];
        if (($reg['v4'] ?? 'down') === 'up') {
            $parts[] = trim('IPv4 ' . (string)($reg['local'] ?? ''));
        }
        if (($reg['v6'] ?? 'down') === 'up') {
            $parts[] = 'IPv6';
        }
        return implode(', ', $parts);
    }

    /**
     * The one thing the user should do next, or null. Untranslated (the view
     * shows it as-is). Order: unsaved Apply, latch, refusal, pause, wrong-ABI packages, reboot,
     * an installed-but-not-booted kernel the kmod does not cover, failed boot.
     */
    private static function advice(array $s): ?string
    {
        if ($s['apply_pending']) {
            return 'Saved but not applied: click Save and Apply.';
        }
        if ($s['latched']) {
            return 'Latched to mpd5 after repeated unclean boots: Save and Apply to retry, then reboot.';
        }
        if ($s['refused'] !== null && $s['persisted'] === 'enabled') {
            return "Unsupported here ({$s['refused']}); using mpd5. A reboot will not help.";
        }
        if ($s['paused'] && !$s['reboot_required'] && $s['persisted'] === 'enabled') {
            return 'Core was reinstalled: Save and Apply, then reboot to resume kernel mode.';
        }
        $abi = $s['package_abi'];
        if ($abi !== null) {
            /* a reboot cannot help until the right build is installed (abi-heal.sh tries on its own) */
            return "Installed {$abi['package']} is built for {$abi['installed']} but this system is {$abi['system']}; reinstall it"
                . ' (System: Firmware: Packages, reinstall if-pppoe-kmod and os-if-pppoe, or'
                . ' pkg install -f -r IfPppoe if-pppoe-kmod os-if-pppoe), then reboot.';
        }
        if ($s['reboot_required']) {
            /* installed_eligible only speaks to *enabling*; reboot_required also fires for
             * desired=disabled (Engine::rebootRequired()), where the reboot is what turns
             * kernel mode off, so the installed-ineligible text would be backwards there. */
            if ($s['persisted'] === 'enabled' && !$s['installed_eligible']) {
                return "Rebooting will not enable kernel PPPoE ({$s['installed_reason']}); using mpd5.";
            }
            return 'Reboot to apply.';
        }
        $inst = $s['installed_kernel'];
        if ($s['persisted'] === 'enabled' && is_array($inst) && $inst['pending_reboot'] && !$inst['covered']) {
            $v = $inst['version'] ?? ('build-id ' . substr((string)$inst['build_id'], 0, 12));
            return "OPNsense kernel {$v} installed (pending reboot) is not covered by if-pppoe-kmod yet; after reboot"
                . ' mpd5 is used until an updated if-pppoe-kmod is published (System: Firmware: Updates).';
        }
        if ($s['boot']['result'] === 'failed' && $s['persisted'] === 'enabled') {
            return 'Kernel mode was not armed at boot (' . (string)$s['boot']['reason'] . '); using mpd5.';
        }
        return null;
    }
}
