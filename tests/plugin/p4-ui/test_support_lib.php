<?php
// Unit tests for OPNsense\IfPppoe\Support -- pure, framework-free logic, so this
// requires only Support.php itself, no OPNsense\Base/Core stubs, no Phalcon.
// Usage: test_support_lib.php <path-to-Support.php>

function check(bool $cond, string $label, array &$failures): void
{
    echo ($cond ? 'ok' : 'FAIL') . " - $label\n";
    if (!$cond) {
        $failures[] = $label;
    }
}

$path = $argv[1] ?? null;
if ($path === null || !is_file($path)) {
    fwrite(STDERR, "no such file: " . var_export($path, true) . "\n");
    exit(1);
}
require $path;

$failures = [];
$M = 'OPNsense\IfPppoe\Support';

// --- mergeStatus() -----------------------------------------------------
// $engine below is the shape `engine status --json` really emits
// (Engine::statusReport()); tests/engine/test_integration.php runs the real
// CLI output through mergeStatus() as well.

function engine(array $over = []): array
{
    return array_replace([
        'desired' => 'enabled',
        'hook' => 'applied',
        'hook_detail' => '',
        'latched' => false,
        'latch_clears_on_reboot' => false,
        'boot' => ['desired' => 'enabled', 'result' => 'enabled', 'reason' => 'ok', 'at' => 1000],
        'notices' => [],
        'features_missing' => [],
        'effective' => ['enabled' => true, 'exclude' => [], 'since' => 1000],
        'settings' => ['enabled' => true, 'exclude' => []],
        'ha' => null,
        'config_error' => null,
        'counters' => [],
        'reboot_required' => false,
        'apply_pending' => false,
        'interfaces' => [
            'wan' => [
                'device' => 'pppoe0', 'enabled' => true, 'backend' => 'kernel', 'reason' => 'eligible',
                'registry' => ['state' => 'up', 'session' => 'up', 'v4' => 'up', 'v6' => 'down', 'local' => '100.64.1.2'],
                'session' => ['ipcp' => 'opened'], 'eligible' => true,
            ],
        ],
    ], $over);
}

// 1. Engine absent (not installed / unparseable): degrade cleanly.
$r = $M::mergeStatus('enabled', null);
check($r['engine_available'] === false, 'engine-absent: engine_available false', $failures);
check($r['reboot_required'] === false, 'engine-absent: reboot_required false (nothing to compare against)', $failures);
check($r['latched'] === false, 'engine-absent: not latched', $failures);
check($r['interfaces'] === [], 'engine-absent: no interfaces', $failures);

// 2. Keys are mapped from the engine's real names.
$r = $M::mergeStatus('enabled', engine());
check($r['persisted'] === 'enabled', 'persisted <- desired', $failures);
check($r['hook_status'] === 'applied', 'hook_status <- hook', $failures);
check($r['boot']['result'] === 'enabled' && $r['boot']['desired'] === 'enabled', 'boot passed through', $failures);
check($r['effective'] === 'kernel', 'effective derived from interface backends', $failures);
check(array_is_list($r['interfaces']), 'interfaces map -> list', $failures);
check($r['interfaces'][0]['friendly'] === 'wan', 'friendly <- map key', $failures);
check($r['interfaces'][0]['session'] === 'up, IPv4 100.64.1.2', 'session is a string for the view', $failures);
check($r['advice'] === null, 'all good: no advice', $failures);

// 3. reboot_required / apply_pending are the engine's, never recomputed here.
$r = $M::mergeStatus('enabled', engine(['reboot_required' => true]));
check($r['reboot_required'] === true && $r['advice'] === 'Reboot to apply.', 'engine reboot_required passed through', $failures);
$r = $M::mergeStatus('disabled', engine(['boot' => ['desired' => 'disabled', 'result' => 'disabled']]));
check($r['reboot_required'] === false, 'model/persisted/boot disagreeing alone never sets reboot_required', $failures);
$r = $M::mergeStatus('enabled', engine(['desired' => 'disabled', 'apply_pending' => true]));
check($r['apply_pending'] === true, 'engine apply_pending passed through', $failures);
check($r['advice'] === 'Saved but not applied: click Save and Apply.', 'apply_pending advice', $failures);
$r = $M::mergeStatus('enabled', engine(['desired' => 'disabled', 'settings' => null, 'config_error' => 'cannot read']));
check($r['apply_pending'] === true, 'engine could not read config.xml: model vs persisted fallback', $failures);

// 4. Effective backend disagreeing with desired never asks for a reboot.
$mpd5 = engine()['interfaces'];
$mpd5['wan'] = ['device' => 'pppoe0', 'backend' => 'mpd5', 'reason' => 'excluded'];
$r = $M::mergeStatus('enabled', engine(['interfaces' => $mpd5]));
check($r['reboot_required'] === false && $r['effective'] === 'mpd5', 'effective!=desired alone: no reboot', $failures);
check($r['interfaces'][0]['session'] === '', 'mpd5 session column empty', $failures);

// 5. Latched only from the engine's latch (or boot.result via the engine), not from refused.
$r = $M::mergeStatus('enabled', engine(['hook' => 'reverted', 'latched' => true,
    'boot' => ['desired' => 'enabled', 'result' => 'latched', 'reason' => 'strikes']]));
check($r['latched'] === true, 'latched', $failures);
check(str_starts_with((string)$r['advice'], 'Latched to mpd5'), 'latched advice', $failures);

// 6. refused:<reason>: unsupported, not latched, no reboot.
$r = $M::mergeStatus('enabled', engine(['hook' => 'refused:anchor', 'hook_detail' => 'anchor:configure']));
check($r['latched'] === false, 'refused is not latched', $failures);
check($r['refused'] === 'anchor', 'refused reason', $failures);
check($r['advice'] === 'Unsupported here (anchor); using mpd5. A reboot will not help.', 'refused advice', $failures);
$r = $M::mergeStatus('enabled', engine(['hook' => 'foreign']));
check($r['refused'] === 'foreign', 'foreign counts as refused', $failures);

// 7. paused:core-reinstall: Save and Apply, then reboot.
$r = $M::mergeStatus('enabled', engine(['hook' => 'paused:core-reinstall']));
check($r['paused'] === true, 'paused', $failures);
check($r['advice'] === 'Core was reinstalled: Save and Apply, then reboot to resume kernel mode.', 'paused advice', $failures);
$r = $M::mergeStatus('enabled', engine(['hook' => 'paused:core-reinstall', 'reboot_required' => true]));
check($r['advice'] === 'Reboot to apply.', 'paused and already re-applied: reboot', $failures);

// 7a. reboot_required for an enable with the installed kmod ineligible: this is
// the direction the advice is meant for.
$r = $M::mergeStatus('enabled', engine([
    'reboot_required' => true, 'installed_eligible' => false,
    'installed_reason' => 'installed kernel module is missing features: if_pppoe_ipv6',
]));
check(
    $r['advice'] === 'Rebooting will not enable kernel PPPoE (installed kernel module is missing features: if_pppoe_ipv6); using mpd5.',
    'enable direction: installed-ineligible advice shown',
    $failures
);

// 7b. reboot_required for a disable (hook still applied) with the installed kmod
// reading as ineligible (e.g. a pending kernel update, or a features file the
// engine can't read yet) must still say "Reboot to apply.", not the
// installed-ineligible advice -- that reboot is exactly what turns kernel mode off.
$r = $M::mergeStatus('disabled', engine([
    'desired' => 'disabled', 'reboot_required' => true,
    'installed_eligible' => false, 'installed_reason' => 'installed kernel module is missing features: if_pppoe_ipv6',
]));
check($r['advice'] === 'Reboot to apply.', 'disable direction: installed-ineligible text does not apply', $failures);

// 8. Failed boot and notices.
$r = $M::mergeStatus('enabled', engine(['hook' => 'reverted',
    'boot' => ['desired' => 'enabled', 'result' => 'failed', 'reason' => 'kmod-missing', 'at' => 1],
    'notices' => ['boot-failed' => ['message' => 'kernel PPPoE not armed this boot (kmod-missing); using mpd5', 'at' => 1]]]));
check($r['advice'] === 'Kernel mode was not armed at boot (kmod-missing); using mpd5.', 'failed boot advice', $failures);
check($r['notices'] === [['key' => 'boot-failed', 'message' => 'kernel PPPoE not armed this boot (kmod-missing); using mpd5', 'at' => 1]],
    'notices map -> list', $failures);

// 9. Kernel matrix: kernels -> supported_kernels / running_kernel / installed_kernel / kernel_upgrade.
$r = $M::mergeStatus('enabled', null);
check($r['supported_kernels'] === null && $r['running_kernel'] === null && $r['installed_kernel'] === null
    && $r['kernel_upgrade'] === null, 'engine-absent: kernel keys present and null', $failures);
$r = $M::mergeStatus('enabled', engine());
check($r['supported_kernels'] === null && $r['installed_kernel'] === null, 'engine without kernels (older engine): unknown', $failures);

$bidA = str_repeat('a', 40);
$bidB = str_repeat('b', 40);
$kernels = [
    'supported' => [
        ['version' => '26.1', 'series' => '26.1', 'build_id' => $bidB],
        ['version' => '25.7.10', 'series' => '25.7', 'build_id' => $bidA],
        ['version' => '25.7.2', 'series' => '25.7', 'build_id' => $bidA],
        ['version' => 7, 'series' => '25.7', 'build_id' => $bidA],
    ],
    'running' => ['build_id' => $bidA, 'version' => '25.7.10', 'covered' => true],
    'installed' => ['build_id' => $bidA, 'version' => '25.7.10', 'covered' => true, 'pending_reboot' => false],
    'upgrade' => null,
];
$r = $M::mergeStatus('enabled', engine(['kernels' => $kernels]));
check($r['supported_kernels'] === ['25.7.2', '25.7.10', '26.1'], 'supported_kernels: version strings, natural order, junk dropped', $failures);
check($r['running_kernel'] === ['version' => '25.7.10', 'build_id' => $bidA, 'covered' => true, 'pending_reboot' => false],
    'running_kernel passed through', $failures);
check($r['installed_kernel']['pending_reboot'] === false && $r['advice'] === null, 'installed = running: no advice', $failures);

$k = $kernels;
$k['installed'] = ['build_id' => $bidB, 'version' => '26.1', 'covered' => false, 'pending_reboot' => true];
$r = $M::mergeStatus('enabled', engine(['kernels' => $k]));
check(
    $r['advice'] === 'OPNsense kernel 26.1 installed (pending reboot) is not covered by if-pppoe-kmod yet; after reboot'
        . ' mpd5 is used until an updated if-pppoe-kmod is published (System: Firmware: Updates).',
    'installed kernel not covered: pre-reboot warning',
    $failures
);
$k['installed']['version'] = null;
$r = $M::mergeStatus('enabled', engine(['kernels' => $k]));
check(str_starts_with((string)$r['advice'], 'OPNsense kernel build-id bbbbbbbbbbbb installed'), 'unnamed kernel: build-id prefix', $failures);
$r = $M::mergeStatus('disabled', engine(['desired' => 'disabled', 'kernels' => $k]));
check($r['advice'] === null, 'disabled: no kernel coverage warning', $failures);
$r = $M::mergeStatus('enabled', engine(['kernels' => $k, 'reboot_required' => true, 'installed_eligible' => false,
    'installed_reason' => 'the installed kernel 26.1 (pending reboot) is not covered by the installed kernel module']));
check(str_starts_with((string)$r['advice'], 'Rebooting will not enable kernel PPPoE (the installed kernel 26.1'),
    'reboot_required branch keeps precedence', $failures);

$k = $kernels;
$k['upgrade'] = ['version' => '26.7', 'covered' => null];
$r = $M::mergeStatus('enabled', engine(['kernels' => $k]));
check($r['kernel_upgrade'] === ['version' => '26.7', 'covered' => null], 'kernel_upgrade: unknown stays null', $failures);
$k['upgrade'] = ['version' => '26.7', 'covered' => 'yes'];
$r = $M::mergeStatus('enabled', engine(['kernels' => $k]));
check($r['kernel_upgrade']['covered'] === null, 'kernel_upgrade: non-bool covered -> null', $failures);

// --- standaloneViolation() ----------------------------------------------

function xml(string $body): SimpleXMLElement
{
    return new SimpleXMLElement('<opnsense>' . $body . '</opnsense>');
}

check(
    $M::standaloneViolation(xml('')) === null,
    'no virtualip/hasync at all: no violation',
    $failures
);

check(
    $M::standaloneViolation(xml('<virtualip><vip><mode>ipalias</mode></vip></virtualip>')) === null,
    'non-CARP VIP: no violation',
    $failures
);

$reason = $M::standaloneViolation(xml('<virtualip><vip><mode>carp</mode></vip></virtualip>'));
check(is_string($reason) && stripos($reason, 'carp') !== false, 'CARP VIP: refused', $failures);

$reason = $M::standaloneViolation(xml('<hasync><pfsyncpeerip>203.0.113.1</pfsyncpeerip></hasync>'));
check(is_string($reason) && stripos($reason, 'hasync') !== false, 'hasync pfsyncpeerip: refused', $failures);

$reason = $M::standaloneViolation(xml('<hasync><pfsyncinterface>igb1</pfsyncinterface></hasync>'));
check(is_string($reason) && stripos($reason, 'hasync') !== false, 'hasync pfsyncinterface: refused', $failures);

// The gap this finding was about: synchronizetoip (XMLRPC config sync) alone,
// with no pfsync peer/interface set, must still be refused.
$reason = $M::standaloneViolation(xml('<hasync><synchronizetoip>203.0.113.2</synchronizetoip></hasync>'));
check(is_string($reason) && stripos($reason, 'hasync') !== false, 'hasync synchronizetoip alone: refused', $failures);

if (!empty($failures)) {
    fwrite(STDERR, "\n" . count($failures) . " failure(s):\n - " . implode("\n - ", $failures) . "\n");
    exit(1);
}
echo "ALL OK\n";
exit(0);
