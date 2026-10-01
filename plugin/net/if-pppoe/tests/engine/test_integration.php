<?php

/*
 * Cross-component contracts: the engine's real output against the GUI's consumers,
 * and the paths/names that more than one component has to agree on.
 */

namespace IfPppoe\Test;

use IfPppoe\Engine\Config;
use IfPppoe\Engine\Engine;
use IfPppoe\Engine\Env;
use IfPppoe\Engine\Lock;
use OPNsense\IfPppoe\Support;

const PLUGIN_SRC = __DIR__ . '/../../src';
const MVC = PLUGIN_SRC . '/opnsense/mvc/app';

require_once MVC . '/library/OPNsense/IfPppoe/Support.php';
require_once __DIR__ . '/stubs/opnsense_status.php';
require_once MVC . '/library/OPNsense/System/Status/IfPppoeStatus.php';

/** real `engine status --json` through Support::mergeStatus() */
function uiStatus(Sandbox $s, string $model = 'enabled'): array
{
    T::eq(0, $s->cli(['status', '--json'], $out), $out);
    $engine = json_decode($out, true);
    T::ok(is_array($engine), $out);
    return Support::mergeStatus($model, $engine);
}

function actions(): array
{
    $sections = [];
    $cur = null;
    foreach (file(PLUGIN_SRC . '/opnsense/service/conf/actions.d/actions_if-pppoe.conf', FILE_IGNORE_NEW_LINES) as $l) {
        if (preg_match('/^\[([a-z0-9_.-]+)\]$/', trim($l), $m)) {
            $cur = $m[1];
        } elseif ($cur !== null && str_contains($l, ':') && !str_starts_with(trim($l), ';')) {
            [$k, $v] = explode(':', $l, 2);
            $sections[$cur][trim($k)] = trim($v);
        }
    }
    return $sections;
}

/* ------------------------------------------------------------ B1 config path */

T::test('contract: the model mount is the config.xml path the engine reads', function () {
    $model = simplexml_load_file(MVC . '/models/OPNsense/IfPppoe/IfPppoe.xml');
    $mount = trim((string)$model->mount);
    T::eq('//OPNsense/IfPppoe', $mount, 'mount');
    /* build <opnsense><OPNsense><IfPppoe><general> from the mount, as BaseModel would */
    $xml = '<general><enabled>1</enabled><exclude>opt1,wan</exclude></general>';
    foreach (array_reverse(explode('/', trim($mount, '/'))) as $el) {
        $xml = "<{$el}>{$xml}</{$el}>";
    }
    $cfg = Config::fromString("<?xml version=\"1.0\"?><opnsense>{$xml}</opnsense>");
    T::eq(['enabled' => true, 'exclude' => ['opt1', 'wan']], $cfg->pluginSettings());
    foreach (glob(__DIR__ . '/fixtures/config-*.xml') as $f) {
        T::ok(Config::fromFile($f)->pluginSettings()['enabled'], basename($f) . ' uses the mount path');
    }
});

/* ------------------------------------------------------------ B2 status schema */

T::test('contract: engine status --json through Support::mergeStatus (kernel WAN up, mpd5 WAN)', function () {
    $s = new Sandbox('config-multi.xml');
    $e = $s->engine();
    T::eq(0, $e->configure('wan', 'pppoe0', 'igb1', '1492', ''));
    $e->linkevent('pppoe0', 'SESSION_UP', []);
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=100.64.0.1']);
    $e->linkevent('pppoe0', 'IPV6CP_UP', ['local=0x0211223344556677', 'remote=0x02aabbccddeeff00']);
    $s->write('/var/run/pppoe_opt1.pid', "alive\n");
    $s->write('/var/run/if_pppoe/boot.json', json_encode(['desired' => 'enabled', 'result' => 'enabled', 'reason' => 'ok', 'at' => time()]));
    $r = uiStatus($s);
    T::eq(true, $r['engine_available']);
    T::eq('enabled', $r['persisted']);
    T::eq('applied', $r['hook_status']);
    T::eq('mixed', $r['effective']);
    T::eq(['result' => 'enabled', 'reason' => 'ok', 'desired' => 'enabled'], array_diff_key($r['boot'], ['at' => 1]));
    T::eq(false, $r['latched']);
    T::eq(false, $r['reboot_required']);
    T::eq(false, $r['apply_pending']);
    T::eq(null, $r['advice']);
    T::ok(array_is_list($r['interfaces']), 'interfaces is a list for the view');
    $by = array_column($r['interfaces'], null, 'friendly');
    T::ok(isset($by['wan'], $by['opt1'], $by['opt2']), 'friendly = engine map key');
    T::eq('kernel', $by['wan']['backend']);
    T::eq('pppoe0', $by['wan']['device']);
    T::eq('up, IPv4 100.64.1.2, IPv6', $by['wan']['session']);
    T::eq('mpd5', $by['opt1']['backend']);
    T::eq('', $by['opt1']['session']);
    T::contains('dial-on-demand', $by['opt2']['reason']);
    foreach ($r['interfaces'] as $i) {
        T::ok(is_string($i['session']) && is_string($i['friendly']) && $i['friendly'] !== '', json_encode($i));
    }
});

T::test('contract: reboot_required/apply_pending come from the engine, not the model', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $r = uiStatus($s, 'enabled');
    T::ok($r['reboot_required'], 'enabled, hook not applied yet');
    T::eq('Reboot to apply.', $r['advice']);
    /* saved enabled in the model but Apply not clicked: the engine says apply_pending */
    $s->write('/conf/if_pppoe/desired', "disabled\n");
    $r = uiStatus($s, 'enabled');
    T::ok($r['apply_pending']);
    T::ok(!$r['reboot_required']);
    T::eq('Saved but not applied: click Save and Apply.', $r['advice']);
});

T::test('contract: a kmod upgrade with no reboot yet forces reboot_required, even with a matching exclude list', function () {
    $s = new Sandbox();
    $r = uiStatus($s);
    T::ok(!$r['reboot_required'], 'sanity: nothing pending yet');
    $s->recordLoadedKmod(); /* matches: no upgrade pending */
    T::ok(!uiStatus($s)['reboot_required']);
    $s->recordLoadedKmod(Sandbox::BUILD_ID, 'not-the-real-sha256'); /* installed .ko changed since load */
    $r = uiStatus($s);
    T::ok($r['reboot_required'], 'installed kmod no longer matches what is loaded');
    T::eq('Reboot to apply.', $r['advice']);
});

T::test('contract: reboot required but the installed kmod would not work after all: advice does not just say "reboot to apply"', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $s->installedFeatures(['if_pppoe_ipv6']);
    $r = uiStatus($s, 'enabled');
    T::ok($r['reboot_required']);
    T::eq(false, $r['installed_eligible']);
    T::contains('installed kernel module is missing features', $r['installed_reason']);
    T::contains('Rebooting will not enable kernel PPPoE', $r['advice']);
});

T::test('contract: refused hook is shown as unsupported, never as latched or reboot', function () {
    $s = new Sandbox();
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'refused:ha', 'detail' => 'hasync-pfsyncpeerip']));
    $r = uiStatus($s);
    T::eq(false, $r['latched']);
    T::eq('ha', $r['refused']);
    T::eq('hasync-pfsyncpeerip', $r['hook_detail']);
    T::eq(false, $r['reboot_required']);
    T::eq('Unsupported here (ha); using mpd5. A reboot will not help.', $r['advice']);
});

T::test('contract: paused:core-reinstall asks for Save and Apply, then reboot', function () {
    $s = new Sandbox();
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'paused:core-reinstall', 'paused_at' => time() + 100]));
    $r = uiStatus($s);
    T::ok($r['paused']);
    T::eq(false, $r['reboot_required'], 'desired older than the pause: a reboot stays paused');
    T::eq('Core was reinstalled: Save and Apply, then reboot to resume kernel mode.', $r['advice']);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'paused:core-reinstall', 'paused_at' => time() - 100]));
    $r = uiStatus($s);
    T::eq(true, $r['reboot_required'], 'desired rewritten after the pause: the next boot re-applies');
    T::eq('Reboot to apply.', $r['advice']);
});

T::test('contract: latch, and a latch that the next boot clears', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $s->write('/conf/if_pppoe/latch', "1\n");
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    $s->write('/var/run/if_pppoe/boot.json', json_encode(['desired' => 'enabled', 'result' => 'latched', 'reason' => 'strikes', 'at' => time()]));
    $r = uiStatus($s);
    T::ok($r['latched']);
    T::ok(!$r['reboot_required']);
    T::contains('Latched to mpd5', (string)$r['advice']);
    /* Save and Apply rewrites desired: early/50 drops the latch on the next boot */
    touch($s->root . '/conf/if_pppoe/latch', time() - 50);
    touch($s->root . '/conf/if_pppoe/desired', time());
    $r = uiStatus($s);
    T::ok(!$r['latched']);
    T::ok($r['reboot_required']);
});

T::test('contract: a boot that failed with the same desired state does not ask for a reboot when the installed kmod is still not eligible', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $s->noInstalledBuildIds(); /* still no kmod covers this kernel: a reboot really would not help */
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    $s->write('/var/run/if_pppoe/boot.json', json_encode(['desired' => 'enabled', 'result' => 'failed', 'reason' => 'kernel-not-supported', 'at' => time() - 10]));
    $s->write('/var/run/if_pppoe/notice.d/boot-failed', "kernel PPPoE not armed this boot (kernel-not-supported); using mpd5\n");
    $r = uiStatus($s);
    T::eq(false, $r['installed_eligible']);
    T::ok(!$r['reboot_required']);
    T::eq('Kernel mode was not armed at boot (kernel-not-supported); using mpd5.', $r['advice']);
    T::eq([['key' => 'boot-failed', 'message' => 'kernel PPPoE not armed this boot (kernel-not-supported); using mpd5']],
        array_map(fn($n) => array_diff_key($n, ['at' => 1]), $r['notices']));
    touch($s->root . '/conf/if_pppoe/desired', time());
    T::ok(uiStatus($s)['reboot_required'], 're-applied after the failed boot');
});

T::test('contract: packages left on the old ABI by a major upgrade: reinstall advice, then the reboot once reinstalled', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    /* booted the 26.7 (FreeBSD:15) kernel with the FreeBSD:14 if-pppoe-kmod: no .ko for it */
    $s->sysctl('kern.build_id', Sandbox::NEW_BUILD_ID);
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:14:amd64');
    $s->bootFailed('kmod-abi-mismatch');
    $r = uiStatus($s);
    T::eq(['package' => 'if-pppoe-kmod', 'installed' => 'FreeBSD:14:amd64', 'system' => 'FreeBSD:15:amd64'], $r['package_abi']);
    T::eq(false, $r['installed_eligible']);
    T::contains('installed if-pppoe-kmod is built for FreeBSD:14:amd64 but this system is FreeBSD:15:amd64', $r['installed_reason']);
    T::ok(!$r['reboot_required'], 'the same packages would fail the same way');
    T::eq('Installed if-pppoe-kmod is built for FreeBSD:14:amd64 but this system is FreeBSD:15:amd64; reinstall it'
        . ' (System: Firmware: Packages, reinstall if-pppoe-kmod and os-if-pppoe, or'
        . ' pkg install -f -r IfPppoe if-pppoe-kmod os-if-pppoe), then reboot.', $r['advice']);
    /* abi-heal.sh reinstalled the FreeBSD:15 builds: new build_ids and a .ko for this kernel */
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:15:amd64');
    $s->installKoFor(Sandbox::NEW_BUILD_ID);
    $r = uiStatus($s);
    T::eq(null, $r['package_abi']);
    T::eq(true, $r['installed_eligible'], $r['installed_reason']);
    T::ok($r['reboot_required'], 'reinstalled since the failed boot: offer the reboot');
    T::eq('Reboot to apply.', $r['advice']);
});

T::test('contract: an os-if-pppoe-only ABI mismatch is advised too', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:15:amd64', 'FreeBSD:14:amd64');
    $r = uiStatus($s);
    T::eq('os-if-pppoe', $r['package_abi']['package'] ?? null);
    T::contains('Installed os-if-pppoe is built for FreeBSD:14:amd64', (string)$r['advice']);
});

T::test('contract: a boot that failed on the kmod, then a fixed if-pppoe-kmod installed, asks for a reboot', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    /* at the failed boot the installed build_ids did not cover this kernel ... */
    $s->noInstalledBuildIds();
    $s->bootFailed('kernel-not-supported');
    T::ok(!uiStatus($s)['reboot_required'], 'sanity: nothing installed yet');
    /* ... then the admin installs a fixed if-pppoe-kmod, without touching desired or rebooting */
    $s->write('/usr/local/share/if_pppoe/build_ids', Sandbox::BUILD_ID . "\n");
    $r = uiStatus($s);
    T::eq(true, $r['installed_eligible']);
    T::ok($r['reboot_required'], 'installed kmod now covers this kernel: offer the reboot again');
    T::eq('Reboot to apply.', $r['advice']);
});

T::test('contract: same upgrade against an older boot.json with no kmod identity falls back to mtimes', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    $s->bootFailed('kernel-not-supported', false);
    T::ok(!uiStatus($s)['reboot_required'], 'files all older than the boot: nothing installed since');
    touch($s->root . '/usr/local/share/if_pppoe/build_ids', time());
    T::ok(uiStatus($s)['reboot_required'], 'build_ids newer than the failed boot');
});

T::test('contract: a kldload failure with an unchanged package does not ask for a reboot', function () {
    foreach ([true, false] as $identity) {
        $s = new Sandbox('config-base.xml', false);
        $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
        touch($s->root . '/conf/if_pppoe/desired', time() - 100);
        $s->bootFailed('kldload', $identity);
        $r = uiStatus($s);
        T::eq(true, $r['installed_eligible'], 'eligibility cannot see a kldload rejection');
        T::ok(!$r['reboot_required'], 'same .ko would be rejected again' . ($identity ? '' : ' (mtime fallback)'));
        T::eq('Kernel mode was not armed at boot (kldload); using mpd5.', $r['advice']);
        /* a build_ids/features-only change is not a new .ko */
        $s->write('/usr/local/share/if_pppoe/features', implode("\n", Env::REQUIRED_FEATURES) . "\n\n");
        T::ok(!uiStatus($s)['reboot_required'], 'features file change alone does not lift kldload');
        $s->installKo();
        T::ok(uiStatus($s)['reboot_required'], 'a different .ko was installed since');
    }
});

T::test('contract: a feature-X failure with no features file and an unchanged package does not ask for a reboot', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    $s->noInstalledFeaturesFile(); /* an older if-pppoe-kmod predating the features file */
    $s->bootFailed('feature-linkevents');
    $r = uiStatus($s);
    T::eq(true, $r['installed_eligible'], 'no features file reads as unknown, not ineligible');
    T::ok(!$r['reboot_required'], 'the same old kmod would miss the same feature again');
    /* even a new .ko cannot be shown to have the feature without a features file */
    $s->installKo();
    T::ok(!uiStatus($s)['reboot_required'], 'new .ko but no features file listing the feature');
    $s->installedFeatures(Env::REQUIRED_FEATURES);
    T::ok(uiStatus($s)['reboot_required'], 'new .ko whose features file lists if_pppoe_linkevents');
});

T::test('contract: a feature-X failure whose features file lists X but the .ko is unchanged does not ask for a reboot', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    /* features file overstates the .ko (grep-derived, e.g. #ifdef INET6) */
    $s->bootFailed('feature-ipv6');
    $r = uiStatus($s);
    T::eq(true, $r['installed_eligible']);
    T::ok(!$r['reboot_required'], 'the listed feature is not what the unchanged .ko exposes');
    $s->installedFeatures(array_values(array_diff(Env::REQUIRED_FEATURES, ['if_pppoe_ipv6'])));
    $s->installKo();
    T::ok(!uiStatus($s)['reboot_required'], 'installed_eligible false once the file drops the feature');
});

T::test('contract: a boot that failed on the interfaces.inc hook does not ask for a reboot even when the kmod is eligible', function () {
    $s = new Sandbox('config-base.xml', false);
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'reverted']));
    touch($s->root . '/conf/if_pppoe/desired', time() - 100);
    $s->write('/var/run/if_pppoe/boot.json', json_encode(['desired' => 'enabled', 'result' => 'failed', 'reason' => 'hook', 'at' => time() - 10]));
    $r = uiStatus($s);
    T::eq(true, $r['installed_eligible']);
    T::ok(!$r['reboot_required'], 'a kmod fix cannot help a hook-apply failure');
    T::eq('Kernel mode was not armed at boot (hook); using mpd5.', $r['advice']);
});

T::test('contract: Support degrades when the engine is missing', function () {
    $r = Support::mergeStatus('enabled', null);
    T::eq(false, $r['engine_available']);
    T::eq(false, $r['reboot_required']);
    T::eq([], $r['interfaces']);
    T::eq(null, $r['advice']);
});

/* ------------------------------------------------------------ B3 boot + notices */

T::test('engine: status and notices report boot.json and notice.d, printable only', function () {
    $s = new Sandbox();
    $s->write('/var/run/if_pppoe/boot.json', json_encode(['desired' => 'enabled', 'result' => 'failed', 'reason' => 'feature-mssfix', 'at' => 1000]));
    $s->write('/var/run/if_pppoe/notice.d/update-fallback', "hook not re-applied\x1b[31m (refused:anchor)\n");
    $s->write('/var/run/if_pppoe/notice.d/.hidden', 'x');
    $s->write('/var/run/if_pppoe/notice.d/BAD KEY', 'x');
    T::eq(0, $s->cli(['notices', '--json'], $out), $out);
    $n = json_decode($out, true);
    T::eq(['desired' => 'enabled', 'result' => 'failed', 'reason' => 'feature-mssfix', 'at' => 1000], $n['boot']);
    T::eq(['update-fallback'], array_keys($n['notices']));
    T::eq('hook not re-applied [31m (refused:anchor)', $n['notices']['update-fallback']['message']);
    $r = $s->engine()->statusReport();
    T::eq($n['boot'], $r['boot']);
    T::eq($n['notices'], $r['notices']);
    $s2 = new Sandbox();
    T::eq(['boot' => null, 'notices' => []], $s2->engine()->notices());
});

T::test('IfPppoeStatus: real engine notices -> System Status entry', function () {
    $s = new Sandbox();
    $cls = '\\OPNsense\\System\\Status\\IfPppoeStatus';
    \OPNsense\Core\Backend::$calls = [];

    $s->cli(['notices', '--json'], $out);
    \OPNsense\Core\Backend::$reply = $out;
    $st = new $cls();
    $st->collectStatus();
    T::eq(\OPNsense\System\SystemStatusCode::OK, $st->getStatus(), 'no notices: OK (core then omits it)');
    T::eq(['if-pppoe notices'], \OPNsense\Core\Backend::$calls);

    $s->write('/var/run/if_pppoe/notice.d/boot-latched', "kernel PPPoE disabled after 3 unclean boots within 24h\n");
    touch($s->root . '/var/run/if_pppoe/notice.d/boot-latched', 1234);
    $s->cli(['notices', '--json'], $out);
    \OPNsense\Core\Backend::$reply = $out;
    $st = new $cls();
    $st->collectStatus();
    T::eq(\OPNsense\System\SystemStatusCode::WARNING, $st->getStatus());
    T::eq('kernel PPPoE disabled after 3 unclean boots within 24h', $st->getMessage());
    T::eq(1234, $st->getTimestamp());
    T::eq('/ui/ifpppoe/settings', $st->getLocation());

    $s->write('/var/run/if_pppoe/notice.d/boot-revert', "could not remove the interfaces.inc hook\n");
    $s->cli(['notices', '--json'], $out);
    \OPNsense\Core\Backend::$reply = $out;
    $st = new $cls();
    $st->collectStatus();
    T::eq(\OPNsense\System\SystemStatusCode::ERROR, $st->getStatus());

    \OPNsense\Core\Backend::$reply = 'Execute error';
    $st = new $cls();
    $st->collectStatus();
    T::eq(\OPNsense\System\SystemStatusCode::OK, $st->getStatus(), 'configd failure is not a notice');
});

T::test('IfPppoeStatus: the configd action it calls exists and runs the engine', function () {
    $a = actions();
    T::eq('/usr/local/opnsense/scripts/if_pppoe/engine', $a['notices']['command']);
    T::eq('notices --json', $a['notices']['parameters']);
    T::eq('script_output', $a['notices']['type']);
    /* core's SystemStatus collects every Status/*Status.php subclass of AbstractStatus */
    T::ok(is_subclass_of('\\OPNsense\\System\\Status\\IfPppoeStatus', '\\OPNsense\\System\\AbstractStatus'));
});

/* ------------------------------------------------------------ F1 pkg trigger */

T::test('contract: pkg trigger path is the directory holding interfaces.inc', function () {
    $ucl = file_get_contents(PLUGIN_SRC . '/share/pkg/triggers/if_pppoe.ucl');
    T::ok(preg_match('/^path:\s*\[\s*"([^"]+)"\s*\]/m', $ucl, $m) === 1, 'one path entry');
    /* pkg compares trigger paths with the dirname of each touched file (libpkg/triggers.c) */
    T::eq(dirname((new Env(''))->interfacesInc()), $m[1]);
    T::eq('/usr/local/etc/inc', $m[1]);
    T::contains('/usr/local/opnsense/scripts/if_pppoe/reapply.sh", "trigger"', $ucl);
});

/* ------------------------------------------------------------ F2 cron */

T::test('contract: cron schedules hook reapply every 5 minutes, engine reconcile every minute, abiheal every 15', function () {
    if (!function_exists('if_pppoe_cron')) {
        require PLUGIN_SRC . '/etc/inc/plugins.inc.d/if_pppoe.inc';
    }
    $jobs = [];
    foreach (\if_pppoe_cron() as $j) {
        $jobs[$j['autocron'][0]] = array_slice($j['autocron'], 1);
    }
    T::eq([
        '/usr/local/sbin/configctl -d if-pppoe reapply' => ['*/5'],
        '/usr/local/sbin/configctl -d if-pppoe reconcile' => ['*'],
        '/usr/local/sbin/configctl -d if-pppoe abiheal cron' => ['*/15'],
    ], $jobs);
    $a = actions();
    T::eq('/bin/sh /usr/local/opnsense/scripts/if_pppoe/reapply.sh', $a['reapply']['command']);
    T::eq('cron', $a['reapply']['parameters']);
    T::eq('/usr/local/opnsense/scripts/if_pppoe/engine', $a['reconcile']['command']);
    T::eq('reconcile', $a['reconcile']['parameters']);
    T::eq('/bin/sh /usr/local/opnsense/scripts/if_pppoe/abi-heal.sh', $a['abiheal']['command']);
    T::eq('%s', $a['abiheal']['parameters']);
    /* the update syshook and the pkg trigger name the same action and mode */
    foreach (['/etc/rc.syshook.d/update/05-if-pppoe', '/share/pkg/triggers/if_pppoe.ucl'] as $f) {
        T::ok(preg_match('/configctl.*-d.*if-pppoe.*abiheal.*deferred/i', (string)file_get_contents(PLUGIN_SRC . $f)) === 1, "$f defers abiheal");
    }
    foreach (['reapply.sh', 'engine', 'abi-heal.sh'] as $f) {
        T::ok(is_file(PLUGIN_SRC . '/opnsense/scripts/if_pppoe/' . $f), "$f shipped");
    }
});

/* ------------------------------------------------------------ F3 after-firmware */

T::test('reconcile --after-firmware: waits for a running reconcile, fails if it cannot hand back', function () {
    $s = new Sandbox();
    $s->engine()->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->write('/conf/if_pppoe/hook.json', json_encode(['status' => 'refused:anchor']));
    $held = Lock::acquire($s->env(), 'pppoe0', 1.0);
    $t = microtime(true);
    T::eq(Engine::EXIT_FAILED, $s->engine()->reconcile(true), 'device busy -> non-zero so reapply.sh falls back');
    $held->release();
    T::ok($s->registry('pppoe0') !== null);
    T::eq(Engine::EXIT_CLAIMED, $s->engine()->reconcile(true));
    T::eq(null, $s->registry('pppoe0'));
    T::ok(microtime(true) - $t < 60);
    T::eq(0, $s->engine()->reconcile(), 'plain cron reconcile still exits 0');
});

/* ------------------------------------------------------------ M2 0.0.0.0 */

T::test('linkevent: 0.0.0.0 from the kmod is never passed to core as an address or DNS server', function () {
    T::eq('', Engine::ipv4('0.0.0.0'));
    T::eq('', Engine::ipv4('0.0.0.0/32'));
    T::eq('1.0.0.0', Engine::ipv4('1.0.0.0'));
    $s = new Sandbox();
    $e = $s->engine();
    $e->configure('wan', 'pppoe0', 'igb1', '1492', '');
    $s->clearCalls();
    $e->linkevent('pppoe0', 'IPCP_UP', ['local=100.64.1.2', 'remote=0.0.0.0', 'dns1=0.0.0.0', 'dns2=0.0.0.0']);
    T::eq([['ppp-linkup.sh', 'pppoe0', 'inet', '100.64.1.2/32', '', '-', '', '', '-', '-']], cmds($s, 'ppp-linkup.sh'));
});

/* ------------------------------------------------------------ M5 timeout path */

T::test('contract: the engine and the hook line use the same timeout(1)', function () {
    T::eq('/bin/timeout', (new Env(''))->bin('timeout'));
    T::contains("mwexecf('/bin/timeout -k 5 45 ", file_get_contents(PLUGIN_SRC . '/opnsense/scripts/if_pppoe/hookctl.php'));
    T::contains('IF_PPPOE_TIMEOUT:=/bin/timeout', file_get_contents(PLUGIN_SRC . '/opnsense/scripts/if_pppoe/lib.sh'));
});

/* ------------------------------------------------------------ M1 HA fields */

T::test('contract: engine, GUI and hookctl refuse on the same hasync fields', function () {
    $fields = ['pfsyncinterface', 'synchronizetoip', 'pfsyncpeerip'];
    $hookctl = file_get_contents(PLUGIN_SRC . '/opnsense/scripts/if_pppoe/hookctl.php');
    foreach ($fields as $f) {
        $cfg = Config::fromString("<opnsense><hasync><{$f}>x</{$f}></hasync></opnsense>");
        T::ok($cfg->haReason() !== null, "engine: $f");
        T::ok(Support::standaloneViolation(new \SimpleXMLElement("<opnsense><hasync><{$f}>x</{$f}></hasync></opnsense>")) !== null, "GUI: $f");
        T::contains("'{$f}'", $hookctl, "hookctl: $f");
    }
});

/* ------------------------------------------------ kernel matrix on the Services page */

T::test('contract: supported/running/installed kernels reach the Services page payload', function () {
    $s = new Sandbox();
    $s->kernelsJson([
        ['series' => '26.1', 'version' => '26.1.3', 'build_id' => Sandbox::NEW_BUILD_ID],
        ['series' => '25.7', 'version' => '25.7.10', 'build_id' => 'aa' . Sandbox::NEW_BUILD_ID],
        ['series' => '25.7', 'version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID],
    ]);
    $r = uiStatus($s);
    T::eq(['25.7.8', '25.7.10', '26.1.3'], $r['supported_kernels'], 'natural version order');
    T::eq(['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID, 'covered' => true, 'pending_reboot' => false], $r['running_kernel']);
    T::eq(false, $r['installed_kernel']['pending_reboot']);
    T::eq(null, $r['kernel_upgrade']);
    T::eq(null, $r['advice']);
});

T::test('contract: an installed OPNsense kernel update the kmod does not cover warns before the reboot', function () {
    $s = new Sandbox();
    $s->kernelsJson([['version' => '25.7.8', 'build_id' => Sandbox::BUILD_ID], ['version' => '25.7.10', 'build_id' => Sandbox::NEW_BUILD_ID]]);
    /* listed in kernels.json but its .ko is not installed: build_ids decides, not the list */
    $s->installedKernel(Sandbox::NEW_BUILD_ID);
    $r = uiStatus($s);
    T::eq(['version' => '25.7.10', 'build_id' => Sandbox::NEW_BUILD_ID, 'covered' => false, 'pending_reboot' => true], $r['installed_kernel']);
    T::ok(!$r['reboot_required'], 'hook applied, nothing else pending');
    T::eq('OPNsense kernel 25.7.10 installed (pending reboot) is not covered by if-pppoe-kmod yet; after reboot'
        . ' mpd5 is used until an updated if-pppoe-kmod is published (System: Firmware: Updates).', $r['advice']);
    $s->installKoFor(Sandbox::NEW_BUILD_ID);
    T::eq(null, uiStatus($s)['advice'], 'covered now: no warning');
});

T::test('contract: an older kmod without kernels.json shows supported kernels as unknown', function () {
    $s = new Sandbox();
    $s->noKernelsJson();
    $r = uiStatus($s);
    T::eq(null, $r['supported_kernels']);
    T::eq(true, $r['running_kernel']['covered']);
    T::eq(null, $r['advice']);
});

T::test('Kernel::packageAbiMismatch: no pkg, matching, wildcard and mismatched ABIs', function () {
    $s = new Sandbox();
    $k = fn() => new \IfPppoe\Engine\Kernel($s->env(), new \IfPppoe\Engine\Proc());
    T::eq(null, $k()->packageAbiMismatch(), 'pkg unavailable');
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:15:amd64');
    T::eq(null, $k()->packageAbiMismatch(), 'same ABI');
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:15:amd64', 'FreeBSD:15:*');
    T::eq(null, $k()->packageAbiMismatch(), 'arch-independent package');
    $s->packageAbi('FreeBSD:15:amd64', 'FreeBSD:14:amd64');
    T::eq(['package' => 'if-pppoe-kmod', 'installed' => 'FreeBSD:14:amd64', 'system' => 'FreeBSD:15:amd64'], $k()->packageAbiMismatch());
    $s->packageAbi('FreeBSD:15:amd64', 'Free BSD;rm');
    T::eq(null, $k()->packageAbiMismatch(), 'unparseable %q is ignored');
    $s->fakeJson('pkg.json', ['abi' => 'FreeBSD:15:amd64', 'installed' => []]);
    T::eq(null, $k()->packageAbiMismatch(), 'packages not installed');
});
