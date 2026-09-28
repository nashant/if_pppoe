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

namespace OPNsense\IfPppoe\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\IfPppoe\IfPppoe;
use OPNsense\IfPppoe\Support;

/**
 * Reboot-to-apply: reconfigure only persists /conf/if_pppoe/desired via configd
 * (the web process can't write under /conf); rc.syshook.d/early/50-if-pppoe
 * reads it at next boot. Reboot itself is a passthrough to core's own action.
 * @package OPNsense\IfPppoe
 */
class ServiceController extends ApiControllerBase
{
    /** Combined status: saved model vs. persisted desired vs. effective backend vs.
     *  last boot result. The merge itself is Support::mergeStatus() (pure, so it's
     *  unit-tested without a live box; see tests/plugin/p4-ui/test_support_lib.php). */
    public function statusAction()
    {
        $mdl = new IfPppoe();
        $desiredModel = (string)$mdl->general->enabled == '1' ? 'enabled' : 'disabled';

        $backend = new Backend();
        $raw = trim((string)$backend->configdRun('if-pppoe status'));
        $engine = json_decode($raw, true);
        if (!is_array($engine)) {
            // engine not installed yet, refused, or returned something we can't parse.
            $engine = null;
        }

        return Support::mergeStatus($desiredModel, $engine);
    }

    /** Persists desired state; only ever sends the literal 'enabled'/'disabled' to configd. */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }

        $mdl = new IfPppoe();
        $desired = (string)$mdl->general->enabled == '1' ? 'enabled' : 'disabled';

        if ($desired === 'enabled') {
            // Defense in depth only: IfPppoe::performValidation() is the primary gate,
            // run at Save time. This can still fire on a race (config.xml changed
            // between Save and this separate configd round-trip).
            $reason = Support::standaloneViolation(Config::getInstance()->object());
            if ($reason !== null) {
                return ['status' => 'failed', 'message' => gettext($reason)];
            }
        }

        $backend = new Backend();
        $raw = trim((string)$backend->configdpRun('if-pppoe reconfigure', [$desired]));
        $result = json_decode($raw, true);
        if (!is_array($result) || empty($result['result']) || $result['result'] !== 'ok') {
            return ['status' => 'failed', 'message' => $raw];
        }

        // reboot_required comes from statusAction() (the engine), never from here
        return ['status' => 'ok', 'desired' => $desired];
    }
}
