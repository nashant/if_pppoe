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

namespace OPNsense\System\Status;

use OPNsense\Core\Backend;
use OPNsense\System\AbstractStatus;
use OPNsense\System\SystemStatusCode;

/**
 * Surfaces the syshooks' notices (boot gate failed or latched, hook revert
 * failed, fallback to mpd5 after a core update) in System > Status and the
 * dashboard. Core picks this class up by globbing Status/*.php
 * (OPNsense\System\SystemStatus::collectClasses()).
 *
 * Read through configd (`if-pppoe notices` = `engine notices --json`), like
 * core's DiskSpaceStatus: /var/run/if_pppoe is root-only and the web GUI may
 * run as wwwonly (webgui.inc, system.webgui.noroot).
 */
class IfPppoeStatus extends AbstractStatus
{
    /* notice.d keys (lib.sh ifp_notice callers) that mean the hook state is unknown */
    private const ERROR_KEYS = ['boot-revert'];

    public function __construct()
    {
        $this->internalPriority = 50;
        /* the notices describe live state; the syshooks clear them, not the user */
        $this->internalPersistent = true;
        $this->internalTitle = gettext('Kernel PPPoE');
        $this->internalLocation = '/ui/ifpppoe/settings';
    }

    public function collectStatus()
    {
        $data = json_decode((string)(new Backend())->configdRun('if-pppoe notices'), true);
        $notices = is_array($data) && is_array($data['notices'] ?? null) ? $data['notices'] : [];
        $messages = [];
        foreach ($notices as $key => $n) {
            if (!is_array($n) || !is_string($n['message'] ?? null) || $n['message'] === '') {
                continue;
            }
            $messages[] = $n['message'];
            if (is_int($n['at'] ?? null) && $n['at'] > (int)$this->internalTimestamp) {
                $this->internalTimestamp = $n['at'];
            }
            if (in_array((string)$key, self::ERROR_KEYS, true)) {
                $this->internalStatus = SystemStatusCode::ERROR;
            } elseif ($this->internalStatus !== SystemStatusCode::ERROR) {
                $this->internalStatus = SystemStatusCode::WARNING;
            }
        }
        if ($messages !== []) {
            /* engine notices() already reduced these to printable ASCII */
            $this->internalMessage = implode(' ', $messages);
        }
    }
}
