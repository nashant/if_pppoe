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

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Config;

/**
 * @package OPNsense\IfPppoe
 */
class IfPppoe extends BaseModel
{
    /**
     * Primary gate for the standalone-only (no CARP/HA) rule: Save itself
     * must fail with a field error, not just Api\ServiceController's later,
     * separate configd round-trip -- that left enabled=1 saved to
     * config.xml with nothing to fix it short of unticking and saving again
     * (see review: reboot_required and _cron/_services then treated the
     * plugin as live off that stale config.xml alone).
     */
    private function checkStandalone($messages)
    {
        if ($this->general->enabled->isEqual('1')) {
            $reason = Support::standaloneViolation(Config::getInstance()->object());
            if ($reason !== null) {
                $messages->appendMessage(new Message(gettext($reason), 'general.enabled'));
            }
        }
    }

    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $this->checkStandalone($messages);
        return $messages;
    }
}
