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

/**
 * Picked up by plugins_services(): file basename (if_pppoe) sets the
 * function prefix, so this must stay named if_pppoe.inc.
 */
function if_pppoe_services()
{
    // Always advertise the row, unconditionally on config.xml's saved
    // general.enabled: reboot-to-apply means that can flip well before (or
    // without) a reboot, while a kernel session from the previous boot may
    // still be live. Gating on the saved model would drop the row from the
    // Services widget the instant someone unticks and saves, even though
    // nothing has actually stopped. No live start/stop either way (there's
    // no configd stop; core/service/stop falls back to killbyname, which is
    // harmless but meaningless here) -- "restart" just re-runs the
    // read-only status probe so the widget has something harmless to call.
    return [[
        'description' => gettext('Kernel PPPoE (if_pppoe)'),
        'configd' => [
            'restart' => ['if-pppoe status'],
        ],
        'name' => 'if_pppoe',
        'nocheck' => true,
    ]];
}

/**
 * Backstops, always scheduled (same reasoning as if_pppoe_services()):
 * - reapply (every 5 minutes): puts the interfaces.inc hook back if core replaced the
 *   file and neither the update syshook nor the pkg trigger did; reapply.sh
 *   exits at once when desired is not enabled, latched, or a firmware run
 *   is in progress.
 * - reconcile (every minute): lost link events, dead clones, mpd5 on an
 *   eligible WAN; a no-op when nothing is managed.
 */
function if_pppoe_cron()
{
    return [
        ['autocron' => ['/usr/local/sbin/configctl -d if-pppoe reapply', '*/5']],
        ['autocron' => ['/usr/local/sbin/configctl -d if-pppoe reconcile', '*']],
    ];
}
