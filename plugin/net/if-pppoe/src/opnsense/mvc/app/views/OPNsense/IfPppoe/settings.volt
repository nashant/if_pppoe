{#
 # Copyright (c) 2026 Anthony Nash
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided the same conditions as this plugin's other files.
 #}

<div class="tab-content content-box tab-content">
    <div id="settings" class="tab-pane fade in active">
        <div class="content-box" style="padding-bottom: 1.5em;">
            {{ partial("layout_partials/base_form",['fields':this_form,'id':'frm_general'])}}
            <div class="col-md-12">
                <hr/>
                <button class="btn btn-primary" id="saveAct" type="button">
                    <b>{{ lang._('Save and Apply') }}</b>
                    <i id="saveAct_progress"></i>
                </button>
                <div id="ifpppoe_message" class="alert alert-danger hidden" style="margin-top:1em;" role="alert"></div>
            </div>
        </div>
        <div class="content-box" style="padding: 1em 1.5em;">
            <table class="table table-striped" id="grid-status">
                <tbody>
                    <tr>
                        <td>{{ lang._('Reboot required') }}</td>
                        <td id="ifpppoe_reboot_banner">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Next step') }}</td>
                        <td id="ifpppoe_advice">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Notices') }}</td>
                        <td id="ifpppoe_notices">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Desired (saved)') }}</td>
                        <td id="ifpppoe_desired">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Persisted (/conf/if_pppoe/desired)') }}</td>
                        <td id="ifpppoe_persisted">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Effective backend') }}</td>
                        <td id="ifpppoe_effective">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Hook status') }}</td>
                        <td id="ifpppoe_hook_status">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Last boot result') }}</td>
                        <td id="ifpppoe_boot">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Supported kernels') }}</td>
                        <td id="ifpppoe_supported_kernels">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Running kernel') }}</td>
                        <td id="ifpppoe_running_kernel">-</td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Installed kernel') }}</td>
                        <td id="ifpppoe_installed_kernel">-</td>
                    </tr>
                </tbody>
            </table>
            <table class="table table-striped" id="grid-interfaces">
                <thead>
                    <tr>
                        <th>{{ lang._('Interface') }}</th>
                        <th>{{ lang._('Backend') }}</th>
                        <th>{{ lang._('Reason') }}</th>
                        <th>{{ lang._('Session') }}</th>
                    </tr>
                </thead>
                <tbody id="ifpppoe_interfaces_body">
                </tbody>
            </table>
            <button class="btn btn-default" id="rebootAct" type="button" style="display:none;">
                <b>{{ lang._('Reboot now') }}</b>
                <i id="rebootAct_progress"></i>
            </button>
        </div>
    </div>
</div>

<script>
function ifpppoe_show_message(text) {
    $("#ifpppoe_message").removeClass("hidden").text(text);
}

function ifpppoe_clear_message() {
    $("#ifpppoe_message").addClass("hidden").text('');
}

// {version, build_id} -> "26.1.3", or the start of the build-id when kernels.json does not name it
function ifpppoe_kernel_label(k) {
    if (k.version) {
        return k.version;
    }
    return k.build_id ? '{{ lang._("build-id") }} ' + k.build_id.substring(0, 12) : '{{ lang._("unknown") }}';
}

function ifpppoe_render_kernels(data) {
    let supported = data.supported_kernels;
    if (Array.isArray(supported)) {
        let bySeries = {};
        let order = [];
        $.each(supported, function(i, v) {
            let series = String(v).split('.').slice(0, 2).join('.');
            if (!(series in bySeries)) {
                bySeries[series] = [];
                order.push(series);
            }
            bySeries[series].push(String(v));
        });
        let $s = $("#ifpppoe_supported_kernels").empty();
        if (order.length === 0) {
            $s.text('{{ lang._("none") }}');
        }
        $.each(order, function(i, series) {
            $s.append($('<div>').text(series + ': ' + bySeries[series].join(', ')));
        });
    } else {
        $("#ifpppoe_supported_kernels").text(data.engine_available
            ? '{{ lang._("unknown (this if-pppoe-kmod does not list them)") }}' : '{{ lang._("unknown") }}');
    }
    let covered = function(k) {
        return k.covered ? '{{ lang._("covered") }}' : '{{ lang._("not covered") }}';
    };
    let run = data.running_kernel;
    $("#ifpppoe_running_kernel").text(run ? ifpppoe_kernel_label(run) + ': ' + covered(run) : '{{ lang._("unknown") }}');
    let inst = data.installed_kernel;
    let $inst = $("#ifpppoe_installed_kernel").empty();
    if (!inst) {
        $inst.text('{{ lang._("unknown") }}');
    } else if (inst.pending_reboot) {
        $inst.append($('<span>').addClass(inst.covered ? '' : 'text-warning').text(
            ifpppoe_kernel_label(inst) + ' {{ lang._("(pending reboot)") }}: ' + covered(inst)));
    } else {
        $inst.text('{{ lang._("same as running") }}');
    }
    let up = data.kernel_upgrade;
    if (up) {
        $inst.append($('<div>').text('{{ lang._("Major upgrade staged to") }} ' + up.version + ': ' + (up.covered
            ? '{{ lang._("covered") }}' : '{{ lang._("decided by the if-pppoe-kmod the upgrade installs") }}')));
    }
}

function ifpppoe_render_status(data) {
    ifpppoe_render_kernels(data);
    $("#ifpppoe_desired").text(data.desired || '-');
    $("#ifpppoe_persisted").text(data.persisted ||
        (data.engine_available ? '{{ lang._("not applied yet") }}' : '{{ lang._("unknown (engine unavailable)") }}'));
    $("#ifpppoe_effective").text(data.effective ||
        (data.engine_available ? '{{ lang._("none") }}' : '{{ lang._("unknown") }}'));
    $("#ifpppoe_hook_status").text(
        data.hook_status ? (data.hook_detail ? data.hook_status + ' (' + data.hook_detail + ')' : data.hook_status)
                         : '{{ lang._("unknown") }}'
    );
    let boot = (data.boot || {});
    if (boot.result) {
        $("#ifpppoe_boot").text(boot.reason ? boot.result + ' (' + boot.reason + ')' : boot.result);
    } else {
        $("#ifpppoe_boot").text('{{ lang._("unknown") }}');
    }
    // reboot_required comes from the engine and is already false wherever a
    // reboot cannot help (latched, refused, a failed boot); advice says why.
    if (data.reboot_required) {
        $("#ifpppoe_reboot_banner").html('<span class="text-danger"><b>{{ lang._("Yes") }}</b></span>');
        $("#rebootAct").show();
    } else {
        $("#ifpppoe_reboot_banner").text('{{ lang._("No") }}');
        $("#rebootAct").hide();
    }
    let $advice = $("#ifpppoe_advice").empty();
    if (data.advice) {
        $advice.append($('<span>').addClass(data.latched || data.refused ? 'text-danger' : 'text-warning')
            .append($('<b>').text(data.advice)));
    } else {
        $advice.text('-');
    }
    let $notices = $("#ifpppoe_notices").empty();
    let notices = data.notices || [];
    if (notices.length === 0) {
        $notices.text('-');
    }
    $.each(notices, function(i, n) {
        $notices.append($('<div>').text(n.message || ''));
    });
    let $body = $("#ifpppoe_interfaces_body");
    $body.empty();
    let interfaces = data.interfaces || [];
    if (interfaces.length === 0) {
        $body.append('<tr><td colspan="4">{{ lang._("No PPPoE interfaces, or engine unavailable.") }}</td></tr>');
    }
    $.each(interfaces, function(i, iface) {
        $body.append(
            $('<tr>').append(
                $('<td>').text(iface.friendly || ''),
                $('<td>').text(iface.backend || ''),
                $('<td>').text(iface.reason || ''),
                $('<td>').text(iface.session || '')
            )
        );
    });
}

function ifpppoe_refresh_status() {
    ajaxGet(url="/api/ifpppoe/service/status", sendData={}, callback=function(data, status) {
        if (status === "success") {
            ifpppoe_render_status(data);
        }
    });
}

$( document ).ready(function() {
    var data_get_map = {'frm_general':"/api/ifpppoe/settings/get"};
    mapDataToFormUI(data_get_map).done(function(data){
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    ifpppoe_refresh_status();

    $("#saveAct").click(function(){
        ifpppoe_clear_message();
        saveFormToEndpoint(url="/api/ifpppoe/settings/set", formid='frm_general', callback_ok=function(){
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url="/api/ifpppoe/service/reconfigure", sendData={}, callback=function(data, status) {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                if (status === "success" && data && data.status && data.status !== 'ok') {
                    ifpppoe_show_message(data.message || '{{ lang._("Apply failed.") }}');
                }
                ifpppoe_refresh_status();
            });
        });
    });

    $("#rebootAct").click(function(){
        stdDialogConfirm(
            '{{ lang._('Reboot now') }}',
            '{{ lang._('This immediately reboots the firewall, dropping all connections including this one. Continue?') }}',
            '{{ lang._('Reboot now') }}', '{{ lang._('Cancel') }}',
            function () {
                ifpppoe_clear_message();
                $("#rebootAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall(url="/api/core/system/reboot", sendData={}, callback=function(data, status) {
                    $("#rebootAct_progress").removeClass("fa fa-spinner fa-pulse");
                    if (status !== "success" || !data || data.status !== 'ok') {
                        ifpppoe_show_message(
                            '{{ lang._("Reboot request failed. Reboot needs the separate diagnostics-rebootsystem privilege.") }}'
                        );
                    }
                });
            }
        );
    });
});
</script>
