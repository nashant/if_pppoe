#!/bin/sh
# PROVIDE: if_pppoe
# REQUIRE: netif FILESYSTEMS
# KEYWORD: shutdown
#
# Activate/de-activate the in-kernel PPPoE client driver (OpenBSD/NetBSD
# port shipped as the os-pppoe package).
#
#   service if_pppoe start        activate  (kldload if_pppoe; idempotent)
#   service if_pppoe stop         deactivate (destroy pppoeN clones -- PADT
#                                  goes out per clone -- then kldunload)
#   service if_pppoe status       loaded / not loaded
#
# Enable the driver at every boot:  sysrc if_pppoe_enable=YES
# (it defaults to YES so a bare `service if_pppoe start` right after
# `pkg add` works; set if_pppoe_enable=NO in /etc/rc.conf.local to keep it
# from auto-loading at boot).
#
# After activation create a session the OPNsense/FreeBSD way:
#   ifconfig pppoe0 create
#   pppoectl -e <parent-iface> pppoe0          # parent bind (PPPOESETPARMS)
#   pppoectl pppoe0 myauthproto=pap myauthname=USER myauthsecret=PASS
#   pppoectl pppoe0 query-dns=3 max-noreceive=0 max-alive-missed=3 alive-interval=1
#   ifconfig pppoe0 up

. /etc/rc.subr

name=if_pppoe
desc="In-kernel PPPoE client driver (OpenBSD/NetBSD port)"
rcvar=if_pppoe_enable

start_cmd="if_pppoe_start"
stop_cmd="if_pppoe_stop"
status_cmd="if_pppoe_status"
extra_commands="status"

load_rc_config "$name"
: "${if_pppoe_enable:=YES}"

_pppoe_clones()
{
    /sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^pppoe[0-9]' || true
}

if_pppoe_start()
{
    if /sbin/kldstat -qm if_pppoe; then
        info "if_pppoe: module already loaded"
    else
        /sbin/kldload if_pppoe
    fi
}

if_pppoe_stop()
{
    # Destroy clones first: clone destroy emits a clean PADT naming the
    # live session id and runs the driver's teardown (address clearing,
    # RTM_IFINFO link-down).  Unloading with clones still attached would
    # force-detach them.
    for _i in $( _pppoe_clones ); do
        /sbin/ifconfig "$_i" down 2>/dev/null
        /sbin/ifconfig "$_i" destroy
    done
    if /sbin/kldstat -qm if_pppoe; then
        /sbin/kldunload if_pppoe
    else
        info "if_pppoe: module not loaded"
    fi
}

if_pppoe_status()
{
    if /sbin/kldstat -qm if_pppoe; then
        echo "if_pppoe: loaded"
        /sbin/ifconfig -l | tr ' ' '\n' | grep '^pppoe[0-9]' || true
    else
        echo "if_pppoe: not loaded"
    fi
}

run_rc_command "$1"