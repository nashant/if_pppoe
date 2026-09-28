# shellcheck shell=bash
# Per-run credential staging for the accel-ppp integration runs (sourced
# once hssh/cssh/croot exist). Secrets are generated per run, move only over
# ssh stdin, and land only on tmpfs (VMHOST /dev/shm, client tmpfs mount);
# creds_cleanup, called from the EXIT trap, removes both.

CREDS_HOST_DIR="/dev/shm/if_pppoe-it.$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
# Literal copy in the croot dial strings below each run script: keep in sync.
CREDS_CLIENT_DIR=/var/run/if_pppoe-it
CREDS_CLEANED=0

gen_secret() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }

# creds_server NAME USER SECRET: write a one-entry chap-secrets file NAME
# into the VMHOST tmpfs dir (stdin only, so the secret is never in argv).
creds_server() {
    printf '%s\t*\t%s\t*\n' "$2" "$3" \
        | hssh "umask 077 && mkdir -p '$CREDS_HOST_DIR' && cat > '$CREDS_HOST_DIR/$1'"
}

# creds_server_path NAME: the remote path creds_server wrote NAME to.
creds_server_path() { printf '%s/%s' "$CREDS_HOST_DIR" "$1"; }

# creds_client_stage: copy stdin ("user\nsecret\n") to $CREDS_CLIENT_DIR/c
# on the client VM, (re)mounting a fresh freebsd-owned 0700 tmpfs there.
creds_client_stage() {
    croot "mkdir -p $CREDS_CLIENT_DIR; umount $CREDS_CLIENT_DIR 2>/dev/null; mount -t tmpfs -o mode=0700,uid=\$(id -u freebsd) tmpfs $CREDS_CLIENT_DIR" \
        </dev/null || return 1
    cssh "umask 077 && cat > $CREDS_CLIENT_DIR/c"
}

creds_cleanup() {
    [ "$CREDS_CLEANED" = "1" ] && return 0
    CREDS_CLEANED=1
    hssh "rm -rf '$CREDS_HOST_DIR'" </dev/null >/dev/null 2>&1 || true
    croot "rm -f $CREDS_CLIENT_DIR/c; umount -f $CREDS_CLIENT_DIR 2>/dev/null; true" \
        </dev/null >/dev/null 2>&1 || true
}
