#!/usr/bin/env bash
# job-common.sh — shared helpers for verify-branch.sh and batch-suite.sh.
# Sourced (not executed) after ./common.sh, with LAB_SLOT and KERNEL_VARIANT
# already exported by the caller.
#
# Module builds ALWAYS use THIS checkout's lab/vm/build-module.sh, never the
# exported rev's own copy: a base rev under test may predate LAB_SLOT support
# (e.g. eb66683, before 75563a6), so only the *sources* come from the rev.

REPO_ROOT="$(cd ../.. && pwd)"

# ---------------------------------------------------------------- job lock
JOB_LOCK_HELD=0
JOB_LOCK_PATH_LIT=""   # literal "$HOME/..." text, expanded remotely

job_lock_acquire() {
    local slot="$1" wait_s="${JOB_LOCK_WAIT:-300}" stale_s="${JOB_LOCK_STALE:-5400}"
    JOB_LOCK_PATH_LIT="\$HOME/$LAB_DIR/leases/slot${slot}-job.lock"
    local waited=0
    while :; do
        local out
        # if/then, not a bare assignment: an ssh transport failure here must
        # not itself trip this script's `set -e` -- it just means retry.
        if out="$(host_ssh bash -s <<EOF
mkdir -p "\$HOME/$LAB_DIR/leases"
if mkdir "$JOB_LOCK_PATH_LIT" 2>/dev/null; then echo ACQUIRED; exit 0; fi
now=\$(date +%s); mtime=\$(stat -c %Y "$JOB_LOCK_PATH_LIT" 2>/dev/null || echo 0); age=\$((now - mtime))
if [ "\$age" -gt $stale_s ]; then
    rmdir "$JOB_LOCK_PATH_LIT" 2>/dev/null
    if mkdir "$JOB_LOCK_PATH_LIT" 2>/dev/null; then echo "ACQUIRED-STALE age=\${age}s"; exit 0; fi
fi
echo "BUSY age=\${age}s"
EOF
)"; then :; else out="SSH-ERROR rc=$?"; fi
        case "$out" in
            ACQUIRED*)
                JOB_LOCK_HELD=1
                echo "job-lock: acquired slot $slot ($out)" >&2
                return 0 ;;
            *)
                if [ "$waited" -ge "$wait_s" ]; then
                    echo "job-lock: timed out waiting ${wait_s}s for slot $slot ($out)" >&2
                    return 1
                fi
                sleep 10; waited=$((waited + 10)) ;;
        esac
    done
}

job_lock_release() {
    [ "$JOB_LOCK_HELD" = 1 ] || return 0
    # No quotes around $JOB_LOCK_PATH_LIT: it must reach the REMOTE shell as
    # bare `$HOME/...` so THAT shell expands $HOME -- single-quoting it here
    # (even though these are outer, local double quotes) would hand the
    # remote shell a literal, unexpanded '$HOME/...' and rmdir would silently
    # no-op forever (confirmed live: the lock survived a full run because of
    # exactly this).
    host_ssh "rmdir $JOB_LOCK_PATH_LIT 2>/dev/null || true" >/dev/null 2>&1 || true
    JOB_LOCK_HELD=0
}

# ------------------------------------------------------------- rev export
# rev_export <rev> <destdir>: full tracked-file tree of <rev>, extracted.
rev_export() {
    local rev="$1" dest="$2"
    mkdir -p "$dest"
    g -C "$REPO_ROOT" archive --format=tar "$(g -C "$REPO_ROOT" rev-parse --verify "${rev}^{commit}")" \
        | tar -C "$dest" -xf -
}

# sync_module_sources <srcdir>: tar srcdir's sys/spikes/tools (whichever
# exist) into $LAB_SLOT's remote WORK dir on the `build` VM, matching this
# checkout's build-module.sh path convention exactly (work / work-slotN).
sync_module_sources() {
    local srcdir="$1"
    local sfx; sfx="$(slot_suffix "$LAB_SLOT")"
    local work="\$HOME/$LAB_DIR/work$sfx"
    local dirs=() d
    for d in sys spikes tools; do
        [ -d "$srcdir/$d" ] && dirs+=("$d")
    done
    [ "${#dirs[@]}" -gt 0 ] || { echo "sync_module_sources: no sys/spikes/tools under $srcdir" >&2; return 1; }
    vm_ssh build "rm -rf $work && mkdir -p $work"
    tar -C "$srcdir" -cf - "${dirs[@]}" | vm_ssh build "tar -C $work -xmf -"
}

# module_loaded: true if if_pppoe is currently kldstat-loaded on the client.
module_loaded() { vm_ssh client "kldstat -q -m if_pppoe" 2>/dev/null; }

# ensure_module_unloaded: best-effort; never fatal (client may be unreachable,
# handled by the caller's own panic check right after).
ensure_module_unloaded() {
    if module_loaded; then
        ./build-module.sh unload if_pppoe || true
    fi
}

# module_build_deploy_load <srcdir> <label> <logdir>: sync, build, deploy,
# load against $LAB_SLOT/$KERNEL_VARIANT (both already exported by caller).
# Prints nothing on success; on failure, the relevant log's tail goes to
# stderr and it returns non-zero.
module_build_deploy_load() {
    local srcdir="$1" label="$2" logdir="$3" rc=0

    sync_module_sources "$srcdir" >"$logdir/sync-$label.log" 2>&1 || {
        echo "module_build_deploy_load($label): sync failed" >&2
        tail -40 "$logdir/sync-$label.log" >&2; return 1; }

    ./build-module.sh build sys/modules/if_pppoe >"$logdir/build-$label.log" 2>&1 || {
        echo "module_build_deploy_load($label): build failed" >&2
        tail -60 "$logdir/build-$label.log" >&2; return 1; }

    ./build-module.sh deploy sys/modules/if_pppoe if_pppoe.ko >"$logdir/deploy-$label.log" 2>&1 || {
        echo "module_build_deploy_load($label): deploy failed" >&2
        tail -40 "$logdir/deploy-$label.log" >&2; return 1; }

    ensure_module_unloaded

    ./build-module.sh load if_pppoe.ko >"$logdir/load-$label.log" 2>&1 || {
        echo "module_build_deploy_load($label): load failed" >&2
        tail -40 "$logdir/load-$label.log" >&2; return 1; }

    # The suite drives /usr/local/sbin/pppoectl & co.; without this the
    # client keeps whatever tools were last installed, so a rev that adds
    # pppoectl keywords or moves ioctl numbers is tested with stale userland.
    TOOLS_SRC_ROOT="$srcdir" ./install-client-tools.sh >"$logdir/tools-$label.log" 2>&1 || {
        echo "module_build_deploy_load($label): client tools install failed" >&2
        tail -40 "$logdir/tools-$label.log" >&2; return 1; }
}

# module_prebuilt_deploy_load <ko> <bindir> <srcdir> <logdir>: ship a prebuilt
# .ko to the client's /tmp/if_pppoe.ko (where the harness kldloads it); a
# build_id file beside it must match kern.build_id. spppauth is never taken
# from <bindir>: the harness needs test_pap_live's positional helper, not tools/spppauth.
module_prebuilt_deploy_load() {
    local ko="$1" bindir="$2" srcdir="$3" logdir="$4" want have b
    [ -f "$ko" ] || { echo "module_prebuilt_deploy_load: no such .ko: $ko" >&2; return 1; }
    if [ -f "$(dirname -- "$ko")/build_id" ]; then
        want="$(tr -d '[:space:]' < "$(dirname -- "$ko")/build_id")"
        have="$(vm_ssh client sysctl -n kern.build_id)"
        [ "$want" = "$have" ] || {
            echo "module_prebuilt_deploy_load: $ko is for build_id $want, client runs $have" >&2; return 1; }
        echo "prebuilt: build_id $want matches the client kernel" >&2
    fi
    echo "prebuilt: $ko sha256 $(sha256sum "$ko" | awk '{print $1}')" | tee "$logdir/deploy-prebuilt.log" >&2
    vm_ssh client 'cat > /tmp/if_pppoe.ko' < "$ko"
    ensure_module_unloaded
    ./build-module.sh load if_pppoe.ko >"$logdir/load-prebuilt.log" 2>&1 || {
        echo "module_prebuilt_deploy_load: load failed" >&2
        tail -40 "$logdir/load-prebuilt.log" >&2; return 1; }
    TOOLS_SRC_ROOT="$srcdir" ./install-client-tools.sh >"$logdir/tools-prebuilt.log" 2>&1 || {
        echo "module_prebuilt_deploy_load: client tools install failed" >&2
        tail -40 "$logdir/tools-prebuilt.log" >&2; return 1; }
    if [ -n "$bindir" ]; then
        for b in pppoectl pppoeparms spppioctl; do
            [ -f "$bindir/$b" ] || continue
            vm_ssh client "cat > /tmp/prebuilt-$b" < "$bindir/$b"
            echo | vm_ssh client "su -m root -c 'install -m 0555 /tmp/prebuilt-$b /usr/local/sbin/$b && rm -f /tmp/prebuilt-$b'"
            echo "prebuilt: /usr/local/sbin/$b <- $bindir/$b ($(sha256sum "$bindir/$b" | awk '{print $1}'))" \
                | tee -a "$logdir/tools-prebuilt.log" >&2
        done
    fi
}

# -------------------------------------------------------- VM up / recovery
ensure_client_up() {
    vm_ssh client true >/dev/null 2>&1 && return 0
    echo "ensure_client_up: client$([ "$LAB_SLOT" = 1 ] || echo "$LAB_SLOT") not reachable, bringing it up" >&2
    ./run.sh client up
}

client_alive() { vm_ssh client true >/dev/null 2>&1; }

# recover_client <reason>: never SIGKILLs. Tries reset-clean first (works
# from db>/login:/shell), falls back to snapshot-revert (fresh known-good
# overlay). Returns 0 only once ssh answers again.
recover_client() {
    local reason="$1"
    echo "recover_client: $reason -- trying reset-clean" >&2
    if ./run.sh client reset-clean >&2; then
        client_alive && return 0
    fi
    echo "recover_client: reset-clean did not bring ssh back -- trying snapshot-revert" >&2
    ./run.sh client snapshot-revert >&2
    client_alive
}

# ---------------------------------------------------------- serial capture
# serial_path_lit: literal "$HOME/..." remote path (LAB_SLOT already exported).
serial_path_lit() {
    local sfx; sfx="$(slot_suffix "$LAB_SLOT")"
    local name="client"; [ "$LAB_SLOT" = 1 ] || name="client$LAB_SLOT"
    echo "\$HOME/$LAB_DIR/run$sfx/$name.serial.log"
}

serial_lines_now() {
    host_ssh "wc -l < $(serial_path_lit) 2>/dev/null || echo 0"
}

# serial_delta <since_line+1> <outfile>: everything appended since.
serial_delta() {
    local since="$1" outfile="$2"
    host_ssh "tail -n +$since $(serial_path_lit) 2>/dev/null" > "$outfile" || true
}

# witness_grep <file>: panic/lock-order/witness lines, one per line, on stdout.
witness_grep() {
    grep -inE 'panic|Fatal trap|lock order reversal|sleeping with|KASSERT|witness' "$1" 2>/dev/null || true
}

# run_phase_with_recovery <label> <logdir> -- <cmd...>: captures the serial
# delta around <cmd>. If the client is unreachable afterwards (panicked),
# records evidence, recovers (never SIGKILL), retries <cmd> ONCE, and always
# leaves PHASE_PANICKED / PHASE_RECOVERED / PHASE_WITNESS set for the caller.
# Returns <cmd>'s exit status from whichever attempt actually ran to
# completion; if recovery itself fails, returns 99.
PHASE_PANICKED=0
PHASE_RECOVERED=0
PHASE_WITNESS_FILE=""
run_phase_with_recovery() {
    local label="$1" logdir="$2"; shift 2
    [ "$1" = "--" ] && shift
    PHASE_PANICKED=0; PHASE_RECOVERED=0
    PHASE_WITNESS_FILE="$logdir/serial-$label.log"
    local before rc
    before="$(serial_lines_now)" || before=0; before=$(( ${before:-0} + 1 ))

    # `&&`/`||`, not a bare `cmd; rc=$?`: the wrapped command's own failure
    # (e.g. a real test failure) must not itself trip this script's `set -e`
    # -- we still need to run the client_alive/recovery check below.
    "$@" && rc=0 || rc=$?

    if ! client_alive; then
        PHASE_PANICKED=1
        serial_delta "$before" "$PHASE_WITNESS_FILE"
        echo "run_phase_with_recovery($label): client unreachable after the phase -- treating as panicked" >&2
        witness_grep "$PHASE_WITNESS_FILE" | sed 's/^/  witness: /' >&2
        if recover_client "phase '$label' left the client unreachable"; then
            PHASE_RECOVERED=1
            echo "run_phase_with_recovery($label): recovered -- retrying once" >&2
            before="$(serial_lines_now)" || before=0; before=$(( ${before:-0} + 1 ))
            "$@" && rc=0 || rc=$?
            if ! client_alive; then
                PHASE_PANICKED=1
                serial_delta "$before" "$logdir/serial-$label-retry.log"
                witness_grep "$logdir/serial-$label-retry.log" | sed 's/^/  witness(retry): /' >&2
                echo "run_phase_with_recovery($label): panicked again on retry" >&2
                return 99
            fi
        else
            echo "run_phase_with_recovery($label): recovery FAILED -- lab is broken" >&2
            return 99
        fi
    else
        serial_delta "$before" "$PHASE_WITNESS_FILE"
    fi
    return "$rc"
}

# --------------------------------------------------------------- pytest run
# run_pytest_phase <local_tests_functional_dir> <select> <label> <logdir>
#   select: "-k EXPR" for a -k filter over the whole dir, "" for the whole
#   dir with no filter, or space-separated node-ids relative to
#   tests/functional/ (e.g. "test_foo.py::test_bar test_baz.py::test_qux").
# Populates (globals, consumed by the caller right after the call):
#   PYTEST_RC          remote pytest exit code (or 90 if ssh/setup itself failed)
#   PYTEST_RESULTS_JSON  path to a local JSON file: [{"nodeid","outcome"}, ...]
#   PYTEST_LOG           path to the local copy of the full remote pytest log
run_pytest_phase() {
    local local_tests="$1" select="$2" label="$3" logdir="$4"
    local sfx; sfx="$(slot_suffix "$LAB_SLOT")"
    local tests_dir="tests-functional$sfx"
    local junit="job-junit-$label.xml"
    local remote_log="job-last-func-$label.log"

    rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' \
        -e ssh "$local_tests/" "$VMHOST:$LAB_DIR/$tests_dir/"

    # Same as lab/Makefile's test-func: tests whose embedded C probes
    # #include the real ABI read it from $tests_dir/vendor-headers (the
    # --delete above wipes any earlier copy, so push the rev's own every time).
    local rev_net="$local_tests/../../sys/net" hdrs=() h
    for h in if_sppp.h if_pppoe.h; do [ -f "$rev_net/$h" ] && hdrs+=("$rev_net/$h"); done
    if [ "${#hdrs[@]}" -gt 0 ]; then
        host_ssh "mkdir -p $LAB_DIR/$tests_dir/vendor-headers/net"
        rsync -a -e ssh "${hdrs[@]}" "$VMHOST:$LAB_DIR/$tests_dir/vendor-headers/net/"
    fi

    # And test_ctl_contract.py's fixtures + replay script (lab/Makefile's
    # test-func does the same), from the rev's own plugin tree.
    local rev_ctl="$local_tests/../../plugin/net/if-pppoe/tests"
    if [ -d "$rev_ctl/fixtures/ctl-contract" ] && [ -f "$rev_ctl/engine/ctl-contract-replay.sh" ]; then
        host_ssh "mkdir -p $LAB_DIR/$tests_dir/vendor-ctl-contract/fixtures"
        rsync -a --delete -e ssh "$rev_ctl/fixtures/ctl-contract/" \
            "$VMHOST:$LAB_DIR/$tests_dir/vendor-ctl-contract/fixtures/"
        rsync -a -e ssh "$rev_ctl/engine/ctl-contract-replay.sh" \
            "$VMHOST:$LAB_DIR/$tests_dir/vendor-ctl-contract/ctl-contract-replay.sh"
    fi

    local node_ids="" kexpr=""
    case "$select" in
        "-k "*) kexpr="${select#-k }" ;;
        "") ;;
        *) node_ids="$select" ;;
    esac
    local b64_nodes b64_kexpr
    b64_nodes="$(printf '%s' "$node_ids" | base64 -w0)"
    b64_kexpr="$(printf '%s' "$kexpr" | base64 -w0)"

    local remote_out rc
    # if/then, not a bare assignment: an ssh/transport failure must not trip
    # this script's `set -e` -- the caller (run_phase_with_recovery) still
    # needs to run its own client_alive/recovery check afterward.
    if remote_out="$(host_ssh bash -s <<EOF
set -o pipefail
cd "\$HOME/$LAB_DIR" || exit 90
test -x venv/bin/python3 || (python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q pytest scapy) || exit 90
NODE_IDS="\$(echo $b64_nodes | base64 -d)"
KEXPR="\$(echo $b64_kexpr | base64 -d)"
TARGETS="$tests_dir"
if [ -n "\$NODE_IDS" ]; then
    TARGETS=""
    for n in \$NODE_IDS; do TARGETS="\$TARGETS $tests_dir/\$n"; done
fi
EXTRA_K=()
[ -n "\$KEXPR" ] && EXTRA_K=(-k "\$KEXPR")
sudo env LAB_SLOT=$LAB_SLOT CLIENT=if_pppoe SERVER=accel \\
    venv/bin/python3 -m pytest \$TARGETS -m "not soak" "\${EXTRA_K[@]}" \\
    --junit-xml="$junit" -q > "$remote_log" 2>&1 < /dev/null
rc=\$?
echo "JOB_REMOTE_RC=\$rc"
tail -80 "$remote_log"
EOF
)"; then rc=0; else rc=$?; fi
    printf '%s\n' "$remote_out" > "$logdir/pytest-$label.remote-tail.log"

    PYTEST_RC=90
    if [ "$rc" -eq 0 ]; then
        PYTEST_RC="$(printf '%s\n' "$remote_out" | sed -n 's/^JOB_REMOTE_RC=//p' | tail -1)"
        [ -n "$PYTEST_RC" ] || PYTEST_RC=90
    fi

    PYTEST_LOG="$logdir/pytest-$label.log"
    scp -q "$VMHOST:$LAB_DIR/$remote_log" "$PYTEST_LOG" 2>/dev/null \
        || printf '%s\n' "$remote_out" > "$PYTEST_LOG"

    local local_junit="$logdir/$junit"
    scp -q "$VMHOST:$LAB_DIR/$junit" "$local_junit" 2>/dev/null || rm -f "$local_junit"

    PYTEST_RESULTS_JSON="$logdir/results-$label.json"
    if [ -f "$local_junit" ] && command -v python3 >/dev/null 2>&1; then
        python3 - "$local_junit" > "$PYTEST_RESULTS_JSON" <<'PY'
import sys, json
import xml.etree.ElementTree as ET
path = sys.argv[1]
out = []
try:
    root = ET.parse(path).getroot()
    for tc in root.iter("testcase"):
        cls = tc.get("classname") or ""
        name = tc.get("name") or ""
        nodeid = f"{cls}::{name}" if cls else name
        outcome = "passed"
        if tc.find("failure") is not None:
            outcome = "failed"
        elif tc.find("error") is not None:
            outcome = "error"
        elif tc.find("skipped") is not None:
            outcome = "skipped"
        out.append({"nodeid": nodeid, "outcome": outcome})
except Exception as e:
    print(json.dumps({"parse_error": str(e)}))
    sys.exit(0)
print(json.dumps(out))
PY
    else
        echo '[]' > "$PYTEST_RESULTS_JSON"
    fi
}

# hardening_probe_phase <logdir>: mirrors lab/Makefile's test-hardening
# target (CLIENT forced to if_pppoe there too). Sets HARDENING_RC.
hardening_probe_phase() {
    local logdir="$1"
    local sfx; sfx="$(slot_suffix "$LAB_SLOT")"
    local tests_dir="tests-functional$sfx"
    local remote_log="job-last-hardening$sfx.log" remote_rc="job-last-hardening$sfx.rc"
    local remote_out
    if remote_out="$(host_ssh bash -s <<EOF
set -o pipefail
cd "\$HOME/$LAB_DIR" || exit 90
test -x venv/bin/python3 || (python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q pytest scapy) || exit 90
sudo env LAB_SLOT=$LAB_SLOT CLIENT=if_pppoe SERVER=accel \\
    venv/bin/python3 $tests_dir/hardening_probe.py > "$remote_log" 2>&1 < /dev/null
rc=\$?
echo "\$rc" > "$remote_rc"
echo "JOB_REMOTE_RC=\$rc"
tail -60 "$remote_log"
EOF
)"; then :; else :; fi
    # The probe outlives flaky ssh captures: if this one came back empty,
    # read its rc + log tail back from the files it left on the host.
    if ! printf '%s\n' "$remote_out" | grep -q '^JOB_REMOTE_RC='; then
        remote_out="$(host_ssh "cd \$HOME/$LAB_DIR && printf 'JOB_REMOTE_RC=%s\n' \"\$(cat $remote_rc 2>/dev/null)\" && tail -60 $remote_log" 2>/dev/null || true)"
    fi
    printf '%s\n' "$remote_out" > "$logdir/hardening.log"
    HARDENING_RC="$(printf '%s\n' "$remote_out" | sed -n 's/^JOB_REMOTE_RC=//p' | tail -1)"
    [ -n "$HARDENING_RC" ] || HARDENING_RC=90
}
