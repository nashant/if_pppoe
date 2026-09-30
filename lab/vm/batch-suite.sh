#!/usr/bin/env bash
# batch-suite.sh --slot N --rev <rev> --out <dir>
#                [--variant SMP|SMPW] [--no-hardening] [--k EXPR]
#                [--prebuilt-ko PATH [--prebuilt-bin DIR]]
#
# Deterministic, non-interactive: build-checks <rev>, builds+deploys+loads
# its module on slot N, runs its own tests/functional full suite (CLIENT=
# if_pppoe SERVER=accel, -m "not soak") plus the S02 hardening probe unless
# --no-hardening, collects serial-log deltas, and writes $out/verdict.json +
# $out/summary.txt.
#
# --k EXPR: restrict the suite to a `pytest -k EXPR` subset (smoke/debug use
# only -- the normal run is the whole suite). Still runs hardening too unless
# --no-hardening is also given.
#
# --prebuilt-ko PATH (or env LAB_PREBUILT_KO): test that already-built
# if_pppoe.ko (e.g. CI's package build) instead of building <rev>'s: no
# build-check, no module build; <rev> still supplies the tests and the
# source-built client tools, --prebuilt-bin DIR (LAB_PREBUILT_BIN) prebuilt
# pppoectl/pppoeparms/spppioctl. See job-common.sh module_prebuilt_deploy_load.
#
# --slot N: used AS GIVEN, never acquired/released via slot.sh (the
# orchestrator may already hold it pinned) -- only a local job lock
# (job-common.sh) serializes two job scripts on the same slot.
#
# Exit: 0 pass, 1 fail, 2 lab-broken. Unlike verify-branch.sh there is only
# one candidate rev here, so a build-check/build/deploy/load failure is a
# plain "fail" (the rev is broken), not lab-broken; lab-broken is reserved
# for a client the lab cannot recover (reset-clean, then snapshot-revert
# both fail). A VM panic that recovers is not itself fatal.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
source ./job-common.sh

SLOT="" REV="" OUTDIR="" VARIANT="SMP" NO_HARDENING=0 KEXPR=""
PREBUILT_KO="${LAB_PREBUILT_KO:-}" PREBUILT_BIN="${LAB_PREBUILT_BIN:-}"
usage() {
    echo "usage: $0 --slot N --rev <rev> --out <dir> [--variant SMP|SMPW] [--no-hardening] [--k EXPR] [--prebuilt-ko PATH [--prebuilt-bin DIR]]" >&2
    exit 1
}
while [ $# -gt 0 ]; do
    case "$1" in
        --slot) SLOT="$2"; shift 2 ;;
        --rev) REV="$2"; shift 2 ;;
        --out) OUTDIR="$2"; shift 2 ;;
        --variant) VARIANT="$2"; shift 2 ;;
        --no-hardening) NO_HARDENING=1; shift ;;
        --k) KEXPR="$2"; shift 2 ;;
        --prebuilt-ko) PREBUILT_KO="$2"; shift 2 ;;
        --prebuilt-bin) PREBUILT_BIN="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$SLOT" ] && [ -n "$REV" ] && [ -n "$OUTDIR" ] || usage
# Absolute only: this script has already cd'd to its own directory.
for p in "$PREBUILT_KO" "$PREBUILT_BIN"; do
    case "$p" in ""|/*) ;; *) echo "batch-suite: --prebuilt-ko/--prebuilt-bin must be absolute (got '$p')" >&2; exit 1 ;; esac
done

REPO_ROOT_CHECK="$(cd ../.. && pwd)"
g -C "$REPO_ROOT_CHECK" rev-parse --verify --quiet "${REV}^{commit}" >/dev/null \
    || { echo "batch-suite: --rev '$REV' is not a valid commit in $REPO_ROOT_CHECK" >&2; exit 1; }

export LAB_SLOT="$SLOT"
export KERNEL_VARIANT="$VARIANT"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
exec > >(tee -a "$OUTDIR/run.log") 2>&1
echo "batch-suite: slot=$SLOT rev=$REV variant=$VARIANT out=$OUTDIR no_hardening=$NO_HARDENING k='${KEXPR}' prebuilt_ko='${PREBUILT_KO}' prebuilt_bin='${PREBUILT_BIN}'"
date -u +%FT%TZ

WITNESS_LINES_FILE="$OUTDIR/witness_lines.txt"
: > "$WITNESS_LINES_FILE"
collect_witness() {
    local phase="$1" file="$2"
    [ -f "$file" ] || return 0
    witness_grep "$file" | sed "s/^/[$phase] /" >> "$WITNESS_LINES_FILE"
}

VERDICT="fail"
BUILD_OK=0
SUITE_RC=90
PASS_COUNT=0 FAIL_COUNT=0
HARDENING_RC="" HARDENING_STATUS="skipped"
LAB_BROKEN_REASON=""
SUITE_RESULTS_JSON=""

write_verdict() {
    local exit_code="$1"
    python3 - "$OUTDIR" "$VERDICT" "$BUILD_OK" "$PASS_COUNT" "$FAIL_COUNT" \
        "${SUITE_RESULTS_JSON:-}" "$HARDENING_STATUS" "${HARDENING_RC:-}" \
        "$LAB_BROKEN_REASON" "$WITNESS_LINES_FILE" "$SLOT" "$REV" "$VARIANT" "$KEXPR" <<'PY' || true
import json, sys, pathlib
(outdir, verdict, build_ok, pass_n, fail_n, results_json, hardening_status,
 hardening_rc, reason, witness_file, slot, rev, variant, kexpr) = sys.argv[1:]

def load(p):
    try:
        return json.loads(pathlib.Path(p).read_text()) if p else []
    except Exception:
        return []

results = load(results_json)
# skipped/xfailed are not failures (a skip is a test declining to run here)
failing = [r["nodeid"] for r in results if r.get("outcome") in ("failed", "error")]
skipped = [r["nodeid"] for r in results if r.get("outcome") == "skipped"]
witness = []
wf = pathlib.Path(witness_file)
if wf.exists():
    witness = [l for l in wf.read_text().splitlines() if l.strip()]

doc = {
    "slot": int(slot), "rev": rev, "variant": variant, "k": kexpr or None,
    "build_ok": build_ok == "1",
    "pass_count": int(pass_n), "fail_count": int(fail_n), "skip_count": len(skipped),
    "failing_test_ids": failing,
    "hardening": {"status": hardening_status, "rc": hardening_rc or None},
    "witness_lines": witness,
    "lab_broken_reason": reason or None,
    "verdict": verdict,
}
pathlib.Path(outdir, "verdict.json").write_text(json.dumps(doc, indent=2) + "\n")

lines = [
    f"verdict: {verdict}",
    f"slot {slot}  rev={rev}  variant={variant}" + (f"  k='{kexpr}'" if kexpr else ""),
    f"build_ok={doc['build_ok']}",
    f"pass={doc['pass_count']}  fail={doc['fail_count']}",
    f"hardening: {hardening_status} (rc={hardening_rc or 'n/a'})",
]
if reason:
    lines.append(f"lab_broken_reason: {reason}")
if failing:
    lines.append(f"failing_test_ids ({len(failing)}):")
    lines += [f"  {n}" for n in failing]
if witness:
    lines.append(f"witness_lines ({len(witness)}):")
    lines += [f"  {w}" for w in witness]
pathlib.Path(outdir, "summary.txt").write_text("\n".join(lines) + "\n")
PY
    cat "$OUTDIR/summary.txt" 2>/dev/null || true
    exit "$exit_code"
}

job_lock_acquire "$SLOT" || { VERDICT="lab-broken"; LAB_BROKEN_REASON="could not acquire job lock on slot $SLOT"; write_verdict 2; }
trap job_lock_release EXIT

echo "== build-check: $REV =="
if [ -n "$PREBUILT_KO" ]; then
    echo "skipped: testing prebuilt $PREBUILT_KO" | tee "$OUTDIR/build-check.log"
elif ./build-check.sh "$REV" >"$OUTDIR/build-check.log" 2>&1; then
    :
else
    tail -60 "$OUTDIR/build-check.log"
    VERDICT="fail"; LAB_BROKEN_REASON="build-check failed on $REV"
    write_verdict 1
fi

TMPROOT="$(mktemp -d)"
cleanup_tmp() { rm -rf "$TMPROOT"; }
trap 'job_lock_release; cleanup_tmp' EXIT
rev_export "$REV" "$TMPROOT/rev"
[ -d "$TMPROOT/rev/tests/functional" ] || { VERDICT="fail"; LAB_BROKEN_REASON="$REV has no tests/functional"; write_verdict 1; }

ensure_client_up || { VERDICT="lab-broken"; LAB_BROKEN_REASON="client on slot $SLOT would not come up"; write_verdict 2; }

echo "== build/deploy/load =="
if [ -n "$PREBUILT_KO" ]; then
    if module_prebuilt_deploy_load "$PREBUILT_KO" "$PREBUILT_BIN" "$TMPROOT/rev" "$OUTDIR"; then
        BUILD_OK=1
    else
        VERDICT="fail"; LAB_BROKEN_REASON="prebuilt deploy/load failed for $PREBUILT_KO"
        write_verdict 1
    fi
elif module_build_deploy_load "$TMPROOT/rev" "rev" "$OUTDIR"; then
    BUILD_OK=1
else
    VERDICT="fail"; LAB_BROKEN_REASON="module build/deploy/load failed for $REV"
    write_verdict 1
fi

echo "== full suite =="
SELECT=""
[ -n "$KEXPR" ] && SELECT="-k $KEXPR"
run_phase_with_recovery "suite" "$OUTDIR" -- \
    run_pytest_phase "$TMPROOT/rev/tests/functional" "$SELECT" "suite" "$OUTDIR" || true
SUITE_RC="${PYTEST_RC:-90}"
SUITE_RESULTS_JSON="$PYTEST_RESULTS_JSON"
collect_witness "suite" "$PHASE_WITNESS_FILE"
if [ "$PHASE_PANICKED" = 1 ] && [ "$PHASE_RECOVERED" != 1 ]; then
    VERDICT="lab-broken"; LAB_BROKEN_REASON="client did not recover after the suite phase"
    write_verdict 2
fi

COUNTS_LINE="$(python3 -c "
import json
r = json.load(open('$SUITE_RESULTS_JSON'))
p = sum(1 for x in r if x.get('outcome') == 'passed')
f = sum(1 for x in r if x.get('outcome') in ('failed', 'error'))
print(p, f)
" 2>/dev/null || echo "0 0")"
read -r PASS_COUNT FAIL_COUNT <<<"$COUNTS_LINE"

HARDENING_STATUS="skipped"
if [ "$NO_HARDENING" != 1 ]; then
    echo "== hardening probe =="
    run_phase_with_recovery "hardening" "$OUTDIR" -- \
        hardening_probe_phase "$OUTDIR" || true
    collect_witness "hardening" "$PHASE_WITNESS_FILE"
    if [ "$PHASE_PANICKED" = 1 ] && [ "$PHASE_RECOVERED" != 1 ]; then
        VERDICT="lab-broken"; LAB_BROKEN_REASON="client did not recover after the hardening phase"
        write_verdict 2
    fi
    HARDENING_RC="${HARDENING_RC:-90}"
    HARDENING_STATUS="pass"; [ "$HARDENING_RC" = 0 ] || HARDENING_STATUS="fail"
fi

if [ "$SUITE_RC" = 0 ] && [ "$FAIL_COUNT" = 0 ] && { [ "$NO_HARDENING" = 1 ] || [ "$HARDENING_STATUS" = pass ]; }; then
    VERDICT="pass"; write_verdict 0
else
    VERDICT="fail"; write_verdict 1
fi
