#!/usr/bin/env bash
# verify-branch.sh --slot N --base <rev> --fix <rev> --tests '<sel>' --out <dir>
#                   [--variant SMP|SMPW]
#
# Deterministic, non-interactive: build-checks both revs, then on slot N
# builds+deploys+loads BASE, runs <sel> (the FIX tree's own tests/functional,
# so the same test content is used against both modules), then does the same
# for FIX, and writes $out/verdict.json + $out/summary.txt.
#
# <sel>: "-k EXPR" (pytest -k filter over the whole dir) or space-separated
# node-ids relative to tests/functional/, e.g.
#   'test_pppoectl_ctl_live.py::test_pppoectl_dash_f_nonexistent_file_exits_nonzero'
#
# --slot N: this slot is used AS GIVEN, never acquired/released via slot.sh
# (the orchestrator may already hold it pinned) -- only a local job lock
# (job-common.sh) serializes two job scripts on the same slot.
#
# Exit: 0 pass, 1 fail, 2 lab-broken. A build-check failure on EITHER rev,
# or a BASE module build/deploy/load failure, or a client the lab cannot
# recover (reset-clean, then snapshot-revert both fail) is lab-broken; a
# FIX-side build/load failure or a FIX run that doesn't pass is fail. A VM
# panic that recovers is not itself fatal -- run_phase_with_recovery retries
# once and the panic is just recorded as evidence (witness_lines).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./common.sh
source ./job-common.sh

SLOT="" BASE_REV="" FIX_REV="" TESTS="" OUTDIR="" VARIANT="SMP"
usage() {
    echo "usage: $0 --slot N --base <rev> --fix <rev> --tests '<sel>' --out <dir> [--variant SMP|SMPW]" >&2
    exit 1
}
while [ $# -gt 0 ]; do
    case "$1" in
        --slot) SLOT="$2"; shift 2 ;;
        --base) BASE_REV="$2"; shift 2 ;;
        --fix) FIX_REV="$2"; shift 2 ;;
        --tests) TESTS="$2"; shift 2 ;;
        --out) OUTDIR="$2"; shift 2 ;;
        --variant) VARIANT="$2"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$SLOT" ] && [ -n "$BASE_REV" ] && [ -n "$FIX_REV" ] && [ -n "$TESTS" ] && [ -n "$OUTDIR" ] || usage

cd "$SCRIPT_DIR"
REPO_ROOT_CHECK="$(cd ../.. && pwd)"
g -C "$REPO_ROOT_CHECK" rev-parse --verify --quiet "${BASE_REV}^{commit}" >/dev/null \
    || { echo "verify-branch: --base '$BASE_REV' is not a valid commit in $REPO_ROOT_CHECK" >&2; exit 1; }
g -C "$REPO_ROOT_CHECK" rev-parse --verify --quiet "${FIX_REV}^{commit}" >/dev/null \
    || { echo "verify-branch: --fix '$FIX_REV' is not a valid commit in $REPO_ROOT_CHECK" >&2; exit 1; }

export LAB_SLOT="$SLOT"
export KERNEL_VARIANT="$VARIANT"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
exec > >(tee -a "$OUTDIR/run.log") 2>&1
echo "verify-branch: slot=$SLOT base=$BASE_REV fix=$FIX_REV variant=$VARIANT tests='$TESTS' out=$OUTDIR"
date -u +%FT%TZ

WITNESS_LINES_FILE="$OUTDIR/witness_lines.txt"
: > "$WITNESS_LINES_FILE"
collect_witness() {
    local phase="$1" file="$2"
    [ -f "$file" ] || return 0
    witness_grep "$file" | sed "s/^/[$phase] /" >> "$WITNESS_LINES_FILE"
}

VERDICT="fail"
BUILD_OK_BASE=0 BUILD_OK_FIX=0
TESTS_FAIL_ON_BASE="false" TESTS_PASS_ON_FIX="false"
LAB_BROKEN_REASON=""

write_verdict() {
    local exit_code="$1"
    # `|| true`: this must still reach `exit "$exit_code"` below even if the
    # python3 heredoc itself failed -- a missing/partial verdict.json is far
    # better than silently dying on `set -e` before we can exit correctly.
    python3 - "$OUTDIR" "$VERDICT" "$BUILD_OK_BASE" "$BUILD_OK_FIX" \
        "$TESTS_FAIL_ON_BASE" "$TESTS_PASS_ON_FIX" "$LAB_BROKEN_REASON" \
        "${BASE_RESULTS_JSON:-}" "${FIX_RESULTS_JSON:-}" "$WITNESS_LINES_FILE" \
        "$SLOT" "$BASE_REV" "$FIX_REV" "$VARIANT" "$TESTS" <<'PY' || true
import json, sys, pathlib
(outdir, verdict, build_base, build_fix, fail_base, pass_fix, reason,
 base_json, fix_json, witness_file, slot, base_rev, fix_rev, variant, tests) = sys.argv[1:]

def load(p):
    try:
        return json.loads(pathlib.Path(p).read_text()) if p else []
    except Exception:
        return []

witness = []
wf = pathlib.Path(witness_file)
if wf.exists():
    witness = [l for l in wf.read_text().splitlines() if l.strip()]

doc = {
    "slot": int(slot), "base_rev": base_rev, "fix_rev": fix_rev,
    "variant": variant, "tests": tests,
    "build": {"base": build_base == "1", "fix": build_fix == "1"},
    "base_results": load(base_json),
    "fix_results": load(fix_json),
    "tests_fail_on_base": fail_base == "true",
    "tests_pass_on_fix": pass_fix == "true",
    "witness_lines": witness,
    "lab_broken_reason": reason or None,
    "verdict": verdict,
}
pathlib.Path(outdir, "verdict.json").write_text(json.dumps(doc, indent=2) + "\n")

lines = [
    f"verdict: {verdict}",
    f"slot {slot}  base={base_rev}  fix={fix_rev}  variant={variant}",
    f"tests: {tests}",
    f"build: base={'ok' if doc['build']['base'] else 'FAIL'} fix={'ok' if doc['build']['fix'] else 'FAIL'}",
    f"tests_fail_on_base={doc['tests_fail_on_base']}  tests_pass_on_fix={doc['tests_pass_on_fix']}",
]
if reason:
    lines.append(f"lab_broken_reason: {reason}")
if witness:
    lines.append(f"witness_lines ({len(witness)}):")
    lines += [f"  {w}" for w in witness]
lines.append("base_results:")
lines += [f"  {r['nodeid']}: {r['outcome']}" for r in doc["base_results"]] or ["  (none)"]
lines.append("fix_results:")
lines += [f"  {r['nodeid']}: {r['outcome']}" for r in doc["fix_results"]] or ["  (none)"]
pathlib.Path(outdir, "summary.txt").write_text("\n".join(lines) + "\n")
PY
    cat "$OUTDIR/summary.txt" 2>/dev/null || true
    exit "$exit_code"
}

job_lock_acquire "$SLOT" || { VERDICT="lab-broken"; LAB_BROKEN_REASON="could not acquire job lock on slot $SLOT"; write_verdict 2; }
trap job_lock_release EXIT

# --- (a) build-check both revs; abort with a verdict on any failure -------
echo "== build-check: base ($BASE_REV) =="
if ./build-check.sh "$BASE_REV" >"$OUTDIR/build-check-base.log" 2>&1; then
    BUILD_OK_BASE=1
else
    tail -60 "$OUTDIR/build-check-base.log"
    VERDICT="lab-broken"; LAB_BROKEN_REASON="build-check failed on base rev $BASE_REV"
    write_verdict 2
fi

echo "== build-check: fix ($FIX_REV) =="
if ./build-check.sh "$FIX_REV" >"$OUTDIR/build-check-fix.log" 2>&1; then
    BUILD_OK_FIX=1
else
    tail -60 "$OUTDIR/build-check-fix.log"
    VERDICT="lab-broken"; LAB_BROKEN_REASON="build-check failed on fix rev $FIX_REV"
    write_verdict 2
fi

# --- (b) export each rev into a temp tree ---------------------------------
TMPROOT="$(mktemp -d)"
cleanup_tmp() { rm -rf "$TMPROOT"; }
trap 'job_lock_release; cleanup_tmp' EXIT
rev_export "$BASE_REV" "$TMPROOT/base"
rev_export "$FIX_REV" "$TMPROOT/fix"
[ -d "$TMPROOT/fix/tests/functional" ] || { VERDICT="lab-broken"; LAB_BROKEN_REASON="fix rev has no tests/functional"; write_verdict 2; }

ensure_client_up || { VERDICT="lab-broken"; LAB_BROKEN_REASON="client on slot $SLOT would not come up"; write_verdict 2; }

# --- (c) base module, run the fix tree's tests against it ----------------
echo "== base: build/deploy/load =="
if ! module_build_deploy_load "$TMPROOT/base" "base" "$OUTDIR"; then
    VERDICT="lab-broken"; LAB_BROKEN_REASON="base module build/deploy/load failed"
    write_verdict 2
fi

echo "== base: run tests =="
run_phase_with_recovery "base-tests" "$OUTDIR" -- \
    run_pytest_phase "$TMPROOT/fix/tests/functional" "$TESTS" "base" "$OUTDIR" || true
BASE_PYTEST_RC="${PYTEST_RC:-90}"
BASE_RESULTS_JSON="$PYTEST_RESULTS_JSON"
collect_witness "base" "$PHASE_WITNESS_FILE"
if [ "$PHASE_PANICKED" = 1 ] && [ "$PHASE_RECOVERED" != 1 ]; then
    VERDICT="lab-broken"; LAB_BROKEN_REASON="client did not recover after the base-tests phase"
    write_verdict 2
fi
if [ "$BASE_PYTEST_RC" != 0 ] || python3 -c "
import json,sys
r=json.load(open('$BASE_RESULTS_JSON'))
sys.exit(0 if any(x.get('outcome')!='passed' for x in r) or not r else 1)
"; then
    TESTS_FAIL_ON_BASE="true"
fi

# --- (d) fix module, same tests -------------------------------------------
echo "== fix: build/deploy/load =="
if ! module_build_deploy_load "$TMPROOT/fix" "fix" "$OUTDIR"; then
    VERDICT="fail"; LAB_BROKEN_REASON="fix module build/deploy/load failed"
    write_verdict 1
fi

echo "== fix: run tests =="
run_phase_with_recovery "fix-tests" "$OUTDIR" -- \
    run_pytest_phase "$TMPROOT/fix/tests/functional" "$TESTS" "fix" "$OUTDIR" || true
FIX_PYTEST_RC="${PYTEST_RC:-90}"
FIX_RESULTS_JSON="$PYTEST_RESULTS_JSON"
collect_witness "fix" "$PHASE_WITNESS_FILE"
if [ "$PHASE_PANICKED" = 1 ] && [ "$PHASE_RECOVERED" != 1 ]; then
    VERDICT="lab-broken"; LAB_BROKEN_REASON="client did not recover after the fix-tests phase"
    write_verdict 2
fi
if [ "$FIX_PYTEST_RC" = 0 ] && [ -s "$FIX_RESULTS_JSON" ] && python3 -c "
import json,sys
r=json.load(open('$FIX_RESULTS_JSON'))
sys.exit(0 if r and all(x.get('outcome')=='passed' for x in r) else 1)
"; then
    TESTS_PASS_ON_FIX="true"
fi

# --- (f) verdict -----------------------------------------------------------
if [ "$TESTS_FAIL_ON_BASE" = "true" ] && [ "$TESTS_PASS_ON_FIX" = "true" ]; then
    VERDICT="pass"; write_verdict 0
else
    VERDICT="fail"; write_verdict 1
fi
