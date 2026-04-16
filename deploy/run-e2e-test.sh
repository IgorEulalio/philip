#!/usr/bin/env bash
# =============================================================================
# Philip E2E Test Runner (runs from your local machine)
# =============================================================================
# Triggers the philip-e2e workflow on your self-hosted runner via gh CLI.
# All Philip API queries happen inside the workflow (on the runner), so this
# script never needs direct access to the EC2.
#
# Prerequisites:
#   gh auth login  (one-time, browser-based — no tokens to export)
#
# Usage:
#   bash deploy/run-e2e-test.sh --baseline                # 12 normal builds to train Philip
#   bash deploy/run-e2e-test.sh --baseline --repeat 20   # 20 baseline builds
#   bash deploy/run-e2e-test.sh --attack                 # simulated supply chain attack
#   bash deploy/run-e2e-test.sh --mixed                  # benign build + one suspicious call
#   bash deploy/run-e2e-test.sh --full                   # all phases sequentially
#   bash deploy/run-e2e-test.sh --status                 # show recent runs
# =============================================================================
set -euo pipefail

BRANCH="${BRANCH:-main}"
BASELINE_RUNS="${BASELINE_RUNS:-12}"
WORKFLOW="philip-e2e.yml"

# Auto-detect repo
REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)
fi
if [ -z "$REPO" ]; then
    echo "ERROR: Cannot detect repository. Run from the repo dir or set GITHUB_REPOSITORY."
    exit 1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}>>>${NC} $*"; }
ok()   { echo -e "  ${GREEN}[OK]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; }

# ---------------------------------------------------------------------------
# Trigger a workflow run and wait for it to finish
# ---------------------------------------------------------------------------
trigger_and_wait() {
    local scenario="$1"
    local iteration="${2:-1}"

    log "Dispatching: scenario=${scenario}  iteration=${iteration}"

    gh workflow run "${WORKFLOW}" \
        --repo "${REPO}" \
        --ref "${BRANCH}" \
        -f scenario="${scenario}" \
        -f iteration="${iteration}"

    # Wait for GitHub to register the run
    sleep 5

    # Find the run ID we just created
    local run_id
    run_id=$(gh run list \
        --repo "${REPO}" \
        --workflow "${WORKFLOW}" \
        --limit 1 \
        --json databaseId \
        -q '.[0].databaseId' 2>/dev/null || echo "")

    if [ -z "$run_id" ]; then
        warn "Could not find run ID — check GitHub Actions tab manually"
        return 1
    fi

    log "Watching run ${run_id}..."
    # gh run watch streams live logs and blocks until completion
    gh run watch "${run_id}" --repo "${REPO}" --exit-status 2>/dev/null || true

    # Print the result
    local conclusion
    conclusion=$(gh run view "${run_id}" --repo "${REPO}" --json conclusion -q '.conclusion' 2>/dev/null || echo "unknown")
    if [ "$conclusion" = "success" ]; then
        ok "${scenario} #${iteration} — passed"
    else
        warn "${scenario} #${iteration} — ${conclusion}"
    fi

    # Show the Philip report step output
    echo ""
    log "Philip report from this run:"
    gh run view "${run_id}" --repo "${REPO}" --log 2>/dev/null \
        | grep -A 50 "Philip Report" \
        | head -60 || warn "Could not extract report (check Actions tab)"
    echo ""
}

# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
run_baseline() {
    echo "=============================================="
    echo " Phase 1: Baseline Training"
    echo " ${BASELINE_RUNS} normal builds → Philip learns typical behavior"
    echo " Baseline activates after 10 runs"
    echo "=============================================="
    echo ""

    for i in $(seq 1 "${BASELINE_RUNS}"); do
        trigger_and_wait "baseline" "$i"
    done

    ok "Baseline phase complete (${BASELINE_RUNS} runs)"
}

run_attack() {
    echo "=============================================="
    echo " Phase 2: Attack Simulation"
    echo " Reverse shells, credential access, exfiltration"
    echo " Philip should flag critical findings"
    echo "=============================================="
    echo ""

    trigger_and_wait "attack" "1"
}

run_mixed() {
    echo "=============================================="
    echo " Phase 3: Mixed Scenario"
    echo " Normal build + one suspicious network call"
    echo "=============================================="
    echo ""

    trigger_and_wait "mixed" "1"
}

run_full() {
    echo "=============================================="
    echo " Philip Full E2E"
    echo " Repo:   ${REPO}"
    echo " Branch: ${BRANCH}"
    echo "=============================================="
    echo ""

    run_baseline
    run_attack
    run_mixed

    echo ""
    log "Full E2E complete. Summary:"
    show_status
}

show_status() {
    echo ""
    log "Recent philip-e2e runs:"
    echo "----------------------------------------------"
    gh run list \
        --repo "${REPO}" \
        --workflow "${WORKFLOW}" \
        --limit 10 \
        --json displayTitle,status,conclusion,createdAt \
        -q '.[] | "\(.status)\t\(.conclusion // "-")\t\(.displayTitle)\t\(.createdAt)"' \
        2>/dev/null | column -t -s $'\t' || warn "Could not list runs"
    echo "----------------------------------------------"
    echo ""
    echo "To see Philip results from a specific run:"
    echo "  gh run view <run-id> --repo ${REPO} --log | grep -A 50 'Philip Report'"
}

# ---------------------------------------------------------------------------
# CLI — parse --repeat N from any position
# ---------------------------------------------------------------------------
REPEAT=1
COMMAND=""
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repeat)
            REPEAT="${2:?--repeat requires a number}"
            shift 2
            ;;
        *)
            args+=("$1")
            shift
            ;;
    esac
done

run_repeated() {
    local func="$1"
    if [ "$REPEAT" -le 1 ]; then
        "$func"
        return
    fi
    log "Running ${REPEAT} iterations..."
    for i in $(seq 1 "$REPEAT"); do
        echo ""
        log "=== Iteration ${i}/${REPEAT} ==="
        "$func"
    done
    ok "All ${REPEAT} iterations complete"
}

case "${args[0]:-}" in
    --baseline)
        # --repeat overrides BASELINE_RUNS for --baseline
        if [ "$REPEAT" -gt 1 ]; then
            BASELINE_RUNS="$REPEAT"
            run_baseline
        else
            run_baseline
        fi
        ;;
    --attack)   run_repeated run_attack   ;;
    --mixed)    run_repeated run_mixed    ;;
    --full)     run_repeated run_full     ;;
    --status)   show_status  ;;
    *)
        echo "Usage: $0 {--baseline|--attack|--mixed|--full|--status} [--repeat N]"
        echo ""
        echo "  --baseline   Train Philip with ${BASELINE_RUNS} normal builds"
        echo "  --attack     Simulate a supply chain attack"
        echo "  --mixed      Normal build + one suspicious action"
        echo "  --full       Run all three phases sequentially"
        echo "  --status     Show recent workflow runs"
        echo ""
        echo "Options:"
        echo "  --repeat N   Repeat the chosen scenario N times"
        echo ""
        echo "Env vars:"
        echo "  BASELINE_RUNS   Number of baseline runs (default: 12)"
        echo "  BRANCH          Branch to test (default: main)"
        echo ""
        echo "Prerequisites: gh auth login"
        exit 1
        ;;
esac
