#!/usr/bin/env bash
# =============================================================================
# Philip E2E Test Runner
# =============================================================================
# Triggers the philip-e2e workflow on your self-hosted runner via gh CLI.
#
# Prerequisites:
#   gh auth login
#
# Usage:
#   run-e2e-test.sh <job> [--repeat N] [--attack]
#
# Jobs:
#   baseline   Normal CI build (go vet, go build, go test, lint)
#   docker     Docker build pipeline
#   python     Python CI pipeline
#   go         Go project pipeline
#   deploy     Deployment tools simulation
#   all        All jobs sequentially
#   status     Show recent workflow runs
#
# Options:
#   --repeat N   Run the job N times (default: 1)
#   --attack     Inject simulated malicious commands into the job
#
# Examples:
#   run-e2e-test.sh baseline --repeat 12         # train Philip with 12 baseline builds
#   run-e2e-test.sh docker                       # single docker build
#   run-e2e-test.sh go --attack                  # Go CI with injected attack
#   run-e2e-test.sh all --repeat 3               # all jobs, 3 times each
#   run-e2e-test.sh all --repeat 5 --attack      # all jobs with attacks, 5 times
# =============================================================================
set -euo pipefail

BRANCH="${BRANCH:-main}"
WORKFLOW="philip-e2e.yml"
ALL_JOBS=(baseline docker python go deploy)

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
    local job="$1"
    local iteration="$2"
    local attack="$3"

    local label="${job}"
    [ "$attack" = "true" ] && label="${job} (attack)"

    log "Dispatching: job=${label}  iteration=${iteration}"

    gh workflow run "${WORKFLOW}" \
        --repo "${REPO}" \
        --ref "${BRANCH}" \
        -f job="${job}" \
        -f iteration="${iteration}" \
        -f attack="${attack}"

    sleep 5

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
    gh run watch "${run_id}" --repo "${REPO}" --exit-status 2>/dev/null || true

    local conclusion
    conclusion=$(gh run view "${run_id}" --repo "${REPO}" --json conclusion -q '.conclusion' 2>/dev/null || echo "unknown")
    if [ "$conclusion" = "success" ]; then
        ok "${label} #${iteration} — passed"
    else
        warn "${label} #${iteration} — ${conclusion}"
    fi

    echo ""
    log "Philip report from this run:"
    gh run view "${run_id}" --repo "${REPO}" --log 2>/dev/null \
        | grep -A 50 "Philip Report" \
        | head -60 || warn "Could not extract report (check Actions tab)"
    echo ""
}

show_status() {
    echo ""
    log "Recent philip-e2e runs:"
    echo "----------------------------------------------"
    gh run list \
        --repo "${REPO}" \
        --workflow "${WORKFLOW}" \
        --limit 15 \
        --json displayTitle,status,conclusion,createdAt \
        -q '.[] | "\(.status)\t\(.conclusion // "-")\t\(.displayTitle)\t\(.createdAt)"' \
        2>/dev/null | column -t -s $'\t' || warn "Could not list runs"
    echo "----------------------------------------------"
    echo ""
    echo "To see Philip results from a specific run:"
    echo "  gh run view <run-id> --repo ${REPO} --log | grep -A 50 'Philip Report'"
}

usage() {
    echo "Usage: $0 <job> [--repeat N] [--attack]"
    echo ""
    echo "Jobs:"
    echo "  baseline   Normal CI build (go vet, go build, go test, lint)"
    echo "  docker     Docker build pipeline"
    echo "  python     Python CI pipeline"
    echo "  go         Go project pipeline"
    echo "  deploy     Deployment tools simulation"
    echo "  all        All jobs sequentially"
    echo "  status     Show recent workflow runs"
    echo ""
    echo "Options:"
    echo "  --repeat N   Run the job N times (default: 1)"
    echo "  --attack     Inject simulated malicious commands into the job"
    echo ""
    echo "Env vars:"
    echo "  BRANCH   Branch to test (default: main)"
    echo ""
    echo "Prerequisites: gh auth login"
    exit 1
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
REPEAT=1
ATTACK="false"
JOB=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repeat)
            REPEAT="${2:?--repeat requires a number}"
            shift 2
            ;;
        --attack)
            ATTACK="true"
            shift
            ;;
        --help|-h)
            usage
            ;;
        -*)
            echo "ERROR: Unknown option: $1"
            usage
            ;;
        *)
            if [ -z "$JOB" ]; then
                JOB="$1"
            else
                echo "ERROR: Unexpected argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

if [ -z "$JOB" ]; then
    usage
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
run_job() {
    local job="$1"
    local attack_label=""
    [ "$ATTACK" = "true" ] && attack_label=" + attack"

    echo "=============================================="
    echo " Job: ${job}${attack_label}"
    echo " Repo:   ${REPO}"
    echo " Branch: ${BRANCH}"
    echo "=============================================="
    echo ""

    for i in $(seq 1 "${REPEAT}"); do
        if [ "$REPEAT" -gt 1 ]; then
            log "=== Iteration ${i}/${REPEAT} ==="
        fi
        trigger_and_wait "$job" "$i" "$ATTACK"
    done

    ok "${job} complete (${REPEAT} run(s))"
}

case "$JOB" in
    baseline|docker|python|go|deploy)
        run_job "$JOB"
        ;;
    all)
        for job in "${ALL_JOBS[@]}"; do
            run_job "$job"
        done
        echo ""
        log "All jobs complete. Summary:"
        show_status
        ;;
    status)
        show_status
        ;;
    *)
        echo "ERROR: Unknown job: $JOB"
        echo "Valid jobs: baseline, docker, python, go, deploy, all, status"
        exit 1
        ;;
esac
