#!/usr/bin/env bash
# Reproduce adaptive attack results (Table 4) from the paper.
#
# Usage:
#   ./scripts/reproduce_adaptive.sh --provider openai-compatible \
#       --base-url https://your-proxy.com/v1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROVIDER="mock"
BASE_URL=""
OUTPUT_DIR="$PROJECT_ROOT/results/adaptive_attack_v2"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)   PROVIDER="$2";   shift 2 ;;
        --base-url)   BASE_URL="$2";   shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

EXTRA=""
[[ -n "$BASE_URL" ]] && EXTRA="$EXTRA --base-url $BASE_URL"

echo "=== Reproducing Adaptive Attack Experiment ==="
echo "Provider: $PROVIDER"

cd "$PROJECT_ROOT"

python experiments/run_adaptive_attack.py \
    --all-defenses \
    --num-cases 20 \
    --max-iterations 10 \
    --attacker-model "${PROVIDER/mock/mock}" \
    --attacker-provider "$PROVIDER" \
    --agent-provider "$PROVIDER" \
    --benchmark-dir data/full_benchmark \
    --output-dir "$OUTPUT_DIR" \
    --run-static-baseline \
    $EXTRA

echo ""
echo "Done. Results in: $OUTPUT_DIR"
