#!/usr/bin/env bash
# Reproduce the main results table (Table 1) from the paper.
# Runs all 11 defenses (D0-D10) across all 4 models with 3 runs each.
#
# Usage:
#   ./scripts/reproduce_main_table.sh --provider openai-compatible \
#       --base-url https://your-proxy.com/v1
#
#   # Mock mode (smoke test, no API key)
#   ./scripts/reproduce_main_table.sh --provider mock
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROVIDER="mock"
BASE_URL=""
MODELS="gpt-4o claude-sonnet-4-5-20250929 deepseek-v3-1-250821 gemini-2.5-flash"
RUNS=3
OUTPUT_DIR="$PROJECT_ROOT/results/full_eval"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)   PROVIDER="$2";   shift 2 ;;
        --base-url)   BASE_URL="$2";   shift 2 ;;
        --models)     MODELS="$2";     shift 2 ;;
        --runs)       RUNS="$2";       shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

EXTRA=""
[[ -n "$BASE_URL" ]] && EXTRA="$EXTRA --base-url $BASE_URL"
[[ "$PROVIDER" == "mock" ]] && MODELS="mock" && RUNS=1

echo "=== Reproducing Main Results Table ==="
echo "Models: $MODELS | Runs: $RUNS | Provider: $PROVIDER"

cd "$PROJECT_ROOT"

python experiments/run_full_evaluation.py \
    --models $MODELS \
    --defenses D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 D10 \
    --runs "$RUNS" \
    --benchmark-dir data/full_benchmark \
    --output-dir "$OUTPUT_DIR" \
    --provider "$PROVIDER" \
    --resume \
    $EXTRA

echo ""
echo "=== Running Statistical Analysis ==="
python experiments/statistical_analysis.py \
    --results-dir "$OUTPUT_DIR" \
    --output-dir "$OUTPUT_DIR/stats"

echo ""
echo "=== Running Error Analysis ==="
python experiments/error_analysis.py \
    --results-dir "$OUTPUT_DIR" \
    --benchmark-dir data/full_benchmark \
    --output-dir "$OUTPUT_DIR/error_analysis"

echo ""
echo "Done. Results in: $OUTPUT_DIR"
