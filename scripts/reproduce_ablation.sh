#!/usr/bin/env bash
# Reproduce CIV ablation results (Table 3) from the paper.
#
# Usage:
#   ./scripts/reproduce_ablation.sh --provider openai-compatible \
#       --base-url https://your-proxy.com/v1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROVIDER="mock"
BASE_URL=""
MODELS="gpt-4o claude-sonnet-4-5-20250929 deepseek-v3-1-250821 gemini-2.5-flash"
OUTPUT_DIR="$PROJECT_ROOT/results/civ_ablation"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)   PROVIDER="$2";   shift 2 ;;
        --base-url)   BASE_URL="$2";   shift 2 ;;
        --models)     MODELS="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

EXTRA=""
[[ -n "$BASE_URL" ]] && EXTRA="$EXTRA --base-url $BASE_URL"
[[ "$PROVIDER" == "mock" ]] && MODELS="mock"

echo "=== Reproducing CIV Ablation Study ==="
echo "Models: $MODELS | Provider: $PROVIDER"

cd "$PROJECT_ROOT"

python experiments/run_civ_ablation.py \
    --models $MODELS \
    --runs 1 \
    --benchmark-dir data/full_benchmark \
    --output-dir "$OUTPUT_DIR" \
    --provider "$PROVIDER" \
    --resume \
    $EXTRA

echo ""
echo "Done. Results in: $OUTPUT_DIR"
