#!/usr/bin/env bash
# ============================================================================
# reproduce.sh — One-click experiment reproduction for Agent Security Sandbox
#
# Usage:
#   # Full reproduction with a real LLM (requires API access):
#   ./scripts/reproduce.sh --provider openai-compatible \
#       --base-url https://your-proxy.com/v1 --model gpt-4o
#
#   # Quick smoke test with mock LLM (no API key needed):
#   ./scripts/reproduce.sh --provider mock
#
#   # Specify custom output directory:
#   ./scripts/reproduce.sh --provider mock --output-dir results/my_run
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
PROVIDER="mock"
MODEL=""
BASE_URL=""
OUTPUT_DIR="$PROJECT_ROOT/results/reproduce_$(date +%Y%m%d_%H%M%S)"
RUNS=1
BENCHMARK_DIR="$PROJECT_ROOT/data/full_benchmark"
NO_FC=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)    PROVIDER="$2";       shift 2 ;;
        --model)       MODEL="$2";          shift 2 ;;
        --base-url)    BASE_URL="$2";       shift 2 ;;
        --output-dir)  OUTPUT_DIR="$2";     shift 2 ;;
        --runs)        RUNS="$2";           shift 2 ;;
        --benchmark)   BENCHMARK_DIR="$2";  shift 2 ;;
        --no-function-calling) NO_FC="--no-function-calling"; shift ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --provider PROVIDER    LLM provider (mock|openai-compatible)"
            echo "  --model MODEL          Model name (e.g. gpt-4o)"
            echo "  --base-url URL         OpenAI-compatible API base URL"
            echo "  --output-dir DIR       Output directory for results"
            echo "  --runs N               Number of runs per configuration (default: 1)"
            echo "  --benchmark DIR        Benchmark directory (default: data/full_benchmark)"
            echo "  --no-function-calling  Use text ReAct mode instead of function calling"
            echo "  -h, --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Build extra args
EXTRA_ARGS=""
if [[ -n "$MODEL" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --model $MODEL"
fi
if [[ -n "$BASE_URL" ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --base-url $BASE_URL"
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "Agent Security Sandbox — Experiment Reproduction"
echo "============================================================"
echo "Provider:      $PROVIDER"
echo "Model:         ${MODEL:-<default>}"
echo "Benchmark:     $BENCHMARK_DIR"
echo "Output:        $OUTPUT_DIR"
echo "Runs per cfg:  $RUNS"
echo "Function call: ${NO_FC:-enabled}"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Step 0: Environment check
# ---------------------------------------------------------------------------
echo ">>> Step 0: Checking environment..."
cd "$PROJECT_ROOT"

python -c "import agent_security_sandbox; print(f'Package version: {agent_security_sandbox.__version__}')" 2>/dev/null \
    || python -c "print('Package importable: OK'); import agent_security_sandbox"

python -m pytest tests/ -q --tb=no 2>&1 | tail -1
echo ""

# ---------------------------------------------------------------------------
# Step 1: Run full evaluation (all defenses × benchmark)
# ---------------------------------------------------------------------------
DEFENSES="D0 D1 D2 D3 D4 D5"

echo ">>> Step 1: Full defense evaluation"
echo "    Defenses: $DEFENSES"
echo ""

for D in $DEFENSES; do
    RESULT_FILE="$OUTPUT_DIR/eval_${D}.json"
    echo "  [$D] Running..."
    python experiments/run_full_evaluation.py \
        --provider "$PROVIDER" \
        $EXTRA_ARGS \
        --benchmark-dir "$BENCHMARK_DIR" \
        --defense "$D" \
        --output "$RESULT_FILE" \
        --runs "$RUNS" \
        $NO_FC \
        2>&1 | sed 's/^/    /'
    echo "  [$D] Done -> $RESULT_FILE"
    echo ""
done

# ---------------------------------------------------------------------------
# Step 2: Defense composition study
# ---------------------------------------------------------------------------
echo ">>> Step 2: Defense composition study"
COMP_DIR="$OUTPUT_DIR/composition"

python experiments/run_composition_study.py \
    --provider "$PROVIDER" \
    $EXTRA_ARGS \
    --benchmark-dir "$BENCHMARK_DIR" \
    --output-dir "$COMP_DIR" \
    --runs "$RUNS" \
    $NO_FC \
    2>&1 | sed 's/^/    /'
echo ""

# ---------------------------------------------------------------------------
# Step 3: Statistical analysis
# ---------------------------------------------------------------------------
echo ">>> Step 3: Statistical analysis"
STATS_DIR="$OUTPUT_DIR/stats"
mkdir -p "$STATS_DIR"

if [[ -f experiments/statistical_analysis.py ]]; then
    python experiments/statistical_analysis.py \
        --results-dir "$OUTPUT_DIR" \
        --output-dir "$STATS_DIR" \
        2>&1 | sed 's/^/    /' || echo "    [WARNING] Statistical analysis failed (may need real results)"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Generate figures
# ---------------------------------------------------------------------------
echo ">>> Step 4: Generate figures"
FIGURES_DIR="$OUTPUT_DIR/figures"
mkdir -p "$FIGURES_DIR"

if [[ -f experiments/generate_figures.py ]]; then
    python experiments/generate_figures.py \
        --results-dir "$OUTPUT_DIR" \
        --output-dir "$FIGURES_DIR" \
        2>&1 | sed 's/^/    /' || echo "    [WARNING] Figure generation failed (may need matplotlib)"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================================"
echo "REPRODUCTION COMPLETE"
echo "============================================================"
echo "Results directory: $OUTPUT_DIR"
echo ""
echo "Contents:"
find "$OUTPUT_DIR" -type f -name "*.json" -o -name "*.png" -o -name "*.pdf" | sort | sed 's/^/  /'
echo ""
echo "To analyze results interactively:"
echo "  python experiments/analyze_results.py --results-dir $OUTPUT_DIR"
echo "============================================================"
