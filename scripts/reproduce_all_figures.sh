#!/usr/bin/env bash
# Reproduce all figures from the paper.
# Assumes results already exist in results/ directories.
#
# Usage:
#   ./scripts/reproduce_all_figures.sh
#   ./scripts/reproduce_all_figures.sh --output-dir figures/paper
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_DIR="$PROJECT_ROOT/figures"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

echo "=== Generating All Paper Figures ==="
echo "Output: $OUTPUT_DIR"

cd "$PROJECT_ROOT"

# Run attack type analysis first (generates data for heatmap)
if [[ -d results/full_eval ]]; then
    echo ""
    echo ">>> Running per-attack-type analysis..."
    python experiments/run_attack_type_analysis.py \
        --results-dir results/full_eval \
        --benchmark-dir data/full_benchmark \
        --output-dir results/attack_type_analysis \
        2>&1 | sed 's/^/    /'
fi

# Generate all figures
echo ""
echo ">>> Generating figures..."
python experiments/generate_figures.py \
    --results-dir results/full_eval \
    --stats-dir experiments/results/stats \
    --composition-dir results/composition \
    --adaptive-dir results/adaptive_attack \
    --ablation-dir results/civ_ablation \
    --attack-type-dir results/attack_type_analysis \
    --output-dir "$OUTPUT_DIR" \
    2>&1 | sed 's/^/    /'

echo ""
echo "=== Figure Generation Complete ==="
echo "Figures saved to: $OUTPUT_DIR"
echo ""
echo "Expected figures:"
echo "  fig_asr_bsr_tradeoff_*.pdf    - Security-Usability trade-off (per model)"
echo "  fig_asr_cost_*.pdf            - Security-Cost trade-off (per model)"
echo "  fig_pareto_*.pdf              - Pareto frontier (per model)"
echo "  fig_cross_model.pdf           - Cross-model comparison"
echo "  fig_attack_type_heatmap.pdf   - Defense x Attack type heatmap"
echo "  fig_adaptive_learning_curve.pdf - Adaptive attack learning curves"
echo "  fig_resilience_scores.pdf     - Defense resilience bar chart"
echo "  fig_civ_ablation.pdf          - CIV ablation study"
echo "  fig_composition_heatmap.pdf   - Composition study"
