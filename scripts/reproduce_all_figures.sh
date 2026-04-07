#!/usr/bin/env bash
# Reproduce the figures referenced by the submission.
#
# Usage:
#   ./scripts/reproduce_all_figures.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Generating Submission Figures ==="
cd "$PROJECT_ROOT"

python experiments/generate_figures.py 2>&1 | sed 's/^/    /'

echo ""
echo "=== Figure Generation Complete ==="
echo "Figures saved to: $PROJECT_ROOT/paper/figures"
echo ""
echo "Expected figures:"
echo "  pareto_frontier.pdf          - 11-defense security-utility tradeoff"
echo "  model_comparison.pdf         - Per-model ASR across 11 defenses"
