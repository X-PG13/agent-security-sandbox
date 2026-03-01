#!/usr/bin/env python3
"""
Analyze experiment results and generate comparison charts.

Usage:
    python experiments/analyze_results.py --results-dir experiments/results --output-dir experiments/results/figures
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("matplotlib and numpy are required. Install with: pip install matplotlib numpy")
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze and chart experiment results.")
    parser.add_argument("--results-dir", default=str(_SCRIPT_DIR / "results"))
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results" / "figures"))
    return parser.parse_args()


def load_results(results_dir: Path) -> Dict[str, Any]:
    """Load all JSON result files from directory."""
    results = {}
    for f in sorted(results_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            results[f.stem] = data
        except (json.JSONDecodeError, Exception):
            continue
    return results


def extract_defense_metrics(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract defense-level metrics from various result formats."""
    metrics = []

    for filename, data in results.items():
        if isinstance(data, dict):
            # Could be {defense_id: {metrics: ...}} or {defense: ..., metrics: ...}
            if "metrics" in data:
                m = data["metrics"]
                metrics.append({
                    "name": data.get("defense_name", data.get("defense", filename)),
                    "asr": m.get("asr", 0),
                    "bsr": m.get("bsr", 0),
                    "fpr": m.get("fpr", 0),
                })
            else:
                for key, val in data.items():
                    if isinstance(val, dict) and "metrics" in val:
                        m = val["metrics"]
                        metrics.append({
                            "name": key,
                            "asr": m.get("asr", 0),
                            "bsr": m.get("bsr", 0),
                            "fpr": m.get("fpr", 0),
                        })

    return metrics


def plot_asr_by_defense(metrics: List[Dict], output_dir: Path) -> None:
    names = [m["name"] for m in metrics]
    asr_vals = [m["asr"] for m in metrics]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(names, asr_vals, color="#e74c3c", alpha=0.8)
    ax.set_ylabel("Attack Success Rate")
    ax.set_title("ASR by Defense Strategy")
    ax.set_ylim(0, 1.05)
    for bar, val in zip(bars, asr_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.1%}", ha="center", fontsize=9)
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(output_dir / "asr_by_defense.png", dpi=150)
    plt.close(fig)
    print(f"  Saved asr_by_defense.png")


def plot_bsr_by_defense(metrics: List[Dict], output_dir: Path) -> None:
    names = [m["name"] for m in metrics]
    bsr_vals = [m["bsr"] for m in metrics]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(names, bsr_vals, color="#2ecc71", alpha=0.8)
    ax.set_ylabel("Benign Success Rate")
    ax.set_title("BSR by Defense Strategy")
    ax.set_ylim(0, 1.05)
    for bar, val in zip(bars, bsr_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.1%}", ha="center", fontsize=9)
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(output_dir / "bsr_by_defense.png", dpi=150)
    plt.close(fig)
    print(f"  Saved bsr_by_defense.png")


def plot_grouped_comparison(metrics: List[Dict], output_dir: Path) -> None:
    names = [m["name"] for m in metrics]
    asr = [m["asr"] for m in metrics]
    bsr = [m["bsr"] for m in metrics]
    fpr = [m["fpr"] for m in metrics]

    x = np.arange(len(names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width, asr, width, label="ASR", color="#e74c3c")
    ax.bar(x, bsr, width, label="BSR", color="#2ecc71")
    ax.bar(x + width, fpr, width, label="FPR", color="#f39c12")

    ax.set_ylabel("Rate")
    ax.set_title("Defense Strategy Comparison: ASR vs BSR vs FPR")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=30, ha="right")
    ax.set_ylim(0, 1.05)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / "grouped_comparison.png", dpi=150)
    plt.close(fig)
    print(f"  Saved grouped_comparison.png")


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        sys.exit(1)

    results = load_results(results_dir)
    if not results:
        print("No result files found.")
        sys.exit(1)

    print(f"Loaded {len(results)} result files")
    metrics = extract_defense_metrics(results)

    if not metrics:
        print("No defense metrics could be extracted.")
        sys.exit(1)

    print(f"Extracted metrics for {len(metrics)} defenses")
    print("Generating charts...")

    plot_asr_by_defense(metrics, output_dir)
    plot_bsr_by_defense(metrics, output_dir)
    plot_grouped_comparison(metrics, output_dir)

    print("\nDone!")


if __name__ == "__main__":
    main()
