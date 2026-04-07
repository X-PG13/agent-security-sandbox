#!/usr/bin/env python3
"""Generate publication-quality figures for the paper."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import PercentFormatter

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFENSE_NAMES = {
    "D0": "D0 Baseline", "D1": "D1 Spotlighting", "D2": "D2 Policy Gate",
    "D3": "D3 Task Align.", "D4": "D4 Re-execution", "D5": "D5 Sandwich",
    "D6": "D6 Output Filter", "D7": "D7 Input Class.",
    "D8": "D8 Semantic FW", "D9": "D9 Dual-LLM", "D10": "D10 CIV",
}
DEFENSE_COLORS = {
    "D0": "#888888",
    "D1": "#2196F3", "D5": "#1565C0", "D7": "#90CAF9",
    "D2": "#FF9800", "D3": "#FFB74D", "D4": "#F57C00",
    "D8": "#E91E63", "D9": "#F48FB1",
    "D6": "#4CAF50", "D10": "#9C27B0",
}
DEFENSE_MARKERS = {
    "D0": "X", "D1": "o", "D5": "s", "D7": "^",
    "D2": "D", "D3": "v", "D4": ">",
    "D8": "p", "D9": "h", "D6": "*", "D10": "P",
}
DEFENSES = ["D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","D10"]
MODELS = ["gpt-4o","claude-sonnet-4-5-20250929","deepseek-v3-1-250821","gemini-2.5-flash"]
MODEL_SHORT = {
    "gpt-4o": "GPT-4o",
    "claude-sonnet-4-5-20250929": "Claude 4.5",
    "deepseek-v3-1-250821": "DeepSeek V3.1",
    "gemini-2.5-flash": "Gemini 2.5",
}
MODEL_COLORS = {
    "gpt-4o": "#D32F2F",
    "claude-sonnet-4-5-20250929": "#2E7D32",
    "deepseek-v3-1-250821": "#1976D2",
    "gemini-2.5-flash": "#6A1B9A",
}
DEFENSE_LABELS = {
    "D0": "D0\nBase",
    "D1": "D1\nSpot",
    "D2": "D2\nGate",
    "D3": "D3\nAlign",
    "D4": "D4\nRe-exec",
    "D5": "D5\nSand",
    "D6": "D6\nOut",
    "D7": "D7\nIn",
    "D8": "D8\nSemFW",
    "D9": "D9\nDual",
    "D10": "D10\nCIV",
}

def load_unified_metrics():
    path = _PROJECT_ROOT / "results" / "stats" / "unified_metrics.json"
    with open(path) as f:
        return json.load(f)

def load_250_metrics():
    try:
        unified = load_unified_metrics()
        return unified.get("250_case", {})
    except Exception:
        metrics = {}
        for d in ["D0","D1","D2","D3","D4","D5","D6","D7"]:
            m_asrs, m_bsrs = [], []
            for m in MODELS:
                asrs, bsrs = [], []
                for r in range(1,4):
                    f = _PROJECT_ROOT/"results"/"full_eval"/f"{m}_{d}_run{r}.json"
                    try:
                        with open(f) as fh:
                            data = json.load(fh)
                        asrs.append(data["metrics"]["asr"])
                        bsrs.append(data["metrics"]["bsr"])
                    except Exception:
                        pass
                if asrs:
                    m_asrs.append(sum(asrs)/len(asrs))
                    m_bsrs.append(sum(bsrs)/len(bsrs))
            if m_asrs:
                metrics[d] = {"asr": sum(m_asrs)/len(m_asrs), "bsr": sum(m_bsrs)/len(m_bsrs)}
        return metrics


def load_per_model_metrics():
    unified = load_unified_metrics()
    per_model = {model: {} for model in MODELS}
    for defense, defense_metrics in unified.get("per_model_250", {}).items():
        for model, stats in defense_metrics.items():
            if model in per_model:
                per_model[model][defense] = stats
    return per_model


def plot_pareto(metrics, out_path):
    fig, ax = plt.subplots(figsize=(7, 5))
    for d in DEFENSES:
        if d not in metrics: continue
        m = metrics[d]
        ax.scatter(m["asr"], m["bsr"], c=DEFENSE_COLORS.get(d,"#333"),
                   marker=DEFENSE_MARKERS.get(d,"o"), s=120 if d!="D0" else 80,
                   zorder=5, edgecolors="black", linewidths=0.5, label=DEFENSE_NAMES[d])

    ax.axhline(y=0.8, color="#ccc", linestyle="--", linewidth=0.8)
    ax.axvline(x=0.1, color="#ccc", linestyle="--", linewidth=0.8)
    ax.text(0.03, 0.97, "Ideal\n(low ASR, high BSR)", transform=ax.transAxes,
            fontsize=8, color="#666", ha="left", va="top")
    ax.set_xlabel("Attack Success Rate (ASR) ↓", fontsize=11)
    ax.set_ylabel("Benign Success Rate (BSR) ↑", fontsize=11)
    ax.set_xlim(-0.02, 0.55)
    ax.set_ylim(0.3, 1.0)
    ax.legend(fontsize=8, loc="lower left", ncol=2, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    ax.set_title("Security-Utility Trade-off (250-case, 4-model avg)", fontsize=12)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out_path}")


def plot_model_comparison(per_model_metrics, out_path):
    """Line chart of per-model ASR across all defenses."""
    fig, ax = plt.subplots(figsize=(7.2, 4.3))
    x = np.arange(len(DEFENSES))

    for model in MODELS:
        y = [per_model_metrics.get(model, {}).get(defense, {}).get("asr", np.nan) for defense in DEFENSES]
        ax.plot(
            x,
            y,
            marker="o",
            markersize=5,
            linewidth=2,
            color=MODEL_COLORS[model],
            label=MODEL_SHORT[model],
        )

    ax.set_xlabel("Defense", fontsize=11)
    ax.set_ylabel("Attack Success Rate (ASR) ↓", fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels([DEFENSE_LABELS[d] for d in DEFENSES], fontsize=9)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
    ax.set_ylim(0, 0.58)
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend(fontsize=9, ncol=2, framealpha=0.9)
    ax.set_title("Per-Model ASR Across 11 Defenses", fontsize=12)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {out_path}")


def main():
    fig_dir = _PROJECT_ROOT / "paper" / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    metrics = load_250_metrics()
    per_model_metrics = load_per_model_metrics()
    print("Loaded metrics for:", list(metrics.keys()))
    plot_pareto(metrics, fig_dir / "pareto_frontier.pdf")
    plot_model_comparison(per_model_metrics, fig_dir / "model_comparison.pdf")


if __name__ == "__main__":
    main()
