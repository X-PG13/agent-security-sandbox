#!/usr/bin/env python3
"""
Generate publication-quality figures for the paper.

Produces 7 figures suitable for ACL/NeurIPS formatting:
  1. Security-Usability trade-off scatter (ASR vs BSR with error bars)
  2. Security-Cost trade-off scatter (ASR vs tokens)
  3. Defense composition heatmap
  4. Cross-model comparison grouped bar chart
  5. Attack technique analysis grouped bar chart
  6. Attack category stacked bar chart
  7. Pareto frontier analysis

Requirements: matplotlib, seaborn, numpy, pandas
    pip install matplotlib seaborn numpy pandas

Usage:
    python experiments/generate_figures.py \
        --results-dir results/full_eval \
        --stats-dir results/stats \
        --output-dir figures/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

try:
    import seaborn as sns
    HAS_SNS = True
except ImportError:
    HAS_SNS = False

try:
    import pandas as pd
    HAS_PD = True
except ImportError:
    HAS_PD = False

# ── Publication Style Constants ────────────────────────────────────────────

# ACL/NeurIPS column widths
SINGLE_COL_WIDTH = 3.3   # inches
DOUBLE_COL_WIDTH = 6.5   # inches
FONT_SIZE = 9
MARKER_SIZE = 60
DPI = 300

DEFENSE_COLORS = {
    "D0": "#808080",   # gray
    "D1": "#1f77b4",   # blue
    "D2": "#ff7f0e",   # orange
    "D3": "#2ca02c",   # green
    "D4": "#d62728",   # red
    "D5": "#9467bd",   # purple
}

DEFENSE_MARKERS = {
    "D0": "o", "D1": "s", "D2": "^", "D3": "D", "D4": "v", "D5": "P",
}

DEFENSE_LABELS = {
    "D0": "D0 (Baseline)",
    "D1": "D1 (Spotlighting)",
    "D2": "D2 (Policy Gate)",
    "D3": "D3 (Task Alignment)",
    "D4": "D4 (Re-execution)",
    "D5": "D5 (Sandwich)",
}


def _setup_style():
    """Configure matplotlib for publication-quality output."""
    plt.rcParams.update({
        "font.size": FONT_SIZE,
        "font.family": "serif",
        "axes.titlesize": FONT_SIZE + 1,
        "axes.labelsize": FONT_SIZE,
        "xtick.labelsize": FONT_SIZE - 1,
        "ytick.labelsize": FONT_SIZE - 1,
        "legend.fontsize": FONT_SIZE - 1,
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.05,
        "axes.grid": True,
        "grid.alpha": 0.3,
    })
    if HAS_SNS:
        sns.set_palette("colorblind")


def _load_json(path: Path) -> Any:
    with open(path) as f:
        return json.load(f)


# ── Figure 1: ASR vs BSR Trade-off ────────────────────────────────────────

def fig_asr_bsr_tradeoff(summary: Dict, output_dir: Path, model_filter: Optional[str] = None):
    """Security-Usability trade-off scatter plot."""
    fig, ax = plt.subplots(figsize=(SINGLE_COL_WIDTH, SINGLE_COL_WIDTH * 0.85))

    for key, data in summary.items():
        model, defense = key.split("|", 1) if "|" in key else ("unknown", key)
        if model_filter and model != model_filter:
            continue

        asr = data["asr_mean"]
        bsr = data["bsr_mean"]
        asr_ci = data.get("asr_ci", (asr, asr))
        bsr_ci = data.get("bsr_ci", (bsr, bsr))

        color = DEFENSE_COLORS.get(defense, "#333333")
        marker = DEFENSE_MARKERS.get(defense, "o")
        label = DEFENSE_LABELS.get(defense, defense)

        ax.scatter(asr, bsr, c=color, marker=marker, s=MARKER_SIZE,
                   label=label, zorder=5, edgecolors="white", linewidths=0.5)

        # Error bars (clamp to non-negative)
        xerr_lo = max(0, asr - asr_ci[0])
        xerr_hi = max(0, asr_ci[1] - asr)
        yerr_lo = max(0, bsr - bsr_ci[0])
        yerr_hi = max(0, bsr_ci[1] - bsr)
        ax.errorbar(asr, bsr,
                     xerr=[[xerr_lo], [xerr_hi]],
                     yerr=[[yerr_lo], [yerr_hi]],
                     fmt="none", ecolor=color, alpha=0.5, capsize=2)

    ax.set_xlabel("Attack Success Rate (ASR) " + r"$\downarrow$")
    ax.set_ylabel("Benign Success Rate (BSR) " + r"$\uparrow$")
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))

    # Ideal region annotation
    ax.annotate("Ideal", xy=(0.0, 1.0), fontsize=7, color="green", alpha=0.5,
                ha="left", va="top")

    ax.legend(loc="lower left", framealpha=0.9, fontsize=FONT_SIZE - 2)
    title = "Security-Usability Trade-off"
    if model_filter:
        title += f" ({model_filter})"
    ax.set_title(title)

    fig.tight_layout()
    suffix = f"_{model_filter}" if model_filter else ""
    fig.savefig(output_dir / f"fig_asr_bsr_tradeoff{suffix}.pdf")
    fig.savefig(output_dir / f"fig_asr_bsr_tradeoff{suffix}.png")
    plt.close(fig)
    print(f"  Saved fig_asr_bsr_tradeoff{suffix}")


# ── Figure 2: ASR vs Token Cost ───────────────────────────────────────────

def fig_asr_cost_tradeoff(summary: Dict, output_dir: Path, model_filter: Optional[str] = None):
    """Security-Cost trade-off scatter plot."""
    fig, ax = plt.subplots(figsize=(SINGLE_COL_WIDTH, SINGLE_COL_WIDTH * 0.85))

    for key, data in summary.items():
        model, defense = key.split("|", 1) if "|" in key else ("unknown", key)
        if model_filter and model != model_filter:
            continue

        asr = data["asr_mean"]
        tokens = data["tokens_mean"]
        color = DEFENSE_COLORS.get(defense, "#333333")
        marker = DEFENSE_MARKERS.get(defense, "o")
        label = DEFENSE_LABELS.get(defense, defense)

        ax.scatter(tokens, asr, c=color, marker=marker, s=MARKER_SIZE,
                   label=label, zorder=5, edgecolors="white", linewidths=0.5)

    ax.set_xlabel("Average Tokens per Evaluation")
    ax.set_ylabel("Attack Success Rate (ASR) " + r"$\downarrow$")
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.legend(loc="upper right", framealpha=0.9, fontsize=FONT_SIZE - 2)
    title = "Security-Cost Trade-off"
    if model_filter:
        title += f" ({model_filter})"
    ax.set_title(title)

    fig.tight_layout()
    suffix = f"_{model_filter}" if model_filter else ""
    fig.savefig(output_dir / f"fig_asr_cost{suffix}.pdf")
    fig.savefig(output_dir / f"fig_asr_cost{suffix}.png")
    plt.close(fig)
    print(f"  Saved fig_asr_cost{suffix}")


# ── Figure 3: Composition Heatmap ─────────────────────────────────────────

def fig_composition_heatmap(composition_data: Dict, output_dir: Path):
    """Heatmap of ASR for defense combinations."""
    if not HAS_SNS or not HAS_PD:
        print("  [SKIP] Composition heatmap requires seaborn and pandas")
        return

    # Parse composition data into a matrix
    combos = {}
    for key, data in composition_data.items():
        meta = data.get("_meta", {})
        name = meta.get("combination_name", key.rsplit("_run", 1)[0])
        metrics = data.get("metrics", {})
        asr = metrics.get("asr", 0)
        if name not in combos:
            combos[name] = []
        combos[name].append(asr)

    # Average across runs
    avg = {name: sum(v) / len(v) for name, v in combos.items()}

    # Build matrix: rows = num defenses, cols = combinations of that size
    if not avg:
        print("  [SKIP] No composition data")
        return

    names = sorted(avg.keys(), key=lambda x: (len(x.split("+")), x))
    values = [avg[n] for n in names]

    fig, ax = plt.subplots(figsize=(DOUBLE_COL_WIDTH, max(2, len(names) * 0.35)))
    colors = plt.cm.RdYlGn_r(np.array(values))
    bars = ax.barh(range(len(names)), values, color=colors, edgecolor="white")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=FONT_SIZE - 1)
    ax.set_xlabel("Attack Success Rate (ASR) " + r"$\downarrow$")
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_title("Defense Composition: ASR Comparison")
    ax.invert_yaxis()

    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, values)):
        ax.text(val + 0.01, i, f"{val:.1%}", va="center", fontsize=FONT_SIZE - 2)

    fig.tight_layout()
    fig.savefig(output_dir / "fig_composition_heatmap.pdf")
    fig.savefig(output_dir / "fig_composition_heatmap.png")
    plt.close(fig)
    print("  Saved fig_composition_heatmap")


# ── Figure 4: Cross-model Comparison ──────────────────────────────────────

def fig_cross_model_comparison(summary: Dict, output_dir: Path):
    """Grouped bar chart comparing defenses across models."""
    if not HAS_PD:
        print("  [SKIP] Cross-model comparison requires pandas")
        return

    # Parse data
    rows = []
    for key, data in summary.items():
        model, defense = key.split("|", 1) if "|" in key else ("unknown", key)
        rows.append({
            "Model": model, "Defense": defense,
            "ASR": data["asr_mean"], "BSR": data["bsr_mean"],
        })

    if not rows:
        return

    df = pd.DataFrame(rows)
    models = sorted(df["Model"].unique())
    defenses = sorted(df["Defense"].unique())

    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL_WIDTH, DOUBLE_COL_WIDTH * 0.4))

    for ax, metric, title in zip(axes, ["ASR", "BSR"],
                                  ["Attack Success Rate", "Benign Success Rate"]):
        x = np.arange(len(defenses))
        width = 0.8 / max(len(models), 1)

        for i, model in enumerate(models):
            model_data = df[df["Model"] == model]
            vals = [model_data[model_data["Defense"] == d][metric].values[0]
                    if len(model_data[model_data["Defense"] == d]) > 0 else 0
                    for d in defenses]
            ax.bar(x + i * width - 0.4 + width / 2, vals, width, label=model, alpha=0.85)

        ax.set_xticks(x)
        ax.set_xticklabels(defenses, rotation=45, ha="right")
        ax.set_ylabel(metric)
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
        ax.set_title(title)
        ax.legend(fontsize=FONT_SIZE - 2)

    fig.tight_layout()
    fig.savefig(output_dir / "fig_cross_model.pdf")
    fig.savefig(output_dir / "fig_cross_model.png")
    plt.close(fig)
    print("  Saved fig_cross_model")


# ── Figure 5: Attack Technique Analysis ───────────────────────────────────

def fig_attack_technique(attack_analysis: Dict, output_dir: Path):
    """Grouped bar chart of ASR by injection technique per defense."""
    if not HAS_PD:
        print("  [SKIP] Attack technique figure requires pandas")
        return

    rows = []
    for key, data in attack_analysis.items():
        defense = data.get("defense", "unknown")
        for technique, counts in data.get("by_technique", {}).items():
            total = counts.get("total", 0)
            succ = counts.get("succeeded", 0)
            asr = succ / total if total > 0 else 0
            rows.append({"Defense": defense, "Technique": technique, "ASR": asr})

    if not rows:
        print("  [SKIP] No attack technique data")
        return

    df = pd.DataFrame(rows)
    # Average across runs
    df = df.groupby(["Defense", "Technique"])["ASR"].mean().reset_index()

    techniques = sorted(df["Technique"].unique())
    defenses = sorted(df["Defense"].unique())

    fig, ax = plt.subplots(figsize=(DOUBLE_COL_WIDTH, DOUBLE_COL_WIDTH * 0.4))
    x = np.arange(len(techniques))
    width = 0.8 / max(len(defenses), 1)

    for i, defense in enumerate(defenses):
        ddf = df[df["Defense"] == defense]
        vals = [ddf[ddf["Technique"] == t]["ASR"].values[0]
                if len(ddf[ddf["Technique"] == t]) > 0 else 0
                for t in techniques]
        color = DEFENSE_COLORS.get(defense, None)
        ax.bar(x + i * width - 0.4 + width / 2, vals, width,
               label=DEFENSE_LABELS.get(defense, defense), color=color, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(techniques, rotation=45, ha="right", fontsize=FONT_SIZE - 2)
    ax.set_ylabel("ASR")
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.set_title("ASR by Injection Technique")
    ax.legend(fontsize=FONT_SIZE - 2, ncol=2)

    fig.tight_layout()
    fig.savefig(output_dir / "fig_attack_technique.pdf")
    fig.savefig(output_dir / "fig_attack_technique.png")
    plt.close(fig)
    print("  Saved fig_attack_technique")


# ── Figure 6: Attack Category Stacked Bar ─────────────────────────────────

def fig_attack_category_stacked(attack_analysis: Dict, output_dir: Path):
    """Stacked bar chart showing attack outcomes by attack type."""
    if not HAS_PD:
        print("  [SKIP] Stacked bar requires pandas")
        return

    rows = []
    for key, data in attack_analysis.items():
        defense = data.get("defense", "unknown")
        for atype, counts in data.get("by_attack_type", {}).items():
            rows.append({
                "Defense": defense, "Attack Type": atype,
                "Succeeded": counts.get("succeeded", 0),
                "Blocked": counts.get("blocked", 0),
            })

    if not rows:
        print("  [SKIP] No attack category data")
        return

    df = pd.DataFrame(rows)
    df = df.groupby(["Defense", "Attack Type"]).sum().reset_index()

    defenses = sorted(df["Defense"].unique())
    attack_types = sorted(df["Attack Type"].unique())

    fig, axes = plt.subplots(1, len(defenses),
                              figsize=(DOUBLE_COL_WIDTH, DOUBLE_COL_WIDTH * 0.35),
                              sharey=True)
    if len(defenses) == 1:
        axes = [axes]

    for ax, defense in zip(axes, defenses):
        ddf = df[df["Defense"] == defense]
        succeeded = [ddf[ddf["Attack Type"] == t]["Succeeded"].values[0]
                     if len(ddf[ddf["Attack Type"] == t]) > 0 else 0
                     for t in attack_types]
        blocked = [ddf[ddf["Attack Type"] == t]["Blocked"].values[0]
                   if len(ddf[ddf["Attack Type"] == t]) > 0 else 0
                   for t in attack_types]

        x = np.arange(len(attack_types))
        ax.bar(x, succeeded, label="Succeeded", color="#d62728", alpha=0.8)
        ax.bar(x, blocked, bottom=succeeded, label="Blocked", color="#2ca02c", alpha=0.8)
        ax.set_xticks(x)
        ax.set_xticklabels(attack_types, rotation=60, ha="right", fontsize=FONT_SIZE - 2)
        ax.set_title(DEFENSE_LABELS.get(defense, defense), fontsize=FONT_SIZE - 1)

    axes[0].set_ylabel("Cases")
    axes[-1].legend(fontsize=FONT_SIZE - 2, loc="upper right")
    fig.suptitle("Attack Outcomes by Category", fontsize=FONT_SIZE + 1)
    fig.tight_layout()
    fig.savefig(output_dir / "fig_attack_category_stacked.pdf")
    fig.savefig(output_dir / "fig_attack_category_stacked.png")
    plt.close(fig)
    print("  Saved fig_attack_category_stacked")


# ── Figure 7: Pareto Frontier ─────────────────────────────────────────────

def fig_pareto_frontier(summary: Dict, output_dir: Path, model_filter: Optional[str] = None):
    """Pareto frontier visualization for ASR vs BSR."""
    fig, ax = plt.subplots(figsize=(SINGLE_COL_WIDTH, SINGLE_COL_WIDTH * 0.85))

    points = []
    for key, data in summary.items():
        model, defense = key.split("|", 1) if "|" in key else ("unknown", key)
        if model_filter and model != model_filter:
            continue
        points.append((data["asr_mean"], data["bsr_mean"], defense))

    if not points:
        plt.close(fig)
        return

    # Find Pareto-optimal points (minimize ASR, maximize BSR)
    pareto = []
    for asr, bsr, defense in points:
        dominated = False
        for a2, b2, _ in points:
            if a2 <= asr and b2 >= bsr and (a2 < asr or b2 > bsr):
                dominated = True
                break
        if not dominated:
            pareto.append((asr, bsr, defense))

    # Plot all points
    for asr, bsr, defense in points:
        color = DEFENSE_COLORS.get(defense, "#333333")
        marker = DEFENSE_MARKERS.get(defense, "o")
        is_pareto = any(d == defense for _, _, d in pareto)
        alpha = 1.0 if is_pareto else 0.4
        size = MARKER_SIZE * 1.5 if is_pareto else MARKER_SIZE * 0.8
        ax.scatter(asr, bsr, c=color, marker=marker, s=size, alpha=alpha,
                   label=DEFENSE_LABELS.get(defense, defense),
                   zorder=5 if is_pareto else 3,
                   edgecolors="black" if is_pareto else "white",
                   linewidths=1.0 if is_pareto else 0.5)

    # Draw Pareto frontier line
    if len(pareto) > 1:
        pareto_sorted = sorted(pareto, key=lambda p: p[0])
        ax.plot([p[0] for p in pareto_sorted], [p[1] for p in pareto_sorted],
                "k--", alpha=0.3, linewidth=1)

    ax.set_xlabel("ASR " + r"$\downarrow$")
    ax.set_ylabel("BSR " + r"$\uparrow$")
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))

    # Remove duplicate legend entries
    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(by_label.values(), by_label.keys(),
              fontsize=FONT_SIZE - 2, loc="lower left")

    title = "Pareto Frontier"
    if model_filter:
        title += f" ({model_filter})"
    ax.set_title(title)

    fig.tight_layout()
    suffix = f"_{model_filter}" if model_filter else ""
    fig.savefig(output_dir / f"fig_pareto{suffix}.pdf")
    fig.savefig(output_dir / f"fig_pareto{suffix}.png")
    plt.close(fig)
    print(f"  Saved fig_pareto{suffix}")


# ── Main ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate paper-quality figures.")
    parser.add_argument("--results-dir", default=str(_PROJECT_ROOT / "results" / "full_eval"),
                        help="Directory with full evaluation results.")
    parser.add_argument("--stats-dir", default=str(_SCRIPT_DIR / "results" / "stats"),
                        help="Directory with statistical analysis output.")
    parser.add_argument("--composition-dir", default=str(_SCRIPT_DIR / "results"),
                        help="Directory with composition study results.")
    parser.add_argument("--attack-analysis-dir", default=str(_SCRIPT_DIR / "results" / "attack_analysis"),
                        help="Directory with attack analysis results.")
    parser.add_argument("--output-dir", default=str(_PROJECT_ROOT / "figures"),
                        help="Where to save figures.")
    parser.add_argument("--model", default=None,
                        help="Filter figures to a specific model.")
    return parser.parse_args()


def main() -> None:
    if not HAS_MPL:
        print("matplotlib is required. Install with: pip install matplotlib")
        sys.exit(1)

    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _setup_style()

    print("Generating figures...")

    # Load statistical summary
    stats_dir = Path(args.stats_dir)
    summary_path = stats_dir / "summary_with_ci.json"
    summary = {}
    if summary_path.exists():
        summary = _load_json(summary_path)
        print(f"  Loaded summary: {len(summary)} entries")

    # Load composition data
    comp_dir = Path(args.composition_dir)
    comp_path = comp_dir / "composition_all.json"
    composition_data = {}
    if comp_path.exists():
        composition_data = _load_json(comp_path)
        print(f"  Loaded composition: {len(composition_data)} entries")

    # Load attack analysis
    attack_dir = Path(args.attack_analysis_dir)
    attack_path = attack_dir / "attack_level_analysis.json"
    attack_data = {}
    if attack_path.exists():
        attack_data = _load_json(attack_path)
        print(f"  Loaded attack analysis: {len(attack_data)} entries")

    # Determine models present
    models = set()
    for key in summary:
        if "|" in key:
            models.add(key.split("|")[0])

    # Generate figures
    if summary:
        # Per-model figures
        for model in sorted(models):
            fig_asr_bsr_tradeoff(summary, output_dir, model_filter=model)
            fig_asr_cost_tradeoff(summary, output_dir, model_filter=model)
            fig_pareto_frontier(summary, output_dir, model_filter=model)

        # Combined (all models)
        if len(models) > 1:
            fig_cross_model_comparison(summary, output_dir)
    else:
        print("  [SKIP] No summary data -- run statistical_analysis.py first")

    if composition_data:
        fig_composition_heatmap(composition_data, output_dir)
    else:
        print("  [SKIP] No composition data -- run run_composition_study.py first")

    if attack_data:
        fig_attack_technique(attack_data, output_dir)
        fig_attack_category_stacked(attack_data, output_dir)
    else:
        print("  [SKIP] No attack analysis data -- run run_attack_levels.py first")

    print(f"\nAll figures saved to {output_dir}")


if __name__ == "__main__":
    main()
