#!/usr/bin/env python3
"""Generate extended results table for all 11 defenses on the full 565-case benchmark.

Reads:
  - D0-D7 (gpt-4o, 1 run): results/full_565_supplement/
  - D8-D10 (4 models, 3 runs): results/unified_565/

Outputs:
  - paper/tables/extended_results_565.tex  (updated with D0-D7 + D8-D10)
  - Console summary

Usage:
    python experiments/generate_full_565_table.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent

DEFENSE_NAMES = {
    "D0": "Baseline",
    "D1": "Spotlighting",
    "D2": "Policy Gate",
    "D3": "Task Alignment",
    "D4": "Re-execution",
    "D5": "Sandwich",
    "D6": "Output Filter",
    "D7": "Input Classifier",
    "D8": "Semantic FW",
    "D9": "Dual-LLM",
    "D10": "CIV",
}

DEFENSE_ORDER = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]


def load_results(results_dir: str) -> dict:
    """Load results as {model: {defense: [run_data, ...]}}."""
    data: dict = defaultdict(lambda: defaultdict(list))
    rdir = Path(results_dir)
    if not rdir.exists():
        return dict(data)

    for f in sorted(rdir.glob("*.json")):
        name = f.stem
        if name in ("all_results", "experiment_config", "sensitivity_summary"):
            continue
        parts = name.rsplit("_", 2)
        if len(parts) < 3:
            continue
        model_part = "_".join(name.rsplit("_", 2)[:-2])
        defense_part = parts[-2]
        try:
            with open(f) as fh:
                d = json.load(fh)
            data[model_part][defense_part].append(d)
        except Exception:
            pass
    return dict(data)


def get_metrics(run_data: dict) -> dict:
    """Extract metrics from a run."""
    m = run_data.get("metrics", {})
    return {
        "asr": m.get("asr", 0),
        "bsr": m.get("bsr", 0),
        "fpr": m.get("fpr", 0),
        "num_cases": m.get("num_cases", 0),
    }


def main():
    # Load D0-D7 from full_565_supplement (gpt-4o only, 1 run)
    d07_data = load_results(str(_PROJECT_ROOT / "results" / "full_565_supplement"))
    # Load D8-D10 from unified_565 (4 models, 3 runs)
    d810_data = load_results(str(_PROJECT_ROOT / "results" / "unified_565"))

    print("=" * 70)
    print("FULL 565-CASE BENCHMARK RESULTS")
    print("=" * 70)

    # --- D0-D7: gpt-4o only, 1 run ---
    print("\n--- D0-D7 (GPT-4o, 1 run, 565 cases) ---")
    print(f"{'Defense':<20} {'ASR':>8} {'BSR':>8} {'FPR':>8} {'Cases':>6}")
    print("-" * 55)

    d07_metrics = {}
    gpt4o_d07 = d07_data.get("gpt-4o", {})
    for defense in ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"]:
        runs = gpt4o_d07.get(defense, [])
        if not runs:
            print(f"{defense:<20} {'N/A':>8} {'N/A':>8} {'N/A':>8}")
            continue
        m = get_metrics(runs[0])
        d07_metrics[defense] = m
        print(f"{DEFENSE_NAMES[defense]:<20} {m['asr']:>8.4f} {m['bsr']:>8.4f} {m['fpr']:>8.4f} {m['num_cases']:>6}")

    # --- D8-D10: gpt-4o averages from unified_565 ---
    print("\n--- D8-D10 (GPT-4o, 3-run avg, 565 cases) ---")
    print(f"{'Defense':<20} {'ASR':>8} {'BSR':>8} {'FPR':>8}")
    print("-" * 55)

    d810_metrics = {}
    gpt4o_d810 = d810_data.get("gpt-4o", {})
    for defense in ["D8", "D9", "D10"]:
        runs = gpt4o_d810.get(defense, [])
        if not runs:
            print(f"{defense:<20} {'N/A':>8} {'N/A':>8} {'N/A':>8}")
            continue
        avg_asr = sum(get_metrics(r)["asr"] for r in runs) / len(runs)
        avg_bsr = sum(get_metrics(r)["bsr"] for r in runs) / len(runs)
        avg_fpr = sum(get_metrics(r)["fpr"] for r in runs) / len(runs)
        d810_metrics[defense] = {"asr": avg_asr, "bsr": avg_bsr, "fpr": avg_fpr}
        print(f"{DEFENSE_NAMES[defense]:<20} {avg_asr:>8.4f} {avg_bsr:>8.4f} {avg_fpr:>8.4f}")

    # --- Combined table for all 11 defenses (GPT-4o on 565 cases) ---
    all_metrics = {**d07_metrics, **d810_metrics}

    if len(all_metrics) < 11:
        print(f"\nWARNING: Only {len(all_metrics)} defenses available (expected 11)")
        missing = [d for d in DEFENSE_ORDER if d not in all_metrics]
        print(f"Missing: {missing}")
        if not d07_metrics:
            print("D0-D7 results not yet available. Run P3 experiment first.")
            return

    # --- Generate LaTeX table ---
    print("\n" + "=" * 70)
    print("EXTENDED RESULTS TABLE (GPT-4o, 565 cases)")
    print("=" * 70)

    # Load 250-case results for comparison column
    d07_250 = load_results(str(_PROJECT_ROOT / "results" / "full_eval"))
    gpt4o_250 = d07_250.get("gpt-4o", {})

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{All 11 defenses on the full 565-case benchmark (GPT-4o). D0--D7: 1 run; D8--D10: 3-run average. Core-250 results (3-run avg) shown for comparison.}",
        r"\label{tab:extended_results}",
        r"\small",
        r"\begin{tabular}{llcccccc}",
        r"\toprule",
        r"& & \multicolumn{3}{c}{\textbf{Core 250}} & \multicolumn{3}{c}{\textbf{Full 565}} \\",
        r"\cmidrule(lr){3-5} \cmidrule(lr){6-8}",
        r"ID & \textbf{Defense} & ASR$\downarrow$ & BSR$\uparrow$ & FPR & ASR$\downarrow$ & BSR$\uparrow$ & FPR \\",
        r"\midrule",
    ]

    for defense in DEFENSE_ORDER:
        name = DEFENSE_NAMES[defense]

        # 250-case results (3-run avg)
        runs_250 = gpt4o_250.get(defense, [])
        if runs_250:
            asr_250 = sum(get_metrics(r)["asr"] for r in runs_250) / len(runs_250)
            bsr_250 = sum(get_metrics(r)["bsr"] for r in runs_250) / len(runs_250)
            fpr_250 = sum(get_metrics(r)["fpr"] for r in runs_250) / len(runs_250)
            col_250 = f"{asr_250:.3f} & {bsr_250:.3f} & {fpr_250:.3f}"
        else:
            col_250 = "--- & --- & ---"

        # 565-case results
        if defense in all_metrics:
            m = all_metrics[defense]
            col_565 = f"{m['asr']:.3f} & {m['bsr']:.3f} & {m['fpr']:.3f}"
        else:
            col_565 = "--- & --- & ---"

        lines.append(f"  {defense} & {name} & {col_250} & {col_565} \\\\")

        if defense == "D0":
            lines.append(r"\midrule")
        elif defense == "D7":
            lines.append(r"\midrule")

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])

    table = "\n".join(lines)
    print(table)

    out_path = _PROJECT_ROOT / "paper" / "tables" / "extended_results_565.tex"
    with open(out_path, "w") as f:
        f.write(table)
    print(f"\nSaved to {out_path}")

    # Also save JSON summary
    summary = {
        "benchmark": "full_565",
        "model": "gpt-4o",
        "d0_d7_runs": 1,
        "d8_d10_runs": 3,
        "metrics": {d: all_metrics.get(d, {}) for d in DEFENSE_ORDER},
    }
    json_path = _PROJECT_ROOT / "results" / "full_565_supplement" / "full_565_summary.json"
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved JSON to {json_path}")


if __name__ == "__main__":
    main()
