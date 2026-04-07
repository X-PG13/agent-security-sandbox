#!/usr/bin/env python3
"""Unified statistical analysis across all defenses on matched 250-case subset.

Extracts the 250-case core subset from D8-D10 565-case results for fair
cross-defense comparison. Computes:
  - Per-defense ASR/BSR/FPR with Wilson score 95% CIs
  - Pairwise McNemar tests (D0 vs each defense)
  - Cross-model summary table (LaTeX)

Usage:
    python experiments/unified_statistical_analysis.py \
        --results-dir results/full_eval \
        --results-565-dir results/unified_565 \
        --core-benchmark data/benchmarks \
        --output-dir paper/tables
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add project root to path
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# ---------------------------------------------------------------------------
# Wilson score CI
# ---------------------------------------------------------------------------

def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score 95% confidence interval for a proportion."""
    if total == 0:
        return (0.0, 0.0)
    p_hat = successes / total
    denom = 1 + z * z / total
    centre = (p_hat + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * total)) / total) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


# ---------------------------------------------------------------------------
# McNemar's test
# ---------------------------------------------------------------------------

def mcnemar_test(verdicts_a: List[str], verdicts_b: List[str]) -> Dict[str, Any]:
    """McNemar's test comparing two defense verdict lists on the same cases.

    For attack cases: success = attack_succeeded
    Returns chi2, p-value, and the contingency counts.
    """
    assert len(verdicts_a) == len(verdicts_b), "Verdict lists must be same length"
    # b = A correct & B wrong, c = A wrong & B correct
    b = 0  # A blocked, B succeeded
    c = 0  # A succeeded, B blocked
    for va, vb in zip(verdicts_a, verdicts_b):
        a_succ = (va == "attack_succeeded")
        b_succ = (vb == "attack_succeeded")
        if not a_succ and b_succ:
            b += 1
        elif a_succ and not b_succ:
            c += 1

    # McNemar chi-squared (with continuity correction)
    if b + c == 0:
        return {"chi2": 0.0, "p_value": 1.0, "b": b, "c": c, "significant": False}

    chi2 = (abs(b - c) - 1) ** 2 / (b + c)

    # p-value from chi-squared distribution with 1 df
    # Using scipy if available, otherwise approximate
    try:
        from scipy.stats import chi2 as chi2_dist
        p_value = 1 - chi2_dist.cdf(chi2, df=1)
    except ImportError:
        # Simple approximation for large chi2
        p_value = math.exp(-chi2 / 2) if chi2 > 0 else 1.0

    return {
        "chi2": chi2,
        "p_value": p_value,
        "b": b, "c": c,
        "significant": p_value < 0.05,
    }


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_results(results_dir: str) -> Dict[str, Dict[str, List[Dict]]]:
    """Load results as {model: {defense: [run_data, ...]}}."""
    data: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))

    for f in sorted(Path(results_dir).glob("*.json")):
        name = f.stem
        if name in ("all_results", "experiment_config", "all_results.json"):
            continue

        parts = name.rsplit("_", 2)  # model_defense_runN
        if len(parts) < 3:
            continue

        run_part = parts[-1]
        defense_part = parts[-2]
        model_part = "_".join(name.rsplit("_", 2)[:-2])

        try:
            with open(f) as fh:
                d = json.load(fh)
            data[model_part][defense_part].append(d)
        except Exception:
            pass

    return dict(data)


def get_core_case_ids(results_250: Dict) -> set:
    """Extract the set of case IDs from 250-case results."""
    ids = set()
    for model_data in results_250.values():
        for defense_runs in model_data.values():
            for run in defense_runs:
                for r in run.get("results", []):
                    ids.add(r["case_id"])
            if ids:
                return ids
    return ids


def extract_matched_subset(run_data: Dict, core_ids: set) -> Dict:
    """Filter a 565-case run to only the 250 core case IDs."""
    results = run_data.get("results", [])
    filtered = [r for r in results if r["case_id"] in core_ids]

    # Recompute metrics
    attack_succeeded = sum(1 for r in filtered if r["verdict"] == "attack_succeeded")
    attack_blocked = sum(1 for r in filtered if r["verdict"] == "attack_blocked")
    benign_completed = sum(1 for r in filtered if r["verdict"] == "benign_completed")
    benign_blocked = sum(1 for r in filtered if r["verdict"] == "benign_blocked")

    total_attack = attack_succeeded + attack_blocked
    total_benign = benign_completed + benign_blocked

    asr = attack_succeeded / total_attack if total_attack > 0 else 0.0
    bsr = benign_completed / total_benign if total_benign > 0 else 0.0
    fpr = benign_blocked / total_benign if total_benign > 0 else 0.0

    return {
        "results": filtered,
        "metrics": {
            "asr": asr, "bsr": bsr, "fpr": fpr,
            "num_cases": len(filtered),
            "attack_cases": total_attack,
            "benign_cases": total_benign,
            "details": {
                "attack_succeeded": attack_succeeded,
                "attack_blocked": attack_blocked,
                "benign_completed": benign_completed,
                "benign_blocked": benign_blocked,
            },
        },
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Unified statistical analysis")
    parser.add_argument("--results-dir", default="results/full_eval",
                        help="Directory with D0-D7 250-case results")
    parser.add_argument("--results-565-dir", default="results/unified_565",
                        help="Directory with D8-D10 565-case results")
    parser.add_argument("--results-v2-dir", default="results/full_eval_v2",
                        help="Directory with D10 v2 results")
    parser.add_argument("--output-dir", default="paper/tables",
                        help="Output directory for LaTeX tables")
    args = parser.parse_args()

    os.chdir(_PROJECT_ROOT)

    print("Loading 250-case results...")
    data_250 = load_results(args.results_dir)

    print("Loading 565-case results...")
    data_565 = load_results(args.results_565_dir)

    print("Loading v2 results...")
    data_v2 = load_results(args.results_v2_dir)

    # Get core 250-case IDs
    core_ids = get_core_case_ids(data_250)
    print(f"Core case IDs: {len(core_ids)}")

    # Models to include (exclude gpt-4o-mini which has only 1 run)
    models = ["gpt-4o", "claude-sonnet-4-5-20250929", "deepseek-v3-1-250821", "gemini-2.5-flash"]
    model_short = {
        "gpt-4o": "GPT-4o",
        "claude-sonnet-4-5-20250929": "Claude 4.5",
        "deepseek-v3-1-250821": "DeepSeek V3.1",
        "gemini-2.5-flash": "Gemini 2.5",
    }
    defenses = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]

    # Merge D8-D10 matched subset into data_250
    for model in models:
        for source in [data_565, data_v2]:
            if model not in source:
                continue
            for defense in ["D8", "D9", "D10"]:
                if defense not in source[model]:
                    continue
                matched_runs = []
                for run in source[model][defense]:
                    if run.get("metrics", {}).get("num_cases", 0) > 300:
                        matched_runs.append(extract_matched_subset(run, core_ids))
                    else:
                        matched_runs.append(run)
                if matched_runs:
                    # Use v2 results for D10 if available
                    if defense == "D10" and model in data_v2 and defense in data_v2[model]:
                        data_250.setdefault(model, {})[defense] = matched_runs
                    elif defense not in data_250.get(model, {}):
                        data_250.setdefault(model, {})[defense] = matched_runs

    # ---- Compute per-defense aggregated metrics ----
    print("\n" + "=" * 80)
    print("UNIFIED RESULTS (all defenses on matched 250-case subset)")
    print("=" * 80)

    # Table: defense × metric, averaged across models and runs
    defense_stats: Dict[str, Dict[str, Any]] = {}
    per_model_stats: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))

    for defense in defenses:
        all_asrs, all_bsrs, all_fprs = [], [], []
        attack_succ_total, attack_total = 0, 0
        benign_comp_total, benign_total = 0, 0

        for model in models:
            model_runs = data_250.get(model, {}).get(defense, [])
            if not model_runs:
                continue

            m_asrs = [r["metrics"]["asr"] for r in model_runs]
            m_bsrs = [r["metrics"]["bsr"] for r in model_runs]
            m_fprs = [r["metrics"]["fpr"] for r in model_runs]

            avg_asr = sum(m_asrs) / len(m_asrs)
            avg_bsr = sum(m_bsrs) / len(m_bsrs)
            avg_fpr = sum(m_fprs) / len(m_fprs)

            per_model_stats[model][defense] = {
                "asr": avg_asr, "bsr": avg_bsr, "fpr": avg_fpr,
                "runs": len(model_runs),
            }

            all_asrs.append(avg_asr)
            all_bsrs.append(avg_bsr)
            all_fprs.append(avg_fpr)

            # Aggregate counts for CIs
            for run in model_runs:
                det = run["metrics"].get("details", {})
                attack_succ_total += det.get("attack_succeeded", 0)
                attack_total += det.get("attack_succeeded", 0) + det.get("attack_blocked", 0)
                benign_comp_total += det.get("benign_completed", 0)
                benign_total += det.get("benign_completed", 0) + det.get("benign_blocked", 0)

        if not all_asrs:
            continue

        avg_asr = sum(all_asrs) / len(all_asrs)
        avg_bsr = sum(all_bsrs) / len(all_bsrs)
        avg_fpr = sum(all_fprs) / len(all_fprs)

        asr_ci = wilson_ci(attack_succ_total, attack_total)
        bsr_ci = wilson_ci(benign_comp_total, benign_total)

        defense_stats[defense] = {
            "avg_asr": avg_asr,
            "avg_bsr": avg_bsr,
            "avg_fpr": avg_fpr,
            "asr_ci": asr_ci,
            "bsr_ci": bsr_ci,
            "n_models": len(all_asrs),
            "asr_reduction": (1 - avg_asr / defense_stats.get("D0", {}).get("avg_asr", avg_asr)) * 100
            if defense != "D0" and "D0" in defense_stats else 0,
        }

        print(f"\n{defense}: ASR={avg_asr:.3f} [{asr_ci[0]:.3f}, {asr_ci[1]:.3f}]  "
              f"BSR={avg_bsr:.3f} [{bsr_ci[0]:.3f}, {bsr_ci[1]:.3f}]  "
              f"FPR={avg_fpr:.3f}  (N_models={len(all_asrs)})")

    # ---- McNemar tests: D0 vs each defense ----
    print("\n" + "=" * 80)
    print("McNEMAR TESTS (D0 vs each defense, per model)")
    print("=" * 80)

    for model in models:
        d0_runs = data_250.get(model, {}).get("D0", [])
        if not d0_runs:
            continue

        # Use run1 for pairwise comparison
        d0_verdicts = {r["case_id"]: r["verdict"] for r in d0_runs[0].get("results", [])}
        d0_attack_verdicts = {k: v for k, v in d0_verdicts.items()
                              if v in ("attack_succeeded", "attack_blocked")}

        print(f"\n{model_short.get(model, model)}:")
        for defense in defenses:
            if defense == "D0":
                continue
            d_runs = data_250.get(model, {}).get(defense, [])
            if not d_runs:
                print(f"  D0 vs {defense}: NO DATA")
                continue

            d_verdicts = {r["case_id"]: r["verdict"] for r in d_runs[0].get("results", [])}

            # Match attack cases only
            common_ids = sorted(set(d0_attack_verdicts.keys()) & set(d_verdicts.keys()))
            if not common_ids:
                print(f"  D0 vs {defense}: no common attack cases")
                continue

            va = [d0_attack_verdicts[cid] for cid in common_ids]
            vb = [d_verdicts[cid] for cid in common_ids]

            result = mcnemar_test(va, vb)
            sig = "***" if result["p_value"] < 0.001 else "**" if result["p_value"] < 0.01 else "*" if result["p_value"] < 0.05 else "ns"
            print(f"  D0 vs {defense}: χ²={result['chi2']:.2f}, p={result['p_value']:.4f} {sig}  "
                  f"(b={result['b']}, c={result['c']})")

    # ---- Generate unified LaTeX table ----
    print("\n" + "=" * 80)
    print("GENERATING UNIFIED LATEX TABLE")
    print("=" * 80)

    defense_names = {
        "D0": "Baseline", "D1": "Spotlighting", "D2": "Policy Gate",
        "D3": "Task Alignment", "D4": "Re-execution", "D5": "Sandwich",
        "D6": "Output Filter", "D7": "Input Classifier",
        "D8": "Semantic FW", "D9": "Dual-LLM", "D10": "CIV",
    }

    latex_lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Unified comparison of all 11 defenses on the 250-case core benchmark, averaged across 4 frontier models $\times$ 3 runs. ASR and BSR with 95\% Wilson CIs.}",
        r"\label{tab:unified_results}",
        r"\small",
        r"\begin{tabular}{llccccc}",
        r"\toprule",
        r"ID & Defense & Avg ASR $\downarrow$ & 95\% CI & Avg BSR $\uparrow$ & 95\% CI & ASR Red. \\",
        r"\midrule",
    ]

    for defense in defenses:
        if defense not in defense_stats:
            continue
        s = defense_stats[defense]
        name = defense_names.get(defense, defense)
        asr = s["avg_asr"]
        bsr = s["avg_bsr"]
        asr_ci = s["asr_ci"]
        bsr_ci = s["bsr_ci"]
        red = s.get("asr_reduction", 0)

        # Bold best ASR
        asr_str = f"{asr:.3f}"
        bsr_str = f"{bsr:.3f}"
        if defense == "D5":
            asr_str = r"\textbf{" + asr_str + "}"
            bsr_str = r"\textbf{" + bsr_str + "}"

        red_str = f"$-${abs(red):.1f}\\%" if red > 0 else (f"$+${abs(red):.1f}\\%" if red < 0 else "---")

        latex_lines.append(
            f"  {defense} & {name} & {asr_str} & [{asr_ci[0]:.3f}, {asr_ci[1]:.3f}] "
            f"& {bsr_str} & [{bsr_ci[0]:.3f}, {bsr_ci[1]:.3f}] & {red_str} \\\\"
        )

        if defense == "D0":
            latex_lines.append(r"\midrule")

    latex_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])

    unified_table = "\n".join(latex_lines)
    print(unified_table)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    out_path = output_dir / "unified_results_250.tex"
    with open(out_path, "w") as f:
        f.write(unified_table)
    print(f"\nSaved to {out_path}")

    # ---- Per-model table ----
    per_model_lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Per-model ASR on the 250-case core benchmark (3-run average). All 11 defenses compared on the same case set.}",
        r"\label{tab:per_model_unified}",
        r"\small",
        r"\begin{tabular}{l" + "c" * len(models) + "c}",
        r"\toprule",
        "Defense & " + " & ".join(model_short.get(m, m) for m in models) + r" & Avg \\",
        r"\midrule",
    ]

    for defense in defenses:
        if defense not in defense_stats:
            continue
        row = [defense_names.get(defense, defense)]
        vals = []
        for model in models:
            s = per_model_stats.get(model, {}).get(defense, {})
            asr = s.get("asr", float("nan"))
            vals.append(asr)
            row.append(f"{asr:.3f}" if not math.isnan(asr) else "---")
        valid = [v for v in vals if not math.isnan(v)]
        avg = sum(valid) / len(valid) if valid else float("nan")
        row.append(f"{avg:.3f}" if not math.isnan(avg) else "---")
        per_model_lines.append("  " + " & ".join(row) + r" \\")
        if defense == "D0":
            per_model_lines.append(r"\midrule")

    per_model_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])

    per_model_table = "\n".join(per_model_lines)
    pm_path = output_dir / "per_model_asr_unified.tex"
    with open(pm_path, "w") as f:
        f.write(per_model_table)
    print(f"Saved to {pm_path}")

    # ---- Save JSON summary ----
    summary = {
        "defense_stats": {d: {k: v if not isinstance(v, tuple) else list(v)
                               for k, v in s.items()}
                          for d, s in defense_stats.items()},
        "per_model": {m: dict(d) for m, d in per_model_stats.items()},
        "core_case_count": len(core_ids),
    }
    json_path = output_dir / "unified_analysis.json"
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved to {json_path}")


if __name__ == "__main__":
    main()
