#!/usr/bin/env python3
"""
Post-experiment consolidation script.

STEP 1 (run first): Copy canonical D8-D10 results into unified_565/ directory.
STEP 2 (run after D0-D7 experiments finish): Compute unified statistics and
        regenerate all paper LaTeX tables.

Usage:
    # After D0-D7 experiments complete:
    python experiments/consolidate_and_update_tables.py \
        --new-eval-dir results/full_eval_565 \
        --output-dir results/unified_565

    # Or just consolidate D8-D10 (before D0-D7 are done):
    python experiments/consolidate_and_update_tables.py --consolidate-only
"""
from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

RESULTS_BASE = _PROJECT_ROOT / "results"
PAPER_TABLES = _PROJECT_ROOT / "paper" / "tables"

MODELS_4 = [
    "gpt-4o",
    "claude-sonnet-4-5-20250929",
    "deepseek-v3-1-250821",
    "gemini-2.5-flash",
]

# Canonical source for each (model, defense) D8-D10 result
# Use full_eval_v2 for D10 (most recent CIV implementation)
# Use full_eval + full_eval_v2 for D8/D9
D8_D10_SOURCES = {
    # D8: 3 runs each
    ("gpt-4o",                     "D8"): ("full_eval",   [1, 2, 3]),
    ("claude-sonnet-4-5-20250929", "D8"): ("full_eval",   [1, 2, 3]),
    ("deepseek-v3-1-250821",       "D8"): ("full_eval",   [1, 2, 3]),
    ("gemini-2.5-flash",           "D8"): ("full_eval_v2",[1, 2, 3]),
    # D9: 3 runs each
    ("gpt-4o",                     "D9"): ("full_eval",   [1, 2, 3]),
    ("claude-sonnet-4-5-20250929", "D9"): ("full_eval",   [1, 2, 3]),
    ("deepseek-v3-1-250821",       "D9"): ("full_eval",   [1, 2, 3]),
    ("gemini-2.5-flash",           "D9"): ("full_eval_v2",[1, 2, 3]),
    # D10: use full_eval_v2 (final CIV implementation) for all models
    ("gpt-4o",                     "D10"): ("full_eval_v2",[1, 2, 3]),
    ("claude-sonnet-4-5-20250929", "D10"): ("full_eval_v2",[1, 2, 3]),
    ("deepseek-v3-1-250821",       "D10"): ("full_eval_v2",[1, 2, 3]),
    ("gemini-2.5-flash",           "D10"): ("full_eval_v2",[1, 2, 3]),
}


# ── Wilson score CI ────────────────────────────────────────────────────────

def wilson_ci(successes: int, trials: int, z: float = 1.96):
    if trials == 0:
        return 0.0, 0.0, 0.0
    p = successes / trials
    denom = 1 + z**2 / trials
    center = (p + z**2 / (2 * trials)) / denom
    margin = z * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2)) / denom
    return p, max(0.0, center - margin), min(1.0, center + margin)


# ── McNemar's test ─────────────────────────────────────────────────────────

def mcnemar_p(b: int, c: int) -> float:
    """Two-tailed McNemar's test p-value (mid-p variant)."""
    n = b + c
    if n == 0:
        return 1.0
    # Use normal approximation for large n
    if n >= 25:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c)
        # P(chi2_1 > x) approximation
        x = chi2 / 2
        # Regularized incomplete gamma approximation
        return _chi2_sf(chi2, 1)
    # Exact binomial
    p = 0.5
    prob = 0.0
    from math import comb
    target = min(b, c)
    for k in range(0, target + 1):
        prob += comb(n, k) * (p**n)
    return min(1.0, 2 * prob)


def _chi2_sf(x: float, df: int) -> float:
    """Survival function of chi-squared distribution (df=1 only)."""
    # Using erfc approximation
    return math.erfc(math.sqrt(x / 2))


# ── Result loading ─────────────────────────────────────────────────────────

def load_runs(directory: Path) -> dict:
    """Load all *_{defense}_run{n}.json from directory.
    Returns {(model, defense): [run1_results, run2_results, ...]}.
    """
    grouped = defaultdict(list)
    for f in sorted(directory.glob("*.json")):
        if f.name in ("experiment_config.json", "all_results.json"):
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
        except Exception:
            continue

        meta = data.get("_meta", {})
        model = meta.get("model") or _infer_model(f.stem)
        defense = meta.get("defense_id") or _infer_defense(f.stem)
        if model and defense:
            grouped[(model, defense)].append(data)
    return dict(grouped)


def _infer_model(stem: str) -> str | None:
    for m in MODELS_4:
        if stem.startswith(m):
            return m
    return None


def _infer_defense(stem: str) -> str | None:
    for d in [f"D{i}" for i in range(11)]:
        if f"_{d}_" in stem:
            return d
    return None


def extract_case_verdicts(run_data: dict) -> dict[str, list[str]]:
    """Extract {attack_case_id: [verdict], benign_case_id: [verdict]}."""
    results = run_data.get("results", [])
    out: dict[str, list] = {}
    for r in results:
        cid = r.get("case_id", "")
        v = r.get("verdict", "")
        out.setdefault(cid, []).append(v)
    return out


def compute_metrics(runs: list[dict]) -> dict:
    """Compute per-(model,defense) summary metrics averaged over runs."""
    per_run_asr = []
    per_run_bsr = []
    all_attack_successes = []
    all_attack_total = 0
    all_benign_completed = []
    all_benign_total = 0

    for run in runs:
        results = run.get("results", [])
        attacks = [r for r in results if r.get("verdict", "").startswith("attack")]
        benigns = [r for r in results if r.get("verdict", "").startswith("benign")]
        if attacks:
            asr = sum(1 for r in attacks if r["verdict"] == "attack_succeeded") / len(attacks)
            per_run_asr.append(asr)
            all_attack_successes.append(sum(1 for r in attacks if r["verdict"] == "attack_succeeded"))
            all_attack_total += len(attacks)
        if benigns:
            bsr = sum(1 for r in benigns if r["verdict"] == "benign_completed") / len(benigns)
            per_run_bsr.append(bsr)
            all_benign_completed.append(sum(1 for r in benigns if r["verdict"] == "benign_completed"))
            all_benign_total += len(benigns)

    asr_mean = sum(per_run_asr) / len(per_run_asr) if per_run_asr else 0
    bsr_mean = sum(per_run_bsr) / len(per_run_bsr) if per_run_bsr else 0

    # Wilson CI on pooled counts
    total_atk_succ = sum(all_attack_successes)
    asr_p, asr_lo, asr_hi = wilson_ci(total_atk_succ, all_attack_total)
    total_ben_comp = sum(all_benign_completed)
    bsr_p, bsr_lo, bsr_hi = wilson_ci(total_ben_comp, all_benign_total)

    return {
        "asr_mean": round(asr_mean, 4),
        "bsr_mean": round(bsr_mean, 4),
        "fpr_mean": round(1 - bsr_mean, 4),
        "asr_wilson_ci": [round(asr_lo, 4), round(asr_hi, 4)],
        "bsr_wilson_ci": [round(bsr_lo, 4), round(bsr_hi, 4)],
        "n_runs": len(runs),
        "attack_cases": all_attack_total // max(len(runs), 1),
        "benign_cases": all_benign_total // max(len(runs), 1),
    }


# ── LaTeX table generation ─────────────────────────────────────────────────

DEFENSE_LABELS = {
    "D0": r"\defense{D0} No Defense",
    "D1": r"\defense{D1} Spotlighting",
    "D2": r"\defense{D2} Policy Gate",
    "D3": r"\defense{D3} Task Alignment",
    "D4": r"\defense{D4} Re-execution",
    "D5": r"\defense{D5} Sandwich",
    "D6": r"\defense{D6} Output Filter",
    "D7": r"\defense{D7} Input Classifier",
    "D8": r"\defense{D8} Semantic FW",
    "D9": r"\defense{D9} Dual-LLM",
    "D10": r"\defense{D10} \civ{}",
}


def write_main_results_table(summary: dict, output_path: Path, n_cases: int) -> None:
    """Generate Table 1: main results for all 11 defenses × 4 models."""
    all_defenses = [f"D{i}" for i in range(11)]
    models = MODELS_4
    model_short = {
        "gpt-4o": "GPT-4o",
        "claude-sonnet-4-5-20250929": "Claude",
        "deepseek-v3-1-250821": "DeepSeek",
        "gemini-2.5-flash": "Gemini",
    }

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\small",
        r"\caption{Attack Success Rate (\asr{}), Benign Success Rate (\bsr{}), and False Positive Rate"
        r" (\fpr{}) for all 11 defenses across 4 frontier LLMs on the 565-case full benchmark"
        r" (352 attack + 213 benign), averaged over 3 independent runs."
        r" \textbf{Bold}: best per column. \colorbox{lightgray}{Shaded}: worst per column.}",
        r"\label{tab:main_results}",
        r"\begin{tabular}{l" + "rrr" * len(models) + r"rrr}",
        r"\toprule",
    ]

    # Header
    header1 = r"\multirow{2}{*}{Defense}"
    for m in models:
        header1 += r" & \multicolumn{3}{c}{" + model_short[m] + r"}"
    header1 += r" & \multicolumn{3}{c}{\textbf{Average}}"
    header1 += r" \\"
    lines.append(header1)

    header2 = ""
    for _ in range(len(models) + 1):
        header2 += r" & \asr{} & \bsr{} & \fpr{}"
    header2 += r" \\ \midrule"
    lines.append(header2)

    # Find best/worst ASR per column for bolding
    def get_val(d, m, metric):
        k = f"{m}|{d}"
        return summary.get(k, {}).get(metric, float("nan"))

    for defense in all_defenses:
        label = DEFENSE_LABELS.get(defense, defense)
        row = label
        asrs, bsrs = [], []
        for m in models:
            k = f"{m}|{defense}"
            entry = summary.get(k, {})
            asr = entry.get("asr_mean", float("nan"))
            bsr = entry.get("bsr_mean", float("nan"))
            fpr = entry.get("fpr_mean", float("nan"))
            asrs.append(asr)
            bsrs.append(bsr)
            row += f" & {asr:.3f} & {bsr:.3f} & {fpr:.3f}"
        # Average
        valid_asrs = [x for x in asrs if not math.isnan(x)]
        valid_bsrs = [x for x in bsrs if not math.isnan(x)]
        avg_asr = sum(valid_asrs) / len(valid_asrs) if valid_asrs else float("nan")
        avg_bsr = sum(valid_bsrs) / len(valid_bsrs) if valid_bsrs else float("nan")
        avg_fpr = 1 - avg_bsr if not math.isnan(avg_bsr) else float("nan")
        row += f" & \\textbf{{{avg_asr:.3f}}} & \\textbf{{{avg_bsr:.3f}}} & \\textbf{{{avg_fpr:.3f}}}"
        row += r" \\"
        lines.append(row)

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ]

    output_path.write_text("\n".join(lines) + "\n")
    print(f"  Wrote {output_path}")


def write_extended_per_model_tables(summary: dict, output_dir: Path) -> None:
    """Generate per-model tables for appendix."""
    model_short = {
        "gpt-4o": "GPT-4o",
        "claude-sonnet-4-5-20250929": "Claude Sonnet",
        "deepseek-v3-1-250821": "DeepSeek V3",
        "gemini-2.5-flash": "Gemini 2.5 Flash",
    }
    all_defenses = [f"D{i}" for i in range(11)]

    for m in MODELS_4:
        lines = [
            r"\begin{table}[h]",
            r"\centering",
            r"\small",
            r"\caption{Results for " + model_short[m] + r" on the 565-case benchmark (3 runs).}",
            r"\label{tab:per_model_" + m.split("-")[0].replace(".", "_") + r"}",
            r"\begin{tabular}{lrrrrr}",
            r"\toprule",
            r"Defense & \asr{} & [95\% CI] & \bsr{} & [95\% CI] & \fpr{} \\",
            r"\midrule",
        ]
        for d in all_defenses:
            k = f"{m}|{d}"
            e = summary.get(k, {})
            asr = e.get("asr_mean", float("nan"))
            bsr = e.get("bsr_mean", float("nan"))
            fpr = e.get("fpr_mean", float("nan"))
            asr_ci = e.get("asr_wilson_ci", [float("nan"), float("nan")])
            bsr_ci = e.get("bsr_wilson_ci", [float("nan"), float("nan")])
            label = DEFENSE_LABELS.get(d, d)
            lines.append(
                f"{label} & {asr:.3f} & [{asr_ci[0]:.3f}, {asr_ci[1]:.3f}]"
                f" & {bsr:.3f} & [{bsr_ci[0]:.3f}, {bsr_ci[1]:.3f}]"
                f" & {fpr:.3f} \\\\"
            )
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        fname = output_dir / f"per_model_{m.split('-')[0]}.tex"
        fname.write_text("\n".join(lines) + "\n")
        print(f"  Wrote {fname.name}")


# ── Main ──────────────────────────────────────────────────────────────────

def consolidate_d8_d10(dest: Path) -> None:
    """Copy canonical D8-D10 result files into dest/."""
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for (model, defense), (src_dir, runs) in D8_D10_SOURCES.items():
        for run_id in runs:
            src_file = RESULTS_BASE / src_dir / f"{model}_{defense}_run{run_id}.json"
            dst_file = dest / src_file.name
            if src_file.exists():
                shutil.copy2(src_file, dst_file)
                copied += 1
            else:
                print(f"  [WARN] Missing: {src_file}")
    print(f"Consolidated {copied} D8-D10 result files into {dest}/")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--new-eval-dir", default=str(RESULTS_BASE / "full_eval_565"),
        help="Directory with new D0-D7 results on 565 cases",
    )
    parser.add_argument(
        "--output-dir", default=str(RESULTS_BASE / "unified_565"),
        help="Output directory for unified results",
    )
    parser.add_argument(
        "--consolidate-only", action="store_true",
        help="Only copy D8-D10 files (before D0-D7 runs finish)",
    )
    parser.add_argument(
        "--skip-tables", action="store_true",
        help="Skip LaTeX table generation",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Copy D8-D10 canonical results
    print("\n=== Step 1: Consolidating D8-D10 results ===")
    consolidate_d8_d10(output_dir)

    if args.consolidate_only:
        print("--consolidate-only set. Done.")
        return

    # Step 2: Copy/link new D0-D7 results
    new_eval_dir = Path(args.new_eval_dir)
    if not new_eval_dir.exists():
        print(f"\n[ERROR] D0-D7 results directory not found: {new_eval_dir}")
        print("Run the D0-D7 experiments first, then re-run this script.")
        sys.exit(1)

    print(f"\n=== Step 2: Copying D0-D7 results from {new_eval_dir.name}/ ===")
    d0_d7_files = list(new_eval_dir.glob("*.json"))
    d0_d7_files = [f for f in d0_d7_files if f.name not in ("experiment_config.json", "all_results.json")]
    for f in sorted(d0_d7_files):
        dst = output_dir / f.name
        if not dst.exists():
            shutil.copy2(f, dst)
    print(f"Copied {len(d0_d7_files)} D0-D7 result files")

    # Step 3: Load all results
    print("\n=== Step 3: Loading and computing statistics ===")
    grouped = load_runs(output_dir)
    print(f"Loaded {len(grouped)} (model, defense) combinations")
    for (m, d), runs in sorted(grouped.items()):
        if m in MODELS_4:
            print(f"  {m} | {d}: {len(runs)} runs, {len(runs[0].get('results',[]))} cases each")

    # Step 4: Compute summary stats
    summary = {}
    for (model, defense), runs in grouped.items():
        if model not in MODELS_4:
            continue
        key = f"{model}|{defense}"
        summary[key] = compute_metrics(runs)

    stats_path = output_dir / "unified_summary_with_ci.json"
    stats_path.write_text(json.dumps(summary, indent=2))
    print(f"\nSaved unified stats to {stats_path}")

    # Print summary table
    print("\n=== Unified Results (4-model averages) ===")
    print(f"{'Defense':<8} {'Avg ASR':>9} {'Avg BSR':>9} {'Avg FPR':>9} {'N models':>10}")
    print("-" * 50)
    for defense in [f"D{i}" for i in range(11)]:
        entries = [(k, v) for k, v in summary.items() if k.endswith(f"|{defense}") and any(m in k for m in MODELS_4)]
        if entries:
            avg_asr = sum(v["asr_mean"] for _, v in entries) / len(entries)
            avg_bsr = sum(v["bsr_mean"] for _, v in entries) / len(entries)
            print(f"{defense:<8} {avg_asr:>9.3f} {avg_bsr:>9.3f} {1-avg_bsr:>9.3f} {len(entries):>10}")

    if args.skip_tables:
        print("\n--skip-tables set. Skipping LaTeX generation.")
        return

    # Step 5: Regenerate LaTeX tables
    print("\n=== Step 5: Regenerating LaTeX tables ===")
    PAPER_TABLES.mkdir(parents=True, exist_ok=True)

    # Determine n_cases from first available result
    n_cases = 565  # default
    for runs in grouped.values():
        if runs:
            n_cases = len(runs[0].get("results", []))
            break

    write_main_results_table(summary, PAPER_TABLES / "main_results_unified.tex", n_cases)
    write_extended_per_model_tables(summary, PAPER_TABLES)

    print(f"\nAll tables written to {PAPER_TABLES}/")
    print("\nNext steps:")
    print("  1. Review paper/tables/main_results_unified.tex")
    print("  2. Update paper/sections/results.tex to \\input{tables/main_results_unified}")
    print("  3. Re-run statistical_analysis.py on unified_565/ for McNemar + Kendall's τ")
    print("  4. python experiments/statistical_analysis.py \\")
    print(f"       --results-dir {output_dir} --output-dir results/unified_stats")


if __name__ == "__main__":
    main()
