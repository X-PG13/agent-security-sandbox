#!/usr/bin/env python3
"""
Statistical analysis for paper-quality results.

Computes:
  1. Wilson score 95% confidence intervals for ASR, BSR, FPR
  2. Bootstrap confidence intervals (1000 resamples)
  3. McNemar's test for pairwise defense comparisons
  4. Kendall's tau for cross-model defense ranking consistency
  5. LaTeX table generation

Usage:
    python experiments/statistical_analysis.py \
        --results-dir results/full_eval \
        --output-dir results/stats
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# ── Wilson Score Interval ──────────────────────────────────────────────────

def wilson_score_interval(
    successes: int, trials: int, confidence: float = 0.95
) -> Tuple[float, float, float]:
    """Compute Wilson score confidence interval.

    Returns (point_estimate, lower, upper).
    """
    if trials == 0:
        return 0.0, 0.0, 0.0

    z = _z_score(confidence)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    center = (p_hat + z**2 / (2 * trials)) / denom
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * trials)) / trials) / denom

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return p_hat, lower, upper


def _z_score(confidence: float) -> float:
    """Approximate z-score for common confidence levels."""
    z_map = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    return z_map.get(confidence, 1.96)


# ── Bootstrap CI ───────────────────────────────────────────────────────────

def bootstrap_ci(
    values: List[float],
    n_bootstrap: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Tuple[float, float, float]:
    """Compute bootstrap confidence interval for the mean.

    Returns (mean, lower, upper).
    """
    if not values:
        return 0.0, 0.0, 0.0

    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(values) for _ in range(n)]
        means.append(sum(sample) / n)

    means.sort()
    alpha = 1 - confidence
    lo_idx = int(n_bootstrap * alpha / 2)
    hi_idx = int(n_bootstrap * (1 - alpha / 2))
    return sum(values) / n, means[lo_idx], means[min(hi_idx, n_bootstrap - 1)]


# ── McNemar's Test ─────────────────────────────────────────────────────────

def mcnemar_test(
    verdicts_a: List[str], verdicts_b: List[str], success_verdict: str
) -> Dict[str, Any]:
    """Compute McNemar's test for paired nominal data.

    Tests whether two defenses have significantly different success/failure
    rates on the same set of cases.

    Returns dict with chi2, p_value, significant (at alpha=0.05), and counts.
    """
    assert len(verdicts_a) == len(verdicts_b), "Verdict lists must be same length"

    # Count discordant pairs
    a_success_b_fail = 0  # A succeeds where B fails
    a_fail_b_success = 0  # B succeeds where A fails

    for va, vb in zip(verdicts_a, verdicts_b):
        a_ok = va == success_verdict
        b_ok = vb == success_verdict
        if a_ok and not b_ok:
            a_success_b_fail += 1
        elif not a_ok and b_ok:
            a_fail_b_success += 1

    n_discordant = a_success_b_fail + a_fail_b_success
    if n_discordant == 0:
        return {
            "chi2": 0.0, "p_value": 1.0, "significant": False,
            "a_only": a_success_b_fail, "b_only": a_fail_b_success,
            "n_cases": len(verdicts_a),
        }

    # McNemar's chi-squared with continuity correction
    chi2 = (abs(a_success_b_fail - a_fail_b_success) - 1) ** 2 / n_discordant

    # Approximate p-value from chi2(1) using survival function
    p_value = _chi2_sf(chi2, df=1)

    return {
        "chi2": round(chi2, 4),
        "p_value": round(p_value, 6),
        "significant": p_value < 0.05,
        "a_only": a_success_b_fail,
        "b_only": a_fail_b_success,
        "n_cases": len(verdicts_a),
    }


def _chi2_sf(x: float, df: int = 1) -> float:
    """Survival function for chi-squared distribution (approximation).

    For df=1, P(X > x) = 2 * (1 - Phi(sqrt(x))) where Phi is the
    standard normal CDF.
    """
    if x <= 0:
        return 1.0
    if df == 1:
        return 2 * (1 - _normal_cdf(math.sqrt(x)))
    # Fallback for df>1: use Wilson-Hilferty approximation
    z = ((x / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 1 - _normal_cdf(z)


def _normal_cdf(x: float) -> float:
    """Standard normal CDF (Abramowitz & Stegun approximation)."""
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


# ── Kendall's Tau ──────────────────────────────────────────────────────────

def kendall_tau(ranking_a: List[str], ranking_b: List[str]) -> float:
    """Compute Kendall's tau-b rank correlation between two defense rankings.

    Rankings are lists of defense names ordered from best to worst.
    Returns tau in [-1, 1]. 1 = identical rankings, -1 = reversed.
    """
    items = list(set(ranking_a) & set(ranking_b))
    if len(items) < 2:
        return 1.0

    rank_a = {d: i for i, d in enumerate(ranking_a) if d in items}
    rank_b = {d: i for i, d in enumerate(ranking_b) if d in items}

    concordant = 0
    discordant = 0
    for i, j in combinations(items, 2):
        diff_a = rank_a[i] - rank_a[j]
        diff_b = rank_b[i] - rank_b[j]
        if diff_a * diff_b > 0:
            concordant += 1
        elif diff_a * diff_b < 0:
            discordant += 1
        # ties: neither concordant nor discordant

    total = concordant + discordant
    if total == 0:
        return 1.0
    return (concordant - discordant) / total


# ── Result Loading ─────────────────────────────────────────────────────────

def load_results(results_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load result files and group by (model, defense).

    Returns: {(model, defense): [run_data_1, run_data_2, ...]}
    """
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for f in sorted(results_dir.glob("*.json")):
        if f.name in ("experiment_config.json", "all_results.json",
                       "composition_all.json", "composition_analysis.json"):
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
            if "results" not in data:
                continue
        except Exception:
            continue

        meta = data.get("_meta", {})
        model = meta.get("model", "unknown")
        defense = meta.get("defense_id", data.get("defense_name", "unknown"))
        key = f"{model}|{defense}"
        grouped[key].append(data)

    return dict(grouped)


# ── LaTeX Table Generation ─────────────────────────────────────────────────

def generate_latex_table(
    summary: Dict[str, Dict[str, Any]],
    caption: str = "Defense evaluation results",
    label: str = "tab:main_results",
) -> str:
    """Generate a LaTeX table from summary data."""
    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{l c c c r}")
    lines.append(r"\toprule")
    lines.append(r"Defense & ASR $\downarrow$ & BSR $\uparrow$ & FPR $\downarrow$ & Tokens \\")
    lines.append(r"\midrule")

    for defense, data in sorted(summary.items()):
        asr = data.get("asr_mean", 0)
        asr_ci = data.get("asr_ci", (0, 0))
        bsr = data.get("bsr_mean", 0)
        bsr_ci = data.get("bsr_ci", (0, 0))
        fpr = data.get("fpr_mean", 0)
        tokens = data.get("tokens_mean", 0)

        lines.append(
            f"{defense} "
            f"& {asr:.1%}$_{{[{asr_ci[0]:.1%},{asr_ci[1]:.1%}]}}$ "
            f"& {bsr:.1%}$_{{[{bsr_ci[0]:.1%},{bsr_ci[1]:.1%}]}}$ "
            f"& {fpr:.1%} "
            f"& {tokens:,.0f} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(f"\\caption{{{caption}}}")
    lines.append(f"\\label{{{label}}}")
    lines.append(r"\end{table}")
    return "\n".join(lines)


def generate_mcnemar_latex(
    comparisons: List[Dict[str, Any]],
    caption: str = "Pairwise defense comparisons (McNemar's test)",
    label: str = "tab:mcnemar",
) -> str:
    """Generate a LaTeX table for McNemar's test results."""
    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{ll c c c c}")
    lines.append(r"\toprule")
    lines.append(r"Defense A & Defense B & $\chi^2$ & $p$ & Sig. & N \\")
    lines.append(r"\midrule")

    for c in comparisons:
        sig = r"\checkmark" if c["significant"] else ""
        lines.append(
            f"{c['defense_a']} & {c['defense_b']} "
            f"& {c['chi2']:.2f} & {c['p_value']:.4f} & {sig} & {c['n_cases']} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(f"\\caption{{{caption}}}")
    lines.append(f"\\label{{{label}}}")
    lines.append(r"\end{table}")
    return "\n".join(lines)


# ── Main Analysis ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Statistical analysis for paper.")
    parser.add_argument("--results-dir", required=True,
                        help="Directory with full evaluation result JSON files.")
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results" / "stats"),
                        help="Where to write analysis outputs.")
    parser.add_argument("--bootstrap-samples", type=int, default=1000)
    parser.add_argument("--confidence", type=float, default=0.95)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load grouped results
    grouped = load_results(Path(args.results_dir))
    print(f"Loaded results for {len(grouped)} (model, defense) combinations")

    if not grouped:
        print("No results found.")
        return

    # ── Per-(model, defense) summary with CIs ──────────────────────────
    summary: Dict[str, Dict[str, Any]] = {}
    all_verdicts: Dict[str, Dict[str, List[str]]] = {}  # for McNemar's test

    for key, runs in grouped.items():
        model, defense = key.split("|", 1)

        # Collect per-case verdicts across runs
        asr_values = []
        bsr_values = []
        fpr_values = []
        token_values = []

        # For McNemar: use first run's per-case verdicts
        case_verdicts: Dict[str, str] = {}
        for run_data in runs:
            m = run_data.get("metrics", {})
            asr_values.append(m.get("asr", 0))
            bsr_values.append(m.get("bsr", 0))
            fpr_values.append(m.get("fpr", 0))
            token_values.append(m.get("total_cost", 0))

            # First run per-case verdicts
            if not case_verdicts:
                for r in run_data.get("results", []):
                    case_verdicts[r["case_id"]] = r["verdict"]

        # Wilson CI from first run's case counts
        first_metrics = runs[0].get("metrics", {})
        details = first_metrics.get("details", {})
        attack_succ = details.get("attack_succeeded", 0)
        attack_total = first_metrics.get("attack_cases", 0)
        benign_comp = details.get("benign_completed", 0)
        benign_total = first_metrics.get("benign_cases", 0)
        benign_blocked = details.get("benign_blocked", 0)

        asr_pt, asr_lo, asr_hi = wilson_score_interval(attack_succ, attack_total, args.confidence)
        bsr_pt, bsr_lo, bsr_hi = wilson_score_interval(benign_comp, benign_total, args.confidence)
        fpr_pt, fpr_lo, fpr_hi = wilson_score_interval(
            benign_blocked, benign_total, args.confidence
        )

        # Bootstrap CI across runs
        if len(runs) > 1:
            _, asr_boot_lo, asr_boot_hi = bootstrap_ci(
                asr_values, args.bootstrap_samples, args.confidence
            )
            _, bsr_boot_lo, bsr_boot_hi = bootstrap_ci(
                bsr_values, args.bootstrap_samples, args.confidence
            )
        else:
            asr_boot_lo, asr_boot_hi = asr_lo, asr_hi
            bsr_boot_lo, bsr_boot_hi = bsr_lo, bsr_hi

        summary[key] = {
            "model": model,
            "defense": defense,
            "n_runs": len(runs),
            "asr_mean": sum(asr_values) / len(asr_values),
            "asr_ci": (asr_lo, asr_hi),
            "asr_bootstrap_ci": (asr_boot_lo, asr_boot_hi),
            "bsr_mean": sum(bsr_values) / len(bsr_values),
            "bsr_ci": (bsr_lo, bsr_hi),
            "bsr_bootstrap_ci": (bsr_boot_lo, bsr_boot_hi),
            "fpr_mean": sum(fpr_values) / len(fpr_values),
            "fpr_ci": (fpr_lo, fpr_hi),
            "tokens_mean": sum(token_values) / len(token_values),
            "attack_cases": attack_total,
            "benign_cases": benign_total,
        }
        all_verdicts[key] = case_verdicts

    # Save summary
    summary_path = output_dir / "summary_with_ci.json"
    with open(summary_path, "w") as fh:
        json.dump(summary, fh, indent=2, default=str)
    print(f"Summary saved to {summary_path}")

    # ── McNemar's pairwise comparisons ─────────────────────────────────
    # Group by model
    model_groups: Dict[str, List[str]] = defaultdict(list)
    for key in summary:
        model = key.split("|")[0]
        model_groups[model].append(key)

    all_comparisons: List[Dict[str, Any]] = []
    for model, keys in model_groups.items():
        for ka, kb in combinations(keys, 2):
            va = all_verdicts.get(ka, {})
            vb = all_verdicts.get(kb, {})

            # Only compare cases present in both
            common_cases = sorted(set(va.keys()) & set(vb.keys()))
            if not common_cases:
                continue

            # Attack cases: test whether one defense blocks more attacks
            attack_a = [va[c] for c in common_cases if "attack" in c]
            attack_b = [vb[c] for c in common_cases if "attack" in c]
            if attack_a:
                result = mcnemar_test(attack_a, attack_b, "attack_blocked")
                result["defense_a"] = ka.split("|")[1]
                result["defense_b"] = kb.split("|")[1]
                result["model"] = model
                result["metric"] = "attack_blocked"
                all_comparisons.append(result)

            # Benign cases: test whether one defense blocks more benign tasks
            benign_a = [va[c] for c in common_cases if "benign" in c]
            benign_b = [vb[c] for c in common_cases if "benign" in c]
            if benign_a:
                result = mcnemar_test(benign_a, benign_b, "benign_completed")
                result["defense_a"] = ka.split("|")[1]
                result["defense_b"] = kb.split("|")[1]
                result["model"] = model
                result["metric"] = "benign_completed"
                all_comparisons.append(result)

    comp_path = output_dir / "mcnemar_comparisons.json"
    with open(comp_path, "w") as fh:
        json.dump(all_comparisons, fh, indent=2)
    print(f"McNemar comparisons saved to {comp_path}")

    # ── Kendall's Tau for cross-model ranking consistency ──────────────
    # Rank defenses by ASR (ascending = better) per model
    model_rankings: Dict[str, List[str]] = {}
    for model, keys in model_groups.items():
        ranked = sorted(keys, key=lambda k: summary[k]["asr_mean"])
        model_rankings[model] = [k.split("|")[1] for k in ranked]

    tau_results: Dict[str, float] = {}
    model_names = sorted(model_rankings.keys())
    for ma, mb in combinations(model_names, 2):
        tau = kendall_tau(model_rankings[ma], model_rankings[mb])
        tau_results[f"{ma}_vs_{mb}"] = round(tau, 4)

    tau_path = output_dir / "kendall_tau.json"
    with open(tau_path, "w") as fh:
        json.dump({"rankings": model_rankings, "tau": tau_results}, fh, indent=2)
    print(f"Kendall's tau saved to {tau_path}")

    # ── Generate LaTeX tables ──────────────────────────────────────────
    # Main results table (per model)
    for model in model_names:
        model_summary = {
            summary[k]["defense"]: summary[k]
            for k in model_groups[model]
        }
        latex = generate_latex_table(
            model_summary,
            caption=f"Defense evaluation on {model}",
            label=f"tab:results_{model.replace('-', '_')}",
        )
        latex_path = output_dir / f"table_{model.replace('/', '_')}.tex"
        with open(latex_path, "w") as fh:
            fh.write(latex)
        print(f"LaTeX table saved to {latex_path}")

    # McNemar table
    if all_comparisons:
        sig_only = [c for c in all_comparisons if c.get("metric") == "attack_blocked"]
        mcnemar_latex = generate_mcnemar_latex(sig_only)
        mcnemar_path = output_dir / "table_mcnemar.tex"
        with open(mcnemar_path, "w") as fh:
            fh.write(mcnemar_latex)
        print(f"McNemar LaTeX table saved to {mcnemar_path}")

    # Print summary
    print("\n" + "=" * 80)
    print("STATISTICAL SUMMARY")
    print("=" * 80)
    print(f"\n{'Model|Defense':<35} {'ASR':>8} {'95% CI':>16} {'BSR':>8} {'FPR':>8}")
    print("-" * 85)
    for key in sorted(summary.keys()):
        s = summary[key]
        ci = s["asr_ci"]
        print(f"{key:<35} {s['asr_mean']:>7.1%} [{ci[0]:.1%}, {ci[1]:.1%}] "
              f"{s['bsr_mean']:>7.1%} {s['fpr_mean']:>7.1%}")

    if tau_results:
        print("\nKendall's tau (cross-model ranking consistency):")
        for pair, tau in tau_results.items():
            print(f"  {pair}: {tau:.4f}")

    sig_comparisons = [c for c in all_comparisons if c["significant"]]
    print(f"\nSignificant McNemar comparisons: {len(sig_comparisons)} / {len(all_comparisons)}")


if __name__ == "__main__":
    main()
