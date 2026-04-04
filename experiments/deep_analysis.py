#!/usr/bin/env python3
"""Deep analysis of defense evaluation results.

Performs five types of analysis to provide actionable insights:

1. Defense Pair Gap Analysis -- why does defense A outperform B?
2. Failure Taxonomy -- (defense, injection_technique) failure matrix
3. Defense Combination Synergy -- interaction effects
4. Cross-Model Divergence -- cases where models disagree
5. Attack Technique x Defense Affinity Matrix -- bypass rates

Usage:
    python experiments/deep_analysis.py \
        --results-dir results/full_eval \
        --output-dir results/deep_analysis
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# ── Result loading ────────────────────────────────────────────────────

def load_all_results(results_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load all result JSON files.

    Returns: {filename_stem: data}
    """
    results = {}
    for f in sorted(results_dir.glob("*.json")):
        if f.name in ("experiment_config.json", "all_results.json",
                       "composition_all.json", "composition_analysis.json"):
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
            if "results" not in data:
                continue
            results[f.stem] = data
        except Exception:
            continue
    return results


def group_by_model_defense(
    results: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Group results as {model: {defense: [case_results]}}."""
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for _stem, data in results.items():
        meta = data.get("_meta", {})
        model = meta.get("model", "unknown")
        defense = meta.get("defense_id", "unknown")
        for case_result in data.get("results", []):
            grouped[model][defense].append(case_result)
    return dict(grouped)


# ── Analysis 1: Defense Pair Gap Analysis ─────────────────────────────

def defense_pair_gap_analysis(
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> List[Dict[str, Any]]:
    """For each pair of defenses, break down performance difference by
    attack_type and injection_technique."""
    gaps = []

    for model, defenses in grouped.items():
        defense_ids = sorted(defenses.keys())
        for da, db in combinations(defense_ids, 2):
            cases_a = {r["case_id"]: r for r in defenses[da]}
            cases_b = {r["case_id"]: r for r in defenses[db]}
            common = sorted(set(cases_a) & set(cases_b))

            # Group by attack_type
            by_type: Dict[str, Dict[str, int]] = defaultdict(
                lambda: {"a_only": 0, "b_only": 0, "both": 0, "neither": 0}
            )

            for cid in common:
                ra = cases_a[cid]
                rb = cases_b[cid]
                attack_type = ra.get("attack_type", ra.get("type", "unknown"))
                a_blocked = ra.get("verdict") in ("attack_blocked", "benign_completed")
                b_blocked = rb.get("verdict") in ("attack_blocked", "benign_completed")

                if a_blocked and not b_blocked:
                    by_type[attack_type]["a_only"] += 1
                elif b_blocked and not a_blocked:
                    by_type[attack_type]["b_only"] += 1
                elif a_blocked and b_blocked:
                    by_type[attack_type]["both"] += 1
                else:
                    by_type[attack_type]["neither"] += 1

            gaps.append({
                "model": model,
                "defense_a": da,
                "defense_b": db,
                "breakdown_by_attack_type": dict(by_type),
                "total_common_cases": len(common),
            })

    return gaps


# ── Analysis 2: Failure Taxonomy ─────────────────────────────────────

def failure_taxonomy(
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> Dict[str, Any]:
    """Build (defense, injection_technique) failure matrix."""
    # Aggregate across models
    matrix: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for _model, defenses in grouped.items():
        for defense_id, case_results in defenses.items():
            for r in case_results:
                if r.get("type") != "attack":
                    continue
                technique = r.get("injection_technique",
                                  r.get("attack_type", "unknown"))
                totals[defense_id][technique] += 1
                if r.get("verdict") == "attack_succeeded":
                    matrix[defense_id][technique] += 1

    # Compute failure rates
    failure_rates: Dict[str, Dict[str, float]] = {}
    for defense_id in sorted(matrix.keys()):
        failure_rates[defense_id] = {}
        for technique in sorted(set(matrix[defense_id]) | set(totals[defense_id])):
            fails = matrix[defense_id].get(technique, 0)
            total = totals[defense_id].get(technique, 0)
            failure_rates[defense_id][technique] = (
                fails / total if total > 0 else 0.0
            )

    # Identify systematic vulnerabilities (failure rate > 0.5)
    vulnerabilities = []
    for defense_id, techniques in failure_rates.items():
        for technique, rate in techniques.items():
            if rate > 0.5:
                vulnerabilities.append({
                    "defense": defense_id,
                    "technique": technique,
                    "failure_rate": round(rate, 4),
                    "failures": matrix[defense_id].get(technique, 0),
                    "total": totals[defense_id].get(technique, 0),
                })

    return {
        "failure_matrix": {
            d: {t: round(r, 4) for t, r in techs.items()}
            for d, techs in failure_rates.items()
        },
        "raw_counts": {
            d: dict(t) for d, t in matrix.items()
        },
        "systematic_vulnerabilities": sorted(
            vulnerabilities, key=lambda x: -x["failure_rate"]
        ),
    }


# ── Analysis 3: Defense Combination Synergy ──────────────────────────

def synergy_analysis(
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> List[Dict[str, Any]]:
    """Compute synergy = actual_combined_ASR - expected_ASR(independence).

    Negative synergy = defenses complement each other (good).
    Positive synergy = redundant or interfering.
    """
    synergies = []

    for model, defenses in grouped.items():
        defense_ids = sorted(defenses.keys())

        # Compute per-case success/failure for each defense
        case_success: Dict[str, Dict[str, bool]] = defaultdict(dict)
        for did, case_results in defenses.items():
            for r in case_results:
                if r.get("type") != "attack":
                    continue
                succeeded = r.get("verdict") == "attack_succeeded"
                case_success[did][r["case_id"]] = succeeded

        for da, db in combinations(defense_ids, 2):
            cases_a = case_success.get(da, {})
            cases_b = case_success.get(db, {})
            common = set(cases_a) & set(cases_b)
            if not common:
                continue

            n = len(common)
            asr_a = sum(1 for c in common if cases_a[c]) / n
            asr_b = sum(1 for c in common if cases_b[c]) / n

            # Combined: attack succeeds only if BOTH defenses fail
            combined_successes = sum(
                1 for c in common if cases_a[c] and cases_b[c]
            )
            actual_combined_asr = combined_successes / n

            # Expected under independence
            expected_combined_asr = asr_a * asr_b

            synergy = actual_combined_asr - expected_combined_asr

            synergies.append({
                "model": model,
                "defense_a": da,
                "defense_b": db,
                "asr_a": round(asr_a, 4),
                "asr_b": round(asr_b, 4),
                "actual_combined_asr": round(actual_combined_asr, 4),
                "expected_combined_asr": round(expected_combined_asr, 4),
                "synergy": round(synergy, 4),
                "interpretation": (
                    "complementary" if synergy < -0.01
                    else "redundant" if synergy > 0.01
                    else "independent"
                ),
                "n_cases": n,
            })

    return sorted(synergies, key=lambda x: x["synergy"])


# ── Analysis 4: Cross-Model Divergence ───────────────────────────────

def cross_model_divergence(
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> Dict[str, Any]:
    """Find cases where models disagree on the same (defense, case)."""
    # Build: {defense: {case_id: {model: verdict}}}
    by_defense: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(
        lambda: defaultdict(dict)
    )

    for model, defenses in grouped.items():
        for defense_id, case_results in defenses.items():
            for r in case_results:
                by_defense[defense_id][r["case_id"]][model] = r.get(
                    "verdict", "unknown"
                )

    divergent_cases = []
    for defense_id, cases in by_defense.items():
        for case_id, model_verdicts in cases.items():
            verdicts = list(model_verdicts.values())
            if len(set(verdicts)) > 1 and len(verdicts) >= 2:
                divergent_cases.append({
                    "defense": defense_id,
                    "case_id": case_id,
                    "model_verdicts": dict(model_verdicts),
                    "unique_verdicts": list(set(verdicts)),
                })

    # Aggregate divergence rate per defense
    defense_divergence: Dict[str, Dict[str, Any]] = {}
    for defense_id, cases in by_defense.items():
        total = 0
        divergent = 0
        for case_id, model_verdicts in cases.items():
            if len(model_verdicts) >= 2:
                total += 1
                if len(set(model_verdicts.values())) > 1:
                    divergent += 1
        defense_divergence[defense_id] = {
            "total_shared_cases": total,
            "divergent_cases": divergent,
            "divergence_rate": round(divergent / total, 4) if total > 0 else 0.0,
        }

    return {
        "per_defense_divergence": defense_divergence,
        "divergent_case_details": divergent_cases[:100],  # cap at 100
        "total_divergent": len(divergent_cases),
    }


# ── Analysis 5: Attack Technique x Defense Affinity Matrix ───────────

def affinity_matrix(
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> Dict[str, Any]:
    """Compute bypass rate for each (injection_technique, defense) pair."""
    # Aggregate across models
    bypasses: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for _model, defenses in grouped.items():
        for defense_id, case_results in defenses.items():
            for r in case_results:
                if r.get("type") != "attack":
                    continue
                technique = r.get("injection_technique",
                                  r.get("attack_type", "unknown"))
                totals[technique][defense_id] += 1
                if r.get("verdict") == "attack_succeeded":
                    bypasses[technique][defense_id] += 1

    # Compute bypass rates
    all_techniques = sorted(set(totals.keys()))
    all_defenses = sorted(
        set(d for techs in totals.values() for d in techs.keys())
    )

    matrix: Dict[str, Dict[str, float]] = {}
    for technique in all_techniques:
        matrix[technique] = {}
        for defense_id in all_defenses:
            total = totals[technique].get(defense_id, 0)
            bypass = bypasses[technique].get(defense_id, 0)
            matrix[technique][defense_id] = (
                round(bypass / total, 4) if total > 0 else 0.0
            )

    # Find strongest and weakest pairings
    strongest_bypasses = []
    for technique in all_techniques:
        for defense_id in all_defenses:
            rate = matrix[technique][defense_id]
            if rate > 0.7:
                strongest_bypasses.append({
                    "technique": technique,
                    "defense": defense_id,
                    "bypass_rate": rate,
                })

    return {
        "bypass_rate_matrix": matrix,
        "techniques": all_techniques,
        "defenses": all_defenses,
        "high_bypass_pairs": sorted(
            strongest_bypasses, key=lambda x: -x["bypass_rate"]
        ),
    }


# ── Main ──────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deep analysis of results.")
    parser.add_argument(
        "--results-dir", type=str,
        default=str(_PROJECT_ROOT / "results" / "full_eval"),
        help="Directory with full evaluation result JSON files.",
    )
    parser.add_argument(
        "--output-dir", type=str,
        default=str(_PROJECT_ROOT / "results" / "deep_analysis"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading results from {results_dir}...")
    all_results = load_all_results(results_dir)
    if not all_results:
        print("No results found. Exiting.")
        return
    print(f"Loaded {len(all_results)} result files.")

    grouped = group_by_model_defense(all_results)
    models = sorted(grouped.keys())
    print(f"Models: {models}")
    for model in models:
        print(f"  {model}: {sorted(grouped[model].keys())}")

    # Analysis 1: Defense Pair Gap
    print("\n[1/5] Defense pair gap analysis...")
    gaps = defense_pair_gap_analysis(grouped)
    gap_path = output_dir / "defense_pair_gaps.json"
    with open(gap_path, "w") as fh:
        json.dump(gaps, fh, indent=2)
    print(f"  Saved {len(gaps)} pair comparisons to {gap_path}")

    # Analysis 2: Failure Taxonomy
    print("[2/5] Failure taxonomy...")
    taxonomy = failure_taxonomy(grouped)
    tax_path = output_dir / "failure_taxonomy.json"
    with open(tax_path, "w") as fh:
        json.dump(taxonomy, fh, indent=2)
    n_vulns = len(taxonomy.get("systematic_vulnerabilities", []))
    print(f"  Found {n_vulns} systematic vulnerabilities. Saved to {tax_path}")

    # Analysis 3: Synergy
    print("[3/5] Defense combination synergy...")
    synergies = synergy_analysis(grouped)
    syn_path = output_dir / "synergy_scores.json"
    with open(syn_path, "w") as fh:
        json.dump(synergies, fh, indent=2)
    complementary = sum(1 for s in synergies if s["synergy"] < -0.01)
    print(f"  {complementary} complementary pairs out of {len(synergies)}. "
          f"Saved to {syn_path}")

    # Analysis 4: Cross-Model Divergence
    print("[4/5] Cross-model divergence...")
    divergence = cross_model_divergence(grouped)
    div_path = output_dir / "cross_model_divergence.json"
    with open(div_path, "w") as fh:
        json.dump(divergence, fh, indent=2)
    print(f"  {divergence['total_divergent']} divergent cases. Saved to {div_path}")

    # Analysis 5: Affinity Matrix
    print("[5/5] Attack technique x defense affinity matrix...")
    affinity = affinity_matrix(grouped)
    aff_path = output_dir / "affinity_matrix.json"
    with open(aff_path, "w") as fh:
        json.dump(affinity, fh, indent=2)
    n_high = len(affinity.get("high_bypass_pairs", []))
    print(f"  {n_high} high-bypass pairs. Saved to {aff_path}")

    print(f"\nAll analyses saved to {output_dir}")


if __name__ == "__main__":
    main()
