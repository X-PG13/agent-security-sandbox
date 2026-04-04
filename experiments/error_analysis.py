#!/usr/bin/env python3
"""
Error analysis for identifying failure patterns and extracting case studies.

Analyzes:
  1. False Negatives -- attacks that bypassed defenses
  2. False Positives -- benign tasks incorrectly blocked
  3. Defense-specific failure patterns
  4. Representative case studies for the paper

Usage:
    python experiments/error_analysis.py \
        --results-dir results/full_eval \
        --benchmark-dir data/full_benchmark \
        --output-dir results/error_analysis
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Error analysis and case study extraction.")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "full_benchmark"))
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results" / "error_analysis"))
    parser.add_argument("--top-k", type=int, default=5,
                        help="Number of representative cases to extract per category.")
    return parser.parse_args()


def _load_results(results_dir: Path) -> List[Dict[str, Any]]:
    """Load all result files."""
    results = []
    for f in sorted(results_dir.glob("*.json")):
        if f.name in ("experiment_config.json", "all_results.json"):
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
            if "results" in data:
                results.append(data)
        except Exception:
            continue
    return results


def _extract_meta(data: Dict) -> Tuple[str, str, int]:
    meta = data.get("_meta", {})
    model = meta.get("model", "unknown")
    defense = meta.get("defense_id", data.get("defense_name", "unknown"))
    run_id = meta.get("run_id", 1)
    return model, defense, run_id


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark metadata
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    case_map = {c.id: c for c in suite.cases}
    print(f"Loaded {len(case_map)} benchmark cases")

    # Load results
    all_data = _load_results(Path(args.results_dir))
    print(f"Loaded {len(all_data)} result files")

    # ── Classify errors ────────────────────────────────────────────────
    false_negatives: List[Dict[str, Any]] = []   # Attacks that succeeded
    false_positives: List[Dict[str, Any]] = []   # Benign tasks blocked
    true_positives: List[Dict[str, Any]] = []    # Attacks blocked
    true_negatives: List[Dict[str, Any]] = []    # Benign completed

    for data in all_data:
        model, defense, run_id = _extract_meta(data)

        for r in data.get("results", []):
            case_id = r.get("case_id", "")
            verdict = r.get("verdict", "")
            reason = r.get("reason", "")
            case = case_map.get(case_id)
            if case is None:
                continue

            entry = {
                "case_id": case_id,
                "model": model,
                "defense": defense,
                "run_id": run_id,
                "verdict": verdict,
                "reason": reason,
                "case_type": case.type,
                "goal": case.goal,
                "attack_type": case.attack_type,
                "injection_technique": case.injection_technique,
                "difficulty": str(case.difficulty),
                "injection_location": case.injection_location,
            }

            if case.type == "attack" and verdict == "attack_succeeded":
                false_negatives.append(entry)
            elif case.type == "attack" and verdict == "attack_blocked":
                true_positives.append(entry)
            elif case.type == "benign" and verdict == "benign_blocked":
                false_positives.append(entry)
            elif case.type == "benign" and verdict == "benign_completed":
                true_negatives.append(entry)

    print("\nError classification:")
    print(f"  True Positives  (attacks blocked):    {len(true_positives)}")
    print(f"  False Negatives (attacks succeeded):  {len(false_negatives)}")
    print(f"  True Negatives  (benign completed):   {len(true_negatives)}")
    print(f"  False Positives (benign blocked):     {len(false_positives)}")

    # ── Analyze False Negative patterns ────────────────────────────────
    fn_analysis = {
        "total": len(false_negatives),
        "by_defense": dict(Counter(e["defense"] for e in false_negatives)),
        "by_attack_type": dict(Counter(
            e["attack_type"] for e in false_negatives if e["attack_type"]
        )),
        "by_technique": dict(Counter(
            e["injection_technique"]
            for e in false_negatives if e["injection_technique"]
        )),
        "by_difficulty": dict(Counter(e["difficulty"] for e in false_negatives)),
        "by_location": dict(Counter(
            e["injection_location"]
            for e in false_negatives if e["injection_location"]
        )),
    }

    # Which specific cases are hardest (bypass most defenses)?
    case_bypass_count: Counter = Counter()
    for e in false_negatives:
        case_bypass_count[e["case_id"]] += 1
    fn_analysis["hardest_cases"] = case_bypass_count.most_common(args.top_k)

    # ── Analyze False Positive patterns ────────────────────────────────
    fp_analysis = {
        "total": len(false_positives),
        "by_defense": dict(Counter(e["defense"] for e in false_positives)),
        "by_reason_prefix": dict(Counter(
            e["reason"][:60] for e in false_positives
        ).most_common(10)),
    }

    # Which benign cases are most often blocked?
    case_block_count: Counter = Counter()
    for e in false_positives:
        case_block_count[e["case_id"]] += 1
    fp_analysis["most_blocked_cases"] = case_block_count.most_common(args.top_k)

    # ── Cross-defense vulnerability matrix ─────────────────────────────
    # For each attack case, which defenses failed?
    case_defense_matrix: Dict[str, Dict[str, str]] = defaultdict(dict)
    for e in false_negatives + true_positives:
        case_defense_matrix[e["case_id"]][e["defense"]] = e["verdict"]

    # Find cases that bypass specific defense combinations
    vulnerable_patterns: List[Dict[str, Any]] = []
    for case_id, defenses in case_defense_matrix.items():
        bypassed = [d for d, v in defenses.items() if v == "attack_succeeded"]
        blocked = [d for d, v in defenses.items() if v == "attack_blocked"]
        if bypassed:
            case = case_map.get(case_id)
            vulnerable_patterns.append({
                "case_id": case_id,
                "bypassed_defenses": bypassed,
                "blocked_by": blocked,
                "attack_type": case.attack_type if case else None,
                "technique": case.injection_technique if case else None,
                "difficulty": str(case.difficulty) if case else None,
            })

    vulnerable_patterns.sort(key=lambda x: len(x["bypassed_defenses"]), reverse=True)

    # ── Extract representative case studies ────────────────────────────
    case_studies: List[Dict[str, Any]] = []

    # Case study 1: Attack that bypasses the most defenses
    if vulnerable_patterns:
        worst = vulnerable_patterns[0]
        case = case_map.get(worst["case_id"])
        if case:
            case_studies.append({
                "title": "Most resilient attack",
                "case_id": worst["case_id"],
                "goal": case.goal,
                "injection_technique": case.injection_technique,
                "attack_type": case.attack_type,
                "bypassed": worst["bypassed_defenses"],
                "blocked_by": worst["blocked_by"],
                "analysis": (
                    f"This attack bypassed {len(worst['bypassed_defenses'])} defenses, "
                    f"demonstrating the challenge of defending against "
                    f"{case.injection_technique} attacks."
                ),
            })

    # Case study 2: Defense with highest false positive rate
    fp_by_defense = Counter(e["defense"] for e in false_positives)
    if fp_by_defense:
        worst_fp_defense = fp_by_defense.most_common(1)[0]
        fp_examples = [e for e in false_positives if e["defense"] == worst_fp_defense[0]][:2]
        case_studies.append({
            "title": f"False positive pattern ({worst_fp_defense[0]})",
            "defense": worst_fp_defense[0],
            "count": worst_fp_defense[1],
            "examples": [
                {"case_id": e["case_id"], "goal": e["goal"], "reason": e["reason"]}
                for e in fp_examples
            ],
            "analysis": (
                f"{worst_fp_defense[0]} incorrectly blocked"
                f" {worst_fp_defense[1]} benign tasks."
            ),
        })

    # Case study 3: D1 effectiveness -- attack blocked by D1 but not D0
    d1_saves = [
        p for p in vulnerable_patterns
        if "D0" in p["bypassed_defenses"] and "D1" in p.get("blocked_by", [])
    ]
    if d1_saves:
        case = case_map.get(d1_saves[0]["case_id"])
        if case:
            case_studies.append({
                "title": "Spotlighting defense effectiveness",
                "case_id": d1_saves[0]["case_id"],
                "goal": case.goal,
                "technique": case.injection_technique,
                "analysis": "D1 (Spotlighting) successfully blocked this attack that "
                           "bypassed the baseline defense, demonstrating the value of "
                           "delimiter-based source marking.",
            })

    # ── Save outputs ───────────────────────────────────────────────────
    outputs = {
        "false_negative_analysis.json": fn_analysis,
        "false_positive_analysis.json": fp_analysis,
        "vulnerability_patterns.json": vulnerable_patterns[:50],
        "case_studies.json": case_studies,
        "false_negatives_full.json": false_negatives,
        "false_positives_full.json": false_positives,
    }

    for filename, data in outputs.items():
        path = output_dir / filename
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        print(f"Saved {path}")

    # ── Print summary ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("ERROR ANALYSIS SUMMARY")
    print("=" * 70)

    print("\n--- False Negatives (attacks that bypassed defenses) ---")
    print(f"{'Defense':<15} {'Count':>8}")
    print("-" * 25)
    for d, count in sorted(fn_analysis["by_defense"].items()):
        print(f"{d:<15} {count:>8}")

    if fn_analysis.get("by_technique"):
        print(f"\n{'Technique':<30} {'Count':>8}")
        print("-" * 40)
        for t, count in sorted(fn_analysis["by_technique"].items(), key=lambda x: -x[1]):
            print(f"{t:<30} {count:>8}")

    print("\n--- False Positives (benign tasks blocked) ---")
    print(f"{'Defense':<15} {'Count':>8}")
    print("-" * 25)
    for d, count in sorted(fp_analysis["by_defense"].items()):
        print(f"{d:<15} {count:>8}")

    if case_studies:
        print("\n--- Case Studies ---")
        for i, cs in enumerate(case_studies, 1):
            print(f"\n{i}. {cs['title']}")
            print(f"   {cs.get('analysis', '')}")


if __name__ == "__main__":
    main()
