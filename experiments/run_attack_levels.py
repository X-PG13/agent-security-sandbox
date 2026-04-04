#!/usr/bin/env python3
"""
Attack difficulty and technique analysis.

Reuses existing full-evaluation result files to analyze:
  1. Per-difficulty ASR breakdown (easy / medium / hard)
  2. Per-injection-technique ASR breakdown
  3. Per-attack-type ASR breakdown
  4. Cross-defense × difficulty heatmap data

Does NOT make additional API calls -- purely post-hoc analysis.

Usage:
    python experiments/run_attack_levels.py \
        --results-dir results/full_eval \
        --benchmark-dir data/full_benchmark \
        --output-dir results/attack_analysis
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkCase, BenchmarkSuite  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze attack success rates by difficulty and technique.",
    )
    parser.add_argument(
        "--results-dir", required=True,
        help="Directory containing full evaluation JSON result files.",
    )
    parser.add_argument(
        "--benchmark-dir",
        default=str(_PROJECT_ROOT / "data" / "full_benchmark"),
        help="Benchmark directory (to load case metadata).",
    )
    parser.add_argument(
        "--output-dir",
        default=str(_SCRIPT_DIR / "results" / "attack_analysis"),
        help="Where to write analysis outputs.",
    )
    return parser.parse_args()


def _load_case_metadata(benchmark_dir: str) -> Dict[str, BenchmarkCase]:
    """Load benchmark cases and return a dict keyed by case ID."""
    suite = BenchmarkSuite.load_from_directory(benchmark_dir)
    return {case.id: case for case in suite.cases}


def _load_results(results_dir: Path) -> List[Dict[str, Any]]:
    """Load all JSON result files from the directory."""
    results = []
    for f in sorted(results_dir.glob("*.json")):
        if f.name in ("experiment_config.json", "all_results.json"):
            continue
        try:
            with open(f) as fh:
                data = json.load(fh)
            # Must have results and _meta or defense_name
            if "results" in data:
                results.append(data)
        except Exception:
            continue
    return results


def _extract_defense_name(data: Dict[str, Any]) -> str:
    """Extract a human-readable defense identifier from result data."""
    meta = data.get("_meta", {})
    if "defense_id" in meta:
        return meta["defense_id"]
    if "combination_name" in meta:
        return meta["combination_name"]
    return data.get("defense_name", "unknown")


def _analyse_by_dimension(
    case_verdicts: List[Tuple[BenchmarkCase, str]],
    dimension: str,
) -> Dict[str, Dict[str, int]]:
    """Group attack cases by a case attribute and count verdicts.

    Args:
        case_verdicts: List of (BenchmarkCase, verdict_str) tuples.
        dimension: Attribute name on BenchmarkCase (e.g. 'difficulty',
            'injection_technique', 'attack_type').

    Returns:
        {dimension_value: {"total": N, "succeeded": M, "blocked": K}}
    """
    groups: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"total": 0, "succeeded": 0, "blocked": 0}
    )
    for case, verdict in case_verdicts:
        val = getattr(case, dimension, None)
        if val is None:
            val = "unknown"
        val = str(val)
        groups[val]["total"] += 1
        if verdict == "attack_succeeded":
            groups[val]["succeeded"] += 1
        else:
            groups[val]["blocked"] += 1
    return dict(groups)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load case metadata
    case_map = _load_case_metadata(args.benchmark_dir)
    attack_cases = {cid: c for cid, c in case_map.items() if c.type == "attack"}
    print(f"Loaded {len(case_map)} benchmark cases ({len(attack_cases)} attack)")

    # Load results
    results_dir = Path(args.results_dir)
    all_results = _load_results(results_dir)
    print(f"Loaded {len(all_results)} result files from {results_dir}")

    if not all_results:
        print("No results found. Run the full evaluation first.")
        return

    # Analyze each result file
    full_analysis: Dict[str, Any] = {}

    for data in all_results:
        defense = _extract_defense_name(data)
        meta = data.get("_meta", {})
        run_id = meta.get("run_id", 1)
        model = meta.get("model", "unknown")
        key = f"{model}_{defense}_run{run_id}"

        # Match result verdicts to benchmark cases
        case_verdicts: List[Tuple[BenchmarkCase, str]] = []
        for r in data.get("results", []):
            case_id = r.get("case_id", "")
            verdict = r.get("verdict", "")
            if case_id in attack_cases:
                case_verdicts.append((attack_cases[case_id], verdict))

        if not case_verdicts:
            continue

        # Analyze by multiple dimensions
        analysis = {
            "defense": defense,
            "model": model,
            "run_id": run_id,
            "total_attack_cases": len(case_verdicts),
            "by_difficulty": _analyse_by_dimension(case_verdicts, "difficulty"),
            "by_technique": _analyse_by_dimension(case_verdicts, "injection_technique"),
            "by_attack_type": _analyse_by_dimension(case_verdicts, "attack_type"),
            "by_location": _analyse_by_dimension(case_verdicts, "injection_location"),
        }
        full_analysis[key] = analysis

    # Save full analysis
    analysis_path = output_dir / "attack_level_analysis.json"
    with open(analysis_path, "w") as fh:
        json.dump(full_analysis, fh, indent=2, ensure_ascii=False)
    print(f"\nFull analysis saved to {analysis_path}")

    # Print summary tables
    dimensions = ["difficulty", "injection_technique", "attack_type"]
    for dim in dimensions:
        print(f"\n{'=' * 70}")
        print(f"ASR by {dim}")
        print(f"{'=' * 70}")

        # Aggregate across runs
        agg: Dict[str, Dict[str, Dict[str, List[float]]]] = defaultdict(
            lambda: defaultdict(lambda: {"asr": []})
        )
        for key, a in full_analysis.items():
            defense = a["defense"]
            by_dim = a.get(f"by_{dim}", {})
            for val, counts in by_dim.items():
                asr = counts["succeeded"] / counts["total"] if counts["total"] > 0 else 0
                agg[defense][val]["asr"].append(asr)

        # Print
        all_vals = sorted({v for d in agg.values() for v in d.keys()})
        header = f"{'Defense':<20}" + "".join(f"{v:>15}" for v in all_vals)
        print(header)
        print("-" * len(header))

        for defense in sorted(agg.keys()):
            row = f"{defense:<20}"
            for val in all_vals:
                asrs = agg[defense][val]["asr"]
                if asrs:
                    mean_asr = sum(asrs) / len(asrs)
                    row += f"{mean_asr:>14.2%} "
                else:
                    row += f"{'N/A':>15}"
            print(row)

    # Generate cross-defense x difficulty heatmap data
    heatmap_data: Dict[str, Dict[str, float]] = {}
    for key, a in full_analysis.items():
        defense = a["defense"]
        if defense not in heatmap_data:
            heatmap_data[defense] = {}
        for val, counts in a.get("by_difficulty", {}).items():
            asr = counts["succeeded"] / counts["total"] if counts["total"] > 0 else 0
            if val not in heatmap_data[defense]:
                heatmap_data[defense][val] = []
            if not isinstance(heatmap_data[defense][val], list):
                heatmap_data[defense][val] = [heatmap_data[defense][val]]
            heatmap_data[defense][val].append(asr)

    # Average the heatmap data
    for defense in heatmap_data:
        for val in heatmap_data[defense]:
            v = heatmap_data[defense][val]
            if isinstance(v, list):
                heatmap_data[defense][val] = sum(v) / len(v) if v else 0

    heatmap_path = output_dir / "defense_difficulty_heatmap.json"
    with open(heatmap_path, "w") as fh:
        json.dump(heatmap_data, fh, indent=2)
    print(f"\nHeatmap data saved to {heatmap_path}")


if __name__ == "__main__":
    main()
