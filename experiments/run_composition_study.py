#!/usr/bin/env python3
"""
Defense composition study -- evaluate single, pairwise, and multi-defense combos.

Tests whether combining defenses yields super-additive (1+1>2) or
diminishing-returns effects on security metrics.

Combinations tested:
  - Individual: D1, D2, D3, D4, D5
  - Pairwise:  D1+D2, D1+D3, D1+D5, D2+D3, D5+D2, ...
  - Triple:    D1+D2+D3, D5+D2+D3, D1+D2+D5, ...
  - Full:      D1+D2+D3+D4, D5+D1+D2+D3+D4

Usage:
    python experiments/run_composition_study.py \
        --provider mock --benchmark-dir data/mini_benchmark

    python experiments/run_composition_study.py \
        --provider openai-compatible --base-url https://proxy.com/v1 \
        --model gpt-4o --benchmark-dir data/full_benchmark \
        --runs 3 --output-dir results/composition
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.tools.registry import ToolRegistry
from agent_security_sandbox.defenses.registry import create_defense, create_composite_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner

# Active defenses (D0 is baseline / no defense, excluded from combinations)
ACTIVE_DEFENSES = ["D1", "D2", "D3", "D4", "D5", "D6", "D7"]


def _make_json_safe(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return {k: _make_json_safe(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


def generate_combinations(max_size: int = 4) -> List[Dict[str, Any]]:
    """Generate all defense combinations up to max_size."""
    combos: List[Dict[str, Any]] = []

    # D0 baseline
    combos.append({"name": "D0", "defenses": ["D0"]})

    # Individual active defenses
    for d in ACTIVE_DEFENSES:
        combos.append({"name": d, "defenses": [d]})

    # Pairwise and larger combinations
    for size in range(2, min(max_size, len(ACTIVE_DEFENSES)) + 1):
        for combo in itertools.combinations(ACTIVE_DEFENSES, size):
            name = "+".join(combo)
            combos.append({"name": name, "defenses": list(combo)})

    # Full combination
    if max_size >= len(ACTIVE_DEFENSES):
        name = "+".join(ACTIVE_DEFENSES)
        # Already included via itertools, but ensure it's there
        existing_names = {c["name"] for c in combos}
        if name not in existing_names:
            combos.append({"name": name, "defenses": ACTIVE_DEFENSES[:]})

    return combos


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Defense composition study.")
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "mini_benchmark"))
    parser.add_argument("--provider", default="mock")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results"))
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of independent runs per combination.")
    parser.add_argument("--max-combo-size", type=int, default=4,
                        help="Maximum number of defenses in a combination.")
    parser.add_argument("--resume", action="store_true",
                        help="Skip combos that already have result files.")
    parser.add_argument("--no-function-calling", action="store_true",
                        help="Use text ReAct mode instead of function calling.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} cases ({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)")

    combos = generate_combinations(max_size=args.max_combo_size)
    total_runs = len(combos) * args.runs
    print(f"Combinations: {len(combos)} x {args.runs} runs = {total_runs} total evaluations")
    print()

    llm_kwargs: Dict[str, Any] = {}
    if args.base_url:
        llm_kwargs["base_url"] = args.base_url
    llm = create_llm_client(provider=args.provider, model=args.model, **llm_kwargs)

    all_results: Dict[str, Any] = {}
    completed = 0

    for combo in combos:
        name = combo["name"]
        defense_ids = combo["defenses"]

        for run_id in range(1, args.runs + 1):
            completed += 1
            key = f"{name}_run{run_id}"
            result_file = output_dir / f"composition_{name}_run{run_id}.json"

            if args.resume and result_file.exists():
                print(f"[{completed}/{total_runs}] {key} -- SKIP (exists)")
                with open(result_file) as f:
                    all_results[key] = json.load(f)
                continue

            print(f"[{completed}/{total_runs}] {key}")

            # Create defense (single or composite)
            if len(defense_ids) == 1:
                defense = create_defense(defense_ids[0], llm_client=llm)
            else:
                defense = create_composite_defense(defense_ids, llm_client=llm)

            runner = ExperimentRunner(
                llm_client=llm,
                tool_registry_factory=ToolRegistry,
                defense_strategy=defense,
                use_function_calling=not args.no_function_calling,
            )

            start = time.time()
            result = runner.run_suite(suite)
            elapsed = time.time() - start

            data = _make_json_safe(result)
            data["_meta"] = {
                "combination_name": name,
                "defense_ids": defense_ids,
                "run_id": run_id,
                "elapsed_seconds": round(elapsed, 2),
                "num_cases": len(suite),
            }

            all_results[key] = data
            with open(result_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)

            m = result.metrics
            print(f"  ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  tokens={m.total_cost}")

    # Save combined results
    combined = output_dir / "composition_all.json"
    with open(combined, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)
    print(f"\nAll results saved to {combined}")

    # Analysis: compute super-additivity
    print("\n" + "=" * 80)
    print("COMPOSITION ANALYSIS")
    print("=" * 80)

    # Average metrics across runs
    avg_metrics: Dict[str, Dict[str, float]] = {}
    for key, data in all_results.items():
        combo_name = data.get("_meta", {}).get("combination_name", key.rsplit("_run", 1)[0])
        metrics = data.get("metrics", {})
        if combo_name not in avg_metrics:
            avg_metrics[combo_name] = {"asr": [], "bsr": [], "fpr": [], "total_cost": [], "count": 0}
        for m in ["asr", "bsr", "fpr", "total_cost"]:
            avg_metrics[combo_name][m].append(metrics.get(m, 0))
        avg_metrics[combo_name]["count"] += 1

    # Compute averages
    summary: Dict[str, Dict[str, float]] = {}
    for name, vals in avg_metrics.items():
        summary[name] = {}
        for m in ["asr", "bsr", "fpr", "total_cost"]:
            v = vals[m]
            summary[name][m] = sum(v) / len(v) if v else 0.0

    # Print summary
    print(f"\n{'Combination':<30} {'ASR':>8} {'BSR':>8} {'FPR':>8} {'Tokens':>10}")
    print("-" * 70)
    for name in sorted(summary.keys(), key=lambda x: (len(x.split("+")), x)):
        s = summary[name]
        print(f"{name:<30} {s['asr']:.4f}   {s['bsr']:.4f}   {s['fpr']:.4f}   {s['total_cost']:>8.0f}")

    # Super-additivity analysis for pairs
    print("\n--- Super-Additivity Analysis (Pairwise) ---")
    print(f"{'Combo':<20} {'Expected ASR':>14} {'Actual ASR':>12} {'Delta':>8} {'Effect':>15}")
    print("-" * 75)

    for combo_name, combo_data in summary.items():
        parts = combo_name.split("+")
        if len(parts) != 2:
            continue
        a, b = parts
        if a not in summary or b not in summary:
            continue
        # Expected: min of individual ASRs (independence assumption)
        expected_asr = summary[a]["asr"] * summary[b]["asr"]
        actual_asr = combo_data["asr"]
        delta = actual_asr - expected_asr
        effect = "super-additive" if delta < -0.01 else "sub-additive" if delta > 0.01 else "additive"
        print(f"{combo_name:<20} {expected_asr:>12.4f}   {actual_asr:>10.4f}   {delta:>+7.4f}   {effect:>15}")

    # Save analysis
    analysis = {
        "summary": summary,
        "timestamp": datetime.now().isoformat(),
        "config": {
            "benchmark_dir": str(args.benchmark_dir),
            "model": args.model,
            "provider": args.provider,
            "runs": args.runs,
        },
    }
    analysis_path = output_dir / "composition_analysis.json"
    with open(analysis_path, "w") as fh:
        json.dump(analysis, fh, indent=2, default=str)
    print(f"\nAnalysis saved to {analysis_path}")


if __name__ == "__main__":
    main()
