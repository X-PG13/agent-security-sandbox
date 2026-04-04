#!/usr/bin/env python3
"""Targeted defense composition study for the paper.

Tests specific combinations of defenses focused on the top performers
and D10 (CIV) to evaluate super-additivity and practical recommendations.

Combinations tested:
  - Singles:  D0, D1, D5, D10
  - Pairs:    D1+D10, D5+D10, D5+D1, D2+D10
  - Triples:  D5+D1+D10, D5+D2+D10

Usage:
    python experiments/run_targeted_composition.py \
        --provider mock --benchmark-dir data/mini_benchmark

    python experiments/run_targeted_composition.py \
        --models gpt-4o claude-sonnet-4-5-20250929 deepseek-v3-1-250821 gemini-2.5-flash \
        --provider openai-compatible --base-url https://your-proxy.com/v1 \
        --benchmark-dir data/full_benchmark --output-dir results/composition \
        --runs 1
"""
from __future__ import annotations

import argparse
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

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import (  # noqa: E402
    create_composite_defense,
    create_defense,
)
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

# Key combinations for the paper (9 total)
TARGET_COMBOS: List[Dict[str, Any]] = [
    {"name": "D0", "defenses": ["D0"]},
    {"name": "D1", "defenses": ["D1"]},
    {"name": "D5", "defenses": ["D5"]},
    {"name": "D10", "defenses": ["D10"]},
    {"name": "D1+D10", "defenses": ["D1", "D10"]},
    {"name": "D5+D10", "defenses": ["D5", "D10"]},
    {"name": "D5+D1", "defenses": ["D5", "D1"]},
    {"name": "D5+D1+D10", "defenses": ["D5", "D1", "D10"]},
    {"name": "D2+D10", "defenses": ["D2", "D10"]},
    {"name": "D5+D2+D10", "defenses": ["D5", "D2", "D10"]},
]

MODEL_PROVIDERS = {
    "gpt-4o": "openai-compatible",
    "claude-sonnet-4-5-20250929": "openai-compatible",
    "deepseek-v3-1-250821": "openai-compatible",
    "gemini-2.5-flash": "openai-compatible",
    "mock": "mock",
}


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Targeted defense composition study.")
    parser.add_argument("--models", nargs="+", default=["mock"])
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "mini_benchmark"))
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--output-dir", default=str(_PROJECT_ROOT / "results" / "composition"))
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-function-calling", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} cases"
          f" ({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)")

    total_runs = len(TARGET_COMBOS) * len(args.models) * args.runs
    print(f"Combinations: {len(TARGET_COMBOS)} x {len(args.models)} models x {args.runs} runs = {total_runs}")
    print()

    all_results: Dict[str, Any] = {}
    completed = 0

    for model in args.models:
        provider = args.provider or MODEL_PROVIDERS.get(model, "openai-compatible")
        llm_kwargs: Dict[str, Any] = {}
        if args.base_url:
            llm_kwargs["base_url"] = args.base_url
        llm = create_llm_client(provider=provider, model=model if model != "mock" else None, **llm_kwargs)

        for combo in TARGET_COMBOS:
            name = combo["name"]
            defense_ids = combo["defenses"]

            for run_id in range(1, args.runs + 1):
                completed += 1
                safe_model = model.replace("/", "_").replace(":", "_")
                key = f"{safe_model}_{name}_run{run_id}"
                result_file = output_dir / f"composition_{safe_model}_{name}_run{run_id}.json"

                if args.resume and result_file.exists():
                    print(f"[{completed}/{total_runs}] {key} -- SKIP (exists)")
                    with open(result_file) as f:
                        all_results[key] = json.load(f)
                    continue

                print(f"[{completed}/{total_runs}] {key}")

                if len(defense_ids) == 1:
                    defense = create_defense(defense_ids[0], llm_client=llm)
                else:
                    defense = create_composite_defense(defense_ids, llm_client=llm)

                runner = ExperimentRunner(
                    llm_client=llm,
                    tool_registry_factory=ToolRegistry,
                    defense_strategy=defense,
                    max_steps=args.max_steps,
                    use_function_calling=not args.no_function_calling,
                )

                start = time.time()
                result = runner.run_suite(suite)
                elapsed = time.time() - start

                data = _make_json_safe(result)
                data["_meta"] = {
                    "combination_name": name,
                    "defense_ids": defense_ids,
                    "model": model,
                    "run_id": run_id,
                    "elapsed_seconds": round(elapsed, 2),
                    "num_cases": len(suite),
                }

                all_results[key] = data
                with open(result_file, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False)

                m = result.metrics
                print(f"  ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  tokens={m.total_cost}")

    # Save combined
    combined = output_dir / "targeted_composition_all.json"
    with open(combined, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)
    print(f"\nAll results saved to {combined}")

    # Super-additivity analysis
    print("\n" + "=" * 80)
    print("SUPER-ADDITIVITY ANALYSIS")
    print("=" * 80)

    # Average metrics per combo (across models and runs)
    avg_metrics: Dict[str, Dict[str, float]] = {}
    for key, data in all_results.items():
        combo_name = data.get("_meta", {}).get("combination_name", "?")
        metrics = data.get("metrics", {})
        if combo_name not in avg_metrics:
            avg_metrics[combo_name] = {"asr": [], "bsr": []}
        avg_metrics[combo_name]["asr"].append(metrics.get("asr", 0))
        avg_metrics[combo_name]["bsr"].append(metrics.get("bsr", 0))

    summary: Dict[str, Dict[str, float]] = {}
    for name, vals in avg_metrics.items():
        summary[name] = {
            "asr": sum(vals["asr"]) / len(vals["asr"]) if vals["asr"] else 0,
            "bsr": sum(vals["bsr"]) / len(vals["bsr"]) if vals["bsr"] else 0,
        }

    print(f"\n{'Combo':<20} {'ASR':>8} {'BSR':>8} {'Expected':>10} {'Delta':>8} {'Effect':>16}")
    print("-" * 75)

    for combo_name in [c["name"] for c in TARGET_COMBOS]:
        if combo_name not in summary:
            continue
        parts = combo_name.split("+")
        s = summary[combo_name]
        if len(parts) == 1:
            print(f"{combo_name:<20} {s['asr']:.4f}   {s['bsr']:.4f}")
        elif len(parts) == 2:
            a, b = parts
            if a in summary and b in summary:
                expected = summary[a]["asr"] * summary[b]["asr"]
                delta = s["asr"] - expected
                effect = "super-additive" if delta < -0.01 else "sub-additive" if delta > 0.01 else "additive"
                print(f"{combo_name:<20} {s['asr']:.4f}   {s['bsr']:.4f}   {expected:>8.4f}   {delta:>+7.4f}   {effect:>16}")
            else:
                print(f"{combo_name:<20} {s['asr']:.4f}   {s['bsr']:.4f}")
        else:
            print(f"{combo_name:<20} {s['asr']:.4f}   {s['bsr']:.4f}")

    # Save analysis
    analysis = {
        "summary": summary,
        "combos": [c["name"] for c in TARGET_COMBOS],
        "timestamp": datetime.now().isoformat(),
    }
    analysis_path = output_dir / "targeted_composition_analysis.json"
    with open(analysis_path, "w") as fh:
        json.dump(analysis, fh, indent=2, default=str)
    print(f"\nAnalysis saved to {analysis_path}")


if __name__ == "__main__":
    main()
