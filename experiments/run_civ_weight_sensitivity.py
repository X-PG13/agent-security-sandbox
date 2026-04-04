#!/usr/bin/env python3
"""CIV weight sensitivity analysis on mini_benchmark.

Tests multiple weight configurations to demonstrate that CIV's performance
is not overfit to a specific set of hand-tuned weights.

Weight configs tested:
  1. Default:  prov=0.45, compat=0.30, plan=0.25  (paper default)
  2. Equal:    prov=0.33, compat=0.33, plan=0.33
  3. Prov-heavy: prov=0.60, compat=0.20, plan=0.20
  4. Compat-heavy: prov=0.25, compat=0.50, plan=0.25
  5. Plan-heavy: prov=0.25, compat=0.25, plan=0.50

Usage:
    python experiments/run_civ_weight_sensitivity.py \
        --model gpt-4o --benchmark-dir data/mini_benchmark
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent

from dotenv import load_dotenv
load_dotenv(_PROJECT_ROOT / ".env", override=True)

for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.defenses.registry import create_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner
from agent_security_sandbox.tools.registry import ToolRegistry


WEIGHT_CONFIGS = {
    "default":      {"provenance_weight": 0.45, "compatibility_weight": 0.30, "plan_weight": 0.25},
    "equal":        {"provenance_weight": 0.33, "compatibility_weight": 0.33, "plan_weight": 0.33},
    "prov_heavy":   {"provenance_weight": 0.60, "compatibility_weight": 0.20, "plan_weight": 0.20},
    "compat_heavy": {"provenance_weight": 0.25, "compatibility_weight": 0.50, "plan_weight": 0.25},
    "plan_heavy":   {"provenance_weight": 0.25, "compatibility_weight": 0.25, "plan_weight": 0.50},
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "mini_benchmark"))
    parser.add_argument("--output-dir", default=str(_PROJECT_ROOT / "results" / "civ_weight_sensitivity"))
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Benchmark: {args.benchmark_dir} ({len(suite)} cases)")
    print(f"Model: {args.model}")
    print(f"Weight configs: {list(WEIGHT_CONFIGS.keys())}")
    print()

    all_results = {}

    for config_name, weights in WEIGHT_CONFIGS.items():
        out_file = output_dir / f"{args.model}_D10_{config_name}.json"

        if args.resume and out_file.exists():
            print(f"[SKIP] {config_name} (already exists)")
            with open(out_file) as f:
                all_results[config_name] = json.load(f)
            continue

        print(f"[RUN] {config_name}: {weights}")

        llm = create_llm_client(provider=args.provider, model=args.model)
        defense = create_defense("D10", config=weights, llm_client=llm)

        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
            max_steps=10,
        )

        start = time.time()

        def _progress(idx, total, case):
            if (idx + 1) % 10 == 0 or idx == 0:
                print(f"  case {idx+1}/{total} ({time.time()-start:.0f}s)", flush=True)

        result = runner.run_suite(suite, progress_callback=_progress)
        elapsed = time.time() - start

        data = _make_json_safe(result)
        data["_meta"] = {
            "model": args.model,
            "config_name": config_name,
            "weights": weights,
            "provider": args.provider,
            "elapsed_seconds": round(elapsed, 2),
            "benchmark_dir": str(args.benchmark_dir),
            "num_cases": len(suite),
        }

        with open(out_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        m = result.metrics
        print(f"  -> ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  "
              f"tokens={m.total_cost}  time={elapsed:.1f}s")
        all_results[config_name] = data

    # Summary table
    print("\n" + "=" * 70)
    print("CIV WEIGHT SENSITIVITY SUMMARY")
    print("=" * 70)
    print(f"{'Config':<15} {'prov':>5} {'compat':>6} {'plan':>5} {'ASR':>8} {'BSR':>8} {'FPR':>8}")
    print("-" * 70)
    for config_name, weights in WEIGHT_CONFIGS.items():
        data = all_results.get(config_name, {})
        m = data.get("metrics", {})
        print(f"{config_name:<15} {weights['provenance_weight']:>5.2f} "
              f"{weights['compatibility_weight']:>6.2f} {weights['plan_weight']:>5.2f} "
              f"{m.get('asr', 0):>8.4f} {m.get('bsr', 0):>8.4f} {m.get('fpr', 0):>8.4f}")

    # Save summary
    summary = {
        "model": args.model,
        "benchmark": args.benchmark_dir,
        "timestamp": datetime.now().isoformat(),
        "configs": {
            name: {
                "weights": WEIGHT_CONFIGS[name],
                "metrics": all_results.get(name, {}).get("metrics", {}),
            }
            for name in WEIGHT_CONFIGS
        },
    }
    with open(output_dir / "sensitivity_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to {output_dir}")


if __name__ == "__main__":
    main()
