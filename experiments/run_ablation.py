#!/usr/bin/env python3
"""
Ablation study comparing defense combinations.

Combinations: D0, D1, D1+D2, D1+D2+D3, D1+D2+D3+D4

Usage:
    python experiments/run_ablation.py --benchmark-dir data/mini_benchmark --provider mock
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
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

COMBINATIONS: List[Dict[str, Any]] = [
    {"name": "D0 (No Defense)", "defenses": ["D0"]},
    {"name": "D1 (Spotlighting)", "defenses": ["D1"]},
    {"name": "D1+D2", "defenses": ["D1", "D2"]},
    {"name": "D1+D2+D3", "defenses": ["D1", "D2", "D3"]},
    {"name": "D1+D2+D3+D4", "defenses": ["D1", "D2", "D3", "D4"]},
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ablation study of defense combinations.")
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "mini_benchmark"))
    parser.add_argument("--provider", default="mock")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} cases")

    kwargs = {}
    if args.base_url:
        kwargs["base_url"] = args.base_url
    llm = create_llm_client(provider=args.provider, model=args.model, **kwargs)

    all_results = {}
    for combo in COMBINATIONS:
        name = combo["name"]
        defense_ids = combo["defenses"]
        print(f"\n{'='*60}\nEvaluating: {name}\n{'='*60}")

        if len(defense_ids) == 1:
            defense = create_defense(defense_ids[0], llm_client=llm)
        else:
            defense = create_composite_defense(defense_ids, llm_client=llm)

        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
        )
        result = runner.run_suite(suite)

        metrics = vars(result.metrics)
        all_results[name] = {
            "defenses": defense_ids,
            "metrics": {k: v for k, v in metrics.items() if not k.startswith("_")},
            "timestamp": datetime.now().isoformat(),
        }
        print(
            f"  ASR={result.metrics.asr:.4f}"
            f" BSR={result.metrics.bsr:.4f}"
            f" FPR={result.metrics.fpr:.4f}"
        )

    # Save results
    output_path = output_dir / "ablation_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")

    # Print summary
    print(f"\n{'Defense':<25} {'ASR':>8} {'BSR':>8} {'FPR':>8}")
    print("-" * 55)
    for name, data in all_results.items():
        m = data["metrics"]
        print(f"{name:<25} {m.get('asr', 0):.4f}   {m.get('bsr', 0):.4f}   {m.get('fpr', 0):.4f}")


if __name__ == "__main__":
    main()
