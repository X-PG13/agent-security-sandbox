#!/usr/bin/env python3
"""
Model comparison experiment - same defense across different models.

Usage:
    python experiments/run_model_comparison.py \
        --models gpt-3.5-turbo,gpt-4 \
        --defense D2 \
        --provider openai
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare defense across different models.")
    parser.add_argument("--models", default="mock-model", help="Comma-separated model names")
    parser.add_argument("--defense", default="D2")
    parser.add_argument("--provider", default="mock")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--benchmark-dir", default=str(_PROJECT_ROOT / "data" / "mini_benchmark"))
    parser.add_argument("--output-dir", default=str(_SCRIPT_DIR / "results"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    models = [m.strip() for m in args.models.split(",")]
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} cases, comparing models: {models}")

    all_results = {}
    for model_name in models:
        print(f"\n{'='*60}\nModel: {model_name}, Defense: {args.defense}\n{'='*60}")

        kwargs = {}
        if args.base_url:
            kwargs["base_url"] = args.base_url

        llm = create_llm_client(provider=args.provider, model=model_name, **kwargs)
        defense = create_defense(args.defense, llm_client=llm)

        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
        )
        result = runner.run_suite(suite)
        metrics = vars(result.metrics)
        all_results[model_name] = {
            "model": model_name,
            "defense": args.defense,
            "metrics": {k: v for k, v in metrics.items() if not k.startswith("_")},
            "timestamp": datetime.now().isoformat(),
        }
        print(f"  ASR={result.metrics.asr:.4f} BSR={result.metrics.bsr:.4f}")

    output_path = output_dir / "model_comparison.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
