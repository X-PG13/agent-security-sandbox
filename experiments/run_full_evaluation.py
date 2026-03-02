#!/usr/bin/env python3
"""
Full-scale evaluation across multiple models, defenses, and runs.

Supports:
  - Multiple models (--models gpt-4o claude-3-5-sonnet llama-3.1-70b)
  - All defense strategies D0-D5 (--defenses D0 D1 D2 D3 D4 D5)
  - Multiple runs for statistical significance (--runs 3)
  - Resume from checkpoint (--resume)
  - Custom benchmark directory (--benchmark-dir)

Usage:
    # Mock mode (no API keys)
    python experiments/run_full_evaluation.py \
        --models mock --defenses D0 D1 D2 --runs 1 \
        --benchmark-dir data/mini_benchmark --output-dir results/test

    # Real evaluation
    python experiments/run_full_evaluation.py \
        --models gpt-4o claude-3-5-sonnet --defenses D0 D1 D2 D3 D4 D5 --runs 3 \
        --benchmark-dir data/full_benchmark --output-dir results/paper_v1 \
        --provider openai-compatible --base-url https://your-proxy.com/v1
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.tools.registry import ToolRegistry
from agent_security_sandbox.defenses.registry import create_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner

ALL_DEFENSES = ["D0", "D1", "D2", "D3", "D4", "D5"]

# Model name -> provider mapping
MODEL_PROVIDERS = {
    "gpt-4o": "openai-compatible",
    "gpt-4o-mini": "openai-compatible",
    "claude-3-5-sonnet": "openai-compatible",
    "llama-3.1-70b": "openai-compatible",
    "qwen-2.5-72b": "openai-compatible",
    "mock": "mock",
}


def _make_json_safe(obj: Any) -> Any:
    """Recursively convert non-serialisable objects for JSON output."""
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
    parser = argparse.ArgumentParser(
        description="Full-scale evaluation across models, defenses, and runs.",
    )
    parser.add_argument(
        "--models", nargs="+", default=["mock"],
        help="Model names to evaluate (e.g. gpt-4o claude-3-5-sonnet). "
             "Use 'mock' for testing without API keys.",
    )
    parser.add_argument(
        "--defenses", nargs="+", default=ALL_DEFENSES,
        help=f"Defense IDs to test. Default: {' '.join(ALL_DEFENSES)}",
    )
    parser.add_argument(
        "--runs", type=int, default=1,
        help="Number of independent runs per (model, defense) pair. Default: 1",
    )
    parser.add_argument(
        "--benchmark-dir", type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
        help="Path to benchmark directory. Default: data/mini_benchmark",
    )
    parser.add_argument(
        "--output-dir", type=str,
        default=str(_PROJECT_ROOT / "results" / "full_eval"),
        help="Output directory for results. Default: results/full_eval",
    )
    parser.add_argument(
        "--provider", type=str, default=None,
        help="Override LLM provider for all models (e.g. openai-compatible).",
    )
    parser.add_argument(
        "--base-url", type=str, default=None,
        help="API base URL (for openai-compatible provider).",
    )
    parser.add_argument(
        "--max-steps", type=int, default=10,
        help="Maximum agent steps per case. Default: 10",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip (model, defense, run) combos that already have result files.",
    )
    return parser.parse_args()


def _checkpoint_path(output_dir: Path, model: str, defense_id: str, run_id: int) -> Path:
    """Consistent file naming for result checkpoints."""
    safe_model = model.replace("/", "_").replace(":", "_")
    return output_dir / f"{safe_model}_{defense_id}_run{run_id}.json"


def _run_single(
    model: str,
    defense_id: str,
    run_id: int,
    suite: BenchmarkSuite,
    args: argparse.Namespace,
    output_dir: Path,
) -> Optional[Dict[str, Any]]:
    """Run evaluation for a single (model, defense, run) triple."""
    checkpoint = _checkpoint_path(output_dir, model, defense_id, run_id)

    if args.resume and checkpoint.exists():
        print(f"  [SKIP] {checkpoint.name} already exists (--resume)")
        with open(checkpoint) as f:
            return json.load(f)

    # Create LLM client
    provider = args.provider or MODEL_PROVIDERS.get(model, "openai-compatible")
    llm_kwargs: Dict[str, Any] = {}
    if args.base_url:
        llm_kwargs["base_url"] = args.base_url

    try:
        llm = create_llm_client(
            provider=provider,
            model=model if model != "mock" else None,
            **llm_kwargs,
        )
    except Exception as exc:
        print(f"  [ERROR] Failed to create LLM client for {model}: {exc}")
        return None

    # Create defense
    try:
        defense = create_defense(defense_id, llm_client=llm)
    except Exception as exc:
        print(f"  [ERROR] Failed to create defense {defense_id}: {exc}")
        return None

    # Run
    runner = ExperimentRunner(
        llm_client=llm,
        tool_registry_factory=ToolRegistry,
        defense_strategy=defense,
        max_steps=args.max_steps,
    )

    start_time = time.time()
    try:
        result = runner.run_suite(suite)
    except Exception as exc:
        print(f"  [ERROR] Evaluation failed: {exc}")
        return None
    elapsed = time.time() - start_time

    # Serialize
    data = _make_json_safe(result)
    data["_meta"] = {
        "model": model,
        "defense_id": defense_id,
        "run_id": run_id,
        "provider": provider,
        "elapsed_seconds": round(elapsed, 2),
        "benchmark_dir": str(args.benchmark_dir),
        "num_cases": len(suite),
    }

    # Save checkpoint
    with open(checkpoint, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    m = result.metrics
    print(f"  ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  "
          f"tokens={m.total_cost}  time={elapsed:.1f}s")
    return data


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark suite
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Benchmark: {args.benchmark_dir}")
    print(f"  {len(suite)} cases ({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)")
    print(f"Models: {args.models}")
    print(f"Defenses: {args.defenses}")
    print(f"Runs: {args.runs}")
    total = len(args.models) * len(args.defenses) * args.runs
    print(f"Total evaluations: {total}")
    print(f"Output: {output_dir}")
    print()

    # Run all combinations
    all_results: Dict[str, Any] = {}
    completed = 0

    for model in args.models:
        for defense_id in args.defenses:
            for run_id in range(1, args.runs + 1):
                key = f"{model}_{defense_id}_run{run_id}"
                completed += 1
                print(f"[{completed}/{total}] {key}")

                data = _run_single(model, defense_id, run_id, suite, args, output_dir)
                if data is not None:
                    all_results[key] = data

    # Save combined results
    combined_path = output_dir / "all_results.json"
    with open(combined_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)
    print(f"\nCombined results saved to {combined_path}")

    # Print summary table
    print(f"\n{'Model':<25} {'Defense':<8} {'Run':>4} {'ASR':>8} {'BSR':>8} {'FPR':>8} {'Tokens':>10}")
    print("-" * 75)
    for key, data in all_results.items():
        meta = data.get("_meta", {})
        metrics = data.get("metrics", {})
        print(f"{meta.get('model', '?'):<25} {meta.get('defense_id', '?'):<8} "
              f"{meta.get('run_id', '?'):>4} "
              f"{metrics.get('asr', 0):.4f}   {metrics.get('bsr', 0):.4f}   "
              f"{metrics.get('fpr', 0):.4f}   {metrics.get('total_cost', 0):>8}")

    # Save experiment config for reproducibility
    config = {
        "models": args.models,
        "defenses": args.defenses,
        "runs": args.runs,
        "benchmark_dir": str(args.benchmark_dir),
        "provider": args.provider,
        "base_url": args.base_url,
        "max_steps": args.max_steps,
        "timestamp": datetime.now().isoformat(),
    }
    config_path = output_dir / "experiment_config.json"
    with open(config_path, "w") as fh:
        json.dump(config, fh, indent=2)
    print(f"Config saved to {config_path}")


if __name__ == "__main__":
    main()
