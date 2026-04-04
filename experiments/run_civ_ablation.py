#!/usr/bin/env python3
"""CIV 2.0 (D10) ablation study -- evaluate each component's contribution.

Tests 7 configurations of CIV 2.0 to isolate the contribution of each
detection signal and the prompt framing layer:

  civ2_full:        All components enabled (prompt framing + 3 signals)
  civ2_no_prompt:   Disable prompt framing layer
  civ2_no_prov:     Disable provenance signal (set weight to 0)
  civ2_no_embed:    Disable embedding compatibility (use keyword fallback)
  civ2_no_plan:     Disable plan deviation signal (set weight to 0)
  civ2_prompt_only: Only prompt framing, no tool gating
  civ1_baseline:    Original CIV 1.0 weights for comparison

Usage:
    # Mock mode
    python experiments/run_civ_ablation.py \
        --models mock --runs 1 \
        --benchmark-dir data/mini_benchmark --output-dir results/civ_ablation

    # Real evaluation
    python experiments/run_civ_ablation.py \
        --models gpt-4o claude-sonnet-4-5-20250929 deepseek-v3-1-250821 gemini-2.5-flash \
        --runs 3 \
        --benchmark-dir data/full_benchmark --output-dir results/civ_ablation \
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

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

# -- Ablation configurations ------------------------------------------

ABLATION_CONFIGS: Dict[str, Dict[str, Any]] = {
    "civ2_full": {
        # Full CIV 2.0: prompt framing + all 3 signals
        "use_prompt_framing": True,
        "use_embedding": True,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.30,
        "provenance_weight": 0.45,
        "compatibility_weight": 0.30,
        "plan_weight": 0.25,
    },
    "civ2_no_prompt": {
        # Disable prompt framing layer
        "use_prompt_framing": False,
        "use_embedding": True,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.30,
        "provenance_weight": 0.45,
        "compatibility_weight": 0.30,
        "plan_weight": 0.25,
    },
    "civ2_no_prov": {
        # Disable provenance signal; renormalize compat+plan
        "use_prompt_framing": True,
        "use_embedding": True,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.30,
        "provenance_weight": 0.0,
        "compatibility_weight": 0.55,   # 0.30/0.55
        "plan_weight": 0.45,            # 0.25/0.55
    },
    "civ2_no_embed": {
        # Disable embedding (force keyword fallback)
        "use_prompt_framing": True,
        "use_embedding": False,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.30,
        "provenance_weight": 0.45,
        "compatibility_weight": 0.30,
        "plan_weight": 0.25,
    },
    "civ2_no_plan": {
        # Disable plan deviation; renormalize prov+compat
        "use_prompt_framing": True,
        "use_embedding": True,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.30,
        "provenance_weight": 0.60,      # 0.45/0.75
        "compatibility_weight": 0.40,    # 0.30/0.75
        "plan_weight": 0.0,
    },
    "civ2_prompt_only": {
        # Only prompt framing, no tool gating (monitored_tools=[])
        "use_prompt_framing": True,
        "use_embedding": False,
        "side_effect_threshold": 0.0,
        "read_only_threshold": 0.0,
        "provenance_weight": 0.0,
        "compatibility_weight": 0.0,
        "plan_weight": 0.0,
        "monitored_tools": [],
    },
    "civ1_baseline": {
        # CIV 1.0 weights (original 3-signal) for comparison
        # Mapped to CIV 2.0 config: prov=0.35, compat=0.25, plan=0.40
        "use_prompt_framing": False,
        "use_embedding": False,
        "side_effect_threshold": 0.45,
        "read_only_threshold": 0.45,  # same threshold for reads (no fast path)
        "provenance_weight": 0.35,
        "compatibility_weight": 0.25,
        "plan_weight": 0.40,
    },
}

MODEL_PROVIDERS = {
    "gpt-4o": "openai-compatible",
    "claude-sonnet-4-5-20250929": "openai-compatible",
    "deepseek-v3-1-250821": "openai-compatible",
    "gemini-2.5-flash": "openai-compatible",
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
        description="CIV 2.0 (D10) ablation study across component configurations.",
    )
    parser.add_argument(
        "--models", nargs="+", default=["mock"],
        help="Model names to evaluate.",
    )
    parser.add_argument(
        "--configs", nargs="+", default=list(ABLATION_CONFIGS.keys()),
        help=f"Ablation config names. Default: all ({', '.join(ABLATION_CONFIGS)})",
    )
    parser.add_argument(
        "--runs", type=int, default=1,
        help="Number of independent runs per (model, config) pair.",
    )
    parser.add_argument(
        "--benchmark-dir", type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
    )
    parser.add_argument(
        "--output-dir", type=str,
        default=str(_PROJECT_ROOT / "results" / "civ_ablation"),
    )
    parser.add_argument("--provider", type=str, default=None)
    parser.add_argument("--base-url", type=str, default=None)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-function-calling", action="store_true")
    return parser.parse_args()


def _checkpoint_path(output_dir: Path, model: str, config_name: str, run_id: int) -> Path:
    safe_model = model.replace("/", "_").replace(":", "_")
    return output_dir / f"{safe_model}_D10_{config_name}_run{run_id}.json"


def _run_single(
    model: str,
    config_name: str,
    config: Dict[str, Any],
    run_id: int,
    suite: BenchmarkSuite,
    args: argparse.Namespace,
    output_dir: Path,
) -> Optional[Dict[str, Any]]:
    """Run evaluation for a single (model, config, run) triple."""
    checkpoint = _checkpoint_path(output_dir, model, config_name, run_id)

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

    # Create D10 with ablation config
    try:
        defense = create_defense("D10", config=config, llm_client=llm)
    except Exception as exc:
        print(f"  [ERROR] Failed to create D10 with config {config_name}: {exc}")
        return None

    # Run
    runner = ExperimentRunner(
        llm_client=llm,
        tool_registry_factory=ToolRegistry,
        defense_strategy=defense,
        max_steps=args.max_steps,
        use_function_calling=not args.no_function_calling,
    )

    def _progress(idx: int, total: int, case) -> None:
        if (idx + 1) % 10 == 0 or idx == 0:
            elapsed_so_far = time.time() - start_time
            print(f"    case {idx + 1}/{total}  ({elapsed_so_far:.0f}s elapsed)",
                  flush=True)

    start_time = time.time()
    try:
        result = runner.run_suite(suite, progress_callback=_progress)
    except Exception as exc:
        print(f"  [ERROR] Evaluation failed: {exc}")
        return None
    elapsed = time.time() - start_time

    # Serialize
    data = _make_json_safe(result)
    data["_meta"] = {
        "model": model,
        "defense_id": "D10",
        "ablation_config": config_name,
        "config": _make_json_safe(config),
        "run_id": run_id,
        "provider": provider,
        "elapsed_seconds": round(elapsed, 2),
        "benchmark_dir": str(args.benchmark_dir),
        "num_cases": len(suite),
    }

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

    # Validate config names
    for cfg in args.configs:
        if cfg not in ABLATION_CONFIGS:
            print(f"Unknown config: {cfg}. Available: {list(ABLATION_CONFIGS.keys())}")
            sys.exit(1)

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Benchmark: {args.benchmark_dir}")
    print(f"  {len(suite)} cases"
          f" ({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)")
    print(f"Models: {args.models}")
    print(f"Configs: {args.configs}")
    print(f"Runs: {args.runs}")
    total = len(args.models) * len(args.configs) * args.runs
    print(f"Total evaluations: {total}")
    print(f"Output: {output_dir}")
    print()

    all_results: Dict[str, Any] = {}
    completed = 0

    for model in args.models:
        for config_name in args.configs:
            config = ABLATION_CONFIGS[config_name]
            for run_id in range(1, args.runs + 1):
                key = f"{model}_D10_{config_name}_run{run_id}"
                completed += 1
                print(f"[{completed}/{total}] {key}")

                data = _run_single(
                    model, config_name, config, run_id, suite, args, output_dir,
                )
                if data is not None:
                    all_results[key] = data

    # Save combined results
    combined_path = output_dir / "ablation_all_results.json"
    with open(combined_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)
    print(f"\nCombined results saved to {combined_path}")

    # Summary table
    print(f"\n{'Model':<25} {'Config':<22} {'Run':>4}"
          f" {'ASR':>8} {'BSR':>8} {'FPR':>8}")
    print("-" * 85)
    for key, data in all_results.items():
        meta = data.get("_meta", {})
        metrics = data.get("metrics", {})
        print(f"{meta.get('model', '?'):<25} {meta.get('ablation_config', '?'):<22} "
              f"{meta.get('run_id', '?'):>4} "
              f"{metrics.get('asr', 0):.4f}   {metrics.get('bsr', 0):.4f}   "
              f"{metrics.get('fpr', 0):.4f}")

    # Compute per-config averages across models
    print("\n" + "=" * 60)
    print("ABLATION SUMMARY (averaged across models and runs)")
    print("=" * 60)

    config_metrics: Dict[str, List[Dict[str, float]]] = {}
    for key, data in all_results.items():
        cfg = data.get("_meta", {}).get("ablation_config", "unknown")
        metrics = data.get("metrics", {})
        if cfg not in config_metrics:
            config_metrics[cfg] = []
        config_metrics[cfg].append(metrics)

    print(f"\n{'Config':<22} {'ASR':>8} {'BSR':>8} {'FPR':>8} {'N':>4}")
    print("-" * 50)
    for cfg in args.configs:
        if cfg not in config_metrics:
            continue
        ms = config_metrics[cfg]
        n = len(ms)
        avg_asr = sum(m.get("asr", 0) for m in ms) / n
        avg_bsr = sum(m.get("bsr", 0) for m in ms) / n
        avg_fpr = sum(m.get("fpr", 0) for m in ms) / n
        print(f"{cfg:<22} {avg_asr:.4f}   {avg_bsr:.4f}   {avg_fpr:.4f}   {n:>3}")

    # Save experiment config
    exp_config = {
        "models": args.models,
        "configs": args.configs,
        "ablation_configs": {k: _make_json_safe(v) for k, v in ABLATION_CONFIGS.items()},
        "runs": args.runs,
        "benchmark_dir": str(args.benchmark_dir),
        "timestamp": datetime.now().isoformat(),
    }
    config_path = output_dir / "experiment_config.json"
    with open(config_path, "w") as fh:
        json.dump(exp_config, fh, indent=2)
    print(f"\nConfig saved to {config_path}")


if __name__ == "__main__":
    main()
