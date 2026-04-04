#!/usr/bin/env python3
"""Run ASB evaluation on an external benchmark (InjecAgent or AgentDojo).

Usage:
    python experiments/run_external_benchmark.py \
        --adapter injecagent --data-path /path/to/injecagent.jsonl \
        --defenses D0 D1 D5 D10 --provider mock

    # Cross-benchmark comparison (run both, then combine)
    python experiments/run_external_benchmark.py \
        --adapter injecagent --data-path data/external_benchmarks/injecagent_sample.jsonl \
        --defenses D0 D1 D5 D8 D9 D10 --provider mock \
        --output-dir results/external/injecagent

    python experiments/run_external_benchmark.py \
        --adapter agentdojo --data-path data/external_benchmarks/agentdojo_sample.json \
        --defenses D0 D1 D5 D8 D9 D10 --provider mock \
        --output-dir results/external/agentdojo
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

from agent_security_sandbox.adapters.agentdojo import AgentDojoAdapter  # noqa: E402
from agent_security_sandbox.adapters.injecagent import InjecAgentAdapter  # noqa: E402
from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

ADAPTERS = {
    "injecagent": InjecAgentAdapter,
    "agentdojo": AgentDojoAdapter,
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
    parser = argparse.ArgumentParser(description="External benchmark evaluation.")
    parser.add_argument("--adapter", choices=list(ADAPTERS), required=True)
    parser.add_argument("--data-path", type=str, required=True)
    parser.add_argument(
        "--defenses", nargs="+",
        default=["D0", "D1", "D5", "D8", "D9", "D10"],
    )
    parser.add_argument("--provider", type=str, default="mock")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--base-url", type=str, default=None)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "external"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    adapter_cls = ADAPTERS[args.adapter]
    adapter = adapter_cls()
    suite = adapter.load_as_suite(args.data_path)

    if args.max_cases:
        suite = type(suite)(suite.cases[: args.max_cases])

    print(f"Adapter: {adapter.name}")
    print(f"Loaded {len(suite)} cases ({len(suite.attack_cases)} attack, "
          f"{len(suite.benign_cases)} benign)")
    print(f"Defenses: {args.defenses}")
    print()

    all_results: Dict[str, Any] = {}
    for defense_id in args.defenses:
        print(f"--- Defense: {defense_id} ---")
        llm_kwargs: Dict[str, Any] = {}
        if args.base_url:
            llm_kwargs["base_url"] = args.base_url
        llm = create_llm_client(args.provider, args.model, **llm_kwargs)
        defense = create_defense(defense_id, llm_client=llm)
        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
            max_steps=args.max_steps,
        )

        start_time = time.time()
        result = runner.run_suite(suite)
        elapsed = time.time() - start_time

        m = result.metrics
        print(f"  ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  ({elapsed:.1f}s)")

        # Per-case results for detailed analysis
        case_results: List[Dict[str, Any]] = []
        if hasattr(result, "case_results"):
            for cr in result.case_results:
                case_results.append(_make_json_safe(cr))

        all_results[defense_id] = {
            "asr": m.asr,
            "bsr": m.bsr,
            "fpr": m.fpr,
            "total_cost": m.total_cost,
            "elapsed_seconds": round(elapsed, 2),
            "case_results": case_results,
        }

    # Save full results
    results_path = output_dir / f"{args.adapter}_results.json"
    with open(results_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"\nResults saved to {results_path}")

    # Print comparison table
    print(f"\n{'='*60}")
    print(f"CROSS-BENCHMARK COMPARISON: {args.adapter}")
    print(f"{'='*60}")
    print(f"\n{'Defense':<12} {'ASR':>8} {'BSR':>8} {'FPR':>8} {'Time(s)':>8}")
    print("-" * 50)
    for defense_id, data in all_results.items():
        print(f"{defense_id:<12} {data['asr']:.4f}   {data['bsr']:.4f}   "
              f"{data['fpr']:.4f}   {data.get('elapsed_seconds', 0):>6.1f}")

    # Save experiment metadata
    meta = {
        "adapter": args.adapter,
        "data_path": str(args.data_path),
        "defenses": args.defenses,
        "provider": args.provider,
        "model": args.model,
        "num_cases": len(suite),
        "num_attack": len(suite.attack_cases),
        "num_benign": len(suite.benign_cases),
        "timestamp": datetime.now().isoformat(),
    }
    meta_path = output_dir / f"{args.adapter}_meta.json"
    with open(meta_path, "w") as fh:
        json.dump(meta, fh, indent=2)


if __name__ == "__main__":
    main()
