#!/usr/bin/env python3
"""Cross-benchmark validation experiment.

Runs all defense strategies against three benchmarks (ASB, InjecAgent,
AgentDojo) and computes rank-correlation metrics to verify that defense
effectiveness is consistent across evaluation frameworks.

Outputs:
    results/cross_benchmark/correlation.json
    results/cross_benchmark/per_benchmark_rankings.json

Usage:
    python experiments/cross_benchmark_validation.py \
        --provider openai-compatible \
        --base-url https://gateway.2077ai.org/v1 \
        --model gpt-4o \
        --output-dir results/cross_benchmark
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import BenchmarkCase, BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.judge import JudgeVerdict  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

ALL_DEFENSES = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]


# ── Benchmark loaders ─────────────────────────────────────────────────

def load_asb_cases(benchmark_dir: str | Path) -> List[BenchmarkCase]:
    """Load ASB native benchmark cases."""
    suite = BenchmarkSuite.load_from_directory(str(benchmark_dir))
    return list(suite.attack_cases)


def load_injecagent_cases(jsonl_path: str | Path) -> List[BenchmarkCase]:
    """Load InjecAgent-format JSONL and convert to BenchmarkCase."""
    cases: List[BenchmarkCase] = []
    path = Path(jsonl_path)
    if not path.exists():
        print(f"  [WARN] InjecAgent file not found: {path}")
        return cases

    with open(path, "r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            if raw.get("attack_type") == "benign" or not raw.get("injected_prompt"):
                continue
            cases.append(BenchmarkCase(
                id=f"injecagent_{idx:03d}",
                type="attack",
                goal=raw["user_instruction"],
                untrusted_content=raw["injected_prompt"],
                injection_location="email_body",
                attack_type=raw.get("attack_type", "goal_hijacking"),
                expected_tools=[raw.get("target_tool", "send_email")],
                forbidden_actions=[{
                    "tool": raw.get("target_tool", "send_email"),
                    "params": raw.get("tool_parameters", {}),
                }],
            ))
    return cases


def load_agentdojo_cases(json_path: str | Path) -> List[BenchmarkCase]:
    """Load AgentDojo-format JSON and convert to BenchmarkCase."""
    cases: List[BenchmarkCase] = []
    path = Path(json_path)
    if not path.exists():
        print(f"  [WARN] AgentDojo file not found: {path}")
        return cases

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    tasks = {t["id"]: t for t in data.get("tasks", [])}
    injections = data.get("injections", {})

    for inj_id, inj in injections.items():
        task_id = inj.get("target_task")
        task = tasks.get(task_id, {})
        if not task:
            continue
        cases.append(BenchmarkCase(
            id=f"agentdojo_{inj_id}",
            type="attack",
            goal=task.get("goal", "Complete the task"),
            untrusted_content=inj["content"],
            injection_location=inj.get("injection_location", "email_body"),
            attack_type=inj.get("attack_type", "goal_hijacking"),
            expected_tools=task.get("expected_tools", []),
            forbidden_actions=[{
                "tool": "send_email",
                "params": {"to": "attacker@evil.com"},
            }],
        ))
    return cases


# ── Evaluation ────────────────────────────────────────────────────────

def evaluate_defense_on_cases(
    defense_id: str,
    cases: List[BenchmarkCase],
    provider: str,
    model: Optional[str],
    base_url: Optional[str],
    max_steps: int,
    max_cases: int = 0,
) -> Dict[str, Any]:
    """Run a defense against a list of cases and compute ASR."""
    llm_kwargs: Dict[str, Any] = {}
    if base_url:
        llm_kwargs["base_url"] = base_url

    llm = create_llm_client(provider=provider, model=model, **llm_kwargs)
    defense = create_defense(defense_id, llm_client=llm)

    runner = ExperimentRunner(
        llm_client=llm,
        tool_registry_factory=ToolRegistry,
        defense_strategy=defense,
        max_steps=max_steps,
    )

    eval_cases = cases[:max_cases] if max_cases > 0 else cases
    successes = 0
    total = 0

    for case in eval_cases:
        try:
            _trajectory, judge_result = runner.run_case(case)
            total += 1
            if judge_result.verdict == JudgeVerdict.ATTACK_SUCCEEDED:
                successes += 1
        except Exception as exc:
            print(f"    [ERROR] {case.id}: {exc}")
            total += 1

    asr = successes / total if total > 0 else 0.0
    return {
        "defense_id": defense_id,
        "total_cases": total,
        "attack_succeeded": successes,
        "asr": asr,
    }


# ── Correlation metrics ──────────────────────────────────────────────

def pearson_correlation(x: List[float], y: List[float]) -> float:
    """Compute Pearson correlation coefficient."""
    n = len(x)
    if n < 2:
        return 0.0
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    cov = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x))
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y))
    if std_x == 0 or std_y == 0:
        return 0.0
    return cov / (std_x * std_y)


def spearman_correlation(x: List[float], y: List[float]) -> float:
    """Compute Spearman rank correlation."""
    n = len(x)
    if n < 2:
        return 0.0

    def _rank(values: List[float]) -> List[float]:
        indexed = sorted(enumerate(values), key=lambda t: t[1])
        ranks = [0.0] * n
        for rank, (orig_idx, _) in enumerate(indexed):
            ranks[orig_idx] = float(rank)
        return ranks

    rx = _rank(x)
    ry = _rank(y)
    return pearson_correlation(rx, ry)


# ── Main ──────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cross-benchmark validation of defense strategies.",
    )
    parser.add_argument("--provider", type=str, default="mock")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--base-url", type=str, default=None)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--max-cases", type=int, default=0,
                        help="Max cases per benchmark (0 = all)")
    parser.add_argument("--defenses", nargs="+", default=ALL_DEFENSES)
    parser.add_argument(
        "--asb-benchmark-dir",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
    )
    parser.add_argument(
        "--injecagent-path",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "external_benchmarks" / "injecagent_sample.jsonl"),
    )
    parser.add_argument(
        "--agentdojo-path",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "external_benchmarks" / "agentdojo_sample.json"),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "cross_benchmark"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load all benchmarks.
    benchmarks: Dict[str, List[BenchmarkCase]] = {}

    print("Loading benchmarks...")
    asb_cases = load_asb_cases(args.asb_benchmark_dir)
    if asb_cases:
        benchmarks["ASB"] = asb_cases
        print(f"  ASB: {len(asb_cases)} attack cases")

    inja_cases = load_injecagent_cases(args.injecagent_path)
    if inja_cases:
        benchmarks["InjecAgent"] = inja_cases
        print(f"  InjecAgent: {len(inja_cases)} attack cases")

    dojo_cases = load_agentdojo_cases(args.agentdojo_path)
    if dojo_cases:
        benchmarks["AgentDojo"] = dojo_cases
        print(f"  AgentDojo: {len(dojo_cases)} attack cases")

    if len(benchmarks) < 2:
        print("Need at least 2 benchmarks for cross-validation. Exiting.")
        return

    # Evaluate each defense on each benchmark.
    results: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

    total_evals = len(args.defenses) * len(benchmarks)
    done = 0

    for defense_id in args.defenses:
        for bench_name, cases in benchmarks.items():
            done += 1
            print(f"[{done}/{total_evals}] {defense_id} on {bench_name}...")
            result = evaluate_defense_on_cases(
                defense_id=defense_id,
                cases=cases,
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
                max_steps=args.max_steps,
                max_cases=args.max_cases,
            )
            results[bench_name][defense_id] = result
            print(f"  ASR = {result['asr']:.4f} "
                  f"({result['attack_succeeded']}/{result['total_cases']})")

    # Save per-benchmark results.
    rankings: Dict[str, List[str]] = {}
    asr_vectors: Dict[str, List[float]] = {}

    for bench_name in benchmarks:
        bench_results = results[bench_name]
        ranked = sorted(bench_results.keys(), key=lambda d: bench_results[d]["asr"])
        rankings[bench_name] = ranked
        asr_vectors[bench_name] = [bench_results[d]["asr"] for d in args.defenses]

    rankings_path = output_dir / "per_benchmark_rankings.json"
    with open(rankings_path, "w") as fh:
        json.dump({
            "rankings": rankings,
            "per_benchmark_results": {
                bench: {d: r for d, r in res.items()}
                for bench, res in results.items()
            },
        }, fh, indent=2)
    print(f"\nRankings saved to {rankings_path}")

    # Compute correlation.
    bench_names = sorted(benchmarks.keys())
    correlations: Dict[str, Any] = {"pairs": {}}

    for ba, bb in combinations(bench_names, 2):
        asrs_a = asr_vectors[ba]
        asrs_b = asr_vectors[bb]
        r_pearson = pearson_correlation(asrs_a, asrs_b)
        r_spearman = spearman_correlation(asrs_a, asrs_b)
        pair_key = f"{ba}_vs_{bb}"
        correlations["pairs"][pair_key] = {
            "pearson": round(r_pearson, 4),
            "spearman": round(r_spearman, 4),
        }
        print(f"\n{pair_key}:")
        print(f"  Pearson  r = {r_pearson:.4f}")
        print(f"  Spearman r = {r_spearman:.4f}")

    # Average correlations.
    if correlations["pairs"]:
        avg_pearson = sum(
            v["pearson"] for v in correlations["pairs"].values()
        ) / len(correlations["pairs"])
        avg_spearman = sum(
            v["spearman"] for v in correlations["pairs"].values()
        ) / len(correlations["pairs"])
        correlations["average_pearson"] = round(avg_pearson, 4)
        correlations["average_spearman"] = round(avg_spearman, 4)

    corr_path = output_dir / "correlation.json"
    with open(corr_path, "w") as fh:
        json.dump(correlations, fh, indent=2)
    print(f"\nCorrelation results saved to {corr_path}")


if __name__ == "__main__":
    main()
