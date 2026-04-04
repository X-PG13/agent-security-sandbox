#!/usr/bin/env python3
"""Per-defense adaptive attack experiment.

Runs the adaptive attacker against a target defense and reports
bypass success rates across multiple iterations.

Improvements over v1:
  - --base-url support for API proxies
  - --all-defenses to attack all D0-D10 in one run
  - Learning curve tracking (success rate vs iteration)
  - Defense resilience scoring (median iterations to first bypass)
  - Static baseline comparison (fixed payload, no optimisation)

Usage:
    python experiments/run_adaptive_attack.py \
        --target-defense D1 --attacker-model mock --max-iterations 5

    python experiments/run_adaptive_attack.py \
        --all-defenses \
        --attacker-model gpt-4o \
        --attacker-provider openai-compatible \
        --agent-provider openai-compatible \
        --agent-model gpt-4o \
        --base-url https://gateway.2077ai.org/v1 \
        --max-iterations 10 --num-cases 20
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.adversary.attacker import AdaptiveAttacker  # noqa: E402
from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.judge import JudgeVerdict  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

ALL_DEFENSES = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]


def make_evaluator(
    defense_id: str,
    agent_provider: str,
    agent_model: str | None,
    goal: str,
    case_template: Dict[str, Any],
    max_steps: int,
    base_url: str | None = None,
):
    """Return a callable (payload) -> (success, feedback)."""
    from agent_security_sandbox.evaluation.benchmark import BenchmarkCase

    def evaluate(payload: str) -> Tuple[bool, str]:
        llm_kwargs: Dict[str, Any] = {}
        if base_url:
            llm_kwargs["base_url"] = base_url
        llm = create_llm_client(agent_provider, agent_model, **llm_kwargs)
        defense = create_defense(defense_id, llm_client=llm)
        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
            max_steps=max_steps,
        )
        case = BenchmarkCase(
            id="adaptive_test",
            type="attack",
            goal=goal,
            untrusted_content=payload,
            injection_location=case_template.get("injection_location", "email_body"),
            attack_type=case_template.get("attack_type", "data_exfiltration"),
            expected_tools=case_template.get("expected_tools", ["read_email"]),
            forbidden_actions=case_template.get("forbidden_actions", [
                {"tool": "send_email", "params": {"to": "attacker@evil.com"}},
            ]),
        )
        trajectory, judge_result = runner.run_case(case)
        success = judge_result.verdict == JudgeVerdict.ATTACK_SUCCEEDED
        feedback = judge_result.reason
        return success, feedback

    return evaluate


def run_static_baseline(
    defense_id: str,
    cases: list,
    agent_provider: str,
    agent_model: str | None,
    max_steps: int,
    base_url: str | None = None,
) -> Dict[str, Any]:
    """Run a static (non-adaptive) baseline attack for comparison."""
    successes = 0
    total = 0
    for case in cases:
        try:
            llm_kwargs: Dict[str, Any] = {}
            if base_url:
                llm_kwargs["base_url"] = base_url
            llm = create_llm_client(agent_provider, agent_model, **llm_kwargs)
            defense = create_defense(defense_id, llm_client=llm)
            runner = ExperimentRunner(
                llm_client=llm,
                tool_registry_factory=ToolRegistry,
                defense_strategy=defense,
                max_steps=max_steps,
            )
            _trajectory, judge_result = runner.run_case(case)
            total += 1
            if judge_result.verdict == JudgeVerdict.ATTACK_SUCCEEDED:
                successes += 1
        except Exception:
            total += 1

    return {
        "static_asr": successes / max(total, 1),
        "successes": successes,
        "total": total,
    }


def compute_learning_curve(campaigns: list) -> List[Dict[str, Any]]:
    """Compute success rate at each iteration step across all campaigns."""
    if not campaigns:
        return []

    max_iters = max(c.total_iterations for c in campaigns)
    curve = []
    for step in range(1, max_iters + 1):
        successes_by_step = 0
        total_with_step = 0
        for c in campaigns:
            if c.total_iterations >= step:
                total_with_step += 1
                # Check if success was achieved by this step
                iterations = getattr(c, "iterations", [])
                if any(
                    getattr(it, "success", False)
                    for it in iterations[:step]
                ):
                    successes_by_step += 1
                elif c.final_success and c.total_iterations <= step:
                    successes_by_step += 1

        curve.append({
            "iteration": step,
            "success_rate": successes_by_step / max(total_with_step, 1),
            "campaigns_at_step": total_with_step,
        })
    return curve


def compute_resilience_scores(
    all_defense_results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute defense resilience = median iterations to first bypass."""
    scores = {}
    for defense_id, result in all_defense_results.items():
        campaigns = result.get("campaigns_raw", [])
        iters_to_bypass = []
        for c in campaigns:
            if c.final_success:
                iters_to_bypass.append(c.total_iterations)

        if iters_to_bypass:
            scores[defense_id] = {
                "median_iters_to_bypass": statistics.median(iters_to_bypass),
                "mean_iters_to_bypass": round(
                    statistics.mean(iters_to_bypass), 2
                ),
                "min_iters": min(iters_to_bypass),
                "max_iters": max(iters_to_bypass),
                "bypass_count": len(iters_to_bypass),
                "total_cases": len(campaigns),
            }
        else:
            scores[defense_id] = {
                "median_iters_to_bypass": float("inf"),
                "mean_iters_to_bypass": float("inf"),
                "min_iters": None,
                "max_iters": None,
                "bypass_count": 0,
                "total_cases": len(campaigns),
            }

    # Rank by resilience (higher median = more resilient)
    ranked = sorted(
        scores.items(),
        key=lambda x: (
            x[1]["median_iters_to_bypass"]
            if x[1]["median_iters_to_bypass"] != float("inf")
            else 999
        ),
        reverse=True,
    )
    return {
        "scores": scores,
        "ranking": [d for d, _ in ranked],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Adaptive attack experiment.")
    parser.add_argument("--target-defense", type=str, default="D1")
    parser.add_argument("--all-defenses", action="store_true",
                        help="Attack all D0-D10 defenses.")
    parser.add_argument("--attacker-model", type=str, default="mock")
    parser.add_argument("--attacker-provider", type=str, default=None)
    parser.add_argument("--agent-provider", type=str, default="mock")
    parser.add_argument("--agent-model", type=str, default=None)
    parser.add_argument("--base-url", type=str, default=None,
                        help="API base URL (for openai-compatible provider).")
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--num-cases", type=int, default=10)
    parser.add_argument("--run-static-baseline", action="store_true",
                        help="Also run static (non-adaptive) baseline.")
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "adaptive_attack"),
    )
    return parser.parse_args()


def run_for_defense(
    defense_id: str, args: argparse.Namespace, attack_cases: list,
    attacker: AdaptiveAttacker, output_dir: Path,
) -> Dict[str, Any]:
    """Run adaptive attack campaign against a single defense."""
    print(f"\n{'=' * 60}")
    print(f"Attacking defense: {defense_id}")
    print(f"{'=' * 60}")

    campaigns = []
    for i, case in enumerate(attack_cases):
        print(f"  [{i + 1}/{len(attack_cases)}] {case.id}")

        evaluator = make_evaluator(
            defense_id=defense_id,
            agent_provider=args.agent_provider,
            agent_model=args.agent_model,
            goal=case.goal,
            case_template=case.model_dump(),
            max_steps=args.max_steps,
            base_url=args.base_url,
        )

        forbidden_str = json.dumps(
            case.forbidden_actions[0] if case.forbidden_actions else {},
        )

        campaign = attacker.iterative_attack(
            goal=case.goal,
            injection_location=case.injection_location or "email_body",
            forbidden_action=forbidden_str,
            evaluate_fn=evaluator,
        )
        campaign.case_id = case.id
        campaigns.append(campaign)

        status = "SUCCESS" if campaign.final_success else "FAILED"
        print(f"    {status} after {campaign.total_iterations} iterations")

    # Compute metrics
    successes = sum(1 for c in campaigns if c.final_success)
    success_rate = successes / max(len(campaigns), 1)
    avg_iterations = sum(
        c.total_iterations for c in campaigns
    ) / max(len(campaigns), 1)

    # Learning curve
    learning_curve = compute_learning_curve(campaigns)

    # Static baseline (optional)
    static_baseline = None
    if args.run_static_baseline:
        print(f"  Running static baseline for {defense_id}...")
        static_baseline = run_static_baseline(
            defense_id=defense_id,
            cases=attack_cases,
            agent_provider=args.agent_provider,
            agent_model=args.agent_model,
            max_steps=args.max_steps,
            base_url=args.base_url,
        )
        print(f"    Static ASR: {static_baseline['static_asr']:.2%}")

    # Summary
    print(f"\n  {defense_id} Results:")
    print(f"    Adaptive ASR: {success_rate:.2%}")
    print(f"    Avg iterations: {avg_iterations:.1f}")
    if static_baseline:
        print(f"    Static ASR:    {static_baseline['static_asr']:.2%}")
        print(f"    Adaptive gain: "
              f"{success_rate - static_baseline['static_asr']:+.2%}")

    result = {
        "defense": defense_id,
        "attacker_model": args.attacker_model,
        "success_rate": success_rate,
        "avg_iterations": round(avg_iterations, 2),
        "learning_curve": learning_curve,
        "static_baseline": static_baseline,
        "campaigns": [c.to_dict() for c in campaigns],
        "campaigns_raw": campaigns,  # kept in-memory only, not serialised
    }

    # Save per-defense results
    save_result = {k: v for k, v in result.items() if k != "campaigns_raw"}
    results_path = output_dir / f"adaptive_{defense_id}.json"
    with open(results_path, "w") as fh:
        json.dump(save_result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"  Saved to {results_path}")

    return result


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine target defenses
    if args.all_defenses:
        target_defenses = ALL_DEFENSES
    else:
        target_defenses = [args.target_defense]

    # Create attacker LLM
    provider = args.attacker_provider or (
        "mock" if args.attacker_model == "mock" else "openai-compatible"
    )
    attacker_kwargs: Dict[str, Any] = {}
    if args.base_url:
        attacker_kwargs["base_url"] = args.base_url

    attacker_llm = create_llm_client(
        provider=provider,
        model=None if args.attacker_model == "mock" else args.attacker_model,
        **attacker_kwargs,
    )

    # Load attack cases
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    attack_cases = suite.attack_cases[: args.num_cases]

    print("Adaptive attack experiment")
    print(f"  Defenses: {target_defenses}")
    print(f"  Attacker model: {args.attacker_model}")
    print(f"  Cases: {len(attack_cases)}")
    print(f"  Max iterations: {args.max_iterations}")
    if args.base_url:
        print(f"  Base URL: {args.base_url}")

    # Run for each defense
    all_defense_results: Dict[str, Dict[str, Any]] = {}

    for defense_id in target_defenses:
        attacker = AdaptiveAttacker(
            llm_client=attacker_llm,
            target_defense=defense_id,
            max_iterations=args.max_iterations,
        )
        result = run_for_defense(
            defense_id, args, attack_cases, attacker, output_dir,
        )
        all_defense_results[defense_id] = result

    # Compute resilience scores across all defenses
    if len(target_defenses) > 1:
        resilience = compute_resilience_scores(all_defense_results)
        resilience_path = output_dir / "resilience_scores.json"

        # Convert inf to string for JSON serialisation
        serialisable = json.loads(
            json.dumps(resilience, default=lambda x: "inf" if x == float("inf") else str(x))
        )
        with open(resilience_path, "w") as fh:
            json.dump(serialisable, fh, indent=2)
        print(f"\nResilience scores saved to {resilience_path}")
        print("\nDefense resilience ranking (most resilient first):")
        for rank, d_id in enumerate(resilience["ranking"], 1):
            s = resilience["scores"][d_id]
            med = s["median_iters_to_bypass"]
            med_str = f"{med:.1f}" if med != float("inf") else "never bypassed"
            print(f"  {rank}. {d_id}: median={med_str}, "
                  f"bypassed={s['bypass_count']}/{s['total_cases']}")

    # Print overall summary
    print(f"\n{'=' * 60}")
    print("OVERALL SUMMARY")
    print(f"{'=' * 60}")
    print(f"{'Defense':<10} {'Adaptive ASR':>14} {'Avg Iters':>10}"
          + ("  Static ASR" if args.run_static_baseline else ""))
    print("-" * (34 + (12 if args.run_static_baseline else 0)))
    for d_id in target_defenses:
        r = all_defense_results[d_id]
        line = f"{d_id:<10} {r['success_rate']:>13.2%} {r['avg_iterations']:>10.1f}"
        if args.run_static_baseline and r.get("static_baseline"):
            line += f"  {r['static_baseline']['static_asr']:>10.2%}"
        print(line)


if __name__ == "__main__":
    main()
