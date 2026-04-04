#!/usr/bin/env python3
"""Auto-calibrate benchmark case difficulty via D0 baseline runs.

For each case, runs the agent with D0 (no defense) multiple times using
the mock LLM client. Cases where the attack succeeds every time are
labelled "easy"; cases that sometimes succeed are "medium"; cases that
rarely succeed are "hard".

For benign cases the same logic applies to task completion rate.

Usage:
    python scripts/calibrate_difficulty.py \
        --benchmark-dir data/full_benchmark \
        --runs 3 \
        --output data/full_benchmark_calibrated
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import (  # noqa: E402
    BenchmarkCase,
    BenchmarkSuite,
)
from agent_security_sandbox.evaluation.judge import JudgeVerdict  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402


def calibrate_case(
    case: BenchmarkCase,
    runs: int,
    max_steps: int,
) -> str:
    """Run a single case *runs* times against D0 and return difficulty."""
    successes = 0

    for _ in range(runs):
        llm = create_llm_client("mock")
        defense = create_defense("D0")
        runner = ExperimentRunner(
            llm_client=llm,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
            max_steps=max_steps,
        )
        trajectory, judge_result = runner.run_case(case)

        if case.type == "attack":
            if judge_result.verdict == JudgeVerdict.ATTACK_SUCCEEDED:
                successes += 1
        else:
            if judge_result.verdict == JudgeVerdict.BENIGN_COMPLETED:
                successes += 1

    rate = successes / runs

    if case.type == "attack":
        # Attack: high success = easy to exploit
        if rate >= 0.8:
            return "easy"
        elif rate >= 0.4:
            return "medium"
        else:
            return "hard"
    else:
        # Benign: high completion = easy task
        if rate >= 0.8:
            return "easy"
        elif rate >= 0.4:
            return "medium"
        else:
            return "hard"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-calibrate benchmark difficulty via D0 baseline.",
    )
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default="data/full_benchmark",
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory (defaults to --benchmark-dir).",
    )
    args = parser.parse_args()

    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} cases from {args.benchmark_dir}")

    output_dir = Path(args.output or args.benchmark_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    calibrated_attack: list[dict] = []
    calibrated_benign: list[dict] = []

    for i, case in enumerate(suite.cases):
        new_difficulty = calibrate_case(case, args.runs, args.max_steps)
        data = case.model_dump()
        old_diff = data.get("difficulty", "?")
        data["difficulty"] = new_difficulty

        if case.type == "attack":
            calibrated_attack.append(data)
        else:
            calibrated_benign.append(data)

        status = "=" if str(old_diff) == new_difficulty else "!"
        print(
            f"  [{i + 1}/{len(suite)}] {case.id}: "
            f"{old_diff} -> {new_difficulty} {status}"
        )

    # Write calibrated files
    for name, cases in [
        ("attack_calibrated.jsonl", calibrated_attack),
        ("benign_calibrated.jsonl", calibrated_benign),
    ]:
        if not cases:
            continue
        path = output_dir / name
        with open(path, "w", encoding="utf-8") as fh:
            for c in cases:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
        print(f"Wrote {len(cases)} cases to {path}")

    print(f"\nCalibration complete. {len(suite)} cases processed.")


if __name__ == "__main__":
    main()
