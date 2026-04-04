#!/usr/bin/env python3
"""
Run baseline defense evaluations (D0 through D5).

Evaluates each individual defense strategy against the benchmark suite and
produces per-defense results, a combined JSON output, and a Markdown report.

Usage:
    python experiments/run_baseline.py \
        --benchmark-dir data/mini_benchmark \
        --provider openai \
        --model gpt-4o \
        --output-dir experiments/results
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Ensure the project root (one level above ``experiments/``) and the ``src/``
# directory are on ``sys.path`` so that imports work when running the script
# directly.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
_SRC_DIR = _PROJECT_ROOT / "src"

for _p in (_PROJECT_ROOT, _SRC_DIR):
    _p_str = str(_p)
    if _p_str not in sys.path:
        sys.path.insert(0, _p_str)

from agent_security_sandbox.core.llm_client import create_llm_client  # noqa: E402
from agent_security_sandbox.defenses.registry import create_defense  # noqa: E402
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.reporter import Reporter  # noqa: E402
from agent_security_sandbox.evaluation.runner import ExperimentRunner  # noqa: E402
from agent_security_sandbox.tools.registry import ToolRegistry  # noqa: E402

# ---------------------------------------------------------------------------
# Defense identifiers to evaluate
# ---------------------------------------------------------------------------
DEFENSE_IDS: List[str] = ["D0", "D1", "D2", "D3", "D4", "D5"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run baseline evaluation for each defense strategy (D0-D5).",
    )
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
        help="Path to the directory containing benchmark JSONL files. "
             "Default: data/mini_benchmark",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="openai",
        choices=["openai", "anthropic", "openai-compatible", "mock"],
        help="LLM provider to use. Default: openai",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model name. Defaults to the provider's default model.",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="Custom base URL for OpenAI-compatible endpoints.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_SCRIPT_DIR / "results"),
        help="Directory where results and reports are written. "
             "Default: experiments/results",
    )
    return parser.parse_args()


def _build_llm_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    """Build keyword arguments for ``create_llm_client``."""
    kwargs: Dict[str, Any] = {}
    if args.base_url:
        kwargs["base_url"] = args.base_url
    return kwargs


def _make_json_safe(obj: Any) -> Any:
    """Recursively convert non-serialisable objects for JSON output.

    Handles ``Enum`` members (e.g. ``JudgeVerdict``) by extracting their
    ``.value``, and falls through to ``str()`` for anything else unknown.
    """
    from enum import Enum

    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    # Fallback for dataclasses and other objects
    if hasattr(obj, "__dict__"):
        return {k: _make_json_safe(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


def _serialize_result(result: Any) -> Dict[str, Any]:
    """Convert an ExperimentResult to a JSON-serialisable dictionary.

    ``ExperimentResult`` may contain non-serialisable objects (such as
    ``JudgeVerdict`` enums) so we do a recursive conversion.
    """
    data: Dict[str, Any] = {
        "defense_name": getattr(result, "defense_name", str(result)),
        "timestamp": getattr(result, "timestamp", datetime.now().isoformat()),
    }

    # Metrics
    metrics = getattr(result, "metrics", None)
    if metrics is not None:
        if isinstance(metrics, dict):
            data["metrics"] = _make_json_safe(metrics)
        else:
            data["metrics"] = _make_json_safe(
                {k: v for k, v in vars(metrics).items() if not k.startswith("_")}
            )
    else:
        data["metrics"] = {}

    # Individual case results
    results_list = getattr(result, "results", [])
    serialised_results: List[Dict[str, Any]] = []
    for r in results_list:
        if isinstance(r, dict):
            serialised_results.append(_make_json_safe(r))
        else:
            serialised_results.append(
                _make_json_safe(
                    {k: v for k, v in vars(r).items() if not k.startswith("_")}
                )
            )
    data["results"] = serialised_results

    return data


def _print_summary_table(all_results: Dict[str, Any]) -> None:
    """Print a compact summary table to stdout."""
    header = f"{'Defense':<12} {'ASR':>8} {'BSR':>8} {'FPR':>8}"
    sep = "-" * len(header)
    print("\n" + sep)
    print(header)
    print(sep)

    for defense_id, result_data in all_results.items():
        metrics = result_data.get("metrics", {})
        asr = metrics.get("attack_success_rate", metrics.get("asr", "N/A"))
        bsr = metrics.get("benign_success_rate", metrics.get("bsr", "N/A"))
        fpr = metrics.get("false_positive_rate", metrics.get("fpr", "N/A"))

        asr_str = f"{asr:.4f}" if isinstance(asr, (int, float)) else str(asr)
        bsr_str = f"{bsr:.4f}" if isinstance(bsr, (int, float)) else str(bsr)
        fpr_str = f"{fpr:.4f}" if isinstance(fpr, (int, float)) else str(fpr)

        print(f"{defense_id:<12} {asr_str:>8} {bsr_str:>8} {fpr_str:>8}")
    print(sep + "\n")


def _generate_markdown_report(
    all_results: Dict[str, Any],
    output_path: Path,
    args: argparse.Namespace,
) -> None:
    """Write a Markdown report summarising all defense evaluations."""
    lines: List[str] = []
    lines.append("# Baseline Defense Evaluation Report")
    lines.append("")
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Provider:** {args.provider}")
    lines.append(f"**Model:** {args.model or '(default)'}")
    lines.append(f"**Benchmark:** {args.benchmark_dir}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Defense | ASR | BSR | FPR |")
    lines.append("|---------|-----|-----|-----|")

    for defense_id, result_data in all_results.items():
        metrics = result_data.get("metrics", {})
        asr = metrics.get("attack_success_rate", metrics.get("asr", "N/A"))
        bsr = metrics.get("benign_success_rate", metrics.get("bsr", "N/A"))
        fpr = metrics.get("false_positive_rate", metrics.get("fpr", "N/A"))

        def _fmt(v: Any) -> str:
            if isinstance(v, float):
                return f"{v:.4f}"
            return str(v)

        lines.append(f"| {defense_id} | {_fmt(asr)} | {_fmt(bsr)} | {_fmt(fpr)} |")

    lines.append("")

    # Per-defense details
    lines.append("## Per-Defense Details")
    lines.append("")
    for defense_id, result_data in all_results.items():
        lines.append(f"### {defense_id}")
        lines.append("")
        metrics = result_data.get("metrics", {})
        for key, value in metrics.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")
        num_cases = len(result_data.get("results", []))
        lines.append(f"- Total cases evaluated: {num_cases}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Markdown report saved to {output_path}")


def main() -> None:
    args = parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark suite
    benchmark_dir = Path(args.benchmark_dir)
    print(f"Loading benchmark suite from {benchmark_dir} ...")
    suite = BenchmarkSuite.load_from_directory(str(benchmark_dir))
    print(f"  Loaded {len(suite)} cases "
          f"({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)")

    # Create LLM client
    llm_kwargs = _build_llm_kwargs(args)
    llm_client = create_llm_client(
        provider=args.provider,
        model=args.model,
        **llm_kwargs,
    )

    all_results: Dict[str, Any] = {}

    for defense_id in DEFENSE_IDS:
        print(f"\n{'='*60}")
        print(f"Evaluating defense: {defense_id}")
        print(f"{'='*60}")

        # Create defense strategy
        defense = create_defense(defense_id, llm_client=llm_client)

        # Build runner -- tool_registry_factory produces a fresh ToolRegistry
        # for each case so that per-case tool state does not leak.
        runner = ExperimentRunner(
            llm_client=llm_client,
            tool_registry_factory=ToolRegistry,
            defense_strategy=defense,
        )

        # Run the suite
        experiment_result = runner.run_suite(suite)

        # Serialise and store
        result_data = _serialize_result(experiment_result)
        all_results[defense_id] = result_data

        # Save individual result
        individual_path = output_dir / f"baseline_{defense_id}.json"
        with open(individual_path, "w", encoding="utf-8") as fh:
            json.dump(result_data, fh, indent=2, default=str)
        print(f"  Results saved to {individual_path}")

    # Save combined results
    combined_path = output_dir / "baseline_all.json"
    with open(combined_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, default=str)
    print(f"\nCombined results saved to {combined_path}")

    # Generate Markdown report
    report_path = output_dir / "baseline_report.md"
    _generate_markdown_report(all_results, report_path, args)

    # Print summary table to stdout
    _print_summary_table(all_results)

    # Optionally use the project Reporter if available
    try:
        reporter = Reporter()
        reporter_output = output_dir / "baseline_reporter_output.md"
        content = reporter.generate_markdown([])
        Reporter.save_report(content, str(reporter_output))
        print(f"Reporter output saved to {reporter_output}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
