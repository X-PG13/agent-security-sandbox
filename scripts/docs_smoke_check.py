#!/usr/bin/env python3
"""Run a small set of executable smoke checks for documented commands."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(command: list[str], cwd: Path) -> None:
    print(f"$ {' '.join(command)}")
    subprocess.run(command, cwd=cwd, check=True)


def main() -> None:
    cli_module = ["-m", "agent_security_sandbox.cli.main"]

    with tempfile.TemporaryDirectory(prefix="asb-docs-smoke-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        results_dir = tmpdir_path / "results"

        _run(
            [
                sys.executable,
                *cli_module,
                "run",
                "Read email_001 and summarize it",
                "--provider",
                "mock",
                "--defense",
                "D5",
                "--quiet",
            ],
            cwd=PROJECT_ROOT,
        )

        _run(
            [
                sys.executable,
                *cli_module,
                "evaluate",
                "--suite",
                "mini",
                "--provider",
                "mock",
                "-d",
                "D0",
                "-d",
                "D5",
                "-d",
                "D10",
                "-o",
                str(results_dir),
            ],
            cwd=PROJECT_ROOT,
        )

        _run(
            [
                sys.executable,
                *cli_module,
                "report",
                "--results-dir",
                str(results_dir),
                "--format",
                "markdown",
            ],
            cwd=PROJECT_ROOT,
        )

        api_check = """
from pathlib import Path
from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.defenses.registry import create_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner
from agent_security_sandbox.tools.registry import ToolRegistry

suite = BenchmarkSuite.load_from_directory(str(Path("data/mini_benchmark")))
llm = create_llm_client("mock", model="mock")
defense = create_defense("D10", llm_client=llm)
runner = ExperimentRunner(
    llm_client=llm,
    tool_registry_factory=ToolRegistry,
    defense_strategy=defense,
    max_steps=5,
)
result = runner.run_suite(suite.filter_by_type("benign"))
assert result.metrics.bsr >= 0
print("python-api-smoke: ok")
"""
        _run([sys.executable, "-c", api_check], cwd=PROJECT_ROOT)

        expected = [
            results_dir / "results_D0.json",
            results_dir / "results_D5.json",
            results_dir / "results_D10.json",
            results_dir / "report.md",
        ]
        missing = [str(path) for path in expected if not path.exists()]
        if missing:
            raise SystemExit(f"Missing smoke-check outputs: {missing}")

        print("Docs smoke checks passed.")


if __name__ == "__main__":
    main()
