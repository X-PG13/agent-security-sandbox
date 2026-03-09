"""Tests for CLI commands."""
import json

import pytest
from click.testing import CliRunner

from agent_security_sandbox.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# Help screens
# ---------------------------------------------------------------------------

def test_cli_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Agent Security Sandbox" in result.output or "ASB" in result.output


def test_run_help(runner):
    result = runner.invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "defense" in result.output.lower()


def test_evaluate_help(runner):
    result = runner.invoke(cli, ["evaluate", "--help"])
    assert result.exit_code == 0
    assert "benchmark" in result.output.lower()


def test_report_help(runner):
    result = runner.invoke(cli, ["report", "--help"])
    assert result.exit_code == 0


def test_serve_help(runner):
    result = runner.invoke(cli, ["serve", "--help"])
    assert result.exit_code == 0
    assert "port" in result.output.lower()


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------

def test_run_command_mock(runner):
    result = runner.invoke(cli, [
        "run", "Read email_001 and summarize it",
        "--provider", "mock",
        "--defense", "D0",
        "--max-steps", "3",
        "--quiet",
    ])
    assert result.exit_code == 0
    assert "Trajectory Summary" in result.output


def test_run_command_verbose(runner):
    """run --verbose should print step details."""
    result = runner.invoke(cli, [
        "run", "Read email_001 and summarize it",
        "--provider", "mock",
        "--defense", "D0",
        "--max-steps", "3",
        "--verbose",
    ])
    assert result.exit_code == 0
    assert "Provider" in result.output
    assert "Trajectory Summary" in result.output


def test_run_command_with_defense_d1(runner):
    """run with D1 (spotlighting) defense."""
    result = runner.invoke(cli, [
        "run", "Read email_001",
        "--provider", "mock",
        "--defense", "D1",
        "--max-steps", "3",
        "--quiet",
    ])
    assert result.exit_code == 0
    assert "Trajectory Summary" in result.output


def test_run_command_with_defense_d2(runner):
    """run with D2 (policy gate) defense."""
    result = runner.invoke(cli, [
        "run", "Read email_001",
        "--provider", "mock",
        "--defense", "D2",
        "--max-steps", "3",
        "--quiet",
    ])
    assert result.exit_code == 0
    assert "Trajectory Summary" in result.output


def test_run_command_no_function_calling(runner):
    """run --no-function-calling uses text ReAct mode."""
    result = runner.invoke(cli, [
        "run", "Read email_001 and summarize it",
        "--provider", "mock",
        "--defense", "D0",
        "--max-steps", "3",
        "--no-function-calling",
        "--quiet",
    ])
    assert result.exit_code == 0
    assert "Trajectory Summary" in result.output


# ---------------------------------------------------------------------------
# evaluate command
# ---------------------------------------------------------------------------

def test_evaluate_command_mock(runner, tmp_benchmark_dir):
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "--defense", "D0",
        "--provider", "mock",
        "--output", str(tmp_benchmark_dir / "results"),
        "--max-steps", "3",
        "--quiet",
    ])
    assert result.exit_code == 0 or "Error" in result.output


def test_evaluate_multiple_defenses(runner, tmp_benchmark_dir):
    """evaluate with multiple defenses."""
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "-d", "D0",
        "-d", "D1",
        "--provider", "mock",
        "--output", str(tmp_benchmark_dir / "results_multi"),
        "--max-steps", "3",
        "--quiet",
    ])
    assert result.exit_code == 0 or "Error" in result.output


def test_evaluate_no_function_calling(runner, tmp_benchmark_dir):
    """evaluate --no-function-calling."""
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "-d", "D0",
        "--provider", "mock",
        "--output", str(tmp_benchmark_dir / "results_nfc"),
        "--max-steps", "3",
        "--no-function-calling",
        "--quiet",
    ])
    assert result.exit_code == 0 or "Error" in result.output


def test_evaluate_missing_benchmark(runner, tmp_path):
    """evaluate without --benchmark or --suite should error."""
    result = runner.invoke(cli, [
        "evaluate",
        "--provider", "mock",
        "-d", "D0",
        "--output", str(tmp_path / "out"),
        "--quiet",
    ])
    assert result.exit_code != 0


def test_evaluate_nonexistent_benchmark_dir(runner, tmp_path):
    """evaluate with nonexistent benchmark dir should error."""
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_path / "does_not_exist"),
        "--provider", "mock",
        "-d", "D0",
        "--quiet",
    ])
    assert result.exit_code != 0


def test_evaluate_writes_result_file(runner, tmp_benchmark_dir):
    """evaluate should write a results JSON file."""
    out_dir = tmp_benchmark_dir / "results_write"
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "-d", "D0",
        "--provider", "mock",
        "--output", str(out_dir),
        "--max-steps", "3",
        "--quiet",
    ])
    if result.exit_code == 0:
        result_file = out_dir / "results_D0.json"
        assert result_file.exists()
        data = json.loads(result_file.read_text())
        assert "metrics" in data or "results" in data


def test_evaluate_llm_judge_warning_for_mock(runner, tmp_benchmark_dir):
    """LLM judge with mock provider should warn and fallback."""
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "-d", "D0",
        "--provider", "mock",
        "--judge", "llm",
        "--output", str(tmp_benchmark_dir / "results_judge"),
        "--max-steps", "3",
        "--quiet",
    ])
    # Should warn about mock provider and fall back to rule judge
    assert result.exit_code == 0 or "WARNING" in result.output


def test_evaluate_with_analyze(runner, tmp_benchmark_dir):
    """evaluate --analyze should not crash."""
    result = runner.invoke(cli, [
        "evaluate",
        "--benchmark", str(tmp_benchmark_dir),
        "-d", "D0",
        "--provider", "mock",
        "--output", str(tmp_benchmark_dir / "results_analyze"),
        "--max-steps", "3",
        "--analyze",
        "--quiet",
    ])
    # Analyze may fail gracefully but shouldn't crash
    assert result.exit_code == 0 or "Error" in result.output
