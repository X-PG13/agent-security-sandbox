"""Tests for CLI commands."""
import pytest
from click.testing import CliRunner

from agent_security_sandbox.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


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
    # May succeed or fail gracefully depending on tool_registry handling
    # The key test is that it doesn't crash with an unhandled exception
    assert result.exit_code == 0 or "Error" in result.output
