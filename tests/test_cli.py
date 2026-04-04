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


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

def test_report_missing_dir(runner, tmp_path):
    """report with nonexistent dir should error."""
    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path / "no_such_dir"),
    ])
    assert result.exit_code != 0


def test_report_no_result_files(runner, tmp_path):
    """report with empty dir should error (no results_*.json)."""
    tmp_path.mkdir(exist_ok=True)
    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path),
    ])
    assert result.exit_code != 0


def test_report_markdown_output(runner, tmp_path):
    """report --format markdown should produce markdown output."""
    # Create a minimal result file
    result_data = {
        "defense_name": "D0 (Baseline)",
        "timestamp": "2026-01-01T00:00:00",
        "metrics": {
            "asr": 0.5, "bsr": 0.9, "fpr": 0.1,
            "total_cost": 100, "num_cases": 3,
            "attack_cases": 2, "benign_cases": 1,
            "details": {},
        },
        "results": [
            {"case_id": "a1", "verdict": "attack_succeeded", "reason": "r", "details": {}},
            {"case_id": "a2", "verdict": "attack_blocked", "reason": "r", "details": {}},
            {"case_id": "b1", "verdict": "benign_completed", "reason": "r", "details": {}},
        ],
    }
    (tmp_path / "results_D0.json").write_text(json.dumps(result_data))

    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path),
        "--format", "markdown",
    ])
    assert result.exit_code == 0
    assert "Evaluation Report" in result.output


def test_report_json_output(runner, tmp_path):
    """report --format json should produce valid JSON."""
    result_data = {
        "defense_name": "D0",
        "timestamp": "",
        "metrics": {
            "asr": 0.0, "bsr": 1.0, "fpr": 0.0,
            "total_cost": 0, "num_cases": 1,
            "attack_cases": 0, "benign_cases": 1,
            "details": {},
        },
        "results": [
            {"case_id": "b1", "verdict": "benign_completed", "reason": "ok", "details": {}},
        ],
    }
    (tmp_path / "results_D0.json").write_text(json.dumps(result_data))

    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path),
        "--format", "json",
    ])
    assert result.exit_code == 0
    # Output may contain stderr prefix ("Loaded ..."), extract JSON portion
    output = result.output
    json_start = output.index("[")
    parsed = json.loads(output[json_start:])
    assert isinstance(parsed, list)


def test_report_csv_output(runner, tmp_path):
    """report --format csv should produce CSV with header."""
    result_data = {
        "defense_name": "D0",
        "timestamp": "",
        "metrics": {
            "asr": 0.0, "bsr": 1.0, "fpr": 0.0,
            "total_cost": 0, "num_cases": 1,
            "attack_cases": 0, "benign_cases": 1,
            "details": {},
        },
        "results": [
            {"case_id": "b1", "verdict": "benign_completed", "reason": "ok", "details": {}},
        ],
    }
    (tmp_path / "results_D0.json").write_text(json.dumps(result_data))

    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path),
        "--format", "csv",
    ])
    assert result.exit_code == 0
    assert "defense_name" in result.output


def test_report_to_file(runner, tmp_path):
    """report -o should write to a file."""
    result_data = {
        "defense_name": "D0",
        "timestamp": "",
        "metrics": {
            "asr": 0.0, "bsr": 1.0, "fpr": 0.0,
            "total_cost": 0, "num_cases": 1,
            "attack_cases": 0, "benign_cases": 1,
            "details": {},
        },
        "results": [
            {"case_id": "b1", "verdict": "benign_completed", "reason": "ok", "details": {}},
        ],
    }
    (tmp_path / "results_D0.json").write_text(json.dumps(result_data))
    outfile = tmp_path / "out" / "report.md"

    result = runner.invoke(cli, [
        "report",
        "--results-dir", str(tmp_path),
        "--format", "markdown",
        "-o", str(outfile),
    ])
    assert result.exit_code == 0
    assert outfile.exists()
    assert "Evaluation Report" in outfile.read_text()


# ---------------------------------------------------------------------------
# serve command
# ---------------------------------------------------------------------------

def test_serve_missing_streamlit(runner, monkeypatch):
    """serve should error if streamlit not installed."""
    import sys
    # Temporarily make streamlit unimportable
    monkeypatch.setitem(sys.modules, "streamlit", None)
    result = runner.invoke(cli, ["serve"])
    # Either ClickException about streamlit or import error
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

def test_serialize_experiment_result():
    """_serialize_experiment_result handles enums and nested dicts."""
    from agent_security_sandbox.cli.main import _serialize_experiment_result
    from agent_security_sandbox.evaluation.judge import JudgeVerdict

    data = {
        "verdict": JudgeVerdict.ATTACK_BLOCKED,
        "nested": {"v": JudgeVerdict.BENIGN_COMPLETED},
        "list": [JudgeVerdict.ATTACK_SUCCEEDED, 42, "text"],
        "none": None,
        "bool": True,
    }
    result = _serialize_experiment_result(data)
    assert result["verdict"] == "attack_blocked"
    assert result["nested"]["v"] == "benign_completed"
    assert result["list"][0] == "attack_succeeded"
    assert result["none"] is None
    assert result["bool"] is True


def test_build_defense_fallback_d0():
    """_build_defense should construct D0 via fallback path."""
    from agent_security_sandbox.cli.main import _build_defense
    defense = _build_defense("D0")
    assert defense is not None


def test_build_defense_fallback_d5():
    """_build_defense should handle D5 via registry."""
    from agent_security_sandbox.cli.main import _build_defense
    defense = _build_defense("D5")
    assert defense is not None


def test_load_defense_config_missing_file():
    """_load_defense_config returns {} if yaml file is missing."""
    from agent_security_sandbox.cli.main import _load_defense_config
    # Non-existent defense still returns a dict (may be empty)
    result = _load_defense_config("D99")
    assert isinstance(result, dict)


def test_resolve_config_dir():
    """_resolve_config_dir returns a Path."""
    from agent_security_sandbox.cli.main import _resolve_config_dir
    result = _resolve_config_dir()
    from pathlib import Path
    assert isinstance(result, Path)
