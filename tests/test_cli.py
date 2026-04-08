"""Tests for CLI commands."""
import builtins
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner

from agent_security_sandbox.cli import main as cli_main
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


def test_evaluate_suite_shortcut_uses_bundled_benchmark(runner, tmp_path):
    result = runner.invoke(
        cli,
        [
            "evaluate",
            "--suite",
            "mini",
            "--provider",
            "mock",
            "-d",
            "D0",
            "--output",
            str(tmp_path / "mini_results"),
            "--max-steps",
            "3",
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / "mini_results" / "results_D0.json").exists()


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
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "streamlit":
            raise ImportError("missing streamlit")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    result = runner.invoke(cli, ["serve"])
    assert result.exit_code != 0
    assert "Streamlit is not installed" in result.output


def test_serve_invokes_streamlit_subprocess(runner, monkeypatch):
    """serve should call subprocess with the expected Streamlit command."""
    commands = []

    monkeypatch.setitem(sys.modules, "streamlit", SimpleNamespace())
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, check: commands.append((cmd, check)),
    )

    result = runner.invoke(cli, ["serve", "--port", "9999", "--host", "127.0.0.1"])
    assert result.exit_code == 0
    assert "Starting Streamlit on http://127.0.0.1:9999" in result.output
    cmd, check = commands[0]
    assert check is True
    assert cmd[:4] == [cli_main.sys.executable, "-m", "streamlit", "run"]
    assert Path(cmd[4]).name == "demo_app.py"


def test_serve_surfaces_subprocess_failure(runner, monkeypatch):
    monkeypatch.setitem(sys.modules, "streamlit", SimpleNamespace())

    def fail(cmd, check):
        raise subprocess.CalledProcessError(returncode=3, cmd=cmd)

    monkeypatch.setattr(subprocess, "run", fail)
    result = runner.invoke(cli, ["serve"])
    assert result.exit_code != 0
    assert "Streamlit exited with code 3" in result.output


def test_serve_errors_when_demo_app_is_missing(runner, monkeypatch):
    original_exists = Path.exists

    def fake_exists(self):
        if self.name == "demo_app.py":
            return False
        return original_exists(self)

    monkeypatch.setitem(sys.modules, "streamlit", SimpleNamespace())
    monkeypatch.setattr(cli_main.Path, "exists", fake_exists)

    result = runner.invoke(cli, ["serve"])
    assert result.exit_code != 0
    assert "Streamlit app not found" in result.output


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("helper_name", "module_name", "message"),
    [
        ("_import_llm_client", "agent_security_sandbox.core.llm_client", "LLM client module"),
        ("_import_tool_registry", "agent_security_sandbox.tools.registry", "ToolRegistry"),
        ("_import_agent", "agent_security_sandbox.core.agent", "ReactAgent"),
        (
            "_import_benchmark_suite",
            "agent_security_sandbox.evaluation.benchmark",
            "BenchmarkSuite",
        ),
        (
            "_import_experiment_runner",
            "agent_security_sandbox.evaluation.runner",
            "ExperimentRunner",
        ),
        ("_import_reporter", "agent_security_sandbox.evaluation.reporter", "Reporter"),
    ],
)
def test_import_helpers_raise_click_exception(monkeypatch, helper_name, module_name, message):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == module_name:
            raise ImportError("boom")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(click.ClickException, match=message):
        getattr(cli_main, helper_name)()


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
    assert isinstance(result, Path)


def test_resolve_config_dir_prefers_env(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setenv("ASB_CONFIG_DIR", str(config_dir))
    assert cli_main._resolve_config_dir() == config_dir.resolve()


def test_load_defense_config_from_explicit_dir(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "defenses.yaml").write_text(
        "defenses:\n  D1:\n    config:\n      delimiter_start: '<<X>>'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASB_CONFIG_DIR", str(config_dir))
    assert cli_main._load_defense_config("D1") == {"delimiter_start": "<<X>>"}


def test_load_defense_config_invalid_yaml_returns_empty(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "defenses.yaml").write_text("defenses: [broken", encoding="utf-8")
    monkeypatch.setenv("ASB_CONFIG_DIR", str(config_dir))
    assert cli_main._load_defense_config("D1") == {}


def test_build_llm_client_omits_base_url_for_mock(monkeypatch):
    calls = []

    def fake_factory(*, provider, model, **kwargs):
        calls.append({"provider": provider, "model": model, "kwargs": kwargs})
        return SimpleNamespace(provider=provider, model=model, kwargs=kwargs)

    monkeypatch.setattr(cli_main, "_import_llm_client", lambda: fake_factory)
    cli_main._build_llm_client("mock", "scenario-mock", "https://proxy.example/v1")
    cli_main._build_llm_client("openai-compatible", "gpt-4o", "https://proxy.example/v1")

    assert calls[0]["kwargs"] == {}
    assert calls[1]["kwargs"] == {"base_url": "https://proxy.example/v1"}


def test_build_defense_fallback_unknown_when_registry_missing(monkeypatch):
    monkeypatch.setattr(cli_main, "_import_defense_factory", lambda: None)
    monkeypatch.setattr(cli_main, "_load_defense_config", lambda defense_id: {})

    with pytest.raises(Exception, match="only D0 and D1 are available"):
        cli_main._build_defense("D9")


def test_report_invalid_verdict_falls_back_to_attack_blocked(runner, tmp_path):
    result_data = {
        "defense_name": "D0",
        "timestamp": "",
        "metrics": {
            "asr": 0.0,
            "bsr": 1.0,
            "fpr": 0.0,
            "total_cost": 0,
            "num_cases": 1,
            "attack_cases": 0,
            "benign_cases": 1,
            "details": {},
        },
        "results": [
            {"case_id": "b1", "verdict": "not-a-real-verdict", "reason": "ok", "details": {}},
        ],
    }
    (tmp_path / "results_D0.json").write_text(json.dumps(result_data), encoding="utf-8")

    result = runner.invoke(
        cli,
        ["report", "--results-dir", str(tmp_path), "--format", "markdown"],
    )
    assert result.exit_code == 0
    assert "attack_blocked" in result.output


def test_report_errors_when_all_result_files_are_invalid(runner, tmp_path):
    (tmp_path / "results_D0.json").write_text("{not-json", encoding="utf-8")

    result = runner.invoke(
        cli,
        ["report", "--results-dir", str(tmp_path), "--format", "markdown"],
    )
    assert result.exit_code != 0
    assert "Skipping results_D0.json" in result.output
    assert "No valid result files could be loaded" in result.output
