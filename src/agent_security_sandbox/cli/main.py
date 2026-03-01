"""
ASB -- Agent Security Sandbox CLI

Entry point for the ``asb`` command defined in pyproject.toml::

    [project.scripts]
    asb = "agent_security_sandbox.cli.main:cli"

Usage examples::

    asb run "Read email_001 and summarize it" --defense D0 --provider mock
    asb evaluate -b data/benchmarks -d D0 -d D1 --provider mock -o results/
    asb report --results-dir results/ --format markdown -o report.md
    asb serve --port 8501
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Optional

import click

# ---------------------------------------------------------------------------
# Lazy / guarded imports -- keep the CLI usable even when optional
# dependencies have not been installed.
# ---------------------------------------------------------------------------

def _import_llm_client():
    """Import create_llm_client; raise clear error if missing."""
    try:
        from agent_security_sandbox.core.llm_client import create_llm_client
        return create_llm_client
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import LLM client module: {exc}. "
            "Make sure the package is installed (pip install -e .)."
        )


def _import_tool_registry():
    """Import ToolRegistry; raise clear error if missing."""
    try:
        from agent_security_sandbox.tools.registry import ToolRegistry
        return ToolRegistry
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import ToolRegistry: {exc}. "
            "Make sure the package is installed (pip install -e .)."
        )


def _import_agent():
    """Import ReactAgent; raise clear error if missing."""
    try:
        from agent_security_sandbox.core.agent import ReactAgent
        return ReactAgent
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import ReactAgent: {exc}. "
            "Make sure the package is installed (pip install -e .)."
        )


def _import_defense_factory():
    """Import create_defense from the defenses registry.

    Returns the factory function, or ``None`` if the module is not yet
    available (so callers can fall back gracefully).
    """
    try:
        from agent_security_sandbox.defenses.registry import create_defense
        return create_defense
    except ImportError:
        return None


def _import_benchmark_suite():
    """Import BenchmarkSuite; raise clear error if missing."""
    try:
        from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
        return BenchmarkSuite
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import BenchmarkSuite: {exc}. "
            "Make sure the evaluation module is available."
        )


def _import_experiment_runner():
    """Import ExperimentRunner; raise clear error if missing."""
    try:
        from agent_security_sandbox.evaluation.runner import ExperimentRunner
        return ExperimentRunner
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import ExperimentRunner: {exc}. "
            "Make sure the evaluation module is available."
        )


def _import_reporter():
    """Import Reporter; raise clear error if missing."""
    try:
        from agent_security_sandbox.evaluation.reporter import Reporter
        return Reporter
    except ImportError as exc:
        raise click.ClickException(
            f"Could not import Reporter: {exc}. "
            "Make sure the evaluation module is available."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_config_dir() -> Path:
    """Return the path to the project-level ``config/`` directory.

    Strategy:
      1. Walk up from this file: ``cli/main.py`` -> ``cli/`` ->
         ``agent_security_sandbox/`` -> ``src/`` -> repo-root -> ``config/``.
      2. If that does not exist, fall back to the current working directory.
    """
    candidate = Path(__file__).resolve().parents[2] / "config"
    if candidate.is_dir():
        return candidate
    # Fallback: repo root relative to cwd
    cwd_candidate = Path.cwd() / "config"
    if cwd_candidate.is_dir():
        return cwd_candidate
    return candidate  # return the canonical path even if it doesn't exist yet


def _build_llm_client(provider: str, model: Optional[str], base_url: Optional[str]):
    """Construct an LLM client from CLI options."""
    create_llm_client = _import_llm_client()
    kwargs: Dict = {}
    if base_url:
        kwargs["base_url"] = base_url
    return create_llm_client(provider=provider, model=model, **kwargs)


def _load_defense_config(defense_id: str) -> dict:
    """Load config for a specific defense from ``config/defenses.yaml``.

    Returns an empty dict if the file is missing or the defense ID is not
    found in the YAML.
    """
    config_dir = _resolve_config_dir()
    yaml_path = config_dir / "defenses.yaml"
    if not yaml_path.exists():
        return {}
    try:
        import yaml  # noqa: F811

        with open(yaml_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        defenses_section = raw.get("defenses", {})
        defense_def = defenses_section.get(defense_id.upper(), {})
        return defense_def.get("config", {}) or {}
    except Exception:
        return {}


def _build_defense(defense_id: str, llm_client=None):
    """Construct a defense strategy from its ID (e.g. ``"D0"``).

    Loads configuration from ``config/defenses.yaml`` and passes it to
    the defense factory.  Falls back to a minimal mapping when the
    registry module is unavailable.
    """
    config = _load_defense_config(defense_id)

    create_defense = _import_defense_factory()
    if create_defense is not None:
        return create_defense(defense_id, config=config, llm_client=llm_client)

    # ---- Fallback: manual mapping for built-in defenses ----
    defense_id_upper = defense_id.upper()

    if defense_id_upper == "D0":
        from agent_security_sandbox.defenses.d0_baseline import BaselineDefense

        return BaselineDefense(config=config)

    if defense_id_upper == "D1":
        from agent_security_sandbox.defenses.d1_spotlighting import (
            SpotlightingDefense,
        )

        return SpotlightingDefense(config=config)

    raise click.ClickException(
        f"Unknown defense '{defense_id}'. The defenses.registry module is not "
        "installed, so only D0 and D1 are available via the fallback path."
    )


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="agent-security-sandbox")
def cli():
    """ASB - Agent Security Sandbox CLI

    A research framework for evaluating AI agent security against
    Indirect Prompt Injection (IPI) attacks.
    """


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("goal")
@click.option(
    "--defense", "-d", default="D0",
    help="Defense strategy ID (D0-D4).",
)
@click.option(
    "--provider", default="mock",
    help="LLM provider: openai, anthropic, openai-compatible, or mock.",
)
@click.option(
    "--model", default=None,
    help="Model name (provider-specific). Uses provider default if omitted.",
)
@click.option(
    "--base-url", default=None,
    help="API base URL for openai-compatible provider.",
)
@click.option(
    "--max-steps", default=10, show_default=True,
    help="Maximum number of agent reasoning steps.",
)
@click.option(
    "--verbose/--quiet", default=True, show_default=True,
    help="Enable or suppress step-by-step output.",
)
def run(goal, defense, provider, model, base_url, max_steps, verbose):
    """Run the agent on a single task.

    GOAL is the natural-language instruction for the agent.

    Examples:

      asb run "Read email_001 and summarize it"

      asb run "Search for 'python security' and save results" -d D1 --provider openai --model gpt-4o
    """
    # -- LLM client ---------------------------------------------------------
    try:
        llm_client = _build_llm_client(provider, model, base_url)
    except Exception as exc:
        raise click.ClickException(f"Failed to create LLM client: {exc}")

    # -- Tool registry ------------------------------------------------------
    tool_registry_cls = _import_tool_registry()
    config_dir = _resolve_config_dir()
    tools_config = config_dir / "tools.yaml"
    tool_registry = tool_registry_cls(
        config_path=str(tools_config) if tools_config.exists() else None
    )

    # -- Defense strategy ---------------------------------------------------
    try:
        defense_strategy = _build_defense(defense, llm_client=llm_client)
    except Exception as exc:
        raise click.ClickException(f"Failed to create defense '{defense}': {exc}")

    # -- Agent --------------------------------------------------------------
    agent_cls = _import_agent()
    agent = agent_cls(
        llm_client=llm_client,
        tool_registry=tool_registry,
        max_steps=max_steps,
        verbose=verbose,
    )

    if verbose:
        click.echo(f"Provider : {provider}")
        click.echo(f"Model    : {model or '(default)'}")
        click.echo(f"Defense  : {defense}")
        click.echo(f"Max steps: {max_steps}")
        click.echo()

    # -- Execute ------------------------------------------------------------
    trajectory = agent.run(goal=goal, defense_strategy=defense_strategy)

    # -- Summary ------------------------------------------------------------
    click.echo()
    click.echo("=" * 60)
    click.echo("Trajectory Summary")
    click.echo("=" * 60)
    click.echo(f"Goal         : {trajectory.goal}")
    click.echo(f"Total steps  : {trajectory.total_steps}")
    click.echo(f"Total tokens : {trajectory.total_tokens}")
    click.echo(f"Final answer : {trajectory.final_answer}")
    click.echo(f"Start time   : {trajectory.start_time}")
    click.echo(f"End time     : {trajectory.end_time}")

    for step in trajectory.steps:
        click.echo(f"\n  Step {step.step_number}:")
        click.echo(f"    Thought : {step.thought[:120]}{'...' if len(step.thought) > 120 else ''}")
        click.echo(f"    Action  : {step.action}")
        click.echo(f"    Tokens  : {step.tokens_used}")
        if step.defense_decision:
            allowed = step.defense_decision.get("allowed", "N/A")
            reason = step.defense_decision.get("reason", "")
            click.echo(f"    Defense : {'ALLOW' if allowed else 'BLOCK'} -- {reason}")


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--benchmark", "-b", required=True,
    help="Path to benchmark directory containing .jsonl files.",
)
@click.option(
    "--defense", "-d", multiple=True, default=["D0"],
    help="Defense strategies to test (repeat for multiple, e.g. -d D0 -d D1).",
)
@click.option(
    "--provider", default="mock",
    help="LLM provider: openai, anthropic, openai-compatible, or mock.",
)
@click.option(
    "--model", default=None,
    help="Model name (provider-specific).",
)
@click.option(
    "--base-url", default=None,
    help="API base URL for openai-compatible provider.",
)
@click.option(
    "--output", "-o", default="results/", show_default=True,
    help="Output directory for result files.",
)
@click.option(
    "--max-steps", default=10, show_default=True,
    help="Maximum number of agent reasoning steps per case.",
)
@click.option(
    "--verbose/--quiet", default=False, show_default=True,
    help="Enable step-by-step output for every case.",
)
def evaluate(benchmark, defense, provider, model, base_url, output, max_steps, verbose):
    """Run benchmark evaluation with specified defenses.

    Loads all .jsonl benchmark cases from the BENCHMARK directory and
    executes each one under every requested defense strategy.  Results
    are written to OUTPUT as JSON files.

    Examples:

      asb evaluate -b data/benchmarks -d D0 -d D1 --provider mock

      asb evaluate -b data/benchmarks -d D0 -d D1 -d D2 \
        --provider openai --model gpt-4o -o results/exp01
    """
    # -- Validate benchmark path --------------------------------------------
    benchmark_path = Path(benchmark)
    if not benchmark_path.is_dir():
        raise click.ClickException(f"Benchmark directory not found: {benchmark}")

    # -- Load benchmark suite -----------------------------------------------
    benchmark_suite_cls = _import_benchmark_suite()
    try:
        suite = benchmark_suite_cls.load_from_directory(str(benchmark_path))
    except Exception as exc:
        raise click.ClickException(f"Failed to load benchmark suite: {exc}")

    click.echo(f"Loaded benchmark suite: {suite}")

    # -- Prepare output directory -------------------------------------------
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # -- Build LLM client ---------------------------------------------------
    try:
        llm_client = _build_llm_client(provider, model, base_url)
    except Exception as exc:
        raise click.ClickException(f"Failed to create LLM client: {exc}")

    # -- Tool registry factory ----------------------------------------------
    tool_registry_cls = _import_tool_registry()
    config_dir = _resolve_config_dir()
    tools_config = config_dir / "tools.yaml"
    tools_config_path = str(tools_config) if tools_config.exists() else None

    def _make_registry():
        return tool_registry_cls(config_path=tools_config_path)

    # -- Run experiments for each defense -----------------------------------
    experiment_runner_cls = _import_experiment_runner()
    all_results = []

    for defense_id in defense:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Defense: {defense_id}")
        click.echo(f"{'=' * 60}")

        try:
            defense_strategy = _build_defense(defense_id, llm_client=llm_client)
        except Exception as exc:
            click.echo(
                f"  [ERROR] Failed to create defense '{defense_id}': {exc}",
                err=True,
            )
            continue

        try:
            runner = experiment_runner_cls(
                llm_client=llm_client,
                tool_registry_factory=_make_registry,
                defense_strategy=defense_strategy,
                max_steps=max_steps,
                verbose=verbose,
            )
            results = runner.run_suite(suite)
            all_results.append({
                "defense": defense_id,
                "results": results,
            })

            # Persist per-defense results
            result_file = output_dir / f"results_{defense_id}.json"
            with open(result_file, "w", encoding="utf-8") as fh:
                json.dump(
                    {"defense": defense_id, "results": results},
                    fh,
                    indent=2,
                    default=str,
                )
            click.echo(f"  Results saved to {result_file}")

        except Exception as exc:
            click.echo(
                f"  [ERROR] Experiment failed for defense '{defense_id}': {exc}",
                err=True,
            )
            continue

    # -- Generate report ----------------------------------------------------
    if all_results:
        try:
            reporter_cls = _import_reporter()
            reporter = reporter_cls()
            experiment_results = [r["results"] for r in all_results]
            md = reporter.generate_markdown(experiment_results)
            report_file = output_dir / "report.md"
            reporter.save_report(md, str(report_file))
            click.echo(f"\nReport saved to {report_file}")
        except Exception as exc:
            click.echo(f"\n[WARNING] Could not generate report: {exc}", err=True)

    click.echo("\nEvaluation complete.")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--results-dir", required=True,
    help="Directory containing result JSON files from evaluation runs.",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["markdown", "json", "csv"]),
    default="markdown", show_default=True,
    help="Output format for the report.",
)
@click.option(
    "--output", "-o", default=None,
    help="Output file path. Prints to stdout if omitted.",
)
def report(results_dir, fmt, output):
    """Generate a report from evaluation results.

    Reads all JSON result files from RESULTS_DIR and produces a combined
    report in the requested format.

    Examples:

      asb report --results-dir results/ --format markdown

      asb report --results-dir results/ --format csv -o results/report.csv
    """
    results_path = Path(results_dir)
    if not results_path.is_dir():
        raise click.ClickException(f"Results directory not found: {results_dir}")

    # -- Collect result files -----------------------------------------------
    result_files = sorted(results_path.glob("results_*.json"))
    if not result_files:
        raise click.ClickException(
            f"No result files (results_*.json) found in {results_dir}"
        )

    all_results = []
    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            all_results.append(data)
            click.echo(f"  Loaded {rf.name}", err=True)
        except Exception as exc:
            click.echo(f"  [WARNING] Skipping {rf.name}: {exc}", err=True)

    if not all_results:
        raise click.ClickException("No valid result files could be loaded.")

    # -- Generate report ----------------------------------------------------
    reporter_cls = _import_reporter()
    try:
        reporter = reporter_cls()
        fmt_method = {
            "markdown": reporter.generate_markdown,
            "json": reporter.generate_json,
            "csv": reporter.generate_csv,
        }
        report_text = fmt_method[fmt](all_results)
    except Exception as exc:
        raise click.ClickException(f"Failed to generate report: {exc}")

    # -- Output -------------------------------------------------------------
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        click.echo(f"Report written to {output_path}")
    else:
        click.echo(report_text)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--port", default=8501, show_default=True,
    help="Port for the Streamlit server.",
)
@click.option(
    "--host", default="localhost", show_default=True,
    help="Host to bind the Streamlit server to.",
)
def serve(port, host):
    """Launch the Streamlit demo UI.

    Requires the ``streamlit`` package (install with ``pip install
    agent-security-sandbox[ui]``).

    Examples:

      asb serve

      asb serve --port 8080 --host 0.0.0.0
    """
    try:
        import streamlit  # noqa: F401 -- just checking availability
    except ImportError:
        raise click.ClickException(
            "Streamlit is not installed. "
            "Install it with: pip install agent-security-sandbox[ui]"
        )

    import subprocess

    # Resolve the Streamlit app entry point.
    # Convention: ``agent_security_sandbox/ui/app.py``
    ui_app = Path(__file__).resolve().parents[1] / "ui" / "demo_app.py"
    if not ui_app.exists():
        raise click.ClickException(
            f"Streamlit app not found at {ui_app}. "
            "Make sure the UI module is installed."
        )

    click.echo(f"Starting Streamlit on http://{host}:{port} ...")
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(ui_app),
        "--server.port", str(port),
        "--server.address", host,
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(f"Streamlit exited with code {exc.returncode}")
    except KeyboardInterrupt:
        click.echo("\nStreamlit server stopped.")


# ---------------------------------------------------------------------------
# Allow ``python -m agent_security_sandbox.cli.main``
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
