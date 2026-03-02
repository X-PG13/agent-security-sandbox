# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-02

### Added

- **D5 Sandwich Defense**: Goal-reminder wrapping of untrusted content with configurable
  warning text, delimiters, and reminder prefix.
- Full benchmark suite (`data/full_benchmark/`): 235 cases across 11 JSONL files covering
  benign (basic, multi-tool, content-heavy, edge cases) and attack (DoS, escalation,
  exfiltration, hijacking, multi-step, social engineering, adaptive) scenarios.
- **20 adaptive attack cases** (`attack_adaptive.jsonl`): Unicode confusables, payload
  splitting, multilingual injection, role-play, jailbreak, format mimicry, and more.
- **15 benign edge cases** (`benign_edge_cases.jsonl`): Legitimate content containing
  security discussions, phishing warnings, API documentation, and similar patterns that
  might trigger false positives.
- **Experiment infrastructure** for paper-quality research:
  - `run_full_evaluation.py`: Multi-model, multi-defense, multi-run evaluation with
    checkpoint/resume support.
  - `run_composition_study.py`: Defense combination ablation study with super-additivity
    analysis.
  - `run_attack_levels.py`: Post-hoc analysis of attack difficulty and technique
    effectiveness.
  - `statistical_analysis.py`: Wilson score CIs, bootstrap CIs, McNemar's test,
    Kendall's tau, and LaTeX table generation.
  - `generate_figures.py`: 7 publication-quality figures (ASR-BSR tradeoff, ASR-cost
    tradeoff, composition heatmap, cross-model comparison, attack technique analysis,
    attack category stacked bars, Pareto frontier).
  - `error_analysis.py`: False negative/positive pattern analysis and case study
    extraction.
- Enhanced token tracking: `prompt_tokens` and `completion_tokens` split in LLM client
  and runner.
- Real GPT-4o experiment results on mini_benchmark (D0-D4, 40 cases each).

### Fixed

- D5 (SandwichDefense) now properly exported from `defenses/__init__.py`.
- `_serialize_result` in `run_baseline.py` now correctly handles `JudgeVerdict` enum
  serialization to JSON.
- `asb evaluate` now properly serializes `ExperimentResult` to JSON (was using `str()`).
- `asb report` now correctly reconstructs `ExperimentResult` from loaded JSON files.
- Placeholder URLs in README.md and pyproject.toml replaced with actual GitHub paths.
- `.gitignore` updated to whitelist `data/full_benchmark/*.jsonl` files.

### Changed

- README.md updated to document all 6 defense strategies (D0-D5) and 235 benchmark cases.
- PROJECT_STATUS.md rewritten to reflect current state with real experiment results.
- pyproject.toml author updated; version bumped to 0.2.0.

## [0.1.0] - 2025-01-15

### Added

- ReAct-based agent framework with configurable LLM backends (OpenAI, Anthropic, mock).
- Mock tool ecosystem: email (read/send/list), file (read/write/create), web search.
- Five defense strategies:
  - **D0** Baseline (no defense)
  - **D1** Spotlighting / source marking
  - **D2** Policy gate with whitelists and permission control
  - **D3** Task alignment verification (rule-based + optional LLM judge)
  - **D4** Re-execution detection with heuristic fallback
- Composite defense pipeline for combining multiple strategies.
- Evaluation framework: benchmark loading (JSONL), automatic judge, ASR/BSR/FPR/cost metrics.
- CLI (`asb`) with `run`, `evaluate`, `report`, and `serve` commands.
- Experiment runners for baseline, ablation, and model comparison studies.
- Mini benchmark dataset (benign + attack cases).
- Streamlit-based demo UI (optional dependency).
- Full documentation: architecture, configuration, defenses, evaluation guides.
- Docker support with Dockerfile and docker-compose.
- Test suite with 160+ tests, ruff and mypy zero-error compliance.
