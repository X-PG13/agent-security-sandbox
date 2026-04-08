# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - Unreleased

### Added

- Reproducibility documentation with an explicit artifact map covering the
  main comparison, CIV ablation, adaptive attacks, composition study, and
  submission figures.
- Maintainer-facing release checklist documenting the GitHub-only release
  flow, validation commands, and optional PyPI path.
- New docs pages for provider configuration, benchmark schema, defense API,
  and FAQ to reduce first-run friction for users and contributors.
- A reference maintainer environment snapshot in
  `requirements/reproducibility-1.0.1.txt`.
- A checksum manifest in `artifacts/reproducibility-checksums.sha256` for
  benchmark files, aggregate result artifacts, and submission figures.

### Changed

- Reorganized the docs site navigation into user-guide, reference, and
  maintainer sections.
- Tightened the README and docs homepage to focus more on installation,
  reproducibility, extension points, and contribution workflow.
- Updated `CONTRIBUTING.md` to point contributors at the release and
  reproducibility guides and to include packaging/docs verification commands.
- Raised the coverage policy to an explicit `85%` minimum and aligned local
  and CI test commands with the same coverage reporting format.
- Pointed the package metadata documentation URL to the live GitHub Pages
  site instead of the raw repository docs directory.

## [1.0.1] - 2026-04-08

### Added

- MkDocs documentation site with GitHub Pages publishing workflow.
- GitHub Release automation that uploads build artifacts and can optionally
  publish to PyPI through Trusted Publishing when explicitly enabled.

### Changed

- Split installation profiles into minimal runtime (`.`), runtime extras
  (`.[all]`), and maintainer tooling (`.[maintainer]`).
- CI now validates package builds, runs `twine check`, performs a wheel
  install smoke test, and builds the docs site in strict mode.
- CLI and Streamlit entry points now resolve bundled config files and the
  mini benchmark correctly when installed from a built wheel.
- README and supplementary docs were tightened to match the current
  565-case / 11-defense project scope.

### Fixed

- Citation metadata now uses software-style references consistently.
- Release notes and reproduction guidance no longer imply that the
  repository itself is limited to the older D0-D7 comparison scope.

## [1.0.0] - 2026-04-05

### Added

- Full `Agent Security Sandbox` benchmark release with 565 benchmark cases,
  11 defense strategies (`D0-D10`), and automated evaluation across four
  frontier LLM families.
- Expanded benchmark coverage for multilingual injections, RAG poisoning,
  tool-output manipulation, adaptive attacks, and generated benign tasks.
- Composite defense pipeline, experiment scripts, paper reproduction scripts,
  and publication-quality figure generation.
- Project-level contributor materials including `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue templates, PR template,
  `CITATION.cff`, and comprehensive `docs/` content.

### Changed

- Stabilized the public package as version `1.0.0` with Python `3.10+`
  support, editable installation, CLI entry points, and multi-version CI.
- Standardized the repository around the 565-case benchmark while retaining
  the matched 250-case subset used for fair cross-defense comparisons in the
  paper tables.
- Updated project metadata, badges, and benchmark summaries to reflect the
  full 11-defense release.

## [0.3.0] - 2026-03-09

### Added

- **OpenAI Function Calling**: Native tool calling support for all LLM providers
  (OpenAI, Anthropic, OpenAI-compatible) with text ReAct as fallback.
  New `LLMResponse` dataclass with structured `tool_calls` field.
- **D6 Output Filter defense**: Post-hoc detection of sensitive data leakage
  in agent outputs using pattern matching (emails, API keys, credentials).
- **D7 Input Classifier defense**: Pre-processing sanitization that strips
  injection-like patterns from untrusted content before agent processing.
- **15 evasion attack cases** (`attack_evasion.jsonl`): Encoding tricks, comment
  injection, Unicode normalization, base64 payloads, and other evasion techniques.
  Full benchmark now contains 250 cases (155 attack + 95 benign).
- **Full evaluation results**: 4 models (GPT-4o, Claude 4.5 Sonnet, DeepSeek V3.1,
  Gemini 2.5 Flash) × 8 defenses (D0-D7) on 250 cases. Key findings: D5 Sandwich
  reduces ASR by 97.6%, D1 Spotlighting by 95.3%.
- `CITATION.cff` for academic citation.
- `docs/limitations_and_ethics.md` with responsible disclosure guidance.
- `docs/related_work.md` with comprehensive literature review.
- `scripts/reproduce.sh` for one-command experiment reproduction.
- 95 new tests covering calendar tools, API client tools, and LLM client edge cases.
  Overall test coverage: 80% → 85% (376 tests).

### Fixed

- Token counting through OpenAI-compatible proxies: `total_tokens` can be `None`
  from Bedrock/Claude, now coalesced with `or 0`.
- Empty content handling: Bedrock/Claude rejects empty text blocks; assistant
  messages now use `content: None` instead of `content: ""` when empty.
- `--function-calling/--no-function-calling` CLI flags for mode selection.

### Changed

- README.md updated with 8 defense strategies, 250 benchmark cases, results
  summary table, and citation block.
- `defenses.yaml` updated with D6 and D7 configurations.
- `docs/defenses.md` updated with D6 and D7 documentation.

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
