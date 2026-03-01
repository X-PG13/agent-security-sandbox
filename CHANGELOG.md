# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
