# Reproducibility

This repository keeps the benchmark, checked-in reference results, figure-generation scripts, and release assets together so users can verify both the code and the published numbers.

## Reproduction Levels

| Goal | Command | Cost |
|---|---|---|
| Smoke test the install | `asb evaluate --suite mini --provider mock -d D0 -o results/smoke` | Free |
| Validate the checked-in paper comparison pipeline | `./scripts/reproduce_main_table.sh --provider mock` | Free |
| Rebuild submission figures from checked-in metrics | `./scripts/reproduce_all_figures.sh` | Free |
| Re-run the full reference sweep on a real provider | `./scripts/reproduce.sh --provider openai-compatible --base-url ... --model gpt-4o` | Paid API usage |

## Reference Environment

The validated maintainer snapshot is pinned in:

- `requirements/reproducibility-1.0.2.txt`

Use it when you want a close match to the environment used to validate the `v1.0.2` release.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/reproducibility-1.0.2.txt
pip install -e .
```

The repository is also exercised in CI on Python `3.10`, `3.11`, and `3.12`.

## Project Manifest

The machine-readable release manifest is stored at:

- `artifacts/project-manifest.json`

It links:

- package version and Python requirement
- benchmark file counts and per-file checksums
- reference result artifacts and submission figures
- reproduction scripts and their expected outputs
- the documented smoke-check commands used in CI

Verify that the checked-in manifest matches the current repository state with:

```bash
python scripts/generate_project_manifest.py --check
```

## Checksum Manifest

The repository ships a machine-readable checksum file:

- `artifacts/reproducibility-checksums.sha256`

It covers:

- all 20 JSONL files in `data/full_benchmark/`
- the main experiment configuration and aggregated statistics
- supplemental 565-case summary outputs
- adaptive-attack and attack-type summary artifacts
- the two submission figures generated under `paper/figures/`

Verify the manifest with:

```bash
shasum -a 256 -c artifacts/reproducibility-checksums.sha256
```

## Artifact Map

| Paper artifact | Script entry point | Primary code path | Output location |
|---|---|---|---|
| Main matched-subset comparison | `scripts/reproduce_main_table.sh` | `experiments/run_full_evaluation.py`, `experiments/statistical_analysis.py`, `experiments/error_analysis.py` | `results/full_eval/`, `results/stats/` |
| CIV ablation | `scripts/reproduce_ablation.sh` | `experiments/run_civ_ablation.py` | `results/civ_ablation/` |
| Adaptive attacks | `scripts/reproduce_adaptive.sh` | `experiments/run_adaptive_attack.py` | `results/adaptive_attack/` |
| Defense composition | `scripts/reproduce_composition.sh` | `experiments/run_targeted_composition.py` | `results/composition/` |
| Submission figures | `scripts/reproduce_all_figures.sh` | `experiments/generate_figures.py` | `paper/figures/pareto_frontier.pdf`, `paper/figures/model_comparison.pdf` |

## Recommended Verification Flow

1. Run the test suite and coverage check.
2. Verify the machine-readable project manifest.
3. Verify the checksum manifest.
4. Run the documented smoke checks.
5. Run the mock reproduction scripts.
6. Compare regenerated outputs with the checked-in summaries.
7. Only then spend API budget on a full external rerun.

```bash
pytest tests/ --cov=agent_security_sandbox --cov-report=term-missing:skip-covered
python scripts/generate_project_manifest.py --check
shasum -a 256 -c artifacts/reproducibility-checksums.sha256
python scripts/docs_smoke_check.py
./scripts/reproduce_main_table.sh --provider mock
./scripts/reproduce_all_figures.sh
```

## Notes On Determinism

- Mock-provider runs should be deterministic and are the right baseline for CI and installation validation.
- Real-provider runs can drift due to model updates, rate limits, retry behavior, and third-party endpoint changes.
- The checked-in summaries and checksums are the canonical reference for this release branch.
- Tagged GitHub releases attach a generated SBOM and project manifest, and the
  release workflow emits provenance and SBOM attestations for the published
  assets.
