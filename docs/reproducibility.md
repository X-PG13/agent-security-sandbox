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

- `requirements/reproducibility-1.0.1.txt`

Use it when you want a close match to the environment used to validate the `v1.0.1` release.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/reproducibility-1.0.1.txt
pip install -e .
```

The repository is also exercised in CI on Python `3.10`, `3.11`, and `3.12`.

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
2. Verify the checksum manifest.
3. Run the mock reproduction scripts.
4. Compare regenerated outputs with the checked-in summaries.
5. Only then spend API budget on a full external rerun.

```bash
pytest tests/ --cov=agent_security_sandbox --cov-report=term-missing:skip-covered
shasum -a 256 -c artifacts/reproducibility-checksums.sha256
./scripts/reproduce_main_table.sh --provider mock
./scripts/reproduce_all_figures.sh
```

## Notes On Determinism

- Mock-provider runs should be deterministic and are the right baseline for CI and installation validation.
- Real-provider runs can drift due to model updates, rate limits, retry behavior, and third-party endpoint changes.
- The checked-in summaries and checksums are the canonical reference for this release branch.
