# FAQ

## Why are there both 565 cases and a 250-case comparison?

The open-source release includes the full 565-case corpus. The main paper comparison uses a matched 250-case subset so every defense is compared on the same case IDs.

## Which install command should I use?

- `pip install -e .` for normal runtime use
- `pip install -e ".[all]"` for UI, analysis, and real-provider integrations
- `pip install -e ".[maintainer]"` for tests, docs, and release tooling

## What is the fastest way to confirm the repo works?

Run:

```bash
asb evaluate --suite mini --provider mock -d D0 -o results/smoke
```

That path requires no API key and exercises the bundled mini benchmark.

## Why does the wheel install only bundle the mini benchmark?

The mini benchmark is enough for smoke tests and keeps wheel size under control. Full benchmark data remains in the repository checkout.

## Is PyPI publishing enabled?

Not by default. GitHub Releases are the canonical distribution channel, and PyPI publishing remains gated behind an explicit repository variable and a Trusted Publisher setup. The intent is to keep the public release surface small until there is clear external demand for a PyPI package.

## How often are releases cut?

Normal maintenance work is batched into patch releases. The project cuts an out-of-band release only for security fixes, broken installs, corrupted benchmark artifacts, or release-pipeline failures.

## Which results are checked into the repository?

The repository keeps benchmark data, summary statistics, supplemental outputs, and representative experiment results needed to reproduce the released figures and tables. See `Reproducibility` for the artifact map.

## Is there a machine-readable manifest for the current release line?

Yes. `artifacts/project-manifest.json` links the package version, benchmark file inventory, reference artifacts, and reproduction scripts. CI checks that it stays in sync.

## How strict is CI?

CI runs linting, type-checking, unit and integration tests, docs builds, package builds, `twine check`, a wheel-install smoke test, executable docs smoke checks, and enforces an 85% total coverage floor on instrumented runs.

## Where should I start if I want to add a defense?

Read `Defense API` first, then `Extending`, then mirror the structure of an existing `D*` implementation and its tests.
