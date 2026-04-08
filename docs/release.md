# Release Checklist

This project currently publishes GitHub Releases. PyPI wiring exists but remains intentionally disabled by default.

## Distribution Policy

- GitHub Releases are the canonical distribution channel for this project.
- PyPI remains opt-in infrastructure, not part of the default maintainer flow.
- Do not enable PyPI just because the workflow supports it. Turn it on only if there is clear external demand for `pip install agent-security-sandbox` or a packaging requirement that GitHub Releases no longer satisfy.

## Release Cadence

- Patch releases (`vX.Y.Z`) are batched when fixes, docs hardening, reproducibility updates, or release-pipeline improvements have accumulated into a meaningful maintenance drop.
- Release immediately for security-critical fixes, broken default installs, or benchmark corruption.
- Avoid cutting tags for tiny README-only changes unless they materially affect installation, release assets, or published documentation.

## Before You Bump Anything

- Ensure `git status` is clean.
- Confirm `CHANGELOG.md` has an entry for the target version.
- Confirm dependency automation remains enabled:
  - `.github/dependabot.yml`
  - `.github/workflows/pip-audit.yml`
- Confirm branch protection on `main` still requires the expected checks.
- Align version strings in:
  - `pyproject.toml`
  - `src/agent_security_sandbox/__init__.py`
  - `PROJECT_STATUS.md`
  - `README.md`
  - `CITATION.cff`
- If benchmark counts or result summaries changed, update `docs/reproducibility.md`, regenerate `artifacts/reproducibility-checksums.sha256`, and refresh `artifacts/project-manifest.json`.

## Validation Commands

Run all of these locally before tagging:

```bash
pytest tests/ --cov=agent_security_sandbox --cov-report=term-missing:skip-covered
ruff check src/ tests/
mypy src/agent_security_sandbox/
python -m pip_audit
mkdocs build --strict
python -m build
python -m twine check dist/*
python scripts/generate_project_manifest.py --check
python scripts/docs_smoke_check.py
shasum -a 256 -c artifacts/reproducibility-checksums.sha256
```

## Tagging A GitHub-Only Release

```bash
git tag v1.0.2
git push origin v1.0.2
```

The `release.yml` workflow will:

1. build `sdist` and `wheel`
2. run `twine check`
3. generate a release SBOM
4. generate a release manifest and checksums for the release assets
5. create provenance and SBOM attestations
6. upload the distribution assets, SBOM, and manifest to the GitHub Release

## Post-Release Checks

- Confirm the release page has both `tar.gz` and `.whl` assets.
- Confirm the release page also has the generated SBOM, manifest, and asset checksum files.
- Confirm the GitHub attestation records exist for both provenance and SBOM.
- Confirm the `pip-audit` workflow is green on the tagged commit or preceding release commit.
- Confirm the docs site still renders successfully.
- Confirm the tag matches the intended commit.
- If release notes are too terse, edit the GitHub Release body after the workflow completes.

## Optional PyPI Path

PyPI is not part of the default release flow. If you later enable it:

- configure a Trusted Publisher on PyPI
- create or reuse the `pypi` GitHub environment
- set the `PYPI_PUBLISH` repository variable to `true`
- approve the environment deployment when the workflow pauses
