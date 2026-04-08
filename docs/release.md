# Release Checklist

This project currently publishes GitHub Releases. PyPI wiring exists but remains intentionally disabled by default.

## Before You Bump Anything

- Ensure `git status` is clean.
- Confirm `CHANGELOG.md` has an entry for the target version.
- Align version strings in:
  - `pyproject.toml`
  - `src/agent_security_sandbox/__init__.py`
  - `PROJECT_STATUS.md`
  - `README.md`
  - `CITATION.cff`
- If benchmark counts or result summaries changed, update `docs/reproducibility.md` and regenerate `artifacts/reproducibility-checksums.sha256`.

## Validation Commands

Run all of these locally before tagging:

```bash
pytest tests/ --cov=agent_security_sandbox --cov-report=term-missing:skip-covered
ruff check src/ tests/
mypy src/agent_security_sandbox/
mkdocs build --strict
python -m build
python -m twine check dist/*
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
3. upload the distribution artifacts
4. create a GitHub Release

## Post-Release Checks

- Confirm the release page has both `tar.gz` and `.whl` assets.
- Confirm the docs site still renders successfully.
- Confirm the tag matches the intended commit.
- If release notes are too terse, edit the GitHub Release body after the workflow completes.

## Optional PyPI Path

PyPI is not part of the default release flow. If you later enable it:

- configure a Trusted Publisher on PyPI
- create or reuse the `pypi` GitHub environment
- set the `PYPI_PUBLISH` repository variable to `true`
- approve the environment deployment when the workflow pauses
