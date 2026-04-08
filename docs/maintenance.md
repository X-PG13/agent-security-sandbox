# Maintenance Policy

This repository is maintained as a release-quality research project, not as a high-volume SaaS product. The goal is predictable maintenance and reproducible releases, not constant churn.

## Distribution Policy

- GitHub Releases are the default distribution channel.
- GitHub Pages is the canonical documentation surface.
- PyPI support is intentionally disabled by default even though the workflow wiring exists.

Enable PyPI only when at least one of these becomes true:

- multiple external users need `pip install agent-security-sandbox`
- downstream automation depends on PyPI metadata
- GitHub Release assets become an obvious packaging bottleneck

Until then, keep the release surface smaller and easier to maintain.

## Issue And PR Cadence

- Triage new issues and questions in short, regular batches.
- Keep `status: needs-triage` temporary; move items to `status: ready`, `status: needs-info`, or close them.
- Review pull requests only after required checks are green unless the PR is clearly blocked on design feedback.
- Prefer merging small, reviewable changes over carrying large long-lived branches.

## Release Cadence

- Batch normal maintenance work into periodic patch releases.
- Cut an out-of-band release only for security fixes, broken installs, corrupted benchmark assets, or release pipeline breakage.
- Update `CHANGELOG.md`, release notes, checksums, and manifests together so every release remains self-consistent.

## Quality Bar

- Keep required CI checks green on `main`.
- Treat docs examples, smoke tests, and reproducibility metadata as release-facing assets, not optional extras.
- If a change adds user-visible behavior, add or update tests before merging.

## Escalation Rules

- Public security reports should be redirected to GitHub Security Advisories.
- Benchmark-content or artifact corruption should be treated as release-blocking.
- If maintainership scope grows beyond one primary maintainer, update `CODEOWNERS`, branch protection, and this policy together.
