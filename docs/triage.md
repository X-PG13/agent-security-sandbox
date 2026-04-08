# Issue Triage Guide

This repository uses a small, explicit label system so issues and pull requests can be filtered quickly without turning the tracker into noise.

## Core Rules

For every new issue or PR, aim to set:

1. One work-type label:
   `bug`, `enhancement`, `documentation`, `question`, `research`, `security`, `maintenance`, `dependencies`, or `release`.
2. One area label:
   `area: benchmark`, `area: cli`, `area: core`, `area: defenses`, `area: evaluation`, `area: docs`, `area: tooling`, or `area: release`.
3. One status label:
   `status: needs-triage`, `status: needs-info`, `status: ready`, `status: in-progress`, or `status: blocked`.
4. A priority label only after triage:
   `priority: p0`, `priority: p1`, `priority: p2`, or `priority: p3`.

If an issue does not yet have enough detail, keep `status: needs-triage` or move it to `status: needs-info`.

## Intake Rules

- New bug reports start with `bug` and `status: needs-triage`.
- New feature requests start with `enhancement` and `status: needs-triage`.
- New usage questions start with `question` and `status: needs-triage`.
- Public security vulnerabilities should not be triaged in public. Redirect them to GitHub Security Advisories and close the issue.

## Priority Guidelines

- `priority: p0`: release-blocking failures, broken default install, corrupted benchmark assets, or security-critical regressions.
- `priority: p1`: important maintainer work that should land in the next short cycle.
- `priority: p2`: normal planned work.
- `priority: p3`: backlog or exploratory work.

## Contributor-Facing Labels

- Use `good first issue` only for self-contained tasks with a clear entry point and low coordination cost.
- Use `help wanted` when external contributions are welcome and the task is not blocked on maintainer-only context.

## CODEOWNERS Policy

`CODEOWNERS` is intentionally simple in this repository:

- `@X-PG13` owns the full repository by default.
- Explicit path entries highlight the highest-risk areas: `.github/`, `docs/`, `scripts/`, `src/`, `tests/`, `data/`, `results/`, and `paper/`.

This keeps review routing predictable while the project remains primarily maintainer-driven.

## Label Sync

The source of truth for repository labels is:

- `.github/labels.json`

To sync labels manually:

```bash
python scripts/sync_labels.py --repo X-PG13/agent-security-sandbox
```

The repository also runs `.github/workflows/labels.yml` when the label spec changes on `main`.
