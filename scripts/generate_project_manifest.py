#!/usr/bin/env python3
"""Generate a machine-readable project manifest for releases and reproduction."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "artifacts" / "project-manifest.json"
CHECKSUM_MANIFEST = PROJECT_ROOT / "artifacts" / "reproducibility-checksums.sha256"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def _count_jsonl(path: Path) -> dict[str, int]:
    total = 0
    attacks = 0
    benign = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            data = json.loads(line)
            if data.get("type") == "attack":
                attacks += 1
            elif data.get("type") == "benign":
                benign += 1
    return {"total_cases": total, "attack_cases": attacks, "benign_cases": benign}


def _read_version() -> str:
    init_file = PROJECT_ROOT / "src" / "agent_security_sandbox" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not match:
        raise RuntimeError("Could not determine package version from __init__.py")
    return match.group(1)


def _load_known_checksums() -> dict[str, str]:
    checksums: dict[str, str] = {}
    with CHECKSUM_MANIFEST.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, relative_path = line.split("  ", maxsplit=1)
            checksums[relative_path] = digest
    return checksums


def _artifact_entry(path: Path, known_checksums: dict[str, str]) -> dict[str, Any]:
    relative_path = _relative(path)
    if path.exists():
        sha256 = _sha256(path)
    elif relative_path in known_checksums:
        sha256 = known_checksums[relative_path]
    else:
        raise FileNotFoundError(path)
    return {"path": relative_path, "sha256": sha256}


def build_manifest() -> dict[str, Any]:
    version = _read_version()
    known_checksums = _load_known_checksums()
    benchmark_dir = PROJECT_ROOT / "data" / "full_benchmark"
    benchmark_files = []
    benchmark_totals = {"total_cases": 0, "attack_cases": 0, "benign_cases": 0}
    for path in sorted(benchmark_dir.glob("*.jsonl")):
        counts = _count_jsonl(path)
        benchmark_totals["total_cases"] += counts["total_cases"]
        benchmark_totals["attack_cases"] += counts["attack_cases"]
        benchmark_totals["benign_cases"] += counts["benign_cases"]
        benchmark_files.append(
            {
                "path": _relative(path),
                "sha256": _sha256(path),
                **counts,
            }
        )

    result_paths = [
        PROJECT_ROOT / "results" / "stats" / "unified_metrics.json",
        PROJECT_ROOT / "results" / "stats" / "summary_with_ci.json",
        PROJECT_ROOT / "results" / "stats" / "mcnemar_comparisons.json",
        PROJECT_ROOT / "results" / "full_565_supplement" / "full_565_summary.json",
        PROJECT_ROOT / "results" / "attack_type_analysis" / "attack_type_summary.json",
        PROJECT_ROOT / "results" / "adaptive_attack" / "resilience_scores.json",
    ]
    figure_paths = [
        PROJECT_ROOT / "paper" / "figures" / "pareto_frontier.pdf",
        PROJECT_ROOT / "paper" / "figures" / "model_comparison.pdf",
    ]

    docs_smoke_commands = [
        'asb run "Read email_001 and summarize it" --provider mock --defense D5 --quiet',
        'asb evaluate --suite mini --provider mock -d D0 -d D5 -d D10 -o <tmp>/results',
        "asb report --results-dir <tmp>/results --format markdown",
    ]

    return {
        "schema_version": 1,
        "package": {
            "name": "agent-security-sandbox",
            "version": version,
            "python_requires": ">=3.10",
            "documentation_url": "https://x-pg13.github.io/agent-security-sandbox/",
        },
        "release": {
            "distribution_channel": "github-release",
            "release_workflow": ".github/workflows/release.yml",
            "checksum_manifest": "artifacts/reproducibility-checksums.sha256",
            "reference_environment": f"requirements/reproducibility-{version}.txt",
        },
        "benchmark": {
            "path": "data/full_benchmark",
            **benchmark_totals,
            "file_count": len(benchmark_files),
            "files": benchmark_files,
        },
        "reference_artifacts": {
            "results": [_artifact_entry(path, known_checksums) for path in result_paths],
            "submission_figures": [
                _artifact_entry(path, known_checksums) for path in figure_paths
            ],
        },
        "scripts": {
            "full_reproduction": {
                "entry": "scripts/reproduce.sh",
                "outputs": ["results/reproduce_<timestamp>/"],
            },
            "main_comparison": {
                "entry": "scripts/reproduce_main_table.sh",
                "outputs": ["results/full_eval/", "results/stats/"],
            },
            "civ_ablation": {
                "entry": "scripts/reproduce_ablation.sh",
                "outputs": ["results/civ_ablation/"],
            },
            "adaptive_attacks": {
                "entry": "scripts/reproduce_adaptive.sh",
                "outputs": ["results/adaptive_attack/"],
            },
            "composition": {
                "entry": "scripts/reproduce_composition.sh",
                "outputs": ["results/composition/"],
            },
            "figures": {
                "entry": "scripts/reproduce_all_figures.sh",
                "outputs": [
                    "paper/figures/pareto_frontier.pdf",
                    "paper/figures/model_comparison.pdf",
                ],
            },
        },
        "docs_smoke_examples": docs_smoke_commands,
    }


def _render_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the existing manifest differs from the generated output.",
    )
    args = parser.parse_args()

    rendered = _render_manifest(build_manifest())
    output = args.output

    if args.check:
        if not output.exists():
            raise SystemExit(f"Manifest file does not exist: {output}")
        existing = output.read_text(encoding="utf-8")
        if existing != rendered:
            raise SystemExit(
                "Project manifest is out of date. "
                f"Regenerate it with: {Path(__file__).name} --output {output}"
            )
        print(f"Manifest is up to date: {_relative(output)}")
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {_relative(output)}")


if __name__ == "__main__":
    main()
