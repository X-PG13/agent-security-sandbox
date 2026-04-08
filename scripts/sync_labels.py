#!/usr/bin/env python3
"""Sync repository labels from .github/labels.json."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import quote

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / ".github" / "labels.json"


def _run_gh_json(args: list[str]) -> Any:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _run_gh(args: list[str]) -> None:
    subprocess.run(["gh", *args], check=True)


def _load_labels(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text(encoding="utf-8"))


def sync_labels(repo: str, labels: list[dict[str, str]]) -> None:
    existing = {
        label["name"]: label
        for label in _run_gh_json(["api", f"repos/{repo}/labels?per_page=100"])
    }

    for label in labels:
        name = label["name"]
        color = label["color"].lstrip("#")
        description = label["description"]

        if name in existing:
            encoded_name = quote(name, safe="")
            _run_gh(
                [
                    "api",
                    "--method",
                    "PATCH",
                    "--silent",
                    f"repos/{repo}/labels/{encoded_name}",
                    "-f",
                    f"new_name={name}",
                    "-f",
                    f"color={color}",
                    "-f",
                    f"description={description}",
                ]
            )
            print(f"updated: {name}")
        else:
            _run_gh(
                [
                    "api",
                    "--method",
                    "POST",
                    "--silent",
                    f"repos/{repo}/labels",
                    "-f",
                    f"name={name}",
                    "-f",
                    f"color={color}",
                    "-f",
                    f"description={description}",
                ]
            )
            print(f"created: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository slug, for example X-PG13/agent-security-sandbox",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    labels = _load_labels(args.config)
    sync_labels(args.repo, labels)


if __name__ == "__main__":
    main()
