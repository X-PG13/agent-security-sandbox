#!/usr/bin/env python3
"""Real environment validation experiment.

Runs a subset of benchmark cases using real tools (Gmail, Google Calendar)
in dry-run mode by default. Switch to live mode with ``--live`` for
actual API calls against sandbox accounts.

Usage:
    # Dry run (default, safe)
    python experiments/run_real_environment.py \
        --benchmark-dir data/mini_benchmark --max-cases 5

    # Live run against sandbox (requires credentials)
    python experiments/run_real_environment.py \
        --benchmark-dir data/mini_benchmark --max-cases 5 \
        --live --credentials config/google_credentials.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.tools.real.calendar_tool import GoogleCalendarTool  # noqa: E402
from agent_security_sandbox.tools.real.email_tool import GmailTool  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Real environment validation experiment.",
    )
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
    )
    parser.add_argument("--max-cases", type=int, default=5)
    parser.add_argument("--defense", type=str, default="D0")
    parser.add_argument("--provider", type=str, default="mock")
    parser.add_argument("--live", action="store_true", help="Enable live API calls")
    parser.add_argument("--credentials", type=str, default=None)
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "real_env"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dry_run = not args.live
    mode = "LIVE" if args.live else "DRY RUN"
    print(f"Mode: {mode}")

    if args.live and not args.credentials:
        print("ERROR: --credentials required for live mode")
        sys.exit(1)

    # Create real tools
    gmail = GmailTool(
        credentials_path=args.credentials,
        dry_run=dry_run,
        sandbox_account="asb-test@gmail.com",
    )
    calendar = GoogleCalendarTool(
        credentials_path=args.credentials,
        dry_run=dry_run,
        sandbox_account="asb-test@gmail.com",
    )

    print(f"Gmail tool: {'DRY RUN' if gmail.dry_run else 'LIVE'}")
    print(f"Calendar tool: {'DRY RUN' if calendar.dry_run else 'LIVE'}")

    # Load benchmark
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    cases = suite.cases[: args.max_cases]
    print(f"\nRunning {len(cases)} cases against defense {args.defense}")

    results = []
    for i, case in enumerate(cases):
        print(f"\n[{i + 1}/{len(cases)}] {case.id} ({case.type})")

        # Demonstrate real tool calls in dry-run.
        if case.type == "attack" and case.forbidden_actions:
            for fa in case.forbidden_actions:
                tool_name = fa.get("tool", "")
                params = fa.get("params", {})
                if "email" in tool_name.lower():
                    result = gmail.execute(**params)
                    print(f"  Gmail: {result}")
                elif "calendar" in tool_name.lower():
                    result = calendar.execute(action="create", **params)
                    print(f"  Calendar: {result}")

        results.append({
            "case_id": case.id,
            "type": case.type,
            "gmail_calls": gmail.call_count,
            "calendar_calls": calendar.call_count,
        })

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Total Gmail calls: {gmail.call_count}")
    print(f"Total Calendar calls: {calendar.call_count}")

    results_path = output_dir / "real_env_results.json"
    with open(results_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"Results saved to {results_path}")


if __name__ == "__main__":
    main()
