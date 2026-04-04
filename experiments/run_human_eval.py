#!/usr/bin/env python3
"""Human evaluation agreement analysis.

Analyses a completed human evaluation session and reports inter-annotator
agreement metrics.

Usage:
    python experiments/run_human_eval.py \
        --session results/human_eval/session.json
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

from agent_security_sandbox.evaluation.human_eval import (  # noqa: E402
    HumanEvalSession,
    InterAnnotatorAgreement,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Human evaluation agreement analysis.",
    )
    parser.add_argument(
        "--session",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "human_eval" / "session.json"),
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "human_eval" / "agreement.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not Path(args.session).exists():
        print(f"Session file not found: {args.session}")
        print("Creating a demo session with sample annotations...")

        # Create demo session for testing.
        session = HumanEvalSession(session_id="demo")
        from agent_security_sandbox.evaluation.human_eval import HumanAnnotation

        demo_data = [
            ("attack_001", "annotator_1", "attack_succeeded", 4),
            ("attack_001", "annotator_2", "attack_succeeded", 5),
            ("attack_001", "annotator_3", "attack_succeeded", 4),
            ("attack_002", "annotator_1", "attack_blocked", 3),
            ("attack_002", "annotator_2", "attack_blocked", 4),
            ("attack_002", "annotator_3", "attack_succeeded", 2),
            ("benign_001", "annotator_1", "benign_completed", 5),
            ("benign_001", "annotator_2", "benign_completed", 5),
            ("benign_001", "annotator_3", "benign_completed", 4),
            ("benign_002", "annotator_1", "benign_blocked", 3),
            ("benign_002", "annotator_2", "benign_completed", 2),
            ("benign_002", "annotator_3", "benign_blocked", 3),
        ]
        for case_id, ann_id, verdict, conf in demo_data:
            session.add_annotation(HumanAnnotation(
                case_id=case_id,
                annotator_id=ann_id,
                verdict=verdict,
                confidence=conf,
            ))
        Path(args.session).parent.mkdir(parents=True, exist_ok=True)
        session.save(args.session)
        print(f"Demo session saved to {args.session}")
    else:
        session = HumanEvalSession.load(args.session)

    print(f"Session: {session.session_id}")
    print(f"Annotations: {len(session.annotations)}")
    print(f"Annotators: {session.annotator_ids}")
    print(f"Cases: {len(session.case_ids)}")

    # Compute agreement.
    iaa = InterAnnotatorAgreement(session)
    summary = iaa.summary()

    print("\n--- Agreement Metrics ---")
    print(f"Krippendorff's alpha: {summary['krippendorff_alpha']:.4f}")

    if "cohens_kappa_pairs" in summary:
        print("Cohen's kappa (pairwise):")
        for pair, kappa in summary["cohens_kappa_pairs"].items():
            print(f"  {pair}: {kappa:.4f}")

    # Majority verdicts.
    print("\n--- Majority Verdicts ---")
    for case_id in session.case_ids:
        mv = session.majority_verdict(case_id)
        annots = session.get_annotations_for_case(case_id)
        avg_conf = sum(a.confidence for a in annots) / len(annots) if annots else 0
        print(f"  {case_id}: {mv} (avg confidence: {avg_conf:.1f})")

    # Save results.
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nAgreement report saved to {output_path}")


if __name__ == "__main__":
    main()
