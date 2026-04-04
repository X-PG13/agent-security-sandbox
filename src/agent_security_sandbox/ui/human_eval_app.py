"""Streamlit annotation UI for human evaluation.

Launch with:
    streamlit run src/agent_security_sandbox/ui/human_eval_app.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    import streamlit as st
except ImportError:
    raise ImportError(
        "streamlit is required for the human evaluation UI. "
        "Install with: pip install agent-security-sandbox[ui]"
    )

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.human_eval import (  # noqa: E402
    HumanAnnotation,
    HumanEvalSession,
    InterAnnotatorAgreement,
)

VERDICTS = [
    "attack_succeeded",
    "attack_blocked",
    "benign_completed",
    "benign_blocked",
    "unclear",
]


def main() -> None:
    st.set_page_config(page_title="ASB Human Evaluation", layout="wide")
    st.title("Agent Security Sandbox -- Human Evaluation")

    # Sidebar configuration.
    st.sidebar.header("Configuration")
    annotator_id = st.sidebar.text_input("Annotator ID", value="annotator_1")
    benchmark_dir = st.sidebar.text_input(
        "Benchmark directory", value="data/mini_benchmark",
    )
    session_file = st.sidebar.text_input(
        "Session file", value="results/human_eval/session.json",
    )
    results_dir = st.sidebar.text_input(
        "Agent results directory", value="results/full_eval",
    )

    # Load or create session.
    session_path = Path(session_file)
    if session_path.exists():
        session = HumanEvalSession.load(session_path)
        st.sidebar.success(f"Loaded {len(session.annotations)} annotations")
    else:
        session = HumanEvalSession(session_id="human_eval_v1")
        st.sidebar.info("New session created")

    # Load benchmark cases.
    try:
        suite = BenchmarkSuite.load_from_directory(benchmark_dir)
        cases = suite.cases
    except Exception as e:
        st.error(f"Failed to load benchmark: {e}")
        return

    st.sidebar.metric("Total cases", len(cases))
    st.sidebar.metric(
        "Annotated",
        len({a.case_id for a in session.get_annotations_by_annotator(annotator_id)}),
    )

    # Case selection.
    case_ids = [c.id for c in cases]
    selected_id = st.selectbox("Select case", case_ids)
    case = next((c for c in cases if c.id == selected_id), None)

    if case is None:
        st.warning("Case not found.")
        return

    # Display case details.
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Case Details")
        st.write(f"**ID:** {case.id}")
        st.write(f"**Type:** {case.type}")
        st.write(f"**Goal:** {case.goal}")
        if case.untrusted_content:
            st.write("**Untrusted Content:**")
            st.code(case.untrusted_content, language=None)
        st.write(f"**Attack Type:** {case.attack_type or 'N/A'}")
        st.write(f"**Expected Tools:** {', '.join(case.expected_tools)}")
        if case.forbidden_actions:
            st.write("**Forbidden Actions:**")
            st.json(case.forbidden_actions)

    with col2:
        st.subheader("Agent Trajectory")
        # Load trajectory if available.
        results_path = Path(results_dir)
        trajectory_loaded = False
        if results_path.exists():
            for result_file in results_path.glob("*.json"):
                try:
                    with open(result_file) as fh:
                        data = json.load(fh)
                    case_results = data.get("case_results", [])
                    for cr in case_results:
                        if cr.get("case_id") == case.id:
                            st.json(cr)
                            trajectory_loaded = True
                            break
                except Exception:
                    continue
                if trajectory_loaded:
                    break

        if not trajectory_loaded:
            st.info("No agent trajectory available for this case.")

    # Annotation form.
    st.subheader("Your Annotation")
    existing = [
        a for a in session.get_annotations_for_case(case.id)
        if a.annotator_id == annotator_id
    ]

    default_verdict = existing[0].verdict if existing else VERDICTS[0]
    default_confidence = existing[0].confidence if existing else 3
    default_reasoning = existing[0].reasoning if existing else ""
    default_quality = existing[0].quality_score if existing else 0.5

    verdict = st.selectbox(
        "Verdict",
        VERDICTS,
        index=VERDICTS.index(default_verdict) if default_verdict in VERDICTS else 0,
    )
    confidence = st.slider("Confidence (1-5)", 1, 5, default_confidence)
    reasoning = st.text_area("Reasoning", value=default_reasoning)
    quality_score = st.slider(
        "Quality Score (0.0-1.0)", 0.0, 1.0, float(default_quality or 0.5), 0.1,
    )

    if st.button("Submit Annotation"):
        annotation = HumanAnnotation(
            case_id=case.id,
            annotator_id=annotator_id,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            quality_score=quality_score,
        )
        # Remove previous annotation for same case+annotator.
        session.annotations = [
            a for a in session.annotations
            if not (a.case_id == case.id and a.annotator_id == annotator_id)
        ]
        session.add_annotation(annotation)
        session.save(session_path)
        st.success(f"Annotation saved for {case.id}")

    # Agreement metrics.
    if len(session.annotator_ids) >= 2:
        st.subheader("Inter-Annotator Agreement")
        iaa = InterAnnotatorAgreement(session)
        summary = iaa.summary()
        st.json(summary)


if __name__ == "__main__":
    main()
