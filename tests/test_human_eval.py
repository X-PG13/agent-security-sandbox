"""Tests for the human evaluation framework."""
from __future__ import annotations

from pathlib import Path

import pytest

from agent_security_sandbox.evaluation.human_eval import (
    HumanAnnotation,
    HumanEvalSession,
    InterAnnotatorAgreement,
)

# -----------------------------------------------------------------------
# HumanAnnotation
# -----------------------------------------------------------------------

class TestHumanAnnotation:
    def test_create(self):
        a = HumanAnnotation(
            case_id="attack_001",
            annotator_id="ann_1",
            verdict="attack_succeeded",
            confidence=4,
            reasoning="Agent sent email to attacker.",
        )
        assert a.case_id == "attack_001"
        assert a.verdict == "attack_succeeded"

    def test_to_dict(self):
        a = HumanAnnotation(
            case_id="benign_001",
            annotator_id="ann_2",
            verdict="benign_completed",
        )
        d = a.to_dict()
        assert d["case_id"] == "benign_001"
        assert d["verdict"] == "benign_completed"
        assert d["confidence"] == 3  # default


# -----------------------------------------------------------------------
# HumanEvalSession
# -----------------------------------------------------------------------

class TestHumanEvalSession:
    def _make_session(self) -> HumanEvalSession:
        session = HumanEvalSession(session_id="test")
        session.add_annotation(HumanAnnotation("c1", "a1", "attack_succeeded"))
        session.add_annotation(HumanAnnotation("c1", "a2", "attack_succeeded"))
        session.add_annotation(HumanAnnotation("c2", "a1", "attack_blocked"))
        session.add_annotation(HumanAnnotation("c2", "a2", "benign_completed"))
        return session

    def test_add_and_retrieve(self):
        session = self._make_session()
        assert len(session.annotations) == 4

    def test_get_by_case(self):
        session = self._make_session()
        c1 = session.get_annotations_for_case("c1")
        assert len(c1) == 2
        assert all(a.case_id == "c1" for a in c1)

    def test_get_by_annotator(self):
        session = self._make_session()
        a1 = session.get_annotations_by_annotator("a1")
        assert len(a1) == 2

    def test_annotator_ids(self):
        session = self._make_session()
        assert session.annotator_ids == ["a1", "a2"]

    def test_case_ids(self):
        session = self._make_session()
        assert session.case_ids == ["c1", "c2"]

    def test_majority_verdict(self):
        session = self._make_session()
        assert session.majority_verdict("c1") == "attack_succeeded"

    def test_save_and_load(self, tmp_path: Path):
        session = self._make_session()
        path = tmp_path / "session.json"
        session.save(path)

        loaded = HumanEvalSession.load(path)
        assert loaded.session_id == "test"
        assert len(loaded.annotations) == 4

    def test_majority_verdict_tie(self):
        session = HumanEvalSession(session_id="tie")
        session.add_annotation(HumanAnnotation("c1", "a1", "attack_succeeded"))
        session.add_annotation(HumanAnnotation("c1", "a2", "attack_blocked"))
        # most_common picks the first — either is acceptable.
        mv = session.majority_verdict("c1")
        assert mv in ("attack_succeeded", "attack_blocked")


# -----------------------------------------------------------------------
# Inter-Annotator Agreement
# -----------------------------------------------------------------------

class TestInterAnnotatorAgreement:
    def _make_perfect_session(self) -> HumanEvalSession:
        """All annotators agree on every case."""
        session = HumanEvalSession(session_id="perfect")
        for case_id in ["c1", "c2", "c3"]:
            for ann_id in ["a1", "a2", "a3"]:
                session.add_annotation(HumanAnnotation(
                    case_id=case_id,
                    annotator_id=ann_id,
                    verdict="attack_succeeded",
                ))
        return session

    def _make_disagreement_session(self) -> HumanEvalSession:
        """Annotators disagree on every case."""
        session = HumanEvalSession(session_id="disagree")
        verdicts_map = {
            "c1": ["attack_succeeded", "attack_blocked", "unclear"],
            "c2": ["benign_completed", "benign_blocked", "unclear"],
        }
        for case_id, verdicts in verdicts_map.items():
            for ann_id, verdict in zip(["a1", "a2", "a3"], verdicts):
                session.add_annotation(HumanAnnotation(
                    case_id=case_id,
                    annotator_id=ann_id,
                    verdict=verdict,
                ))
        return session

    def test_cohens_kappa_perfect(self):
        session = self._make_perfect_session()
        iaa = InterAnnotatorAgreement(session)
        kappa = iaa.cohens_kappa("a1", "a2")
        # Perfect agreement but all same category => p_e = 1.0 => kappa = 1.0
        assert kappa == pytest.approx(1.0)

    def test_cohens_kappa_no_common_cases(self):
        session = HumanEvalSession(session_id="empty")
        session.add_annotation(HumanAnnotation("c1", "a1", "attack_succeeded"))
        session.add_annotation(HumanAnnotation("c2", "a2", "attack_blocked"))
        iaa = InterAnnotatorAgreement(session)
        kappa = iaa.cohens_kappa("a1", "a2")
        assert kappa == pytest.approx(0.0)

    def test_krippendorff_perfect(self):
        session = self._make_perfect_session()
        iaa = InterAnnotatorAgreement(session)
        alpha = iaa.krippendorff_alpha()
        # Perfect agreement should give alpha = 1.0.
        assert alpha == pytest.approx(1.0, abs=0.01)

    def test_krippendorff_single_annotator(self):
        session = HumanEvalSession(session_id="single")
        session.add_annotation(HumanAnnotation("c1", "a1", "attack_succeeded"))
        iaa = InterAnnotatorAgreement(session)
        alpha = iaa.krippendorff_alpha()
        assert alpha == 1.0  # trivial case

    def test_summary(self):
        session = self._make_perfect_session()
        iaa = InterAnnotatorAgreement(session)
        summary = iaa.summary()
        assert summary["num_annotators"] == 3
        assert summary["num_cases"] == 3
        assert "krippendorff_alpha" in summary
        assert "cohens_kappa_pairs" in summary
