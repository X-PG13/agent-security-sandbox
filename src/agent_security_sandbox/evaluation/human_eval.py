"""Human evaluation framework with inter-annotator agreement metrics.

Provides:
- ``HumanAnnotation``: A single human annotation for a case.
- ``HumanEvalSession``: Manages a batch of annotations.
- ``InterAnnotatorAgreement``: Computes Cohen's kappa and Krippendorff's alpha.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# -----------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------

@dataclass
class HumanAnnotation:
    """A single human annotation for a benchmark case.

    Attributes:
        case_id: ID of the benchmark case being annotated.
        annotator_id: Identifier for the human annotator.
        verdict: ``"attack_succeeded"``, ``"attack_blocked"``,
            ``"benign_completed"``, ``"benign_blocked"``, or ``"unclear"``.
        confidence: Annotator confidence (1-5 scale).
        reasoning: Free-text explanation of the verdict.
        quality_score: Optional quality rating (0.0-1.0).
    """

    case_id: str
    annotator_id: str
    verdict: str
    confidence: int = 3
    reasoning: str = ""
    quality_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "annotator_id": self.annotator_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "quality_score": self.quality_score,
        }


@dataclass
class HumanEvalSession:
    """Manages a batch of human annotations.

    Supports loading/saving annotations, computing agreement, and
    merging annotations from multiple annotators.
    """

    session_id: str
    annotations: List[HumanAnnotation] = field(default_factory=list)

    def add_annotation(self, annotation: HumanAnnotation) -> None:
        self.annotations.append(annotation)

    def get_annotations_for_case(self, case_id: str) -> List[HumanAnnotation]:
        return [a for a in self.annotations if a.case_id == case_id]

    def get_annotations_by_annotator(
        self, annotator_id: str,
    ) -> List[HumanAnnotation]:
        return [a for a in self.annotations if a.annotator_id == annotator_id]

    @property
    def annotator_ids(self) -> List[str]:
        return sorted({a.annotator_id for a in self.annotations})

    @property
    def case_ids(self) -> List[str]:
        return sorted({a.case_id for a in self.annotations})

    def save(self, path: str | Path) -> None:
        """Save annotations to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "session_id": self.session_id,
            "annotations": [a.to_dict() for a in self.annotations],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str | Path) -> "HumanEvalSession":
        """Load annotations from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        session = cls(session_id=data.get("session_id", "unknown"))
        for raw in data.get("annotations", []):
            session.add_annotation(HumanAnnotation(**raw))
        return session

    def majority_verdict(self, case_id: str) -> Optional[str]:
        """Return the majority verdict for a case, or None if tied."""
        annots = self.get_annotations_for_case(case_id)
        if not annots:
            return None
        counts = Counter(a.verdict for a in annots)
        top = counts.most_common(1)[0]
        return top[0]


# -----------------------------------------------------------------------
# Inter-Annotator Agreement
# -----------------------------------------------------------------------

class InterAnnotatorAgreement:
    """Compute agreement metrics between human annotators.

    Supports:
    - Cohen's kappa (for 2 annotators).
    - Krippendorff's alpha (for 2+ annotators, handles missing data).
    """

    def __init__(self, session: HumanEvalSession) -> None:
        self._session = session

    def cohens_kappa(
        self,
        annotator_a: str,
        annotator_b: str,
    ) -> float:
        """Compute Cohen's kappa between two annotators.

        Only considers cases annotated by both annotators.

        Returns:
            Kappa value in [-1, 1].  1 = perfect agreement,
            0 = chance agreement, negative = below chance.
        """
        a_annots = {
            a.case_id: a.verdict
            for a in self._session.get_annotations_by_annotator(annotator_a)
        }
        b_annots = {
            a.case_id: a.verdict
            for a in self._session.get_annotations_by_annotator(annotator_b)
        }

        common = sorted(set(a_annots) & set(b_annots))
        if not common:
            return 0.0

        n = len(common)
        categories = sorted({a_annots[c] for c in common} | {b_annots[c] for c in common})

        # Observed agreement
        agree = sum(1 for c in common if a_annots[c] == b_annots[c])
        p_o = agree / n

        # Expected agreement
        p_e = 0.0
        for cat in categories:
            p_a = sum(1 for c in common if a_annots[c] == cat) / n
            p_b = sum(1 for c in common if b_annots[c] == cat) / n
            p_e += p_a * p_b

        if p_e == 1.0:
            return 1.0
        return (p_o - p_e) / (1 - p_e)

    def krippendorff_alpha(self) -> float:
        """Compute Krippendorff's alpha for all annotators.

        Uses nominal metric (exact match for categories).
        Handles missing data (not all annotators need to annotate
        every case).

        Returns:
            Alpha value.  1 = perfect agreement, 0 = chance agreement.
        """
        case_ids = self._session.case_ids
        annotator_ids = self._session.annotator_ids

        if len(annotator_ids) < 2:
            return 1.0

        # Build a reliability matrix: case_id -> annotator_id -> verdict
        matrix: Dict[str, Dict[str, str]] = defaultdict(dict)
        for annotation in self._session.annotations:
            matrix[annotation.case_id][annotation.annotator_id] = annotation.verdict

        # Collect all observed disagreement and expected disagreement.
        all_values: List[str] = []
        for case_id in case_ids:
            for ann_id in annotator_ids:
                if ann_id in matrix[case_id]:
                    all_values.append(matrix[case_id][ann_id])

        if not all_values:
            return 0.0

        value_counts = Counter(all_values)
        n_total = len(all_values)

        # Observed disagreement (D_o)
        d_o = 0.0
        n_units = 0
        for case_id in case_ids:
            values = [
                matrix[case_id][a]
                for a in annotator_ids
                if a in matrix[case_id]
            ]
            m = len(values)
            if m < 2:
                continue
            n_units += 1
            # Count disagreements within this unit.
            for i in range(m):
                for j in range(i + 1, m):
                    if values[i] != values[j]:
                        d_o += 1

        # Expected disagreement (D_e)
        d_e = 0.0
        categories = sorted(value_counts.keys())
        for i, cat_a in enumerate(categories):
            for j, cat_b in enumerate(categories):
                if i >= j:
                    continue
                if cat_a != cat_b:
                    d_e += value_counts[cat_a] * value_counts[cat_b]

        if d_e == 0:
            return 1.0

        # Normalise
        n_pairs_total = n_total * (n_total - 1) / 2
        d_e_norm = d_e / n_pairs_total if n_pairs_total > 0 else 0

        n_obs_pairs: float = 0
        for case_id in case_ids:
            m = sum(1 for a in annotator_ids if a in matrix[case_id])
            n_obs_pairs += m * (m - 1) / 2
        d_o_norm = d_o / n_obs_pairs if n_obs_pairs > 0 else 0

        if d_e_norm == 0:
            return 1.0

        return 1 - d_o_norm / d_e_norm

    def summary(self) -> Dict[str, Any]:
        """Generate a summary of agreement metrics."""
        annotators = self._session.annotator_ids
        result: Dict[str, Any] = {
            "num_annotators": len(annotators),
            "num_cases": len(self._session.case_ids),
            "num_annotations": len(self._session.annotations),
            "krippendorff_alpha": self.krippendorff_alpha(),
        }

        # Pairwise Cohen's kappa for pairs of annotators.
        if len(annotators) >= 2:
            kappas = {}
            for i in range(len(annotators)):
                for j in range(i + 1, len(annotators)):
                    k = self.cohens_kappa(annotators[i], annotators[j])
                    kappas[f"{annotators[i]}_vs_{annotators[j]}"] = round(k, 4)
            result["cohens_kappa_pairs"] = kappas

        return result
