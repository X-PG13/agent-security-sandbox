"""Interpretability analysis tools for understanding defense behaviour.

Provides:
- ``InjectionHeatmapAnalyzer``: Token-level injection influence scoring.
- ``DefenseVisualization``: Defense decision distribution visualisation.
- ``AttentionAnalyzer``: Logprob-based attention analysis.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# -----------------------------------------------------------------------
# Injection Heatmap
# -----------------------------------------------------------------------

@dataclass
class TokenScore:
    """Score for a single token in the injection analysis."""

    token: str
    score: float
    position: int


class InjectionHeatmapAnalyzer:
    """Analyses which tokens in the untrusted content most influence
    the agent's decision to execute a forbidden action.

    Uses a simple perturbation-based approach: mask each token and
    measure the change in forbidden-action probability (approximated
    by keyword matching or logprob change).
    """

    def __init__(self, llm_client: Any = None) -> None:
        self._llm = llm_client

    def analyze(
        self,
        goal: str,
        untrusted_content: str,
        forbidden_keywords: Optional[List[str]] = None,
    ) -> List[TokenScore]:
        """Score each token in *untrusted_content* by injection influence.

        Without a real LLM, uses keyword co-occurrence as a proxy.
        """
        tokens = untrusted_content.split()
        forbidden_keywords = forbidden_keywords or [
            "ignore", "override", "send", "forward", "attacker",
            "evil", "system", "admin", "urgent", "elevated",
        ]
        fk_set = {k.lower() for k in forbidden_keywords}

        scores: List[TokenScore] = []
        for i, token in enumerate(tokens):
            clean = re.sub(r"[^\w]", "", token.lower())
            # Base score: direct keyword match.
            if clean in fk_set:
                score = 1.0
            # Partial match.
            elif any(k in clean for k in fk_set):
                score = 0.7
            # Contextual: tokens near keywords get partial score.
            else:
                neighbours = tokens[max(0, i - 2): i + 3]
                neighbour_text = " ".join(neighbours).lower()
                hits = sum(1 for k in fk_set if k in neighbour_text)
                score = min(hits * 0.15, 0.5)

            scores.append(TokenScore(token=token, score=score, position=i))

        return scores

    def to_html(self, scores: List[TokenScore]) -> str:
        """Render token scores as an HTML heatmap string."""
        parts = []
        for ts in scores:
            r = int(255 * ts.score)
            g = int(255 * (1 - ts.score))
            color = f"rgb({r},{g},0)"
            parts.append(
                f'<span style="background-color:{color};padding:2px;">'
                f"{ts.token}</span>"
            )
        return " ".join(parts)


# -----------------------------------------------------------------------
# Defense Visualization
# -----------------------------------------------------------------------

@dataclass
class DefenseDecisionStats:
    """Aggregated statistics for defense decisions."""

    defense_id: str
    total_checks: int = 0
    allowed: int = 0
    blocked: int = 0
    per_tool: Dict[str, Dict[str, int]] = field(default_factory=dict)
    per_attack_type: Dict[str, Dict[str, int]] = field(default_factory=dict)


class DefenseVisualization:
    """Aggregates and visualises defense decision patterns from experiment results."""

    def aggregate(
        self, results: List[Dict[str, Any]],
    ) -> Dict[str, DefenseDecisionStats]:
        """Aggregate defense decisions from experiment result dicts.

        Each result dict is expected to have:
          - ``defense_id``
          - ``case_results``: list of per-case dicts with
            ``defense_decisions``, ``attack_type``, and tool call info.
        """
        stats: Dict[str, DefenseDecisionStats] = {}

        for result in results:
            did = result.get("defense_id", "unknown")
            if did not in stats:
                stats[did] = DefenseDecisionStats(defense_id=did)
            s = stats[did]

            for case in result.get("case_results", []):
                for decision in case.get("defense_decisions", []):
                    s.total_checks += 1
                    action = decision.get("action", "allow")
                    if action == "allow":
                        s.allowed += 1
                    else:
                        s.blocked += 1

                    tool = decision.get("tool", "unknown")
                    if tool not in s.per_tool:
                        s.per_tool[tool] = {"allowed": 0, "blocked": 0}
                    s.per_tool[tool]["allowed" if action == "allow" else "blocked"] += 1

                    atype = case.get("attack_type", "unknown")
                    if atype not in s.per_attack_type:
                        s.per_attack_type[atype] = {"allowed": 0, "blocked": 0}
                    s.per_attack_type[atype][
                        "allowed" if action == "allow" else "blocked"
                    ] += 1

        return stats

    def generate_summary(
        self, stats: Dict[str, DefenseDecisionStats],
    ) -> str:
        """Generate a Markdown summary of defense decision statistics."""
        lines = ["# Defense Decision Analysis\n"]

        for did, s in sorted(stats.items()):
            block_rate = s.blocked / max(s.total_checks, 1)
            lines.append(f"## {did}")
            lines.append(
                f"- Total checks: {s.total_checks}  "
                f"Allowed: {s.allowed}  Blocked: {s.blocked}  "
                f"Block rate: {block_rate:.1%}"
            )
            if s.per_tool:
                lines.append("- Per-tool breakdown:")
                for tool, counts in sorted(s.per_tool.items()):
                    lines.append(
                        f"  - {tool}: allowed={counts['allowed']}, "
                        f"blocked={counts['blocked']}"
                    )
            lines.append("")

        return "\n".join(lines)


# -----------------------------------------------------------------------
# Attention / Logprob Analyzer
# -----------------------------------------------------------------------

class AttentionAnalyzer:
    """Analyse logprob data from LLM responses to identify which input
    tokens received the most 'attention' during generation.

    This is a simplified proxy for attention analysis — it examines
    logprobs of generated tokens to infer which parts of the input
    most influenced the output.
    """

    def analyze_logprobs(
        self,
        logprobs: List[Dict[str, Any]],
    ) -> Dict[str, float]:
        """Summarise logprob data into per-token confidence scores.

        Args:
            logprobs: List of logprob entries, each containing
                ``"token"`` and ``"logprob"`` keys.

        Returns:
            Dict mapping token text to average probability.
        """
        token_probs: Dict[str, List[float]] = defaultdict(list)

        for entry in logprobs:
            token = entry.get("token", "")
            lp = entry.get("logprob", 0.0)
            prob = math.exp(lp) if lp != 0 else 1.0
            token_probs[token].append(prob)

        return {
            token: sum(probs) / len(probs)
            for token, probs in token_probs.items()
        }

    def identify_high_influence_tokens(
        self,
        logprobs: List[Dict[str, Any]],
        threshold: float = 0.8,
    ) -> List[str]:
        """Return tokens with average probability above *threshold*."""
        avg_probs = self.analyze_logprobs(logprobs)
        return [
            token for token, prob in avg_probs.items()
            if prob >= threshold
        ]
