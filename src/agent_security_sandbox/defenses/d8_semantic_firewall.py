"""D8 -- Semantic Firewall defense.

Uses embedding cosine similarity to detect instruction drift between the
user's original goal and a proposed tool action.  When the semantic
distance between the goal and the action description exceeds a threshold
the call is blocked.

Falls back to keyword-overlap scoring when ``embed()`` is not available
on the LLM client.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

from ..tools.base import Tool
from .base import DefenseStrategy


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _keyword_overlap(text_a: str, text_b: str) -> float:
    """Simple keyword-overlap score as fallback for embed()."""
    # Split on both whitespace and underscores to handle tool names like "read_email".
    words_a = set(re.findall(r"[a-z0-9]+", text_a.lower()))
    words_b = set(re.findall(r"[a-z0-9]+", text_b.lower()))
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)  # Jaccard similarity


class SemanticFirewallDefense(DefenseStrategy):
    """Embedding-based defense that detects goal-action semantic drift.

    Configuration keys (all optional):
        similarity_threshold (float): Minimum cosine similarity between
            the goal embedding and the action description embedding for
            the call to be allowed.  Default ``0.3``.
        use_embedding (bool): Whether to attempt using ``llm_client.embed()``.
            Default ``True``.
        fallback_to_keyword (bool): If ``embed()`` fails, fall back to
            keyword overlap.  Default ``True``.
        monitored_tools (list[str]): Tools to check.  If empty, all
            tools are checked.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        llm_client: Any = None,
    ) -> None:
        self._config = config or {}
        self._llm_client = llm_client
        self._similarity_threshold: float = self._config.get(
            "similarity_threshold", 0.3,
        )
        self._use_embedding: bool = self._config.get("use_embedding", True)
        self._fallback_to_keyword: bool = self._config.get(
            "fallback_to_keyword", True,
        )
        self._monitored_tools: List[str] = self._config.get(
            "monitored_tools", [],
        )
        # Cache goal embedding to avoid redundant API calls.
        self._goal_text: str = ""
        self._goal_embedding: Optional[List[float]] = None

    # ------------------------------------------------------------------
    # DefenseStrategy interface
    # ------------------------------------------------------------------

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Cache the goal and pass through unmodified context."""
        self._goal_text = goal
        self._goal_embedding = None  # reset cache
        if untrusted_content:
            return f"{goal}\n\nExternal content:\n{untrusted_content}"
        return goal

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        tool_name = tool.metadata.name if hasattr(tool, "metadata") else str(tool)

        # Only check monitored tools (if list is non-empty).
        if self._monitored_tools and tool_name not in self._monitored_tools:
            return True, "Tool not monitored by semantic firewall."

        # Build a natural-language description of the proposed action.
        action_desc = self._describe_action(tool_name, params)

        similarity = self._compute_similarity(self._goal_text, action_desc)

        if similarity >= self._similarity_threshold:
            return True, (
                f"Semantic similarity {similarity:.3f} >= "
                f"threshold {self._similarity_threshold:.3f}."
            )

        return False, (
            f"BLOCKED by semantic firewall: similarity {similarity:.3f} < "
            f"threshold {self._similarity_threshold:.3f}. "
            f"Action '{action_desc}' appears unrelated to goal."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_similarity(self, goal: str, action: str) -> float:
        """Compute similarity between goal and action strings."""
        if self._use_embedding and self._llm_client is not None:
            try:
                if self._goal_embedding is None:
                    self._goal_embedding = self._llm_client.embed(goal)
                action_emb = self._llm_client.embed(action)
                return _cosine_similarity(self._goal_embedding, action_emb)
            except (NotImplementedError, Exception):
                if not self._fallback_to_keyword:
                    # Cannot compute — allow by default.
                    return 1.0

        # Keyword-overlap fallback.
        return _keyword_overlap(goal, action)

    @staticmethod
    def _describe_action(tool_name: str, params: Dict[str, Any]) -> str:
        """Create a natural-language summary of a tool call."""
        parts = [f"Calling {tool_name}"]
        for key, value in params.items():
            parts.append(f"{key}={value}")
        return " ".join(parts)
