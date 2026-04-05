"""
D0 -- Baseline (No Defense)

The simplest defense strategy: do nothing.  Untrusted content is
concatenated directly with the goal, and every tool call is allowed.
This serves as the control condition in ablation studies.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from ..tools.base import Tool
from .base import DefenseStrategy


class BaselineDefense(DefenseStrategy):
    """No-op defense -- always allows everything."""

    def __init__(self, config: Dict[str, Any] | None = None):
        # Config is accepted for interface uniformity but ignored.
        self.config = config or {}

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Simply concatenate goal and untrusted content with no marking."""
        return f"{goal}\n\nContext:\n{untrusted_content}"

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Always allow the tool call."""
        return True, "No defense active -- all calls allowed."
