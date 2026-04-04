"""
Base classes for defense strategies.

Defines the abstract interface that all defense strategies must implement,
along with common data structures for defense decisions.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Tuple

from ..tools.base import Tool


class DefenseDecision(str, Enum):
    """Possible outcomes of a defense check."""
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class DefenseResult:
    """Result of a defense strategy evaluation.

    Attributes:
        decision: Whether the action is allowed or blocked.
        reason: Human-readable explanation for the decision.
        details: Optional dictionary with extra metadata about the decision.
    """
    decision: DefenseDecision
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_allowed(self) -> bool:
        """Convenience property: True if the decision is ALLOW."""
        return self.decision == DefenseDecision.ALLOW


class DefenseStrategy(ABC):
    """Abstract base class for all defense strategies.

    Every defense strategy must implement two hooks that the agent calls:

    1. ``prepare_context`` -- called once at the start of a task to produce
       the user message that is fed to the LLM.  Defenses can use this to
       mark untrusted content with delimiters, add warnings, etc.

    2. ``should_allow_tool_call`` -- called before every tool execution so
       the defense can inspect the tool, its parameters, and the current
       context and decide whether the call should proceed.
    """

    @abstractmethod
    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Prepare the user message that will be sent to the LLM.

        Args:
            goal: The user's original goal / task description.
            untrusted_content: External content (e.g. email body) that may
                contain prompt-injection payloads.

        Returns:
            A combined string suitable for use as the user message.
        """
        ...

    @abstractmethod
    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Decide whether a tool call should be allowed.

        Args:
            tool: The ``Tool`` instance that the agent wants to invoke.
            params: The parameters the agent intends to pass to the tool.
            context: Additional context about the current execution state.
                Typically contains at least ``{"goal": str, "step": int}``.

        Returns:
            A tuple ``(allowed, reason)`` where *allowed* is a bool and
            *reason* is a human-readable explanation.
        """
        ...
