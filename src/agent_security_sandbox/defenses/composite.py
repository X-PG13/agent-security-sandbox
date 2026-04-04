"""
Composite Defense -- Pipeline of multiple defense strategies.

Combines several ``DefenseStrategy`` instances into a single strategy:

* **prepare_context**: Each defense's ``prepare_context`` is applied in
  sequence, with each one receiving the output of the previous one as
  the ``untrusted_content`` (the goal is preserved unchanged).
* **should_allow_tool_call**: Every defense is consulted; if **any**
  defense blocks the call, the overall result is a block.
"""
from typing import Any, Dict, List, Tuple

from ..tools.base import Tool
from .base import DefenseStrategy


class CompositeDefense(DefenseStrategy):
    """Pipeline that applies multiple defense strategies in order.

    Args:
        strategies: An ordered list of ``DefenseStrategy`` instances.
            The order matters for ``prepare_context`` (applied sequentially).
            For ``should_allow_tool_call`` every strategy is checked and
            any single block causes the call to be blocked.
    """

    def __init__(self, strategies: List[DefenseStrategy]):
        if not strategies:
            raise ValueError(
                "CompositeDefense requires at least one strategy."
            )
        self.strategies = strategies

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Apply each strategy's prepare_context in sequence.

        The first strategy receives the raw *goal* and *untrusted_content*.
        Subsequent strategies receive the same *goal* but the *output*
        of the previous strategy as *untrusted_content*, so that
        delimiters / warnings accumulate correctly.
        """
        result = untrusted_content
        for strategy in self.strategies:
            result = strategy.prepare_context(goal, result)
        return result

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Consult every strategy; block if any strategy blocks.

        Returns:
            ``(True, reasons)`` only if *every* strategy allows the call.
            ``(False, reason)`` as soon as a strategy blocks, with the
            blocking strategy's reason.
        """
        allow_reasons: List[str] = []

        for strategy in self.strategies:
            allowed, reason = strategy.should_allow_tool_call(
                tool, params, context
            )
            if not allowed:
                strategy_name = type(strategy).__name__
                return (
                    False,
                    f"Blocked by {strategy_name}: {reason}",
                )
            allow_reasons.append(reason)

        combined_reason = " | ".join(allow_reasons)
        return True, f"All defenses passed: [{combined_reason}]"
