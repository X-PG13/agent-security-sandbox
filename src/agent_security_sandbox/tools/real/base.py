"""Base class for real-environment tools with safety guardrails.

All real tools support:
- ``dry_run`` mode: logs the action without executing it.
- Rate limiting: enforces a minimum interval between calls.
- Sandboxed accounts: tools operate on dedicated test accounts.
"""
from __future__ import annotations

import logging
import time
from abc import abstractmethod
from typing import Any, Dict, Optional

from ..base import Tool, ToolMetadata

logger = logging.getLogger(__name__)


class RealTool(Tool):
    """Base class for tools that interact with real external services.

    Args:
        metadata: Tool metadata (name, description, risk level, etc.).
        dry_run: If ``True``, log actions without executing them.
        rate_limit_seconds: Minimum interval between consecutive calls.
        sandbox_account: Identifier for the sandboxed test account.
    """

    def __init__(
        self,
        metadata: ToolMetadata,
        dry_run: bool = True,
        rate_limit_seconds: float = 1.0,
        sandbox_account: Optional[str] = None,
    ) -> None:
        super().__init__(metadata)
        self.dry_run = dry_run
        self.rate_limit_seconds = rate_limit_seconds
        self.sandbox_account = sandbox_account
        self._last_call_time: float = 0.0
        self._call_count: int = 0

    def execute(self, **kwargs: Any) -> Dict[str, Any]:
        """Execute the tool with rate limiting and dry-run support."""
        # Rate limiting.
        now = time.time()
        elapsed = now - self._last_call_time
        if elapsed < self.rate_limit_seconds:
            wait = self.rate_limit_seconds - elapsed
            logger.debug(
                "Rate limiting %s: sleeping %.2fs", self.metadata.name, wait,
            )
            time.sleep(wait)

        self._last_call_time = time.time()
        self._call_count += 1

        if self.dry_run:
            logger.info(
                "[DRY RUN] %s called with %s", self.metadata.name, kwargs,
            )
            return self._dry_run_response(**kwargs)

        return self._real_execute(**kwargs)

    @abstractmethod
    def _real_execute(self, **kwargs: Any) -> Dict[str, Any]:
        """Subclasses implement the actual API call here."""
        ...

    def _dry_run_response(self, **kwargs: Any) -> Dict[str, Any]:
        """Default dry-run response."""
        return {
            "status": "dry_run",
            "tool": self.metadata.name,
            "would_execute_with": kwargs,
            "sandbox_account": self.sandbox_account,
        }

    @property
    def call_count(self) -> int:
        return self._call_count
