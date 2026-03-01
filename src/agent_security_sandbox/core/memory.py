"""
Conversation memory management for agent interactions.

Provides structured storage of messages and configurable retrieval
strategies (full history vs. sliding window).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


@dataclass
class Message:
    """A single message in a conversation.

    Attributes:
        role: The role of the message author (e.g. "system", "user",
              "assistant", "tool").
        content: The textual content of the message.
        timestamp: UTC timestamp of when the message was created.
                   Defaults to the current time if not supplied.
    """
    role: str
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MemoryStrategy(Enum):
    """Strategy used when retrieving conversation history.

    FULL           -- return the entire conversation history.
    SLIDING_WINDOW -- return only the most recent *n* messages
                      (configured via ``window_size``).
    """
    FULL = "full"
    SLIDING_WINDOW = "sliding_window"


class ConversationMemory:
    """Manages an ordered list of :class:`Message` objects and provides
    configurable retrieval strategies.

    Parameters:
        strategy: The retrieval strategy to use (default: FULL).
        window_size: Number of recent messages to keep when using
                     the SLIDING_WINDOW strategy (default: 10).
    """

    def __init__(
        self,
        strategy: MemoryStrategy = MemoryStrategy.FULL,
        window_size: int = 10,
    ) -> None:
        self.strategy = strategy
        self.window_size = window_size
        self._messages: List[Message] = []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_message(self, role: str, content: str, timestamp: Optional[datetime] = None) -> Message:
        """Append a new message to the conversation history.

        Args:
            role: The role of the message author.
            content: The textual content of the message.
            timestamp: Optional explicit timestamp; defaults to now (UTC).

        Returns:
            The newly created :class:`Message`.
        """
        if timestamp is not None:
            msg = Message(role=role, content=content, timestamp=timestamp)
        else:
            msg = Message(role=role, content=content)
        self._messages.append(msg)
        return msg

    def clear(self) -> None:
        """Remove all messages from the conversation history."""
        self._messages.clear()

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_messages(self) -> List[Message]:
        """Return messages according to the configured strategy.

        * ``FULL`` -- returns a copy of the entire history.
        * ``SLIDING_WINDOW`` -- returns the last ``window_size`` messages.
        """
        if self.strategy == MemoryStrategy.SLIDING_WINDOW:
            return list(self._messages[-self.window_size:])
        # Default: FULL
        return list(self._messages)

    def get_window(self, n: int) -> List[Message]:
        """Return the last *n* messages regardless of the configured strategy.

        This is useful when you need an ad-hoc window size that differs from
        the default ``window_size``.

        Args:
            n: Number of recent messages to return.

        Returns:
            A list of up to *n* most recent messages.
        """
        return list(self._messages[-n:]) if n > 0 else []

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dicts(self) -> List[dict]:
        """Return messages (per current strategy) as plain dicts suitable for
        passing directly to an LLM client's ``call()`` method.

        Each dict has keys ``"role"`` and ``"content"``.
        """
        return [{"role": m.role, "content": m.content} for m in self.get_messages()]

    @property
    def size(self) -> int:
        """Total number of messages stored (irrespective of strategy)."""
        return len(self._messages)

    def __len__(self) -> int:
        return self.size

    def __repr__(self) -> str:
        return (
            f"ConversationMemory(strategy={self.strategy.value!r}, "
            f"window_size={self.window_size}, messages={self.size})"
        )
