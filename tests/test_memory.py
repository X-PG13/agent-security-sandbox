"""Tests for ConversationMemory."""
from datetime import datetime, timezone

from agent_security_sandbox.core.memory import ConversationMemory, MemoryStrategy, Message


class TestMessage:
    def test_default_timestamp(self):
        m = Message(role="user", content="hello")
        assert m.role == "user"
        assert m.content == "hello"
        assert isinstance(m.timestamp, datetime)

    def test_explicit_timestamp(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        m = Message(role="assistant", content="hi", timestamp=ts)
        assert m.timestamp == ts


class TestConversationMemory:
    def test_default_strategy(self):
        mem = ConversationMemory()
        assert mem.strategy == MemoryStrategy.FULL
        assert mem.window_size == 10

    def test_add_message(self):
        mem = ConversationMemory()
        msg = mem.add_message("user", "hello")
        assert msg.role == "user"
        assert mem.size == 1

    def test_add_message_with_timestamp(self):
        mem = ConversationMemory()
        ts = datetime(2024, 6, 15, tzinfo=timezone.utc)
        msg = mem.add_message("user", "hi", timestamp=ts)
        assert msg.timestamp == ts

    def test_clear(self):
        mem = ConversationMemory()
        mem.add_message("user", "a")
        mem.add_message("assistant", "b")
        mem.clear()
        assert mem.size == 0
        assert mem.get_messages() == []

    def test_get_messages_full(self):
        mem = ConversationMemory(strategy=MemoryStrategy.FULL)
        for i in range(5):
            mem.add_message("user", f"msg{i}")
        msgs = mem.get_messages()
        assert len(msgs) == 5

    def test_get_messages_sliding_window(self):
        mem = ConversationMemory(strategy=MemoryStrategy.SLIDING_WINDOW, window_size=3)
        for i in range(5):
            mem.add_message("user", f"msg{i}")
        msgs = mem.get_messages()
        assert len(msgs) == 3
        assert msgs[0].content == "msg2"

    def test_get_window(self):
        mem = ConversationMemory()
        for i in range(5):
            mem.add_message("user", f"msg{i}")
        window = mem.get_window(2)
        assert len(window) == 2
        assert window[0].content == "msg3"

    def test_get_window_zero(self):
        mem = ConversationMemory()
        mem.add_message("user", "a")
        assert mem.get_window(0) == []

    def test_to_dicts(self):
        mem = ConversationMemory()
        mem.add_message("user", "hello")
        mem.add_message("assistant", "hi")
        dicts = mem.to_dicts()
        assert dicts == [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]

    def test_len(self):
        mem = ConversationMemory()
        assert len(mem) == 0
        mem.add_message("user", "a")
        assert len(mem) == 1

    def test_repr(self):
        mem = ConversationMemory(strategy=MemoryStrategy.SLIDING_WINDOW, window_size=5)
        r = repr(mem)
        assert "sliding_window" in r
        assert "window_size=5" in r
