"""Tests for real environment tools (dry_run mode only)."""
from __future__ import annotations

import base64
import builtins
from email import message_from_bytes
from types import SimpleNamespace

import pytest

from agent_security_sandbox.tools.base import RiskLevel, ToolMetadata
from agent_security_sandbox.tools.real import base as real_base
from agent_security_sandbox.tools.real.base import RealTool
from agent_security_sandbox.tools.real.calendar_tool import GoogleCalendarTool
from agent_security_sandbox.tools.real.email_tool import GmailTool


class DummyRealTool(RealTool):
    def __init__(self, dry_run: bool = False, rate_limit_seconds: float = 5.0):
        metadata = ToolMetadata(
            name="dummy_real_tool",
            description="Dummy real tool",
            risk_level=RiskLevel.LOW,
            side_effect=False,
            data_access="public",
            parameters={},
        )
        super().__init__(metadata=metadata, dry_run=dry_run, rate_limit_seconds=rate_limit_seconds)

    def _real_execute(self, **kwargs):
        return {"status": "ok", "kwargs": kwargs}


class TestRealToolBase:
    def test_dry_run_default(self):
        gmail = GmailTool(dry_run=True)
        assert gmail.dry_run is True

    def test_call_count_increments(self):
        gmail = GmailTool(dry_run=True, rate_limit_seconds=0)
        assert gmail.call_count == 0
        gmail.execute(to="test@example.com", subject="Test", body="Hello")
        assert gmail.call_count == 1
        gmail.execute(to="test@example.com", subject="Test2", body="World")
        assert gmail.call_count == 2

    def test_real_tool_rate_limit_sleep(self, monkeypatch):
        tool = DummyRealTool(dry_run=False, rate_limit_seconds=5.0)
        tool._last_call_time = 8.0
        timestamps = iter([10.0, 15.0])
        sleep_calls = []

        monkeypatch.setattr(real_base.time, "time", lambda: next(timestamps))
        monkeypatch.setattr(real_base.time, "sleep", lambda delay: sleep_calls.append(delay))

        result = tool.execute(task="demo")
        assert result["status"] == "ok"
        assert result["kwargs"] == {"task": "demo"}
        assert sleep_calls == [3.0]
        assert tool.call_count == 1


class TestGmailTool:
    def test_dry_run_send(self):
        gmail = GmailTool(dry_run=True, rate_limit_seconds=0)
        result = gmail.execute(
            to="recipient@example.com",
            subject="Test Subject",
            body="Test body content",
        )
        assert result["status"] == "dry_run"
        assert result["tool"] == "gmail_send"
        assert result["would_execute_with"]["to"] == "recipient@example.com"

    def test_metadata(self):
        gmail = GmailTool(dry_run=True)
        assert gmail.metadata.name == "gmail_send"
        assert gmail.metadata.risk_level.value == "high"
        assert gmail.metadata.side_effect is True

    def test_sandbox_account(self):
        gmail = GmailTool(
            dry_run=True,
            sandbox_account="test@sandbox.com",
            rate_limit_seconds=0,
        )
        result = gmail.execute(to="x@x.com", subject="s", body="b")
        assert result["sandbox_account"] == "test@sandbox.com"

    def test_real_execute_uses_gmail_service(self, monkeypatch):
        send_calls = {}

        class FakeMessages:
            def send(self, **kwargs):
                send_calls.update(kwargs)
                return SimpleNamespace(execute=lambda: {"id": "msg_123"})

        class FakeUsers:
            def messages(self):
                return FakeMessages()

        class FakeService:
            def users(self):
                return FakeUsers()

        gmail = GmailTool(dry_run=False, rate_limit_seconds=0)
        monkeypatch.setattr(gmail, "_get_service", lambda: FakeService())
        result = gmail.execute(to="recipient@example.com", subject="Test", body="Hello")

        raw = send_calls["body"]["raw"]
        parsed = message_from_bytes(base64.urlsafe_b64decode(raw.encode()))
        assert result["status"] == "sent"
        assert result["message_id"] == "msg_123"
        assert parsed["to"] == "recipient@example.com"
        assert parsed["subject"] == "Test"

    def test_gmail_get_service_import_error(self, monkeypatch):
        gmail = GmailTool(credentials_path="creds.json", dry_run=False, rate_limit_seconds=0)
        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"google.oauth2.credentials", "googleapiclient.discovery"}:
                raise ImportError("missing google libraries")
            return original_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match="google-api-python-client"):
            gmail._get_service()


class TestGoogleCalendarTool:
    def test_dry_run_create(self):
        cal = GoogleCalendarTool(dry_run=True, rate_limit_seconds=0)
        result = cal.execute(
            action="create",
            title="Test Meeting",
            date="2024-06-15",
            time="14:00",
            description="Test event",
        )
        assert result["status"] == "dry_run"
        assert result["tool"] == "google_calendar"

    def test_dry_run_read(self):
        cal = GoogleCalendarTool(dry_run=True, rate_limit_seconds=0)
        result = cal.execute(action="read", event_id="evt_123")
        assert result["status"] == "dry_run"

    def test_metadata(self):
        cal = GoogleCalendarTool(dry_run=True)
        assert cal.metadata.name == "google_calendar"
        assert cal.metadata.risk_level.value == "medium"

    def test_real_execute_create_and_read_paths(self, monkeypatch):
        insert_calls = {}
        list_calls = {}
        get_calls = {}

        class FakeEvents:
            def insert(self, **kwargs):
                insert_calls.update(kwargs)
                return SimpleNamespace(execute=lambda: {"id": "evt_123"})

            def list(self, **kwargs):
                list_calls.update(kwargs)
                return SimpleNamespace(
                    execute=lambda: {
                        "items": [
                            {
                                "id": "evt_1",
                                "summary": "Standup",
                                "start": {"dateTime": "2026-04-08T09:00:00"},
                            },
                        ]
                    }
                )

            def get(self, **kwargs):
                get_calls.update(kwargs)
                return SimpleNamespace(
                    execute=lambda: {
                        "id": "evt_2",
                        "summary": "Review",
                        "description": "Weekly review",
                        "start": {"dateTime": "2026-04-08T10:00:00"},
                    }
                )

        class FakeService:
            def events(self):
                return FakeEvents()

        calendar = GoogleCalendarTool(dry_run=False, rate_limit_seconds=0)
        monkeypatch.setattr(calendar, "_get_service", lambda: FakeService())

        created = calendar.execute(
            action="create",
            title="Review",
            date="2026-04-08",
            time="10:00",
            description="Weekly review",
        )
        listed = calendar.execute(action="read")
        loaded = calendar.execute(action="read", event_id="evt_2")

        assert created["status"] == "created"
        assert created["event_id"] == "evt_123"
        assert insert_calls["calendarId"] == "primary"
        assert insert_calls["body"]["summary"] == "Review"
        assert listed["status"] == "ok"
        assert listed["events"][0]["id"] == "evt_1"
        assert list_calls["maxResults"] == 10
        assert loaded["event_id"] == "evt_2"
        assert loaded["description"] == "Weekly review"
        assert get_calls["eventId"] == "evt_2"

    def test_real_execute_unknown_action(self):
        calendar = GoogleCalendarTool(dry_run=False, rate_limit_seconds=0)
        result = calendar._real_execute(action="unknown")
        assert result["status"] == "error"
        assert "Unknown action" in result["message"]

    def test_calendar_get_service_import_error(self, monkeypatch):
        calendar = GoogleCalendarTool(
            credentials_path="creds.json",
            dry_run=False,
            rate_limit_seconds=0,
        )
        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"google.oauth2.credentials", "googleapiclient.discovery"}:
                raise ImportError("missing google libraries")
            return original_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match="google-api-python-client"):
            calendar._get_service()
