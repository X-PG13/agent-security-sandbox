"""Tests for real environment tools (dry_run mode only)."""
from __future__ import annotations

from agent_security_sandbox.tools.real.calendar_tool import GoogleCalendarTool
from agent_security_sandbox.tools.real.email_tool import GmailTool


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
