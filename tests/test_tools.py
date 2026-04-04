"""Tests for the tool system."""
import pytest

from agent_security_sandbox.tools.base import RiskLevel
from agent_security_sandbox.tools.registry import ToolRegistry


@pytest.fixture
def registry():
    return ToolRegistry()


def test_read_email_success(registry):
    result = registry.execute_tool("read_email", email_id="email_001")
    assert result["status"] == "success"
    assert result["data"]["subject"] == "Q4 Financial Report Request"


def test_read_email_not_found(registry):
    result = registry.execute_tool("read_email", email_id="email_999")
    assert result["status"] == "error"


def test_send_email_whitelist_pass(registry):
    result = registry.execute_tool(
        "send_email", to="user@company.com", subject="Test", body="Hello"
    )
    assert result["status"] == "success"


def test_send_email_whitelist_block(registry):
    result = registry.execute_tool(
        "send_email", to="attacker@evil.com", subject="Test", body="Hello"
    )
    assert result["status"] == "error"
    assert "whitelist" in result["message"]


def test_search_web(registry):
    result = registry.execute_tool("search_web", query="python")
    assert result["status"] == "success"
    assert result["data"]["count"] > 0


def test_read_file_success(registry):
    result = registry.execute_tool("read_file", file_path="/docs/readme.txt")
    assert result["status"] == "success"
    assert "readme" in result["data"]["content"].lower()


def test_read_file_not_found(registry):
    result = registry.execute_tool("read_file", file_path="/nonexistent.txt")
    assert result["status"] == "error"


def test_write_file(registry):
    result = registry.execute_tool(
        "write_file", file_path="/tmp/test.txt", content="test content"
    )
    assert result["status"] == "success"


def test_create_document(registry):
    result = registry.execute_tool(
        "create_document", title="Test Doc", content="Test content"
    )
    assert result["status"] == "success"
    assert result["data"]["title"] == "Test Doc"


def test_tool_risk_levels(registry):
    read_email = registry.get_tool("read_email")
    send_email = registry.get_tool("send_email")
    search_web = registry.get_tool("search_web")

    assert read_email.metadata.risk_level == RiskLevel.MEDIUM
    assert send_email.metadata.risk_level == RiskLevel.HIGH
    assert search_web.metadata.risk_level == RiskLevel.LOW


def test_registry_disabled_tool(registry):
    """Disabled tools should not execute."""
    tool = registry.get_tool("read_email")
    tool.metadata.enabled = False

    result = registry.execute_tool("read_email", email_id="email_001")
    assert result["status"] == "error"
    assert "disabled" in result["message"]

    # Re-enable for other tests
    tool.metadata.enabled = True


def test_registry_unknown_tool(registry):
    result = registry.execute_tool("nonexistent_tool")
    assert result["status"] == "error"
    assert "not found" in result["message"]


def test_list_enabled_tools(registry):
    tools = registry.list_enabled_tools()
    assert "read_email" in tools
    assert "send_email" in tools
    assert "search_web" in tools
