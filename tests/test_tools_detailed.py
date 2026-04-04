"""Detailed tests for the tool system -- registry, schemas, risk filtering."""
import textwrap

import pytest

from agent_security_sandbox.tools.base import (
    RiskLevel,
    create_tool_metadata,
)
from agent_security_sandbox.tools.email import ListEmailsTool, ReadEmailTool, SendEmailTool
from agent_security_sandbox.tools.registry import ToolRegistry
from agent_security_sandbox.tools.search import SearchWebTool

# ---------------------------------------------------------------------------
# ToolRegistry._load_from_config via YAML
# ---------------------------------------------------------------------------

class TestRegistryYamlLoading:
    def test_load_from_custom_config(self, tmp_path):
        yaml_content = textwrap.dedent("""\
            tools:
              - name: read_email
                enabled: false
              - name: send_email
                enabled: true
                parameters:
                  to:
                    whitelist:
                      - "only@allowed.com"
        """)
        cfg = tmp_path / "tools.yaml"
        cfg.write_text(yaml_content)

        reg = ToolRegistry(config_path=str(cfg))
        # read_email should be disabled by config
        assert reg.get_tool("read_email").metadata.enabled is False
        # send_email whitelist should be overridden
        send = reg.get_tool("send_email")
        assert send.metadata.parameters["to"].whitelist == ["only@allowed.com"]

    def test_invalid_config_path_warns(self, tmp_path):
        """Registry should not crash on a bad YAML file."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(":::: not valid yaml ::::")
        # Should not raise
        reg = ToolRegistry(config_path=str(bad_file))
        assert len(reg.tools) > 0  # defaults still registered


# ---------------------------------------------------------------------------
# get_tools_by_risk
# ---------------------------------------------------------------------------

class TestGetToolsByRisk:
    def test_low_only(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        low = reg.get_tools_by_risk("low")
        for tool in low.values():
            assert tool.metadata.risk_level == RiskLevel.LOW

    def test_medium_includes_low(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        med = reg.get_tools_by_risk("medium")
        names = set(med.keys())
        assert "search_web" in names   # LOW
        assert "read_email" in names   # MEDIUM

    def test_high_includes_send_email(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        high = reg.get_tools_by_risk("high")
        assert "send_email" in high

    def test_invalid_risk_raises(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        with pytest.raises(ValueError):
            reg.get_tools_by_risk("unknown_level")


# ---------------------------------------------------------------------------
# get_function_schemas
# ---------------------------------------------------------------------------

class TestGetFunctionSchemas:
    def test_schema_format(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        schemas = reg.get_function_schemas(enabled_only=True)
        assert len(schemas) > 0
        for s in schemas:
            assert "name" in s
            assert "description" in s
            assert "parameters" in s
            assert "properties" in s["parameters"]

    def test_includes_all_when_not_enabled_only(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        # Disable one tool
        reg.get_tool("read_email").metadata.enabled = False
        enabled_schemas = reg.get_function_schemas(enabled_only=True)
        all_schemas = reg.get_function_schemas(enabled_only=False)
        assert len(all_schemas) > len(enabled_schemas)


# ---------------------------------------------------------------------------
# ListEmailsTool.execute
# ---------------------------------------------------------------------------

class TestListEmailsTool:
    def test_returns_email_ids(self):
        tool = ListEmailsTool()
        result = tool.execute()
        assert result["status"] == "success"
        assert "email_ids" in result["data"]
        assert len(result["data"]["email_ids"]) >= 1

    def test_count_matches(self):
        tool = ListEmailsTool()
        result = tool.execute()
        assert result["data"]["count"] == len(result["data"]["email_ids"])


# ---------------------------------------------------------------------------
# Tool parameter validation
# ---------------------------------------------------------------------------

class TestToolValidation:
    def test_missing_required_param(self):
        tool = ReadEmailTool()
        is_valid, msg = tool.validate_params()  # no email_id
        assert is_valid is False
        assert "email_id" in msg

    def test_whitelist_rejection(self):
        tool = SendEmailTool()
        is_valid, msg = tool.validate_params(
            to="evil@hacker.com", subject="x", body="y"
        )
        assert is_valid is False
        assert "whitelist" in msg

    def test_whitelist_pass(self):
        tool = SendEmailTool()
        is_valid, msg = tool.validate_params(
            to="user@company.com", subject="x", body="y"
        )
        assert is_valid is True
        assert msg == ""

    def test_custom_whitelist(self):
        tool = SendEmailTool(whitelist=["custom@domain.com"])
        is_valid, _ = tool.validate_params(
            to="custom@domain.com", subject="x", body="y"
        )
        assert is_valid is True
        is_valid2, _ = tool.validate_params(
            to="user@company.com", subject="x", body="y"
        )
        assert is_valid2 is False


# ---------------------------------------------------------------------------
# create_tool_metadata helper
# ---------------------------------------------------------------------------

class TestCreateToolMetadata:
    def test_basic(self):
        config = {
            "name": "my_tool",
            "description": "A tool",
            "risk_level": "high",
            "side_effect": True,
            "data_access": "private",
            "parameters": {
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "Search query",
                }
            },
        }
        meta = create_tool_metadata(config)
        assert meta.name == "my_tool"
        assert meta.risk_level == RiskLevel.HIGH
        assert "query" in meta.parameters
        assert meta.parameters["query"].required is True

    def test_with_whitelist(self):
        config = {
            "name": "t",
            "description": "t",
            "risk_level": "low",
            "parameters": {
                "to": {
                    "type": "string",
                    "whitelist": ["a@b.com"],
                }
            },
        }
        meta = create_tool_metadata(config)
        assert meta.parameters["to"].whitelist == ["a@b.com"]


# ---------------------------------------------------------------------------
# Tool string representation
# ---------------------------------------------------------------------------

class TestToolStr:
    def test_str(self):
        tool = SearchWebTool()
        s = str(tool)
        assert "search_web" in s
        assert "LOW" in s


# ---------------------------------------------------------------------------
# ToolRegistry.get_tool_info
# ---------------------------------------------------------------------------

class TestGetToolInfo:
    def test_existing_tool(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        info = reg.get_tool_info("send_email")
        assert info is not None
        assert info["name"] == "send_email"
        assert info["risk_level"] == "high"
        assert "to" in info["parameters"]

    def test_nonexistent_tool(self):
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()
        assert reg.get_tool_info("nonexistent") is None


# ---------------------------------------------------------------------------
# Tool state isolation between ToolRegistry instances
# ---------------------------------------------------------------------------

class TestToolIsolation:
    """Verify that each ToolRegistry gets independent database instances."""

    def test_email_db_isolation(self):
        """Sending an email in registry A must not appear in registry B."""
        reg_a = ToolRegistry.__new__(ToolRegistry)
        reg_a.tools = {}
        reg_a.config_path = None
        reg_a._register_default_tools()

        reg_b = ToolRegistry.__new__(ToolRegistry)
        reg_b.tools = {}
        reg_b.config_path = None
        reg_b._register_default_tools()

        # Send email in registry A
        reg_a.execute_tool(
            "send_email",
            to="user@company.com",
            subject="test",
            body="hello",
        )
        # Registry B should have zero sent emails
        send_b = reg_b.get_tool("send_email")
        assert len(send_b._db.sent_emails) == 0

    def test_file_system_isolation(self):
        """Writing a file in registry A must not be readable in registry B."""
        reg_a = ToolRegistry.__new__(ToolRegistry)
        reg_a.tools = {}
        reg_a.config_path = None
        reg_a._register_default_tools()

        reg_b = ToolRegistry.__new__(ToolRegistry)
        reg_b.tools = {}
        reg_b.config_path = None
        reg_b._register_default_tools()

        # Write file in registry A
        reg_a.execute_tool(
            "write_file",
            file_path="/tmp/leak.txt",
            content="secret",
        )
        # Registry B should not have the file
        result = reg_b.execute_tool("read_file", file_path="/tmp/leak.txt")
        assert result["status"] == "error"

    def test_shared_email_db_within_registry(self):
        """Email tools within the same registry share the same database."""
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()

        read_tool = reg.get_tool("read_email")
        send_tool = reg.get_tool("send_email")
        list_tool = reg.get_tool("list_emails")

        assert read_tool._db is send_tool._db
        assert send_tool._db is list_tool._db

    def test_shared_fs_within_registry(self):
        """File tools within the same registry share the same filesystem."""
        reg = ToolRegistry.__new__(ToolRegistry)
        reg.tools = {}
        reg.config_path = None
        reg._register_default_tools()

        read_tool = reg.get_tool("read_file")
        write_tool = reg.get_tool("write_file")
        create_tool = reg.get_tool("create_document")

        assert read_tool._fs is write_tool._fs
        assert write_tool._fs is create_tool._fs
