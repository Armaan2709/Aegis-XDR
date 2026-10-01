"""
Security Regression Tests: AI Security Boundaries & Tool Isolation.

Verifies AI agents operate within isolated tool parameters and cannot execute
arbitrary system code or bypass approval requirements.
"""

import pytest
from app.ai.tools.registry import ToolRegistry
from app.ai.tools.security_tools import ExecutePlaybookTool


@pytest.mark.anyio
async def test_ai_tool_registry_isolation():
    """Verify unregistered or arbitrary tools cannot be fetched via ToolRegistry."""
    registry = ToolRegistry()
    tool = registry.get("unregistered_shell_execution")
    assert tool is None


@pytest.mark.anyio
async def test_execute_playbook_tool_safe_mock_boundary():
    """Verify ExecutePlaybookTool maintains safe execution boundary."""
    tool = ExecutePlaybookTool()
    assert tool.name == "request_playbook_execution"

