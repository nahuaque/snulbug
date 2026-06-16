from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from snulbug import (
    ToolRiskAnalyzer,
    ToolRiskContext,
    ToolRiskFinding,
    ToolRiskSignal,
    classify_mcp_tool,
    get_tool_risk_analyzer,
    list_tool_risk_analyzers,
    register_tool_risk_analyzer,
)


def test_builtin_tool_risk_analyzers_are_registered():
    analyzers = list_tool_risk_analyzers()

    assert analyzers == (
        "tool-name",
        "tool-annotations",
        "tool-schema-arguments",
        "tool-schema-shape",
        "tool-schema-drift",
    )
    assert get_tool_risk_analyzer("tool-name").normalized_name == "tool-name"


def test_builtin_tool_risk_classification_keeps_share_report_signals():
    result = classify_mcp_tool(
        {
            "name": "shell_exec",
            "description": "Execute a shell command in the workspace",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Shell command"}},
            },
            "annotations": {"destructiveHint": True},
        },
        count=2,
    )

    signal_codes = {signal["code"] for signal in result["signals"]}
    assert result["name"] == "shell_exec"
    assert result["level"] == "high"
    assert result["count"] == 2
    assert "command" in result["categories"]
    assert "tool.shell_or_process" in signal_codes
    assert "argument.command" in signal_codes
    assert "annotation.destructive" in signal_codes
    assert "schema.open_arguments" in signal_codes


def test_external_tool_risk_analyzer_can_add_signals_and_advice():
    class FixtureToolRiskAnalyzer(ToolRiskAnalyzer):
        name = "fixture"

        def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
            if context.name != "fixture_tool":
                return ()
            return (
                ToolRiskFinding(
                    ToolRiskSignal("fixture.risky", "high", "fixture-specific risk signal"),
                    "fixture",
                ),
            )

        def suggest_policy(
            self,
            context: ToolRiskContext,
            risk: Mapping[str, Any],
        ) -> Sequence[Mapping[str, Any]]:
            if context.name != "fixture_tool" or risk.get("level") != "high":
                return ()
            return (
                {
                    "action": "confirm",
                    "reason_code": "fixture.confirm_required",
                    "tool": context.name,
                },
            )

        def suggest_lease(
            self,
            context: ToolRiskContext,
            risk: Mapping[str, Any],
        ) -> Sequence[Mapping[str, Any]]:
            if context.name != "fixture_tool" or risk.get("level") != "high":
                return ()
            return ({"confirm_tools": [context.name], "ttl_seconds": 300},)

    analyzer = FixtureToolRiskAnalyzer()

    assert register_tool_risk_analyzer(analyzer, replace=True) is analyzer
    assert get_tool_risk_analyzer("fixture") is analyzer

    result = classify_mcp_tool(
        {
            "name": "fixture_tool",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        }
    )

    assert result["level"] == "high"
    assert "fixture" in result["categories"]
    assert {"code": "fixture.risky", "severity": "high", "reason": "fixture-specific risk signal"} in result["signals"]
    assert result["advice"]["policy"] == [
        {
            "action": "confirm",
            "reason_code": "fixture.confirm_required",
            "tool": "fixture_tool",
        }
    ]
    assert result["advice"]["lease"] == [{"confirm_tools": ["fixture_tool"], "ttl_seconds": 300}]


def test_duplicate_tool_risk_analyzer_registration_requires_replace():
    class DuplicateToolRiskAnalyzer(ToolRiskAnalyzer):
        name = "tool-name"

    with pytest.raises(ValueError, match="already registered"):
        register_tool_risk_analyzer(DuplicateToolRiskAnalyzer())
