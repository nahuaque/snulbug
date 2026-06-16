# Tool risk analyzer plugins

Tool risk analyzers classify MCP tools from discovered schemas, live traffic, and
share reports. They power the risk summary in `snulbug mcp share status` and
`snulbug mcp share report`.

Built-ins cover:

- `tool-name`: names and descriptions that imply shell, mutation, network,
  secret, filesystem, or read-only behavior
- `tool-annotations`: MCP annotations such as `destructiveHint`,
  `openWorldHint`, and `readOnlyHint`
- `tool-schema-arguments`: path-like, URL-like, command-like, or secret-like
  input arguments
- `tool-schema-shape`: open object schemas that allow undeclared arguments
- `tool-schema-drift`: multiple observed schema variants for the same tool

External analyzers can add product-specific risk categories and policy advice:

```python
from collections.abc import Mapping, Sequence
from typing import Any

from snulbug import (
    ToolRiskAnalyzer,
    ToolRiskContext,
    ToolRiskFinding,
    ToolRiskSignal,
    register_tool_risk_analyzer,
)


class DeployToolRiskAnalyzer(ToolRiskAnalyzer):
    name = "deploy-tools"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        if context.name.startswith("deploy."):
            return (
                ToolRiskFinding(
                    ToolRiskSignal("deploy.tool", "high", "tool can deploy application changes"),
                    "deploy",
                ),
            )
        return ()

    def suggest_policy(
        self,
        context: ToolRiskContext,
        risk: Mapping[str, Any],
    ) -> Sequence[Mapping[str, Any]]:
        if "deploy" not in risk.get("categories", ()):
            return ()
        return (
            {
                "action": "confirm",
                "reason_code": "tool.deploy.confirm_required",
                "tool": context.name,
            },
        )

    def suggest_lease(
        self,
        context: ToolRiskContext,
        risk: Mapping[str, Any],
    ) -> Sequence[Mapping[str, Any]]:
        if "deploy" not in risk.get("categories", ()):
            return ()
        return ({"confirm_tools": [context.name], "ttl_seconds": 600},)


register_tool_risk_analyzer(DeployToolRiskAnalyzer(), replace=True)
```

`analyze()` receives a `ToolRiskContext` containing secret-safe schema metadata:

- `name`, `description`, `annotations`, and `input_schema`
- observation `count`
- schema catalog provenance such as `schema_hash`, `catalog_paths`, and
  `schema_variants`
- evidence metadata such as `evidence_sources` and `confidence`

Return `ToolRiskFinding` values. Each finding has a `ToolRiskSignal` with:

- `code`: stable, reviewable reason code
- `severity`: `low`, `medium`, or `high`
- `reason`: human-readable explanation
- `category`: grouping used in reports

`suggest_policy()` and `suggest_lease()` are optional advisor hooks. They let an
analyzer recommend policy actions or short-lived lease shapes without changing
the policy engine itself. Keep these outputs secret-safe because they appear in
share status/report artifacts.
