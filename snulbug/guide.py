from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

MCP_GUIDE_WORKFLOWS = ("share", "learn-amend-impact", "leases", "facade")


def build_mcp_guide(*, workflow: str = "all") -> dict[str, Any]:
    """Return agent-readable MCP workflow guidance."""

    workflows = _workflows()
    if workflow == "all":
        selected = list(workflows.values())
    elif workflow in workflows:
        selected = [workflows[workflow]]
    else:
        allowed = ", ".join(("all", *MCP_GUIDE_WORKFLOWS))
        raise ValueError(f"unknown workflow {workflow!r}; expected one of: {allowed}")

    return {
        "ok": True,
        "generated_by": "snulbug mcp guide",
        "recommended_entrypoint": "snulbug mcp guide --compact",
        "default_public_tunnel_profile": "tunnel-safe",
        "workflows": selected,
        "next_steps": [
            "Run `snulbug mcp guide --workflow share` for the highest-level ephemeral sharing workflow.",
            "Run `snulbug mcp guide --workflow learn-amend-impact --compact` when automating policy promotion.",
        ],
    }


def format_mcp_guide(guide: Mapping[str, Any]) -> str:
    """Render guide data as copy-pasteable Markdown."""

    lines = [
        "# snulbug MCP guide",
        "",
        "Use this when wiring snulbug into a local MCP client, public tunnel, or agentic harness.",
        "For machine-readable output, run `snulbug mcp guide --compact`.",
        "",
    ]
    for workflow in guide.get("workflows", []):
        lines.extend(_format_workflow(workflow))
        lines.append("")

    next_steps = guide.get("next_steps", [])
    if next_steps:
        lines.append("## Next steps")
        for step in _strings(next_steps):
            lines.append(f"- {step}")
        lines.append("")

    return "\n".join(lines).rstrip()


def _format_workflow(workflow: Mapping[str, Any]) -> list[str]:
    lines = [
        f"## {workflow['title']}",
        "",
        str(workflow["purpose"]),
        "",
        f"When to use: {workflow['when_to_use']}",
        f"Safety default: {workflow['safety_default']}",
        "",
        "Copy-paste flow:",
        "",
    ]
    for index, step in enumerate(workflow.get("steps", []), start=1):
        lines.append(f"{index}. {step['title']}")
        if step.get("requires"):
            lines.append(f"   Requires: {'; '.join(_strings(step['requires']))}")
        lines.append("")
        lines.append("   ```bash")
        lines.extend(f"   {line}" for line in str(step["command"]).splitlines())
        lines.append("   ```")
        if step.get("produces"):
            lines.append(f"   Produces: {', '.join(_strings(step['produces']))}")
        if step.get("success_signals"):
            lines.append(f"   Success signals: {'; '.join(_strings(step['success_signals']))}")
        if step.get("next"):
            lines.append(f"   Next: {step['next']}")
        lines.append("")

    if workflow.get("stop_conditions"):
        lines.append("Stop conditions:")
        for condition in _strings(workflow["stop_conditions"]):
            lines.append(f"- {condition}")
    return lines


def _workflows() -> dict[str, dict[str, Any]]:
    return {
        "share": {
            "id": "share",
            "title": "Ephemeral MCP Share Session",
            "purpose": (
                "Create one bounded share directory with a tunnel-safe policy, random bearer token, task-scoped "
                "lease, provider setup, MCP client config, audit paths, and close-out commands."
            ),
            "when_to_use": "You want to hand an agent or collaborator temporary access to local MCP tools.",
            "safety_default": (
                "Use a generated bearer token, require a lease for tools/call, and keep the default 30 minute TTL."
            ),
            "steps": [
                {
                    "id": "create-share",
                    "title": "Create the ephemeral share",
                    "command": "\n".join(
                        [
                            "snulbug mcp share create \\",
                            "  --provider holepunch \\",
                            "  --upstream http://127.0.0.1:9000 \\",
                            "  --allow-tool safe_read_file \\",
                            "  --allow-tool list_project_files \\",
                            "  --ttl 30m",
                        ]
                    ),
                    "requires": ["local MCP upstream planned at http://127.0.0.1:9000"],
                    "produces": [
                        ".snulbug/shares/share-*/snulbug.toml",
                        ".snulbug/shares/share-*/share.json",
                        ".snulbug/shares/share-*/mcp-client.json",
                        ".snulbug/shares/share-*/SHARE.md",
                    ],
                    "success_signals": ["generated policy validates", "lease is active", "client config is written"],
                    "next": "Run share run, provider bridge if needed, share doctor, then share client.",
                },
                {
                    "id": "start-share",
                    "title": "Start and verify the share",
                    "command": "\n".join(
                        [
                            "export SNULBUG_SHARE_TOKEN=...",
                            "uv run snulbug mcp share run .snulbug/shares/share-*",
                            "uv run snulbug mcp share doctor .snulbug/shares/share-*",
                            "uv run snulbug mcp share client .snulbug/shares/share-*",
                            "(cd .snulbug/shares/share-*/tunnel && \\",
                            "  hypertele-server -l 8080 --address 127.0.0.1 -c hypertele-server.json --private)",
                        ]
                    ),
                    "requires": ["generated share directory", "local MCP upstream is listening"],
                    "produces": ["live decision console", "redacted replay log", "redacted audit log", "client config"],
                    "success_signals": ["proxy listens locally", "share doctor passes"],
                    "next": "Share mcp-client.json only after share doctor passes.",
                },
                {
                    "id": "close-share",
                    "title": "Close and report when done",
                    "command": "\n".join(
                        [
                            "uv run snulbug mcp share close .snulbug/shares/share-* --report --revoke",
                            "uv run snulbug mcp share status .snulbug/shares/share-*",
                        ]
                    ),
                    "requires": ["share session traffic"],
                    "produces": ["session report", "revoked lease"],
                    "success_signals": ["lease is no longer active", "session report exists"],
                    "next": (
                        "Stop the proxy and provider process, then delete the share directory "
                        "if it is no longer needed."
                    ),
                },
            ],
            "stop_conditions": [
                "Do not share mcp-client.json until share doctor passes.",
                "Do not keep using a share after its task or TTL is no longer appropriate.",
                "Do not expose the upstream MCP server directly.",
            ],
        },
        "learn-amend-impact": {
            "id": "learn-amend-impact",
            "title": "Record, Learn, Amend, and Impact-Check",
            "purpose": (
                "Turn observed local MCP traffic into a least-privilege policy bundle, then preview changes "
                "before promotion."
            ),
            "when_to_use": "You have a representative dev session and want policy changes to be reviewable.",
            "safety_default": (
                "Learn from redacted records, review the generated bundle, and run impact before switching."
            ),
            "steps": [
                {
                    "id": "inspect-session",
                    "title": "Inspect captured traffic",
                    "command": (
                        "snulbug mcp evidence inspect traces/session.jsonl --report-out traces/session-report.md"
                    ),
                    "requires": ["traces/session.jsonl from a proxy or lab run"],
                    "produces": ["traces/session-report.md"],
                    "success_signals": ["report summarizes methods, tools, targets, actions, and reason codes"],
                    "next": "If the session is representative, learn a candidate policy.",
                },
                {
                    "id": "learn-policy",
                    "title": "Learn least privilege from observed traffic",
                    "command": "snulbug mcp policy learn traces/session.jsonl --out learned-policy.snulbug",
                    "requires": ["representative replay or audit log"],
                    "produces": ["learned-policy.snulbug/"],
                    "success_signals": ["learned bundle validates", "learned bundle tests pass"],
                    "next": "Preview the learned policy against the captured session.",
                },
                {
                    "id": "preview-impact",
                    "title": "Preview policy impact before promotion",
                    "command": "\n".join(
                        [
                            "snulbug mcp evidence impact traces/session.jsonl \\",
                            "  --policy learned-policy.snulbug/policy.lua \\",
                            "  --report-out traces/impact-report.md",
                        ]
                    ),
                    "requires": ["learned-policy.snulbug/policy.lua", "traces/session.jsonl"],
                    "produces": ["traces/impact-report.md"],
                    "success_signals": ["no unexpected newly blocked calls"],
                    "next": "Switch snulbug.toml to the learned policy only after review.",
                },
                {
                    "id": "amend-blocked",
                    "title": "Generate a candidate amendment for legitimate blocks",
                    "command": "\n".join(
                        [
                            "snulbug mcp policy amend learned-policy.snulbug traces/audit.jsonl \\",
                            "  --out candidate-policy.snulbug",
                        ]
                    ),
                    "requires": ["audit log containing blocked `mcp.learn.*` decisions"],
                    "produces": ["candidate-policy.snulbug/"],
                    "success_signals": ["candidate contains the smallest observed additions"],
                    "next": "Run `snulbug mcp evidence impact` against the candidate before promoting it.",
                },
            ],
            "stop_conditions": [
                "Do not learn from an unrepresentative session without reviewing the generated policy.",
                "Do not promote a policy when impact reports unexpected newly blocked calls.",
                "Do not amend risky shell-style tools unless the reviewer explicitly accepts that risk.",
            ],
        },
        "leases": {
            "id": "leases",
            "title": "Task-Scoped Capability Lease",
            "purpose": "Grant a temporary tool/path capability for one agent task without broadening the base policy.",
            "when_to_use": "An agent needs a narrow exception for a bounded task.",
            "safety_default": (
                "Short TTLs, explicit tools, explicit paths or hosts, and `lease_required` for tools/call."
            ),
            "steps": [
                {
                    "id": "create-lease",
                    "title": "Create a short-lived lease",
                    "command": "\n".join(
                        [
                            "snulbug mcp share lease create \\",
                            "  --file leases.json \\",
                            '  --task "Read project docs only" \\',
                            "  --allow-tool safe_read_file \\",
                            "  --allow-path README.md \\",
                            "  --ttl 30m \\",
                            "  --max-calls 10",
                        ]
                    ),
                    "requires": ['proxy configured with lease_file = "leases.json"'],
                    "produces": ["lease token for the `x-snulbug-lease` header"],
                    "success_signals": ["lease appears in `snulbug mcp share lease list --active-only`"],
                    "next": "Send the lease token with MCP tools/call requests.",
                },
                {
                    "id": "preview-lease-impact",
                    "title": "Preview lease coverage against a session",
                    "command": "snulbug mcp evidence impact traces/session.jsonl --lease leases.json",
                    "requires": ["traces/session.jsonl", "leases.json"],
                    "produces": ["lease coverage summary"],
                    "success_signals": ["expected calls are covered; unexpected calls remain uncovered"],
                    "next": "Revoke the lease when the task is done.",
                },
                {
                    "id": "revoke-lease",
                    "title": "Revoke a lease",
                    "command": "snulbug mcp share lease revoke LEASE_ID --file leases.json",
                    "requires": ["lease id from create or list output"],
                    "produces": ["updated leases.json"],
                    "success_signals": ["lease no longer appears as active"],
                    "next": "Keep the base policy unchanged unless the permission should become permanent.",
                },
            ],
            "stop_conditions": [
                "Do not create open-ended leases for broad tools.",
                "Do not use a lease as a substitute for reviewing permanent policy amendments.",
            ],
        },
        "facade": {
            "id": "facade",
            "title": "Thin Facade for Multiple Local MCP Servers",
            "purpose": (
                "Expose several local, stdio, or Holepunch-bridged MCP servers through one snulbug URL while "
                "preserving namespaced tool identities for policy, recording, and learning."
            ),
            "when_to_use": "A developer runs multiple local or peer-bridged MCP servers and wants one endpoint.",
            "safety_default": (
                "Namespace upstream tools and learn policies from facade traffic before tunnel or peer-bridge use."
            ),
            "steps": [
                {
                    "id": "run-facade",
                    "title": "Run a two-upstream facade",
                    "command": "\n".join(
                        [
                            "snulbug mcp share config init --output snulbug.toml",
                            "snulbug mcp share run --config snulbug.toml",
                        ]
                    ),
                    "requires": ["files MCP server on port 9001", "git MCP server on port 9002", "policy bundle"],
                    "produces": ["single protected MCP endpoint", "namespaced tools such as files.read and git.status"],
                    "success_signals": ["tools/list returns namespaced tools"],
                    "next": "Learn from the facade session so policies include namespaced tool names.",
                },
                {
                    "id": "learn-facade-policy",
                    "title": "Learn a facade-aware policy",
                    "command": "snulbug mcp policy learn traces/session.jsonl --out learned-facade-policy.snulbug",
                    "requires": ["facade traffic recorded in traces/session.jsonl"],
                    "produces": ["learned-facade-policy.snulbug/"],
                    "success_signals": ["learned tools include upstream namespaces"],
                    "next": "Impact-check before switching the facade proxy to the learned policy.",
                },
            ],
            "stop_conditions": [
                "Do not remove tool namespaces in policy review.",
                "Do not expose facade mode publicly until the policy has been learned, reviewed, and impact-checked.",
            ],
        },
    }


def _strings(values: Iterable[Any]) -> list[str]:
    return [str(value) for value in values]
