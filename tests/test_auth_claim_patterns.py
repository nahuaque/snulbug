from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from snulbug import load_mcp_proxy_config
from snulbug.mcp_auth import OAuthResourceConfig, evaluate_claim_policy, evaluate_required_claims

EXAMPLE = Path("examples/auth_claim_patterns")


def test_auth_claim_pattern_configs_load():
    configs = {
        "tenant-isolation.toml": "tenant-a-tool-family",
        "group-gated-tools.toml": "platform-dev-git-read",
        "ci-workload-identity.toml": "release-workflow-readonly",
    }

    for filename, expected_rule in configs.items():
        config = load_mcp_proxy_config(EXAMPLE / filename)
        auth = config["auth"]
        rules = auth["claim_policy"]["rules"]

        assert config["policy"] == EXAMPLE / "policy.lua"
        assert auth["mode"] == "oauth-resource"
        assert auth["strip_authorization_upstream"] is True
        assert auth["claim_policy"]["enabled"] is True
        assert auth["claim_policy"]["default_action"] == "deny"
        assert any(rule["id"] == expected_rule for rule in rules)


def test_tenant_claim_pattern_allows_only_matching_tenant_tools():
    auth = _auth_config("tenant-isolation.toml")

    required = evaluate_required_claims(claims={"tenant": "tenant-a"}, config=auth)
    allowed = evaluate_claim_policy(
        claims={"tenant": "tenant-a"},
        body=_tool_call("tenant_a.read_file"),
        config=auth,
    )
    wrong_tenant = evaluate_required_claims(claims={"tenant": "tenant-b"}, config=auth)
    wrong_tool = evaluate_claim_policy(
        claims={"tenant": "tenant-a"},
        body=_tool_call("tenant_b.read_file"),
        config=auth,
    )

    assert required["allowed"] is True
    assert allowed["allowed"] is True
    assert allowed["matched_rule"]["id"] == "tenant-a-tool-family"
    assert wrong_tenant["allowed"] is False
    assert wrong_tenant["reason_code"] == "oauth.required_claims_denied"
    assert wrong_tool["allowed"] is False
    assert wrong_tool["reason_code"] == "oauth.claim_policy_denied"


def test_group_claim_pattern_gates_tool_families_by_group_membership():
    auth = _auth_config("group-gated-tools.toml")

    platform_git = evaluate_claim_policy(
        claims={"groups": ["platform-dev"]},
        body=_tool_call("git.status"),
        config=auth,
    )
    reader_git = evaluate_claim_policy(
        claims={"groups": ["mcp-readers"]},
        body=_tool_call("git.status"),
        config=auth,
    )
    admin_filesystem = evaluate_claim_policy(
        claims={"groups": ["mcp-admins"]},
        body=_tool_call("filesystem.write_file"),
        config=auth,
    )

    assert platform_git["allowed"] is True
    assert platform_git["matched_rule"]["id"] == "platform-dev-git-read"
    assert reader_git["allowed"] is False
    assert reader_git["matching_claim_rules"][0]["id"] == "readers-filesystem-read"
    assert admin_filesystem["allowed"] is True
    assert admin_filesystem["matched_tool"] == {"kind": "tool_prefix", "value": "filesystem."}


def test_ci_workload_claim_pattern_uses_required_claims_and_workflow_ref():
    auth = _auth_config("ci-workload-identity.toml")
    claims = {
        "repository": "acme/widget-service",
        "ref": "refs/heads/main",
        "event_name": "workflow_dispatch",
        "job_workflow_ref": "acme/widget-service/.github/workflows/snulbug-demo.yml@refs/heads/main",
    }

    required = evaluate_required_claims(claims=claims, config=auth)
    allowed = evaluate_claim_policy(
        claims=claims,
        body=_tool_call("github.get_file_contents"),
        config=auth,
    )
    wrong_ref = evaluate_required_claims(claims={**claims, "ref": "refs/heads/feature"}, config=auth)
    wrong_tool = evaluate_claim_policy(claims=claims, body=_tool_call("shell.run"), config=auth)

    assert auth.required_scopes == ()
    assert required["allowed"] is True
    assert allowed["allowed"] is True
    assert allowed["matched_rule"]["id"] == "release-workflow-readonly"
    assert wrong_ref["allowed"] is False
    assert wrong_ref["missing"] == {"ref": ["refs/heads/main"]}
    assert wrong_tool["allowed"] is False


def _auth_config(filename: str) -> OAuthResourceConfig:
    auth = load_mcp_proxy_config(EXAMPLE / filename)["auth"]
    return OAuthResourceConfig(
        mode=auth["mode"],
        resource=auth["resource"],
        issuer=auth["issuer"],
        authorization_servers=tuple(auth["authorization_servers"]),
        audience=auth["audience"],
        required_scopes=tuple(auth["required_scopes"]),
        scopes_supported=tuple(auth["scopes_supported"]),
        issuer_discovery=auth["issuer_discovery"],
        token_validation=auth["token_validation"],
        strip_authorization_upstream=auth["strip_authorization_upstream"],
        scope_map={scope: tuple(selectors) for scope, selectors in auth["scope_map"].items()},
        claim_policy=auth["claim_policy"],
        required_claims={claim: tuple(values) for claim, values in auth["required_claims"].items()},
    )


def _tool_call(name: str, arguments: dict[str, Any] | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "test",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    ).encode("utf-8")
