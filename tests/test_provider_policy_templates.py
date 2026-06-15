from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from snulbug.runtime import compile_lua_script

EXAMPLE = Path("examples/provider_policy_templates")


def test_keycloak_role_gate_template_allows_admin_and_blocks_missing_reader_role():
    script = _script("keycloak-role-gate.lua")

    allowed = script.decide(
        _tool_call("git.push"),
        {
            "auth": {
                "provider": {
                    "keycloak": {
                        "realm_roles": ["mcp-admin"],
                        "client_roles": {"snulbug-mcp": ["mcp-reader"]},
                    }
                }
            }
        },
    )
    denied = script.decide(
        _tool_call("filesystem.read_file"),
        {"auth": {"provider": {"keycloak": {"realm_roles": [], "client_roles": {}}}}},
    )

    assert allowed["reason_code"] == "auth.keycloak.admin_allowed"
    assert allowed["context"]["tool"] == "git.push"
    assert denied["reason_code"] == "oauth.keycloak_reader_role_required"
    assert denied["context"]["provider"] == "keycloak"


def test_entra_app_role_gate_template_allows_write_role_and_blocks_wrong_tenant():
    script = _script("entra-app-role-gate.lua")
    tenant_id = "00000000-0000-0000-0000-000000000000"

    allowed = script.decide(
        _tool_call("filesystem.write_file"),
        {
            "auth": {
                "provider": {
                    "entra": {
                        "tenant_id": tenant_id,
                        "app_roles": ["Mcp.Tools.Write"],
                    }
                }
            }
        },
    )
    denied = script.decide(
        _tool_call("git.status"),
        {
            "auth": {
                "provider": {
                    "entra": {
                        "tenant_id": "11111111-1111-1111-1111-111111111111",
                        "app_roles": ["Mcp.Tools.Read"],
                    }
                }
            }
        },
    )

    assert allowed["reason_code"] == "auth.entra.write_allowed"
    assert allowed["context"]["tenant_id"] == tenant_id
    assert denied["reason_code"] == "oauth.entra_tenant_denied"
    assert denied["context"]["required_tenant"] == tenant_id


def test_github_actions_workload_gate_template_composes_claims_with_task_lease():
    script = _script("github-actions-workload-gate.lua")
    context = {
        "auth": {
            "subject": "repo:acme/widget-service:ref:refs/heads/main",
            "provider": {
                "github_actions": {
                    "repository": "acme/widget-service",
                    "workflow": "snulbug-demo",
                    "ref": "refs/heads/main",
                    "event_name": "workflow_dispatch",
                    "job_workflow_ref": ("acme/widget-service/.github/workflows/snulbug-demo.yml@refs/heads/main"),
                }
            },
        },
        "lease": {
            "enabled": True,
            "required": True,
            "checked": True,
            "allowed": True,
            "method": "tools/call",
            "id": "lease-1",
            "task": "release metadata read",
        },
    }

    allowed = script.decide(_tool_call("github.get_file_contents"), context)
    wrong_ref = script.decide(
        _tool_call("github.get_file_contents"),
        {
            **context,
            "auth": {
                **context["auth"],
                "provider": {
                    "github_actions": {
                        **context["auth"]["provider"]["github_actions"],
                        "ref": "refs/heads/feature",
                    }
                },
            },
        },
    )
    missing_lease = script.decide(
        _tool_call("github.get_file_contents"),
        {
            **context,
            "lease": {
                "enabled": True,
                "required": True,
                "checked": True,
                "allowed": False,
                "method": "tools/call",
                "reason_code": "lease.missing",
            },
        },
    )

    assert allowed["reason_code"] == "auth.github_actions.workload_allowed"
    assert allowed["context"]["lease_id"] == "lease-1"
    assert wrong_ref["reason_code"] == "oauth.github_workload_denied"
    assert wrong_ref["context"]["required_ref"] == "refs/heads/main"
    assert missing_lease["reason_code"] == "lease.github_workload_required"


def test_cloudflare_access_group_gate_template_requires_valid_assertion_and_group():
    script = _script("cloudflare-access-group-gate.lua")

    allowed = script.decide(
        _tool_call("git.status"),
        {
            "auth": {
                "provider": {
                    "cloudflare_access": {
                        "jwt_validated": True,
                        "jwt_subject": "cf-user-1",
                        "email": "dev@example.com",
                        "groups": ["platform-dev"],
                    }
                }
            }
        },
    )
    unvalidated = script.decide(
        _tool_call("git.status"),
        {
            "auth": {
                "provider": {
                    "cloudflare_access": {
                        "jwt_validated": False,
                        "email": "dev@example.com",
                        "groups": ["platform-dev"],
                    }
                }
            }
        },
    )
    wrong_group = script.decide(
        _tool_call("git.status"),
        {
            "auth": {
                "provider": {
                    "cloudflare_access": {
                        "jwt_validated": True,
                        "jwt_subject": "cf-user-1",
                        "email": "dev@example.com",
                        "groups": ["contractor"],
                    }
                }
            }
        },
    )

    assert allowed["reason_code"] == "auth.cloudflare_access.group_allowed"
    assert allowed["context"]["subject"] == "cf-user-1"
    assert unvalidated["reason_code"] == "cloudflare_access.jwt_validation_required"
    assert wrong_group["reason_code"] == "oauth.cloudflare_access_group_required"


def _script(filename: str):
    return compile_lua_script((EXAMPLE / filename).read_text(encoding="utf-8"))


def _tool_call(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "test",
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments or {},
                },
            }
        )
    }
