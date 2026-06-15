from __future__ import annotations

from snulbug.runtime import compile_lua_script


def test_mcp_helpers_read_json_rpc_method_and_tool_name():
    script = compile_lua_script(
        """
        return function(request, context)
          return {
            action = "respond",
            status = 200,
            context = {
              method = mcp.method(request),
              is_call = mcp.is_tool_call(request),
              tool = mcp.tool_name(request),
              path = mcp.params(request).arguments.path
            }
          }
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"README.md"}}}'
            )
        }
    )

    assert decision["context"] == {
        "method": "tools/call",
        "is_call": True,
        "tool": "safe_read_file",
        "path": "README.md",
    }


def test_mcp_allow_tools_returns_nil_for_non_tool_calls():
    script = compile_lua_script(
        """
        return function(request, context)
          local blocked = mcp.allow_tools(request, { "safe_read_file" })
          if blocked ~= nil then
            return blocked
          end
          return { action = "continue", context = { method = mcp.method(request) } }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'})

    assert decision == {"action": "continue", "context": {"method": "tools/list"}}


def test_mcp_allow_tools_rejects_unlisted_tool():
    script = compile_lua_script(
        """
        return function(request, context)
          return mcp.allow_tools(request, { safe_read_file = true }) or { action = "continue" }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "MCP tool not allowed: shell_exec",
        "reason": "MCP tool not allowed: shell_exec",
        "reason_code": "mcp.tool_not_allowed",
    }


def test_mcp_allow_tools_can_override_rejection_reason():
    script = compile_lua_script(
        """
        return function(request, context)
          return mcp.allow_tools(request, { safe_read_file = true }, {
            body = "blocked",
            reason = "Tool is outside this session's allowlist",
            reason_code = "session.tool_blocked"
          }) or { action = "continue" }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "blocked",
        "reason": "Tool is outside this session's allowlist",
        "reason_code": "session.tool_blocked",
    }


def test_mcp_helpers_treat_malformed_body_as_not_mcp():
    script = compile_lua_script(
        """
        return function(request, context)
          return {
            action = "continue",
            context = {
              body_type = type(mcp.body(request)),
              method_type = type(mcp.method(request)),
              tool_type = type(mcp.tool_name(request))
            }
          }
        end
        """
    )

    decision = script.decide({"body": "not json"})

    assert decision == {
        "action": "continue",
        "context": {"body_type": "nil", "method_type": "nil", "tool_type": "nil"},
    }


def test_mcp_call_normalizes_tool_call_arguments():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return decision.respond(200, "ok", {
            context = {
              method = call.method,
              tool = call.tool,
              path = call.args.path,
              write = call.is_write,
              read = call.is_read,
              batch = call.batch,
              invalid = call.invalid
            }
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"docs/api.md"}}}'
            )
        }
    )

    assert decision == {
        "action": "respond",
        "status": 200,
        "body": "ok",
        "context": {
            "method": "tools/call",
            "tool": "safe_read_file",
            "path": "docs/api.md",
            "write": True,
            "read": False,
            "batch": False,
            "invalid": False,
        },
    }


def test_mcp_argument_helpers_read_values_and_sorted_keys():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          local keys = mcp.arg_keys(call)
          return decision.allow("test.args", {
            request_path = mcp.arg(request, "path"),
            call_path = mcp.arg(call, "path"),
            first_key = keys[1],
            second_key = keys[2],
            missing_type = type(mcp.arg(call, "missing"))
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"docs/api.md","encoding":"utf-8"}}}'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.args",
        "context": {
            "request_path": "docs/api.md",
            "call_path": "docs/api.md",
            "first_key": "encoding",
            "second_key": "path",
            "missing_type": "nil",
        },
    }


def test_mcp_call_identifies_batch_requests():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return decision.allow("test.observed", {
            batch = call.batch,
            error = call.error,
            method_type = type(call.method)
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '[{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}},'
                '{"jsonrpc":"2.0","id":"2","method":"prompts/list","params":{}}]'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.observed",
        "context": {
            "batch": True,
            "error": "batch JSON-RPC request",
            "method_type": "nil",
        },
    }


def test_decision_helpers_build_supported_actions():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.reject(451, "blocked by policy", {
            reason_code = "test.blocked",
            context = { source = "decision-helper" }
          })
        end
        """
    )

    decision = script.decide({"body": "{}"})

    assert decision == {
        "action": "reject",
        "status": 451,
        "body": "blocked by policy",
        "reason": "blocked by policy",
        "reason_code": "test.blocked",
        "context": {"source": "decision-helper"},
    }


def test_decision_reject_carries_confirmation_options():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.reject(403, "blocked by policy", {
            confirm = true,
            prompt = "Allow once?",
            remember_key = "tool:shell_exec",
            timeout_seconds = 5,
            reason_code = "test.confirmable"
          })
        end
        """
    )

    decision = script.decide({"body": "{}"})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "blocked by policy",
        "reason": "blocked by policy",
        "reason_code": "test.confirmable",
        "confirm": True,
        "prompt": "Allow once?",
        "remember_key": "tool:shell_exec",
        "timeout_seconds": 5,
    }


def test_access_missing_scope_builder_returns_standard_challenge():
    script = compile_lua_script(
        """
        return function(request, context)
          return access.missing_scope("mcp:tool.git.status")
        end
        """
    )

    decision = script.decide({"body": "{}"})

    assert decision == {
        "action": "challenge",
        "status": 401,
        "body": "insufficient scope",
        "error": "insufficient_scope",
        "reason": "insufficient scope",
        "reason_code": "oauth.missing_scope",
        "context": {
            "missing_scope": "mcp:tool.git.status",
            "required_scope": "mcp:tool.git.status",
        },
    }


def test_access_wrong_tenant_and_group_builders_include_current_auth_context():
    script = compile_lua_script(
        """
        return function(request, context)
          return access.wrong_tenant("tenant-a", {
            context = { policy = "tenant-fence" }
          })
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {"auth": {"enabled": True, "tenant": "tenant-b", "groups": ["contractor"]}},
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "tenant not allowed",
        "reason": "tenant not allowed",
        "reason_code": "oauth.tenant_denied",
        "context": {
            "tenant": "tenant-b",
            "required_tenant": "tenant-a",
            "policy": "tenant-fence",
        },
    }


def test_access_wrong_group_builder_uses_standard_reason_code():
    script = compile_lua_script(
        """
        return function(request, context)
          return access.wrong_group({ "platform-dev", "mcp-admins" })
        end
        """
    )

    decision = script.decide({"body": "{}"}, {"auth": {"enabled": True, "groups": ["contractor"]}})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "group not allowed",
        "reason": "group not allowed",
        "reason_code": "oauth.group_denied",
        "context": {
            "groups": ["contractor"],
            "required_group": ["platform-dev", "mcp-admins"],
        },
    }


def test_access_expired_lease_builder_returns_standard_lease_context():
    script = compile_lua_script(
        """
        return function(request, context)
          return access.expired_lease()
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {
            "lease": {
                "id": "lease_123",
                "task": "Inspect git status",
                "required": True,
                "reason_code": "lease.expired",
                "expires_at": "2026-06-14T12:00:00+00:00",
            }
        },
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "task lease expired",
        "reason": "task lease expired",
        "reason_code": "lease.expired",
        "context": {
            "lease_id": "lease_123",
            "lease_task": "Inspect git status",
            "lease_required": True,
            "lease_reason_code": "lease.expired",
            "lease_expires_at": "2026-06-14T12:00:00+00:00",
        },
    }


def test_share_helpers_expose_contract_binding_context():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.allow("test.share_context", {
            bound = share.bound(),
            required = share.required(),
            signed = share.signed(),
            verified = share.verified(),
            runtime_status = share.runtime_status(),
            digest = share.contract_digest(),
            binding_digest = share.binding_digest(),
            document_digest = share.document_digest(),
            key_id = share.key_id()
          })
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {
            "share": {
                "contract_digest": "sha256:binding",
                "contract_binding_digest": "sha256:binding",
                "contract_document_digest": "sha256:document",
                "contract_key_id": "local-review",
                "contract_required": True,
                "contract_signed": True,
                "contract_verified": True,
                "contract_runtime_status": "bound",
            }
        },
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.share_context",
        "context": {
            "bound": True,
            "required": True,
            "signed": True,
            "verified": True,
            "runtime_status": "bound",
            "digest": "sha256:binding",
            "binding_digest": "sha256:binding",
            "document_digest": "sha256:document",
            "key_id": "local-review",
        },
    }


def test_share_require_contract_bound_returns_standard_rejection_when_missing():
    script = compile_lua_script(
        """
        return function(request, context)
          return share.require_contract_bound()
            or decision.allow("test.share_bound", {
              digest = share.contract_digest()
            })
        end
        """
    )

    missing = script.decide({"body": "{}"})
    bound = script.decide(
        {"body": "{}"},
        {
            "share": {
                "contract_digest": "sha256:binding",
                "contract_runtime_status": "bound",
            }
        },
    )

    assert missing == {
        "action": "reject",
        "status": 403,
        "body": "approved share contract required",
        "reason": "approved share contract required",
        "reason_code": "share.contract_required",
        "context": {},
    }
    assert bound == {
        "action": "continue",
        "reason_code": "test.share_bound",
        "context": {"digest": "sha256:binding"},
    }


def test_share_contract_digest_and_key_id_guards_return_standard_mismatches():
    script = compile_lua_script(
        """
        return function(request, context)
          return share.require_contract_digest("sha256:expected")
            or share.require_contract_key_id("local-review")
            or decision.allow("test.share_contract_allowed")
        end
        """
    )

    wrong_digest = script.decide(
        {"body": "{}"},
        {
            "share": {
                "contract_digest": "sha256:actual",
                "contract_binding_digest": "sha256:actual",
                "contract_key_id": "local-review",
                "contract_runtime_status": "bound",
            }
        },
    )
    wrong_key = script.decide(
        {"body": "{}"},
        {
            "share": {
                "contract_digest": "sha256:expected",
                "contract_binding_digest": "sha256:expected",
                "contract_key_id": "other-key",
                "contract_runtime_status": "bound",
            }
        },
    )
    allowed = script.decide(
        {"body": "{}"},
        {
            "share": {
                "contract_digest": "sha256:expected",
                "contract_binding_digest": "sha256:expected",
                "contract_key_id": "local-review",
                "contract_runtime_status": "bound",
            }
        },
    )

    assert wrong_digest == {
        "action": "reject",
        "status": 403,
        "body": "share contract mismatch",
        "reason": "share contract mismatch",
        "reason_code": "share.contract_mismatch",
        "context": {
            "contract_digest": "sha256:actual",
            "contract_binding_digest": "sha256:actual",
            "contract_key_id": "local-review",
            "contract_runtime_status": "bound",
            "required_contract_digest": "sha256:expected",
            "actual_contract_digest": "sha256:actual",
            "actual_contract_binding_digest": "sha256:actual",
        },
    }
    assert wrong_key == {
        "action": "reject",
        "status": 403,
        "body": "share contract mismatch",
        "reason": "share contract mismatch",
        "reason_code": "share.contract_mismatch",
        "context": {
            "contract_digest": "sha256:expected",
            "contract_binding_digest": "sha256:expected",
            "contract_key_id": "other-key",
            "contract_runtime_status": "bound",
            "required_contract_key_id": "local-review",
            "actual_contract_key_id": "other-key",
        },
    }
    assert allowed == {"action": "continue", "reason_code": "test.share_contract_allowed"}


def test_access_route_mismatch_builder_returns_standard_access_reason():
    script = compile_lua_script(
        """
        return function(request, context)
          return access.route_mismatch({
            expected_route = "tenant-a",
            actual_route = "tenant-b",
            upstream = "files"
          })
        end
        """
    )

    decision = script.decide({"body": "{}"})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "route not allowed for caller",
        "reason": "route not allowed for caller",
        "reason_code": "access.route_mismatch",
        "context": {
            "expected_route": "tenant-a",
            "actual_route": "tenant-b",
            "upstream": "files",
        },
    }


def test_upstream_helpers_expose_facade_route_context():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.allow("test.upstream_context", {
            matched = upstream.matched(),
            name = upstream.name(),
            transport = upstream.transport(),
            tool_prefix = upstream.tool_prefix(),
            tool = upstream.tool(),
            upstream_tool = upstream.upstream_tool(),
            manifest_identity = upstream.manifest_identity()
          })
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {
            "upstream": {
                "matched": True,
                "name": "git",
                "transport": "http",
                "tool_prefix": "git.",
                "tool": "git.status",
                "upstream_tool": "status",
                "manifest_identity": "git-dev",
            }
        },
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.upstream_context",
        "context": {
            "matched": True,
            "name": "git",
            "transport": "http",
            "tool_prefix": "git.",
            "tool": "git.status",
            "upstream_tool": "status",
            "manifest_identity": "git-dev",
        },
    }


def test_upstream_tenant_issuer_and_profile_guards_use_route_mismatch_builder():
    script = compile_lua_script(
        """
        return function(request, context)
          return upstream.require_for_tenant({
            ["tenant-a"] = { "files" },
            ["tenant-b"] = { "git" }
          }) or upstream.require_for_issuer({
            ["https://issuer.example.test"] = { "files" }
          }) or upstream.require_for_auth_profile({
            ["tenant-a-profile"] = { "files" }
          }) or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {
            "auth": {
                "enabled": True,
                "tenant": "tenant-a",
                "issuer": "https://issuer.example.test",
                "profile_id": "tenant-a-profile",
            },
            "upstream": {
                "matched": True,
                "name": "git",
                "transport": "http",
                "tool_prefix": "git.",
                "tool": "git.status",
                "upstream_tool": "status",
                "route_revision": 7,
            },
        },
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "route not allowed for caller",
        "reason": "route not allowed for caller",
        "reason_code": "access.route_mismatch",
        "context": {
            "upstream": "git",
            "required_upstream": ["files"],
            "tool": "git.status",
            "upstream_tool": "status",
            "tool_prefix": "git.",
            "transport": "http",
            "route_revision": 7,
            "tenant": "tenant-a",
            "issuer": "https://issuer.example.test",
            "profile_id": "tenant-a-profile",
            "policy_dimension": "tenant",
        },
    }


def test_auth_and_lease_guards_delegate_to_standard_access_builders():
    script = compile_lua_script(
        """
        return function(request, context)
          return auth.require_tenant("tenant-a")
            or lease.require()
            or decision.allow("test.allowed")
        end
        """
    )

    tenant_decision = script.decide(
        {"body": "{}"},
        {
            "auth": {"enabled": True, "tenant": "tenant-b"},
            "lease": {"enabled": True, "method": "tools/call", "allowed": False, "reason_code": "lease.expired"},
        },
    )
    lease_decision = script.decide(
        {"body": "{}"},
        {
            "auth": {"enabled": True, "tenant": "tenant-a"},
            "lease": {"enabled": True, "method": "tools/call", "allowed": False, "reason_code": "lease.expired"},
        },
    )

    assert tenant_decision["reason_code"] == "oauth.tenant_denied"
    assert tenant_decision["context"]["tenant"] == "tenant-b"
    assert lease_decision["reason_code"] == "lease.expired"
    assert lease_decision["body"] == "task lease expired"


def test_provider_aware_auth_helpers_read_normalized_claims():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.allow("test.provider_claims", {
            keycloak_realm_admin = auth.keycloak_has_role("realm-admin"),
            keycloak_client_writer = auth.keycloak_has_role("writer", "mcp-client"),
            cloudflare_email = auth.cloudflare_email(),
            cloudflare_subject = auth.cloudflare_subject(),
            cloudflare_validated = auth.cloudflare_jwt_validated(),
            cloudflare_platform = auth.cloudflare_has_group("platform-dev"),
            github_repository = auth.github_repository(),
            github_ref = auth.github_ref(),
            github_match = auth.github_matches({
              repository = "acme/widget",
              ref = { "refs/heads/main", "refs/tags/v1" },
              workflow = "deploy"
            }),
            entra_group = auth.entra_has_group("group-1"),
            entra_role = auth.entra_has_app_role("Files.Read")
          })
        end
        """
    )

    decision = script.decide(
        {"body": "{}"},
        {
            "auth": {
                "provider": {
                    "keycloak": {
                        "realm_roles": ["realm-admin"],
                        "client_roles": {"mcp-client": ["writer"]},
                    },
                    "cloudflare_access": {
                        "email": "dev@example.com",
                        "jwt_validated": True,
                        "jwt_subject": "cf-user-1",
                        "groups": ["platform-dev"],
                    },
                    "github_actions": {
                        "repository": "acme/widget",
                        "workflow": "deploy",
                        "ref": "refs/heads/main",
                    },
                    "entra": {
                        "groups": ["group-1"],
                        "app_roles": ["Files.Read"],
                    },
                }
            }
        },
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.provider_claims",
        "context": {
            "keycloak_realm_admin": True,
            "keycloak_client_writer": True,
            "cloudflare_email": "dev@example.com",
            "cloudflare_subject": "cf-user-1",
            "cloudflare_validated": True,
            "cloudflare_platform": True,
            "github_repository": "acme/widget",
            "github_ref": "refs/heads/main",
            "github_match": True,
            "entra_group": True,
            "entra_role": True,
        },
    }


def test_mcp_allow_tools_carries_confirmation_options():
    script = compile_lua_script(
        """
        return function(request, context)
          return mcp.allow_tools(request, { safe_read_file = true }, {
            confirm = true,
            prompt = "Allow unlisted tool?",
            remember_key = "tool:" .. tostring(mcp.tool_name(request)),
            timeout_seconds = 10,
            reason_code = "test.tool_rejected"
          }) or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "MCP tool not allowed: shell_exec",
        "reason": "MCP tool not allowed: shell_exec",
        "reason_code": "test.tool_rejected",
        "confirm": True,
        "prompt": "Allow unlisted tool?",
        "remember_key": "tool:shell_exec",
        "timeout_seconds": 10,
    }


def test_capability_guards_return_nil_when_all_checks_pass():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.method(request, { "tools/call" })
            or cap.tool(request, { "safe_fetch" })
            or cap.path(call.args.path, { "README.md", "docs" })
            or cap.host(call.args.url, { "api.example.com", "*.trusted.local" })
            or cap.command(call.args.command, { "git" })
            or decision.allow("test.allowed", {
              tool = call.tool,
              path = call.args.path
            })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_fetch","arguments":{'
                '"path":"docs/api.md",'
                '"url":"https://cache.trusted.local/v1",'
                '"command":"git status"}}}'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.allowed",
        "context": {"tool": "safe_fetch", "path": "docs/api.md"},
    }


def test_argument_capability_guards_return_nil_when_all_checks_pass():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.tool(request, { "safe_fetch" })
            or cap.arg_path(call, "path", { "README.md", "docs" })
            or cap.arg_host(request, "url", { "api.example.com", "*.trusted.local" })
            or cap.arg_command(call, "command", { "git" })
            or decision.allow("test.allowed", {
              tool = call.tool,
              path = mcp.arg(call, "path")
            })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_fetch","arguments":{'
                '"path":"docs/api.md",'
                '"url":"https://cache.trusted.local/v1",'
                '"command":"git status"}}}'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.allowed",
        "context": {"tool": "safe_fetch", "path": "docs/api.md"},
    }


def test_argument_capability_guards_reject_missing_argument():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.arg_path(call, "path", { "docs" }, {
            body = "path is required",
            reason_code = "test.path_missing"
          }) or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide(
        {"body": '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"safe_read_file","arguments":{}}}'}
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "path is required",
        "reason": "argument path must be a non-empty string",
        "reason_code": "test.path_missing",
    }


def test_capability_guards_carry_confirmation_options():
    script = compile_lua_script(
        """
        return function(request, context)
          return cap.tool(request, { "safe_read_file" }, {
            confirm = true,
            prompt = "Allow this tool once?",
            remember_key = "tool:" .. tostring(mcp.tool_name(request)),
            timeout_seconds = 15,
            reason_code = "test.tool_guard"
          }) or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "MCP tool not allowed: shell_exec",
        "reason": "MCP tool not allowed: shell_exec",
        "reason_code": "test.tool_guard",
        "confirm": True,
        "prompt": "Allow this tool once?",
        "remember_key": "tool:shell_exec",
        "timeout_seconds": 15,
    }


def test_capability_guards_reject_parent_path_traversal():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.path(call.args.path, { "." })
            or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"../secret.txt"}}}'
            )
        }
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "parent path traversal is not allowed",
        "reason": "parent path traversal is not allowed",
        "reason_code": "mcp.path_traversal",
    }


def test_workspace_require_under_project_allows_relative_project_paths():
    script = compile_lua_script(
        """
        return function(request, context)
          return workspace.require_under_project("path", {
            allowed_paths = { "README.md", "docs/" }
          }) or decision.allow("test.workspace_allowed", {
            values = workspace.path_values("path")
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"docs/api.md"}}}'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.workspace_allowed",
        "context": {"values": ["docs/api.md"]},
    }


def test_workspace_require_under_project_rejects_absolute_and_traversal_paths():
    script = compile_lua_script(
        """
        return function(request, context)
          return workspace.require_under_project("path")
            or decision.allow("test.workspace_allowed")
        end
        """
    )

    traversal = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"../secrets.env"}}}'
            )
        }
    )
    absolute = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"2","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"/tmp/secrets.env"}}}'
            )
        }
    )

    assert traversal["action"] == "reject"
    assert traversal["reason_code"] == "mcp.workspace_path_outside"
    assert traversal["context"]["workspace"] == {
        "argument": "path",
        "path": "../secrets.env",
        "path_class": "outside",
        "write_intent": False,
    }
    assert absolute["action"] == "reject"
    assert absolute["reason_code"] == "mcp.workspace_path_outside"
    assert absolute["context"]["workspace"]["path"] == "/tmp/secrets.env"


def test_workspace_secret_and_generated_path_helpers_block_common_local_dev_risks():
    script = compile_lua_script(
        """
        return function(request, context)
          return workspace.require_under_project({ "path", "target" }, {
            allowed_paths = { "." }
          }) or workspace.block_secret_paths({ "path", "target" })
            or workspace.block_generated_paths({ "path", "target" })
            or decision.allow("test.workspace_allowed")
        end
        """
    )

    secret = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":".env"}}}'
            )
        }
    )
    generated = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"2","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"target":"node_modules/pkg/index.js"}}}'
            )
        }
    )

    assert secret["action"] == "reject"
    assert secret["reason_code"] == "mcp.workspace_secret_blocked"
    assert secret["context"]["workspace"] == {
        "argument": "path",
        "path": ".env",
        "path_class": "secret",
        "write_intent": False,
    }
    assert generated["action"] == "reject"
    assert generated["reason_code"] == "mcp.workspace_generated_path_blocked"
    assert generated["context"]["workspace"] == {
        "argument": "target",
        "path": "node_modules/pkg/index.js",
        "path_class": "generated",
        "write_intent": False,
    }


def test_workspace_block_generated_paths_can_be_limited_to_write_like_tools():
    script = compile_lua_script(
        """
        return function(request, context)
          return workspace.block_generated_paths("path", {
            write_only = true,
            reason_code = "mcp.workspace_generated_write_blocked"
          }) or decision.allow("test.workspace_allowed")
        end
        """
    )

    read = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"dist/app.js"}}}'
            )
        }
    )
    write = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"2","method":"tools/call",'
                '"params":{"name":"write_file","arguments":{"path":"dist/app.js"}}}'
            )
        }
    )

    assert read == {"action": "continue", "reason_code": "test.workspace_allowed"}
    assert write["action"] == "reject"
    assert write["reason_code"] == "mcp.workspace_generated_write_blocked"
    assert write["context"]["workspace"]["write_intent"] is True


def test_workspace_readonly_only_blocks_write_like_tools_and_non_read_methods():
    script = compile_lua_script(
        """
        return function(request, context)
          return workspace.readonly_only()
            or decision.allow("test.readonly_allowed", {
              write_intent = workspace.write_intent()
            })
        end
        """
    )

    read = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"README.md"}}}'
            )
        }
    )
    write_tool = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"2","method":"tools/call",'
                '"params":{"name":"write_file","arguments":{"path":"README.md"}}}'
            )
        }
    )
    write_method = script.decide({"body": '{"jsonrpc":"2.0","id":"3","method":"roots/set","params":{}}'})

    assert read == {
        "action": "continue",
        "reason_code": "test.readonly_allowed",
        "context": {"write_intent": False},
    }
    assert write_tool["action"] == "reject"
    assert write_tool["reason_code"] == "mcp.workspace_readonly_required"
    assert write_tool["context"]["tool"] == "write_file"
    assert write_tool["context"]["workspace"]["write_intent"] is True
    assert write_method["action"] == "reject"
    assert write_method["reason_code"] == "mcp.workspace_readonly_required"
    assert write_method["context"]["method"] == "roots/set"
