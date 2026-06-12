from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

PRESET_GROUP = "mcp"
PRESET_SUFFIX = ".asgi-lua"
DEFAULT_TOKEN = "local-dev-secret"
DEFAULT_ALLOWED_TOOLS = ["safe_read_file", "list_project_files"]
DEFAULT_ALLOWED_PATHS = ["README.md", "docs/", "examples/", "asgi_lua/", "tests/"]
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW = 60


@dataclass(frozen=True)
class McpPolicyOptions:
    token: str | None = None
    token_env: str | None = None
    allowed_tools: list[str] | None = field(default_factory=lambda: list(DEFAULT_ALLOWED_TOOLS))
    allowed_paths: list[str] | None = field(default_factory=lambda: list(DEFAULT_ALLOWED_PATHS))
    rate_limit: int | None = DEFAULT_RATE_LIMIT
    rate_window: int | None = DEFAULT_RATE_WINDOW

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_tools",
            list(self.allowed_tools) if self.allowed_tools else list(DEFAULT_ALLOWED_TOOLS),
        )
        object.__setattr__(
            self,
            "allowed_paths",
            list(self.allowed_paths) if self.allowed_paths else list(DEFAULT_ALLOWED_PATHS),
        )
        object.__setattr__(self, "rate_limit", self.rate_limit or DEFAULT_RATE_LIMIT)
        object.__setattr__(self, "rate_window", self.rate_window or DEFAULT_RATE_WINDOW)
        if self.rate_limit <= 0:
            raise ValueError("rate_limit must be positive")
        if self.rate_window <= 0:
            raise ValueError("rate_window must be positive")

    @property
    def customized(self) -> bool:
        return (
            self.token is not None
            or self.token_env is not None
            or self.allowed_tools != DEFAULT_ALLOWED_TOOLS
            or self.allowed_paths != DEFAULT_ALLOWED_PATHS
            or self.rate_limit != DEFAULT_RATE_LIMIT
            or self.rate_window != DEFAULT_RATE_WINDOW
        )


def list_builtin_presets() -> list[dict[str, Any]]:
    """Return bundled policy presets that can be copied into a project."""

    presets = []
    for preset in _preset_root().iterdir():
        if not preset.is_dir() or not preset.name.endswith(PRESET_SUFFIX):
            continue
        manifest = _read_resource_json(preset.joinpath("manifest.json"))
        presets.append(
            {
                "preset": preset.name.removesuffix(PRESET_SUFFIX),
                "name": manifest.get("name"),
                "version": manifest.get("version"),
                "description": manifest.get("description", ""),
                "required_capabilities": manifest.get("required_capabilities", []),
                "risk_profile": manifest.get("risk_profile"),
            }
        )
    return sorted(presets, key=lambda item: str(item["preset"]))


def copy_builtin_preset(preset: str, output: str | Path, *, force: bool = False) -> dict[str, Any]:
    """Copy a bundled preset policy bundle to a local directory."""

    source = _preset_path(preset)
    destination = Path(output)
    if destination.exists() and not force:
        raise FileExistsError(f"output path already exists: {destination}")
    if destination.exists() and force:
        shutil.rmtree(destination)
    _copy_tree(source, destination)
    manifest = _read_json_file(destination / "manifest.json")
    return {
        "ok": True,
        "preset": preset,
        "output": str(destination),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "description": manifest.get("description", ""),
    }


def generate_mcp_preset(
    preset: str,
    output: str | Path,
    *,
    options: McpPolicyOptions | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Copy a bundled MCP preset and optionally render policy values."""

    policy_options = options or McpPolicyOptions()
    result = copy_builtin_preset(preset, output, force=force)
    destination = Path(output)
    if policy_options.customized:
        _render_policy(destination, preset.removesuffix(PRESET_SUFFIX), policy_options)
        result["generated"] = True
        result["options"] = {
            "token": policy_options.token,
            "token_env": policy_options.token_env,
            "allowed_tools": policy_options.allowed_tools,
            "allowed_paths": policy_options.allowed_paths,
            "rate_limit": policy_options.rate_limit,
            "rate_window": policy_options.rate_window,
        }
    else:
        result["generated"] = False
    return result


def _preset_root() -> Any:
    return resources.files("asgi_lua").joinpath("builtin_presets", PRESET_GROUP)


def _preset_path(preset: str) -> Any:
    normalized = preset.removesuffix(PRESET_SUFFIX)
    source = _preset_root().joinpath(f"{normalized}{PRESET_SUFFIX}")
    if not source.is_dir():
        known = ", ".join(item["preset"] for item in list_builtin_presets())
        raise KeyError(f"unknown MCP preset {preset!r}; available presets: {known}")
    return source


def _copy_tree(source: Any, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir():
            _copy_tree(child, target)
        else:
            with child.open("rb") as source_file, target.open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file)


def _render_policy(root: Path, preset: str, options: McpPolicyOptions) -> None:
    if preset == "auth-required":
        policy = _auth_required_policy(options)
    elif preset == "tool-allowlist":
        policy = _tool_allowlist_policy(options)
    elif preset == "local-dev-safe":
        policy = _local_dev_safe_policy(options)
    elif preset == "read-only-local-dev":
        policy = _read_only_local_dev_policy(options)
    elif preset == "no-shell-tools":
        policy = _no_shell_tools_policy(options)
    elif preset == "project-path-allowlist":
        policy = _project_path_allowlist_policy(options)
    elif preset == "tunnel-safe":
        policy = _tunnel_safe_policy(options)
    else:
        raise ValueError(f"preset {preset!r} does not support generation")

    (root / "policy.lua").write_text(policy, encoding="utf-8")
    _write_generated_readme(root, preset, options)
    _rewrite_fixtures(root, options)
    _rewrite_manifest(root, options)


def _auth_required_policy(options: McpPolicyOptions) -> str:
    return f"""return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  return {{
    action = "continue",
    reason = "MCP bearer token accepted",
    reason_code = "mcp.authenticated",
    context = {{
      policy = "mcp-auth-required"
    }}
  }}
end
"""


def _tool_allowlist_policy(options: McpPolicyOptions) -> str:
    return f"""local allowed_tools = {{
{_lua_tool_lines(options.allowed_tools)}
}}

return function(request, context, state)
  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {{
    action = "continue",
    reason = "MCP tool is allowed",
    reason_code = "mcp.tool_allowed",
    context = {{
      policy = "mcp-tool-allowlist",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""


def _local_dev_safe_policy(options: McpPolicyOptions) -> str:
    return f"""local allowed_tools = {{
{_lua_tool_lines(options.allowed_tools)}
}}

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {{
    action = "rate_limit",
    key = "mcp:token:" .. token,
    limit = {options.rate_limit},
    window = {options.rate_window},
    body = "too many MCP calls",
    reason = "MCP request is subject to the local fixed-window rate limit",
    reason_code = "mcp.rate_limit",
    context = {{
      policy = "mcp-local-dev-safe",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""


def _read_only_local_dev_policy(options: McpPolicyOptions) -> str:
    return f"""local allowed_tools = {{
{_lua_tool_lines(options.allowed_tools)}
}}

local read_methods = {{
  ["initialize"] = true,
  ["notifications/initialized"] = true,
  ["tools/list"] = true,
  ["tools/call"] = true,
  ["resources/list"] = true,
  ["resources/read"] = true,
  ["prompts/list"] = true,
  ["prompts/get"] = true,
}}

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  local method = mcp.method(request)
  if method == nil then
    return {{
      action = "reject",
      status = 400,
      body = "invalid MCP JSON-RPC request",
      reason = "MCP request body is not a JSON-RPC object with a method",
      reason_code = "mcp.invalid_json"
    }}
  end

  if read_methods[method] ~= true then
    return {{
      action = "reject",
      status = 403,
      body = "MCP method is not allowed by read-only profile: " .. method,
      reason = "MCP method is outside the read-only local-dev profile",
      reason_code = "mcp.method_not_read_only"
    }}
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {{
    action = "rate_limit",
    key = "mcp:read-only:" .. token,
    limit = {options.rate_limit},
    window = {options.rate_window},
    body = "too many MCP calls",
    reason = "MCP request is allowed by the read-only local-dev profile",
    reason_code = "mcp.read_only_allowed",
    context = {{
      policy = "mcp-read-only-local-dev",
      method = method,
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""


def _no_shell_tools_policy(options: McpPolicyOptions) -> str:
    return f"""local dangerous_terms = {{
  "shell",
  "exec",
  "command",
  "terminal",
  "subprocess",
  "bash",
  "zsh",
  "powershell",
  "cmd",
  "spawn",
  "system",
}}

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  local tool = mcp.tool_name(request)
  if tool ~= nil then
    local lower_tool = string.lower(tool)
    for _, term in ipairs(dangerous_terms) do
      if string.find(lower_tool, term, 1, true) ~= nil then
        return {{
          action = "reject",
          status = 403,
          body = "MCP shell-like tool blocked: " .. tool,
          reason = "MCP tool name matches a shell or process execution denylist",
          reason_code = "mcp.shell_tool_blocked"
        }}
      end
    end
  end

  return {{
    action = "continue",
    reason = "MCP request passed the no-shell-tools profile",
    reason_code = "mcp.no_shell_allowed",
    context = {{
      policy = "mcp-no-shell-tools",
      method = mcp.method(request) or "",
      tool = tool or ""
    }}
  }}
end
"""


def _project_path_allowlist_policy(options: McpPolicyOptions) -> str:
    return f"""local allowed_tools = {{
{_lua_tool_lines(options.allowed_tools)}
}}

local allowed_paths = {{
{_lua_path_lines(options.allowed_paths)}
}}

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function path_is_allowed(path)
  if type(path) ~= "string" or path == "" then
    return false
  end
  if string.sub(path, 1, 1) == "/" or string.sub(path, 1, 1) == "~" then
    return false
  end
  if string.match(path, "^%a:") ~= nil then
    return false
  end
  if path == ".." or starts_with(path, "../") then
    return false
  end
  if string.find(path, "/../", 1, true) ~= nil or string.sub(path, -3) == "/.." then
    return false
  end
  for _, allowed in ipairs(allowed_paths) do
    if path == allowed or starts_with(path, allowed) then
      return true
    end
  end
  return false
end

local function reject_path(path)
  return {{
    action = "reject",
    status = 403,
    body = "MCP path not allowed: " .. tostring(path),
    reason = "MCP tool argument path is outside the project path allowlist",
    reason_code = "mcp.path_not_allowed"
  }}
end

local function check_path_value(value)
  if type(value) == "string" then
    if not path_is_allowed(value) then
      return reject_path(value)
    end
  elseif type(value) == "table" then
    for _, item in ipairs(value) do
      if type(item) == "string" and not path_is_allowed(item) then
        return reject_path(item)
      end
    end
  end
  return nil
end

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  local params = mcp.params(request)
  local arguments = params.arguments
  if type(arguments) == "table" then
    local path_block = check_path_value(arguments.path)
    if path_block ~= nil then
      return path_block
    end
    path_block = check_path_value(arguments.paths)
    if path_block ~= nil then
      return path_block
    end
  end

  return {{
    action = "continue",
    reason = "MCP request paths are within the project allowlist",
    reason_code = "mcp.path_allowed",
    context = {{
      policy = "mcp-project-path-allowlist",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""


def _tunnel_safe_policy(options: McpPolicyOptions) -> str:
    return f"""local allowed_tools = {{
{_lua_tool_lines(options.allowed_tools)}
}}

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }}
  end

  local body = mcp.body(request)
  if type(body) ~= "table" then
    return {{
      action = "reject",
      status = 400,
      body = "invalid MCP JSON-RPC request",
      reason = "MCP request body is not a JSON-RPC object",
      reason_code = "mcp.invalid_json"
    }}
  end
  if type(body[1]) == "table" then
    return {{
      action = "reject",
      status = 400,
      body = "MCP batch requests are disabled for tunnel-safe profile",
      reason = "Batch JSON-RPC requests are disabled for tunneled local-dev exposure",
      reason_code = "mcp.batch_rejected"
    }}
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {{
    action = "rate_limit",
    key = "mcp:tunnel:" .. token,
    limit = {options.rate_limit},
    window = {options.rate_window},
    body = "too many MCP calls",
    reason = "MCP request is allowed by the tunnel-safe profile",
    reason_code = "mcp.tunnel_safe_rate_limit",
    context = {{
      policy = "mcp-tunnel-safe",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""


def _token_assignment(options: McpPolicyOptions) -> str:
    escaped_token = _lua_escape(options.token or DEFAULT_TOKEN)
    if options.token_env:
        token_key = _lua_identifier(options.token_env)
        return f'  local token = context.{token_key} or "{escaped_token}"'
    return f'  local token = "{escaped_token}"'


def _lua_tool_lines(tools: list[str]) -> str:
    return "\n".join(f'  "{_lua_escape(tool)}",' for tool in tools)


def _lua_path_lines(paths: list[str]) -> str:
    return "\n".join(f'  "{_lua_escape(path)}",' for path in paths)


def _lua_identifier(value: str) -> str:
    normalized = value.lower().replace("-", "_")
    if not normalized.replace("_", "").isalnum() or normalized[0].isdigit():
        raise ValueError("token_env must contain only letters, numbers, underscores, or dashes")
    return normalized


def _lua_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _write_generated_readme(root: Path, preset: str, options: McpPolicyOptions) -> None:
    if options.token_env:
        token_line = f"Token env context key: `{options.token_env}`."
    else:
        token_line = "Token is embedded in `policy.lua`."
    body = f"""# Generated MCP Policy

Generated from `{preset}`.

- {token_line}
- Allowed tools: {", ".join(f"`{tool}`" for tool in options.allowed_tools) or "none"}
- Allowed paths: {", ".join(f"`{path}`" for path in options.allowed_paths) or "none"}
- Rate limit: {options.rate_limit} requests per {options.rate_window} seconds

Validate and test:

```bash
uv run asgi-lua bundle validate .
uv run asgi-lua bundle test .
```
"""
    (root / "README.md").write_text(body, encoding="utf-8")


def _rewrite_fixtures(root: Path, options: McpPolicyOptions) -> None:
    fixtures = root / "fixtures"
    if not fixtures.is_dir():
        return
    safe_tool = options.allowed_tools[0] if options.allowed_tools else "safe_read_file"
    safe_path = options.allowed_paths[0] if options.allowed_paths else "README.md"
    for path in fixtures.glob("*.json"):
        data = _read_json_file(path)
        headers = data.get("headers")
        if isinstance(headers, dict) and "authorization" in headers:
            headers["authorization"] = f"Bearer {options.token or DEFAULT_TOKEN}"
        body = data.get("body")
        if isinstance(body, str) and "safe_read_file" in body:
            body = body.replace("safe_read_file", safe_tool)
        if isinstance(body, str) and "README.md" in body:
            body = body.replace("README.md", safe_path)
        if isinstance(body, str):
            data["body"] = body
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rewrite_manifest(root: Path, options: McpPolicyOptions) -> None:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return
    safe_tool = options.allowed_tools[0] if options.allowed_tools else "safe_read_file"
    manifest = _read_json_file(manifest_path)
    fixtures = manifest.get("fixtures", [])
    if not isinstance(fixtures, list):
        return
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        expect = fixture.get("expect")
        if not isinstance(expect, dict):
            continue
        if expect.get("decision.context.tool") == "safe_read_file":
            expect["decision.context.tool"] = safe_tool
        if expect.get("decision.limit") == DEFAULT_RATE_LIMIT:
            expect["decision.limit"] = options.rate_limit
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_resource_json(path: Any) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"resource JSON must be an object: {path}")
    return value


def _read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"JSON file must be an object: {path}")
    return value
