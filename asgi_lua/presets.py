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
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW = 60


@dataclass(frozen=True)
class McpPolicyOptions:
    token: str | None = None
    token_env: str | None = None
    allowed_tools: list[str] | None = field(default_factory=lambda: list(DEFAULT_ALLOWED_TOOLS))
    rate_limit: int | None = DEFAULT_RATE_LIMIT
    rate_window: int | None = DEFAULT_RATE_WINDOW

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_tools",
            list(self.allowed_tools) if self.allowed_tools else list(DEFAULT_ALLOWED_TOOLS),
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
    else:
        raise ValueError(f"preset {preset!r} does not support generation")

    (root / "policy.lua").write_text(policy, encoding="utf-8")
    _write_generated_readme(root, preset, options)
    _rewrite_fixtures(root, options)
    _rewrite_manifest(root, options)


def _auth_required_policy(options: McpPolicyOptions) -> str:
    return f"""return function(request, context, state)
  if request.path ~= "/mcp" then
    return {{ action = "reject", status = 404, body = "unknown MCP endpoint" }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required"
    }}
  end

  return {{
    action = "continue",
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
    return {{ action = "reject", status = 404, body = "unknown MCP endpoint" }}
  end

{_token_assignment(options)}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required"
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
    context = {{
      policy = "mcp-local-dev-safe",
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
    for path in fixtures.glob("*.json"):
        data = _read_json_file(path)
        headers = data.get("headers")
        if isinstance(headers, dict) and "authorization" in headers:
            headers["authorization"] = f"Bearer {options.token or DEFAULT_TOKEN}"
        body = data.get("body")
        if isinstance(body, str) and "safe_read_file" in body:
            data["body"] = body.replace("safe_read_file", safe_tool)
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
