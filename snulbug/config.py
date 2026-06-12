from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

DEFAULT_CONFIG_PATH = "snulbug.toml"

DEFAULT_MCP_PROXY_CONFIG = {
    "upstream": "http://127.0.0.1:9000",
    "upstreams": [],
    "policy": "policy.snulbug/policy.lua",
    "host": "127.0.0.1",
    "port": 8080,
    "state": "memory",
    "trace": True,
    "record_out": "traces/session.jsonl",
    "audit_out": "traces/audit.jsonl",
    "redact_records": True,
    "decision_console": False,
    "decision_console_format": "text",
    "confirm": False,
    "max_body_bytes": 65536,
    "response_max_bytes": 262144,
    "response_redact_secrets": True,
    "response_block_instructions": False,
    "tool_pinning": True,
    "tool_pinning_action": "block",
    "schema_validation": True,
    "schema_validation_action": "block",
    "lease_file": "leases.json",
    "lease_required": False,
    "lease_header": "x-snulbug-lease",
    "timeout": 30.0,
}

SAMPLE_CONFIG = """[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
redact_records = true
decision_console = false
decision_console_format = "text"
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
timeout = 30.0

# Optional MCP facade mode:
# [[mcp.proxy.upstreams]]
# name = "files"
# url = "http://127.0.0.1:9001/mcp"
#
# [[mcp.proxy.upstreams]]
# name = "git"
# url = "http://127.0.0.1:9002/mcp"
#
# [[mcp.proxy.upstreams]]
# name = "filesystem"
# transport = "stdio"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
"""


def write_sample_config(path: str | Path = DEFAULT_CONFIG_PATH, *, force: bool = False) -> dict[str, Any]:
    output = Path(path)
    if output.exists() and not force:
        raise FileExistsError(f"config file already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(SAMPLE_CONFIG, encoding="utf-8")
    return {"ok": True, "config": str(output)}


def load_mcp_proxy_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    with config_path.open("rb") as file:
        raw_config = tomllib.load(file)
    if not isinstance(raw_config, Mapping):
        raise ValueError("config file must contain a TOML object")
    mcp = raw_config.get("mcp", {})
    if not isinstance(mcp, Mapping):
        raise ValueError("config section [mcp] must be a table")
    proxy = mcp.get("proxy", {})
    if not isinstance(proxy, Mapping):
        raise ValueError("config section [mcp.proxy] must be a table")
    return normalize_mcp_proxy_config(proxy, base_dir=config_path.parent)


def normalize_mcp_proxy_config(config: Mapping[str, Any], *, base_dir: str | Path = ".") -> dict[str, Any]:
    normalized = dict(DEFAULT_MCP_PROXY_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})
    base = Path(base_dir)

    for field in (
        "upstream",
        "host",
        "state",
        "decision_console_format",
        "tool_pinning_action",
        "schema_validation_action",
        "lease_header",
    ):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"mcp.proxy.{field} must be a string")
    for field in ("policy", "record_out", "audit_out", "lease_file"):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str | Path):
            raise ValueError(f"mcp.proxy.{field} must be a string path")
    for field in ("port", "max_body_bytes", "response_max_bytes"):
        value = normalized.get(field)
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"mcp.proxy.{field} must be a positive integer")
    if not isinstance(normalized.get("timeout"), int | float) or float(normalized["timeout"]) <= 0:
        raise ValueError("mcp.proxy.timeout must be a positive number")
    for field in (
        "trace",
        "redact_records",
        "decision_console",
        "confirm",
        "response_redact_secrets",
        "response_block_instructions",
        "tool_pinning",
        "schema_validation",
        "lease_required",
    ):
        if not isinstance(normalized.get(field), bool):
            raise ValueError(f"mcp.proxy.{field} must be a boolean")
    if normalized["decision_console_format"] not in {"text", "json"}:
        raise ValueError("mcp.proxy.decision_console_format must be 'text' or 'json'")
    if normalized["tool_pinning_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.tool_pinning_action must be 'warn' or 'block'")
    if normalized["schema_validation_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.schema_validation_action must be 'warn' or 'block'")

    normalized["upstreams"] = _normalize_upstreams(normalized.get("upstreams", []))
    normalized["policy"] = _resolve_path(base, normalized["policy"])
    for field in ("record_out", "audit_out"):
        if normalized.get(field):
            normalized[field] = _resolve_path(base, normalized[field])
    if normalized.get("lease_file"):
        normalized["lease_file"] = _resolve_path(base, normalized["lease_file"])
    normalized["timeout"] = float(normalized["timeout"])
    return normalized


def merge_mcp_proxy_config(config: Mapping[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(config)
    for key, value in overrides.items():
        if value is not None:
            merged[key] = value
    return normalize_mcp_proxy_config(merged)


def _resolve_path(base_dir: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _normalize_upstreams(value: Any) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("mcp.proxy.upstreams must be a list of tables")

    upstreams = []
    names = set()
    prefixes = set()
    default_count = 0
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"mcp.proxy.upstreams[{index}] must be a table")
        name = item.get("name")
        transport = item.get("transport") or ("stdio" if item.get("command") else "http")
        url = item.get("url", item.get("upstream"))
        command = item.get("command")
        args = item.get("args", [])
        cwd = item.get("cwd")
        env = item.get("env")
        tool_prefix = item.get("tool_prefix", f"{name}.")
        default = bool(item.get("default", False))
        if not isinstance(name, str) or not name:
            raise ValueError(f"mcp.proxy.upstreams[{index}].name must be a non-empty string")
        if transport not in {"http", "stdio"}:
            raise ValueError(f"mcp.proxy.upstreams[{index}].transport must be 'http' or 'stdio'")
        if transport == "http" and (not isinstance(url, str) or not url):
            raise ValueError(f"mcp.proxy.upstreams[{index}].url must be a non-empty string")
        if transport == "stdio" and (not isinstance(command, str) or not command):
            raise ValueError(f"mcp.proxy.upstreams[{index}].command must be a non-empty string")
        if not isinstance(tool_prefix, str) or not tool_prefix:
            raise ValueError(f"mcp.proxy.upstreams[{index}].tool_prefix must be a non-empty string")
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f"mcp.proxy.upstreams[{index}].args must be a list of strings")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError(f"mcp.proxy.upstreams[{index}].cwd must be a string")
        if env is not None:
            if not isinstance(env, Mapping):
                raise ValueError(f"mcp.proxy.upstreams[{index}].env must be a table of strings")
            if not all(isinstance(key, str) and isinstance(item_value, str) for key, item_value in env.items()):
                raise ValueError(f"mcp.proxy.upstreams[{index}].env must be a table of strings")
        if name in names:
            raise ValueError(f"duplicate mcp.proxy.upstreams name: {name!r}")
        if tool_prefix in prefixes:
            raise ValueError(f"duplicate mcp.proxy.upstreams tool_prefix: {tool_prefix!r}")
        names.add(name)
        prefixes.add(tool_prefix)
        default_count += int(default)
        upstreams.append(
            {
                "name": name,
                "transport": transport,
                "tool_prefix": tool_prefix,
                "default": default,
                **({"url": url} if transport == "http" else {}),
                **(
                    {
                        "command": command,
                        "args": list(args),
                        **({"cwd": cwd} if cwd is not None else {}),
                        **({"env": dict(env)} if isinstance(env, Mapping) else {}),
                    }
                    if transport == "stdio"
                    else {}
                ),
            }
        )
    if default_count > 1:
        raise ValueError("only one mcp.proxy.upstreams entry may set default = true")
    return upstreams
