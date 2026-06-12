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
    "max_body_bytes": 65536,
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
max_body_bytes = 65536
timeout = 30.0

# Optional MCP facade mode:
# [[mcp.proxy.upstreams]]
# name = "files"
# url = "http://127.0.0.1:9001/mcp"
#
# [[mcp.proxy.upstreams]]
# name = "git"
# url = "http://127.0.0.1:9002/mcp"
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

    for field in ("upstream", "host", "state", "decision_console_format"):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"mcp.proxy.{field} must be a string")
    for field in ("policy", "record_out", "audit_out"):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str | Path):
            raise ValueError(f"mcp.proxy.{field} must be a string path")
    for field in ("port", "max_body_bytes"):
        value = normalized.get(field)
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"mcp.proxy.{field} must be a positive integer")
    if not isinstance(normalized.get("timeout"), int | float) or float(normalized["timeout"]) <= 0:
        raise ValueError("mcp.proxy.timeout must be a positive number")
    for field in ("trace", "redact_records", "decision_console"):
        if not isinstance(normalized.get(field), bool):
            raise ValueError(f"mcp.proxy.{field} must be a boolean")
    if normalized["decision_console_format"] not in {"text", "json"}:
        raise ValueError("mcp.proxy.decision_console_format must be 'text' or 'json'")

    normalized["upstreams"] = _normalize_upstreams(normalized.get("upstreams", []))
    normalized["policy"] = _resolve_path(base, normalized["policy"])
    for field in ("record_out", "audit_out"):
        if normalized.get(field):
            normalized[field] = _resolve_path(base, normalized[field])
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
        url = item.get("url", item.get("upstream"))
        tool_prefix = item.get("tool_prefix", f"{name}.")
        default = bool(item.get("default", False))
        if not isinstance(name, str) or not name:
            raise ValueError(f"mcp.proxy.upstreams[{index}].name must be a non-empty string")
        if not isinstance(url, str) or not url:
            raise ValueError(f"mcp.proxy.upstreams[{index}].url must be a non-empty string")
        if not isinstance(tool_prefix, str) or not tool_prefix:
            raise ValueError(f"mcp.proxy.upstreams[{index}].tool_prefix must be a non-empty string")
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
                "url": url,
                "tool_prefix": tool_prefix,
                "default": default,
            }
        )
    if default_count > 1:
        raise ValueError("only one mcp.proxy.upstreams entry may set default = true")
    return upstreams
