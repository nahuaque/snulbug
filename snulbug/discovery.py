from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

DISCOVERY_PROVIDER_TYPES = ("file", "directory", "env")


def resolve_fabric_discovery(
    fabric_config: Mapping[str, Any],
    *,
    base_dir: str | Path = ".",
    strict: bool = True,
) -> dict[str, Any]:
    """Resolve configured discovery providers into raw facade upstream entries."""

    base = Path(base_dir)
    providers = _normalize_discovery_providers(fabric_config, base_dir=base)
    upstreams: list[dict[str, Any]] = []
    provider_results = []
    errors = []
    for provider in providers:
        result = _resolve_provider(provider)
        provider_results.append(_provider_result_for_output(result))
        upstreams.extend(result.get("upstreams", []))
        if result.get("status") == "error":
            errors.append(
                {
                    "provider": result.get("name"),
                    "type": result.get("type"),
                    "error": result.get("error"),
                }
            )

    if errors and strict:
        error_text = "; ".join(f"{error['provider']}: {error['error']}" for error in errors)
        raise ValueError(f"fabric discovery failed: {error_text}")

    return {
        "ok": not errors,
        "providers": provider_results,
        "upstreams": upstreams,
        "errors": errors,
        "summary": {
            "provider_count": len(providers),
            "enabled_provider_count": sum(1 for provider in providers if provider["enabled"]),
            "upstream_count": len(upstreams),
            "error_count": len(errors),
        },
    }


def apply_fabric_discovery(
    proxy_config: Mapping[str, Any],
    fabric_config: Mapping[str, Any],
    *,
    base_dir: str | Path = ".",
    strict: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Append discovered upstreams to raw proxy config and return discovery metadata."""

    discovery = resolve_fabric_discovery(fabric_config, base_dir=base_dir, strict=strict)
    proxy = dict(proxy_config)
    configured = proxy.get("upstreams")
    if configured in (None, ""):
        upstreams = []
    elif isinstance(configured, list):
        upstreams = list(configured)
    else:
        return proxy, discovery
    upstreams.extend(discovery["upstreams"])
    if upstreams:
        proxy["upstreams"] = upstreams
    return proxy, discovery


def _normalize_discovery_providers(fabric_config: Mapping[str, Any], *, base_dir: Path) -> list[dict[str, Any]]:
    discovery = fabric_config.get("discovery")
    if discovery in (None, ""):
        return []
    if not isinstance(discovery, Mapping):
        raise ValueError("mcp.fabric.discovery must be a table")
    enabled = discovery.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("mcp.fabric.discovery.enabled must be a boolean")
    providers = discovery.get("providers", [])
    if providers in (None, ""):
        return []
    if not isinstance(providers, list):
        raise ValueError("mcp.fabric.discovery.providers must be a list of tables")

    normalized = []
    names = set()
    for index, provider in enumerate(providers):
        if not isinstance(provider, Mapping):
            raise ValueError(f"mcp.fabric.discovery.providers[{index}] must be a table")
        normalized_provider = _normalize_provider(provider, index=index, enabled=enabled, base_dir=base_dir)
        name = normalized_provider["name"]
        if name in names:
            raise ValueError(f"duplicate mcp.fabric.discovery.providers name: {name!r}")
        names.add(name)
        normalized.append(normalized_provider)
    return normalized


def _normalize_provider(
    provider: Mapping[str, Any],
    *,
    index: int,
    enabled: bool,
    base_dir: Path,
) -> dict[str, Any]:
    provider_type = provider.get("type", "file")
    if provider_type not in DISCOVERY_PROVIDER_TYPES:
        raise ValueError(
            f"mcp.fabric.discovery.providers[{index}].type must be one of: {', '.join(DISCOVERY_PROVIDER_TYPES)}"
        )
    name = provider.get("name") or _default_provider_name(provider, provider_type)
    if not isinstance(name, str) or not name:
        raise ValueError(f"mcp.fabric.discovery.providers[{index}].name must be a non-empty string")
    provider_enabled = provider.get("enabled", enabled)
    if not isinstance(provider_enabled, bool):
        raise ValueError(f"mcp.fabric.discovery.providers[{index}].enabled must be a boolean")
    required = provider.get("required", False)
    if not isinstance(required, bool):
        raise ValueError(f"mcp.fabric.discovery.providers[{index}].required must be a boolean")

    normalized: dict[str, Any] = {
        "name": name,
        "type": provider_type,
        "enabled": provider_enabled,
        "required": required,
    }
    if provider_type in {"file", "directory"}:
        path = provider.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError(f"mcp.fabric.discovery.providers[{index}].path must be a non-empty string")
        normalized["path"] = _resolve_path(base_dir, path)
    if provider_type == "directory":
        glob = provider.get("glob", "*.json")
        if not isinstance(glob, str) or not glob:
            raise ValueError(f"mcp.fabric.discovery.providers[{index}].glob must be a non-empty string")
        normalized["glob"] = glob
    if provider_type == "env":
        env = provider.get("env", provider.get("variable"))
        if not isinstance(env, str) or not env:
            raise ValueError(f"mcp.fabric.discovery.providers[{index}].env must be a non-empty string")
        normalized["env"] = env
    return normalized


def _default_provider_name(provider: Mapping[str, Any], provider_type: str) -> str:
    if provider_type in {"file", "directory"} and provider.get("path"):
        return Path(str(provider["path"])).stem
    if provider_type == "env" and provider.get("env"):
        return str(provider["env"]).lower()
    if provider_type == "env" and provider.get("variable"):
        return str(provider["variable"]).lower()
    return provider_type


def _resolve_provider(provider: Mapping[str, Any]) -> dict[str, Any]:
    if not provider["enabled"]:
        return {**_provider_base(provider), "status": "disabled", "upstreams": []}
    try:
        upstreams = _provider_upstreams(provider)
    except FileNotFoundError as exc:
        if provider["required"]:
            return {**_provider_base(provider), "status": "error", "error": str(exc), "upstreams": []}
        return {**_provider_base(provider), "status": "missing", "error": str(exc), "upstreams": []}
    except Exception as exc:
        return {**_provider_base(provider), "status": "error", "error": str(exc), "upstreams": []}
    return {
        **_provider_base(provider),
        "status": "loaded",
        "upstreams": [_annotate_upstream(upstream, provider) for upstream in upstreams],
    }


def _provider_upstreams(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    provider_type = provider["type"]
    if provider_type == "file":
        path = _path(provider["path"])
        document = _load_document(path)
        return _extract_upstreams(document, source=path)
    if provider_type == "directory":
        path = _path(provider["path"])
        if not path.is_dir():
            raise FileNotFoundError(f"discovery directory not found: {path}")
        upstreams = []
        for item in sorted(path.glob(str(provider.get("glob", "*.json")))):
            if not item.is_file():
                continue
            upstreams.extend(_extract_upstreams(_load_document(item), source=item))
        return upstreams
    if provider_type == "env":
        env = str(provider["env"])
        value = os.environ.get(env)
        if not value:
            raise FileNotFoundError(f"discovery environment variable is not set: {env}")
        try:
            document = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"discovery environment variable {env} must contain JSON: {exc}") from exc
        return _extract_upstreams(document, source=env)
    raise ValueError(f"unsupported discovery provider type: {provider_type}")


def _load_document(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"discovery file not found: {path}")
    if path.suffix == ".toml":
        with path.open("rb") as file:
            return tomllib.load(file)
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _extract_upstreams(document: Any, *, source: str | Path) -> list[Mapping[str, Any]]:
    if isinstance(document, list):
        upstreams = document
    elif isinstance(document, Mapping):
        if isinstance(document.get("upstreams"), list):
            upstreams = document["upstreams"]
        else:
            mcp = document.get("mcp")
            proxy = mcp.get("proxy") if isinstance(mcp, Mapping) else None
            if isinstance(proxy, Mapping) and isinstance(proxy.get("upstreams"), list):
                upstreams = proxy["upstreams"]
            elif isinstance(document.get("name"), str):
                upstreams = [document]
            else:
                raise ValueError(f"discovery document {source} must contain an upstream or upstreams list")
    else:
        raise ValueError(f"discovery document {source} must be a JSON/TOML object or list")

    result = []
    for index, upstream in enumerate(upstreams):
        if not isinstance(upstream, Mapping):
            raise ValueError(f"discovery document {source} upstreams[{index}] must be a table")
        result.append(dict(upstream))
    return result


def _annotate_upstream(upstream: Mapping[str, Any], provider: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(upstream),
        "discovered": True,
        "discovery_provider": provider["name"],
        "discovery_type": provider["type"],
        "discovery_source": _provider_source(provider),
    }


def _provider_base(provider: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": provider["name"],
        "type": provider["type"],
        "enabled": provider["enabled"],
        "required": provider["required"],
        "source": _provider_source(provider),
    }


def _provider_result_for_output(result: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "name": result.get("name"),
            "type": result.get("type"),
            "enabled": result.get("enabled"),
            "required": result.get("required"),
            "source": result.get("source"),
            "status": result.get("status"),
            "upstream_count": len(result.get("upstreams", [])) if isinstance(result.get("upstreams"), list) else 0,
            "error": result.get("error"),
        }
    )


def _provider_source(provider: Mapping[str, Any]) -> str | None:
    if provider["type"] in {"file", "directory"}:
        return str(provider.get("path"))
    if provider["type"] == "env":
        return str(provider.get("env"))
    return None


def _path(value: Any) -> Path:
    return value if isinstance(value, Path) else Path(str(value))


def _resolve_path(base_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}
