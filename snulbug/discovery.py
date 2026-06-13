from __future__ import annotations

import base64
import http.client
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .fabric_members import DEFAULT_FABRIC_MEMBER_REGISTRY_KEY, load_fabric_member_registry, member_upstreams

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

DiscoveryResolver = Callable[[Mapping[str, Any]], list[Mapping[str, Any]]]

DISCOVERY_PROVIDER_REGISTRY: dict[str, DiscoveryResolver] = {}


def register_discovery_provider(provider_type: str, resolver: DiscoveryResolver) -> None:
    """Register a discovery provider resolver.

    Resolvers receive a normalized provider table and return raw facade upstream
    tables. The normal config loader still validates duplicates, transport
    fields, manifests, and generated bridge arguments after discovery runs.
    """

    if not provider_type or not isinstance(provider_type, str):
        raise ValueError("discovery provider type must be a non-empty string")
    DISCOVERY_PROVIDER_REGISTRY[provider_type] = resolver


def discovery_provider_types() -> tuple[str, ...]:
    return tuple(sorted(DISCOVERY_PROVIDER_REGISTRY))


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
    provider_type = _provider_type_alias(str(provider.get("type", "file")))
    if provider_type not in DISCOVERY_PROVIDER_REGISTRY:
        raise ValueError(
            f"mcp.fabric.discovery.providers[{index}].type must be one of: {', '.join(discovery_provider_types())}"
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
        "base_dir": base_dir,
    }
    for key, value in provider.items():
        if key in {"name", "type", "enabled", "required"}:
            continue
        normalized[str(key)] = _normalize_provider_value(str(key), value, base_dir=base_dir)
    return normalized


def _normalize_provider_value(key: str, value: Any, *, base_dir: Path) -> Any:
    if key in {"path", "source"} and isinstance(value, str):
        return _resolve_path(base_dir, value)
    if key in {"paths", "sources"} and isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_resolve_path(base_dir, str(item)) for item in value]
    if isinstance(value, Mapping):
        return {str(item_key): item_value for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [dict(item) if isinstance(item, Mapping) else item for item in value]
    return value


def _default_provider_name(provider: Mapping[str, Any], provider_type: str) -> str:
    if provider.get("path"):
        return Path(str(provider["path"])).stem
    if provider.get("env"):
        return str(provider["env"]).lower()
    if provider.get("variable"):
        return str(provider["variable"]).lower()
    if provider_type in {
        "docker_compose",
        "kubernetes",
        "tailscale",
        "mdns",
        "codespaces",
        "devcontainer",
        "supervisor",
    }:
        return provider_type
    return "static" if provider_type == "static_toml" else provider_type


def _provider_type_alias(provider_type: str) -> str:
    aliases = {
        "compose": "docker_compose",
        "docker-compose": "docker_compose",
        "docker_compose": "docker_compose",
        "k8s": "kubernetes",
        "dns-sd": "mdns",
        "dns_sd": "mdns",
        "github_codespaces": "codespaces",
        "github-codespaces": "codespaces",
        "process_registry": "supervisor",
        "process-supervisor": "supervisor",
        "process_supervisor": "supervisor",
        "member_registry": "members",
        "remote_members": "members",
        "toml": "static_toml",
    }
    return aliases.get(provider_type, provider_type)


def _resolve_provider(provider: Mapping[str, Any]) -> dict[str, Any]:
    if not provider["enabled"]:
        return {**_provider_base(provider), "status": "disabled", "upstreams": []}
    try:
        upstreams = DISCOVERY_PROVIDER_REGISTRY[str(provider["type"])](provider)
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


def _resolve_file_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    path = _required_path(provider)
    return _extract_upstreams(_load_document(path), source=path)


def _resolve_directory_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    path = _required_path(provider)
    if not path.is_dir():
        raise FileNotFoundError(f"discovery directory not found: {path}")
    glob = str(provider.get("glob", "*.json"))
    upstreams = []
    for item in sorted(path.glob(glob)):
        if not item.is_file():
            continue
        upstreams.extend(_extract_upstreams(_load_document(item), source=item))
    return upstreams


def _resolve_env_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    env = _required_env_name(provider)
    return _extract_upstreams(_load_env_document(env), source=env)


def _resolve_static_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if provider.get("path") is not None:
        return _extract_upstreams(_load_document(_path(provider["path"])), source=_path(provider["path"]))
    upstreams = provider.get("upstreams")
    if not isinstance(upstreams, list):
        raise ValueError("static discovery provider requires an upstreams list")
    return _extract_upstreams(upstreams, source="inline static provider")


def _resolve_docker_compose_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    path = _provider_path_or_default(
        provider,
        defaults=("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"),
    )
    document = _load_document(path)
    services = _mapping(document.get("services"))
    if not services:
        raise ValueError(f"compose discovery document {path} must contain services")
    prefix = str(provider.get("label_prefix", "snulbug.mcp."))
    upstreams = []
    for service_name, service in services.items():
        if not isinstance(service, Mapping):
            continue
        labels = _labels_mapping(service.get("labels"))
        enabled = labels.get(f"{prefix}enabled")
        if enabled is None and provider.get("include_all") is not True:
            continue
        if enabled is not None and not _truthy(enabled):
            continue
        upstream = _upstream_from_metadata(
            labels,
            prefix=prefix,
            default_name=str(service_name),
            default_host=str(service_name),
            default_port=_first_compose_port(service),
        )
        if upstream:
            upstreams.append(upstream)
    return upstreams


def _resolve_kubernetes_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    document = _load_provider_document(provider)
    items = _kubernetes_items(document)
    prefix = str(provider.get("annotation_prefix", "snulbug.dev/mcp-"))
    upstreams = []
    for item in items:
        if not isinstance(item, Mapping) or item.get("kind") != "Service":
            continue
        metadata = _mapping(item.get("metadata"))
        spec = _mapping(item.get("spec"))
        annotations = _string_mapping(metadata.get("annotations"))
        labels = _string_mapping(metadata.get("labels"))
        values = {**labels, **annotations}
        enabled = values.get(f"{prefix}enabled")
        if enabled is None and provider.get("include_all") is not True:
            continue
        if enabled is not None and not _truthy(enabled):
            continue
        service_name = str(metadata.get("name", "service"))
        namespace = str(metadata.get("namespace", provider.get("namespace", "default")))
        default_host = str(provider.get("host_template", "{name}.{namespace}.svc")).format(
            name=service_name,
            namespace=namespace,
        )
        upstream = _upstream_from_metadata(
            values,
            prefix=prefix,
            default_name=service_name,
            default_host=default_host,
            default_port=_first_kubernetes_service_port(spec),
        )
        if upstream:
            upstreams.append(upstream)
    return upstreams


def _resolve_tailscale_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    document = _load_provider_document(provider)
    devices = _tailscale_devices(document)
    tags = _configured_tags(provider, default=("tag:mcp",))
    port = _optional_int(provider.get("port")) or 9000
    path = str(provider.get("path_suffix", provider.get("mcp_path", "/mcp")))
    scheme = str(provider.get("scheme", "http"))
    upstreams = []
    for device in devices:
        device_tags = [str(tag) for tag in device.get("tags", [])]
        if tags and not any(tag in device_tags for tag in tags):
            continue
        host = _tailscale_host(device)
        if not host:
            continue
        name = _safe_name(str(device.get("hostname") or device.get("name") or host).split(".")[0])
        upstreams.append(
            {
                "name": name,
                "url": _build_url(scheme=scheme, host=host, port=port, path=path),
                "tool_prefix": str(device.get("tool_prefix") or f"{name}."),
            }
        )
    return upstreams


def _resolve_mdns_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    records = _mdns_records(provider)
    service_type = str(provider.get("service_type", "_mcp._tcp.local."))
    upstreams = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if record.get("type") and str(record["type"]) != service_type:
            continue
        properties = _string_mapping(record.get("properties", record.get("txt", {})))
        prefix = str(provider.get("txt_prefix", "snulbug.mcp."))
        metadata = {
            **properties,
            **{str(key): value for key, value in record.items() if key not in {"properties", "txt"}},
        }
        upstream = _upstream_from_metadata(
            metadata,
            prefix=prefix,
            default_name=_safe_name(str(record.get("name", "mdns"))),
            default_host=str(record.get("host", record.get("hostname", ""))),
            default_port=_optional_int(record.get("port")),
        )
        if upstream:
            upstreams.append(upstream)
    return upstreams


def _resolve_codespaces_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    document = _optional_provider_document(provider)
    ports = provider.get("ports") or _mapping(document).get("ports")
    if isinstance(ports, Mapping):
        ports = [{"name": name, **(_mapping(value) or {"port": value})} for name, value in ports.items()]
    if not isinstance(ports, list):
        raise ValueError("codespaces discovery provider requires a ports list or mapping")
    codespace_name = str(
        provider.get("codespace_name")
        or _mapping(document).get("codespace_name")
        or os.environ.get("CODESPACE_NAME", "")
    )
    domain = str(
        provider.get("domain")
        or _mapping(document).get("domain")
        or os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "")
    )
    public = bool(provider.get("public", bool(codespace_name and domain)))
    upstreams = []
    for item in ports:
        if not isinstance(item, Mapping):
            continue
        port = _optional_int(item.get("port"))
        if port is None:
            continue
        name = _safe_name(str(item.get("name") or f"port-{port}"))
        path = str(item.get("path", provider.get("path_suffix", "/mcp")))
        if public:
            if not codespace_name or not domain:
                raise FileNotFoundError("codespaces discovery requires CODESPACE_NAME and port forwarding domain")
            url = f"https://{codespace_name}-{port}.{domain}{_normalized_path(path)}"
        else:
            host = str(item.get("host", provider.get("host", "127.0.0.1")))
            url = _build_url(
                scheme=str(item.get("scheme", provider.get("scheme", "http"))),
                host=host,
                port=port,
                path=path,
            )
        upstreams.append({"name": name, "url": url, "tool_prefix": str(item.get("tool_prefix", f"{name}."))})
    return upstreams


def _resolve_devcontainer_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    path = _provider_path_or_default(provider, defaults=(".devcontainer/devcontainer.json", "devcontainer.json"))
    document = _load_document(path)
    customizations = _mapping(_mapping(document).get("customizations"))
    snulbug = _mapping(document.get("snulbug")) or _mapping(customizations.get("snulbug"))
    if snulbug:
        return _extract_upstreams(snulbug, source=path)
    raise ValueError(f"devcontainer discovery document {path} must contain snulbug.upstreams")


def _resolve_supervisor_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    document = _load_provider_document(provider)
    processes = document.get("processes", document.get("services")) if isinstance(document, Mapping) else document
    if not isinstance(processes, list):
        raise ValueError("supervisor discovery document must contain processes or services")
    ready_states = {str(value) for value in _sequence(provider.get("ready_states", ["ready", "running"]))}
    include_unready = provider.get("include_unready") is True
    upstreams = []
    for process in processes:
        if not isinstance(process, Mapping):
            continue
        status = process.get("status", process.get("state", "running"))
        if not include_unready and str(status) not in ready_states:
            continue
        if isinstance(process.get("upstream"), Mapping):
            upstreams.append(dict(process["upstream"]))
            continue
        port = _optional_int(process.get("port"))
        name = process.get("name")
        if port is None or not name:
            continue
        path = str(process.get("path", provider.get("path_suffix", "/mcp")))
        host = str(process.get("host", provider.get("host", "127.0.0.1")))
        scheme = str(process.get("scheme", provider.get("scheme", "http")))
        safe_name = _safe_name(str(name))
        upstreams.append(
            {
                "name": safe_name,
                "url": _build_url(scheme=scheme, host=host, port=port, path=path),
                "tool_prefix": str(process.get("tool_prefix", f"{safe_name}.")),
            }
        )
    return upstreams


def _resolve_members_provider(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    registry_spec = provider.get("registry", provider.get("state", provider.get("path")))
    if registry_spec is None:
        raise FileNotFoundError(f"discovery provider {provider.get('name')} has no path, registry, or state")
    registry_key = str(provider.get("registry_key", provider.get("state_key", DEFAULT_FABRIC_MEMBER_REGISTRY_KEY)))
    registry = load_fabric_member_registry(registry_spec, key=registry_key)
    roles = [str(role).replace("-", "_") for role in _sequence(provider.get("roles", ["data_plane"]))]
    statuses = [str(status).replace("-", "_") for status in _sequence(provider.get("statuses", ["active"]))]
    return member_upstreams(
        registry,
        roles=roles,
        statuses=statuses,
        include_expired=provider.get("include_expired") is True,
        prefix_member_names=provider.get("prefix_member_names", True) is not False,
    )


def _load_provider_document(provider: Mapping[str, Any]) -> Any:
    document = _optional_provider_document(provider)
    if document is not None:
        return document
    raise FileNotFoundError(f"discovery provider {provider.get('name')} has no path, env, api_url, or inline data")


def _optional_provider_document(provider: Mapping[str, Any]) -> Any:
    if provider.get("document") is not None:
        return provider["document"]
    if provider.get("data") is not None:
        return provider["data"]
    if provider.get("records") is not None:
        return {"records": provider["records"]}
    if provider.get("path") is not None:
        return _load_document(_path(provider["path"]))
    env = provider.get("env", provider.get("variable"))
    if env is not None:
        return _load_env_document(str(env))
    if provider.get("api_url") is not None:
        return _load_http_json(provider)
    return None


def _load_env_document(env: str) -> Any:
    value = os.environ.get(env)
    if not value:
        raise FileNotFoundError(f"discovery environment variable is not set: {env}")
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"discovery environment variable {env} must contain JSON: {exc}") from exc


def _load_http_json(provider: Mapping[str, Any]) -> Any:
    url = str(provider["api_url"])
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("discovery api_url must be an absolute http:// or https:// URL")
    headers = {"Accept": "application/json", "User-Agent": "snulbug-discovery"}
    authorization = _authorization_header(provider)
    if authorization:
        headers["Authorization"] = authorization
    connection = _http_connection(parsed, float(provider.get("timeout", 5.0)))
    try:
        target = f"{parsed.path or '/'}?{parsed.query}" if parsed.query else parsed.path or "/"
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        body = response.read()
        if int(response.status) >= 400:
            raise ValueError(f"discovery API returned HTTP {response.status}")
        return json.loads(body.decode("utf-8"))
    finally:
        connection.close()


def _authorization_header(provider: Mapping[str, Any]) -> str | None:
    authorization_env = provider.get("authorization_env")
    if isinstance(authorization_env, str) and os.environ.get(authorization_env):
        return os.environ[authorization_env]
    bearer_token_env = provider.get("bearer_token_env", provider.get("token_env"))
    if isinstance(bearer_token_env, str) and os.environ.get(bearer_token_env):
        return f"Bearer {os.environ[bearer_token_env]}"
    basic_token_env = provider.get("basic_token_env")
    if isinstance(basic_token_env, str) and os.environ.get(basic_token_env):
        token = base64.b64encode(f"{os.environ[basic_token_env]}:".encode("utf-8")).decode("ascii")
        return f"Basic {token}"
    return None


def _load_document(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"discovery file not found: {path}")
    suffix = path.suffix.lower()
    if suffix == ".toml":
        with path.open("rb") as file:
            return tomllib.load(file)
    text = path.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        return _load_yaml(text, source=path)
    if path.name == "devcontainer.json":
        return json.loads(_strip_json_comments(text))
    return json.loads(text)


def _load_yaml(text: str, *, source: str | Path) -> Any:
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        raise ValueError(f"YAML discovery document {source} requires PyYAML or JSON/TOML input") from exc
    return yaml.safe_load(text) or {}


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
    if provider.get("path") is not None:
        return str(provider.get("path"))
    if provider.get("env") is not None:
        return str(provider.get("env"))
    if provider.get("variable") is not None:
        return str(provider.get("variable"))
    if provider.get("api_url") is not None:
        return str(provider.get("api_url"))
    if (
        provider.get("upstreams") is not None
        or provider.get("records") is not None
        or provider.get("ports") is not None
    ):
        return "inline"
    return None


def _upstream_from_metadata(
    metadata: Mapping[str, Any],
    *,
    prefix: str,
    default_name: str,
    default_host: str,
    default_port: int | None,
) -> dict[str, Any]:
    name = _safe_name(str(_meta(metadata, prefix, "name") or default_name))
    transport = _meta(metadata, prefix, "transport")
    url = _meta(metadata, prefix, "url", "upstream")
    port = _optional_int(_meta(metadata, prefix, "port")) or default_port
    path = str(_meta(metadata, prefix, "path") or "/mcp")
    host = str(_meta(metadata, prefix, "host") or default_host)
    scheme = str(_meta(metadata, prefix, "scheme") or "http")
    upstream: dict[str, Any] = {"name": name, "tool_prefix": str(_meta(metadata, prefix, "tool_prefix") or f"{name}.")}
    if transport is not None:
        upstream["transport"] = str(transport)
    if url is not None:
        upstream["url"] = str(url)
    elif port is not None and host:
        upstream["url"] = _build_url(scheme=scheme, host=host, port=port, path=path)
    elif upstream.get("transport") != "stdio":
        return {}

    for field_name in (
        "command",
        "cwd",
        "peer",
        "manifest",
        "manifest_secret_env",
        "manifest_key_id",
        "manifest_identity",
        "bridge_config",
        "bridge_command",
    ):
        value = _meta(metadata, prefix, field_name)
        if value is not None:
            upstream[field_name] = str(value)
    for field_name in ("local_port", "bridge_ready_timeout"):
        value = _optional_int(_meta(metadata, prefix, field_name))
        if value is not None:
            upstream[field_name] = value
    default = _meta(metadata, prefix, "default")
    if default is not None:
        upstream["default"] = _truthy(default)
    return upstream


def _meta(metadata: Mapping[str, Any], prefix: str, field_name: str, alias: str | None = None) -> Any:
    for key in (f"{prefix}{field_name}", f"{prefix}{field_name.replace('_', '-')}", field_name, alias):
        if key and key in metadata:
            return metadata[key]
    return None


def _labels_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        labels = {}
        for item in value:
            key, separator, label_value = str(item).partition("=")
            labels[key] = label_value if separator else "true"
        return labels
    return {}


def _first_compose_port(service: Mapping[str, Any]) -> int | None:
    ports = service.get("ports", [])
    if not isinstance(ports, Sequence) or isinstance(ports, str | bytes | bytearray):
        return None
    for port in ports:
        if isinstance(port, int):
            return port
        if isinstance(port, Mapping):
            value = port.get("target", port.get("published"))
            parsed = _optional_int(value)
            if parsed is not None:
                return parsed
        text = str(port)
        candidate = text.rsplit(":", 1)[-1].split("/", 1)[0]
        parsed = _optional_int(candidate)
        if parsed is not None:
            return parsed
    return None


def _kubernetes_items(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, Mapping) and isinstance(document.get("items"), list):
        return [item for item in document["items"] if isinstance(item, Mapping)]
    if isinstance(document, list):
        return [item for item in document if isinstance(item, Mapping)]
    if isinstance(document, Mapping):
        return [document]
    raise ValueError("kubernetes discovery document must be an object or list")


def _first_kubernetes_service_port(spec: Mapping[str, Any]) -> int | None:
    ports = spec.get("ports", [])
    if not isinstance(ports, Sequence) or isinstance(ports, str | bytes | bytearray):
        return None
    for port in ports:
        if isinstance(port, Mapping):
            parsed = _optional_int(port.get("port", port.get("targetPort")))
            if parsed is not None:
                return parsed
    return None


def _tailscale_devices(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, Mapping) and isinstance(document.get("devices"), list):
        return [_tailscale_device(item) for item in document["devices"] if isinstance(item, Mapping)]
    if isinstance(document, Mapping) and isinstance(document.get("Peer"), Mapping):
        peers = [_tailscale_status_peer(peer) for peer in document["Peer"].values() if isinstance(peer, Mapping)]
        self_peer = _tailscale_status_peer(document["Self"]) if isinstance(document.get("Self"), Mapping) else None
        return ([self_peer] if self_peer else []) + peers
    if isinstance(document, list):
        return [_tailscale_device(item) for item in document if isinstance(item, Mapping)]
    raise ValueError("tailscale discovery document must contain devices, Peer, or a device list")


def _tailscale_device(device: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": device.get("name"),
        "hostname": device.get("hostname") or device.get("hostName"),
        "dns_name": device.get("dnsName") or device.get("DNSName"),
        "addresses": device.get("addresses") or device.get("TailscaleIPs") or device.get("tailscaleIPs") or [],
        "tags": device.get("tags") or device.get("Tags") or [],
    }


def _tailscale_status_peer(peer: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": peer.get("DNSName") or peer.get("HostName"),
        "hostname": peer.get("HostName"),
        "dns_name": peer.get("DNSName"),
        "addresses": peer.get("TailscaleIPs") or [],
        "tags": peer.get("Tags") or [],
    }


def _tailscale_host(device: Mapping[str, Any]) -> str | None:
    dns_name = device.get("dns_name")
    if isinstance(dns_name, str) and dns_name:
        return dns_name.rstrip(".")
    addresses = device.get("addresses")
    if isinstance(addresses, Sequence) and not isinstance(addresses, str | bytes | bytearray) and addresses:
        return str(addresses[0])
    return None


def _mdns_records(provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if provider.get("records") is not None:
        records = provider["records"]
    else:
        document = _load_provider_document(provider)
        records = document.get("records", document.get("services")) if isinstance(document, Mapping) else document
    if not isinstance(records, list):
        raise ValueError("mDNS discovery provider requires records or services")
    return [record for record in records if isinstance(record, Mapping)]


def _configured_tags(provider: Mapping[str, Any], *, default: Sequence[str]) -> list[str]:
    value = provider.get("tags", provider.get("tag", list(default)))
    if isinstance(value, str):
        return [value]
    return [str(item) for item in _sequence(value)]


def _provider_path_or_default(provider: Mapping[str, Any], *, defaults: Sequence[str]) -> Path:
    if provider.get("path") is not None:
        return _path(provider["path"])
    base = _path(provider.get("base_dir", "."))
    for candidate in defaults:
        path = base / candidate
        if path.exists():
            return path
    raise FileNotFoundError(f"none of the discovery files exist: {', '.join(str(base / item) for item in defaults)}")


def _required_path(provider: Mapping[str, Any]) -> Path:
    if provider.get("path") is None:
        raise FileNotFoundError(f"discovery provider {provider.get('name')} requires path")
    return _path(provider["path"])


def _required_env_name(provider: Mapping[str, Any]) -> str:
    env = provider.get("env", provider.get("variable"))
    if not isinstance(env, str) or not env:
        raise FileNotFoundError(f"discovery provider {provider.get('name')} requires env")
    return env


def _path(value: Any) -> Path:
    return value if isinstance(value, Path) else Path(str(value))


def _resolve_path(base_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _build_url(*, scheme: str, host: str, port: int, path: str) -> str:
    return f"{scheme}://{host}:{port}{_normalized_path(path)}"


def _normalized_path(value: str) -> str:
    return value if value.startswith("/") else f"/{value}"


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    if value in (None, ""):
        return []
    return [value]


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "upstream"


def _strip_json_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(^|\s)//.*$", "", text, flags=re.MULTILINE)


def _http_connection(url: SplitResult, timeout: float) -> http.client.HTTPConnection:
    host = url.hostname
    if host is None:
        raise ValueError("discovery API host is required")
    if url.scheme == "https":
        return http.client.HTTPSConnection(host, port=url.port, timeout=timeout)
    return http.client.HTTPConnection(host, port=url.port, timeout=timeout)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


for _provider_type, _resolver in {
    "file": _resolve_file_provider,
    "directory": _resolve_directory_provider,
    "env": _resolve_env_provider,
    "static": _resolve_static_provider,
    "static_toml": _resolve_static_provider,
    "docker_compose": _resolve_docker_compose_provider,
    "kubernetes": _resolve_kubernetes_provider,
    "tailscale": _resolve_tailscale_provider,
    "mdns": _resolve_mdns_provider,
    "codespaces": _resolve_codespaces_provider,
    "devcontainer": _resolve_devcontainer_provider,
    "supervisor": _resolve_supervisor_provider,
    "members": _resolve_members_provider,
}.items():
    register_discovery_provider(_provider_type, _resolver)

DISCOVERY_PROVIDER_TYPES = discovery_provider_types()
