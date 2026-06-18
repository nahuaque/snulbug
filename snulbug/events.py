from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from .redaction import redact_secrets

DEFAULT_WEBHOOK_EVENTS = ("snulbug.audit",)
WEBHOOK_USER_AGENT = "snulbug-webhook/0.1"


class EventSink(Protocol):
    def emit(self, event: Mapping[str, Any]) -> None: ...


class EventSinkProvider:
    """Extension point for event sink and observability outputs."""

    type = ""
    aliases: tuple[str, ...] = ()

    @property
    def normalized_type(self) -> str:
        return str(self.type).strip().lower()

    @property
    def names(self) -> tuple[str, ...]:
        return (self.normalized_type, *(str(alias).strip().lower() for alias in self.aliases if str(alias).strip()))

    def normalize_config(
        self,
        item: Mapping[str, Any],
        *,
        sink_type: str,
        index: int,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del sink_type, index, base_dir
        return dict(item)

    def build(self, config: Mapping[str, Any]) -> EventSink:
        raise NotImplementedError(f"event sink provider {self.normalized_type!r} does not build sinks")


class EventDispatcher:
    """Fan out structured snulbug events to configured sinks."""

    def __init__(self, sinks: Sequence[EventSink]) -> None:
        self.sinks = list(sinks)

    def emit(self, event: Mapping[str, Any]) -> None:
        for sink in self.sinks:
            sink.emit(event)

    @property
    def enabled(self) -> bool:
        return bool(self.sinks)


@dataclass(frozen=True)
class JsonlEventSink:
    path: Path
    events: tuple[str, ...] = ("*",)
    enabled: bool = True

    def emit(self, event: Mapping[str, Any]) -> None:
        if not _event_matches(event, self.events, enabled=self.enabled):
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(_jsonish(event), sort_keys=True, separators=(",", ":")))
            file.write("\n")


@dataclass(frozen=True)
class ConsoleEventSink:
    output: TextIO
    output_format: str = "text"
    events: tuple[str, ...] = ("snulbug.audit",)
    enabled: bool = True
    include_internal: bool = False

    def __post_init__(self) -> None:
        if self.output_format not in {"text", "json"}:
            raise ValueError("console event sink format must be 'text' or 'json'")

    def emit(self, event: Mapping[str, Any]) -> None:
        if not _event_matches(event, self.events, enabled=self.enabled):
            return
        if not self.include_internal and _is_internal_probe_event(event):
            return
        if self.output_format == "json":
            line = json.dumps(_jsonish(event), sort_keys=True, separators=(",", ":"))
        else:
            line = format_decision_console_line(event)
        self.output.write(line)
        self.output.write("\n")
        self.output.flush()


@dataclass(frozen=True)
class ForwardEventSink:
    dispatcher: Any
    events: tuple[str, ...] = ("*",)
    enabled: bool = True

    def emit(self, event: Mapping[str, Any]) -> None:
        if _event_matches(event, self.events, enabled=self.enabled):
            self.dispatcher.emit(event)


@dataclass(frozen=True)
class WebhookSink:
    name: str
    url: str | None = None
    url_env: str | None = None
    events: tuple[str, ...] = DEFAULT_WEBHOOK_EVENTS
    body_mode: str = "metadata_only"
    redaction: str = "strict"
    timeout_ms: int = 750
    retry_attempts: int = 3
    signing_secret_env: str | None = None
    enabled: bool = True


@dataclass(frozen=True)
class WebhookDeliveryResult:
    sink: str
    delivered: bool
    skipped: bool = False
    status: int | None = None
    error: str | None = None
    attempts: int = 0


class WebhookEventSink:
    """Fail-open background sink for redacted webhook delivery."""

    def __init__(self, sink: WebhookSink | Mapping[str, Any], *, max_in_flight: int = 64) -> None:
        self.sink = sink if isinstance(sink, WebhookSink) else _normalize_webhook_sink(sink, index=0)
        if max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        self._slots = threading.BoundedSemaphore(max_in_flight)

    def emit(self, event: Mapping[str, Any]) -> None:
        if not _event_matches(event, self.sink.events, enabled=self.sink.enabled):
            return
        if not self._slots.acquire(blocking=False):
            return
        thread = threading.Thread(target=self._deliver_and_release, args=(dict(event),), daemon=True)
        thread.start()

    def _deliver_and_release(self, event: Mapping[str, Any]) -> None:
        try:
            deliver_webhook_event(self.sink, event)
        finally:
            self._slots.release()


class JsonlEventSinkProvider(EventSinkProvider):
    type = "jsonl"
    aliases = ("audit_jsonl", "fabric_jsonl")

    def normalize_config(
        self,
        item: Mapping[str, Any],
        *,
        sink_type: str,
        index: int,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        return _normalize_jsonl_sink(item, sink_type=sink_type, index=index, base_dir=base_dir)

    def build(self, config: Mapping[str, Any]) -> EventSink:
        return JsonlEventSink(
            Path(str(config["path"])),
            events=_string_tuple(config.get("events", ["*"]), field="mcp.events.sinks.events"),
            enabled=bool(config.get("enabled", True)),
        )


class ConsoleEventSinkProvider(EventSinkProvider):
    type = "console"

    def normalize_config(
        self,
        item: Mapping[str, Any],
        *,
        sink_type: str,
        index: int,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del sink_type, base_dir
        return _normalize_console_sink(item, index=index)

    def build(self, config: Mapping[str, Any]) -> EventSink:
        return ConsoleEventSink(
            console_stream(config.get("output", True)) or sys.stderr,
            output_format=str(config.get("format", "text")),
            events=_string_tuple(config.get("events", ["snulbug.audit"]), field="mcp.events.sinks.events"),
            enabled=bool(config.get("enabled", True)),
            include_internal=bool(config.get("include_internal", False)),
        )


class WebhookEventSinkProvider(EventSinkProvider):
    type = "webhook"

    def normalize_config(
        self,
        item: Mapping[str, Any],
        *,
        sink_type: str,
        index: int,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del sink_type, base_dir
        webhook = _normalize_webhook_sink(item, index=index, field_prefix="mcp.events.sinks")
        return {"type": "webhook", "webhook": webhook}

    def build(self, config: Mapping[str, Any]) -> EventSink:
        webhook = config.get("webhook")
        if not isinstance(webhook, WebhookSink):
            raise ValueError("webhook event sink is missing normalized webhook config")
        return WebhookEventSink(webhook)


_EVENT_SINK_PROVIDER_REGISTRY: dict[str, EventSinkProvider] = {}
_EVENT_SINK_PROVIDER_CANONICAL_NAMES: dict[str, str] = {}


def register_event_sink_provider(provider: EventSinkProvider, *, replace: bool = False) -> EventSinkProvider:
    """Register an event sink/observability provider plugin."""

    name = provider.normalized_type
    if not name:
        raise ValueError("event sink provider type is required")
    names = provider.names
    if any(existing in _EVENT_SINK_PROVIDER_REGISTRY for existing in names) and not replace:
        conflicts = ", ".join(existing for existing in names if existing in _EVENT_SINK_PROVIDER_REGISTRY)
        raise ValueError(f"event sink provider already registered: {conflicts}")
    for existing, canonical in list(_EVENT_SINK_PROVIDER_CANONICAL_NAMES.items()):
        if canonical == name and existing not in names:
            _EVENT_SINK_PROVIDER_REGISTRY.pop(existing, None)
            _EVENT_SINK_PROVIDER_CANONICAL_NAMES.pop(existing, None)
    for alias in names:
        _EVENT_SINK_PROVIDER_REGISTRY[alias] = provider
        _EVENT_SINK_PROVIDER_CANONICAL_NAMES[alias] = name
    return provider


def get_event_sink_provider(sink_type: str) -> EventSinkProvider:
    normalized = str(sink_type).strip().lower()
    try:
        return _EVENT_SINK_PROVIDER_REGISTRY[normalized]
    except KeyError as exc:
        known = ", ".join(list_event_sink_providers()) or "<none>"
        raise ValueError(f"unknown event sink provider {sink_type!r}; known providers: {known}") from exc


def list_event_sink_providers() -> tuple[str, ...]:
    """Return canonical event sink provider names in registration order."""

    seen: set[str] = set()
    names: list[str] = []
    for canonical in _EVENT_SINK_PROVIDER_CANONICAL_NAMES.values():
        if canonical not in seen:
            seen.add(canonical)
            names.append(canonical)
    return tuple(names)


def build_event_dispatcher(
    *,
    event_sinks: Sequence[Mapping[str, Any]] | None = None,
    fabric_event_log: str | Path | None = None,
    extra_sinks: Sequence[EventSink] = (),
) -> EventDispatcher | None:
    sinks: list[EventSink] = []
    event_sink_configs = list(event_sinks or [])
    sinks.extend(_event_sink_from_config(config) for config in event_sink_configs)
    if fabric_event_log is not None and not _has_sink_type(event_sink_configs, "fabric_jsonl"):
        sinks.append(JsonlEventSink(Path(fabric_event_log), events=("snulbug.fabric.reconcile",)))
    sinks.extend(extra_sinks)
    return EventDispatcher(sinks) if sinks else None


def normalize_event_sink_configs(value: Any, *, base_dir: str | Path = ".") -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("mcp.events.sinks must be a list of tables")

    base = Path(base_dir)
    normalized = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"mcp.events.sinks[{index}] must be a table")
        sink_type = item.get("type")
        if not isinstance(sink_type, str) or not sink_type:
            raise ValueError(f"mcp.events.sinks[{index}].type must be a non-empty string")
        try:
            provider = get_event_sink_provider(sink_type)
        except ValueError as exc:
            raise ValueError(
                f"mcp.events.sinks[{index}].type must be one of: {', '.join(_event_sink_provider_names_for_error())}"
            ) from exc
        normalized.append(dict(provider.normalize_config(item, sink_type=sink_type, index=index, base_dir=base)))
    return normalized


def event_names(event: Mapping[str, Any]) -> set[str]:
    names = set()
    event_type = event.get("type")
    if isinstance(event_type, str) and event_type:
        names.add(event_type)

    if event_type == "snulbug.audit":
        names.update(_audit_event_names(event))

    event_types = event.get("event_types")
    if isinstance(event_types, Sequence) and not isinstance(event_types, str | bytes | bytearray):
        names.update(str(item) for item in event_types if isinstance(item, str) and item)
    control_events = event.get("control_events")
    if isinstance(control_events, Sequence) and not isinstance(control_events, str | bytes | bytearray):
        for control_event in control_events:
            if isinstance(control_event, Mapping) and isinstance(control_event.get("type"), str):
                names.add(str(control_event["type"]))
    return names


def prepare_webhook_payload(sink: WebhookSink, event: Mapping[str, Any]) -> dict[str, Any]:
    payload = _metadata_only_event(event) if sink.body_mode == "metadata_only" else _jsonish(event)
    if sink.redaction == "strict":
        payload = redact_secrets(payload)
    return {
        "type": "snulbug.webhook",
        "version": 1,
        "sink": sink.name,
        "event_names": sorted(event_names(event)),
        "event": payload,
    }


def deliver_webhook_event(sink: WebhookSink, event: Mapping[str, Any]) -> WebhookDeliveryResult:
    if not sink.enabled:
        return WebhookDeliveryResult(sink=sink.name, delivered=False, skipped=True, error="sink disabled")
    url = _resolve_url(sink)
    if not url:
        return WebhookDeliveryResult(sink=sink.name, delivered=False, skipped=True, error="webhook URL not configured")

    payload = prepare_webhook_payload(sink, event)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = _webhook_headers(sink, body)
    attempts = max(1, sink.retry_attempts + 1)
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            status = _post_json(url, body, headers, timeout=sink.timeout_ms / 1000)
        except Exception as exc:  # pragma: no cover - exact urllib exceptions vary by platform.
            last_error = str(exc)
        else:
            if 200 <= status < 300:
                return WebhookDeliveryResult(sink=sink.name, delivered=True, status=status, attempts=attempt)
            last_error = f"HTTP {status}"
        if attempt < attempts:
            time.sleep(min(0.25, 0.05 * attempt))
    return WebhookDeliveryResult(sink=sink.name, delivered=False, error=last_error, attempts=attempts)


def decision_console_event(
    record: Mapping[str, Any],
    *,
    audit_event: Mapping[str, Any],
) -> dict[str, Any]:
    event = dict(audit_event)
    result = record.get("result")
    trace = result.get("trace") if isinstance(result, Mapping) else None
    if isinstance(trace, Mapping):
        event["trace"] = {
            "duration_ms": trace.get("duration_ms"),
            "instruction_count": trace.get("instruction_count"),
        }
    return event


def format_decision_console_line(event: Mapping[str, Any]) -> str:
    request = event.get("request") if isinstance(event.get("request"), Mapping) else {}
    decision = event.get("decision") if isinstance(event.get("decision"), Mapping) else {}
    response = event.get("response") if isinstance(event.get("response"), Mapping) else {}
    mcp = event.get("mcp") if isinstance(event.get("mcp"), Mapping) else {}
    trace = event.get("trace") if isinstance(event.get("trace"), Mapping) else {}
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    lease = metadata.get("lease") if isinstance(metadata.get("lease"), Mapping) else {}
    tunnel = event.get("tunnel") if isinstance(event.get("tunnel"), Mapping) else {}
    cloudflare_access = (
        event.get("cloudflare_access")
        if isinstance(event.get("cloudflare_access"), Mapping)
        else metadata.get("cloudflare_access")
        if isinstance(metadata.get("cloudflare_access"), Mapping)
        else {}
    )
    confirmation = decision.get("confirmation") if isinstance(decision.get("confirmation"), Mapping) else {}

    parts = [
        "snulbug",
        f"decision={decision.get('action', 'unknown')}",
        f"allowed={str(bool(decision.get('allowed', False))).lower()}",
        f"status={response.get('status', decision.get('status', '-'))}",
        f"method={request.get('method', '-')}",
        f"path={request.get('path', '-')}",
    ]
    if decision.get("reason_code"):
        parts.append(f"reason_code={decision['reason_code']}")
    if decision.get("reason"):
        parts.append(f"reason={_console_value(decision['reason'])}")
    if confirmation:
        parts.append(f"confirm.approved={str(bool(confirmation.get('approved', False))).lower()}")
        if confirmation.get("mode"):
            parts.append(f"confirm.mode={confirmation['mode']}")
        if confirmation.get("reason_code"):
            parts.append(f"confirm.reason_code={confirmation['reason_code']}")
    if lease:
        if lease.get("id"):
            parts.append(f"lease.id={lease['id']}")
        if lease.get("task"):
            parts.append(f"lease.task={_console_value(lease['task'])}")
        if lease.get("reason_code"):
            parts.append(f"lease.reason_code={lease['reason_code']}")
        if lease.get("allowed") is not None:
            parts.append(f"lease.allowed={str(bool(lease['allowed'])).lower()}")
    if tunnel:
        if tunnel.get("provider"):
            parts.append(f"tunnel.provider={tunnel['provider']}")
        if tunnel.get("edge_request_id"):
            parts.append(f"tunnel.edge_request_id={tunnel['edge_request_id']}")
    if cloudflare_access:
        if cloudflare_access.get("mode"):
            parts.append(f"cf_access.mode={cloudflare_access['mode']}")
        if cloudflare_access.get("reason_code"):
            parts.append(f"cf_access.reason_code={cloudflare_access['reason_code']}")
        if cloudflare_access.get("email"):
            parts.append(f"cf_access.email={_console_value(cloudflare_access['email'])}")
    if request.get("query_string"):
        parts.append(f"query={request['query_string']}")
    if mcp.get("method"):
        parts.append(f"mcp.method={mcp['method']}")
    if mcp.get("tool"):
        parts.append(f"mcp.tool={mcp['tool']}")
    elif mcp.get("target"):
        parts.append(f"mcp.target={mcp['target']}")
    if mcp.get("request_id") is not None:
        parts.append(f"mcp.id={mcp['request_id']}")
    if trace.get("duration_ms") is not None:
        parts.append(f"lua_ms={float(trace['duration_ms']):.3f}")
    if trace.get("instruction_count") is not None:
        parts.append(f"lua_instructions={trace['instruction_count']}")
    return " ".join(parts)


def console_stream(value: bool | TextIO) -> TextIO | None:
    if value is True:
        return sys.stderr
    if value is False or value is None:
        return None
    return value


def _event_sink_from_config(config: Mapping[str, Any]) -> EventSink:
    sink_type = config.get("type")
    if not isinstance(sink_type, str) or not sink_type:
        raise ValueError("event sink config type must be a non-empty string")
    return get_event_sink_provider(sink_type).build(config)


def _has_sink_type(event_sinks: Sequence[Mapping[str, Any]], sink_type: str) -> bool:
    return any(config.get("type") == sink_type for config in event_sinks)


def _event_sink_provider_names_for_error() -> tuple[str, ...]:
    return tuple(_EVENT_SINK_PROVIDER_REGISTRY)


def _normalize_jsonl_sink(
    item: Mapping[str, Any],
    *,
    sink_type: str,
    index: int,
    base_dir: Path,
) -> dict[str, Any]:
    path = item.get("path")
    if not isinstance(path, str | Path) or not str(path):
        raise ValueError(f"mcp.events.sinks[{index}].path must be a non-empty string path")
    resolved = _resolve_path(base_dir, path)
    default_events = {
        "audit_jsonl": ["snulbug.audit"],
        "fabric_jsonl": ["snulbug.fabric.reconcile"],
        "jsonl": ["*"],
    }[sink_type]
    return {
        "type": sink_type,
        "path": resolved,
        "events": _string_tuple(item.get("events", default_events), field=f"mcp.events.sinks[{index}].events"),
        "enabled": _bool_value(item.get("enabled", True), field=f"mcp.events.sinks[{index}].enabled"),
    }


def _normalize_console_sink(item: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    output_format = item.get("format", "text")
    if output_format not in {"text", "json"}:
        raise ValueError(f"mcp.events.sinks[{index}].format must be 'text' or 'json'")
    normalized = {
        "type": "console",
        "format": output_format,
        "events": _string_tuple(item.get("events", ["snulbug.audit"]), field=f"mcp.events.sinks[{index}].events"),
        "enabled": _bool_value(item.get("enabled", True), field=f"mcp.events.sinks[{index}].enabled"),
    }
    if "include_internal" in item:
        normalized["include_internal"] = _bool_value(
            item.get("include_internal", False),
            field=f"mcp.events.sinks[{index}].include_internal",
        )
    return normalized


def _normalize_webhook_sink(
    item: Mapping[str, Any],
    *,
    index: int,
    field_prefix: str = "mcp.events.sinks",
) -> WebhookSink:
    if not isinstance(item, Mapping):
        raise ValueError(f"{field_prefix}[{index}] must be a table")
    name = item.get("name", f"webhook-{index + 1}")
    if not isinstance(name, str) or not name:
        raise ValueError(f"{field_prefix}[{index}].name must be a non-empty string")
    url = item.get("url")
    url_env = item.get("url_env")
    if url is not None and (not isinstance(url, str) or not url):
        raise ValueError(f"{field_prefix}[{index}].url must be a non-empty string")
    if url_env is not None and (not isinstance(url_env, str) or not url_env):
        raise ValueError(f"{field_prefix}[{index}].url_env must be a non-empty string")
    if not url and not url_env:
        raise ValueError(f"{field_prefix}[{index}] requires url or url_env")
    if url and not url.startswith(("http://", "https://")):
        raise ValueError(f"{field_prefix}[{index}].url must start with http:// or https://")

    events = _string_tuple(item.get("events", list(DEFAULT_WEBHOOK_EVENTS)), field=f"{field_prefix}[{index}].events")
    if not events:
        raise ValueError(f"{field_prefix}[{index}].events must not be empty")

    body_mode = item.get("body_mode", "metadata_only")
    if body_mode not in {"metadata_only", "full_event"}:
        raise ValueError(f"{field_prefix}[{index}].body_mode must be 'metadata_only' or 'full_event'")
    redaction = item.get("redaction", "strict")
    if redaction not in {"strict", "none"}:
        raise ValueError(f"{field_prefix}[{index}].redaction must be 'strict' or 'none'")

    timeout_ms = item.get("timeout_ms", 750)
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ValueError(f"{field_prefix}[{index}].timeout_ms must be a positive integer")
    retry_attempts = item.get("retry_attempts", 3)
    if not isinstance(retry_attempts, int) or retry_attempts < 0:
        raise ValueError(f"{field_prefix}[{index}].retry_attempts must be a non-negative integer")
    signing_secret_env = item.get("signing_secret_env")
    if signing_secret_env is not None and (not isinstance(signing_secret_env, str) or not signing_secret_env):
        raise ValueError(f"{field_prefix}[{index}].signing_secret_env must be a non-empty string")
    enabled = _bool_value(item.get("enabled", True), field=f"{field_prefix}[{index}].enabled")

    return WebhookSink(
        name=name,
        url=url,
        url_env=url_env,
        events=events,
        body_mode=body_mode,
        redaction=redaction,
        timeout_ms=timeout_ms,
        retry_attempts=retry_attempts,
        signing_secret_env=signing_secret_env,
        enabled=enabled,
    )


def _event_matches(event: Mapping[str, Any], events: Sequence[str], *, enabled: bool) -> bool:
    if not enabled:
        return False
    names = event_names(event)
    return "*" in events or any(event_name in names for event_name in events)


def _is_internal_probe_event(event: Mapping[str, Any]) -> bool:
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    return isinstance(metadata.get("internal_probe"), Mapping)


def _audit_event_names(event: Mapping[str, Any]) -> set[str]:
    names = {"mcp.request"}
    decision = event.get("decision") if isinstance(event.get("decision"), Mapping) else {}
    allowed = bool(decision.get("allowed")) if isinstance(decision, Mapping) else False
    names.add("mcp.decision.allowed" if allowed else "mcp.decision.blocked")
    action = decision.get("action") if isinstance(decision, Mapping) else None
    if isinstance(action, str) and action:
        names.add(f"mcp.decision.{action}")
    reason_code = decision.get("reason_code") if isinstance(decision, Mapping) else None
    if isinstance(reason_code, str) and reason_code:
        names.add(reason_code)

    if "response" in event:
        names.add("mcp.response")
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    response_policy = metadata.get("response_policy") if isinstance(metadata, Mapping) else None
    if isinstance(response_policy, Mapping):
        if response_policy.get("redacted"):
            names.add("mcp.response.redacted")
        if response_policy.get("blocked"):
            names.add("mcp.response.blocked")
        if response_policy.get("warnings"):
            names.add("mcp.response.warning")
        if response_policy.get("reason_code"):
            names.add(str(response_policy["reason_code"]))
        tool_pinning = response_policy.get("tool_pinning")
        if isinstance(tool_pinning, Mapping) and tool_pinning.get("changed"):
            names.add("mcp.tool.changed")
    return names


def _metadata_only_event(event: Mapping[str, Any]) -> dict[str, Any]:
    value = _jsonish(event)
    if value.get("type") == "snulbug.audit":
        request = value.get("request")
        if isinstance(request, Mapping):
            value["request"] = {key: request[key] for key in ("method", "path") if key in request}
    return value


def _jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonish(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_jsonish(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Path):
        return str(value)
    try:
        json.dumps(value)
    except TypeError:
        return str(value)
    return value


def _resolve_url(sink: WebhookSink) -> str | None:
    if sink.url:
        return sink.url
    if sink.url_env:
        return os.environ.get(sink.url_env) or None
    return None


def _webhook_headers(sink: WebhookSink, body: bytes) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "user-agent": WEBHOOK_USER_AGENT,
        "x-snulbug-webhook-sink": sink.name,
    }
    if sink.signing_secret_env:
        secret = os.environ.get(sink.signing_secret_env)
        if secret:
            timestamp = str(int(time.time()))
            signed = timestamp.encode("utf-8") + b"." + body
            digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
            headers["x-snulbug-signature-timestamp"] = timestamp
            headers["x-snulbug-signature"] = f"sha256={digest}"
    return headers


def _post_json(url: str, body: bytes, headers: Mapping[str, str], *, timeout: float) -> int:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is user config.
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def _string_tuple(value: Any, *, field: str) -> tuple[str, ...]:
    if isinstance(value, tuple) and all(isinstance(item, str) and item for item in value):
        return value
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return tuple(value)


def _bool_value(value: Any, *, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


for _provider in (JsonlEventSinkProvider(), ConsoleEventSinkProvider(), WebhookEventSinkProvider()):
    register_event_sink_provider(_provider, replace=True)


def _console_value(value: Any) -> str:
    return json.dumps(str(value), separators=(",", ":"))


def _resolve_path(base_dir: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path
