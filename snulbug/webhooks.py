from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .redaction import redact_secrets

DEFAULT_WEBHOOK_EVENTS = ("snulbug.audit",)
WEBHOOK_USER_AGENT = "snulbug-webhook/0.1"


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


class WebhookDispatcher:
    """Fail-open background dispatcher for redacted snulbug events."""

    def __init__(self, sinks: Sequence[WebhookSink | Mapping[str, Any]], *, max_in_flight: int = 64) -> None:
        self.sinks = normalize_webhook_sinks(sinks)
        if max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        self._slots = threading.BoundedSemaphore(max_in_flight)

    def emit(self, event: Mapping[str, Any]) -> None:
        """Schedule matching webhook deliveries without blocking request flow."""

        for sink in matching_webhook_sinks(self.sinks, event):
            if not self._slots.acquire(blocking=False):
                continue
            thread = threading.Thread(target=self._deliver_and_release, args=(sink, dict(event)), daemon=True)
            thread.start()

    def _deliver_and_release(self, sink: WebhookSink, event: Mapping[str, Any]) -> None:
        try:
            deliver_webhook_event(sink, event)
        finally:
            self._slots.release()


def normalize_webhook_sinks(value: Any) -> list[WebhookSink]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("mcp.webhooks must be a list of tables")

    sinks = []
    names = set()
    for index, item in enumerate(value):
        if isinstance(item, WebhookSink):
            sink = item
        else:
            if not isinstance(item, Mapping):
                raise ValueError(f"mcp.webhooks[{index}] must be a table")
            sink = _normalize_webhook_sink(item, index=index)
        if sink.name in names:
            raise ValueError(f"duplicate mcp.webhooks name: {sink.name!r}")
        names.add(sink.name)
        sinks.append(sink)
    return sinks


def matching_webhook_sinks(sinks: Sequence[WebhookSink], event: Mapping[str, Any]) -> list[WebhookSink]:
    names = webhook_event_names(event)
    return [
        sink
        for sink in sinks
        if sink.enabled and ("*" in sink.events or any(event_name in names for event_name in sink.events))
    ]


def webhook_event_names(event: Mapping[str, Any]) -> set[str]:
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
        "event_names": sorted(webhook_event_names(event)),
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


def _normalize_webhook_sink(item: Mapping[str, Any], *, index: int) -> WebhookSink:
    name = item.get("name", f"webhook-{index + 1}")
    if not isinstance(name, str) or not name:
        raise ValueError(f"mcp.webhooks[{index}].name must be a non-empty string")
    url = item.get("url")
    url_env = item.get("url_env")
    if url is not None and (not isinstance(url, str) or not url):
        raise ValueError(f"mcp.webhooks[{index}].url must be a non-empty string")
    if url_env is not None and (not isinstance(url_env, str) or not url_env):
        raise ValueError(f"mcp.webhooks[{index}].url_env must be a non-empty string")
    if not url and not url_env:
        raise ValueError(f"mcp.webhooks[{index}] requires url or url_env")
    if url and not url.startswith(("http://", "https://")):
        raise ValueError(f"mcp.webhooks[{index}].url must start with http:// or https://")

    events = _string_tuple(item.get("events", list(DEFAULT_WEBHOOK_EVENTS)), field=f"mcp.webhooks[{index}].events")
    if not events:
        raise ValueError(f"mcp.webhooks[{index}].events must not be empty")

    body_mode = item.get("body_mode", "metadata_only")
    if body_mode not in {"metadata_only", "full_event"}:
        raise ValueError(f"mcp.webhooks[{index}].body_mode must be 'metadata_only' or 'full_event'")
    redaction = item.get("redaction", "strict")
    if redaction not in {"strict", "none"}:
        raise ValueError(f"mcp.webhooks[{index}].redaction must be 'strict' or 'none'")

    timeout_ms = item.get("timeout_ms", 750)
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ValueError(f"mcp.webhooks[{index}].timeout_ms must be a positive integer")
    retry_attempts = item.get("retry_attempts", 3)
    if not isinstance(retry_attempts, int) or retry_attempts < 0:
        raise ValueError(f"mcp.webhooks[{index}].retry_attempts must be a non-negative integer")
    signing_secret_env = item.get("signing_secret_env")
    if signing_secret_env is not None and (not isinstance(signing_secret_env, str) or not signing_secret_env):
        raise ValueError(f"mcp.webhooks[{index}].signing_secret_env must be a non-empty string")
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"mcp.webhooks[{index}].enabled must be a boolean")

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
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return tuple(value)
