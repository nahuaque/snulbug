from __future__ import annotations

import io
import json

from snulbug import (
    ConsoleEventSink,
    EventDispatcher,
    EventSinkProvider,
    JsonlEventSink,
    build_event_dispatcher,
    get_event_sink_provider,
    list_event_sink_providers,
    normalize_event_sink_configs,
    register_event_sink_provider,
)


def test_event_dispatcher_fans_out_same_event_to_jsonl_and_console(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    console = io.StringIO()
    event = {
        "type": "snulbug.audit",
        "request": {"method": "POST", "path": "/mcp"},
        "decision": {"action": "reject", "allowed": False, "reason_code": "mcp.tool_not_allowed"},
        "trace": {"instruction_count": 1000},
    }
    dispatcher = EventDispatcher(
        [
            JsonlEventSink(audit_log, events=("snulbug.audit",)),
            ConsoleEventSink(console, output_format="json"),
        ]
    )

    dispatcher.emit(event)

    assert json.loads(audit_log.read_text(encoding="utf-8")) == event
    assert json.loads(console.getvalue()) == event


def test_console_event_sink_suppresses_internal_probe_events_by_default():
    event = {
        "type": "snulbug.audit",
        "request": {"method": "POST", "path": "/mcp"},
        "decision": {"action": "continue", "allowed": True},
        "metadata": {"internal_probe": {"kind": "share-status"}},
    }
    quiet_console = io.StringIO()
    verbose_console = io.StringIO()

    ConsoleEventSink(quiet_console).emit(event)
    ConsoleEventSink(verbose_console, include_internal=True).emit(event)

    assert quiet_console.getvalue() == ""
    assert "decision=continue" in verbose_console.getvalue()


def test_normalize_event_sink_configs_resolves_paths_and_webhooks(tmp_path):
    sinks = normalize_event_sink_configs(
        [
            {"type": "fabric_jsonl", "path": "fabric-events.jsonl"},
            {
                "type": "webhook",
                "name": "alerts",
                "url_env": "SNULBUG_WEBHOOK_URL",
                "events": ["snulbug.fabric.upstream.unhealthy"],
            },
        ],
        base_dir=tmp_path,
    )

    assert sinks[0] == {
        "type": "fabric_jsonl",
        "path": tmp_path / "fabric-events.jsonl",
        "events": ("snulbug.fabric.reconcile",),
        "enabled": True,
    }
    assert sinks[1]["type"] == "webhook"
    assert sinks[1]["webhook"].name == "alerts"
    assert sinks[1]["webhook"].events == ("snulbug.fabric.upstream.unhealthy",)


def test_build_event_dispatcher_uses_explicit_audit_sink(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    dispatcher = build_event_dispatcher(
        event_sinks=[
            {
                "type": "audit_jsonl",
                "path": audit_log,
                "events": ("snulbug.audit",),
                "enabled": True,
            }
        ],
    )

    assert dispatcher is not None
    dispatcher.emit({"type": "snulbug.audit", "decision": {"action": "continue", "allowed": True}})

    assert len(audit_log.read_text(encoding="utf-8").splitlines()) == 1


def test_builtin_event_sink_providers_are_registered():
    assert list_event_sink_providers() == ("jsonl", "console", "webhook")
    assert get_event_sink_provider("jsonl").normalized_type == "jsonl"
    assert get_event_sink_provider("audit_jsonl").normalized_type == "jsonl"
    assert get_event_sink_provider("fabric_jsonl").normalized_type == "jsonl"
    assert get_event_sink_provider("console").normalized_type == "console"
    assert get_event_sink_provider("webhook").normalized_type == "webhook"


def test_custom_event_sink_provider_normalizes_and_builds_sink(tmp_path):
    captured = []

    class FixtureSink:
        def __init__(self, label):
            self.label = label

        def emit(self, event):
            captured.append({"label": self.label, "event": dict(event)})

    class FixtureEventSinkProvider(EventSinkProvider):
        type = "fixture-observer"
        aliases = ("fixture",)

        def normalize_config(self, item, *, sink_type, index, base_dir):
            return {
                "type": sink_type,
                "label": item.get("label", f"fixture-{index}"),
                "base_dir": str(base_dir),
            }

        def build(self, config):
            return FixtureSink(config["label"])

    provider = FixtureEventSinkProvider()
    assert register_event_sink_provider(provider, replace=True) is provider
    normalized = normalize_event_sink_configs(
        [{"type": "fixture", "label": "unit"}],
        base_dir=tmp_path,
    )
    dispatcher = build_event_dispatcher(event_sinks=normalized)

    assert normalized == [{"type": "fixture", "label": "unit", "base_dir": str(tmp_path)}]
    assert dispatcher is not None
    dispatcher.emit({"type": "snulbug.audit", "decision": {"allowed": True}})
    assert captured == [
        {
            "label": "unit",
            "event": {"type": "snulbug.audit", "decision": {"allowed": True}},
        }
    ]
