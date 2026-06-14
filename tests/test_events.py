from __future__ import annotations

import io
import json

from snulbug import (
    ConsoleEventSink,
    EventDispatcher,
    JsonlEventSink,
    build_event_dispatcher,
    normalize_event_sink_configs,
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
