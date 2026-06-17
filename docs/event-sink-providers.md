# Event sink provider plugins

Event sink providers extend `[[mcp.events.sinks]]` and
`build_event_dispatcher()`. Use them for observability outputs such as OpenTelemetry
exporters, metrics bridges, log aggregators, chat alerts, or internal audit
streams.

Built-ins cover:

- `jsonl`: append events to JSONL files
- `audit_jsonl`: JSONL alias defaulting to `snulbug.audit`
- `fabric_jsonl`: JSONL alias defaulting to fabric reconcile events
- `console`: write decision-console lines or JSON to stderr/stdout-like streams
- `webhook`: deliver redacted webhook events asynchronously

External providers can register the same surface from Python:

```python
from snulbug import EventSinkProvider, register_event_sink_provider


class AcmeObservabilityProvider(EventSinkProvider):
    type = "acme-observability"
    aliases = ("acme",)

    def normalize_config(self, item, *, sink_type, index, base_dir):
        return {
            "type": sink_type,
            "dataset": item.get("dataset", "mcp-dev"),
            "events": tuple(item.get("events", ["*"])),
        }

    def build(self, config):
        return AcmeEventSink(
            dataset=config["dataset"],
            events=config["events"],
        )


register_event_sink_provider(AcmeObservabilityProvider(), replace=True)
```

Config can then use the provider type or alias:

```toml
[[mcp.events.sinks]]
type = "acme"
dataset = "local-mcp"
events = ["snulbug.audit", "mcp.response.redacted"]
```

Provider responsibilities:

- `normalize_config()` validates raw TOML fields and returns a JSON-like config
  mapping. Keep the `type` field so the dispatcher can build it later.
- `build()` returns an object with `emit(event)`; delivery should be
  fail-open and non-blocking when the sink talks to external services.
- Event payloads may contain redacted replay/audit metadata. Treat all provider
  config and emitted diagnostics as secret-safe review artifacts.
