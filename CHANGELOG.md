# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning after `1.0.0`. Before `1.0.0`, minor versions may include action schema or trace schema changes.

## [Unreleased]

## [0.1.1] - 2026-06-16

- Fixed PyPI/TestPyPI project metadata and README logo URLs to point at the
  published `nahuaque/snulbug` repository.
- Added public GitHub project metadata, CI, contribution docs, security docs, issue templates, and reference documentation.
- Added the basic ASGI middleware example under `examples/basic`.
- Added bundled MCP policy presets with `snulbug mcp policy preset`.
- Added MCP request decision recording and replay with `snulbug mcp evidence record` and `snulbug mcp evidence replay`.
- Added secret redaction and redacted MCP audit JSONL logs.
- Added local-dev MCP reverse proxy mode with `snulbug mcp share run`.
- Added live proxy request recording and audit logging with `snulbug mcp share run --record-out`.
- Added MCP proxy TOML config files with `snulbug mcp share config init` and `snulbug mcp share run --config`.
- Added configurable MCP policy generation options to `snulbug mcp policy preset`.
- Added live proxy decision console output with generated console event sinks.
- Added MCP-aware audit fields for JSON-RPC id, method, operation, targets, key names, batches, and initialize metadata.
- Added policy decision `reason` and `reason_code` conventions across MCP helpers, presets, audit logs, and live console output.
- Added offline MCP log inspection with `snulbug mcp evidence inspect`.
- Changed MCP record/proxy defaults to redact replay artifacts unless exact logging is explicitly requested.
- Added MCP client setup recipes for local, tunneled, authenticated, recording, and stdio-only workflows.
- Added a local MCP policy gateway quickstart and `snulbug mcp share quickstart` generator.
- Added a runnable end-to-end MCP policy proxy demo.
- Added MCP risk-profile presets for read-only local development, shell-tool denial, project path allowlists, and tunneled servers.
- Added Markdown MCP session reports with `snulbug mcp evidence inspect --report-out`.
- Documented `tunnel-safe` as the recommended default for public tunnel use.
- Added MCP facade mode for serving multiple local MCP HTTP servers through one `snulbug mcp share run` endpoint.
- Added managed stdio MCP upstreams for facade mode, so local stdio servers can be exposed through the same policy-controlled HTTP endpoint.
- Added MCP learn mode with `snulbug mcp policy learn` to compile captured replay/audit logs into least-privilege policy bundles.
- Added MCP amend mode with `snulbug mcp policy amend` to produce candidate patches from blocked learned-policy decisions.
- Added `snulbug mcp share lab`, a one-command local MCP policy lab covering facade, recording, inspection, learn, and amend.

## [0.1.0] - 2026-06-12

- Initial alpha package for programmable Lua request policy in ASGI middleware.
- Added request actions: `continue`, `set_context`, `rewrite`, `respond`, `reject`, `challenge`, `redirect`, and `rate_limit`.
- Added bounded policy state with memory, SQLite, Redis, snapshot, and dry-run support.
- Added simulator, policy diffing, shadow policy support, bundle validation, bundle tests, and bundle packing.
- Added customer-owned request policy, webhook normalization, state replay, idempotency bundle, and MCP gateway examples.
