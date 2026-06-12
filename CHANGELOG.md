# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning after `1.0.0`. Before `1.0.0`, minor versions may include action schema or trace schema changes.

## [Unreleased]

- Added public GitHub project metadata, CI, contribution docs, security docs, issue templates, and reference documentation.
- Added the basic ASGI middleware example under `examples/basic`.
- Added bundled MCP policy presets with `asgi-lua mcp presets` and `asgi-lua mcp init`.
- Added MCP request decision recording and replay with `asgi-lua mcp record` and `asgi-lua mcp replay`.
- Added secret redaction and redacted MCP audit JSONL logs with `asgi-lua mcp record --audit-out`.
- Added local-dev MCP reverse proxy mode with `asgi-lua mcp proxy`.
- Added live proxy request recording and audit logging with `asgi-lua mcp proxy --record-out --audit-out`.
- Added MCP proxy TOML config files with `asgi-lua mcp config init` and `asgi-lua mcp proxy --config`.

## [0.1.0] - 2026-06-12

- Initial alpha package for programmable Lua request policy in ASGI middleware.
- Added request actions: `continue`, `set_context`, `rewrite`, `respond`, `reject`, `challenge`, `redirect`, and `rate_limit`.
- Added bounded policy state with memory, SQLite, Redis, snapshot, and dry-run support.
- Added simulator, policy diffing, shadow policy support, bundle validation, bundle tests, and bundle packing.
- Added customer-owned request policy, webhook normalization, state replay, idempotency bundle, and MCP gateway examples.
