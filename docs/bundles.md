# Policy bundles

A bundle packages a Lua policy with fixtures, snapshots, expectations, and documentation:

```text
policy.asgi-lua/
  manifest.json
  policy.lua
  fixtures/
  snapshots/
  README.md
```

Validate and test:

```bash
uv run asgi-lua bundle validate examples/bundles/idempotency.asgi-lua
uv run asgi-lua bundle test examples/bundles/idempotency.asgi-lua
```

Pack:

```bash
uv run asgi-lua bundle pack examples/bundles/idempotency.asgi-lua dist/idempotency.asgi-lua.tar.gz
```

Expectations can match direct fields such as `action`, `status`, `path`, `body`, `headers`, and `context`, or nested dotted paths such as `decision.context.tenant`.
