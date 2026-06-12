# Policy bundles

A bundle packages a Lua policy with fixtures, snapshots, expectations, and documentation:

```text
policy.snulbug/
  manifest.json
  policy.lua
  fixtures/
  snapshots/
  README.md
```

Validate and test:

```bash
uv run snulbug bundle validate examples/bundles/idempotency.snulbug
uv run snulbug bundle test examples/bundles/idempotency.snulbug
```

Pack:

```bash
uv run snulbug bundle pack examples/bundles/idempotency.snulbug dist/idempotency.snulbug.tar.gz
```

Expectations can match direct fields such as `action`, `status`, `path`, `body`, `headers`, and `context`, or nested dotted paths such as `decision.context.tenant`.
