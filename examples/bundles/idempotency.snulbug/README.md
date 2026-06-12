# Webhook Idempotency Policy Bundle

Validate the bundle:

```bash
uv run snulbug bundle validate examples/bundles/idempotency.snulbug
```

Run its fixtures:

```bash
uv run snulbug bundle test examples/bundles/idempotency.snulbug
```

Pack it:

```bash
uv run snulbug bundle pack examples/bundles/idempotency.snulbug dist/idempotency.snulbug.tar.gz
```
