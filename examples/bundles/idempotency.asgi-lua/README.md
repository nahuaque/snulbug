# Webhook Idempotency Policy Bundle

Validate the bundle:

```bash
uv run asgi-lua bundle validate examples/bundles/idempotency.asgi-lua
```

Run its fixtures:

```bash
uv run asgi-lua bundle test examples/bundles/idempotency.asgi-lua
```

Pack it:

```bash
uv run asgi-lua bundle pack examples/bundles/idempotency.asgi-lua dist/idempotency.asgi-lua.tar.gz
```
