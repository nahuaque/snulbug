# Replayable Webhook Normalization Demo

This demo shows vendor-specific webhook payloads being normalized at the ASGI
edge before the Python app handles them.

Each Lua policy:

- validates the vendor-specific request shape
- extracts a few stable fields
- rewrites the path to `/webhooks/normalized`
- replaces the bounded request body with canonical JSON
- attaches context and trace metadata for audit/replay

Run the app:

```bash
uv run uvicorn examples.webhook_normalization.app:application
```

Replay a Stripe fixture without starting a server:

```bash
uv run snulbug simulate \
  examples/webhook_normalization/policies/stripe.lua \
  examples/webhook_normalization/requests/stripe-invoice.json
```

The normalized body appears in the `decision.body` field of the simulator
output. In the ASGI app, that same body is what downstream Python receives.

This pattern is useful when every upstream vendor has a different webhook
format, but your core application wants one stable internal event schema:

```json
{
  "vendor": "stripe",
  "event_id": "evt_123",
  "event_type": "invoice.payment_succeeded",
  "subject": "cus_456",
  "source_path": "/webhooks/stripe"
}
```
