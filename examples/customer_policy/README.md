# Customer-Owned Request Policy Demo

This demo shows the pattern that makes `snulbug` useful: Python owns the
stable ASGI host, while each customer owns a small Lua request policy.

The app selects a policy by the `x-tenant` request header:

- `acme.lua` verifies a customer-specific signature, rewrites the request to a
  canonical tenant route, adds normalized headers, and attaches policy context.
- `globex.lua` enforces method rules and short-circuits sandbox callbacks with a
  direct response.
- `default.lua` rejects traffic for tenants without an installed policy.

Run the app:

```bash
uv run uvicorn examples.customer_policy.app:application
```

Replay a policy in CI or during customer onboarding:

```bash
uv run snulbug simulate \
  examples/customer_policy/policies/acme.lua \
  examples/customer_policy/requests/acme-valid.json
```

The output is a JSON decision trace. That gives support and customer success a
way to validate customer-owned logic before enabling it on live traffic.
