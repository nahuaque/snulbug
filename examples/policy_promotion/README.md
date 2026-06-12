# Policy Promotion Demo

This demo shows a promotion gate for customer-owned request policies.

Compare the active policy with a draft policy:

```bash
uv run uvicorn-lua diff \
  examples/policy_promotion/active.lua \
  examples/policy_promotion/draft.lua \
  examples/policy_promotion/fixtures
```

The draft intentionally changes Acme signature requirements. The diff reports
that a previously accepted fixture would now be rejected, so
`safe_to_promote` is `false` and the command exits non-zero.

In live middleware, pass `shadow_script=` to run a candidate policy beside the
active policy:

```python
application = LuaMiddleware(
    app,
    active_policy,
    shadow_script=draft_policy,
    config=LuaConfig(trace=True),
)
```

The active policy still controls the request. The candidate result is attached
to `scope["lua_shadow_trace"]` for logging, dashboards, or promotion decisions.
