# Stateful Replay Snapshot Demo

Replay an idempotency policy with a captured initial state:

```bash
uv run snulbug simulate \
  examples/state_replay/idempotency.lua \
  examples/state_replay/request.json \
  --state examples/state_replay/duplicate-state.json
```

The policy rejects the request as a duplicate and the output includes the
initial state, state operations, and final state.
