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

## Lifecycle

Policy bundles can carry signed lifecycle metadata in `manifest.json`:

```text
observed -> proposed -> approved -> active
```

Missing lifecycle metadata is treated as `observed`. Promotion validates the
manifest, replays bundle fixtures, writes lifecycle history, and signs a
canonical digest of the manifest metadata plus every bundle file except
`manifest.json`.

Use an HMAC secret from `SNULBUG_BUNDLE_SECRET`:

```bash
export SNULBUG_BUNDLE_SECRET="replace-with-a-local-review-secret"

uv run snulbug bundle promote policy.snulbug --to proposed --key-id local-review
uv run snulbug bundle promote policy.snulbug --to approved --key-id local-review
uv run snulbug bundle promote policy.snulbug --to active --key-id local-review
```

Verify before enabling a bundle:

```bash
uv run snulbug bundle verify policy.snulbug --state active
uv run snulbug bundle lifecycle policy.snulbug
```

For managed fabrics, the controller can own the final activation step. Configure
`[mcp.fabric.policy_activation] mode = "promote_approved"` to promote a signed
`approved` bundle to `active` before `fabric run` starts the data plane.

Illegal skips, such as `observed -> active`, are rejected. Any edit to
`policy.lua`, fixtures, snapshots, README files, or lifecycle metadata after
signing changes the bundle digest and causes verification to fail.
