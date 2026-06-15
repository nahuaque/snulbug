# CI policy gates

`snulbug` can emit SARIF for MCP policy and share-safety review gates. This lets
GitHub code scanning show policy regressions, schema drift, and failed share
readiness checks alongside normal pull-request review.

## Gates

### Policy evidence diff

Use this when a candidate Lua policy or policy bundle changes:

```bash
uv run snulbug mcp evidence diff \
  policy.snulbug/policy.lua \
  policy.snulbug.candidate/policy.lua \
  fixtures \
  --report-out .snulbug/ci/policy-diff.md \
  --sarif-out .snulbug/ci/policy-diff.sarif
```

SARIF includes:

- `snulbug.policy.regression` as `error`
- `snulbug.policy.newly_allowed_capability` as `warning`

### MCP schema diff

Use this when an upstream MCP server's declared capability surface changes:

```bash
uv run snulbug mcp policy schemas diff \
  .snulbug/schemas/baseline.json \
  .snulbug/schemas/current.json \
  --fail-on changed \
  --fail-on removed \
  --report-out .snulbug/ci/schema-diff.md \
  --sarif-out .snulbug/ci/schema-diff.sarif
```

Schema changes selected by `--fail-on` are emitted as SARIF errors. Other added,
changed, or removed schema items are emitted as warnings.

### Share doctor

Use this before publishing or sharing a generated MCP share session:

```bash
uv run snulbug mcp share doctor .snulbug/shares/review \
  --no-live-checks \
  --require-conformance \
  --conformance-pack .snulbug/fabric-conformance \
  --sarif-out .snulbug/ci/share-doctor.sarif
```

Failed checks are emitted as `snulbug.share.doctor_failed_check` errors.
Warnings are emitted as `snulbug.share.doctor_warning_check`.

## GitHub Actions

Copy
[`examples/github-actions/snulbug-policy-gates.yml`](../examples/github-actions/snulbug-policy-gates.yml)
to `.github/workflows/snulbug-policy-gates.yml` and adjust the artifact paths
for your repo. The template:

- runs policy evidence diff, schema diff, and share doctor gates
- writes Markdown review artifacts under `.snulbug/ci`
- uploads SARIF with `github/codeql-action/upload-sarif`

Keep `--compact` JSON for harnesses that need machine-readable command output.
Use `--report-out` for durable human review reports. Use `--sarif-out` for CI
annotations and security/code-scanning integration.
