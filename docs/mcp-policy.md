# MCP policy workflow

`snulbug mcp policy` is the policy creation and promotion surface. Use it to
start from a bundled profile, learn a least-privilege bundle from observed
traffic, amend legitimate blocked requests into candidate bundles, and move
reviewed bundles through lifecycle states.

## Commands

| Command | Use it for |
| --- | --- |
| `snulbug mcp policy preset` | Copy or tailor a bundled policy profile. |
| `snulbug mcp policy learn` | Compile replay or audit evidence into a least-privilege bundle. |
| `snulbug mcp policy amend` | Generate a candidate bundle from legitimate blocked decisions. |
| `snulbug mcp policy lifecycle` | Inspect, sign, verify, and promote bundle lifecycle state. |

Schema-derived policy generation lives under
[`snulbug mcp policy schemas generate`](mcp-schemas.md#generate-a-policy-from-a-catalog)
because the schema catalog is the source artifact.

## Recommended loop

Start with the conservative tunnel profile:

```bash
uv run snulbug mcp policy preset tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Run the proxy and capture evidence:

```bash
uv run snulbug mcp share run --config snulbug.toml
```

Learn a least-privilege bundle from the captured session:

```bash
uv run snulbug mcp policy learn traces/session.jsonl --out learned-policy.snulbug
uv run snulbug bundle validate learned-policy.snulbug
uv run snulbug bundle test learned-policy.snulbug
```

Preview impact before switching to it:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua \
  --report-out traces/impact-report.md
```

When the learned bundle blocks a legitimate request, generate a candidate
amendment instead of editing the active policy directly:

```bash
uv run snulbug mcp policy amend \
  learned-policy.snulbug \
  traces/audit.jsonl \
  --out candidate-policy.snulbug
```

`policy amend` writes `AMEND.md` and records a capability delta in
`manifest.json`. That delta makes the review concrete: newly allowed tools,
MCP path patterns, resources/prompts, and tool argument shapes are listed before
the generated Lua is promoted.

If a human approved a blocked or risky request through the confirmation broker,
use the same command with the approved-confirmation source to turn those
approvals into a reviewable candidate bundle:

```bash
uv run snulbug mcp policy amend \
  learned-policy.snulbug \
  traces/session.jsonl \
  --source approved-confirmations \
  --out approval-candidate.snulbug
```

Promote only after review:

```bash
uv run snulbug mcp policy lifecycle promote candidate-policy.snulbug --to proposed --key-id local-review
uv run snulbug mcp policy lifecycle promote candidate-policy.snulbug --to approved --key-id local-review
uv run snulbug mcp policy lifecycle promote candidate-policy.snulbug --to active --key-id local-review
```

## How to choose a source

Use `preset` when you know the shape of access you want up front: tunnel-safe
public sharing, read-only local development, workspace firewalling, or a simple
tool allowlist.

Use `learn` when the safest policy is the one your actual dev session already
proved it needed. Learned policies are intentionally mechanical: they allow
observed methods, tools, targets, and argument keys, then deny drift.

Use `amend` when a real workflow was missed. By default it reads blocked
`mcp.learn.*` decisions and proposes the smallest expansion in a new bundle.
With `--source approved-confirmations`, it reads approved confirmation results
from replay evidence and proposes the observed paths, MCP methods, tools,
targets, and argument keys.

Use `policy schemas generate` when the upstream's declared contract should drive the
starting policy. This is useful before trusting a new upstream or after a
schema discovery review.

## Deep references

- [MCP presets](mcp-presets.md)
- [MCP learn and amend mode](mcp-learn.md)
- [Policy bundles and lifecycle](bundles.md)
- [MCP schema discovery and schema-derived policies](mcp-schemas.md)
- [MCP evidence workflow](mcp-evidence.md)
