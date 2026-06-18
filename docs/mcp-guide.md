# MCP CLI guide for agents and harnesses

`snulbug mcp guide` prints operational workflows for local-dev MCP policy
proxying. It is meant for humans who want copy-paste commands and for agentic
harnesses that need structured next steps.

Human-readable guide:

```bash
snulbug mcp guide
snulbug mcp guide --workflow share
snulbug mcp guide --workflow learn-amend-impact
```

Machine-readable compact JSON:

```bash
snulbug mcp guide --compact
snulbug mcp guide --workflow share --compact
```

## Workflows

- `share`: create a bounded share directory with generated bearer auth, task
  lease, provider setup, MCP client config, and close-out commands.
- `learn-amend-impact`: inspect a captured session, learn a least-privilege
  policy, preview impact, and generate candidate amendments for legitimate
  blocks.
- `leases-invites`: create, preview, and revoke task-scoped leases; package
  lease-backed setup snippets for downstream MCP clients.
- `facade`: run several local MCP upstreams behind one protected endpoint with
  namespaced tool identities.

## Compact JSON contract

The compact output includes:

- `ok`: whether the guide was generated.
- `recommended_entrypoint`: the command a harness can call for full structured
  guidance.
- `default_public_tunnel_profile`: the recommended profile for public tunnel
  use.
- `workflows`: selected workflow objects.
- `workflows[].steps[]`: ordered commands with `requires`, `produces`,
  `success_signals`, and `next` fields.
- `workflows[].stop_conditions`: conditions where the harness should stop and
  ask for review instead of continuing automatically.

Example:

```bash
snulbug mcp guide --workflow learn-amend-impact --compact
```

Use this before automating `learn`, `amend`, or `impact` so policy promotion
stays reviewable.
