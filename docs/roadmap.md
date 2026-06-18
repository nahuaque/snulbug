# Roadmap

This page tracks near-term follow-ups that are useful but not required for the
current documented workflow.

## Pending

### Scope-qualified task capabilities

OAuth scopes and snulbug invite capabilities are related but should remain
separate concepts. OAuth scopes come from an identity provider and say which MCP
methods or tools an authenticated caller may ask this protected resource to
use. Snulbug capabilities are local, task-scoped lease labels declared by Lua
policy and granted by the share owner for one recipient, task, and TTL.

Future work: let Lua capability declarations express OAuth eligibility
requirements without turning task capabilities into OAuth scopes:

```lua
capabilities.declare({
  {
    id = "git_inspection",
    label = "Git inspection",
    required_scopes = { "mcp:tools.git.read" },
  },
})
```

In that model, selecting `git_inspection` in an invite would still mint a normal
task lease, but using it on an OAuth-protected share would require both the
active lease capability and a caller token with the mapped OAuth scope. The
access model remains:

```text
valid OAuth subject + required OAuth scopes
  + active snulbug task lease + invite capability labels
  + Lua policy approval
  = allowed MCP action
```

Acceptance criteria:

- `capabilities.declare(...)` can include scope eligibility metadata.
- The share console displays scope requirements next to capability labels.
- Invite creation warns or blocks when selected capabilities cannot be used
  under the current auth profile.
- Lua helpers expose whether a capability is scope-eligible for the current
  caller.
- Audit metadata records capability, scope match, and denial reason without raw
  token data.

### Golden path demo

Build a runnable demo that exercises the primary share session loop end to end:

```text
share create -> share run -> share status -> share policy amend -> share policy activate -> share report
```

The demo should start a mock MCP upstream, generate a share session, drive both
allowed and blocked traffic, amend a legitimate blocked call, activate the
reviewed policy bundle, and emit a final share report from the generated
evidence.

Acceptance criteria:

- The demo runs from one command in a clean checkout.
- It writes all artifacts under a disposable `.snulbug-*` directory.
- It prints the exact next commands for manual replay.
- It does not require a public tunnel, Redis, Docker, or a PyPI release.
- It is linked from the README only after it exists.
