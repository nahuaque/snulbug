# Roadmap

This page tracks near-term follow-ups that are useful but not required for the
current documented workflow.

## Pending

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
