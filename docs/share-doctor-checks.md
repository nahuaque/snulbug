# Share doctor check plugins

Share doctor checks extend `snulbug mcp share doctor`. They are useful when a
plugin or local platform integration needs to prove readiness before a public
MCP URL or peer bridge is shared.

Built-ins currently cover:

- `status`: share session status, leases, recordings, contracts, and findings
- `config`: proxy/fabric config loading
- `policy`: policy bundle/entrypoint readiness
- `cloudflare`: Cloudflare Access/OAuth profile safety
- `tailscale`: Tailscale Funnel/Serve profile safety
- `fabric`: fabric doctor checks
- `conformance`: generated fabric conformance pack checks
- `tunnel`: provider-specific tunnel doctor checks

External checks can register the same surface from Python:

```python
from snulbug import (
    ShareDoctorCheck,
    ShareDoctorCheckResult,
    ShareDoctorContext,
    register_share_doctor_check,
)


class AcmeShareDoctorCheck(ShareDoctorCheck):
    name = "acme-platform"
    component = "acme"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        ok = acme_policy_exists(context.share_dir)
        return ShareDoctorCheckResult(
            checks=[
                {
                    "id": "acme.platform_policy_present",
                    "status": "pass" if ok else "fail",
                    "message": "Acme platform policy is present"
                    if ok
                    else "Acme platform policy is missing",
                    "component": self.component,
                    "details": {"share": str(context.share_dir)},
                }
            ],
            recommendations=[]
            if ok
            else ["Run `acme policy sync` before sharing this MCP endpoint."],
            artifacts={"acme": {"policy_present": ok}},
        )


register_share_doctor_check(AcmeShareDoctorCheck(), replace=True)
```

Checks use the same normalized shape as built-ins:

- `id`: stable check identifier
- `status`: `pass`, `fail`, `warn`, or `skip`
- `message`: concise human-readable result
- `component`: grouping for reports and SARIF
- `details`: optional secret-safe JSON-like metadata

`ShareDoctorContext` includes the resolved share directory, manifest, client
URL, client headers, config path, timeout, live-check flag, share status, and
the loaded proxy/fabric config once the built-in `config` check has run.

Plugin artifacts are merged into `doctor_artifacts` in the `share doctor`
result. Keep artifacts secret-safe; doctor results are intended for review,
reports, and CI gates.
