# AWS MCP Policy Pack

Policy pack for putting snulbug in front of AWS MCP servers.

The default posture is intentionally narrow:

- `Authorization: Bearer local-dev-secret` is required.
- JSON-RPC batch requests are rejected.
- AWS Knowledge and Documentation tools are allowed after bearer auth.
- Broader AWS API tools require a task lease with a policy-declared capability.
- Non-identity/non-secret mutations require `aws_sandbox_change`, explicit
  account and region arguments, configured sandbox allowlists, and live
  confirmation.

Share invites use Lua-declared temporary capability labels:

- `aws_knowledge`: default; AWS docs, regional availability, and skills.
- `aws_inventory_read`: read-only control-plane inventory calls.
- `aws_observability_read`: CloudWatch, Logs, CloudTrail, and X-Ray triage.
- `aws_cost_read`: Cost Explorer, Pricing, Billing, Budgets, and CUR reads.
- `aws_identity_review`: IAM, KMS, Organizations, SSO, STS, and Access Analyzer
  reads.
- `aws_data_read`: data-plane reads such as S3 object reads and DynamoDB
  queries/scans.
- `aws_sandbox_change`: confirm-gated non-sensitive mutations in configured
  sandbox accounts and regions.

Edit `policy.lua` after copying the preset to set real sandbox account and
region allowlists, adjust AWS service/action heuristics, or tune rate limits.
