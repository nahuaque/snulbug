# AWS MCP policy pack

`aws-mcp` is a built-in policy pack for placing snulbug in front of AWS MCP
servers. It is designed for two AWS surfaces:

- the remote AWS Knowledge MCP Server for documentation, API references,
  regional availability, and AWS skills
- local or remote AWS API MCP servers that can inspect or change AWS resources

The pack does not replace AWS IAM, CloudTrail, or provider-side authorization.
It adds an MCP-aware control point before a client or agent can invoke AWS MCP
tools through a local-dev share.

## Create the policy

```bash
snulbug mcp policy preset aws-mcp --output policy.snulbug
snulbug bundle test policy.snulbug
```

For a share session:

```bash
snulbug mcp share create \
  --preset aws-mcp \
  --upstream https://knowledge-mcp.global.api.aws \
  --token local-dev-secret
```

For AWS API MCP servers running locally over stdio or HTTP, point `--upstream`
at the snulbug-facing MCP endpoint for that server or facade member.

## Capability labels

The policy declares invite capabilities so the share console can mint narrow
task leases:

- `aws_knowledge`: default; AWS docs, regional availability, and skills.
- `aws_inventory_read`: read-only control-plane inventory calls.
- `aws_observability_read`: CloudWatch, Logs, CloudTrail, and X-Ray triage.
- `aws_cost_read`: Cost Explorer, Pricing, Billing, Budgets, and CUR reads.
- `aws_identity_review`: IAM, KMS, Organizations, SSO, STS, and Access Analyzer
  reads.
- `aws_data_read`: data-plane reads such as S3 object reads, DynamoDB
  queries/scans, and SQL-like selects.
- `aws_sandbox_change`: confirm-gated non-sensitive mutations in configured
  sandbox accounts and regions.

Without a configured lease store, the preset only allows AWS Knowledge/docs
tools after bearer auth. Broader AWS API tools require an active task lease with
one of the declared capability labels.

## Guardrails

The first-cut classifier is intentionally conservative:

- AWS Knowledge tools such as `search_documentation`, `read_documentation`,
  `list_regions`, `get_regional_availability`, and `retrieve_skill` are allowed
  by the default capability.
- read-only verbs such as `Get`, `List`, `Describe`, `Search`, `Read`,
  `Lookup`, `Query`, `Scan`, `Retrieve`, `Estimate`, `Validate`, and `Simulate`
  are mapped to the narrowest AWS read capability the policy can infer.
- data-plane reads such as S3 `GetObject`, DynamoDB `Query`/`Scan`, and
  SQL-like `ExecuteStatement` require `aws_data_read`, not generic inventory
  read.
- IAM, KMS, Organizations, Access Analyzer, SSO, STS, and Secrets Manager reads
  require `aws_identity_review`.
- identity, secret, organization, and audit mutations are blocked.
- other mutating verbs require `aws_sandbox_change`, an allowed account, an
  allowed region, and live confirmation.

After copying the preset, edit `policy.lua` to replace the sample sandbox
account and region allowlists:

```lua
local sandbox_accounts = {
  "123456789012",
}

local sandbox_regions = {
  "us-east-1",
}
```

## What this enables

The useful product loop is:

```text
record AWS MCP traffic -> learn observed tools -> apply aws-mcp guardrails
  -> invite with narrow AWS capability labels -> review audit/CloudTrail evidence
```

The natural next integration is evidence-to-policy: record AWS MCP usage,
classify service/action/account/region/resource patterns, and generate both a
snulbug policy amendment and an IAM session-policy or permission-boundary
suggestion for review.
