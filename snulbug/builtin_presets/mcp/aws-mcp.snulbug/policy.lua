local fallback_token = "local-dev-secret"

-- Replace these sample values after copying the preset. Mutating AWS API tools
-- are blocked unless the request carries an explicit allowed account and region.
local sandbox_accounts = {
  "111122223333",
}

local sandbox_regions = {
  "us-east-1",
  "us-west-2",
}

local knowledge_tools = {
  "search_documentation",
  "read_documentation",
  "list_regions",
  "get_regional_availability",
  "retrieve_skill",
}

local read_methods = {
  ["initialize"] = true,
  ["notifications/initialized"] = true,
  ["tools/list"] = true,
  ["resources/list"] = true,
  ["resources/read"] = true,
  ["resources/templates/list"] = true,
  ["prompts/list"] = true,
  ["prompts/get"] = true,
  ["completion/complete"] = true,
  ["tasks/get"] = true,
  ["tasks/list"] = true,
  ["tasks/result"] = true,
  ["notifications/progress"] = true,
  ["notifications/cancelled"] = true,
  ["notifications/tasks/status"] = true,
}

local read_verbs = {
  "get",
  "list",
  "describe",
  "search",
  "read",
  "lookup",
  "query",
  "scan",
  "retrieve",
  "estimate",
  "validate",
  "simulate",
  "check",
}

local mutation_verbs = {
  "create",
  "put",
  "update",
  "delete",
  "remove",
  "start",
  "stop",
  "restart",
  "reboot",
  "terminate",
  "run",
  "invoke",
  "execute",
  "send",
  "publish",
  "tag",
  "untag",
  "attach",
  "detach",
  "associate",
  "disassociate",
  "enable",
  "disable",
  "modify",
  "set",
  "rotate",
  "restore",
  "revoke",
  "authorize",
}

local service_aliases = {
  { id = "cloudwatch", names = { "cloudwatch", "cw" } },
  { id = "cloudtrail", names = { "cloudtrail" } },
  { id = "logs", names = { "logs", "cloudwatchlogs", "cloudwatch_logs" } },
  { id = "xray", names = { "xray", "x_ray" } },
  { id = "pricing", names = { "pricing" } },
  { id = "costexplorer", names = { "costexplorer", "cost_explorer", "cost-and-usage", "cost_and_usage" } },
  { id = "billing", names = { "billing", "budgets", "cur" } },
  { id = "iam", names = { "iam" } },
  { id = "kms", names = { "kms" } },
  { id = "organizations", names = { "organizations", "orgs" } },
  { id = "accessanalyzer", names = { "accessanalyzer", "access_analyzer" } },
  { id = "sso", names = { "sso", "identitystore", "identity_store" } },
  { id = "secretsmanager", names = { "secretsmanager", "secrets_manager" } },
  { id = "sts", names = { "sts" } },
  { id = "ec2", names = { "ec2" } },
  { id = "ecs", names = { "ecs" } },
  { id = "eks", names = { "eks" } },
  { id = "lambda", names = { "lambda" } },
  { id = "apigateway", names = { "apigateway", "api_gateway", "apigw" } },
  { id = "cloudformation", names = { "cloudformation", "cloud_formation", "cfn" } },
  { id = "s3", names = { "s3" } },
  { id = "dynamodb", names = { "dynamodb", "dynamo_db" } },
  { id = "rds", names = { "rds" } },
  { id = "redshift", names = { "redshift" } },
  { id = "athena", names = { "athena" } },
  { id = "opensearch", names = { "opensearch", "open_search" } },
}

local observability_services = {
  cloudwatch = true,
  cloudtrail = true,
  logs = true,
  xray = true,
}

local cost_services = {
  pricing = true,
  costexplorer = true,
  billing = true,
}

local identity_services = {
  iam = true,
  kms = true,
  organizations = true,
  accessanalyzer = true,
  sso = true,
  secretsmanager = true,
  sts = true,
}

local sensitive_mutation_services = {
  iam = true,
  kms = true,
  organizations = true,
  accessanalyzer = true,
  sso = true,
  secretsmanager = true,
  sts = true,
  cloudtrail = true,
}

local data_access_terms = {
  "get_object",
  "getobject",
  "get_item",
  "getitem",
  "batch_get",
  "batchget",
  "query",
  "scan",
  "select_object",
  "selectobject",
  "execute_statement",
  "executestatement",
}

local function policy_token(context)
  return fallback_token
end

capabilities.declare({
  {
    id = "aws_knowledge",
    label = "AWS knowledge",
    description = "Allow AWS Knowledge and Documentation MCP tools for docs, regional availability, and skills.",
    default = true,
  },
  {
    id = "aws_inventory_read",
    label = "AWS inventory read",
    description = "Allow read-only AWS control-plane inventory calls such as List, Get, Describe, Search, and Validate.",
  },
  {
    id = "aws_observability_read",
    label = "AWS observability read",
    description = "Allow CloudWatch, CloudWatch Logs, CloudTrail, and X-Ray read/triage calls.",
  },
  {
    id = "aws_cost_read",
    label = "AWS cost read",
    description = "Allow Cost Explorer, Pricing, Billing, Budget, and CUR read-only calls.",
  },
  {
    id = "aws_identity_review",
    label = "AWS identity review",
    description = "Allow IAM, KMS, Organizations, Access Analyzer, SSO, and STS read-only review calls.",
  },
  {
    id = "aws_data_read",
    label = "AWS data read",
    description = "Allow data-plane reads such as S3 object reads, DynamoDB queries, scans, and SQL-like selects.",
  },
  {
    id = "aws_sandbox_change",
    label = "AWS sandbox change",
    description = "Allow confirm-gated non-identity mutations only in configured sandbox accounts and regions.",
  },
})

local function lower(value)
  if value == nil then
    return ""
  end
  return string.lower(tostring(value))
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function list_contains(values, value)
  if value == nil then
    return false
  end
  for _, candidate in ipairs(values) do
    if tostring(candidate) == tostring(value) then
      return true
    end
  end
  return false
end

local function configured(values)
  return type(values) == "table" and #values > 0
end

local function string_arg(call, names)
  local scopes = { call.args, call.params }
  for _, scope in ipairs(scopes) do
    if type(scope) == "table" then
      for _, name in ipairs(names) do
        local value = scope[name]
        if type(value) == "string" or type(value) == "number" then
          return tostring(value)
        end
      end
    end
  end
  return nil
end

local function last_segment(value)
  local text = tostring(value or "")
  local last = text
  for segment in string.gmatch(text, "[^%.:%-/]+") do
    last = segment
  end
  return last
end

local function action_from_tool(tool)
  local original = tostring(tool or "")
  local text = lower(original)
  for _, service in ipairs(service_aliases) do
    for _, name in ipairs(service.names) do
      local lowered = lower(name)
      local prefixes = {
        lowered .. "_",
        lowered .. ".",
        lowered .. ":",
        lowered .. "-",
        lowered .. "/",
      }
      for _, prefix in ipairs(prefixes) do
        if starts_with(text, prefix) then
          return string.sub(original, #prefix + 1)
        end
      end
    end
  end
  return last_segment(original)
end

local function name_has_term(value, terms)
  local text = lower(value)
  for _, term in ipairs(terms) do
    if string.find(text, lower(term), 1, true) ~= nil then
      return true
    end
  end
  return false
end

local function name_has_verb(value, verbs)
  local text = lower(value)
  for _, verb in ipairs(verbs) do
    local lowered = lower(verb)
    if starts_with(text, lowered)
      or string.find(text, "_" .. lowered, 1, true) ~= nil
      or string.find(text, "." .. lowered, 1, true) ~= nil
      or string.find(text, "-" .. lowered, 1, true) ~= nil
      or string.find(text, "/" .. lowered, 1, true) ~= nil
      or string.find(text, ":" .. lowered, 1, true) ~= nil then
      return true
    end
  end
  return false
end

local function aws_action(call)
  local explicit = string_arg(call, { "action", "Action", "operation", "api", "api_action", "aws_action" })
  if explicit ~= nil then
    return explicit
  end
  if call.tool ~= nil then
    return action_from_tool(call.tool)
  end
  return last_segment(call.method or "")
end

local function aws_service(call)
  local explicit = string_arg(call, { "service", "Service", "service_name", "aws_service" })
  if explicit ~= nil then
    return lower(explicit)
  end
  local tool = lower(call.tool or "")
  for _, service in ipairs(service_aliases) do
    for _, name in ipairs(service.names) do
      if string.find(tool, lower(name), 1, true) ~= nil then
        return service.id
      end
    end
  end
  return ""
end

local function aws_account(call)
  return string_arg(call, { "account", "account_id", "accountId", "aws_account", "awsAccountId" })
end

local function aws_region(call)
  return string_arg(call, { "region", "Region", "aws_region", "awsRegion" })
end

local function knowledge_tool(tool)
  if tool == nil then
    return false
  end
  if list_contains(knowledge_tools, tool) then
    return true
  end
  local text = lower(tool)
  return string.find(text, "documentation", 1, true) ~= nil
    or string.find(text, "knowledge", 1, true) ~= nil
    or string.find(text, "regional_availability", 1, true) ~= nil
    or string.find(text, "retrieve_skill", 1, true) ~= nil
end

local function is_read_action(call)
  if knowledge_tool(call.tool) then
    return true
  end
  return name_has_verb(call.tool or "", read_verbs) or name_has_verb(aws_action(call), read_verbs)
end

local function is_mutating_action(call)
  if knowledge_tool(call.tool) then
    return false
  end
  return name_has_verb(call.tool or "", mutation_verbs) or name_has_verb(aws_action(call), mutation_verbs)
end

local function is_data_access_read(call)
  return name_has_term(call.tool or "", data_access_terms) or name_has_term(aws_action(call), data_access_terms)
end

local function aws_context(call, capability, access_kind)
  local service = aws_service(call)
  local action = aws_action(call)
  return {
    policy = "mcp-aws",
    method = call.method or "",
    tool = call.tool or "",
    lease_id = lease.id() or "",
    capabilities = lease.capabilities(),
    aws = {
      service = service,
      action = action,
      account = aws_account(call) or "",
      region = aws_region(call) or "",
      capability = capability or "",
      access = access_kind or "",
      knowledge = knowledge_tool(call.tool),
      mutation = is_mutating_action(call),
      data_access = is_data_access_read(call),
    },
  }
end

local function reject_aws(call, reason_code, body, capability, access_kind)
  return decision.reject(403, body, {
    reason = body,
    reason_code = reason_code,
    context = aws_context(call, capability, access_kind),
  })
end

local function reject_capability(call, capability, access_kind)
  return access.lease_required({
    body = "AWS MCP tool requires a matching task capability",
    reason = "Active lease does not include the AWS capability required for this MCP tool",
    reason_code = "lease.capability_missing",
    context = aws_context(call, capability, access_kind),
  })
end

local function allow_with_rate_limit(token, call, capability, access_kind)
  return {
    action = "rate_limit",
    key = "mcp:aws:" .. token .. ":" .. tostring(capability or "protocol"),
    limit = 60,
    window = 60,
    body = "too many AWS MCP calls",
    reason = "MCP request is allowed by the AWS MCP policy pack",
    reason_code = "mcp.aws_allowed",
    context = aws_context(call, capability, access_kind),
  }
end

local function require_scope_for_reads(call)
  local service = aws_service(call)
  if is_data_access_read(call) then
    return "aws_data_read", "data_read"
  end
  if cost_services[service] == true then
    return "aws_cost_read", "cost_read"
  end
  if observability_services[service] == true then
    return "aws_observability_read", "observability_read"
  end
  if identity_services[service] == true then
    return "aws_identity_review", "identity_read"
  end
  return "aws_inventory_read", "inventory_read"
end

local function scope_block(call, capability, access_kind)
  local account = aws_account(call)
  local region = aws_region(call)
  if account ~= nil and configured(sandbox_accounts) and not list_contains(sandbox_accounts, account) then
    return reject_aws(call, "aws.account_denied", "AWS account is outside the policy allowlist", capability, access_kind)
  end
  if region ~= nil and configured(sandbox_regions) and not list_contains(sandbox_regions, region) then
    return reject_aws(call, "aws.region_denied", "AWS region is outside the policy allowlist", capability, access_kind)
  end
  return nil
end

local function mutation_scope_block(call)
  local account = aws_account(call)
  local region = aws_region(call)
  if not configured(sandbox_accounts) then
    return reject_aws(call, "aws.account_allowlist_required", "AWS sandbox mutations require configured account allowlist", "aws_sandbox_change", "mutation")
  end
  if account == nil or account == "" then
    return reject_aws(call, "aws.account_required", "AWS sandbox mutations require an explicit AWS account", "aws_sandbox_change", "mutation")
  end
  if not list_contains(sandbox_accounts, account) then
    return reject_aws(call, "aws.account_denied", "AWS account is outside the policy allowlist", "aws_sandbox_change", "mutation")
  end
  if not configured(sandbox_regions) then
    return reject_aws(call, "aws.region_allowlist_required", "AWS sandbox mutations require configured region allowlist", "aws_sandbox_change", "mutation")
  end
  if region == nil or region == "" then
    return reject_aws(call, "aws.region_required", "AWS sandbox mutations require an explicit AWS region", "aws_sandbox_change", "mutation")
  end
  if not list_contains(sandbox_regions, region) then
    return reject_aws(call, "aws.region_denied", "AWS region is outside the policy allowlist", "aws_sandbox_change", "mutation")
  end
  return nil
end

local function allow_tool_call(request, token, call)
  if knowledge_tool(call.tool) then
    if lease.enabled() and not lease.has_capability("aws_knowledge") then
      return reject_capability(call, "aws_knowledge", "knowledge")
    end
    return allow_with_rate_limit(token, call, "aws_knowledge", "knowledge")
  end

  if not lease.enabled() then
    return reject_aws(call, "aws.lease_required_for_api", "AWS API tools require a task-scoped lease capability", "aws_knowledge", "unknown")
  end

  local blocked = lease.require({
    reason_code = "lease.active_task_lease_required",
    body = "active AWS MCP task lease required",
    context = aws_context(call, "", "unknown"),
  })
  if blocked ~= nil then
    return blocked
  end

  local service = aws_service(call)
  if is_mutating_action(call) then
    if sensitive_mutation_services[service] == true then
      return reject_aws(call, "aws.sensitive_mutation_blocked", "AWS identity, secret, organization, or audit mutation is blocked", "aws_sandbox_change", "mutation")
    end
    if not lease.has_capability("aws_sandbox_change") then
      return reject_capability(call, "aws_sandbox_change", "mutation")
    end
    blocked = mutation_scope_block(call)
    if blocked ~= nil then
      return blocked
    end
    return decision.confirm("Allow AWS sandbox change " .. tostring(call.tool or aws_action(call)) .. "?", {
      reason = "AWS sandbox mutation requires live confirmation",
      reason_code = "aws.sandbox_change_confirm",
      remember_key = "aws:" .. service .. ":" .. lower(aws_action(call)),
      timeout_seconds = 60,
      context = aws_context(call, "aws_sandbox_change", "mutation"),
    })
  end

  if not is_read_action(call) then
    return reject_aws(call, "aws.action_unclassified", "AWS MCP tool is not classified as read-only or sandbox-mutating", "", "unknown")
  end

  local capability, access = require_scope_for_reads(call)
  if not lease.has_capability(capability) then
    return reject_capability(call, capability, access)
  end
  blocked = scope_block(call, capability, access)
  if blocked ~= nil then
    return blocked
  end
  return allow_with_rate_limit(token, call, capability, access)
end

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }
  end

  local token = policy_token(context)
  if request.headers.authorization ~= "Bearer " .. token then
    return {
      action = "challenge",
      scheme = "Bearer",
      realm = "aws-mcp",
      error = "invalid_token",
      body = "AWS MCP bearer token required",
      reason = "Missing or invalid AWS MCP bearer token",
      reason_code = "mcp.auth_required"
    }
  end

  local body = mcp.body(request)
  if type(body) ~= "table" then
    return {
      action = "reject",
      status = 400,
      body = "invalid MCP JSON-RPC request",
      reason = "MCP request body is not a JSON-RPC object",
      reason_code = "mcp.invalid_json"
    }
  end
  if type(body[1]) == "table" then
    return {
      action = "reject",
      status = 400,
      body = "MCP batch requests are disabled for AWS MCP policy pack",
      reason = "Batch JSON-RPC requests are disabled for AWS MCP exposure",
      reason_code = "mcp.batch_rejected"
    }
  end

  local call = mcp.call(request)
  if call.is_server_to_client_request then
    return reject_aws(call, "aws.server_to_client_blocked", "AWS MCP server-to-client requests require an explicit policy", "", "server_to_client")
  end
  if call.is_resource_subscription then
    return reject_aws(call, "aws.resource_subscription_blocked", "AWS resource subscriptions require an explicit policy", "", "subscription")
  end
  if call.method == "tasks/cancel" then
    return reject_aws(call, "aws.task_cancel_blocked", "AWS MCP task cancellation requires an explicit policy", "", "task_cancel")
  end

  if call.is_tool_call then
    return allow_tool_call(request, token, call)
  end

  if read_methods[call.method] == true then
    return allow_with_rate_limit(token, call, "aws_protocol", "protocol")
  end

  return reject_aws(call, "mcp.method_not_allowed", "MCP method is not allowed by AWS MCP policy pack: " .. tostring(call.method), "", "protocol")
end
