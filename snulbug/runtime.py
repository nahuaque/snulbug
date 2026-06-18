from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any


class LuaRuntimeError(RuntimeError):
    """Raised when the Lua engine cannot load or execute a script."""


class LuaDecisionError(ValueError):
    """Raised when a script returns an invalid middleware decision."""


LuaValue = str | int | float | bool | None | list["LuaValue"] | dict[str, "LuaValue"]


@dataclass(frozen=True)
class LuaDecisionTrace:
    """Execution trace for one Lua policy decision."""

    decision: dict[str, Any]
    source_name: str
    duration_ms: float
    instruction_count: int
    state_operations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "duration_ms": self.duration_ms,
            "instruction_count": self.instruction_count,
            "state_operations": self.state_operations,
        }


@dataclass(frozen=True)
class CompiledLuaScript:
    """A compiled Lua policy script."""

    source_name: str
    _runtime: Any = field(repr=False)
    _handler: Any = field(repr=False)

    def decide(self, request: Mapping[str, Any], context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.decide_with_trace(request, context).decision

    def decide_with_trace(
        self,
        request: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        state: Any = None,
    ) -> LuaDecisionTrace:
        request_table = _to_lua(self._runtime, request)
        context_table = _to_lua(self._runtime, context or {})
        state_table = _to_lua(self._runtime, _state_api(state))

        started_at = perf_counter()
        try:
            result = self._handler(request_table, context_table, state_table)
        except LuaDecisionError:
            raise
        except Exception as exc:  # Lupa raises LuaError, but do not import it at module import time.
            raise LuaRuntimeError(f"Lua script {self.source_name!r} failed: {exc}") from exc
        duration_ms = (perf_counter() - started_at) * 1000

        execution = _from_lua(result)
        if not isinstance(execution, dict):
            raise LuaDecisionError("Lua runtime returned an invalid execution result")

        decision = _normalize_decision(execution.get("decision"))
        instruction_count = execution.get("instruction_count", 0)
        if not isinstance(instruction_count, int):
            raise LuaDecisionError("Lua runtime returned an invalid instruction count")

        return LuaDecisionTrace(
            decision=decision,
            source_name=self.source_name,
            duration_ms=duration_ms,
            instruction_count=instruction_count,
            state_operations=[dict(operation) for operation in getattr(state, "operations", [])],
        )


def _normalize_decision(decision: Any) -> dict[str, Any]:
    if decision is None:
        decision = {"action": "continue"}
    if isinstance(decision, str):
        decision = {"action": decision}
    if not isinstance(decision, dict):
        raise LuaDecisionError("Lua script must return a table, action string, or nil")

    action = decision.get("action", "continue")
    if not isinstance(action, str):
        raise LuaDecisionError("Lua decision field 'action' must be a string")
    decision["action"] = action
    for metadata_field in ("reason", "reason_code"):
        if metadata_field in decision and not isinstance(decision[metadata_field], str):
            raise LuaDecisionError(f"Lua decision field {metadata_field!r} must be a string")
    return decision


def compile_lua_script(
    source: str,
    *,
    source_name: str = "<snulbug>",
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> CompiledLuaScript:
    """Compile a Lua policy script in a narrow sandbox.

    Scripts must return a function with this shape:

        return function(request, context, state)
          return { action = "continue" }
        end

    The script sees only safe standard-library globals and the request/context
    tables passed to the returned function. When configured, the state argument
    contains a narrow capability table. Python objects are recursively converted
    to Lua tables before execution.
    """

    try:
        from lupa import LuaRuntime  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - exercised only without the optional runtime installed.
        raise LuaRuntimeError(
            "snulbug requires the 'lupa' package to execute Lua scripts. "
            "Install this project with its runtime dependencies."
        ) from exc

    runtime_kwargs: dict[str, Any] = {
        "unpack_returned_tuples": True,
        "register_eval": False,
        "register_builtins": False,
    }
    if memory_limit_bytes is not None:
        runtime_kwargs["max_memory"] = memory_limit_bytes

    try:
        runtime = LuaRuntime(**runtime_kwargs)
    except TypeError:
        runtime_kwargs.pop("max_memory", None)
        runtime = LuaRuntime(**runtime_kwargs)
        if memory_limit_bytes is not None and hasattr(runtime, "set_max_memory"):
            runtime.set_max_memory(memory_limit_bytes)

    loader = runtime.execute(_LOADER)
    try:
        handler = loader(source, source_name, int(instruction_limit))
    except Exception as exc:
        raise LuaRuntimeError(f"Could not compile Lua script {source_name!r}: {exc}") from exc

    return CompiledLuaScript(source_name=source_name, _runtime=runtime, _handler=handler)


def compile_lua_file(
    path: str | Path,
    *,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> CompiledLuaScript:
    lua_path = Path(path)
    return compile_lua_script(
        lua_path.read_text(encoding="utf-8"),
        source_name=str(lua_path),
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )


def _to_lua(runtime: Any, value: Any) -> Any:
    if isinstance(value, Mapping):
        return runtime.table_from({str(k): _to_lua(runtime, v) for k, v in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return runtime.table_from([_to_lua(runtime, item) for item in value])
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return value


def _state_api(state: Any) -> Any:
    if state is None:
        return {}
    if hasattr(state, "lua_api"):
        return state.lua_api()
    return state


def _from_lua(value: Any) -> Any:
    if _is_lua_table(value):
        keys = list(value.keys())
        if keys and all(isinstance(key, int) for key in keys):
            max_key = max(keys)
            if sorted(keys) == list(range(1, max_key + 1)):
                return [_from_lua(value[index]) for index in range(1, max_key + 1)]
        return {str(key): _from_lua(value[key]) for key in keys}
    return value


def _is_lua_table(value: Any) -> bool:
    return hasattr(value, "keys") and hasattr(value, "__getitem__") and not isinstance(value, dict)


_LOADER = r"""
return function(source, source_name, instruction_limit)
  local safe_env = {
    assert = assert,
    error = error,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = pcall,
    select = select,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    unpack = unpack or table.unpack,
    math = {
      abs = math.abs,
      ceil = math.ceil,
      floor = math.floor,
      max = math.max,
      min = math.min,
      random = math.random,
      sqrt = math.sqrt,
    },
    string = {
      byte = string.byte,
      char = string.char,
      find = string.find,
      format = string.format,
      gmatch = string.gmatch,
      gsub = string.gsub,
      len = string.len,
      lower = string.lower,
      match = string.match,
      rep = string.rep,
      sub = string.sub,
      upper = string.upper,
    },
    table = {
      concat = table.concat,
      insert = table.insert,
      remove = table.remove,
      sort = table.sort,
    },
  }

  local json_null = {}

  local function json_error(message)
    error("invalid JSON body: " .. message, 0)
  end

  local function json_skip_ws(source, index)
    while true do
      local char = string.sub(source, index, index)
      if char == " " or char == "\n" or char == "\r" or char == "\t" then
        index = index + 1
      else
        return index
      end
    end
  end

  local function json_parse_string(source, index)
    local result = {}
    index = index + 1
    while index <= #source do
      local char = string.sub(source, index, index)
      if char == '"' then
        return table.concat(result), index + 1
      end
      if char == "\\" then
        local escape = string.sub(source, index + 1, index + 1)
        if escape == '"' or escape == "\\" or escape == "/" then
          table.insert(result, escape)
          index = index + 2
        elseif escape == "b" then
          table.insert(result, "\b")
          index = index + 2
        elseif escape == "f" then
          table.insert(result, "\f")
          index = index + 2
        elseif escape == "n" then
          table.insert(result, "\n")
          index = index + 2
        elseif escape == "r" then
          table.insert(result, "\r")
          index = index + 2
        elseif escape == "t" then
          table.insert(result, "\t")
          index = index + 2
        elseif escape == "u" then
          local hex = string.sub(source, index + 2, index + 5)
          if not string.match(hex, "^%x%x%x%x$") then
            json_error("bad unicode escape")
          end
          local codepoint = tonumber(hex, 16)
          if codepoint < 128 then
            table.insert(result, string.char(codepoint))
          else
            table.insert(result, "?")
          end
          index = index + 6
        else
          json_error("bad string escape")
        end
      else
        table.insert(result, char)
        index = index + 1
      end
    end
    json_error("unterminated string")
  end

  local json_parse_value

  local function json_parse_array(source, index)
    local result = {}
    index = json_skip_ws(source, index + 1)
    if string.sub(source, index, index) == "]" then
      return result, index + 1
    end
    while true do
      local value
      value, index = json_parse_value(source, index)
      table.insert(result, value)
      index = json_skip_ws(source, index)
      local char = string.sub(source, index, index)
      if char == "]" then
        return result, index + 1
      end
      if char ~= "," then
        json_error("expected ',' or ']' in array")
      end
      index = json_skip_ws(source, index + 1)
    end
  end

  local function json_parse_object(source, index)
    local result = {}
    index = json_skip_ws(source, index + 1)
    if string.sub(source, index, index) == "}" then
      return result, index + 1
    end
    while true do
      if string.sub(source, index, index) ~= '"' then
        json_error("expected object key")
      end
      local key
      key, index = json_parse_string(source, index)
      index = json_skip_ws(source, index)
      if string.sub(source, index, index) ~= ":" then
        json_error("expected ':' after object key")
      end
      index = json_skip_ws(source, index + 1)
      result[key], index = json_parse_value(source, index)
      index = json_skip_ws(source, index)
      local char = string.sub(source, index, index)
      if char == "}" then
        return result, index + 1
      end
      if char ~= "," then
        json_error("expected ',' or '}' in object")
      end
      index = json_skip_ws(source, index + 1)
    end
  end

  local function json_parse_number(source, index)
    local start = index
    local char = string.sub(source, index, index)
    if char == "-" then
      index = index + 1
    end
    while string.match(string.sub(source, index, index), "%d") do
      index = index + 1
    end
    if string.sub(source, index, index) == "." then
      index = index + 1
      while string.match(string.sub(source, index, index), "%d") do
        index = index + 1
      end
    end
    char = string.sub(source, index, index)
    if char == "e" or char == "E" then
      index = index + 1
      char = string.sub(source, index, index)
      if char == "+" or char == "-" then
        index = index + 1
      end
      while string.match(string.sub(source, index, index), "%d") do
        index = index + 1
      end
    end
    local value = tonumber(string.sub(source, start, index - 1))
    if value == nil then
      json_error("bad number")
    end
    return value, index
  end

  function json_parse_value(source, index)
    index = json_skip_ws(source, index)
    local char = string.sub(source, index, index)
    if char == '"' then
      return json_parse_string(source, index)
    end
    if char == "{" then
      return json_parse_object(source, index)
    end
    if char == "[" then
      return json_parse_array(source, index)
    end
    if string.sub(source, index, index + 3) == "true" then
      return true, index + 4
    end
    if string.sub(source, index, index + 4) == "false" then
      return false, index + 5
    end
    if string.sub(source, index, index + 3) == "null" then
      return json_null, index + 4
    end
    return json_parse_number(source, index)
  end

  local function json_decode(source)
    if type(source) ~= "string" or source == "" then
      return nil
    end
    local value, index = json_parse_value(source, 1)
    index = json_skip_ws(source, index)
    if index <= #source then
      json_error("trailing content")
    end
    return value
  end

  local function options_table(options)
    if type(options) == "table" then
      return options
    end
    return {}
  end

  local function copy_option(result, options, key)
    if options[key] ~= nil then
      result[key] = options[key]
    end
  end

  local function copy_options(options)
    local copied = {}
    options = options_table(options)
    for key, value in pairs(options) do
      copied[key] = value
    end
    return copied
  end

  local function with_options(result, options)
    options = options_table(options)
    copy_option(result, options, "reason")
    copy_option(result, options, "reason_code")
    copy_option(result, options, "context")
    copy_option(result, options, "headers")
    copy_option(result, options, "capability_request")
    return result
  end

  local function with_confirmation_options(result, options)
    options = options_table(options)
    copy_option(result, options, "confirm")
    copy_option(result, options, "prompt")
    copy_option(result, options, "remember_key")
    copy_option(result, options, "timeout_seconds")
    return result
  end

  local function list_contains(values, needle)
    if type(values) ~= "table" or needle == nil then
      return false
    end
    if values[needle] == true then
      return true
    end
    for _, value in ipairs(values) do
      if value == needle then
        return true
      end
    end
    return false
  end

  local function value_matches(value, allowed)
    if value == nil then
      return false
    end
    if type(allowed) == "table" then
      return list_contains(allowed, value)
    end
    return value == allowed
  end

  local function table_is_array(value)
    if type(value) ~= "table" then
      return false
    end
    return type(value[1]) == "table"
  end

  local function starts_with(value, prefix)
    return string.sub(value, 1, #prefix) == prefix
  end

  local function ends_with(value, suffix)
    return suffix == "" or string.sub(value, -#suffix) == suffix
  end

  local function selector_matches(configured, requested)
    if type(configured) ~= "string" or type(requested) ~= "string" then
      return false
    end
    if configured == requested or configured == "*" then
      return true
    end
    if ends_with(configured, "*") then
      return starts_with(requested, string.sub(configured, 1, #configured - 1))
    end
    return false
  end

  local decision = {}

  decision["continue"] = function(options)
    return with_options({ action = "continue" }, options)
  end

  function decision.allow(reason_code, context)
    if type(reason_code) == "table" then
      return decision["continue"](reason_code)
    end
    return decision["continue"]({
      reason_code = reason_code,
      context = context,
    })
  end

  function decision.set_context(context, options)
    local result = { action = "set_context", context = context or {} }
    return with_options(result, options)
  end

  function decision.respond(status, body, options)
    local result = {
      action = "respond",
      status = status or 200,
      body = body or "",
    }
    return with_options(result, options)
  end

  function decision.reject(status, body, options)
    local message = body or "forbidden"
    local result = {
      action = "reject",
      status = status or 403,
      body = message,
      reason = message,
    }
    return with_confirmation_options(with_options(result, options), options)
  end

  function decision.challenge(options)
    options = options_table(options)
    local result = {
      action = "challenge",
      status = options.status or 401,
      body = options.body or "authentication required",
    }
    copy_option(result, options, "scheme")
    copy_option(result, options, "realm")
    copy_option(result, options, "error")
    copy_option(result, options, "error_description")
    return with_options(result, options)
  end

  function decision.redirect(location, options)
    local result = {
      action = "redirect",
      location = location,
      status = options_table(options).status or 307,
    }
    return with_options(result, options)
  end

  function decision.rate_limit(key, limit, window, options)
    local result = {
      action = "rate_limit",
      key = key,
      limit = limit,
      window = window,
    }
    return with_options(result, options)
  end

  function decision.confirm(prompt, options)
    options = options_table(options)
    local result = {
      action = "confirm",
      prompt = prompt or options.prompt,
      status = options.status or 403,
      body = options.body or "confirmation denied",
    }
    copy_option(result, options, "remember_key")
    copy_option(result, options, "timeout_seconds")
    return with_options(result, options)
  end

  safe_env.decision = decision

  local current_auth = {}
  local current_lease = {}
  local current_request = {}
  local current_share = {}
  local current_upstream = {}
  local current_intent = {}

  local function merge_context(defaults, context)
    local merged = {}
    if type(defaults) == "table" then
      for key, value in pairs(defaults) do
        merged[key] = value
      end
    end
    if type(context) == "table" then
      for key, value in pairs(context) do
        merged[key] = value
      end
    end
    return merged
  end

  local function access_challenge(defaults, options)
    options = copy_options(options)
    options.status = options.status or defaults.status or 401
    options.body = options.body or defaults.body or "authentication required"
    options.reason = options.reason or defaults.reason or options.body
    options.reason_code = options.reason_code or defaults.reason_code
    options.context = merge_context(defaults.context, options.context)
    options.error = options.error or defaults.error
    options.error_description = options.error_description or defaults.error_description
    return decision.challenge(options)
  end

  local function access_reject(defaults, options)
    options = copy_options(options)
    local body = options.body or defaults.body or "forbidden"
    options.reason = options.reason or defaults.reason or body
    options.reason_code = options.reason_code or defaults.reason_code
    options.context = merge_context(defaults.context, options.context)
    return decision.reject(options.status or defaults.status or 403, body, options)
  end

  local function lease_context()
    return {
      lease_id = current_lease.id,
      lease_task = current_lease.task,
      lease_reason_code = current_lease.reason_code,
      lease_required = current_lease.required,
      lease_expires_at = current_lease.expires_at,
    }
  end

  local function share_context(details)
    return merge_context({
      contract_digest = current_share.contract_digest,
      contract_binding_digest = current_share.contract_binding_digest,
      contract_document_digest = current_share.contract_document_digest,
      contract_key_id = current_share.contract_key_id,
      contract_required = current_share.contract_required,
      contract_signed = current_share.contract_signed,
      contract_verified = current_share.contract_verified,
      contract_runtime_status = current_share.contract_runtime_status,
    }, details)
  end

  local function upstream_context(details)
    return merge_context({
      upstream = current_upstream.name,
      required_upstream = nil,
      tool = current_upstream.tool,
      upstream_tool = current_upstream.upstream_tool,
      tool_prefix = current_upstream.tool_prefix,
      transport = current_upstream.transport,
      route_revision = current_upstream.route_revision,
      route_fingerprint = current_upstream.route_fingerprint,
      tenant = current_auth.tenant,
      issuer = current_auth.issuer,
      profile_id = current_auth.profile_id,
    }, details)
  end

  local access = {}

  function access.missing_scope(scope, options)
    return access_challenge({
      body = "insufficient scope",
      reason_code = "oauth.missing_scope",
      error = "insufficient_scope",
      context = {
        missing_scope = scope,
        required_scope = scope,
      },
    }, options)
  end

  function access.scope_denied(selector, options)
    return access_challenge({
      body = "insufficient scope",
      reason_code = "oauth.scope_map_denied",
      error = "insufficient_scope",
      context = {
        selector = selector,
      },
    }, options)
  end

  function access.wrong_subject(subjects, options)
    return access_reject({
      body = "subject not allowed",
      reason_code = "oauth.subject_denied",
      context = {
        subject = current_auth.subject,
        required_subject = subjects,
      },
    }, options)
  end

  function access.wrong_tenant(tenants, options)
    return access_reject({
      body = "tenant not allowed",
      reason_code = "oauth.tenant_denied",
      context = {
        tenant = current_auth.tenant,
        required_tenant = tenants,
      },
    }, options)
  end

  function access.wrong_group(groups, options)
    local current_groups = {}
    if type(current_auth.groups) == "table" then
      current_groups = current_auth.groups
    end
    return access_reject({
      body = "group not allowed",
      reason_code = "oauth.group_denied",
      context = {
        groups = current_groups,
        required_group = groups,
      },
    }, options)
  end

  function access.lease_required(options)
    return access_reject({
      body = "active task lease required",
      reason_code = current_lease.reason_code or "lease.required",
      context = lease_context(),
    }, options)
  end

  function access.expired_lease(options)
    return access_reject({
      body = "task lease expired",
      reason_code = "lease.expired",
      context = lease_context(),
    }, options)
  end

  function access.contract_required(options)
    return access_reject({
      body = "approved share contract required",
      reason_code = "share.contract_required",
      context = share_context(),
    }, options)
  end

  function access.contract_mismatch(details, options)
    if type(details) ~= "table" then
      details = { required_contract_digest = details }
    end
    return access_reject({
      body = "share contract mismatch",
      reason_code = "share.contract_mismatch",
      context = share_context(details),
    }, options)
  end

  function access.route_mismatch(details, options)
    if type(details) ~= "table" then
      details = { route = details }
    end
    return access_reject({
      body = "route not allowed for caller",
      reason_code = "access.route_mismatch",
      context = upstream_context(details),
    }, options)
  end

  safe_env.access = access

  local function set_auth_context(context)
    if type(context) == "table" and type(context.auth) == "table" then
      current_auth = context.auth
    else
      current_auth = {}
    end
  end

  local auth = {}

  function auth.claims()
    return current_auth
  end

  function auth.subject()
    return current_auth.subject
  end

  function auth.issuer()
    return current_auth.issuer
  end

  function auth.profile_id()
    return current_auth.profile_id
  end

  function auth.client_id()
    return current_auth.client_id
  end

  function auth.email()
    return current_auth.email
  end

  function auth.tenant()
    return current_auth.tenant
  end

  function auth.groups()
    if type(current_auth.groups) == "table" then
      return current_auth.groups
    end
    return {}
  end

  function auth.is_subject(subjects)
    return value_matches(auth.subject(), subjects)
  end

  function auth.in_tenant(tenants)
    return value_matches(auth.tenant(), tenants)
  end

  function auth.has_group(groups)
    if type(groups) == "table" then
      for _, group in ipairs(groups) do
        if list_contains(auth.groups(), group) then
          return true
        end
      end
      return false
    end
    return list_contains(auth.groups(), groups)
  end

  local function auth_provider(name)
    if type(current_auth.provider) == "table" and type(current_auth.provider[name]) == "table" then
      return current_auth.provider[name]
    end
    return {}
  end

  local function provider_list(provider_name, key)
    local provider = auth_provider(provider_name)
    if type(provider[key]) == "table" then
      return provider[key]
    end
    return {}
  end

  function auth.keycloak_realm_roles()
    return provider_list("keycloak", "realm_roles")
  end

  function auth.keycloak_client_roles(client_id)
    local keycloak = auth_provider("keycloak")
    local client_roles = keycloak.client_roles
    if type(client_roles) ~= "table" then
      return {}
    end
    local roles = client_roles[client_id]
    if type(roles) == "table" then
      return roles
    end
    return {}
  end

  function auth.keycloak_has_role(role, client_id)
    if client_id ~= nil then
      return list_contains(auth.keycloak_client_roles(client_id), role)
    end
    if list_contains(auth.keycloak_realm_roles(), role) then
      return true
    end
    local keycloak = auth_provider("keycloak")
    if type(keycloak.client_roles) == "table" then
      for _, roles in pairs(keycloak.client_roles) do
        if list_contains(roles, role) then
          return true
        end
      end
    end
    return false
  end

  function auth.cloudflare_email()
    return auth_provider("cloudflare_access").email
  end

  function auth.cloudflare_jwt_validated()
    return auth_provider("cloudflare_access").jwt_validated == true
  end

  function auth.cloudflare_subject()
    return auth_provider("cloudflare_access").jwt_subject
  end

  function auth.cloudflare_groups()
    return provider_list("cloudflare_access", "groups")
  end

  function auth.cloudflare_has_group(groups)
    if type(groups) == "table" then
      for _, group in ipairs(groups) do
        if list_contains(auth.cloudflare_groups(), group) then
          return true
        end
      end
      return false
    end
    return list_contains(auth.cloudflare_groups(), groups)
  end

  local function github_actions()
    return auth_provider("github_actions")
  end

  function auth.github_repository()
    return github_actions().repository
  end

  function auth.github_workflow()
    return github_actions().workflow
  end

  function auth.github_workflow_ref()
    return github_actions().workflow_ref
  end

  function auth.github_job_workflow_ref()
    return github_actions().job_workflow_ref
  end

  function auth.github_ref()
    return github_actions().ref
  end

  function auth.github_event_name()
    return github_actions().event_name
  end

  function auth.github_matches(options)
    options = options_table(options)
    local github = github_actions()
    local fields = {
      "repository",
      "repository_owner",
      "workflow",
      "workflow_ref",
      "job_workflow_ref",
      "ref",
      "event_name",
      "actor",
      "environment",
    }
    for _, field in ipairs(fields) do
      if options[field] ~= nil and not value_matches(github[field], options[field]) then
        return false
      end
    end
    return true
  end

  function auth.entra_groups()
    return provider_list("entra", "groups")
  end

  function auth.entra_has_group(groups)
    if type(groups) == "table" then
      for _, group in ipairs(groups) do
        if list_contains(auth.entra_groups(), group) then
          return true
        end
      end
      return false
    end
    return list_contains(auth.entra_groups(), groups)
  end

  function auth.entra_app_roles()
    return provider_list("entra", "app_roles")
  end

  function auth.entra_has_app_role(roles)
    if type(roles) == "table" then
      for _, role in ipairs(roles) do
        if list_contains(auth.entra_app_roles(), role) then
          return true
        end
      end
      return false
    end
    return list_contains(auth.entra_app_roles(), roles)
  end

  function auth.entra_tenant_id()
    return auth_provider("entra").tenant_id
  end

  function auth.entra_app_id()
    return auth_provider("entra").app_id
  end

  function auth.scopes()
    if type(current_auth.scopes) == "table" then
      return current_auth.scopes
    end
    return {}
  end

  function auth.has_scope(scope)
    return list_contains(auth.scopes(), scope)
  end

  function auth.can(selector)
    if type(current_auth.scope_map) ~= "table" then
      return false
    end
    for _, scope in ipairs(auth.scopes()) do
      local selectors = current_auth.scope_map[scope]
      if type(selectors) == "table" then
        for _, configured in ipairs(selectors) do
          if selector_matches(configured, selector) then
            return true
          end
        end
      end
    end
    return false
  end

  function auth.require_scope(scope, options)
    if auth.has_scope(scope) then
      return nil
    end
    return access.missing_scope(scope, options)
  end

  function auth.require_subject(subjects, options)
    if auth.is_subject(subjects) then
      return nil
    end
    return access.wrong_subject(subjects, options)
  end

  function auth.require_tenant(tenants, options)
    if auth.in_tenant(tenants) then
      return nil
    end
    return access.wrong_tenant(tenants, options)
  end

  function auth.require_group(groups, options)
    if auth.has_group(groups) then
      return nil
    end
    return access.wrong_group(groups, options)
  end

  function auth.require(selector, options)
    if auth.can(selector) then
      return nil
    end
    return access.scope_denied(selector, options)
  end

  safe_env.auth = auth

  local function set_upstream_context(context)
    if type(context) == "table" and type(context.upstream) == "table" then
      current_upstream = context.upstream
    else
      current_upstream = {}
    end
  end

  local upstream = {}

  function upstream.info()
    return current_upstream
  end

  function upstream.matched()
    return current_upstream.matched == true
  end

  function upstream.name()
    return current_upstream.name
  end

  function upstream.transport()
    return current_upstream.transport
  end

  function upstream.tool_prefix()
    return current_upstream.tool_prefix
  end

  function upstream.tool()
    return current_upstream.tool
  end

  function upstream.upstream_tool()
    return current_upstream.upstream_tool
  end

  function upstream.manifest_identity()
    return current_upstream.manifest_identity
  end

  function upstream.is(upstreams)
    return value_matches(upstream.name(), upstreams)
  end

  local function allowed_upstreams_for_identity(mapping, identity)
    if type(mapping) ~= "table" then
      return nil
    end
    local allowed = mapping[identity]
    if allowed == nil then
      allowed = mapping["*"]
    end
    return allowed
  end

  function upstream.require(upstreams, options)
    if upstream.is(upstreams) then
      return nil
    end
    return access.route_mismatch({
      required_upstream = upstreams,
    }, options)
  end

  function upstream.require_for_tenant(mapping, options)
    local tenant = auth.tenant()
    local allowed = allowed_upstreams_for_identity(mapping, tenant)
    if allowed ~= nil and upstream.is(allowed) then
      return nil
    end
    return access.route_mismatch({
      policy_dimension = "tenant",
      tenant = tenant,
      required_upstream = allowed,
    }, options)
  end

  function upstream.require_for_issuer(mapping, options)
    local issuer = auth.issuer()
    local allowed = allowed_upstreams_for_identity(mapping, issuer)
    if allowed ~= nil and upstream.is(allowed) then
      return nil
    end
    return access.route_mismatch({
      policy_dimension = "issuer",
      issuer = issuer,
      required_upstream = allowed,
    }, options)
  end

  function upstream.require_for_auth_profile(mapping, options)
    local profile_id = auth.profile_id()
    local allowed = allowed_upstreams_for_identity(mapping, profile_id)
    if allowed ~= nil and upstream.is(allowed) then
      return nil
    end
    return access.route_mismatch({
      policy_dimension = "auth_profile",
      profile_id = profile_id,
      required_upstream = allowed,
    }, options)
  end

  safe_env.upstream = upstream

  local function set_share_context(context)
    if type(context) == "table" and type(context.share) == "table" then
      current_share = context.share
    else
      current_share = {}
    end
  end

  local share = {}

  function share.info()
    return current_share
  end

  function share.bound()
    return current_share.contract_runtime_status == "bound"
      and current_share.contract_digest ~= nil
      and current_share.contract_digest ~= ""
  end

  function share.required()
    return current_share.contract_required == true
  end

  function share.signed()
    return current_share.contract_signed == true
  end

  function share.verified()
    return current_share.contract_verified == true
  end

  function share.runtime_status()
    return current_share.contract_runtime_status
  end

  function share.contract_digest()
    return current_share.contract_digest
  end

  function share.binding_digest()
    return current_share.contract_binding_digest or current_share.contract_digest
  end

  function share.document_digest()
    return current_share.contract_document_digest
  end

  function share.key_id()
    return current_share.contract_key_id
  end

  function share.require_contract_bound(options)
    if share.bound() then
      return nil
    end
    return access.contract_required(options)
  end

  function share.require_contract_digest(digest, options)
    if value_matches(share.contract_digest(), digest) or value_matches(share.binding_digest(), digest) then
      return nil
    end
    return access.contract_mismatch({
      required_contract_digest = digest,
      actual_contract_digest = share.contract_digest(),
      actual_contract_binding_digest = share.binding_digest(),
    }, options)
  end

  function share.require_contract_key_id(key_id, options)
    if value_matches(share.key_id(), key_id) then
      return nil
    end
    return access.contract_mismatch({
      required_contract_key_id = key_id,
      actual_contract_key_id = share.key_id(),
    }, options)
  end

  safe_env.share = share

  local function set_lease_context(context)
    if type(context) == "table" and type(context.lease) == "table" then
      current_lease = context.lease
    else
      current_lease = {}
    end
  end

  local lease = {}

  function lease.info()
    return current_lease
  end

  function lease.enabled()
    return current_lease.enabled == true
  end

  function lease.required()
    return current_lease.required == true
  end

  function lease.checked()
    return current_lease.checked == true
  end

  function lease.allowed()
    return current_lease.allowed == true
  end

  function lease.active()
    return lease.allowed()
  end

  function lease.id()
    return current_lease.id
  end

  function lease.task()
    return current_lease.task
  end

  function lease.capabilities()
    if type(current_lease.capabilities) == "table" then
      return current_lease.capabilities
    end
    return {}
  end

  function lease.has_capability(name)
    if type(name) ~= "string" then
      return false
    end
    local capabilities = lease.capabilities()
    for _, capability in ipairs(capabilities) do
      if capability == name then
        return true
      end
    end
    return false
  end

  function lease.reason_code()
    return current_lease.reason_code
  end

  function lease.require(options)
    if not lease.enabled() then
      return nil
    end
    if current_lease.method ~= "tools/call" then
      return nil
    end
    if lease.allowed() then
      return nil
    end
    if current_lease.reason_code == "lease.expired" then
      return access.expired_lease(options)
    end
    return access.lease_required(options)
  end

  safe_env.lease = lease

  local mcp = {}

  function mcp.body(request)
    if request.__mcp_body_cached then
      return request.__mcp_body
    end
    local ok, value = pcall(json_decode, request.body or "")
    request.__mcp_body_cached = true
    if not ok or type(value) ~= "table" then
      return nil
    end
    request.__mcp_body = value
    return value
  end

  function mcp.call(request)
    if request.__mcp_call_cached then
      return request.__mcp_call
    end

    local body = mcp.body(request)
    local call = {
      body = body,
      params = {},
      args = {},
      invalid = false,
      batch = false,
      is_tool_call = false,
      is_read = false,
      is_write = false,
    }
    request.__mcp_call_cached = true
    request.__mcp_call = call

    if type(body) ~= "table" then
      call.invalid = true
      call.error = "invalid MCP JSON-RPC body"
      return call
    end

    if table_is_array(body) then
      call.batch = true
      call.error = "batch JSON-RPC request"
      return call
    end

    call.id = body.id
    if type(body.method) ~= "string" then
      call.invalid = true
      call.error = "missing JSON-RPC method"
      return call
    end

    call.method = body.method
    if type(body.params) == "table" then
      call.params = body.params
    end

    if call.method == "tools/call" then
      call.is_tool_call = true
      call.is_write = true
      if type(call.params.name) == "string" then
        call.tool = call.params.name
      end
      if type(call.params.arguments) == "table" then
        call.args = call.params.arguments
      end
      return call
    end

    if call.method == "resources/read" then
      call.is_read = true
      if type(call.params.uri) == "string" then
        call.resource_uri = call.params.uri
      end
      return call
    end

    if call.method == "prompts/get" then
      call.is_read = true
      if type(call.params.name) == "string" then
        call.prompt = call.params.name
      end
      if type(call.params.arguments) == "table" then
        call.args = call.params.arguments
      end
      return call
    end

    if call.method == "tools/list"
      or call.method == "resources/list"
      or call.method == "resources/templates/list"
      or call.method == "prompts/list" then
      call.is_read = true
    end

    return call
  end

  function mcp.method(request)
    return mcp.call(request).method
  end

  function mcp.params(request)
    return mcp.call(request).params
  end

  local function mcp_call_from(value)
    if type(value) ~= "table" then
      return { args = {} }
    end
    if type(value.args) == "table" and (value.method ~= nil or value.is_tool_call ~= nil or value.params ~= nil) then
      return value
    end
    return mcp.call(value)
  end

  function mcp.arg(request_or_call, key)
    local call = mcp_call_from(request_or_call)
    if type(call.args) ~= "table" then
      return nil
    end
    return call.args[key]
  end

  function mcp.arg_keys(request_or_call)
    local call = mcp_call_from(request_or_call)
    local keys = {}
    if type(call.args) ~= "table" then
      return keys
    end
    for key, _ in pairs(call.args) do
      table.insert(keys, tostring(key))
    end
    table.sort(keys)
    return keys
  end

  function mcp.is_method(request, method)
    return mcp.method(request) == method
  end

  function mcp.is_tool_call(request)
    return mcp.call(request).is_tool_call
  end

  function mcp.tool_name(request)
    return mcp.call(request).tool
  end

  function mcp.tool_allowed(request, allowed)
    local name = mcp.tool_name(request)
    if name == nil then
      return true
    end
    return list_contains(allowed, name)
  end

  function mcp.reject_tool(request_or_name, status, body, options)
    local name = request_or_name
    if type(request_or_name) == "table" then
      name = mcp.tool_name(request_or_name)
    end
    options = options_table(options)
    local message = body or options.body or ("MCP tool not allowed: " .. tostring(name))
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or message
    decision_options.reason_code = options.reason_code or "mcp.tool_not_allowed"
    return decision.reject(status or options.status or 403, message, decision_options)
  end

  function mcp.allow_tools(request, allowed, options)
    local name = mcp.tool_name(request)
    if name == nil or list_contains(allowed, name) then
      return nil
    end
    options = options_table(options)
    return mcp.reject_tool(name, options.status or 403, options.body, options)
  end

  safe_env.mcp = mcp

  local function set_intent_context(context)
    if type(context) == "table" and type(context.intent) == "table" then
      current_intent = context.intent
    else
      current_intent = {}
    end
  end

  local risk_order = {
    low = 0,
    medium = 1,
    high = 2,
  }

  local risk_weights = {
    low = 10,
    medium = 30,
    high = 60,
  }

  local intent_terms = {
    command = {
      "shell",
      "exec",
      "execute",
      "command",
      "terminal",
      "subprocess",
      "process",
      "spawn",
      "bash",
      "zsh",
      "powershell",
      "cmd",
      "system",
    },
    write = {
      "write",
      "edit",
      "create",
      "delete",
      "remove",
      "rename",
      "move",
      "patch",
      "replace",
      "append",
      "mkdir",
      "rm",
      "save",
      "mutate",
      "update",
    },
    destructive = {
      "delete",
      "remove",
      "rm",
      "destroy",
      "drop",
      "wipe",
      "kill",
      "terminate",
    },
    network = {
      "url",
      "uri",
      "host",
      "http",
      "https",
      "fetch",
      "request",
      "webhook",
      "network",
      "download",
    },
    secrets = {
      "secret",
      "token",
      "password",
      "credential",
      "apikey",
      "api_key",
      "private_key",
      "ssh_key",
    },
    filesystem = {
      "file",
      "files",
      "filesystem",
      "path",
      "directory",
      "dir",
      "read_file",
      "list_project_files",
    },
    read = {
      "list",
      "read",
      "get",
      "show",
      "status",
      "describe",
      "inspect",
      "search",
    },
    git = {
      "git",
      "commit",
      "branch",
      "checkout",
      "merge",
      "push",
      "pull",
      "status",
      "diff",
    },
  }

  local function intent_contains_any(value, terms)
    for _, term in ipairs(terms) do
      if string.find(value, term, 1, true) ~= nil then
        return true
      end
    end
    return false
  end

  local function intent_add_category(categories, category)
    categories[category] = true
  end

  local function intent_add_signal(signals, code, severity, reason)
    table.insert(signals, {
      code = code,
      severity = severity,
      reason = reason,
    })
  end

  local function intent_categories_from_set(categories)
    local result = {}
    for category, enabled in pairs(categories) do
      if enabled == true then
        table.insert(result, category)
      end
    end
    table.sort(result)
    return result
  end

  local function intent_has_category_value(categories, category)
    if type(categories) ~= "table" or type(category) ~= "string" then
      return false
    end
    for _, value in ipairs(categories) do
      if selector_matches(category, value) or selector_matches(value, category) then
        return true
      end
    end
    return false
  end

  local function intent_signal_level(score, signals)
    local level = "low"
    if score >= 60 then
      level = "high"
    elseif score >= 30 then
      level = "medium"
    end
    for _, signal in ipairs(signals) do
      local severity = signal.severity or "low"
      if (risk_order[severity] or 0) > (risk_order[level] or 0) then
        level = severity
      end
    end
    return level
  end

  local function intent_classify_name(name)
    name = tostring(name or "")
    local haystack = string.gsub(string.lower(name), "-", "_")
    local categories = {}
    local signals = {}

    if intent_contains_any(haystack, intent_terms.command) then
      intent_add_signal(signals, "tool.shell_or_process", "high", "tool looks able to run commands")
      intent_add_category(categories, "command")
    end
    if intent_contains_any(haystack, intent_terms.secrets) then
      intent_add_signal(signals, "tool.secret_name", "high", "tool name suggests secret or credential access")
      intent_add_category(categories, "secrets")
    end
    if intent_contains_any(haystack, intent_terms.destructive) then
      intent_add_signal(signals, "tool.destructive_name", "high", "tool name suggests destructive mutation")
      intent_add_category(categories, "mutation")
    elseif intent_contains_any(haystack, intent_terms.write) then
      intent_add_signal(signals, "tool.mutating_name", "medium", "tool name suggests mutation")
      intent_add_category(categories, "mutation")
    end
    if intent_contains_any(haystack, intent_terms.network) then
      intent_add_signal(signals, "tool.network_name", "medium", "tool name suggests network access")
      intent_add_category(categories, "network")
    end
    if intent_contains_any(haystack, intent_terms.filesystem) then
      intent_add_signal(signals, "tool.filesystem_name", "medium", "tool name suggests filesystem access")
      intent_add_category(categories, "filesystem")
    end
    if intent_contains_any(haystack, intent_terms.read) then
      intent_add_signal(signals, "tool.read_like_name", "low", "tool name suggests read-only or inspection use")
      intent_add_category(categories, "read")
    end
    if intent_contains_any(haystack, intent_terms.git) then
      intent_add_category(categories, "git")
    end
    if #signals == 0 then
      intent_add_signal(signals, "tool.observed", "low", "tool was observed but has no obvious high-risk signal")
      intent_add_category(categories, "unknown")
    end

    local score = 0
    for _, signal in ipairs(signals) do
      score = score + (risk_weights[signal.severity] or 0)
    end
    if score > 100 then
      score = 100
    end

    return {
      name = name,
      level = intent_signal_level(score, signals),
      score = score,
      categories = intent_categories_from_set(categories),
      signals = signals,
      evidence_sources = { "name" },
      confidence = "low",
      source = "name",
    }
  end

  local function intent_current_info()
    if type(current_intent) == "table" and type(current_intent.name) == "string" then
      return current_intent
    end
    local tool = mcp.tool_name(current_request) or current_upstream.tool
    if type(tool) == "string" and tool ~= "" then
      return intent_classify_name(tool)
    end
    return {}
  end

  local function intent_all_categories(info)
    info = info or intent_current_info()
    local categories = {}
    if type(info.categories) == "table" then
      for _, category in ipairs(info.categories) do
        intent_add_category(categories, tostring(category))
      end
    end
    local name = string.gsub(string.lower(tostring(info.name or "")), "-", "_")
    if categories.command then
      intent_add_category(categories, "shell.exec")
    end
    if categories.network then
      intent_add_category(categories, "network.egress")
    end
    if categories.secrets then
      intent_add_category(categories, "secrets.access")
    end
    if categories.filesystem and categories.mutation then
      intent_add_category(categories, "filesystem.write")
    elseif categories.filesystem then
      intent_add_category(categories, "filesystem.read")
    end
    if categories.git and categories.mutation then
      intent_add_category(categories, "git.write")
    elseif categories.git then
      intent_add_category(categories, "git.read")
    end
    if categories.mutation then
      intent_add_category(categories, "write")
    end
    if categories.read then
      intent_add_category(categories, "read")
    end
    if string.find(name, "push", 1, true) ~= nil then
      intent_add_category(categories, "git.write")
    end
    return intent_categories_from_set(categories)
  end

  local function intent_context(info, details)
    info = info or intent_current_info()
    return merge_context({
      tool = info.name or mcp.tool_name(current_request),
      intent = info.name,
      risk = info.level,
      risk_score = info.score,
      categories = intent_all_categories(info),
      source = info.source,
      confidence = info.confidence,
    }, details)
  end

  local function intent_reject(body, reason_code, options, details)
    options = options_table(options)
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or body
    decision_options.reason_code = options.reason_code or reason_code
    decision_options.context = merge_context(intent_context(nil, details), options.context)
    return decision.reject(options.status or 403, options.body or body, decision_options)
  end

  local intent = {}

  function intent.info()
    return intent_current_info()
  end

  function intent.name()
    return intent_current_info().name
  end

  function intent.categories()
    return intent_all_categories(intent_current_info())
  end

  function intent.category()
    local categories = intent.categories()
    return categories[1]
  end

  function intent.risk()
    return intent_current_info().level
  end

  function intent.risk_score()
    return intent_current_info().score
  end

  function intent.has_category(categories)
    local actual = intent.categories()
    if type(categories) == "table" then
      for _, category in ipairs(categories) do
        if intent_has_category_value(actual, category) then
          return true
        end
      end
      for category, enabled in pairs(categories) do
        if enabled == true and intent_has_category_value(actual, category) then
          return true
        end
      end
      return false
    end
    return intent_has_category_value(actual, categories)
  end

  function intent.require_category(categories, options)
    local name = intent.name()
    if name == nil then
      return nil
    end
    if intent.has_category(categories) then
      return nil
    end
    return intent_reject(
      "MCP tool intent category not allowed: " .. tostring(name),
      "mcp.intent_category_denied",
      options,
      { required_category = categories }
    )
  end

  function intent.require_max_risk(level, options)
    local name = intent.name()
    if name == nil then
      return nil
    end
    local actual = intent.risk() or "low"
    if (risk_order[actual] or 0) <= (risk_order[level] or -1) then
      return nil
    end
    return intent_reject(
      "MCP tool risk exceeds policy: " .. tostring(name),
      "mcp.intent_risk_denied",
      options,
      { max_risk = level }
    )
  end

  function intent.block_if(categories, options)
    local name = intent.name()
    if name == nil or not intent.has_category(categories) then
      return nil
    end
    return intent_reject(
      "MCP tool intent blocked: " .. tostring(name),
      "mcp.intent_blocked",
      options,
      { blocked_category = categories }
    )
  end

  function intent.confirm_if(categories, options)
    local name = intent.name()
    if name == nil or not intent.has_category(categories) then
      return nil
    end
    options = options_table(options)
    local prompt = options.prompt or ("Allow MCP tool " .. tostring(name) .. "?")
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or "MCP tool requires confirmation"
    decision_options.reason_code = options.reason_code or "mcp.intent_confirmation_required"
    decision_options.context = merge_context(
      intent_context(nil, { confirmation_category = categories }),
      options.context
    )
    return decision.confirm(prompt, decision_options)
  end

  safe_env.intent = intent

  local cap = {}

  local function option_list(options, key)
    local value = options[key]
    if value == nil then
      return {}
    end
    if type(value) == "table" then
      return value
    end
    return { value }
  end

  local function optional_list(options, key)
    local values = option_list(options, key)
    if #values == 0 then
      return nil
    end
    return values
  end

  local function capability_task(call, options)
    if options.task ~= nil then
      return options.task
    end
    if call.tool ~= nil then
      return "Temporary MCP access for " .. tostring(call.tool)
    end
    if call.method ~= nil then
      return "Temporary MCP access for " .. tostring(call.method)
    end
    return "Temporary MCP access"
  end

  local function capability_request(call, options)
    local allow_tools = option_list(options, "allow_tools")
    if #allow_tools == 0 and call.tool ~= nil then
      allow_tools = { call.tool }
    end
    local task = capability_task(call, options)
    return {
      schema = "snulbug.capability_request.v1",
      kind = options.kind or "task_lease",
      task = task,
      method = call.method,
      tool = call.tool,
      argument_keys = mcp.arg_keys(call),
      reason_code = options.reason_code or "mcp.capability_request",
      suggested_lease = {
        task = task,
        ttl = options.ttl or "30m",
        max_calls = options.max_calls,
        allow_tools = allow_tools,
        allow_paths = optional_list(options, "allow_paths"),
        allow_hosts = optional_list(options, "allow_hosts"),
        allow_commands = optional_list(options, "allow_commands"),
      },
    }
  end

  local function rejection(options, body, reason_code)
    options = options_table(options)
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or body
    decision_options.reason_code = options.reason_code or reason_code
    return decision.reject(options.status or 403, options.body or body, decision_options)
  end

  local function value_allowed(value, allowed)
    return list_contains(allowed, value)
  end

  function cap.allowed(value, allowed)
    return value_allowed(value, allowed)
  end

  function cap.request(request, options)
    options = options_table(options)
    local call = mcp.call(request or current_request)
    local request_details = capability_request(call, options)
    local prompt = options.prompt
      or ("Request temporary MCP capability for " .. tostring(call.tool or call.method or "this request") .. "?")
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or "MCP capability requires approval"
    decision_options.reason_code = options.reason_code or "mcp.capability_request"
    decision_options.capability_request = request_details
    decision_options.context = merge_context({
      capability_request = request_details,
      tool = call.tool,
      method = call.method,
    }, options.context)
    return decision.confirm(prompt, decision_options)
  end

  function cap.method(request_or_method, allowed, options)
    local method = request_or_method
    if type(request_or_method) == "table" then
      method = mcp.method(request_or_method)
    end
    if value_allowed(method, allowed) then
      return nil
    end
    return rejection(options, "MCP method not allowed: " .. tostring(method), "mcp.method_not_allowed")
  end

  function cap.tool(request_or_name, allowed, options)
    local name = request_or_name
    if type(request_or_name) == "table" then
      if not mcp.is_tool_call(request_or_name) then
        return nil
      end
      name = mcp.tool_name(request_or_name)
    end
    if value_allowed(name, allowed) then
      return nil
    end
    return rejection(options, "MCP tool not allowed: " .. tostring(name), "mcp.tool_not_allowed")
  end

  local function normalize_relative_path(path)
    while starts_with(path, "./") do
      path = string.sub(path, 3)
    end
    return path
  end

  local function contains_parent_segment(path)
    return path == ".."
      or starts_with(path, "../")
      or ends_with(path, "/..")
      or string.find(path, "/../", 1, true) ~= nil
  end

  local function path_under(path, root)
    if type(root) ~= "string" or root == "" then
      return false
    end
    if root == "." or root == "./" then
      return true
    end
    root = normalize_relative_path(root)
    while ends_with(root, "/") and root ~= "" do
      root = string.sub(root, 1, #root - 1)
    end
    if root == "" then
      return false
    end
    return path == root or starts_with(path, root .. "/")
  end

  function cap.path(path, allowed_paths, options)
    if type(path) ~= "string" or path == "" then
      return rejection(options, "path must be a non-empty string", "mcp.path_invalid")
    end
    path = normalize_relative_path(path)
    if starts_with(path, "/") then
      return rejection(options, "absolute paths are not allowed", "mcp.path_absolute")
    end
    if contains_parent_segment(path) then
      return rejection(options, "parent path traversal is not allowed", "mcp.path_traversal")
    end
    if value_allowed(path, allowed_paths) then
      return nil
    end
    if type(allowed_paths) == "table" then
      for _, root in ipairs(allowed_paths) do
        if path_under(path, root) then
          return nil
        end
      end
    end
    return rejection(options, "path not allowed: " .. path, "mcp.path_not_allowed")
  end

  local function argument_value(request_or_call, key)
    return mcp.arg(request_or_call, key)
  end

  local function argument_label(key)
    return "argument " .. tostring(key)
  end

  function cap.arg_string(request_or_call, key, options)
    local value = argument_value(request_or_call, key)
    if type(value) == "string" and value ~= "" then
      return nil
    end
    return rejection(options, argument_label(key) .. " must be a non-empty string", "mcp.argument_invalid")
  end

  function cap.arg_path(request_or_call, key, allowed_paths, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.path(argument_value(request_or_call, key), allowed_paths, options)
  end

  local function extract_host(value)
    if type(value) ~= "string" or value == "" then
      return nil
    end
    local host = string.match(value, "^[%a][%w+.-]*://([^/:/%?#]+)")
    if host == nil then
      host = string.match(value, "^([^/:/%?#]+)")
    end
    if host == nil or host == "" then
      return nil
    end
    return string.lower(host)
  end

  local function host_allowed(host, allowed_hosts)
    if value_allowed(host, allowed_hosts) then
      return true
    end
    if type(allowed_hosts) ~= "table" then
      return false
    end
    for _, allowed in ipairs(allowed_hosts) do
      if type(allowed) == "string" then
        allowed = string.lower(allowed)
        if starts_with(allowed, "*.") and ends_with(host, string.sub(allowed, 2)) then
          return true
        end
      end
    end
    return false
  end

  function cap.host(value, allowed_hosts, options)
    local host = extract_host(value)
    if host ~= nil and host_allowed(host, allowed_hosts) then
      return nil
    end
    return rejection(options, "host not allowed: " .. tostring(host), "mcp.host_not_allowed")
  end

  function cap.arg_host(request_or_call, key, allowed_hosts, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.host(argument_value(request_or_call, key), allowed_hosts, options)
  end

  local function command_name(command)
    if type(command) ~= "string" then
      return nil
    end
    return string.match(command, "^%s*([^%s]+)")
  end

  function cap.command(command, allowed_commands, options)
    local name = command_name(command)
    if value_allowed(name, allowed_commands) then
      return nil
    end
    return rejection(options, "command not allowed: " .. tostring(name), "mcp.command_not_allowed")
  end

  function cap.arg_command(request_or_call, key, allowed_commands, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.command(argument_value(request_or_call, key), allowed_commands, options)
  end

  local workspace_path_keys = {
    path = true,
    paths = true,
    filepath = true,
    file = true,
    files = true,
    filename = true,
    directory = true,
    dir = true,
    root = true,
    cwd = true,
    source = true,
    src = true,
    destination = true,
    dest = true,
    target = true,
    targetpath = true,
    oldpath = true,
    newpath = true,
    from = true,
    to = true,
  }

  local workspace_secret_suffixes = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".cert",
  }

  local workspace_generated_segments = {
    ".git",
    ".snulbug",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "coverage",
  }

  local workspace_write_terms = {
    "write",
    "edit",
    "create",
    "delete",
    "remove",
    "rename",
    "move",
    "patch",
    "replace",
    "append",
    "mkdir",
    "rm",
    "touch",
    "save",
  }

  local workspace_read_methods = {
    ["initialize"] = true,
    ["notifications/initialized"] = true,
    ["tools/list"] = true,
    ["tools/call"] = true,
    ["resources/list"] = true,
    ["resources/templates/list"] = true,
    ["resources/read"] = true,
    ["prompts/list"] = true,
    ["prompts/get"] = true,
  }

  local function normalize_workspace_arg_key(key)
    local lower = string.lower(tostring(key or ""))
    return string.gsub(lower, "[_%.%-]", "")
  end

  local function workspace_key_matches(key, keys)
    local normalized = normalize_workspace_arg_key(key)
    if keys == nil then
      return workspace_path_keys[normalized] == true
    end
    if type(keys) == "string" then
      return normalized == normalize_workspace_arg_key(keys)
    end
    if type(keys) == "table" then
      if keys[normalized] == true or keys[key] == true then
        return true
      end
      for _, configured in ipairs(keys) do
        if normalized == normalize_workspace_arg_key(configured) then
          return true
        end
      end
    end
    return false
  end

  local function workspace_basename(path)
    return string.match(path, "([^/]+)$") or path
  end

  local function workspace_has_segment(path, segment)
    return string.find("/" .. path .. "/", "/" .. segment .. "/", 1, true) ~= nil
  end

  local function workspace_is_secret_path(path)
    local lower = string.lower(path or "")
    local base = workspace_basename(lower)
    if base == ".env" or starts_with(base, ".env.") then
      return true
    end
    if workspace_has_segment(lower, ".ssh")
      or workspace_has_segment(lower, ".gnupg")
      or workspace_has_segment(lower, "secrets") then
      return true
    end
    if lower == ".kube/config" or ends_with(lower, "/.kube/config") then
      return true
    end
    for _, suffix in ipairs(workspace_secret_suffixes) do
      if ends_with(lower, suffix) then
        return true
      end
    end
    return false
  end

  local function workspace_is_generated_path(path)
    local lower = string.lower(path or "")
    for _, segment in ipairs(workspace_generated_segments) do
      if workspace_has_segment(lower, segment) then
        return true
      end
    end
    return false
  end

  local function workspace_tool_is_write_like(tool)
    local lower = string.lower(tool or "")
    for _, term in ipairs(workspace_write_terms) do
      if string.find(lower, term, 1, true) ~= nil then
        return true
      end
    end
    return false
  end

  local function workspace_allowed_roots(options)
    options = options_table(options)
    if type(options.roots) == "table" then
      return options.roots
    end
    if type(options.allowed_paths) == "table" then
      return options.allowed_paths
    end
    if type(options.project_paths) == "table" then
      return options.project_paths
    end
    return { "." }
  end

  local function workspace_path_under_roots(path, roots)
    if value_allowed(path, roots) then
      return true
    end
    if type(roots) == "table" then
      for _, root in ipairs(roots) do
        if path_under(path, root) then
          return true
        end
      end
    end
    return false
  end

  local function workspace_path_info(path, argument, roots)
    local info = {
      argument = argument or "",
      path = tostring(path),
      path_class = "allowed",
    }
    if type(path) ~= "string" or path == "" then
      info.path_class = "invalid"
      return info
    end

    local normalized = normalize_relative_path(path)
    info.path = normalized
    if starts_with(normalized, "/") or starts_with(normalized, "~") or string.match(normalized, "^%a:") ~= nil then
      info.path_class = "outside"
      return info
    end
    if contains_parent_segment(normalized) then
      info.path_class = "outside"
      return info
    end
    if not workspace_path_under_roots(normalized, roots) then
      info.path_class = "outside"
      return info
    end
    if workspace_is_secret_path(normalized) then
      info.path_class = "secret"
      return info
    end
    if workspace_is_generated_path(normalized) then
      info.path_class = "generated"
      return info
    end
    return info
  end

  local function workspace_collect_path_values(value, key, keys, output, depth)
    if depth > 5 then
      return
    end

    if workspace_key_matches(key, keys) then
      if type(value) == "string" then
        table.insert(output, { argument = tostring(key), value = value })
      elseif type(value) == "table" then
        for _, item in ipairs(value) do
          table.insert(output, { argument = tostring(key), value = item })
        end
      else
        table.insert(output, { argument = tostring(key), value = value })
      end
    end

    if type(value) == "table" then
      for child_key, child_value in pairs(value) do
        if type(child_key) == "string" then
          workspace_collect_path_values(child_value, child_key, keys, output, depth + 1)
        end
      end
    end
  end

  local function workspace_path_values(keys)
    local values = {}
    local call = mcp.call(current_request)
    if type(call.args) == "table" then
      workspace_collect_path_values(call.args, "", keys, values, 0)
    end
    return values
  end

  local function workspace_context(info, details)
    local call = mcp.call(current_request)
    local workspace_details = {
      argument = info.argument or "",
      path = info.path or "",
      path_class = info.path_class or "none",
      write_intent = workspace_tool_is_write_like(call.tool),
    }
    return merge_context({
      policy = "mcp-workspace",
      method = call.method or "",
      tool = call.tool or "",
      workspace = workspace_details,
    }, details)
  end

  local function workspace_reject(info, body, reason, reason_code, options)
    options = options_table(options)
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or reason
    decision_options.reason_code = options.reason_code or reason_code
    decision_options.context = merge_context(workspace_context(info), options.context)
    return decision.reject(options.status or 403, options.body or body, decision_options)
  end

  local workspace = {}

  function workspace.write_intent()
    local call = mcp.call(current_request)
    return workspace_tool_is_write_like(call.tool)
  end

  function workspace.path_values(keys)
    local result = {}
    for _, value in ipairs(workspace_path_values(keys)) do
      table.insert(result, value.value)
    end
    return result
  end

  function workspace.path_summary(keys, options)
    local roots = workspace_allowed_roots(options)
    local values = workspace_path_values(keys)
    if #values == 0 then
      return {
        argument = "",
        path = "",
        path_class = "none",
        write_intent = workspace.write_intent(),
      }
    end
    local first = nil
    for _, value in ipairs(values) do
      local info = workspace_path_info(value.value, value.argument, roots)
      if first == nil then
        first = info
      end
      if info.path_class == "generated" then
        info.write_intent = workspace.write_intent()
        return info
      end
    end
    first.write_intent = workspace.write_intent()
    return first
  end

  function workspace.require_under_project(keys, options)
    options = options_table(options)
    local roots = workspace_allowed_roots(options)
    local values = workspace_path_values(keys)
    if #values == 0 and options.required == true then
      local missing = { argument = type(keys) == "string" and keys or "", path = "", path_class = "invalid" }
      return workspace_reject(
        missing,
        "MCP workspace path blocked (invalid): ",
        "MCP tool path argument is missing or invalid",
        "mcp.workspace_path_invalid",
        options
      )
    end
    for _, value in ipairs(values) do
      local info = workspace_path_info(value.value, value.argument, roots)
      if info.path_class == "invalid" then
        return workspace_reject(
          info,
          "MCP workspace path blocked (invalid): " .. tostring(info.path),
          "MCP tool path argument is missing or invalid",
          "mcp.workspace_path_invalid",
          options
        )
      end
      if info.path_class == "outside" then
        return workspace_reject(
          info,
          "MCP workspace path blocked (outside): " .. tostring(info.path),
          "MCP tool path is outside the allowed workspace paths",
          "mcp.workspace_path_outside",
          options
        )
      end
    end
    return nil
  end

  function workspace.block_secret_paths(keys, options)
    options = options_table(options)
    for _, value in ipairs(workspace_path_values(keys)) do
      if type(value.value) == "string" then
        local path = normalize_relative_path(value.value)
        if workspace_is_secret_path(path) then
          local info = { argument = value.argument, path = path, path_class = "secret" }
          return workspace_reject(
            info,
            "MCP workspace path blocked (secret): " .. tostring(path),
            "MCP tool path looks like a secret-bearing file or directory",
            "mcp.workspace_secret_blocked",
            options
          )
        end
      end
    end
    return nil
  end

  function workspace.block_generated_paths(keys, options)
    options = options_table(options)
    if options.write_only == true and not workspace.write_intent() then
      return nil
    end
    for _, value in ipairs(workspace_path_values(keys)) do
      if type(value.value) == "string" then
        local path = normalize_relative_path(value.value)
        if workspace_is_generated_path(path) then
          local info = { argument = value.argument, path = path, path_class = "generated" }
          return workspace_reject(
            info,
            "MCP workspace path blocked (generated): " .. tostring(path),
            "MCP tool path targets generated or cache output",
            "mcp.workspace_generated_path_blocked",
            options
          )
        end
      end
    end
    return nil
  end

  function workspace.readonly_only(options)
    options = options_table(options)
    local call = mcp.call(current_request)
    local method = call.method
    local tool = call.tool or ""
    local allowed = workspace_read_methods[method] == true
    if method == "tools/call" and workspace_tool_is_write_like(tool) then
      allowed = false
    end
    if allowed then
      return nil
    end
    local info = { argument = "", path = "", path_class = "none" }
    return workspace_reject(
      info,
      "MCP request is not read-only",
      "MCP method or tool is outside the read-only workspace policy",
      "mcp.workspace_readonly_required",
      options
    )
  end

  safe_env.workspace = workspace

  safe_env.cap = cap

  local loader = loadstring or load
  local chunk, err
  if loadstring then
    chunk, err = loadstring(source, source_name)
    if chunk then
      setfenv(chunk, safe_env)
    end
  else
    chunk, err = load(source, source_name, "t", safe_env)
  end
  if not chunk then
    error(err)
  end

  local handler = chunk()
  if type(handler) ~= "function" then
    error("Lua script must return a function(request, context)")
  end

  return function(request, context, state)
    local instruction_count = 0
    local function check_instruction_limit()
      instruction_count = instruction_count + 1000
      if instruction_count > instruction_limit then
        error("Lua instruction limit exceeded")
      end
    end

    if debug and debug.sethook then
      debug.sethook(check_instruction_limit, "", 1000)
    end

    set_auth_context(context)
    set_lease_context(context)
    current_request = request
    set_share_context(context)
    set_upstream_context(context)
    set_intent_context(context)
    local ok, result = pcall(handler, request, context, state or {})
    set_auth_context({})
    set_lease_context({})
    current_request = {}
    set_share_context({})
    set_upstream_context({})
    set_intent_context({})

    if debug and debug.sethook then
      debug.sethook()
    end

    if not ok then
      error(result)
    end
    return {
      decision = result,
      instruction_count = instruction_count,
    }
  end
end
"""
