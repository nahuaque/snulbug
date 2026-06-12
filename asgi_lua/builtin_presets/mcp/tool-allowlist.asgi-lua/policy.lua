local allowed_tools = {
  "safe_read_file",
  "list_project_files",
}

return function(request, context, state)
  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "continue",
    context = {
      policy = "mcp-tool-allowlist",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }
  }
end
