from asgi_lua import LuaMiddleware


async def app(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": f"hello from {scope['path']}".encode(),
            "more_body": False,
        }
    )


lua_script = """
return function(request, context)
  if request.path == "/blocked" then
    return { action = "reject", status = 403, body = "blocked by Lua\\n" }
  end

  return {
    action = "continue",
    context = { policy = "example" }
  }
end
"""

application = LuaMiddleware(app, lua_script)
