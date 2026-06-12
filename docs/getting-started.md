# Getting started

`asgi-lua` wraps any ASGI app with a Lua policy layer.

Install:

```bash
pip install asgi-lua
```

Minimal policy:

```python
from asgi_lua import LuaMiddleware


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


policy = """
return function(request, context)
  if request.headers.authorization ~= "Bearer secret" then
    return { action = "reject", status = 401, body = "unauthorized" }
  end

  return { action = "continue" }
end
"""

application = LuaMiddleware(app, policy)
```

Run the included basic example:

```bash
uv run uvicorn examples.basic.app:application --host 127.0.0.1 --port 8000
```
