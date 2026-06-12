# Basic ASGI policy

Run the smallest complete middleware example:

```bash
uv run uvicorn examples.basic.app:application --host 127.0.0.1 --port 8000
```

Try the allowed path:

```bash
curl http://127.0.0.1:8000/
```

Try the blocked path:

```bash
curl -i http://127.0.0.1:8000/blocked
```
