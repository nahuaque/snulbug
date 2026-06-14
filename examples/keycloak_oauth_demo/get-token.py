from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEFAULT_TOKEN_URL = "http://127.0.0.1:8080/realms/snulbug-demo/protocol/openid-connect/token"


def main() -> int:
    parser = argparse.ArgumentParser(description="Request a demo Keycloak client-credentials token.")
    parser.add_argument("--token-url", default=DEFAULT_TOKEN_URL)
    parser.add_argument("--client-id", default="snulbug-agent")
    parser.add_argument("--client-secret", default="snulbug-agent-secret")
    parser.add_argument("--scope", default="", help="optional space-separated scope request")
    parser.add_argument("--json", action="store_true", help="print the full token response")
    args = parser.parse_args()

    form = {
        "grant_type": "client_credentials",
        "client_id": args.client_id,
        "client_secret": args.client_secret,
    }
    if args.scope:
        form["scope"] = args.scope
    request = Request(
        args.token_url,
        data=urlencode(form).encode("utf-8"),
        headers={"content-type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310 - local demo URL
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        sys.stderr.write(f"Keycloak token request failed with HTTP {exc.code}: {exc.read().decode('utf-8')}\n")
        return 1
    except (OSError, URLError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Keycloak token request failed: {exc}\n")
        return 1

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        sys.stderr.write("Keycloak token response did not include access_token\n")
        return 1
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
