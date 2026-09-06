"""Deterministic stdio peer for multiplexing and process-lifecycle tests."""

import json
import os
import sys

SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"
subscriptions = {}


def emit(payload):
    print(json.dumps(payload), flush=True)


def notify(identifier, method, **params):
    emit({"jsonrpc": "2.0", "method": method, "params": {"_meta": {SUBSCRIPTION_ID: identifier}, **params}})


for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "notifications/cancelled":
        subscriptions.pop(request["params"]["requestId"], None)
        continue
    identifier = request["id"]
    if method == "subscriptions/listen":
        filters = request["params"]["notifications"]
        subscriptions[identifier] = filters
        notify(identifier, "notifications/subscriptions/acknowledged", notifications=filters)
        continue
    name = request.get("params", {}).get("name")
    if name == "crash":
        sys.exit(3)
    if name == "bad-id":
        notify("not-a-request", "notifications/tools/list_changed")
        continue
    if name == "server-request":
        emit({"jsonrpc": "2.0", "id": "server-id", "method": "roots/list"})
        continue
    if name in {"emit", "violate", "finish", "flood"}:
        for sub, filters in list(subscriptions.items()):
            if name == "finish":
                emit(
                    {"jsonrpc": "2.0", "id": sub, "result": {"resultType": "complete", "_meta": {SUBSCRIPTION_ID: sub}}}
                )
                del subscriptions[sub]
            elif name == "violate":
                notify(sub, "notifications/resources/updated", uri="file:///outside")
            else:
                for _ in range(100 if name == "flood" else 1):
                    if filters.get("resourceSubscriptions"):
                        notify(sub, "notifications/resources/updated", uri=filters["resourceSubscriptions"][0])
                    else:
                        notify(sub, "notifications/tools/list_changed")
    emit(
        {
            "jsonrpc": "2.0",
            "id": identifier,
            "result": {
                "resultType": "complete",
                "content": [],
                "pid": os.getpid(),
                "subscriptions": list(subscriptions),
            },
        }
    )
