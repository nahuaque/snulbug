"""Evidence-based request explanations, shared by live and offline consumers."""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from .credentials import CredentialResolutionError

_TRANSPORT_FAILURES = {
    "upstream.credentials_unavailable": (
        "Upstream authentication could not be prepared.",
        "Check the configured upstream credential broker and its environment or file reference.",
    ),
    "upstream.dns_failed": (
        "The upstream hostname could not be resolved.",
        "Check the upstream address and DNS from the gateway's network namespace.",
    ),
    "upstream.connection_refused": (
        "The upstream refused the connection.",
        "Start the upstream or bridge and verify its configured address and listening port.",
    ),
    "upstream.tls_failed": (
        "TLS verification or negotiation with the upstream failed.",
        "Check the upstream hostname, certificate chain, and trust configuration; do not disable TLS verification.",
    ),
    "upstream.timeout": (
        "The upstream exchange timed out.",
        "Check upstream health and latency; verify whether a side effect occurred before repeating the call.",
    ),
    "upstream.protocol_failed": (
        "The upstream exchange failed at the HTTP protocol layer.",
        "Check upstream protocol and transport configuration and inspect the upstream's own logs.",
    ),
    "upstream.process_unavailable": (
        "The managed stdio upstream executable could not be found.",
        "Check the upstream command and the gateway service account's PATH and working directory.",
    ),
    "upstream.transport_failed": (
        "The upstream exchange failed without a more specific recorded cause.",
        "Check the upstream or bridge logs and share doctor; verify side effects before repeating the call.",
    ),
    "upstream.invalid_response": (
        "The upstream returned an invalid MCP response.",
        "Inspect the upstream's MCP transport and response format; do not change the request policy to fix this.",
    ),
}


def upstream_failure(exc: Exception, *, transport: str = "http") -> dict[str, Any]:
    """Classify exception types, never their potentially secret-bearing messages."""
    code = "upstream.transport_failed"
    not_forwarded = False
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(8):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if isinstance(current, CredentialResolutionError):
            code, not_forwarded = "upstream.credentials_unavailable", True
            break
        if isinstance(current, socket.gaierror):
            code, not_forwarded = "upstream.dns_failed", True
            break
        if isinstance(current, ConnectionRefusedError):
            code, not_forwarded = "upstream.connection_refused", True
            break
        if isinstance(current, ssl.SSLError):
            code = "upstream.tls_failed"
            not_forwarded = isinstance(current, ssl.SSLCertVerificationError)
            break
        if isinstance(current, FileNotFoundError) and transport == "stdio":
            code, not_forwarded = "upstream.process_unavailable", True
            break
        if isinstance(current, (TimeoutError, httpx.TimeoutException)):
            code = "upstream.timeout"
            break
        if isinstance(current, (http.client.HTTPException, httpx.ProtocolError)):
            code = "upstream.protocol_failed"
        current = current.__cause__
    return {"failure_code": code, "execution": "not_forwarded" if not_forwarded else "unknown"}


def upstream_failure_message(failure: Mapping[str, Any]) -> str:
    return _TRANSPORT_FAILURES.get(str(failure.get("failure_code")), _TRANSPORT_FAILURES["upstream.transport_failed"])[
        0
    ]


def upstream_observation_failed(item: Mapping[str, Any]) -> bool:
    return bool(
        item.get("failure_code")
        or item.get("rpc_error")
        or item.get("tool_error")
        or (isinstance(item.get("status"), int) and item["status"] >= 400)
    )


def upstream_response_observation(response: Mapping[str, Any]) -> dict[str, Any]:
    """Observe bounded MCP envelopes without retaining payloads or error messages."""
    result: dict[str, Any] = {"status": response.get("status"), "execution": "response_received"}
    body = response.get("body")
    if not isinstance(body, bytes) or len(body) > 131_072:
        return result
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return result
    if not isinstance(payload, Mapping) or payload.get("jsonrpc") != "2.0":
        return result
    if isinstance(payload.get("error"), Mapping):
        result["rpc_error"] = True
    if _mapping(payload.get("result")).get("isError") is True:
        result["tool_error"] = True
    return result


def explain_request(event: Mapping[str, Any]) -> dict[str, Any]:
    """Explain recorded facts; absence of evidence is not proof of an upstream failure."""
    metadata = _mapping(event.get("metadata"))
    decision = _mapping(event.get("decision"))
    response = _mapping(event.get("response"))
    status = response.get("status", decision.get("status"))
    auth = _mapping(metadata.get("auth") or event.get("auth"))
    lease = _mapping(metadata.get("lease"))

    def explanation(
        stage: str,
        code: Any,
        summary: str,
        next_step: str,
        *,
        execution: str = "not_forwarded",
        outcome: str = "blocked",
        basis: str = "recorded_metadata",
        upstream: Any = None,
    ) -> dict[str, Any]:
        reason = str(code or "request.denied")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", reason):
            reason = "request.denied"
        evidence = {"basis": basis, "http_status": status}
        if isinstance(upstream, str):
            evidence["upstream"] = upstream[:128]
        return {
            "outcome": outcome,
            "stage": stage,
            "reason_code": reason,
            "summary": summary,
            "next_steps": [next_step],
            "execution": execution,
            "evidence": evidence,
        }

    for gate in (auth, _mapping(metadata.get("cloudflare_access") or event.get("cloudflare_access"))):
        if gate.get("allowed") is False and gate.get("enabled") is not False:
            return explanation(
                "authentication",
                gate.get("reason_code") or "auth.denied",
                "Client authentication or authorization denied the request.",
                "Review Auth Visibility, the selected issuer/profile, identity permissions, and scope mapping.",
            )
    if not lease:
        lease = _mapping(_mapping(metadata.get("access")).get("lease"))
    if not lease and decision.get("allowed") is False:
        lease = _mapping(metadata.get("lease_preview"))
    if (
        lease.get("enabled")
        and lease.get("checked")
        and (lease.get("blocked") is True or lease.get("allowed") is False)
    ):
        return explanation(
            "lease",
            lease.get("reason_code") or "lease.denied",
            "The task lease did not authorize this request.",
            "Review the invite's backing lease, expiry, revocation, identity binding, and granted capabilities.",
        )
    for name, stage in (
        ("mcp_transport", "request_validation"),
        ("mcp_protocol", "request_validation"),
        ("parameter_headers", "request_validation"),
        ("completion_policy", "request_policy"),
        ("schema_validation", "request_validation"),
    ):
        gate = _mapping(metadata.get(name))
        if gate.get("blocked") is True or gate.get("allowed") is False:
            return explanation(
                stage,
                gate.get("reason_code") or "request.validation_failed",
                "The gateway rejected the request before forwarding.",
                "Check the recorded validation/policy reason and the MCP request shape and transport headers.",
            )

    for name in ("protocol_policy", "resource_policy"):
        policy = _mapping(metadata.get(name))
        gate = _mapping(policy.get("request")) or policy
        if gate.get("blocked") is True or gate.get("allowed") is False:
            return explanation(
                "request_policy",
                gate.get("reason_code") or "request.protocol_denied",
                "The gateway's MCP request controls rejected the request.",
                "Review progress, cancellation, or resource subscription controls and the recorded reason.",
            )

    confirmation = _mapping(decision.get("confirmation"))
    if confirmation and confirmation.get("approved") is not True:
        return explanation(
            "confirmation",
            confirmation.get("reason_code") or "confirmation.not_approved",
            "The request did not receive the required user confirmation.",
            "Review the existing pending confirmation or capability request; do not bypass the approval requirement.",
        )

    if decision.get("allowed") is False and decision.get("action") not in {None, "unknown", "respond"}:
        return explanation(
            "request_policy",
            decision.get("reason_code") or "policy.denied",
            "The request policy did not allow this request.",
            "Review the Lua decision and any pending confirmation or capability request; do not widen policy blindly.",
        )

    for gate in (
        _mapping(metadata.get("response_policy")),
        _mapping(_mapping(metadata.get("schema_validation")).get("tool_result")),
        _mapping(_mapping(metadata.get("protocol_policy")).get("response")),
        _mapping(_mapping(metadata.get("resource_policy")).get("response")),
    ):
        if gate.get("blocked") is True:
            return explanation(
                "response_policy",
                gate.get("reason_code") or "response.denied",
                "The upstream response was blocked by a gateway response check.",
                "Review response policy, schema pins, and drift evidence; "
                "the upstream may already have performed the action.",
                execution="response_received",
            )

    exchanges = [item for item in _sequence(metadata.get("upstream_exchanges")) if isinstance(item, Mapping)]
    failures = [item for item in exchanges if upstream_observation_failed(item)]
    if failures:
        failure = failures[0]
        code = str(failure.get("failure_code") or "")
        execution = str(failure.get("execution") or "unknown")
        if execution not in {"not_forwarded", "unknown", "response_received"}:
            execution = "unknown"
        if code in _TRANSPORT_FAILURES:
            summary, step = _TRANSPORT_FAILURES[code]
            stage = "upstream_credentials" if code == "upstream.credentials_unavailable" else "upstream_transport"
        elif code == "stream.failed":
            stage, summary = "stream", "The MCP stream failed or was rejected by a gateway stream check."
            step = (
                "Inspect stream policy and upstream transport evidence; verify side effects before repeating the call."
            )
        elif code:
            code, stage, execution = "request.failure_unattributed", "unknown", "unknown"
            summary = "An unrecognized failure marker was recorded for an upstream exchange."
            step = "Inspect the transport plugin and gateway logs; the marker alone does not establish the cause."
        elif failure.get("status") in {401, 403}:
            code, stage = "upstream.auth_rejected", "upstream_response"
            summary = "The upstream rejected the gateway's upstream authentication or permissions."
            step = (
                "Review upstream-specific credentials and permissions; "
                "do not forward the client's identity proof as a workaround."
            )
        else:
            stage = "upstream_response"
            code = (
                "upstream.tool_error"
                if failure.get("tool_error")
                else ("upstream.rpc_error" if failure.get("rpc_error") else "upstream.http_error")
            )
            summary = (
                "The upstream reported a tool error."
                if failure.get("tool_error")
                else (
                    "The upstream returned a JSON-RPC error."
                    if failure.get("rpc_error")
                    else "The upstream returned an unsuccessful HTTP response."
                )
            )
            step = (
                "Inspect the upstream's own logs and request contract; verify side effects before repeating the call."
            )
        partial = metadata.get("operation") == "tools/list" and isinstance(status, int) and status < 400
        result = explanation(
            stage,
            code,
            summary,
            step,
            execution=execution,
            outcome="partial" if partial else "failed",
            upstream=failure.get("upstream"),
        )
        if isinstance(failure.get("status"), int):
            result["evidence"]["upstream_status"] = failure["status"]
        if partial:
            result["summary"] = "The facade returned a partial catalog because an upstream exchange failed."
        return result

    stream = _mapping(metadata.get("stream"))
    if stream.get("status") in {"failed", "disconnected", "cancelled"}:
        return explanation(
            "stream",
            "stream." + stream["status"],
            "The request stream did not complete normally.",
            "Inspect stream policy and connection state; "
            "a disconnected or timed-out call may still have performed an action.",
            execution="unknown",
            outcome="failed",
        )
    if status == 503 and (
        _mapping(metadata.get("operational_controls")).get("paused")
        or _mapping(metadata.get("upstream_health")).get("skipped")
        or _mapping(metadata.get("operational_controls")).get("disabled_upstreams")
    ):
        return explanation(
            "routing",
            "routing.unavailable",
            "The selected upstream route is unavailable.",
            "Review operational controls and upstream health before enabling the route.",
            outcome="failed",
        )
    if isinstance(status, int) and status >= 400:
        return explanation(
            "unknown",
            "request.failure_unattributed",
            "The recorded HTTP failure does not identify which component caused it.",
            "Run share doctor and inspect gateway/upstream logs; do not assume a policy change or retry is safe.",
            execution="unknown",
            outcome="failed",
            basis="http_status_only",
        )
    return {}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()
