"""Programmable Lua request middleware for ASGI applications."""

__version__ = "0.1.0"

from .bundle import pack_bundle, test_bundle, validate_bundle
from .middleware import LuaConfig, LuaMiddleware
from .presets import copy_builtin_preset, list_builtin_presets
from .promotion import compare_decisions, diff_policies
from .proxy import ReverseProxyApp, create_proxy_application, run_proxy
from .recorder import append_record, load_record_log, record_audit_event, record_policy_request, replay_record_log
from .redaction import RedactionConfig, append_audit_event, build_audit_event, redact_secrets
from .runtime import LuaDecisionError, LuaDecisionTrace, LuaRuntimeError
from .simulator import simulate_policy
from .state import (
    BoundedPolicyState,
    MemoryStateStore,
    RedisStateStore,
    SnapshotStateStore,
    SQLiteStateStore,
    StateLimits,
)

__all__ = [
    "BoundedPolicyState",
    "LuaConfig",
    "LuaDecisionError",
    "LuaDecisionTrace",
    "LuaMiddleware",
    "LuaRuntimeError",
    "MemoryStateStore",
    "RedisStateStore",
    "RedactionConfig",
    "ReverseProxyApp",
    "SQLiteStateStore",
    "SnapshotStateStore",
    "StateLimits",
    "__version__",
    "append_audit_event",
    "append_record",
    "build_audit_event",
    "compare_decisions",
    "copy_builtin_preset",
    "create_proxy_application",
    "diff_policies",
    "load_record_log",
    "list_builtin_presets",
    "pack_bundle",
    "record_audit_event",
    "record_policy_request",
    "redact_secrets",
    "replay_record_log",
    "run_proxy",
    "simulate_policy",
    "test_bundle",
    "validate_bundle",
]
