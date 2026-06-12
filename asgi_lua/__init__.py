"""Programmable Lua request middleware for ASGI applications."""

__version__ = "0.1.0"

from .bundle import pack_bundle, test_bundle, validate_bundle
from .middleware import LuaConfig, LuaMiddleware
from .presets import copy_builtin_preset, list_builtin_presets
from .promotion import compare_decisions, diff_policies
from .recorder import append_record, load_record_log, record_policy_request, replay_record_log
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
    "SQLiteStateStore",
    "SnapshotStateStore",
    "StateLimits",
    "__version__",
    "append_record",
    "compare_decisions",
    "copy_builtin_preset",
    "diff_policies",
    "load_record_log",
    "list_builtin_presets",
    "pack_bundle",
    "record_policy_request",
    "replay_record_log",
    "simulate_policy",
    "test_bundle",
    "validate_bundle",
]
