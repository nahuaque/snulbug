from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .runtime import LuaDecisionError


class PolicyStateStore(Protocol):
    def get(self, key: str) -> str | None: ...

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None: ...

    def delete(self, key: str) -> bool: ...

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int: ...

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool: ...


@dataclass(frozen=True)
class StateLimits:
    max_operations: int = 16
    max_key_bytes: int = 256
    max_value_bytes: int = 4096
    max_ttl_seconds: int = 7 * 24 * 60 * 60


@dataclass
class BoundedPolicyState:
    store: PolicyStateStore
    limits: StateLimits = field(default_factory=StateLimits)
    key_prefix: str = ""
    read_only: bool = False
    operations: list[dict[str, Any]] = field(default_factory=list)

    def lua_api(self) -> dict[str, Any]:
        return {
            "get": self.get,
            "put": self.put,
            "delete": self.delete,
            "incr": self.incr,
            "cas": self.cas,
        }

    def get(self, key: Any) -> str | None:
        self._ensure_operation_allowed()
        full_key = self._key(key)
        value = self.store.get(full_key)
        self._record({"op": "get", "key": full_key, "hit": value is not None})
        return value

    def put(self, key: Any, value: Any, options: Any = None) -> bool:
        self._require_write("put")
        self._ensure_operation_allowed()
        full_key = self._key(key)
        state_value = self._value(value)
        ttl = self._ttl(options)
        self.store.put(full_key, state_value, ttl=ttl)
        self._record({"op": "put", "key": full_key, "value_bytes": len(state_value.encode("utf-8")), "ttl": ttl})
        return True

    def delete(self, key: Any) -> bool:
        self._require_write("delete")
        self._ensure_operation_allowed()
        full_key = self._key(key)
        deleted = self.store.delete(full_key)
        self._record({"op": "delete", "key": full_key, "deleted": deleted})
        return deleted

    def incr(self, key: Any, amount: Any = 1, options: Any = None) -> int:
        self._require_write("incr")
        self._ensure_operation_allowed()
        full_key = self._key(key)
        increment = int(amount)
        ttl = self._ttl(options)
        value = self.store.incr(full_key, increment, ttl=ttl)
        self._record({"op": "incr", "key": full_key, "amount": increment, "value": value, "ttl": ttl})
        return value

    def cas(self, key: Any, expected: Any, value: Any, options: Any = None) -> bool:
        self._require_write("cas")
        self._ensure_operation_allowed()
        full_key = self._key(key)
        expected_value = None if expected is None else self._value(expected)
        state_value = self._value(value)
        ttl = self._ttl(options)
        swapped = self.store.cas(full_key, expected_value, state_value, ttl=ttl)
        self._record({"op": "cas", "key": full_key, "swapped": swapped, "ttl": ttl})
        return swapped

    def _key(self, key: Any) -> str:
        full_key = f"{self.key_prefix}{key}"
        if not full_key:
            raise LuaDecisionError("state key must not be empty")
        if len(full_key.encode("utf-8")) > self.limits.max_key_bytes:
            raise LuaDecisionError("state key exceeds max_key_bytes")
        return full_key

    def _value(self, value: Any) -> str:
        state_value = str(value)
        if len(state_value.encode("utf-8")) > self.limits.max_value_bytes:
            raise LuaDecisionError("state value exceeds max_value_bytes")
        return state_value

    def _ttl(self, options: Any) -> float | None:
        data = _from_lua_options(options)
        ttl = data.get("ttl")
        if ttl is None:
            return None
        ttl_seconds = float(ttl)
        if ttl_seconds <= 0:
            raise LuaDecisionError("state ttl must be positive")
        if ttl_seconds > self.limits.max_ttl_seconds:
            raise LuaDecisionError("state ttl exceeds max_ttl_seconds")
        return ttl_seconds

    def _record(self, operation: dict[str, Any]) -> None:
        self.operations.append(operation)

    def _ensure_operation_allowed(self) -> None:
        if len(self.operations) >= self.limits.max_operations:
            raise LuaDecisionError("state operation limit exceeded")

    def _require_write(self, op: str) -> None:
        if self.read_only:
            raise LuaDecisionError(f"state.{op} is not available in read-only state")


class MemoryStateStore:
    def __init__(self) -> None:
        self._items: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            value, expires_at = item
            if _expired(expires_at):
                self._items.pop(key, None)
                return None
            return value

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None:
        with self._lock:
            self._items[key] = (value, _expires_at(ttl))

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._items.pop(key, None) is not None

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int:
        with self._lock:
            current = self.get(key)
            value = int(current or "0") + amount
            self._items[key] = (str(value), _expires_at(ttl))
            return value

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool:
        with self._lock:
            current = self.get(key)
            if current != expected:
                return False
            self._items[key] = (value, _expires_at(ttl))
            return True


class DryRunStateStore:
    def __init__(self, store: PolicyStateStore) -> None:
        self.store = store

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None:
        return None

    def delete(self, key: str) -> bool:
        return self.store.get(key) is not None

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int:
        return int(self.store.get(key) or "0") + amount

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool:
        return self.store.get(key) == expected


class SnapshotStateStore:
    """Deterministic state store for replaying and recording policy state."""

    def __init__(self, initial_state: Mapping[str, Any] | None = None) -> None:
        self.initial_state = _normalize_snapshot_state(initial_state or {})
        self._items = dict(self.initial_state)
        self.operations: list[dict[str, Any]] = []

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any] | None) -> "SnapshotStateStore":
        if snapshot is None:
            return cls()
        initial_state = snapshot.get("initial_state", snapshot.get("state", snapshot))
        if not isinstance(initial_state, Mapping):
            raise LuaDecisionError("state snapshot must contain an object initial_state")
        return cls(initial_state)

    def get(self, key: str) -> str | None:
        value = self._items.get(key)
        self.operations.append({"op": "get", "key": key, "value": value, "hit": value is not None})
        return value

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None:
        before = self._items.get(key)
        self._items[key] = value
        self.operations.append({"op": "put", "key": key, "before": before, "after": value, "ttl": ttl})

    def delete(self, key: str) -> bool:
        before = self._items.get(key)
        deleted = key in self._items
        self._items.pop(key, None)
        self.operations.append({"op": "delete", "key": key, "before": before, "deleted": deleted})
        return deleted

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int:
        before = self._items.get(key)
        after = int(before or "0") + amount
        self._items[key] = str(after)
        self.operations.append(
            {"op": "incr", "key": key, "before": before, "amount": amount, "after": str(after), "ttl": ttl}
        )
        return after

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool:
        before = self._items.get(key)
        swapped = before == expected
        if swapped:
            self._items[key] = value
        self.operations.append(
            {
                "op": "cas",
                "key": key,
                "before": before,
                "expected": expected,
                "after": self._items.get(key),
                "swapped": swapped,
                "ttl": ttl,
            }
        )
        return swapped

    def snapshot(self) -> dict[str, Any]:
        return {
            "initial_state": dict(sorted(self.initial_state.items())),
            "operations": list(self.operations),
            "final_state": dict(sorted(self._items.items())),
        }


class SQLiteStateStore:
    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 250) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_state (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              expires_at REAL,
              updated_at REAL NOT NULL
            )
            """
        )

    def get(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value, expires_at FROM policy_state WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            value, expires_at = row
            if _expired(expires_at):
                self._conn.execute("DELETE FROM policy_state WHERE key = ?", (key,))
                return None
            return str(value)

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO policy_state(key, value, expires_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                  value = excluded.value,
                  expires_at = excluded.expires_at,
                  updated_at = excluded.updated_at
                """,
                (key, value, _expires_at(ttl), time.time()),
            )

    def delete(self, key: str) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM policy_state WHERE key = ?", (key,))
            return cursor.rowcount > 0

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                current = self.get(key)
                value = int(current or "0") + amount
                self.put(key, str(value), ttl=ttl)
                self._conn.execute("COMMIT")
                return value
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                current = self.get(key)
                if current != expected:
                    self._conn.execute("COMMIT")
                    return False
                self.put(key, value, ttl=ttl)
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        self._conn.close()


class RedisStateStore:
    def __init__(self, url: str | None = None, *, client: Any = None, key_prefix: str = "") -> None:
        if client is None:
            try:
                import redis
                from redis.exceptions import WatchError
            except Exception as exc:  # pragma: no cover - depends on optional redis extra.
                raise RuntimeError("RedisStateStore requires the optional 'redis' package") from exc
            client = redis.Redis.from_url(url or "redis://localhost:6379/0", decode_responses=True)
        else:
            try:
                from redis.exceptions import WatchError
            except Exception:  # pragma: no cover - only used with custom clients in tests/apps.
                WatchError = RuntimeError
        self.client = client
        self.key_prefix = key_prefix
        self._watch_error = WatchError

    def get(self, key: str) -> str | None:
        value = self.client.get(self._key(key))
        return None if value is None else str(value)

    def put(self, key: str, value: str, *, ttl: float | None = None) -> None:
        if ttl is None:
            self.client.set(self._key(key), value)
        else:
            self.client.set(self._key(key), value, ex=int(ttl))

    def delete(self, key: str) -> bool:
        return bool(self.client.delete(self._key(key)))

    def incr(self, key: str, amount: int = 1, *, ttl: float | None = None) -> int:
        full_key = self._key(key)
        value = int(self.client.incrby(full_key, amount))
        if ttl is not None:
            self.client.expire(full_key, int(ttl))
        return value

    def cas(self, key: str, expected: str | None, value: str, *, ttl: float | None = None) -> bool:
        full_key = self._key(key)
        with self.client.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(full_key)
                    current = pipe.get(full_key)
                    if current != expected:
                        pipe.unwatch()
                        return False
                    pipe.multi()
                    if ttl is None:
                        pipe.set(full_key, value)
                    else:
                        pipe.set(full_key, value, ex=int(ttl))
                    pipe.execute()
                    return True
                except self._watch_error:
                    continue

    def _key(self, key: str) -> str:
        return f"{self.key_prefix}{key}"


def _expires_at(ttl: float | None) -> float | None:
    return None if ttl is None else time.time() + ttl


def _expired(expires_at: float | None) -> bool:
    return expires_at is not None and expires_at <= time.time()


def _from_lua_options(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {str(key): value[key] for key in value}
    if hasattr(value, "keys") and hasattr(value, "__getitem__"):
        return {str(key): value[key] for key in value.keys()}
    raise LuaDecisionError("state options must be a table/object")


def _normalize_snapshot_state(state: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in state.items():
        if value is not None:
            result[str(key)] = str(value)
    return result
