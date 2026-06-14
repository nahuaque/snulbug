from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScaffoldFile:
    path: str | Path
    content: str | bytes
    kind: str = "file"
    executable: bool = False
    encoding: str = "utf-8"


@dataclass(frozen=True)
class ScaffoldPlan:
    name: str
    root: str | Path
    files: Sequence[ScaffoldFile] = ()
    directories: Sequence[str | Path] = ()
    commands: Mapping[str, Any] = field(default_factory=dict)
    env: Mapping[str, Any] = field(default_factory=dict)
    client: Mapping[str, Any] = field(default_factory=dict)
    smoke_checks: Sequence[Mapping[str, Any]] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GeneratedArtifact:
    name: str
    path: str | Path
    kind: str = "file"
    description: str = ""


@dataclass(frozen=True)
class GeneratedCommand:
    name: str
    command: Any
    description: str = ""
    kind: str = "command"


@dataclass(frozen=True)
class GeneratedClient:
    name: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    config: str | Path | None = None
    description: str = ""


@dataclass(frozen=True)
class GeneratedEnv:
    name: str
    value: str
    description: str = ""


@dataclass(frozen=True)
class GeneratedLog:
    name: str
    path: str | Path
    kind: str = "jsonl"
    description: str = ""


@dataclass(frozen=True)
class GeneratedSession:
    name: str
    root: str | Path
    generated_by: str = ""
    artifacts: Sequence[GeneratedArtifact] = ()
    commands: Sequence[GeneratedCommand] = ()
    clients: Sequence[GeneratedClient] = ()
    env: Sequence[GeneratedEnv] = ()
    logs: Sequence[GeneratedLog] = ()
    next_steps: Sequence[str] = ()
    scaffolds: Sequence[Mapping[str, Any]] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


def json_scaffold_file(
    path: str | Path,
    value: Any,
    *,
    kind: str = "json",
    executable: bool = False,
) -> ScaffoldFile:
    return ScaffoldFile(
        path=path,
        content=json.dumps(value, indent=2, sort_keys=True) + "\n",
        kind=kind,
        executable=executable,
    )


def session_result(session: GeneratedSession, *, ok: bool = True) -> dict[str, Any]:
    artifacts = [_artifact_result(artifact) for artifact in session.artifacts]
    commands = [_command_result(command) for command in session.commands]
    clients = [_client_result(client) for client in session.clients]
    env = [_env_result(item) for item in session.env]
    logs = [_log_result(log) for log in session.logs]
    return {
        "ok": ok,
        "name": session.name,
        "generated_by": session.generated_by,
        "root": str(session.root),
        "artifacts": artifacts,
        "file_map": {artifact["name"]: artifact["path"] for artifact in artifacts},
        "commands": commands,
        "command_map": {command["name"]: command["command"] for command in commands},
        "clients": clients,
        "primary_client": clients[0] if clients else None,
        "env": env,
        "env_map": {item["name"]: item["value"] for item in env},
        "logs": logs,
        "log_map": {log["name"]: log["path"] for log in logs},
        "next_steps": list(session.next_steps),
        "scaffolds": [dict(scaffold) for scaffold in session.scaffolds],
        "metadata": dict(session.metadata),
    }


def session_summary(result: GeneratedSession | Mapping[str, Any], *, redact: bool = True) -> dict[str, Any]:
    session = session_result(result) if isinstance(result, GeneratedSession) else dict(result)
    summary = {
        "ok": session.get("ok"),
        "name": session.get("name"),
        "generated_by": session.get("generated_by"),
        "root": session.get("root"),
        "files": dict(_mapping(session.get("file_map"))),
        "commands": dict(_mapping(session.get("command_map"))),
        "client": dict(_mapping(session.get("primary_client"))),
        "env": dict(_mapping(session.get("env_map"))),
        "logs": dict(_mapping(session.get("log_map"))),
        "next_steps": list(_sequence(session.get("next_steps"))),
        "metadata": dict(_mapping(session.get("metadata"))),
    }
    return redact_session_secrets(summary) if redact else summary


def format_session_report(
    result: GeneratedSession | Mapping[str, Any],
    *,
    title: str | None = None,
    sections: Sequence[str] | None = None,
    extra_sections: Sequence[tuple[str, str | Sequence[str]]] = (),
    redact: bool = True,
) -> str:
    session = session_result(result) if isinstance(result, GeneratedSession) else dict(result)
    if redact:
        session = redact_session_secrets(session)
    active_sections = tuple(sections or ("overview", "client", "files", "env", "logs", "commands", "next_steps"))
    lines = [f"# {title or session.get('name') or 'snulbug session'}", ""]
    if "overview" in active_sections:
        _append_overview(lines, session)
    if "metadata" in active_sections:
        _append_metadata(lines, session)
    if "client" in active_sections:
        _append_clients(lines, session)
    if "files" in active_sections:
        _append_artifacts(lines, session)
    if "env" in active_sections:
        _append_env(lines, session)
    if "logs" in active_sections:
        _append_logs(lines, session)
    if "commands" in active_sections:
        _append_commands(lines, session)
    if "next_steps" in active_sections:
        _append_next_steps(lines, session)
    for heading, body in extra_sections:
        _append_extra_section(lines, heading, body)
    return "\n".join(lines).rstrip() + "\n"


def redact_session_secrets(value: Any) -> Any:
    return _redact_session_value(value, key=None)


def _append_overview(lines: list[str], session: Mapping[str, Any]) -> None:
    generated_by = session.get("generated_by")
    if generated_by:
        lines.extend([f"Generated by: `{generated_by}`", ""])
    root = session.get("root")
    if root:
        lines.extend([f"Root: `{root}`", ""])
    ok = session.get("ok")
    if isinstance(ok, bool):
        lines.extend([f"Status: `{'ok' if ok else 'failed'}`", ""])


def _append_metadata(lines: list[str], session: Mapping[str, Any]) -> None:
    metadata = _mapping(session.get("metadata"))
    if not metadata:
        return
    lines.extend(["## Metadata", "", "```json", json.dumps(metadata, indent=2, sort_keys=True), "```", ""])


def _append_clients(lines: list[str], session: Mapping[str, Any]) -> None:
    clients = _sequence(session.get("clients"))
    if not clients:
        primary = session.get("primary_client")
        clients = [primary] if isinstance(primary, Mapping) else []
    if not clients:
        return
    lines.extend(["## Client", ""])
    for client in clients:
        if not isinstance(client, Mapping):
            continue
        name = client.get("name")
        prefix = f"- `{name}`" if name else "-"
        lines.append(f"{prefix}: `{client.get('url')}`")
        config = client.get("config")
        if config:
            lines.append(f"  Config: `{config}`")
        headers = _mapping(client.get("headers"))
        if headers:
            lines.append("  Headers:")
            for key, value in headers.items():
                lines.append(f"  - `{key}`: `{value}`")
    lines.append("")


def _append_artifacts(lines: list[str], session: Mapping[str, Any]) -> None:
    artifacts = _sequence(session.get("artifacts"))
    if not artifacts:
        file_map = _mapping(session.get("file_map"))
        artifacts = [{"name": key, "path": value} for key, value in file_map.items()]
    if not artifacts:
        return
    lines.extend(["## Files", ""])
    for artifact in artifacts:
        if isinstance(artifact, Mapping):
            label = artifact.get("name") or artifact.get("kind") or "file"
            lines.append(f"- `{label}`: `{artifact.get('path')}`")
    lines.append("")


def _append_env(lines: list[str], session: Mapping[str, Any]) -> None:
    env = _sequence(session.get("env"))
    if not env:
        env_map = _mapping(session.get("env_map"))
        env = [{"name": key, "value": value} for key, value in env_map.items()]
    if not env:
        return
    lines.extend(["## Environment", ""])
    for item in env:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('name')}`: `{item.get('value')}`")
    lines.append("")


def _append_logs(lines: list[str], session: Mapping[str, Any]) -> None:
    logs = _sequence(session.get("logs"))
    if not logs:
        log_map = _mapping(session.get("log_map"))
        logs = [{"name": key, "path": value} for key, value in log_map.items()]
    if not logs:
        return
    lines.extend(["## Logs", ""])
    for log in logs:
        if isinstance(log, Mapping):
            lines.append(f"- `{log.get('name')}`: `{log.get('path')}`")
    lines.append("")


def _append_commands(lines: list[str], session: Mapping[str, Any]) -> None:
    commands = _sequence(session.get("commands"))
    if not commands:
        command_map = _mapping(session.get("command_map"))
        commands = [{"name": key, "command": value} for key, value in command_map.items()]
    if not commands:
        return
    lines.extend(["## Commands", ""])
    for command in commands:
        if not isinstance(command, Mapping):
            continue
        name = command.get("name") or "command"
        lines.append(f"- `{name}`:")
        for rendered in _command_lines(command.get("command")):
            lines.append(f"  - `{rendered}`")
    lines.append("")


def _append_next_steps(lines: list[str], session: Mapping[str, Any]) -> None:
    next_steps = _sequence(session.get("next_steps"))
    if not next_steps:
        return
    lines.extend(["## Next Steps", ""])
    lines.extend(f"- `{step}`" for step in next_steps)
    lines.append("")


def _append_extra_section(lines: list[str], heading: str, body: str | Sequence[str]) -> None:
    lines.extend([f"## {heading}", ""])
    if isinstance(body, str):
        lines.extend([body.rstrip(), ""])
    else:
        lines.extend(str(line) for line in body)
        lines.append("")


def write_scaffold(plan: ScaffoldPlan, *, force: bool = False) -> dict[str, Any]:
    root = Path(plan.root)
    directories = [_resolve_scaffold_path(root, directory) for directory in plan.directories]
    files = [_materialize_file(root, file) for file in plan.files]

    for directory in directories:
        if directory.exists() and not directory.is_dir():
            raise FileExistsError(f"{plan.name} output already exists and is not a directory: {directory}")
    for file, path in files:
        if path.exists() and not force:
            raise FileExistsError(f"{plan.name} output already exists: {path}")

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    for file, path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(file.content, bytes):
            path.write_bytes(file.content)
        else:
            path.write_text(file.content, encoding=file.encoding)
        if file.executable:
            path.chmod(path.stat().st_mode | 0o111)

    return scaffold_result(plan, files=files, directories=directories)


def scaffold_result(
    plan: ScaffoldPlan,
    *,
    files: Sequence[tuple[ScaffoldFile, Path]] | None = None,
    directories: Sequence[Path] | None = None,
) -> dict[str, Any]:
    root = Path(plan.root)
    materialized_files = list(files) if files is not None else [_materialize_file(root, file) for file in plan.files]
    materialized_dirs = (
        list(directories)
        if directories is not None
        else [_resolve_scaffold_path(root, directory) for directory in plan.directories]
    )
    return {
        "ok": True,
        "name": plan.name,
        "root": str(root),
        "files": [
            {
                "path": str(path),
                "kind": file.kind,
                "executable": file.executable,
            }
            for file, path in materialized_files
        ],
        "written_files": [str(path) for _file, path in materialized_files],
        "directories": [str(path) for path in materialized_dirs],
        "commands": dict(plan.commands),
        "env": dict(plan.env),
        "client": dict(plan.client),
        "smoke_checks": [dict(check) for check in plan.smoke_checks],
        "metadata": dict(plan.metadata),
    }


def format_scaffold_report(result: Mapping[str, Any]) -> str:
    lines = [f"# {result.get('name', 'snulbug scaffold')}", ""]
    root = result.get("root")
    if root:
        lines.extend([f"Root: `{root}`", ""])
    files = result.get("written_files")
    if isinstance(files, Sequence) and not isinstance(files, str | bytes | bytearray):
        lines.extend(["## Files", ""])
        lines.extend(f"- `{file}`" for file in files)
    commands = result.get("commands")
    if isinstance(commands, Mapping) and commands:
        lines.extend(["", "## Commands", ""])
        lines.extend(f"- `{key}`: `{value}`" for key, value in commands.items())
    return "\n".join(lines).rstrip() + "\n"


def _materialize_file(root: Path, file: ScaffoldFile) -> tuple[ScaffoldFile, Path]:
    return file, _resolve_scaffold_path(root, file.path)


def _resolve_scaffold_path(root: Path, path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else root / value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return value
    return []


def _command_lines(command: Any) -> list[str]:
    if isinstance(command, Sequence) and not isinstance(command, str | bytes | bytearray):
        return [str(item) for item in command]
    return [str(command)]


def _redact_session_value(value: Any, *, key: str | None) -> Any:
    if isinstance(value, Mapping):
        if _is_secret_key(str(value.get("name", ""))) and "value" in value:
            redacted = dict(value)
            redacted["value"] = "<redacted>"
            return redacted
        return {
            str(item_key): _redact_session_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_session_value(item, key=key) for item in value]
    if isinstance(value, str):
        if _normalized_key(key) == "authorization":
            return _redact_secret_text(value)
        if _is_secret_key(key):
            return "<redacted>"
        return _redact_secret_text(value)
    return value


def _is_secret_key(key: str | None) -> bool:
    normalized = _normalized_key(key)
    return normalized in {
        "authorization",
        "token",
        "access_token",
        "api_key",
        "x_api_key",
        "x_snulbug_lease",
        "password",
        "secret",
    } or normalized.endswith(("_token", "_secret", "_password", "_api_key"))


def _normalized_key(key: str | None) -> str:
    if not key:
        return ""
    return key.lower().replace("-", "_")


def _redact_secret_text(value: str) -> str:
    redacted = re.sub(r"\bBearer\s+[^'\"\s]+", "Bearer <redacted>", value)
    redacted = re.sub(r"\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)=([^'\"\s]+)", _redact_env_match, redacted)
    redacted = re.sub(r"\bsb[tl]_[A-Za-z0-9_-]+", "<redacted>", redacted)
    return redacted


def _redact_env_match(match: re.Match[str]) -> str:
    return match.group(0).split("=", 1)[0] + "=<redacted>"


def _artifact_result(artifact: GeneratedArtifact) -> dict[str, Any]:
    return {
        "name": artifact.name,
        "path": str(artifact.path),
        "kind": artifact.kind,
        "description": artifact.description,
    }


def _command_result(command: GeneratedCommand) -> dict[str, Any]:
    return {
        "name": command.name,
        "command": command.command,
        "kind": command.kind,
        "description": command.description,
    }


def _client_result(client: GeneratedClient) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": client.name,
        "url": client.url,
        "headers": dict(client.headers),
        "description": client.description,
    }
    if client.config is not None:
        result["config"] = str(client.config)
    return result


def _env_result(env: GeneratedEnv) -> dict[str, Any]:
    return {
        "name": env.name,
        "value": env.value,
        "description": env.description,
    }


def _log_result(log: GeneratedLog) -> dict[str, Any]:
    return {
        "name": log.name,
        "path": str(log.path),
        "kind": log.kind,
        "description": log.description,
    }
