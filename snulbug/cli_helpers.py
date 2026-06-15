from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable, TextIO


def add_token_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    parser.add_argument("--token", help=help)


def add_token_env_arg(
    parser: argparse.ArgumentParser,
    *,
    help: str,
    default: str | None = None,
) -> None:
    kwargs: dict[str, Any] = {"help": help}
    if default is not None:
        kwargs["default"] = default
    parser.add_argument("--token-env", **kwargs)


def add_allow_path_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    parser.add_argument("--allow-path", action="append", default=[], help=help)


def add_force_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    parser.add_argument("--force", action="store_true", help=help)


def add_validate_arg(
    parser: argparse.ArgumentParser,
    *,
    help: str,
    default: bool = True,
) -> None:
    parser.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=default,
        help=help,
    )


def add_compact_arg(parser: argparse.ArgumentParser, *, help: str = "emit compact JSON") -> None:
    parser.add_argument("--compact", action="store_true", help=help)


def add_report_out_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    parser.add_argument("--report-out", type=Path, help=help)


def add_sarif_out_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    parser.add_argument("--sarif-out", type=Path, help=help)


def format_json_output(payload: Any, *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, indent=2, sort_keys=True)


def write_json_output(payload: Any, *, compact: bool, stream: TextIO | None = None) -> None:
    output = format_json_output(payload, compact=compact)
    target = stream or sys.stdout
    target.write(output)
    target.write("\n")


def write_result_output(
    payload: Any,
    *,
    compact: bool,
    formatter: Callable[[Any], str] | None = None,
    stream: TextIO | None = None,
) -> None:
    target = stream or sys.stdout
    if compact or formatter is None:
        target.write(format_json_output(payload, compact=compact))
    else:
        target.write(formatter(payload))
    target.write("\n")


def write_generated_session_output(
    payload: Any,
    *,
    compact: bool,
    formatter: Callable[[Any], str] | None = None,
    stream: TextIO | None = None,
    include_legacy: bool = True,
    redact_compact: bool = False,
) -> None:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("generated_session"), Mapping):
        write_result_output(payload, compact=compact, formatter=formatter, stream=stream)
        return

    target = stream or sys.stdout
    if compact:
        from .scaffolds import session_summary

        output = session_summary(payload["generated_session"], redact=redact_compact)
        if include_legacy:
            output["legacy"] = {str(key): value for key, value in payload.items() if key != "generated_session"}
        target.write(format_json_output(output, compact=True))
    else:
        if formatter is not None:
            target.write(formatter(payload))
        else:
            from .scaffolds import format_session_report

            target.write(format_session_report(payload["generated_session"]))
    target.write("\n")


def write_report_output(
    report_out: str | Path,
    report_text: str,
    result: dict[str, Any],
    *,
    report_format: str | None = None,
    trailing_newline: bool = False,
) -> None:
    path = Path(report_out)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = report_text
    if trailing_newline and not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")
    result["report_out"] = str(path)
    if report_format is not None:
        result["report_format"] = report_format


def write_sarif_output(
    sarif_out: str | Path,
    sarif: Mapping[str, Any],
    result: dict[str, Any],
) -> None:
    path = Path(sarif_out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["sarif_out"] = str(path)
