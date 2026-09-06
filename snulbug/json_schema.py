"""Offline JSON Schema 2020-12 validation with bounded, value-free diagnostics."""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from itertools import islice
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012

DIALECT = "https://json-schema.org/draft/2020-12/schema"
MAX_SCHEMA_BYTES = 256 * 1024
MAX_NODES = 10000
MAX_DEPTH = 64
MAX_ISSUES = 20


class SchemaBoundaryError(ValueError):
    pass


def _no_retrieval(uri: str):
    raise NoSuchResource(ref=uri)


def _check_size(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise SchemaBoundaryError("schema.validation_limit")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise SchemaBoundaryError("schema.non_json")
            children = item.values()
        elif isinstance(item, list):
            children = item
        else:
            if not isinstance(item, (str, int, float, bool, type(None))) or (
                isinstance(item, float) and not math.isfinite(item)
            ):
                raise SchemaBoundaryError("schema.non_json")
            continue
        if count + len(pending) + len(children) > MAX_NODES:
            raise SchemaBoundaryError("schema.validation_limit")
        pending.extend((child, depth + 1) for child in children)


@lru_cache(maxsize=64)
def _compiled(encoded: str) -> Draft202012Validator:
    schema = json.loads(encoded)
    Draft202012Validator.check_schema(schema)
    pending = [DRAFT202012.create_resource(schema)]
    while pending:
        resource = pending.pop()
        contents = resource.contents
        if isinstance(contents, dict):
            dialect = contents.get("$schema", DIALECT)
            if dialect not in (DIALECT, DIALECT + "#"):
                raise SchemaBoundaryError("schema.dialect_unsupported")
        pending.extend(resource.subresources())
    # An explicit registry disables jsonschema's deprecated automatic URL retrieval.
    return Draft202012Validator(schema, registry=Registry(retrieve=_no_retrieval))


def _issue(path: str, code: str, message: str) -> dict[str, str]:
    return {"path": path[:512], "reason_code": code, "message": message}


def validate_schema(value: Any, schema: Any, *, path: str = "$") -> list[dict[str, str]]:
    """Return existing policy issue records; never expose library exception messages."""
    try:
        _check_size(schema)
        _check_size(value)
        encoded = json.dumps(schema, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > MAX_SCHEMA_BYTES:
            raise SchemaBoundaryError("schema.validation_limit")
        validator = _compiled(encoded)
        issues = []
        for error in islice(validator.iter_errors(value), MAX_ISSUES):
            issue_path = path
            for segment in error.absolute_path:
                if isinstance(segment, int):
                    issue_path += f"[{segment}]"
                elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(segment)):
                    issue_path += "." + str(segment)
                else:
                    issue_path += "[" + json.dumps(str(segment)) + "]"
            keyword = error.validator or "false"
            code = re.sub(r"(?<!^)([A-Z])", r"_\1", keyword).lower()
            issues.append(_issue(issue_path, "schema." + code, f"value does not satisfy {keyword}"))
        return issues
    except SchemaBoundaryError as exc:
        return [_issue(path, str(exc), "schema validation is outside the supported boundary")]
    except SchemaError:
        return [_issue(path, "schema.invalid", "schema is not valid JSON Schema 2020-12")]
    except Unresolvable:
        return [_issue(path, "schema.ref_unresolved", "schema reference cannot be resolved offline")]
    except RecursionError:
        return [_issue(path, "schema.ref_cycle", "schema evaluation exceeded the recursion limit")]
    except (ValueError, TypeError, OverflowError, re.error):
        return [_issue(path, "schema.invalid", "schema could not be evaluated")]
