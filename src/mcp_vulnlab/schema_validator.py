"""Validate JSON arguments and run cooperative async in-memory mock tools."""

import asyncio
import json
import math
from collections.abc import Awaitable, Callable, Iterable
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry


class InputTooLarge(ValueError):
    """The compact UTF-8 JSON representation exceeds its byte budget."""


def normalize_path(value: str) -> str:
    """Normalize a relative POSIX path within a virtual root, without I/O."""
    if not isinstance(value, str) or not value:
        raise ValueError("expected a nonempty relative POSIX path")
    path = PurePosixPath(value)
    if path.anchor or PureWindowsPath(value).drive or "\\" in value or "\0" in value:
        raise ValueError("expected a relative POSIX path")

    parts = []
    for part in path.parts:
        if part == "..":
            if not parts:
                raise ValueError("path leaves the virtual root")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) or "."


async def run_mock(
    tool: Callable[[dict[str, Any]], Awaitable[Any]],
    arguments: dict[str, Any],
    schema: dict[str, Any] | bool,
    *,
    path_fields: Iterable[str] = (),
    max_bytes: int = 64 * 1024,
    timeout: float = 1.0,
) -> Any:
    """Check JSON and selected paths before invoking a trusted async mock.

    Schema validation covers both the supplied and normalized arguments. Only
    in-document schema references are available. The deadline covers the mock
    call and relies on the callable yielding and honoring cancellation.
    """
    if max_bytes <= 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("byte limit and timeout must be positive and finite")
    if not isinstance(arguments, dict):
        raise TypeError("tool arguments must be a JSON object")

    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    chunks = []
    size = 0
    for chunk in encoder.iterencode(arguments):
        remaining = max_bytes - size
        if len(chunk) > remaining:
            raise InputTooLarge(f"arguments exceed {max_bytes} UTF-8 bytes")
        size += len(chunk.encode("utf-8"))
        if size > max_bytes:
            raise InputTooLarge(f"arguments exceed {max_bytes} UTF-8 bytes")
        chunks.append(chunk)
    payload = json.loads("".join(chunks))

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, registry=Registry())
    validator.validate(payload)
    for field in path_fields:
        if field in payload:
            payload[field] = normalize_path(payload[field])
    validator.validate(payload)

    async with asyncio.timeout(timeout):
        return await tool(payload)
