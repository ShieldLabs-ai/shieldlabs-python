"""Typed, tolerant boundary between generated HTTP fields and public models.

Annotations check the declared contract at build time. Runtime checks deliberately keep
the SDK's historical missing/null/malformed defaults, without validating whole responses.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional, Union

from ._normalize import as_int, as_str


def text(value: Optional[str]) -> str:
    return as_str(value)


def integer(value: Optional[Union[int, float]], default: int = 0) -> int:
    return as_int(value, default)


def boolean(value: Optional[bool]) -> bool:
    return bool(value)


def mapping(value: Optional[Mapping[str, object]]) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def records(value: Optional[list[Mapping[str, object]]]) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []
