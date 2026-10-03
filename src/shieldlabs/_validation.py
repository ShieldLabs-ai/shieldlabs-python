"""Argument validation shared by the clients. Every check runs before any HTTP request."""

from __future__ import annotations

import ipaddress
import math
import os
import re
import warnings
from typing import Optional, Union
from urllib.parse import quote, urlsplit
from uuid import UUID

from ._errors import ShieldLabsWarning, ValidationError
from ._generated_wire import LookupType as LookupType

__all__ = [
    "DEFAULT_HISTORY_BASE_URL",
    "DEFAULT_MANAGEMENT_BASE_URL",
    "LOOKUP_TYPES",
    "LookupType",
    "history_origin",
    "management_origin",
    "normalize_domain",
    "require_secret",
    "resolve_api_key",
    "validate_count",
    "validate_limit",
    "validate_lookup",
    "validate_max_retries",
    "validate_offset",
    "validate_seconds",
    "validate_uuid",
]

LOOKUP_TYPES: tuple[LookupType, ...] = (
    "ip",
    "user_hid",
    "visitor_id",
    "request_id",
    "device_id",
    "session_id",
    "cookie_id",
)

DEFAULT_HISTORY_BASE_URL = "https://account.shieldlabs.ai"
DEFAULT_MANAGEMENT_BASE_URL = "https://api.shieldlabs.ai"

_UUID_TYPES = frozenset({"visitor_id", "request_id", "device_id", "session_id", "cookie_id"})
_UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_PATTERN = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")
_API_KEY_PATTERN = re.compile(r"sec_[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}")
_URL_PATTERN = re.compile(r"https?://[^/\s?#]+(?:/[^\s?#]*)?", re.IGNORECASE)

# The History API matches a User HID only when its path segment uses this canonical escaping:
# letters, digits, "-._~" and the characters below stay as they are, everything else is
# percent-encoded as UTF-8 with uppercase hex. Any other spelling (for example "%40" for "@")
# is compared literally and matches nothing.
_USER_HID_SAFE = "$&+,:;=@"


def _text(value: Union[str, UUID], name: str) -> str:
    if isinstance(value, UUID):
        return str(value)
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string, got {type(value).__name__}")
    return value


def validate_uuid(value: Union[str, UUID], name: str = "request_id") -> str:
    """Return the UUID in lowercase, or raise ``ValidationError``. Any version, nil allowed."""
    text = _text(value, name)
    if not _UUID_PATTERN.fullmatch(text):
        raise ValidationError(f"{name} must be a UUID like 8f14e45f-ceea-4c1e-a3b2-1d2c3b4a5f60")
    return text.lower()


def validate_lookup(lookup_type: str, value: Union[str, UUID]) -> tuple[str, str]:
    """Validate a History lookup and return ``(type, value as an encoded path segment)``."""
    if lookup_type not in LOOKUP_TYPES:
        allowed = ", ".join(LOOKUP_TYPES)
        raise ValidationError(f"type must be one of {allowed}; got {lookup_type!r}")
    if lookup_type in _UUID_TYPES:
        return lookup_type, validate_uuid(value, lookup_type)
    text = _text(value, lookup_type)
    if lookup_type == "ip":
        if ":" in text:
            raise ValidationError(
                "ip must be a dotted IPv4 address; IPv6 addresses are not searchable"
            )
        if not _IPV4_PATTERN.fullmatch(text):
            raise ValidationError(
                f"ip must be a dotted IPv4 address such as 203.0.113.7; got {text!r}"
            )
        return lookup_type, text
    return lookup_type, _user_hid_segment(text)


def _user_hid_segment(text: str) -> str:
    """Encode a User HID as one path segment the History API can match, or raise."""
    if text == "":
        raise ValidationError("user_hid must be a non-empty string")
    if text in (".", ".."):
        raise ValidationError(
            f"user_hid {text!r} cannot be searched: URL handling removes '.' and '..' "
            "path segments, so the lookup would request a different path"
        )
    if "/" in text:
        raise ValidationError(
            "user_hid values that contain '/' cannot be searched in the History API; "
            "use User HIDs without '/', such as the hex output of user_hid()"
        )
    try:
        return quote(text, safe=_USER_HID_SAFE)
    except UnicodeEncodeError:
        raise ValidationError(
            "user_hid must be valid Unicode text (it contains an unpaired surrogate)"
        ) from None


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer, got {value!r}")
    return value


def validate_limit(value: object, name: str = "limit") -> int:
    """An integer from 1 to 100 (the server silently replaces other values with 20)."""
    number = _integer(value, name)
    if not 1 <= number <= 100:
        raise ValidationError(f"{name} must be between 1 and 100, got {number}")
    return number


def validate_count(value: object, name: str) -> int:
    """An integer that is 0 or greater."""
    number = _integer(value, name)
    if number < 0:
        raise ValidationError(f"{name} must be 0 or greater, got {number}")
    return number


def validate_offset(value: object) -> int:
    return validate_count(value, "offset")


def validate_max_retries(value: object) -> int:
    return validate_count(value, "max_retries")


def validate_seconds(value: object, name: str, *, allow_zero: bool) -> float:
    """A finite number of seconds; positive, or non-negative when ``allow_zero``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{name} must be a number of seconds, got {value!r}")
    try:
        seconds = float(value)
    except OverflowError:  # an int too large for a float
        raise ValidationError(f"{name} must be a finite number of seconds") from None
    if not math.isfinite(seconds):
        raise ValidationError(f"{name} must be a finite number of seconds, got {value!r}")
    if seconds < 0 or (seconds == 0 and not allow_zero):
        qualifier = "0 or greater" if allow_zero else "greater than 0"
        raise ValidationError(f"{name} must be {qualifier}, got {value!r}")
    return seconds


def _base_url(value: Optional[str], env_name: str, default: str) -> str:
    if value is None:
        value = os.environ.get(env_name) or default
    if not isinstance(value, str):
        raise ValidationError("base_url must be a string")
    url = value.strip().rstrip("/")
    host = _url_host(url) if _URL_PATTERN.fullmatch(url) else None
    if not host:
        raise ValidationError(f"base_url must be an http(s) URL such as {default}; got {value!r}")
    if url[:5].lower() == "http:" and not _is_loopback(host):
        # Every request carries a credential, so plain http is limited to local test servers.
        raise ValidationError(
            f"base_url must use https; plain http is accepted only for localhost, 127.0.0.1 "
            f"and ::1 (got a plain http URL for {host})"
        )
    return url


def _url_host(url: str) -> Optional[str]:
    try:
        return urlsplit(url).hostname
    except ValueError:  # for example an unclosed IPv6 bracket
        return None


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def history_origin(base_url: Optional[str]) -> str:
    """History API origin. A trailing ``/api`` is removed: request paths already start with it."""
    url = _base_url(base_url, "SHIELDLABS_API_BASE_URL", DEFAULT_HISTORY_BASE_URL)
    if url.endswith("/api"):
        url = url[: -len("/api")]
    return url


def management_origin(base_url: Optional[str]) -> str:
    """Management API origin."""
    return _base_url(base_url, "SHIELDLABS_MANAGEMENT_BASE_URL", DEFAULT_MANAGEMENT_BASE_URL)


def _require_header_safe(text: str, name: str) -> None:
    # Checked up front so that an unusable value never reaches the HTTP layer, whose errors
    # could echo it. The value itself is never included in the message.
    if not all("!" <= ch <= "~" for ch in text):
        raise ValidationError(
            f"{name} contains characters that cannot be sent in an HTTP header "
            "(only visible ASCII characters are allowed)"
        )


def require_secret(value: Optional[str], env_name: str, name: str) -> str:
    """Return a credential from the argument or the environment, stripped; never empty."""
    if value is None:
        value = os.environ.get(env_name)
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    text = (value or "").strip()
    if not text:
        raise ValidationError(f"{name} is required: pass it or set {env_name}")
    _require_header_safe(text, name)
    return text


def resolve_api_key(value: Optional[str]) -> str:
    """Private API Key from the argument or ``SHIELDLABS_API_KEY``. Warns on an unusual shape."""
    key = require_secret(value, "SHIELDLABS_API_KEY", "api_key")
    if not _API_KEY_PATTERN.fullmatch(key):
        warnings.warn(
            "api_key does not look like a ShieldLabs Private API Key "
            "(sec_xxxxxxxx-xxxxxxxx-xxxxxxxx). The History API expects the Private API Key, "
            "not the Public Key or the Secret Key.",
            ShieldLabsWarning,
            stacklevel=4,
        )
    return key


def normalize_domain(value: Optional[str]) -> str:
    """Normalize a registered domain the way the server stores it.

    Trims and lowercases, then removes a scheme, any path, query or trailing slash, and a
    leading ``www.``. ``https://www.Example.com/`` becomes ``example.com``.
    """
    if value is None:
        value = os.environ.get("SHIELDLABS_DOMAIN")
    if value is not None and not isinstance(value, str):
        raise ValidationError("domain must be a string")
    text = (value or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    elif text.startswith("//"):
        text = text[2:]
    for separator in ("/", "?", "#"):
        text = text.split(separator, 1)[0]
    if text.startswith("www."):
        text = text[len("www.") :]
    if not text:
        raise ValidationError(
            "domain is required: pass the registered domain or set SHIELDLABS_DOMAIN"
        )
    if not text.isascii():
        raise ValidationError("domain must be ASCII: pass the punycode form (xn--...)")
    _require_header_safe(text, "domain")
    return text
