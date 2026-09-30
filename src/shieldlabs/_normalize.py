"""Shared normalization rules.

History API rows and webhook ``data`` objects describe the same identification with different
field names. The helpers here implement the normalization rules that every ShieldLabs server SDK
follows (signal names, timestamps, IP sentinels, risk bands), so that both sources produce the
same ``Identification``.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

__all__ = [
    "FLAG_KEYS",
    "HISTORY_FLAG_MAP",
    "NIL_UUID",
    "TRAFFIC_KEYS",
    "RiskBand",
    "as_int",
    "as_str",
    "clean_ip",
    "fallback_slug",
    "format_timestamp",
    "is_rate_limited",
    "parse_history_time",
    "parse_rfc3339",
    "risk_band",
    "signal_slug",
]

RiskBand = Literal["trusted", "suspicious", "dangerous", "rate_limited"]
"""Client-side label of a Risk Score. ``rate_limited`` marks the 999 marker, not a band."""

NIL_UUID = "00000000-0000-0000-0000-000000000000"
"""The all-zero UUID. As a device ID it means "no usable device signals"."""

FLAG_KEYS: tuple[str, ...] = (
    "vpn",
    "privacy_relay",
    "browser_vpn_proxy",
    "tor",
    "proxy",
    "datacenter_ip",
    "abuser",
    "os_mismatch",
    "os_not_detected",
    "timezone_mismatch",
    "anti_detect_browser",
    "browser_automation",
    "ip_mismatch",
    "incognito",
    "search_bot",
    "suspicious_paid_click",
    "javascript_disabled",
    "stun_not_checked",
    "check_incomplete",
)
"""The 19 detection flags, in wire order."""

HISTORY_FLAG_MAP: dict[str, str] = {
    "vpn": "is_vpn",
    "privacy_relay": "is_privacy_relay",
    "tor": "is_tor",
    "proxy": "is_proxy",
    "datacenter_ip": "is_datacenter",
    "abuser": "is_abuser",
    "os_mismatch": "is_os_mismatch",
    "os_not_detected": "is_os_not_detected",
    "timezone_mismatch": "is_timezone_mismatch",
    "anti_detect_browser": "is_antidetect",
    "browser_automation": "is_browser_automation",
    "incognito": "is_incognito",
    "search_bot": "is_search_bot",
    "suspicious_paid_click": "is_suspicious_paid_click",
    "javascript_disabled": "is_js_disabled",
    "stun_not_checked": "is_stun_not_checked",
    "check_incomplete": "check_incomplete",
}
"""Detection flag to History row column (``browser_vpn_proxy`` and ``ip_mismatch`` are derived)."""

TRAFFIC_KEYS: tuple[str, ...] = (
    "channel",
    "referrer_domain",
    "landing_url",
    "click_id_type",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
)

_EXACT_SLUGS: dict[str, str] = {
    "Is tor": "tor",
    "Is VPN": "vpn",
    "Is privacy relay": "privacy_relay",
    "Is proxy": "proxy",
    "Is datacenter": "datacenter_ip",
    "Is abuser": "abuser",
    "Stun is not checked": "stun_not_checked",
    "Stun passed (late arrival, corrected)": "stun_late_correction",
    "UA OS is not detected": "os_not_detected",
    "Network OS is not detected": "os_not_detected",
    "Browser timezone ≠ IP-timezone": "timezone_mismatch",
    "Browser VPN/Proxy": "browser_vpn_proxy",
    "Browser Automation": "browser_automation",
    "Port scan routed via proxy (antidetect browser pattern)": "proxy_routed_antidetect",
    "User has been banned 1H, to many requests": "rate_limited",
}

_PREFIX_SLUGS: tuple[tuple[str, str], ...] = (
    ("Antidetect browser", "antidetect_browser"),
    ("Os_mismatch", "os_mismatch"),
    ("OS mismatch2", "os_mismatch2"),
    ("TCP handshake", "tcp_handshake_v2"),
    ("Latency test", "ws_tcp_latency"),
    ("JavaScript disabled", "javascript_disabled"),
)

_STICKY_PREFIX = "Sticky verdict: "
_NOT_EQUAL = "≠"
_SEPARATORS = (" ", "-", "/")


def _is_letter_or_digit(ch: str) -> bool:
    category = unicodedata.category(ch)
    return category.startswith("L") or category == "Nd"


def fallback_slug(description: str) -> str:
    """Slugify a free-text description: the text before the first ``(``, lowercased."""
    text = description.strip()
    paren = text.find("(")
    if paren >= 0:
        text = text[:paren].strip()
    out: list[str] = []
    prev_sep = False
    for ch in text:
        if ch in _SEPARATORS:
            if not prev_sep and out:
                out.append("_")
                prev_sep = True
        elif ch == _NOT_EQUAL:
            out.append("_neq_")
            prev_sep = False
        elif _is_letter_or_digit(ch):
            out.append(ch.lower())
            prev_sep = False
    slug = "".join(out).strip("_")
    return slug or "unknown"


def signal_slug(description: str) -> str:
    """Map a History ``score_details`` description to the risk signal name used on webhooks."""
    exact = _EXACT_SLUGS.get(description)
    if exact is not None:
        return exact
    for prefix, slug in _PREFIX_SLUGS:
        if description.startswith(prefix):
            return slug
    if description.startswith(_STICKY_PREFIX):
        colon = description.find(":")
        rest = description[colon + 1 :].strip()
        return fallback_slug(rest)
    return fallback_slug(description)


_HISTORY_TIME = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:?[0-9]{2})?$"
)
_RFC3339_TIME = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$"
)


def _build_utc(match: re.Match[str]) -> Optional[datetime]:
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction = match.group(7) or ""
    microsecond = int(fraction[:6].ljust(6, "0"))
    try:
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_history_time(value: object) -> Optional[datetime]:
    """Parse History ``created_at`` (``YYYY-MM-DD HH:MM:SS[.fff]``, UTC) into an aware datetime.

    The value carries no zone; it is always UTC. A trailing designator, if any, is ignored.
    Returns ``None`` when the value is empty or not in that format.
    """
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        return None
    match = _HISTORY_TIME.match(text)
    if match is None:
        return None
    return _build_utc(match)


def parse_rfc3339(value: object) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp (up to 9 fractional digits) into an aware UTC datetime.

    Sub-microsecond digits are truncated. Returns ``None`` when the value is not RFC 3339.
    """
    if not isinstance(value, str):
        return None
    match = _RFC3339_TIME.match(value)
    if match is None:
        return None
    moment = _build_utc(match)
    if moment is None:
        return None
    designator = match.group(8)
    if designator == "Z":
        return moment
    sign = 1 if designator[0] == "+" else -1
    offset = timedelta(hours=int(designator[1:3]), minutes=int(designator[4:6]))
    try:
        return moment - sign * offset
    except OverflowError:
        return None


def format_timestamp(moment: Optional[datetime]) -> Optional[str]:
    """Format a datetime as RFC 3339 UTC with millisecond precision (truncated) and ``Z``."""
    if moment is None:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}."
        f"{moment.microsecond // 1000:03d}Z"
    )


def as_str(value: object) -> str:
    """Return ``value`` when it is a string, else ``""``."""
    return value if isinstance(value, str) else ""


def as_int(value: object, default: int = 0) -> int:
    """Return ``value`` as an integer when it is one (booleans excluded), else ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return default


def clean_ip(value: object) -> str:
    """Normalize an IP string: surrounding whitespace removed, ``0.0.0.0`` becomes ``""``."""
    text = as_str(value).strip()
    return "" if text in ("", "0.0.0.0") else text


def risk_band(score: int) -> RiskBand:
    """Return the risk band of a Risk Score.

    ``trusted`` for 0-29, ``suspicious`` for 30-59, ``dangerous`` for 60-100, and
    ``rate_limited`` for values above 100 (the 999 rate-limit marker is not a score).
    """
    if score > 100:
        return "rate_limited"
    if score >= 60:
        return "dangerous"
    if score >= 30:
        return "suspicious"
    return "trusted"


def is_rate_limited(score: int) -> bool:
    """Return ``True`` for the rate-limit marker (any value above 100, in practice 999)."""
    return score > 100
