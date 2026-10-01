"""Policy and identity helpers."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal, Optional, Union, get_args

from ._errors import ValidationError
from ._models import Identification
from ._normalize import FLAG_KEYS, RiskBand, is_rate_limited, risk_band
from ._validation import validate_seconds

__all__ = ["Evaluation", "EvaluationReason", "evaluate_identification", "user_hid"]

EvaluationReason = Literal[
    "missing",
    "replayed",
    "stale",
    "rate_limited",
    "no_device_signals",
    "blocked_flag",
    "blocked_band",
]
"""Why ``evaluate_identification`` refused an identification."""

_BANDS = frozenset(get_args(RiskBand))
_FLAGS = frozenset(FLAG_KEYS)


@dataclass(frozen=True)
class Evaluation:
    """Result of ``evaluate_identification``.

    Attributes:
        ok: ``True`` when no check failed.
        reason: The first check that failed, or ``None`` when ``ok``.
        band: Risk band of the identification (``None`` when it is missing).
        flag: The detection flag that blocked it, when ``reason`` is ``"blocked_flag"``.
    """

    ok: bool
    reason: Optional[EvaluationReason]
    band: Optional[RiskBand]
    flag: Optional[str] = None


def _names(
    values: Union[str, Iterable[str]], allowed: frozenset[str], what: str
) -> tuple[str, ...]:
    items = (values,) if isinstance(values, str) else tuple(values)
    for item in items:
        if item not in allowed:
            known = ", ".join(sorted(allowed))
            raise ValidationError(f"unknown {what} {item!r}; expected one of {known}")
    return items


def _max_age_seconds(max_age: Union[float, timedelta]) -> float:
    # A NaN, infinite or negative window would silently disable or invert the freshness check.
    if isinstance(max_age, timedelta):
        return validate_seconds(max_age.total_seconds(), "max_age", allow_zero=True)
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
        raise ValidationError("max_age must be a number of seconds or a timedelta")
    return validate_seconds(max_age, "max_age", allow_zero=True)


def evaluate_identification(
    identification: Optional[Identification],
    *,
    max_age: Union[float, timedelta] = 300.0,
    now: Optional[datetime] = None,
    block_bands: Iterable[str] = ("dangerous",),
    block_flags: Iterable[str] = ("browser_automation", "javascript_disabled"),
    is_replay: Optional[Callable[[str], bool]] = None,
) -> Evaluation:
    """Apply a starting-point policy to one identification before a protected action.

    Checks run in this order and the first failure wins:

    1. ``missing``: no identification (unverified, never clean).
    2. ``replayed``: ``is_replay(request_id)`` returned ``True``. The SDK stores nothing; keep
       used request IDs in your own store.
    3. ``stale``: ``observed_at`` is older than ``max_age`` (a finite number of seconds, 0 or
       greater, or a timedelta).
    4. ``rate_limited``: the Risk Score is the rate-limit marker (above 100).
    5. ``no_device_signals``: the device ID is the all-zero UUID.
    6. ``blocked_flag``: a flag in ``block_flags`` is set (reported in ``flag``).
    7. ``blocked_band``: the risk band is in ``block_bands``.

    The defaults are a starting point: tune ``block_bands``, ``block_flags`` and ``max_age``
    to your product.

    Raises:
        ValidationError: An unknown band or flag name, or an invalid ``max_age``.
    """
    bands = _names(block_bands, _BANDS, "band")
    flags = _names(block_flags, _FLAGS, "detection flag")
    max_age_seconds = _max_age_seconds(max_age)

    if identification is None:
        return Evaluation(ok=False, reason="missing", band=None)
    band = risk_band(identification.risk_score)
    if is_replay is not None and is_replay(identification.request_id):
        return Evaluation(ok=False, reason="replayed", band=band)

    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    observed = identification.observed_at
    if observed is not None and observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    if observed is None or (current - observed).total_seconds() > max_age_seconds:
        return Evaluation(ok=False, reason="stale", band=band)

    if is_rate_limited(identification.risk_score):
        return Evaluation(ok=False, reason="rate_limited", band=band)
    if not identification.has_device_signals:
        return Evaluation(ok=False, reason="no_device_signals", band=band)
    for name in flags:
        if getattr(identification.detection_flags, name):
            return Evaluation(ok=False, reason="blocked_flag", band=band, flag=name)
    if band in bands:
        return Evaluation(ok=False, reason="blocked_band", band=band)
    return Evaluation(ok=True, reason=None, band=band)


def user_hid(user_id: str, secret: Union[str, bytes]) -> str:
    """Derive a stable, irreversible User HID for one of your accounts.

    Returns HMAC-SHA256(key = ``secret``, message = ``user_id``) as 64 lowercase hex
    characters. Compute it on your server and pass it to the browser agent instead of a raw
    email address or account ID. Keep ``secret`` private and stable: changing it changes
    every User HID.

    Raises:
        ValidationError: ``user_id`` or ``secret`` is empty or not a string.
    """
    if not isinstance(user_id, str) or not user_id:
        raise ValidationError("user_id must be a non-empty string")
    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        raise ValidationError("secret must be a string or bytes")
    if not key:
        raise ValidationError("secret must not be empty")
    return hmac.new(key, user_id.encode("utf-8"), hashlib.sha256).hexdigest()
