"""evaluate_identification and user_hid."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from _support import load_json
from shieldlabs import (
    NIL_UUID,
    DetectionFlags,
    Evaluation,
    Identification,
    ValidationError,
    evaluate_identification,
    user_hid,
)

CASES = {c["name"]: c for c in load_json("normalization-cases.json")["cases"]}
OBSERVED = datetime(2026, 9, 30, 12, 34, 57, tzinfo=timezone.utc)
NOW = OBSERVED + timedelta(seconds=30)


def _identification(**changes: Any) -> Identification:
    base = Identification.from_webhook_data(CASES["webhook_test_delivery"]["input"])
    base = replace(base, observed_at=OBSERVED, risk_score=10)
    return replace(base, **changes)


def test_missing_identification() -> None:
    assert evaluate_identification(None) == Evaluation(ok=False, reason="missing", band=None)


def test_clean_identification_is_ok() -> None:
    verdict = evaluate_identification(_identification(), now=NOW)
    assert verdict == Evaluation(ok=True, reason=None, band="trusted", flag=None)


def test_replay_callback_receives_request_id() -> None:
    seen: list[str] = []

    def is_replay(request_id: str) -> bool:
        seen.append(request_id)
        return True

    verdict = evaluate_identification(_identification(), now=NOW, is_replay=is_replay)
    assert verdict.reason == "replayed"
    assert verdict.band == "trusted"
    assert seen == ["13f84f05-7c2a-4e9b-9f1d-2a6b8c0e4d11"]
    assert evaluate_identification(_identification(), now=NOW, is_replay=lambda _: False).ok


def test_stale_identification() -> None:
    late = OBSERVED + timedelta(seconds=301)
    assert evaluate_identification(_identification(), now=late).reason == "stale"
    assert evaluate_identification(_identification(), now=OBSERVED + timedelta(seconds=300)).ok
    assert evaluate_identification(_identification(), now=late, max_age=600).ok
    assert evaluate_identification(_identification(), now=late, max_age=timedelta(minutes=10)).ok
    assert evaluate_identification(_identification(observed_at=None), now=NOW).reason == "stale"


def test_now_defaults_to_current_time() -> None:
    fresh = _identification(observed_at=datetime.now(timezone.utc) - timedelta(seconds=5))
    assert evaluate_identification(fresh).ok
    old = _identification(observed_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert evaluate_identification(old).reason == "stale"


def test_naive_datetimes_are_treated_as_utc() -> None:
    naive_now = NOW.replace(tzinfo=None)
    assert evaluate_identification(_identification(), now=naive_now).ok
    naive_observed = _identification(observed_at=OBSERVED.replace(tzinfo=None))
    assert evaluate_identification(naive_observed, now=NOW).ok


def test_future_observed_at_is_not_stale() -> None:
    ahead = _identification(observed_at=NOW + timedelta(seconds=5))
    assert evaluate_identification(ahead, now=NOW).ok


def test_rate_limit_marker() -> None:
    marker = Identification.from_webhook_data(CASES["webhook_rate_limited"]["input"])
    marker = replace(marker, observed_at=OBSERVED)
    verdict = evaluate_identification(marker, now=NOW)
    assert verdict == Evaluation(ok=False, reason="rate_limited", band="rate_limited")


def test_nil_device_id() -> None:
    verdict = evaluate_identification(_identification(device_id=NIL_UUID), now=NOW)
    assert verdict.reason == "no_device_signals"
    assert evaluate_identification(_identification(device_id=""), now=NOW).reason == (
        "no_device_signals"
    )


def test_blocked_flags_in_order() -> None:
    flags = DetectionFlags(javascript_disabled=True, browser_automation=True)
    verdict = evaluate_identification(_identification(detection_flags=flags), now=NOW)
    assert verdict == Evaluation(
        ok=False, reason="blocked_flag", band="trusted", flag="browser_automation"
    )
    only_js = DetectionFlags(javascript_disabled=True)
    assert (
        evaluate_identification(_identification(detection_flags=only_js), now=NOW).flag
        == "javascript_disabled"
    )


def test_custom_block_flags() -> None:
    flags = DetectionFlags(vpn=True, browser_automation=True)
    identification = _identification(detection_flags=flags)
    assert evaluate_identification(identification, now=NOW, block_flags=["vpn"]).flag == "vpn"
    assert evaluate_identification(identification, now=NOW, block_flags="vpn").flag == "vpn"
    assert evaluate_identification(identification, now=NOW, block_flags=()).ok


def test_blocked_bands() -> None:
    dangerous = _identification(risk_score=80)
    assert evaluate_identification(dangerous, now=NOW) == Evaluation(
        ok=False, reason="blocked_band", band="dangerous"
    )
    suspicious = _identification(risk_score=45)
    assert evaluate_identification(suspicious, now=NOW).ok
    both = ["suspicious", "dangerous"]
    assert evaluate_identification(suspicious, now=NOW, block_bands=both).reason == "blocked_band"
    assert evaluate_identification(dangerous, now=NOW, block_bands="suspicious").ok
    assert evaluate_identification(dangerous, now=NOW, block_bands=[]).ok


def test_check_order_replay_before_stale_before_marker() -> None:
    marker = _identification(risk_score=999, device_id=NIL_UUID)
    late = NOW + timedelta(hours=1)
    assert evaluate_identification(marker, now=late, is_replay=lambda _: True).reason == "replayed"
    assert evaluate_identification(marker, now=late).reason == "stale"
    assert evaluate_identification(marker, now=NOW).reason == "rate_limited"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"block_bands": ["critical"]},
        {"block_flags": ["automation"]},
        {"block_flags": "anti_detect"},
        {"max_age": "300"},
        {"max_age": True},
        {"max_age": None},
    ],
)
def test_invalid_policy_arguments(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        evaluate_identification(_identification(), now=NOW, **kwargs)


@pytest.mark.parametrize(
    "max_age",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        -1,
        -0.5,
        timedelta(seconds=-1),
        10**400,
    ],
)
def test_freshness_window_must_be_finite_and_not_negative(max_age: Any) -> None:
    # A window that can never be exceeded would silently accept stale identifications.
    old = _identification(observed_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ValidationError, match="max_age"):
        evaluate_identification(old, now=NOW, max_age=max_age)
    with pytest.raises(ValidationError, match="max_age"):
        evaluate_identification(None, max_age=max_age)


def test_zero_freshness_window() -> None:
    assert evaluate_identification(_identification(), now=OBSERVED, max_age=0).ok
    assert evaluate_identification(_identification(), now=NOW, max_age=timedelta()).reason == (
        "stale"
    )


def test_user_hid_is_hmac_sha256_hex() -> None:
    expected = hmac.new(b"server-secret", b"user-42", hashlib.sha256).hexdigest()
    assert user_hid("user-42", "server-secret") == expected
    assert user_hid("user-42", b"server-secret") == expected
    assert len(expected) == 64
    assert user_hid("user-42", "server-secret") == user_hid("user-42", "server-secret")
    assert user_hid("user-43", "server-secret") != expected


def test_user_hid_known_vector() -> None:
    # HMAC-SHA256(key="key", message="The quick brown fox jumps over the lazy dog")
    assert user_hid("The quick brown fox jumps over the lazy dog", "key") == (
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    )


def test_user_hid_unicode_is_utf8() -> None:
    expected = hmac.new(b"k", "élève".encode(), hashlib.sha256).hexdigest()
    assert user_hid("élève", "k") == expected


@pytest.mark.parametrize(
    ("user_id", "secret"),
    [("", "secret"), ("user", ""), ("user", b""), (42, "secret"), ("user", None)],
)
def test_user_hid_rejects_empty_input(user_id: Any, secret: Any) -> None:
    with pytest.raises(ValidationError):
        user_hid(user_id, secret)
