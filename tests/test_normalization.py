"""Shared fixture tests: History rows and webhook data normalize into the same Identification."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from _support import load_json
from shieldlabs import (
    NIL_UUID,
    DetectionFlags,
    HistoryPage,
    Identification,
    IpInfo,
    Signal,
    SignalName,
    TrafficSource,
    is_rate_limited,
    risk_band,
)
from shieldlabs._normalize import (
    FLAG_KEYS,
    fallback_slug,
    format_timestamp,
    parse_history_time,
    parse_rfc3339,
    signal_slug,
)

NORMALIZATION = load_json("normalization-cases.json")["cases"]
SLUGS = load_json("signal-slug-cases.json")["cases"]
BANDS = load_json("risk-band-cases.json")["cases"]


def _normalize(case: dict[str, Any]) -> Identification:
    if case["source"] == "history":
        return Identification.from_history_row(case["input"])
    return Identification.from_webhook_data(case["input"])


def _truncate_ms(value: str) -> str:
    return value[:23]


def test_fixture_covers_both_sources() -> None:
    sources = {case["source"] for case in NORMALIZATION}
    assert sources == {"history", "webhook"}
    assert len(NORMALIZATION) == 8


@pytest.mark.parametrize("case", NORMALIZATION, ids=[c["name"] for c in NORMALIZATION])
def test_normalization_cases(case: dict[str, Any]) -> None:
    identification = _normalize(case)
    expected = case["expected"]
    actual = identification.to_dict()

    # observed_at is compared at millisecond precision (truncated).
    assert _truncate_ms(actual.pop("observed_at")) == _truncate_ms(expected["observed_at"])
    expected_rest = {key: value for key, value in expected.items() if key != "observed_at"}
    assert actual == expected_rest

    assert identification.raw == case["input"]
    assert identification.source == case["source"]
    assert identification.observed_at is not None
    assert identification.observed_at.tzinfo is not None
    assert identification.observed_at.utcoffset() == timedelta(0)
    assert isinstance(identification.signals, tuple)
    assert all(isinstance(signal.weight, int) for signal in identification.signals)
    assert len(identification.detection_flags.to_dict()) == 19


@pytest.mark.parametrize("case", NORMALIZATION, ids=[c["name"] for c in NORMALIZATION])
def test_to_dict_round_trip(case: dict[str, Any]) -> None:
    identification = _normalize(case)
    rebuilt = Identification.from_dict(identification.to_dict())
    assert rebuilt.to_dict() == identification.to_dict()
    assert rebuilt.source == identification.source
    json.dumps(identification.to_dict())


def test_webhook_keeps_nanosecond_input_as_microseconds() -> None:
    case = next(c for c in NORMALIZATION if c["name"] == "webhook_scored")
    identification = _normalize(case)
    assert identification.observed_at == datetime(
        2026, 9, 30, 12, 34, 57, 482913, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("case", SLUGS, ids=[c["slug"] + ":" + c["description"] for c in SLUGS])
def test_signal_slug_cases(case: dict[str, str]) -> None:
    assert signal_slug(case["description"]) == case["slug"]


@pytest.mark.parametrize("case", BANDS, ids=[str(c["score"]) for c in BANDS])
def test_risk_band_cases(case: dict[str, Any]) -> None:
    assert risk_band(case["score"]) == case["band"]
    assert is_rate_limited(case["score"]) is (case["band"] == "rate_limited")


def test_identification_band_properties() -> None:
    marker = next(c for c in NORMALIZATION if c["name"] == "webhook_rate_limited")
    identification = _normalize(marker)
    assert identification.risk_score == 999
    assert identification.risk_band == "rate_limited"
    assert identification.is_rate_limited
    assert not identification.has_device_signals
    assert identification.device_id == NIL_UUID

    scored = _normalize(next(c for c in NORMALIZATION if c["name"] == "webhook_scored"))
    assert scored.risk_band == "dangerous"
    assert not scored.is_rate_limited
    assert scored.has_device_signals
    assert scored.detection_flags.active() == (
        "proxy",
        "datacenter_ip",
        "anti_detect_browser",
        "ip_mismatch",
        "suspicious_paid_click",
    )


def test_history_row_tolerates_missing_and_malformed_fields() -> None:
    identification = Identification.from_history_row(
        {
            "request_id": 42,
            "score": "high",
            "score_details": "not json",
            "created_at": "yesterday",
            "user_hid": "",
            "ip": " 0.0.0.0 ",
        }
    )
    assert identification.request_id == ""
    assert identification.risk_score == 0
    assert identification.signals == ()
    assert identification.observed_at is None
    assert identification.user_hid is None
    assert identification.public_ip == IpInfo("", "")
    assert identification.detection_flags == DetectionFlags()


@pytest.mark.parametrize(
    "score_details",
    ["", "{}", "[1, 2]", '"text"', "[" * 100_000, None, 7],
)
def test_history_row_score_details_edge_cases(score_details: Any) -> None:
    identification = Identification.from_history_row({"score_details": score_details})
    assert identification.signals == ()


def test_history_row_keeps_negative_and_repeated_signals_and_skips_non_integers() -> None:
    details = [
        {"Value": 30, "Description": "Stun is not checked"},
        {"Value": -30, "Description": "Stun passed (late arrival, corrected)"},
        {"Value": 30, "Description": "Stun is not checked"},
        {"Value": 0, "Description": "Check Incomplete"},
        {"Value": 10.5, "Description": "Is proxy"},
        {"Value": True, "Description": "Is VPN"},
        "garbage",
        {"Description": "no value"},
    ]
    identification = Identification.from_history_row({"score_details": json.dumps(details)})
    assert [(s.name, s.weight) for s in identification.signals] == [
        ("stun_not_checked", 30),
        ("stun_late_correction", -30),
        ("stun_not_checked", 30),
    ]


def test_history_ip_mismatch_rules() -> None:
    base = {"ip": "203.0.113.1", "web_rtc_ip": "198.51.100.2"}
    assert Identification.from_history_row(base).detection_flags.ip_mismatch
    same = {"ip": "203.0.113.1", "web_rtc_ip": "203.0.113.1"}
    assert not Identification.from_history_row(same).detection_flags.ip_mismatch
    bot = dict(base, is_search_bot=True)
    assert not Identification.from_history_row(bot).detection_flags.ip_mismatch
    detail = {"score_details": json.dumps([{"Value": 0, "Description": "IP ≠ leakIP (a ≠ b)"}])}
    assert Identification.from_history_row(detail).detection_flags.ip_mismatch


def test_history_browser_vpn_proxy_is_derived_from_connection_type() -> None:
    row = {"connection_type": "browser_vpn_proxy"}
    assert Identification.from_history_row(row).detection_flags.browser_vpn_proxy
    assert Identification.from_history_row(row).connection_type == "browser_vpn_proxy"


def test_history_domain_prefers_site_domain() -> None:
    row = {"domain": "shop.example.com", "site_domain": "example.com"}
    assert Identification.from_history_row(row).domain == "example.com"
    assert Identification.from_history_row({"domain": "shop.example.com"}).domain == (
        "shop.example.com"
    )


def test_history_local_ip_uses_leak_source_only_when_set() -> None:
    row = {
        "web_rtc_ip": "198.51.100.2",
        "web_rtc_country": "Germany",
        "webrtc_leak_ip": "203.0.113.9",
        "webrtc_leak_country": "Spain",
        "webrtc_leak_source": "none",
    }
    assert Identification.from_history_row(row).local_ip == IpInfo("198.51.100.2", "Germany")
    row["webrtc_leak_source"] = "shield"
    assert Identification.from_history_row(row).local_ip == IpInfo("203.0.113.9", "Spain")


def test_webhook_data_tolerates_partial_objects() -> None:
    identification = Identification.from_webhook_data(
        {
            "request_id": "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53",
            "risk_score": 35,
            "user_hid": None,
            "signals": [{"name": "vpn", "weight": 15}, "bad", {"weight": 5}],
            "detection_flags": ["not", "a", "map"],
            "public_ip": "not a map",
        }
    )
    assert identification.risk_score == 35
    assert identification.user_hid is None
    assert identification.signals == (Signal("vpn", 15), Signal("", 5))
    assert identification.detection_flags == DetectionFlags()
    assert identification.public_ip == IpInfo()
    assert identification.traffic_source == TrafficSource()
    assert identification.observed_at is None
    assert identification.source == "webhook"


def test_user_hid_sentinels_are_kept() -> None:
    for sentinel in ("anonymous", "fail", "-1", "unknown"):
        assert Identification.from_history_row({"user_hid": sentinel}).user_hid == sentinel
        assert Identification.from_webhook_data({"user_hid": sentinel}).user_hid == sentinel


def test_from_dict_accepts_datetime_and_signal_descriptions() -> None:
    moment = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    identification = Identification.from_dict(
        {
            "request_id": "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53",
            "signals": [{"name": "proxy", "weight": 10, "description": "Is proxy"}],
            "observed_at": moment,
            "source": "history",
        }
    )
    assert identification.observed_at == moment
    assert identification.signals == (Signal("proxy", 10, "Is proxy"),)
    assert identification.source == "history"
    assert Identification.from_dict({}).source == "webhook"


def test_history_page_from_dict() -> None:
    page = HistoryPage.from_dict(load_json("history-page.json"))
    assert page.total == 37
    assert len(page.data) == 5
    assert all(item.source == "history" for item in page.data)
    empty = HistoryPage.from_dict(load_json("history-empty.json"))
    assert empty == HistoryPage(data=(), total=0)
    odd = HistoryPage.from_dict({"data": [{"request_id": "x"}, "junk"], "total": None})
    assert odd.total == 1
    assert HistoryPage.from_dict({"data": "nope"}).data == ()


def test_history_page_rows_match_normalization_cases() -> None:
    page = HistoryPage.from_dict(load_json("history-page.json"))
    expected = {c["name"]: c["expected"] for c in NORMALIZATION if c["source"] == "history"}
    by_request = {v["request_id"]: v for v in expected.values()}
    for identification in page.data:
        assert identification.to_dict() == by_request[identification.request_id]


def test_known_signal_names_are_plain_strings() -> None:
    assert SignalName.ANTIDETECT_BROWSER == "antidetect_browser"
    assert SignalName.STUN_LATE_CORRECTION == "stun_late_correction"
    assert SignalName.RATE_LIMITED == "rate_limited"


def test_models_are_frozen() -> None:
    signal = Signal("vpn", 15)
    with pytest.raises(AttributeError):
        signal.weight = 99  # type: ignore[misc]


def test_flag_keys_order_matches_detection_flags() -> None:
    assert tuple(DetectionFlags().to_dict()) == FLAG_KEYS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-30 12:34:56.123", "2026-09-30T12:34:56.123Z"),
        ("2026-09-30 12:34:56", "2026-09-30T12:34:56.000Z"),
        ("2026-09-30T12:34:56.1", "2026-09-30T12:34:56.100Z"),
        ("2026-09-30 12:34:56.123456789", "2026-09-30T12:34:56.123Z"),
        ("  2026-09-30 12:34:56.999  ", "2026-09-30T12:34:56.999Z"),
        ("2026-09-30 12:34:56Z", "2026-09-30T12:34:56.000Z"),
        ("2026-09-30 12:34:56+02:00", "2026-09-30T12:34:56.000Z"),
        ("2026-02-30 12:34:56", None),
        ("2026-09-30", None),
        ("", None),
        (None, None),
        (1790771696123, None),
    ],
)
def test_parse_history_time(value: Any, expected: Any) -> None:
    assert format_timestamp(parse_history_time(value)) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-30T12:34:57.482913041Z", "2026-09-30T12:34:57.482Z"),
        ("2026-09-30T13:10:00.5Z", "2026-09-30T13:10:00.500Z"),
        ("2026-09-30T12:34:56Z", "2026-09-30T12:34:56.000Z"),
        ("2026-09-30T14:34:56+02:00", "2026-09-30T12:34:56.000Z"),
        ("2026-09-30T10:04:56-02:30", "2026-09-30T12:34:56.000Z"),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z"),
        ("0001-01-01T00:00:00+01:00", None),
        ("2026-09-30 12:34:56Z", None),
        ("2026-09-30T12:34:56", None),
        ("2026-13-30T12:34:56Z", None),
        (None, None),
    ],
)
def test_parse_rfc3339(value: Any, expected: Any) -> None:
    assert format_timestamp(parse_rfc3339(value)) == expected


def test_format_timestamp_converts_offsets_and_handles_naive() -> None:
    aware = datetime(2026, 9, 30, 14, 0, 0, 999999, tzinfo=timezone(timedelta(hours=2)))
    assert format_timestamp(aware) == "2026-09-30T12:00:00.999Z"
    assert format_timestamp(datetime(2026, 9, 30, 12, 0)) == "2026-09-30T12:00:00.000Z"
    assert format_timestamp(None) is None


def test_fallback_slug_examples() -> None:
    assert fallback_slug("A - . - B") == "a_b"
    assert fallback_slug("--x--") == "x"
    assert fallback_slug("Latency (x)") == "latency"


def test_numeric_coercion_keeps_integers() -> None:
    assert Identification.from_webhook_data({"risk_score": 45.0}).risk_score == 45
    assert Identification.from_webhook_data({"risk_score": 45.5}).risk_score == 0
    assert Identification.from_webhook_data({"risk_score": True}).risk_score == 0
    assert Identification.from_webhook_data({"risk_score": "45"}).risk_score == 0
