"""Webhook signature vectors and typed event parsing."""

from __future__ import annotations

import base64
import json
import warnings
from datetime import datetime, timezone
from typing import Any

import pytest

from _support import load_bytes, load_json, sign
from shieldlabs import (
    IdentificationScoredEvent,
    ShieldLabsWarning,
    SignatureVerificationError,
    UnknownWebhookEvent,
    WebhookParseError,
    WebhookPingEvent,
    webhooks,
)

VECTORS = load_json("webhook-signature-vectors.json")
SECRET = "whsec_00112233445566778899aabbccddeeff"
NORMALIZATION = {c["name"]: c for c in load_json("normalization-cases.json")["cases"]}


def _secret(vector: dict[str, Any]) -> Any:
    return vector["secret"] if "secret" in vector else vector["secrets"]


def test_all_signature_vectors_present() -> None:
    assert VECTORS["header_name"] == webhooks.SIGNATURE_HEADER
    assert len(VECTORS["vectors"]) == 21
    assert any("secrets" in vector for vector in VECTORS["vectors"])


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_signature_vector_bytes_and_str(vector: dict[str, Any]) -> None:
    body = base64.b64decode(vector["body_base64"])
    assert body.decode("utf-8") == vector["body"]
    header = vector["signature_header"]
    expected = vector["valid"]
    assert webhooks.verify_signature(body, header, _secret(vector)) is expected
    assert webhooks.verify_signature(vector["body"], header, _secret(vector)) is expected
    assert webhooks.verify_signature(bytearray(body), header, _secret(vector)) is expected
    assert webhooks.verify_signature(memoryview(body), header, _secret(vector)) is expected


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=[v["name"] for v in VECTORS["vectors"]])
def test_signature_vector_construct_event(vector: dict[str, Any]) -> None:
    body = base64.b64decode(vector["body_base64"])
    if vector["valid"]:
        event = webhooks.construct_event(body, vector["signature_header"], _secret(vector))
        assert event.event_type == json.loads(body)["event_type"]
    else:
        with pytest.raises(SignatureVerificationError):
            webhooks.construct_event(body, vector["signature_header"], _secret(vector))


def test_verify_rejects_missing_header_and_empty_secrets() -> None:
    body = load_bytes("webhook-ping.raw.txt")
    header = sign(SECRET, body)
    assert webhooks.verify_signature(body, header, SECRET)
    assert not webhooks.verify_signature(body, None, SECRET)
    assert not webhooks.verify_signature(body, header, [])
    assert not webhooks.verify_signature(body, header, ["", ""])
    assert not webhooks.verify_signature(body, header, None)  # type: ignore[arg-type]
    assert not webhooks.verify_signature(body, "sha256 =" + header[7:], SECRET)
    assert not webhooks.verify_signature(body, "SHA256=" + header[7:], SECRET)
    assert webhooks.verify_signature(body, header, ("whsec_other", SECRET))


def test_verify_rejects_parsed_json_and_bad_secret_types() -> None:
    body = load_bytes("webhook-ping.raw.txt")
    header = sign(SECRET, body)
    with pytest.raises(TypeError, match="raw request body"):
        webhooks.verify_signature(json.loads(body), header, SECRET)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        webhooks.verify_signature(body, header, SECRET.encode())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        webhooks.verify_signature(body, header, [SECRET.encode()])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        webhooks.verify_signature(body, header, 42)  # type: ignore[arg-type]


def test_verify_returns_false_for_unencodable_str_payload() -> None:
    assert not webhooks.verify_signature("\ud800", "sha256=" + "0" * 64, SECRET)
    with pytest.raises(SignatureVerificationError):
        webhooks.construct_event("\ud800", "sha256=" + "0" * 64, SECRET)


def test_scored_event_from_raw_bytes_matches_normalization() -> None:
    body = load_bytes("webhook-identification-scored.raw.txt")
    event = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert isinstance(event, IdentificationScoredEvent)
    assert event.event_type == "identification.scored"
    assert event.schema_version == webhooks.SCHEMA_VERSION
    assert event.created_at == datetime(2026, 9, 30, 12, 34, 57, 482913, tzinfo=timezone.utc)
    assert event.data.to_dict() == NORMALIZATION["webhook_scored"]["expected"]
    assert event.data.traffic_source.landing_url.endswith("utm_medium=cpc&gclid=abc123")
    assert event.raw == load_json("webhook-identification-scored.json")


def test_scored_event_accepts_str_body() -> None:
    body = load_bytes("webhook-identification-scored.raw.txt")
    event = webhooks.construct_event(body.decode("utf-8"), sign(SECRET, body), SECRET)
    assert isinstance(event, IdentificationScoredEvent)


def test_ping_event_from_raw_bytes() -> None:
    body = load_bytes("webhook-ping.raw.txt")
    event = webhooks.construct_event(body, sign(SECRET, body), [SECRET])
    assert isinstance(event, WebhookPingEvent)
    assert event.event_type == "webhook.ping"
    assert event.created_at == datetime(2026, 9, 30, 12, 34, 56, tzinfo=timezone.utc)
    assert event.raw == load_json("webhook-ping.json")


def test_rate_limited_event() -> None:
    body = json.dumps(load_json("webhook-rate-limited.json")).encode()
    event = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert isinstance(event, IdentificationScoredEvent)
    assert event.data.risk_score == 999
    assert event.data.is_rate_limited
    assert event.data.risk_band == "rate_limited"
    assert [(s.name, s.weight) for s in event.data.signals] == [("rate_limited", 999)]
    assert event.data.to_dict() == NORMALIZATION["webhook_rate_limited"]["expected"]


def test_dashboard_test_delivery_with_17_flags() -> None:
    delivery = load_json("webhook-test-delivery.json")
    assert len(delivery["data"]["detection_flags"]) == 17
    body = json.dumps(delivery, separators=(",", ":"), sort_keys=True).encode()
    event = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert isinstance(event, IdentificationScoredEvent)
    flags = event.data.detection_flags
    assert flags.browser_automation is False
    assert flags.search_bot is False
    assert flags.proxy
    assert flags.datacenter_ip
    assert flags.abuser
    assert event.data.user_hid is None
    assert event.data.to_dict() == NORMALIZATION["webhook_test_delivery"]["expected"]


def test_unknown_event_type_is_not_an_error() -> None:
    envelope = {
        "event_type": "identification.refined",
        "schema_version": "2026-06-01",
        "created_at": "2026-09-30T12:00:00Z",
        "data": {"request_id": "02f1d973-84db-4156-a7f7-e799e6bf389b"},
        "extra": True,
    }
    body = json.dumps(envelope).encode()
    event = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert isinstance(event, UnknownWebhookEvent)
    assert event.event_type == "identification.refined"
    assert event.data == envelope["data"]
    assert event.raw == envelope

    no_data = json.dumps({"event_type": "x", "schema_version": "2026-06-01"}).encode()
    parsed = webhooks.construct_event(no_data, sign(SECRET, no_data), SECRET)
    assert isinstance(parsed, UnknownWebhookEvent)
    assert parsed.data is None
    assert parsed.created_at is None


def test_unknown_schema_version_warns_but_parses() -> None:
    body = (
        b'{"event_type":"webhook.ping","schema_version":"2027-01-01",'
        b'"created_at":"2027-01-01T00:00:00Z"}'
    )
    with pytest.warns(ShieldLabsWarning, match="schema_version"):
        event = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert isinstance(event, WebhookPingEvent)
    assert event.schema_version == "2027-01-01"

    missing = b'{"event_type":"webhook.ping"}'
    with pytest.warns(ShieldLabsWarning):
        event = webhooks.construct_event(missing, sign(SECRET, missing), SECRET)
    assert event.schema_version == ""


def test_known_schema_version_does_not_warn() -> None:
    body = load_bytes("webhook-ping.raw.txt")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        webhooks.construct_event(body, sign(SECRET, body), SECRET)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "not valid JSON"),
        (b"\xff\xfe\x00", "not valid JSON"),
        (b"[1, 2]", "not a JSON object"),
        (b'{"schema_version":"2026-06-01"}', "no event_type"),
        (b'{"event_type":7,"schema_version":"2026-06-01"}', "no event_type"),
        (
            b'{"event_type":"identification.scored","schema_version":"2026-06-01"}',
            "no data object",
        ),
        (
            b'{"event_type":"identification.scored","schema_version":"2026-06-01","data":[]}',
            "no data object",
        ),
    ],
)
def test_parse_errors_after_valid_signature(body: bytes, message: str) -> None:
    with pytest.raises(WebhookParseError, match=message):
        webhooks.construct_event(body, sign(SECRET, body), SECRET)


def test_scored_event_is_hashable_free_of_raw_in_equality() -> None:
    body = load_bytes("webhook-ping.raw.txt")
    first = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    second = webhooks.construct_event(body, sign(SECRET, body), SECRET)
    assert first == second
    assert "raw" not in repr(first)
