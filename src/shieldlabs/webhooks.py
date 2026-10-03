"""Verify and parse ShieldLabs webhook deliveries.

Every delivery is a ``POST`` with a JSON body and the header
``X-Shield-Signature: sha256=<hex HMAC-SHA256>``. The HMAC key is the endpoint signing secret
string exactly as shown in the analytics dashboard, ``whsec_`` prefix included, and the message
is the raw request body. Always verify the raw bytes you received, before parsing them.

ShieldLabs sends one delivery per identification and endpoint, with a 1-second timeout and no
retries. Respond with a 2xx within 1 second and do slow work afterwards. Keep handlers
idempotent on ``data.request_id``: a future release retries deliveries, and a retry resends
identical bytes. Use the History API for guaranteed reads and for the latest state.

Example::

    from shieldlabs import webhooks, IdentificationScoredEvent

    event = webhooks.construct_event(raw_body, headers.get("X-Shield-Signature"), secret)
    if isinstance(event, IdentificationScoredEvent):
        handle(event.data)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional, Union

from ._errors import ShieldLabsWarning, SignatureVerificationError, WebhookParseError
from ._generated_wire import IdentificationScoredEvent as WireEvent
from ._generated_wire import WebhookPingEvent as WirePing
from ._models import Identification
from ._normalize import parse_rfc3339
from ._wire import text

__all__ = [
    "SCHEMA_VERSION",
    "SIGNATURE_HEADER",
    "IdentificationScoredEvent",
    "UnknownWebhookEvent",
    "WebhookEvent",
    "WebhookPingEvent",
    "construct_event",
    "verify_signature",
]

SIGNATURE_HEADER = "X-Shield-Signature"
"""Name of the header that carries the signature."""

SCHEMA_VERSION = "2026-06-01"
"""Webhook ``schema_version`` this SDK was built for. Other values are parsed with a warning."""

_SIGNATURE_PREFIX = "sha256="
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")

Payload = Union[bytes, bytearray, memoryview, str]
Secrets = Union[str, Sequence[str]]


@dataclass(frozen=True)
class IdentificationScoredEvent:
    """``identification.scored``: one identification was scored.

    Attributes:
        event_type: Always ``"identification.scored"``.
        schema_version: Envelope schema version, for example ``"2026-06-01"``.
        created_at: When the event was created (aware UTC datetime), ``None`` if unparsable.
        data: The normalized identification.
        raw: The whole parsed envelope.
    """

    event_type: Literal["identification.scored"]
    schema_version: str
    created_at: Optional[datetime]
    data: Identification
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class WebhookPingEvent:
    """``webhook.ping``: sent when you press Verify on an endpoint. It carries no data."""

    event_type: Literal["webhook.ping"]
    schema_version: str
    created_at: Optional[datetime]
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class UnknownWebhookEvent:
    """An event type this SDK version does not know. Acknowledge it and ignore it or log it.

    Attributes:
        data: The ``data`` object of the envelope when it has one, else ``None``.
    """

    event_type: str
    schema_version: str
    created_at: Optional[datetime]
    data: Optional[Mapping[str, Any]] = None
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)


WebhookEvent = Union[IdentificationScoredEvent, WebhookPingEvent, UnknownWebhookEvent]
"""Every event ``construct_event`` can return."""


def _payload_bytes(payload: Payload) -> bytes:
    if isinstance(payload, str):
        return payload.encode("utf-8", errors="surrogateescape")
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload)
    raise TypeError(
        "payload must be the raw request body as bytes or str, "
        f"not {type(payload).__name__}: never re-serialize parsed JSON"
    )


def _secret_list(secret: Optional[Secrets]) -> list[str]:
    if secret is None:
        return []
    if isinstance(secret, str):
        return [secret]
    if isinstance(secret, (bytes, bytearray, memoryview)) or not isinstance(secret, Sequence):
        raise TypeError("secret must be a string or a sequence of strings")
    items = list(secret)
    for item in items:
        if not isinstance(item, str):
            raise TypeError("secret must be a string or a sequence of strings")
    return items


def verify_signature(
    payload: Payload,
    signature_header: Optional[str],
    secret: Secrets,
) -> bool:
    """Check the ``X-Shield-Signature`` header of a delivery.

    Args:
        payload: The raw request body, as bytes or str. Never re-serialized JSON.
        signature_header: The ``X-Shield-Signature`` header value (``None`` when absent).
        secret: The endpoint signing secret (``whsec_...``), or a list of secrets while you
            rotate one: the delivery is valid when any of them matches.

    Returns:
        ``True`` when the signature is valid. ``False`` for a missing or malformed header,
        an empty secret or a wrong signature.
    """
    try:
        body = _payload_bytes(payload)
    except UnicodeEncodeError:
        return False
    secrets = [item for item in _secret_list(secret) if item]
    if not secrets or not isinstance(signature_header, str):
        return False
    header = signature_header.strip()
    if not header.startswith(_SIGNATURE_PREFIX):
        return False
    received = header[len(_SIGNATURE_PREFIX) :].lower()
    if not _HEX_DIGEST.fullmatch(received):
        return False
    valid = False
    for item in secrets:
        expected = hmac.new(item.encode("utf-8"), body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, received):
            valid = True
    return valid


def construct_event(
    payload: Payload,
    signature_header: Optional[str],
    secret: Secrets,
) -> WebhookEvent:
    """Verify a delivery, then parse it into a typed event.

    Returns ``IdentificationScoredEvent``, ``WebhookPingEvent`` or ``UnknownWebhookEvent``
    (never raises for an unknown ``event_type``).

    Raises:
        SignatureVerificationError: The signature is missing or does not match.
        WebhookParseError: The verified body is not a webhook envelope.
    """
    if not verify_signature(payload, signature_header, secret):
        raise SignatureVerificationError(
            "Webhook signature verification failed: check the endpoint signing secret and "
            "pass the raw request body"
        )
    return _parse_event(_payload_bytes(payload))


def _parse_event(body: bytes) -> WebhookEvent:
    try:
        envelope = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise WebhookParseError("Webhook body is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise WebhookParseError("Webhook body is not a JSON object")
    event_type = text(WireEvent.event_type.read(envelope))
    if not isinstance(event_type, str) or not event_type:
        raise WebhookParseError("Webhook body has no event_type")
    envelope_fields = WirePing if event_type == "webhook.ping" else WireEvent
    schema_version = text(envelope_fields.schema_version.read(envelope))
    if schema_version != SCHEMA_VERSION:
        warnings.warn(
            f"Webhook schema_version {schema_version!r} is not {SCHEMA_VERSION!r}; "
            "parsing it anyway. Upgrade the shieldlabs package to get the latest fields.",
            ShieldLabsWarning,
            stacklevel=3,
        )
    created_at = parse_rfc3339(text(envelope_fields.created_at.read(envelope)))
    data = WireEvent.data.read(envelope)
    if event_type == "identification.scored":
        if not isinstance(data, dict):
            raise WebhookParseError("identification.scored event has no data object")
        return IdentificationScoredEvent(
            event_type="identification.scored",
            schema_version=schema_version,
            created_at=created_at,
            data=Identification.from_webhook_data(data),
            raw=envelope,
        )
    if event_type == "webhook.ping":
        return WebhookPingEvent(
            event_type="webhook.ping",
            schema_version=schema_version,
            created_at=created_at,
            raw=envelope,
        )
    return UnknownWebhookEvent(
        event_type=event_type,
        schema_version=schema_version,
        created_at=created_at,
        data=data if isinstance(data, dict) else None,
        raw=envelope,
    )
