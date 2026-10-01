"""Public surface of the package."""

from __future__ import annotations

import builtins
from pathlib import Path

import shieldlabs

EXPECTED_EXPORTS = {
    "ShieldLabs",
    "AsyncShieldLabs",
    "ShieldLabsManagement",
    "AsyncShieldLabsManagement",
    "webhooks",
    "risk_band",
    "is_rate_limited",
    "evaluate_identification",
    "user_hid",
    "Identification",
    "Signal",
    "DetectionFlags",
    "TrafficSource",
    "IpInfo",
    "HistoryPage",
    "DomainProfile",
    "LookupType",
    "RiskBand",
    "Evaluation",
    "IdentificationScoredEvent",
    "WebhookPingEvent",
    "UnknownWebhookEvent",
    "ShieldLabsError",
    "ApiError",
    "BadRequestError",
    "AuthenticationError",
    "QuotaExceededError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "APIConnectionError",
    "APITimeoutError",
    "SignatureVerificationError",
    "WebhookParseError",
    "ValidationError",
}


def test_every_documented_name_is_exported() -> None:
    missing = EXPECTED_EXPORTS - set(shieldlabs.__all__)
    assert not missing
    for name in shieldlabs.__all__:
        assert hasattr(shieldlabs, name), name


def test_no_export_shadows_a_builtin() -> None:
    assert not set(shieldlabs.__all__) & set(dir(builtins))


def test_error_hierarchy() -> None:
    api_errors = [
        shieldlabs.BadRequestError,
        shieldlabs.AuthenticationError,
        shieldlabs.QuotaExceededError,
        shieldlabs.NotFoundError,
        shieldlabs.RateLimitError,
        shieldlabs.ServerError,
    ]
    for cls in api_errors:
        assert issubclass(cls, shieldlabs.ApiError)
    for cls in [
        shieldlabs.ApiError,
        shieldlabs.APIConnectionError,
        shieldlabs.APITimeoutError,
        shieldlabs.SignatureVerificationError,
        shieldlabs.WebhookParseError,
        shieldlabs.ValidationError,
    ]:
        assert issubclass(cls, shieldlabs.ShieldLabsError)
    assert not issubclass(shieldlabs.APITimeoutError, shieldlabs.APIConnectionError)


def test_version_and_typing_marker() -> None:
    assert shieldlabs.__version__ == "1.0.0"
    assert (Path(shieldlabs.__file__).parent / "py.typed").exists()


def test_webhooks_module_surface() -> None:
    assert shieldlabs.webhooks.SIGNATURE_HEADER == "X-Shield-Signature"
    assert shieldlabs.webhooks.SCHEMA_VERSION == "2026-06-01"
    assert shieldlabs.webhooks.IdentificationScoredEvent is shieldlabs.IdentificationScoredEvent
