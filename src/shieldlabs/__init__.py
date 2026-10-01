"""ShieldLabs server SDK for Python.

Read identification verdicts from the History API, read the domain profile from the Management
API, verify and parse webhook deliveries, and apply risk helpers.

Quick start::

    from shieldlabs import ShieldLabs, evaluate_identification

    client = ShieldLabs(api_key="sec_your_private_key")
    identification = client.identifications.get(request_id)
    verdict = evaluate_identification(identification)
"""

from . import webhooks
from ._client import AsyncShieldLabs, ShieldLabs
from ._errors import (
    APIConnectionError,
    ApiError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    ShieldLabsError,
    ShieldLabsWarning,
    SignatureVerificationError,
    ValidationError,
    WebhookParseError,
)
from ._helpers import Evaluation, EvaluationReason, evaluate_identification, user_hid
from ._management import AsyncShieldLabsManagement, ShieldLabsManagement
from ._models import (
    DetectionFlags,
    DomainProfile,
    HistoryPage,
    Identification,
    IdentificationSource,
    IpInfo,
    Signal,
    SignalName,
    TrafficSource,
)
from ._normalize import NIL_UUID, RiskBand, is_rate_limited, risk_band
from ._validation import LookupType
from ._version import __version__
from .webhooks import (
    IdentificationScoredEvent,
    UnknownWebhookEvent,
    WebhookEvent,
    WebhookPingEvent,
)

__all__ = [
    "NIL_UUID",
    "APIConnectionError",
    "APITimeoutError",
    "ApiError",
    "AsyncShieldLabs",
    "AsyncShieldLabsManagement",
    "AuthenticationError",
    "BadRequestError",
    "DetectionFlags",
    "DomainProfile",
    "Evaluation",
    "EvaluationReason",
    "HistoryPage",
    "Identification",
    "IdentificationScoredEvent",
    "IdentificationSource",
    "IpInfo",
    "LookupType",
    "NotFoundError",
    "QuotaExceededError",
    "RateLimitError",
    "RiskBand",
    "ServerError",
    "ShieldLabs",
    "ShieldLabsError",
    "ShieldLabsManagement",
    "ShieldLabsWarning",
    "Signal",
    "SignalName",
    "SignatureVerificationError",
    "TrafficSource",
    "UnknownWebhookEvent",
    "ValidationError",
    "WebhookEvent",
    "WebhookParseError",
    "WebhookPingEvent",
    "__version__",
    "evaluate_identification",
    "is_rate_limited",
    "risk_band",
    "user_hid",
    "webhooks",
]
