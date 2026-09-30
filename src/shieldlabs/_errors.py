"""Exceptions and warnings raised by the ShieldLabs SDK."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

__all__ = [
    "APIConnectionError",
    "APITimeoutError",
    "ApiError",
    "AuthenticationError",
    "BadRequestError",
    "NotFoundError",
    "QuotaExceededError",
    "RateLimitError",
    "ServerError",
    "ShieldLabsError",
    "ShieldLabsWarning",
    "SignatureVerificationError",
    "ValidationError",
    "WebhookParseError",
]


class ShieldLabsError(Exception):
    """Base class of every exception raised by this package."""

    message: str

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ApiError(ShieldLabsError):
    """A ShieldLabs API answered with a status outside 2xx.

    Attributes:
        status: HTTP status code.
        body: The response body parsed as JSON when possible, else the text, else ``None``.
        headers: The response headers (case-insensitive when they come from a response).
    """

    status: int
    body: Any
    headers: Mapping[str, str]

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body
        self.headers = headers if headers is not None else {}

    def __str__(self) -> str:
        return f"{self.message} (HTTP {self.status})"


class BadRequestError(ApiError):
    """HTTP 400: the server rejected the request."""


class AuthenticationError(ApiError):
    """HTTP 401 or 403: the key is missing, wrong, rotated, or the domain is disabled."""


class QuotaExceededError(ApiError):
    """HTTP 402. Neither the History API nor the Management API returns it today.

    An account over its included volume shows a negative ``remaining_identifications`` in the
    domain profile instead.
    """


class NotFoundError(ApiError):
    """HTTP 404: the path does not exist (check the base URL)."""


class RateLimitError(ApiError):
    """HTTP 429: too many requests.

    Attributes:
        retry_after: Seconds to wait before the next request, when the server sent ``Retry-After``.
    """

    retry_after: Optional[float]

    def __init__(
        self,
        message: str,
        *,
        status: int = 429,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, status=status, body=body, headers=headers)
        self.retry_after = retry_after


class ServerError(ApiError):
    """HTTP 5xx: a server or edge proxy error."""


class APIConnectionError(ShieldLabsError):
    """The request never produced a response (DNS, TCP, TLS or protocol failure)."""


class APITimeoutError(ShieldLabsError):
    """The request did not complete within the configured timeout."""


class SignatureVerificationError(ShieldLabsError):
    """A webhook delivery did not carry a valid ``X-Shield-Signature`` for the given secret."""


class WebhookParseError(ShieldLabsError):
    """A verified webhook body could not be parsed into an event."""


class ValidationError(ShieldLabsError, ValueError):
    """An argument is invalid. Raised before any HTTP request is sent."""


class ShieldLabsWarning(UserWarning):
    """Non-fatal configuration or data issue detected by the SDK."""
