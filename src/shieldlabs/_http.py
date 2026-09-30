"""HTTP transport: headers, retries with backoff, and error mapping."""

from __future__ import annotations

import email.utils
import http
import json
import math
import platform
import random
import re
import time
from collections.abc import Awaitable, Mapping
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import httpx

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
)
from ._version import __version__

try:  # anyio ships with httpx; it lets the async client run under asyncio and trio.
    from anyio import sleep as _async_sleep
except ImportError:  # pragma: no cover
    from asyncio import sleep as _async_sleep

__all__ = [
    "USER_AGENT",
    "AsyncTransport",
    "SyncTransport",
    "backoff_delay",
    "error_from_response",
    "json_object",
    "parse_retry_after",
]

USER_AGENT = (
    f"shieldlabs-python/{__version__} "
    f"({platform.python_implementation()} {platform.python_version()}; httpx {httpx.__version__})"
)

RETRY_BASE_DELAY = 0.5
RETRY_MAX_DELAY = 8.0
RETRY_AFTER_CAP = 10.0
RATE_LIMIT_MIN_DELAY = 1.0
"""Shortest wait after a 429, in seconds (the History API limit is a 1-second window): after any
429 inside the wait of ``identifications.get``, and before retrying an ordinary request whose 429
had no ``Retry-After``. With ``Retry-After`` an ordinary request waits as long as it says, capped
at ``RETRY_AFTER_CAP``."""

_STATUS_ERRORS: dict[int, type[ApiError]] = {
    400: BadRequestError,
    401: AuthenticationError,
    402: QuotaExceededError,
    403: AuthenticationError,
    404: NotFoundError,
    429: RateLimitError,
}

Params = Mapping[str, Any]


def backoff_delay(attempt: int, rand: Callable[[], float]) -> float:
    """Exponential backoff with jitter: base 0.5 s, factor 2, cap 8 s, times a random 0.5 to 1."""
    delay = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2**attempt))
    return float(delay * (0.5 + 0.5 * rand()))


_RETRY_AFTER_SECONDS = re.compile(r"[0-9]+(?:\.[0-9]+)?")


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse ``Retry-After`` (seconds or an HTTP date) into seconds, or ``None``.

    Seconds are digits with an optional fraction. Anything else that is not an HTTP date, such as
    a sign, an exponent or an underscore, counts as no ``Retry-After``.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if _RETRY_AFTER_SECONDS.fullmatch(text):
        seconds = float(text)
    else:
        try:
            moment = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        seconds = (moment - datetime.now(timezone.utc)).total_seconds()
    if math.isnan(seconds) or math.isinf(seconds):
        return None
    return max(0.0, seconds)


def _describe_body(content: bytes) -> tuple[Any, Optional[str]]:
    """Return ``(parsed body, message)`` without ever raising."""
    try:
        text = content.decode("utf-8", errors="replace").strip()
        if not text:
            return None, None
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            if text.startswith("<"):
                return text, None
            return text, text.splitlines()[0][:200]
        if isinstance(parsed, dict):
            for key in ("error", "message"):
                detail = parsed.get(key)
                if isinstance(detail, str) and detail.strip():
                    return parsed, detail.strip()[:500]
            return parsed, None
        if isinstance(parsed, str) and parsed.strip():
            return parsed, parsed.strip()[:500]
        return parsed, None
    except Exception:  # pragma: no cover - defensive: building an error must never fail
        return None, None


def _reason(status: int) -> str:
    try:
        return http.HTTPStatus(status).phrase
    except ValueError:
        return "Unexpected response"


def error_from_response(response: httpx.Response) -> ApiError:
    """Map a non-2xx response to the matching ``ApiError`` subclass."""
    status = response.status_code
    body, detail = _describe_body(response.content)
    message = detail or _reason(status)
    if status == 429:
        return RateLimitError(
            message,
            status=status,
            body=body,
            headers=response.headers,
            retry_after=parse_retry_after(response.headers.get("retry-after")),
        )
    cls = _STATUS_ERRORS.get(status) or (ServerError if 500 <= status <= 599 else ApiError)
    return cls(message, status=status, body=body, headers=response.headers)


def json_object(response: httpx.Response) -> Mapping[str, Any]:
    """Decode a 2xx response body that must be a JSON object."""
    try:
        parsed = json.loads(response.content)
    except (ValueError, RecursionError):
        raise ApiError(
            "Response body is not valid JSON",
            status=response.status_code,
            body=response.content.decode("utf-8", errors="replace"),
            headers=response.headers,
        ) from None
    if not isinstance(parsed, dict):
        raise ApiError(
            "Response body is not a JSON object",
            status=response.status_code,
            body=parsed,
            headers=response.headers,
        )
    return parsed


class _TransportBase:
    """Retry policy shared by the sync and async transports."""

    def __init__(
        self,
        *,
        timeout: float,
        max_retries: int,
        retry_rate_limited: bool,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_rate_limited = retry_rate_limited
        self._random: Callable[[], float] = random.random
        self._clock: Callable[[], float] = time.monotonic

    def _retryable(self, status: int) -> bool:
        if status == 429:
            return self.retry_rate_limited
        return 500 <= status <= 599

    def _delay_for(self, attempt: int, error: ApiError) -> float:
        retry_after = parse_retry_after(error.headers.get("retry-after"))
        if retry_after is not None:
            return min(retry_after, RETRY_AFTER_CAP)
        delay = backoff_delay(attempt, self._random)
        if error.status == 429:
            # A retry inside the same 1-second window would only be refused again.
            delay = max(delay, RATE_LIMIT_MIN_DELAY)
        return delay


def _timeout_error(exc: httpx.TimeoutException, timeout: float) -> APITimeoutError:
    kind = type(exc).__name__
    return APITimeoutError(f"Request to ShieldLabs timed out after {timeout:g} s ({kind})")


def _connection_error(exc: httpx.RequestError) -> APIConnectionError:
    detail = str(exc) or type(exc).__name__
    return APIConnectionError(f"Could not reach ShieldLabs: {detail}")


class SyncTransport(_TransportBase):
    """Blocking transport over ``httpx.Client``. Safe to share across threads."""

    def __init__(
        self,
        *,
        client: Optional[httpx.Client],
        timeout: float,
        max_retries: int,
        retry_rate_limited: bool,
    ) -> None:
        super().__init__(
            timeout=timeout, max_retries=max_retries, retry_rate_limited=retry_rate_limited
        )
        self.client = client if client is not None else httpx.Client()
        self.owns_client = client is None
        self._sleep: Callable[[float], None] = time.sleep

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Optional[Params] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> httpx.Response:
        """GET with retries. Returns a 2xx response or raises a ``ShieldLabsError``."""
        attempt_timeout = self.timeout if timeout is None else timeout
        retries = self.max_retries if max_retries is None else max_retries
        attempt = 0
        while True:
            try:
                response = self.client.get(
                    url, headers=dict(headers), params=params, timeout=attempt_timeout
                )
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    self._sleep(backoff_delay(attempt, self._random))
                    attempt += 1
                    continue
                raise _timeout_error(exc, attempt_timeout) from exc
            except httpx.RequestError as exc:
                if attempt < retries:
                    self._sleep(backoff_delay(attempt, self._random))
                    attempt += 1
                    continue
                raise _connection_error(exc) from exc
            if response.is_success:
                return response
            error = error_from_response(response)
            if attempt < retries and self._retryable(response.status_code):
                self._sleep(self._delay_for(attempt, error))
                attempt += 1
                continue
            raise error

    def close(self) -> None:
        if self.owns_client:
            self.client.close()


class AsyncTransport(_TransportBase):
    """Asynchronous transport over ``httpx.AsyncClient``. Safe for concurrent tasks."""

    def __init__(
        self,
        *,
        client: Optional[httpx.AsyncClient],
        timeout: float,
        max_retries: int,
        retry_rate_limited: bool,
    ) -> None:
        super().__init__(
            timeout=timeout, max_retries=max_retries, retry_rate_limited=retry_rate_limited
        )
        self.client = client if client is not None else httpx.AsyncClient()
        self.owns_client = client is None
        self._sleep: Callable[[float], Awaitable[None]] = _async_sleep

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Optional[Params] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> httpx.Response:
        """GET with retries. Returns a 2xx response or raises a ``ShieldLabsError``."""
        attempt_timeout = self.timeout if timeout is None else timeout
        retries = self.max_retries if max_retries is None else max_retries
        attempt = 0
        while True:
            try:
                response = await self.client.get(
                    url, headers=dict(headers), params=params, timeout=attempt_timeout
                )
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await self._sleep(backoff_delay(attempt, self._random))
                    attempt += 1
                    continue
                raise _timeout_error(exc, attempt_timeout) from exc
            except httpx.RequestError as exc:
                if attempt < retries:
                    await self._sleep(backoff_delay(attempt, self._random))
                    attempt += 1
                    continue
                raise _connection_error(exc) from exc
            if response.is_success:
                return response
            error = error_from_response(response)
            if attempt < retries and self._retryable(response.status_code):
                await self._sleep(self._delay_for(attempt, error))
                attempt += 1
                continue
            raise error

    async def aclose(self) -> None:
        if self.owns_client:
            await self.client.aclose()
