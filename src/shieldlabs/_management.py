"""Management API clients (sync and async)."""

from __future__ import annotations

from types import TracebackType
from typing import Optional

import httpx

from ._generated_wire import PROFILE_PATH, ProfileHeaders
from ._http import USER_AGENT, AsyncTransport, SyncTransport, json_object
from ._models import DomainProfile
from ._validation import (
    management_origin,
    normalize_domain,
    require_secret,
    validate_max_retries,
    validate_seconds,
)

__all__ = ["AsyncShieldLabsManagement", "ShieldLabsManagement"]

_PROFILE_PATH = PROFILE_PATH


class _ManagementConfig:
    """Configuration shared by the sync and async Management clients."""

    base_url: str
    """Management API origin, for example ``https://api.shieldlabs.ai``."""
    domain: str
    """The registered domain, normalized (sent as ``X-Shield-Domain``)."""

    def _configure(
        self,
        secret_key: Optional[str],
        domain: Optional[str],
        base_url: Optional[str],
        timeout: float,
        max_retries: int,
    ) -> tuple[float, int]:
        secret = require_secret(secret_key, "SHIELDLABS_SECRET_KEY", "secret_key")
        self.domain = normalize_domain(domain)
        self.base_url = management_origin(base_url)
        profile_headers: ProfileHeaders = {"X-Shield-Domain": self.domain}
        self._headers: dict[str, str] = {
            "X-Shield-Domain": profile_headers["X-Shield-Domain"],
            "Authorization": f"Bearer {secret}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        return (
            validate_seconds(timeout, "timeout", allow_zero=False),
            validate_max_retries(max_retries),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(domain={self.domain!r}, base_url={self.base_url!r})"


class ShieldLabsManagement(_ManagementConfig):
    """Client for the ShieldLabs Management API (domain profile, Secret Key + domain).

    The Management API allows about 15 requests per minute per caller IP and then blocks the
    IP for 10 minutes, so this client never retries a 429 (``RateLimitError`` is raised at
    once). Call it sparingly and cache the profile.

    Args:
        secret_key: Secret Key of the domain. Defaults to ``SHIELDLABS_SECRET_KEY``.
        domain: Registered domain. Defaults to ``SHIELDLABS_DOMAIN``. Normalized before use
            (``https://www.Example.com/`` becomes ``example.com``).
        base_url: Management API origin. Defaults to ``SHIELDLABS_MANAGEMENT_BASE_URL`` or
            ``https://api.shieldlabs.ai``. Must use https; plain http is accepted only for
            localhost, 127.0.0.1 and ::1 (local test servers).
        timeout: Timeout of one HTTP attempt, in seconds.
        max_retries: Retries for connection errors, timeouts and 5xx responses (never 429).
        http_client: Your own ``httpx.Client``. It is not closed by ``close()``.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        domain: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        checked_timeout, checked_retries = self._configure(
            secret_key, domain, base_url, timeout, max_retries
        )
        self._transport = SyncTransport(
            client=http_client,
            timeout=checked_timeout,
            max_retries=checked_retries,
            retry_rate_limited=False,
        )

    def get_profile(self) -> DomainProfile:
        """Read the domain profile (``GET /v1/profile``).

        Raises:
            AuthenticationError: Wrong Secret Key, unknown or disabled domain.
            RateLimitError: Per-IP limit reached; the IP stays blocked for 10 minutes.
        """
        response = self._transport.get(f"{self.base_url}{_PROFILE_PATH}", headers=self._headers)
        return DomainProfile.from_dict(json_object(response))

    def close(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        self._transport.close()

    def __enter__(self) -> ShieldLabsManagement:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()


class AsyncShieldLabsManagement(_ManagementConfig):
    """Asynchronous client for the ShieldLabs Management API.

    Same arguments and rate-limit rules as ``ShieldLabsManagement``; ``http_client`` is an
    ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        domain: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        checked_timeout, checked_retries = self._configure(
            secret_key, domain, base_url, timeout, max_retries
        )
        self._transport = AsyncTransport(
            client=http_client,
            timeout=checked_timeout,
            max_retries=checked_retries,
            retry_rate_limited=False,
        )

    async def get_profile(self) -> DomainProfile:
        """Async ``ShieldLabsManagement.get_profile``."""
        response = await self._transport.get(
            f"{self.base_url}{_PROFILE_PATH}", headers=self._headers
        )
        return DomainProfile.from_dict(json_object(response))

    async def aclose(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        await self._transport.aclose()

    async def __aenter__(self) -> AsyncShieldLabsManagement:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        await self.aclose()
