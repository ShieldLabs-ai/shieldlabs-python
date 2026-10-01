"""History API clients (sync and async)."""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator, Iterator
from types import TracebackType
from typing import Callable, Optional, Union
from uuid import UUID

import httpx

from ._errors import (
    APIConnectionError,
    APITimeoutError,
    RateLimitError,
    ServerError,
    ShieldLabsError,
)
from ._http import (
    RATE_LIMIT_MIN_DELAY,
    RETRY_AFTER_CAP,
    USER_AGENT,
    AsyncTransport,
    SyncTransport,
    json_object,
)
from ._models import HistoryPage, Identification
from ._validation import (
    LookupType,
    history_origin,
    resolve_api_key,
    validate_count,
    validate_limit,
    validate_lookup,
    validate_max_retries,
    validate_offset,
    validate_seconds,
    validate_uuid,
)

__all__ = [
    "AsyncHistory",
    "AsyncIdentifications",
    "AsyncShieldLabs",
    "History",
    "Identifications",
    "ShieldLabs",
]

POLL_WAIT_CAP = 2.0
"""Cap of every wait between two polls of ``identifications.get``, in seconds, unless
``poll_interval`` is longer: then ``poll_interval`` is the cap."""

POLL_MIN_ATTEMPT_TIMEOUT = 1.0
"""Shortest timeout of one poll, in seconds, even when less time is left before the deadline."""

POLL_STEPS = (1, 2, 4, 6, 8)
"""Waits between polls as multiples of ``poll_interval``; the last multiple repeats."""

# Errors that do not end a wait: the next poll can still succeed. Everything else (400, 401,
# 403, 404 and any other API error) is raised at once.
_TRANSIENT_ERRORS = (RateLimitError, ServerError, APIConnectionError, APITimeoutError)
_HISTORY_PATH = "/api/v1/history"


def poll_waits(initial: float) -> Iterator[float]:
    """Waits between polls: ``initial`` times 1, 2, 4, 6 and 8, then 8 again.

    Each wait is capped at ``max(2 s, initial)``. With the default initial wait of 0.25 s: 0.25,
    0.5, 1, 1.5, 2, 2, ... With 0.1 s: 0.1, 0.2, 0.4, 0.6, 0.8, 0.8, ... With 1 s: 1, 2, 2, ...
    An initial wait of 2 s or more is used for every wait: 3 s gives 3, 3, 3, ...
    """
    cap = max(POLL_WAIT_CAP, initial)
    for factor in POLL_STEPS:
        yield min(cap, initial * factor)
    yield from itertools.repeat(min(cap, initial * POLL_STEPS[-1]))


class _PollPlan:
    """Timing of one ``identifications.get`` wait, shared by the sync and async clients.

    ``budget`` is the total time the wait may take. Polls follow ``poll_waits`` and the last
    one runs at the deadline.
    """

    def __init__(
        self,
        clock: Callable[[], float],
        budget: float,
        initial_wait: float,
        client_timeout: float,
    ) -> None:
        self._clock = clock
        self._deadline = clock() + budget
        self._waits = poll_waits(initial_wait)
        self._client_timeout = client_timeout
        self._final = False

    def attempt_timeout(self) -> float:
        """Timeout of the next poll: the client timeout, cut to the time left, at least 1 s."""
        remaining = self._deadline - self._clock()
        return min(self._client_timeout, max(remaining, POLL_MIN_ATTEMPT_TIMEOUT))

    def next_wait(self, error: Optional[ShieldLabsError]) -> Optional[float]:
        """Seconds to wait before the next poll, or ``None`` when the wait ends now.

        ``error`` is the transient error of the poll that just ran, or ``None`` when it answered
        without a row. Every wait takes the next ladder step. After a 429 the wait is the
        longest of that step, 1 s and ``Retry-After`` capped at 10 s (a missing header, ``0`` or
        a date in the past counts as 0). A capped ``Retry-After`` longer than the time left ends
        the wait at once; any other wait is cut so that the last poll runs at the deadline.
        """
        remaining = self._deadline - self._clock()
        if self._final or remaining <= 0:
            return None
        wait = next(self._waits)
        if isinstance(error, RateLimitError):
            retry_after = min(error.retry_after or 0.0, RETRY_AFTER_CAP)
            if retry_after > remaining:
                return None
            # The History API limit is counted per second: an earlier poll is refused again.
            wait = max(wait, RATE_LIMIT_MIN_DELAY, retry_after)
        if wait >= remaining:
            wait = remaining
            self._final = True
        return wait


class _HistoryConfig:
    """Configuration shared by the sync and async History clients."""

    base_url: str
    """History API origin, for example ``https://account.shieldlabs.ai``."""

    def _configure(
        self,
        api_key: Optional[str],
        base_url: Optional[str],
        timeout: float,
        max_retries: int,
    ) -> tuple[float, int]:
        key = resolve_api_key(api_key)
        self.base_url = history_origin(base_url)
        self._headers = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        return (
            validate_seconds(timeout, "timeout", allow_zero=False),
            validate_max_retries(max_retries),
        )

    def _history_url(self, lookup_type: str, value: Union[str, UUID]) -> str:
        checked_type, segment = validate_lookup(lookup_type, value)
        return f"{self.base_url}{_HISTORY_PATH}/{checked_type}/{segment}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r})"


class ShieldLabs(_HistoryConfig):
    """Client for the ShieldLabs History API (read identifications with a Private API Key).

    Args:
        api_key: Private API Key (``sec_...``). Defaults to ``SHIELDLABS_API_KEY``.
        base_url: History API origin. Defaults to ``SHIELDLABS_API_BASE_URL`` or
            ``https://account.shieldlabs.ai``. A trailing ``/api`` is removed. Must use https;
            plain http is accepted only for localhost, 127.0.0.1 and ::1 (local test servers).
        timeout: Timeout of one HTTP attempt, in seconds.
        max_retries: Retries for connection errors, timeouts, 429 and 5xx responses.
        http_client: Your own ``httpx.Client`` (proxies, transports). It is not closed by
            ``close()``.

    The client is safe to share across threads. Use it as a context manager or call
    ``close()`` when you are done.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        checked_timeout, checked_retries = self._configure(api_key, base_url, timeout, max_retries)
        self._transport = SyncTransport(
            client=http_client,
            timeout=checked_timeout,
            max_retries=checked_retries,
            retry_rate_limited=True,
        )
        self.history = History(self)
        self.identifications = Identifications(self)

    def _search(
        self,
        lookup_type: str,
        value: Union[str, UUID],
        limit: int,
        offset: int,
        *,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> HistoryPage:
        url = self._history_url(lookup_type, value)
        response = self._transport.get(
            url,
            headers=self._headers,
            params={"limit": validate_limit(limit), "offset": validate_offset(offset)},
            timeout=timeout,
            max_retries=max_retries,
        )
        return HistoryPage.from_dict(json_object(response))

    def close(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        self._transport.close()

    def __enter__(self) -> ShieldLabs:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()


class History:
    """``client.history``: search identifications by one identifier."""

    def __init__(self, client: ShieldLabs) -> None:
        self._client = client

    def search(
        self,
        type: LookupType,
        value: Union[str, UUID],
        limit: int = 20,
        offset: int = 0,
    ) -> HistoryPage:
        """Read one page of identifications that match ``type`` = ``value``, newest first.

        Args:
            type: ``ip``, ``user_hid``, ``visitor_id``, ``request_id``, ``device_id``,
                ``session_id`` or ``cookie_id``.
            value: A UUID for the ID types, a dotted IPv4 address for ``ip``, a non-empty
                string for ``user_hid`` (matched exactly; ``.``, ``..`` and values that contain
                ``/`` cannot be matched in the request path and raise ``ValidationError``).
            limit: Page size, 1 to 100.
            offset: Rows to skip.

        Raises:
            ValidationError: Invalid arguments (nothing is sent).
            ApiError: The API answered with an error status.
        """
        return self._client._search(type, value, limit, offset)

    def iter(
        self,
        type: LookupType,
        value: Union[str, UUID],
        page_size: int = 100,
        max_items: Optional[int] = None,
    ) -> Iterator[Identification]:
        """Iterate over every identification that matches, newest first, page by page.

        Rows are de-duplicated on ``request_id`` (offset paging can repeat a row while new
        identifications arrive). Iteration stops at ``total``, at an empty page, or after
        ``max_items`` identifications.
        """
        validate_lookup(type, value)
        size = validate_limit(page_size, "page_size")
        if max_items is not None:
            max_items = validate_count(max_items, "max_items")
        return self._iterate(type, value, size, max_items)

    def _iterate(
        self,
        lookup_type: str,
        value: Union[str, UUID],
        page_size: int,
        max_items: Optional[int],
    ) -> Iterator[Identification]:
        seen: set[str] = set()
        offset = 0
        count = 0
        while max_items is None or count < max_items:
            page = self._client._search(lookup_type, value, page_size, offset)
            if not page.data:
                return
            for identification in page.data:
                if identification.request_id in seen:
                    continue
                seen.add(identification.request_id)
                yield identification
                count += 1
                if max_items is not None and count >= max_items:
                    return
            offset += len(page.data)
            if offset >= page.total:
                return


class Identifications:
    """``client.identifications``: read the verdict for one request ID."""

    def __init__(self, client: ShieldLabs) -> None:
        self._client = client

    def get(
        self,
        request_id: Union[str, UUID],
        wait: bool = True,
        timeout: float = 10.0,
        poll_interval: float = 0.25,
    ) -> Optional[Identification]:
        """Return the identification for ``request_id``, waiting for it to be scored.

        Scoring is asynchronous: the History row appears about 1-3 s after the browser call
        and can be refined for up to about 10 s while follow-up checks finish. This method
        returns the first version it finds; read the row again with ``history.search`` when you
        need the refined state.

        With ``wait=True``, ``timeout`` is the total time budget of the call. The History API is
        polled immediately, then after waits of ``poll_interval`` times 1, 2, 4, 6 and 8, then
        8 again, each wait capped at ``max(2 s, poll_interval)`` (by default 0.25 s, 0.5 s, 1 s,
        1.5 s and then every 2 s; every 3 s for ``poll_interval=3``), and a last time at the
        deadline. Each poll is one HTTP attempt, never retried inside the poll, with a timeout
        of ``min(client timeout, max(time left, 1 s))``. A 429, a 5xx response, a connection
        error or a timeout does not end the wait: polling continues. After a 429 the next wait
        is the longest of the ladder step, 1 s and ``Retry-After`` capped at 10 s
        (``Retry-After: 0`` or a date in the past counts as 0), cut to the deadline; a capped
        ``Retry-After`` longer than the time left raises the 429 at once. A 400, 401, 403 or 404
        is raised at once.

        With ``wait=False`` one lookup is made, with the client's regular retries.

        Returns:
            The ``Identification``, or ``None`` when the last poll answered without a row (treat
            that as unverified, never as clean).

        Raises:
            ValidationError: ``request_id`` is not a UUID (nothing is sent).
            BadRequestError, AuthenticationError, NotFoundError: A 400, a 401 or 403, or a 404
                answer; polling stops at once.
            RateLimitError, ServerError, APIConnectionError, APITimeoutError: The last poll
                failed with this error, or a 429 asked for a pause longer than the time left.
        """
        rid = validate_uuid(request_id, "request_id")
        total_timeout = validate_seconds(timeout, "timeout", allow_zero=True)
        initial_wait = validate_seconds(poll_interval, "poll_interval", allow_zero=False)
        client = self._client
        if not wait:
            page = client._search("request_id", rid, 1, 0)
            return page.data[0] if page.data else None

        transport = client._transport
        plan = _PollPlan(transport._clock, total_timeout, initial_wait, transport.timeout)
        while True:
            error: Optional[ShieldLabsError] = None
            try:
                page = client._search(
                    "request_id", rid, 1, 0, timeout=plan.attempt_timeout(), max_retries=0
                )
            except _TRANSIENT_ERRORS as exc:
                error = exc
            else:
                if page.data:
                    return page.data[0]
            delay = plan.next_wait(error)
            if delay is None:
                if error is not None:
                    raise error
                return None
            transport._sleep(delay)


class AsyncShieldLabs(_HistoryConfig):
    """Asynchronous client for the ShieldLabs History API.

    Same arguments as ``ShieldLabs``; ``http_client`` is an ``httpx.AsyncClient``. Safe to share
    across tasks. Use ``async with`` or call ``aclose()`` when you are done.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        checked_timeout, checked_retries = self._configure(api_key, base_url, timeout, max_retries)
        self._transport = AsyncTransport(
            client=http_client,
            timeout=checked_timeout,
            max_retries=checked_retries,
            retry_rate_limited=True,
        )
        self.history = AsyncHistory(self)
        self.identifications = AsyncIdentifications(self)

    async def _search(
        self,
        lookup_type: str,
        value: Union[str, UUID],
        limit: int,
        offset: int,
        *,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> HistoryPage:
        url = self._history_url(lookup_type, value)
        response = await self._transport.get(
            url,
            headers=self._headers,
            params={"limit": validate_limit(limit), "offset": validate_offset(offset)},
            timeout=timeout,
            max_retries=max_retries,
        )
        return HistoryPage.from_dict(json_object(response))

    async def aclose(self) -> None:
        """Close the underlying HTTP client (unless it was passed in)."""
        await self._transport.aclose()

    async def __aenter__(self) -> AsyncShieldLabs:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        await self.aclose()


class AsyncHistory:
    """``client.history`` on ``AsyncShieldLabs``."""

    def __init__(self, client: AsyncShieldLabs) -> None:
        self._client = client

    async def search(
        self,
        type: LookupType,
        value: Union[str, UUID],
        limit: int = 20,
        offset: int = 0,
    ) -> HistoryPage:
        """Async ``ShieldLabs.history.search``."""
        return await self._client._search(type, value, limit, offset)

    def iter(
        self,
        type: LookupType,
        value: Union[str, UUID],
        page_size: int = 100,
        max_items: Optional[int] = None,
    ) -> AsyncIterator[Identification]:
        """Async ``ShieldLabs.history.iter``: use it with ``async for``."""
        validate_lookup(type, value)
        size = validate_limit(page_size, "page_size")
        if max_items is not None:
            max_items = validate_count(max_items, "max_items")
        return self._iterate(type, value, size, max_items)

    async def _iterate(
        self,
        lookup_type: str,
        value: Union[str, UUID],
        page_size: int,
        max_items: Optional[int],
    ) -> AsyncIterator[Identification]:
        seen: set[str] = set()
        offset = 0
        count = 0
        while max_items is None or count < max_items:
            page = await self._client._search(lookup_type, value, page_size, offset)
            if not page.data:
                return
            for identification in page.data:
                if identification.request_id in seen:
                    continue
                seen.add(identification.request_id)
                yield identification
                count += 1
                if max_items is not None and count >= max_items:
                    return
            offset += len(page.data)
            if offset >= page.total:
                return


class AsyncIdentifications:
    """``client.identifications`` on ``AsyncShieldLabs``."""

    def __init__(self, client: AsyncShieldLabs) -> None:
        self._client = client

    async def get(
        self,
        request_id: Union[str, UUID],
        wait: bool = True,
        timeout: float = 10.0,
        poll_interval: float = 0.25,
    ) -> Optional[Identification]:
        """Async ``ShieldLabs.identifications.get``: same waiting rules, errors and result."""
        rid = validate_uuid(request_id, "request_id")
        total_timeout = validate_seconds(timeout, "timeout", allow_zero=True)
        initial_wait = validate_seconds(poll_interval, "poll_interval", allow_zero=False)
        client = self._client
        if not wait:
            page = await client._search("request_id", rid, 1, 0)
            return page.data[0] if page.data else None

        transport = client._transport
        plan = _PollPlan(transport._clock, total_timeout, initial_wait, transport.timeout)
        while True:
            error: Optional[ShieldLabsError] = None
            try:
                page = await client._search(
                    "request_id", rid, 1, 0, timeout=plan.attempt_timeout(), max_retries=0
                )
            except _TRANSIENT_ERRORS as exc:
                error = exc
            else:
                if page.data:
                    return page.data[0]
            delay = plan.next_wait(error)
            if delay is None:
                if error is not None:
                    raise error
                return None
            await transport._sleep(delay)
