"""identifications.get: the wait-for-verdict rules, for the sync and the async client.

- ``timeout`` is the total budget of the call.
- The first poll runs at once, then after waits of ``poll_interval`` times 1, 2, 4, 6 and 8, then
  8 again, each capped at ``max(2 s, poll_interval)`` (0.25 s, 0.5 s, 1 s, 1.5 s and every 2 s by
  default); the last poll runs at the deadline.
- Each poll is one HTTP attempt with a timeout of ``min(client timeout, max(time left, 1 s))``.
- 429, 5xx, connection errors and timeouts keep the wait going. At the deadline the error of the
  last poll is raised; when the last poll answered without a row, the result is ``None``.
- After a 429 the next wait is ``max(ladder step, 1 s, min(Retry-After or 0, 10 s))``, cut to the
  deadline (``Retry-After: 0`` and past dates count as 0); a capped ``Retry-After`` longer than
  the time left raises the 429 at once.
- 400, 401, 403 and 404 stop the wait at once.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Callable, Optional, Union

import httpx
import pytest
import respx

from _support import (
    API_KEY,
    HISTORY_HOST,
    REQUEST_ID,
    REQUEST_PATH,
    FakeTime,
    empty_page,
    load_json,
)
from shieldlabs import (
    APIConnectionError,
    ApiError,
    APITimeoutError,
    AsyncShieldLabs,
    AuthenticationError,
    BadRequestError,
    Identification,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    ShieldLabs,
    ValidationError,
)
from shieldlabs._client import poll_waits

pytestmark = pytest.mark.anyio

Client = Union[ShieldLabs, AsyncShieldLabs]
Answer = Callable[[], Union[httpx.Response, Exception]]

LADDER_TIMES = [0.0, 0.25, 0.75, 1.75, 3.25, 5.25, 7.25, 9.25, 10.0]
"""When the polls of a default 10-second wait run."""


def _found() -> httpx.Response:
    page = load_json("history-page.json")
    return httpx.Response(200, json={"data": page["data"][:1], "total": 1})


def _status(code: int, retry_after: Any = None) -> Answer:
    def answer() -> httpx.Response:
        headers = {"content-type": "application/json"}
        if retry_after is not None:
            headers["retry-after"] = str(retry_after)
        return httpx.Response(code, text='{"error":"request failed"}\n', headers=headers)

    return answer


class Server:
    """Answers each poll with the next scripted answer (the last one repeats).

    An answer is a response or an exception to raise. The server records when each poll ran on
    the fake clock and the timeout of its HTTP attempt, and can let every answer take
    ``latency`` seconds.
    """

    def __init__(self, fake_time: FakeTime, *answers: Answer, latency: float = 0.0) -> None:
        self._fake_time = fake_time
        self._answers = answers
        self._latency = latency
        self.times: list[float] = []
        self.timeouts: list[float] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.times.append(round(self._fake_time.now, 6))
        self.timeouts.append(request.extensions["timeout"]["read"])
        self._fake_time.now += self._latency
        answer = self._answers[min(len(self.times), len(self._answers)) - 1]()
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(params=["sync", "async"])
def make_client(request: pytest.FixtureRequest, fake_time: FakeTime) -> Callable[..., Client]:
    def make(**options: Any) -> Client:
        cls = ShieldLabs if request.param == "sync" else AsyncShieldLabs
        instance: Client = cls(api_key=API_KEY, **options)
        fake_time.install(instance._transport)
        return instance

    return make


@pytest.fixture
def client(make_client: Callable[..., Client]) -> Client:
    return make_client()


@pytest.fixture
def mock() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


def serve(mock: respx.MockRouter, fake_time: FakeTime, *answers: Answer, **kw: Any) -> Server:
    server = Server(fake_time, *answers, **kw)
    mock.get(host=HISTORY_HOST, path=REQUEST_PATH).mock(side_effect=server)
    return server


async def get(client: Client, *args: Any, **kwargs: Any) -> Optional[Identification]:
    if isinstance(client, AsyncShieldLabs):
        return await client.identifications.get(*args, **kwargs)
    return client.identifications.get(*args, **kwargs)


def _take(iterator: Iterator[float], count: int) -> list[float]:
    return [next(iterator) for _ in range(count)]


# The ladder


def test_poll_waits_default_schedule() -> None:
    assert _take(poll_waits(0.25), 8) == [0.25, 0.5, 1.0, 1.5, 2.0, 2.0, 2.0, 2.0]


@pytest.mark.parametrize(
    ("initial", "expected"),
    [
        # poll_interval times 1, 2, 4, 6 and 8, then 8 again, each wait capped at
        # max(2 s, poll_interval).
        (0.01, [0.01, 0.02, 0.04, 0.06, 0.08, 0.08, 0.08, 0.08]),  # no lower limit
        (0.1, [0.1, 0.2, 0.4, 0.6, 0.8, 0.8, 0.8, 0.8]),
        (0.2, [0.2, 0.4, 0.8, 1.2, 1.6, 1.6, 1.6, 1.6]),
        (0.3, [0.3, 0.6, 1.2, 1.8, 2.0, 2.0, 2.0, 2.0]),
        (0.5, [0.5, 1.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0]),
        (1.0, [1.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0]),
        (2.0, [2.0] * 8),
        (3.0, [3.0] * 8),
        (60.0, [60.0] * 8),
    ],
)
def test_poll_waits_scale_with_the_poll_interval(initial: float, expected: list[float]) -> None:
    assert _take(poll_waits(initial), 8) == pytest.approx(expected)


async def test_first_poll_is_immediate_and_found(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _found)
    identification = await get(client, REQUEST_ID)
    assert isinstance(identification, Identification)
    assert identification.request_id == REQUEST_ID
    assert server.times == [0.0]
    assert fake_time.sleeps == []


async def test_polls_on_the_ladder_until_the_row_appears(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[empty_page(), empty_page(), empty_page(), _found()]
    )
    assert await get(client, REQUEST_ID.upper()) is not None
    assert fake_time.sleeps == [0.25, 0.5, 1.0]
    assert route.call_count == 4
    assert route.calls.last.request.url.path == REQUEST_PATH
    params = route.calls.last.request.url.params
    assert (params["limit"], params["offset"]) == ("1", "0")


async def test_custom_poll_interval_sets_the_first_wait(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    serve(mock, fake_time, empty_page, empty_page, _found)
    assert await get(client, REQUEST_ID, poll_interval=0.5) is not None
    assert fake_time.sleeps == [0.5, 1.0]


async def test_small_poll_interval_keeps_its_own_ladder_until_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    # 0.1 s gives waits of 0.1, 0.2, 0.4, 0.6 and 0.8 s, then 0.8 s again; the last one is cut
    # so that the last poll runs at the deadline.
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID, timeout=5, poll_interval=0.1) is None
    assert fake_time.sleeps == pytest.approx([0.1, 0.2, 0.4, 0.6, 0.8, 0.8, 0.8, 0.8, 0.5])
    assert server.times == pytest.approx([0.0, 0.1, 0.3, 0.7, 1.3, 2.1, 2.9, 3.7, 4.5, 5.0])


@pytest.mark.parametrize(
    ("poll_interval", "sleeps", "times"),
    [
        # Waits of p, 2p, 4p, 6p and 8p, then 8p again, each at most max(2 s, p). The last wait
        # is cut so that the last poll runs at the 10 s deadline.
        (0.25, [0.25, 0.5, 1.0, 1.5, 2.0, 2.0, 2.0, 0.75], LADDER_TIMES),
        (1.0, [1.0, 2.0, 2.0, 2.0, 2.0, 1.0], [0.0, 1.0, 3.0, 5.0, 7.0, 9.0, 10.0]),
        (3.0, [3.0, 3.0, 3.0, 1.0], [0.0, 3.0, 6.0, 9.0, 10.0]),
    ],
)
async def test_the_ladder_of_a_poll_interval_until_the_deadline(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    poll_interval: float,
    sleeps: list[float],
    times: list[float],
) -> None:
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID, poll_interval=poll_interval) is None
    assert fake_time.sleeps == sleeps
    assert server.times == times


# The deadline: total budget, last poll at the deadline, None when nothing was found


async def test_last_poll_runs_at_the_deadline_and_none_is_returned(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID) is None
    assert server.times == LADDER_TIMES
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 1.5, 2.0, 2.0, 2.0, 0.75]
    assert fake_time.now == 10.0


async def test_short_budget_cuts_the_last_wait_to_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID, timeout=3) is None
    assert server.times == [0.0, 0.25, 0.75, 1.75, 3.0]
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 1.25]


async def test_budget_counts_the_time_polls_take(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    # Every answer takes 0.3 s: the waits keep their length and the last poll still starts at
    # the deadline (3 s), so the call ends when that answer arrives.
    server = serve(mock, fake_time, empty_page, latency=0.3)
    assert await get(client, REQUEST_ID, timeout=3) is None
    assert server.times == [0.0, 0.55, 1.35, 2.65, 3.0]
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 0.05]
    assert fake_time.now == pytest.approx(3.3)


async def test_poll_after_the_last_wait_is_final_even_when_a_sleep_ends_early(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    # Event loop timers can fire slightly early. The poll that follows the wait cut to the
    # deadline is still the last one, even though a sliver of time seems to be left.
    def early_sleep(seconds: float) -> None:
        assert len(fake_time.sleeps) < 20, "polling did not stop"
        fake_time.sleeps.append(round(seconds, 6))
        fake_time.now += max(0.0, seconds - 0.001)

    async def early_async_sleep(seconds: float) -> None:
        early_sleep(seconds)

    if isinstance(client, AsyncShieldLabs):
        client._transport._sleep = early_async_sleep
    else:
        client._transport._sleep = early_sleep
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID, timeout=3) is None
    assert server.times == [0.0, 0.249, 0.748, 1.747, 2.999]


async def test_a_poll_that_ends_after_the_deadline_is_the_last_one(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page, latency=4.0)
    assert await get(client, REQUEST_ID, timeout=3) is None
    assert server.times == [0.0]
    assert fake_time.sleeps == []


async def test_a_failed_poll_that_ends_after_the_deadline_raises(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _status(504), latency=4.0)
    with pytest.raises(ServerError):
        await get(client, REQUEST_ID, timeout=3)
    assert server.times == [0.0]


async def test_timeout_zero_polls_once(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page)
    assert await get(client, REQUEST_ID, timeout=0) is None
    assert server.times == [0.0]
    assert fake_time.sleeps == []


async def test_none_when_the_last_poll_finds_nothing_after_errors(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(
        mock,
        fake_time,
        _status(503),
        lambda: httpx.ConnectError("connection refused"),
        empty_page,
    )
    assert await get(client, REQUEST_ID, timeout=1) is None
    assert server.times == [0.0, 0.25, 0.75, 1.0]


# One HTTP attempt per poll and its timeout


@pytest.mark.parametrize(
    ("client_timeout", "budget", "expected"),
    [
        # min(client timeout, max(time left, 1 s)) at the start of each poll.
        (10.0, 10.0, [10.0, 9.75, 9.25, 8.25, 6.75, 4.75, 2.75, 1.0, 1.0]),
        (2.0, 5.0, [2.0, 2.0, 2.0, 2.0, 1.75, 1.0]),
        (0.5, 1.0, [0.5, 0.5, 0.5, 0.5]),
    ],
)
async def test_attempt_timeout_is_the_client_timeout_cut_to_the_time_left(
    make_client: Callable[..., Client],
    mock: respx.MockRouter,
    fake_time: FakeTime,
    client_timeout: float,
    budget: float,
    expected: list[float],
) -> None:
    server = serve(mock, fake_time, empty_page)
    client = make_client(timeout=client_timeout)
    assert await get(client, REQUEST_ID, timeout=budget) is None
    assert server.timeouts == pytest.approx(expected)


async def test_attempt_timeout_counts_the_time_polls_take(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page, latency=0.3)
    await get(client, REQUEST_ID, timeout=3)
    assert server.times == [0.0, 0.55, 1.35, 2.65, 3.0]
    assert server.timeouts == pytest.approx([3.0, 2.45, 1.65, 1.0, 1.0])


async def test_each_poll_is_one_http_attempt(
    make_client: Callable[..., Client], mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    # max_retries applies to single requests; inside the wait a failed poll is not retried.
    server = serve(mock, fake_time, _status(500), _status(500), _found)
    client = make_client(max_retries=5)
    assert await get(client, REQUEST_ID) is not None
    assert server.times == [0.0, 0.25, 0.75]
    assert fake_time.sleeps == [0.25, 0.5]


# Transient errors keep the wait going


_TRANSIENT: list[tuple[str, Answer, type[Exception]]] = [
    ("500", _status(500), ServerError),
    ("502", lambda: httpx.Response(502, text="<html>bad gateway</html>"), ServerError),
    ("503", _status(503), ServerError),
    ("connect", lambda: httpx.ConnectError("connection refused"), APIConnectionError),
    ("read-timeout", lambda: httpx.ReadTimeout("slow"), APITimeoutError),
    ("connect-timeout", lambda: httpx.ConnectTimeout("slow"), APITimeoutError),
]


@pytest.mark.parametrize(
    ("answer", "error_type"),
    [pytest.param(answer, error_type, id=name) for name, answer, error_type in _TRANSIENT],
)
async def test_transient_error_keeps_polling_and_is_raised_at_the_deadline(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    answer: Answer,
    error_type: type[Exception],
) -> None:
    server = serve(mock, fake_time, answer)
    with pytest.raises(error_type):
        await get(client, REQUEST_ID, timeout=4)
    assert server.times == [0.0, 0.25, 0.75, 1.75, 3.25, 4.0]
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 1.5, 0.75]


@pytest.mark.parametrize(
    "answer", [pytest.param(answer, id=name) for name, answer, _ in _TRANSIENT]
)
async def test_transient_error_then_row_returns_the_row(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime, answer: Answer
) -> None:
    server = serve(mock, fake_time, answer, answer, _found)
    identification = await get(client, REQUEST_ID)
    assert identification is not None
    assert identification.request_id == REQUEST_ID
    assert server.times == [0.0, 0.25, 0.75]


async def test_mixed_transient_errors_keep_polling(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(
        mock,
        fake_time,
        lambda: httpx.Response(502, text="<html>bad gateway</html>"),
        lambda: httpx.ConnectError("connection refused"),
        lambda: httpx.ReadTimeout("slow"),
        _found,
    )
    assert await get(client, REQUEST_ID) is not None
    assert server.times == [0.0, 0.25, 0.75, 1.75]


async def test_error_of_the_last_poll_is_raised(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(
        mock,
        fake_time,
        _status(500),
        _status(429),
        lambda: httpx.ConnectError("refused at the deadline"),
    )
    with pytest.raises(APIConnectionError, match="refused at the deadline"):
        await get(client, REQUEST_ID, timeout=0.5)
    assert server.times == [0.0, 0.25, 0.5]


async def test_last_poll_failing_after_empty_answers_raises(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page, _status(500))
    with pytest.raises(ServerError):
        await get(client, REQUEST_ID, timeout=0.25)
    assert server.times == [0.0, 0.25]


# 429 inside the wait


async def test_rate_limit_without_retry_after_waits_at_least_one_second(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _status(429), _status(429), empty_page, _status(429), _found)
    assert await get(client, REQUEST_ID) is not None
    # The 0.25 s and 0.5 s steps become 1 s after a 429; the 1.5 s step is already long enough.
    assert fake_time.sleeps == [1.0, 1.0, 1.0, 1.5]
    assert server.times == [0.0, 1.0, 2.0, 3.0, 4.5]


async def test_rate_limit_without_retry_after_until_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _status(429))
    with pytest.raises(RateLimitError) as caught:
        await get(client, REQUEST_ID, timeout=4)
    assert caught.value.status == 429
    assert caught.value.retry_after is None
    assert server.times == [0.0, 1.0, 2.0, 3.0, 4.0]


async def test_one_second_floor_never_passes_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _status(429))
    with pytest.raises(RateLimitError):
        await get(client, REQUEST_ID, timeout=0.2)
    assert server.times == [0.0, 0.2]
    assert fake_time.sleeps == [0.2]


async def test_retry_after_is_honoured_then_the_ladder_continues(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    serve(mock, fake_time, _status(429, retry_after=1.5), empty_page, _found)
    assert await get(client, REQUEST_ID) is not None
    assert fake_time.sleeps == [1.5, 0.5]


async def test_retry_after_is_capped_at_ten_seconds(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, _status(429, retry_after=60), _found)
    assert await get(client, REQUEST_ID, timeout=30) is not None
    assert server.times == [0.0, 10.0]


async def test_retry_after_shorter_than_the_ladder_step_keeps_the_step(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    serve(
        mock,
        fake_time,
        empty_page,
        empty_page,
        empty_page,
        empty_page,
        _status(429, retry_after=1),
        _status(429, retry_after=0),
        _found,
    )
    assert await get(client, REQUEST_ID, timeout=30) is not None
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 1.5, 2.0, 2.0]


@pytest.mark.parametrize(
    "retry_after",
    [
        pytest.param("0", id="zero"),
        pytest.param("Wed, 21 Oct 2015 07:28:00 GMT", id="past-date"),
    ],
)
async def test_zero_or_past_retry_after_still_waits_one_second(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime, retry_after: str
) -> None:
    # Both count as 0: the wait is max(ladder step, 1 s, 0), so the 0.25 s step becomes 1 s.
    server = serve(mock, fake_time, _status(429, retry_after=retry_after), empty_page, _found)
    assert await get(client, REQUEST_ID) is not None
    assert fake_time.sleeps == [1.0, 0.5]
    assert server.times == [0.0, 1.0, 1.5]


@pytest.mark.parametrize(
    "retry_after",
    [
        pytest.param("0", id="zero"),
        pytest.param("Wed, 21 Oct 2015 07:28:00 GMT", id="past-date"),
    ],
)
async def test_zero_retry_after_near_the_deadline_polls_at_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime, retry_after: str
) -> None:
    server = serve(mock, fake_time, _status(429, retry_after=retry_after))
    with pytest.raises(RateLimitError) as caught:
        await get(client, REQUEST_ID, timeout=0.5)
    assert caught.value.retry_after == 0.0
    assert server.times == [0.0, 0.5]
    assert fake_time.sleeps == [0.5]


@pytest.mark.parametrize(
    ("retry_after", "sleeps"),
    [
        # The 3 s step is longer than the 1 s floor and a shorter Retry-After. A longer
        # Retry-After wins, and the ladder then goes on with its next step.
        pytest.param(None, [3.0, 3.0], id="no-retry-after"),
        pytest.param(2, [3.0, 3.0], id="shorter-retry-after"),
        pytest.param(5, [5.0, 3.0], id="longer-retry-after"),
    ],
)
async def test_rate_limit_keeps_the_ladder_of_a_long_poll_interval(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    retry_after: Optional[float],
    sleeps: list[float],
) -> None:
    serve(mock, fake_time, _status(429, retry_after=retry_after), empty_page, _found)
    assert await get(client, REQUEST_ID, poll_interval=3) is not None
    assert fake_time.sleeps == sleeps


async def test_rate_limit_floor_applies_to_a_custom_ladder(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    serve(mock, fake_time, _status(429), empty_page, empty_page, _found)
    assert await get(client, REQUEST_ID, poll_interval=0.1) is not None
    # The 0.1 s step becomes 1 s after the 429; the ladder then goes on with 0.2 s and 0.4 s.
    assert fake_time.sleeps == pytest.approx([1.0, 0.2, 0.4])


async def test_retry_after_between_floor_and_step_is_cut_to_the_deadline(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    # At 3.25 s the step is 2 s, longer than Retry-After (1.5 s) and the 1 s floor, and only
    # 1.75 s is left: the wait is cut and the last poll runs at the deadline.
    server = serve(
        mock,
        fake_time,
        empty_page,
        empty_page,
        empty_page,
        empty_page,
        _status(429, retry_after=1.5),
        _found,
    )
    assert await get(client, REQUEST_ID, timeout=5) is not None
    assert fake_time.sleeps == [0.25, 0.5, 1.0, 1.5, 1.75]
    assert server.times == [0.0, 0.25, 0.75, 1.75, 3.25, 5.0]


@pytest.mark.parametrize(
    ("retry_after", "budget"),
    [
        (5, 4),
        (60, 4),
        (60, 9.5),  # capped at 10 s, which is still longer than the time left
    ],
)
async def test_retry_after_longer_than_the_time_left_raises_at_once(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    retry_after: float,
    budget: float,
) -> None:
    server = serve(mock, fake_time, _status(429, retry_after=retry_after), _found)
    with pytest.raises(RateLimitError) as caught:
        await get(client, REQUEST_ID, timeout=budget)
    assert caught.value.retry_after == retry_after
    assert server.times == [0.0]
    assert fake_time.sleeps == []


async def test_retry_after_later_in_the_wait_raises_when_it_does_not_fit(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    server = serve(mock, fake_time, empty_page, empty_page, empty_page, _status(429, retry_after=9))
    with pytest.raises(RateLimitError):
        await get(client, REQUEST_ID)
    assert server.times == [0.0, 0.25, 0.75, 1.75]
    assert fake_time.now == 1.75


@pytest.mark.parametrize(
    ("retry_after", "budget"),
    [
        (2, 2),
        (60, 10),  # capped at 10 s, which fits exactly
    ],
)
async def test_retry_after_equal_to_the_time_left_polls_at_the_deadline(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    retry_after: float,
    budget: float,
) -> None:
    server = serve(mock, fake_time, _status(429, retry_after=retry_after), _found)
    assert await get(client, REQUEST_ID, timeout=budget) is not None
    assert server.times == [0.0, budget]


# Errors that stop the wait at once

STOP_STATUSES = [
    (400, BadRequestError),
    (401, AuthenticationError),
    (403, AuthenticationError),
    (404, NotFoundError),
]


@pytest.mark.parametrize(("status", "error_type"), STOP_STATUSES)
async def test_client_errors_stop_polling_at_once(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    status: int,
    error_type: type[ApiError],
) -> None:
    server = serve(mock, fake_time, _status(status))
    with pytest.raises(error_type) as caught:
        await get(client, REQUEST_ID)
    assert caught.value.status == status
    assert server.times == [0.0]
    assert fake_time.sleeps == []


@pytest.mark.parametrize(("status", "error_type"), STOP_STATUSES)
async def test_client_error_after_a_transient_error_stops_at_once(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    status: int,
    error_type: type[ApiError],
) -> None:
    server = serve(mock, fake_time, _status(503), _status(status), _found)
    with pytest.raises(error_type):
        await get(client, REQUEST_ID)
    assert server.times == [0.0, 0.25]


async def test_authentication_error_message_is_kept(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    mock.get(host=HISTORY_HOST).respond(
        401, text='{"error":"invalid api key"}\n', headers={"content-type": "text/plain"}
    )
    with pytest.raises(AuthenticationError, match="invalid api key"):
        await get(client, REQUEST_ID)


async def test_not_found_page_stops_polling(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(404, text="404 page not found")
    with pytest.raises(NotFoundError, match="404 page not found"):
        await get(client, REQUEST_ID)
    assert route.call_count == 1


@pytest.mark.parametrize(("status", "error_type"), [(402, QuotaExceededError), (409, ApiError)])
async def test_other_error_statuses_stop_polling_too(
    client: Client,
    mock: respx.MockRouter,
    fake_time: FakeTime,
    status: int,
    error_type: type[ApiError],
) -> None:
    server = serve(mock, fake_time, _status(status))
    with pytest.raises(error_type):
        await get(client, REQUEST_ID)
    assert server.times == [0.0]


# wait=False and validation


async def test_wait_false_sends_one_request(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=[empty_page(), _found()])
    assert await get(client, REQUEST_ID, wait=False) is None
    assert await get(client, REQUEST_ID, wait=False) is not None
    assert route.call_count == 2
    assert fake_time.sleeps == []


async def test_wait_false_uses_regular_retries(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=lambda request: _status(429)())
    with pytest.raises(RateLimitError):
        await get(client, REQUEST_ID, wait=False)
    assert route.call_count == 3
    assert fake_time.sleeps == [1.0, 1.0]  # a 429 without Retry-After waits at least 1 s


async def test_connection_error_without_wait_is_raised(
    client: Client, mock: respx.MockRouter, fake_time: FakeTime
) -> None:
    mock.get(host=HISTORY_HOST).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(APIConnectionError, match="down"):
        await get(client, REQUEST_ID, wait=False)


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        (("not-a-uuid",), {}),
        ((REQUEST_ID,), {"timeout": -1}),
        ((REQUEST_ID,), {"timeout": float("inf")}),
        ((REQUEST_ID,), {"poll_interval": 0}),
        ((REQUEST_ID,), {"poll_interval": float("nan")}),
    ],
)
async def test_get_validates_before_sending(
    client: Client, mock: respx.MockRouter, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    route = mock.get(host=HISTORY_HOST).mock(return_value=empty_page())
    with pytest.raises(ValidationError):
        await get(client, *args, **kwargs)
    assert route.call_count == 0
