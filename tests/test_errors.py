"""Error mapping and retries, driven by the shared error-responses fixture."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any

import httpx
import pytest
import respx

import shieldlabs
from _support import (
    API_KEY,
    DOMAIN,
    HISTORY_HOST,
    MANAGEMENT_HOST,
    REQUEST_ID,
    SECRET_KEY,
    FakeTime,
    load_json,
)
from shieldlabs import (
    APIConnectionError,
    ApiError,
    APITimeoutError,
    RateLimitError,
    ServerError,
    ShieldLabs,
    ShieldLabsError,
    ShieldLabsManagement,
)
from shieldlabs._http import backoff_delay, error_from_response, parse_retry_after

CASES = load_json("error-responses.json")["cases"]


def _response(case: dict[str, Any]) -> httpx.Response:
    headers = {"content-type": case["content_type"]} if case["content_type"] else {}
    return httpx.Response(case["status"], content=case["body"].encode("utf-8"), headers=headers)


@pytest.fixture
def mock() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield router


def _call(surface: str, fake_time: FakeTime, max_retries: int = 1) -> None:
    if surface == "history":
        client = ShieldLabs(api_key=API_KEY, max_retries=max_retries)
        fake_time.install(client._transport)
        client.history.search("request_id", REQUEST_ID)
    else:
        management = ShieldLabsManagement(
            secret_key=SECRET_KEY, domain=DOMAIN, max_retries=max_retries
        )
        fake_time.install(management._transport)
        management.get_profile()


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[f"{c['surface']}-{c['status']}-{i}" for i, c in enumerate(CASES)],
)
def test_error_responses_fixture(case: dict[str, Any], mock: Any, fake_time: FakeTime) -> None:
    host = HISTORY_HOST if case["surface"] == "history" else MANAGEMENT_HOST
    route = mock.get(host=host).mock(side_effect=lambda request: _response(case))
    expected_class = getattr(shieldlabs, case["expected_error"])

    with pytest.raises(expected_class) as caught:
        _call(case["surface"], fake_time)

    error = caught.value
    assert type(error) is expected_class
    assert isinstance(error, ApiError)
    assert isinstance(error, ShieldLabsError)
    assert error.status == case["status"]
    assert f"(HTTP {case['status']})" in str(error)
    assert route.call_count == (2 if case["retry"] else 1)
    if case["content_type"]:
        assert error.headers["content-type"] == case["content_type"]


def test_error_messages_are_parsed_defensively() -> None:
    def build(status: int, body: bytes, content_type: str = "text/plain") -> ApiError:
        response = httpx.Response(status, content=body, headers={"content-type": content_type})
        return error_from_response(response)

    assert build(401, b'{"error":"invalid api key"}\n').message == "invalid api key"
    assert build(401, b'{"error":"invalid api key"}\n').body == {"error": "invalid api key"}
    assert build(400, b"null").message == "Bad Request"
    assert build(400, b"null").body is None
    assert build(400, b'"fail parse uuid"').message == "fail parse uuid"
    assert build(401, b"").message == "Unauthorized"
    assert build(401, b"").body is None
    assert build(404, b"404 page not found").message == "404 page not found"
    assert build(502, b"<html><h1>502</h1></html>", "text/html").message == "Bad Gateway"
    assert build(502, b"<html><h1>502</h1></html>").body.startswith("<html>")
    assert build(503, b'{"message":"busy"}').message == "busy"
    assert build(500, b'{"other":1}').message == "Internal Server Error"
    assert build(500, b"[1,2]").body == [1, 2]
    assert build(500, b"\xff\xfe garbage").message is not None
    assert build(599, b"").message == "Unexpected response"
    unknown = build(418, b"teapot")
    assert type(unknown) is ApiError
    assert unknown.message == "teapot"


def test_rate_limit_error_carries_retry_after() -> None:
    response = httpx.Response(
        429, json={"error": "too many requests"}, headers={"Retry-After": "3"}
    )
    error = error_from_response(response)
    assert isinstance(error, RateLimitError)
    assert error.retry_after == 3.0
    assert error_from_response(httpx.Response(429)).retry_after is None


def test_parse_retry_after_formats() -> None:
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after(" 2.5 ") == 2.5
    for malformed in ("-5", "-0", "+5", "1e3", "5_0", "0x10", "\u0665"):
        assert parse_retry_after(malformed) is None, malformed
    assert parse_retry_after("nan") is None
    assert parse_retry_after("soon") is None
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    seconds = parse_retry_after(format_datetime(future, usegmt=True))
    assert seconds is not None
    assert 25 <= seconds <= 31
    naive = format_datetime(future.replace(tzinfo=None))
    assert parse_retry_after(naive) is not None
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    assert parse_retry_after(format_datetime(past, usegmt=True)) == 0.0


def test_backoff_delay_has_jitter_and_cap() -> None:
    assert backoff_delay(0, lambda: 0.0) == 0.25
    assert backoff_delay(0, lambda: 1.0) == 0.5
    assert backoff_delay(1, lambda: 1.0) == 1.0
    assert backoff_delay(3, lambda: 1.0) == 4.0
    assert backoff_delay(10, lambda: 1.0) == 8.0
    assert backoff_delay(10, lambda: 0.0) == 4.0


def test_retries_use_backoff_then_raise(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=lambda request: httpx.Response(503))
    client = ShieldLabs(api_key=API_KEY, max_retries=3)
    fake_time.install(client._transport)
    with pytest.raises(ServerError):
        client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 4
    assert fake_time.sleeps == [0.5, 1.0, 2.0]


def test_rate_limit_without_retry_after_waits_at_least_one_second(
    mock: Any, fake_time: FakeTime
) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=lambda request: httpx.Response(429))
    client = ShieldLabs(api_key=API_KEY, max_retries=3)
    fake_time.install(client._transport)
    with pytest.raises(RateLimitError):
        client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 4
    assert fake_time.sleeps == [1.0, 1.0, 2.0]  # backoff 0.5, 1, 2 with a 1 s floor


def test_retry_after_is_honoured_and_capped(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "3"}),
            httpx.Response(503, headers={"Retry-After": "120"}),
            httpx.Response(200, json={"data": [], "total": 0}),
        ]
    )
    client = ShieldLabs(api_key=API_KEY, max_retries=2)
    fake_time.install(client._transport)
    page = client.history.search("request_id", REQUEST_ID)
    assert page.total == 0
    assert route.call_count == 3
    assert fake_time.sleeps == [3.0, 10.0]


def test_retry_after_is_followed_as_sent_even_below_one_second(
    mock: Any, fake_time: FakeTime
) -> None:
    # Only the wait of identifications.get raises the delay after a 429 to at least 1 s.
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(429, headers={"Retry-After": "0.5"}),
            httpx.Response(200, json={"data": [], "total": 0}),
        ]
    )
    client = ShieldLabs(api_key=API_KEY, max_retries=2)
    fake_time.install(client._transport)
    assert client.history.search("request_id", REQUEST_ID).total == 0
    assert route.call_count == 3
    assert fake_time.sleeps == [0.0, 0.5]


@pytest.mark.parametrize("status", [400, 401, 402, 403, 404])
def test_client_errors_are_never_retried(mock: Any, fake_time: FakeTime, status: int) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=lambda request: httpx.Response(status))
    client = ShieldLabs(api_key=API_KEY, max_retries=5)
    fake_time.install(client._transport)
    with pytest.raises(ApiError):
        client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 1
    assert fake_time.sleeps == []


def test_connection_errors_are_retried(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[httpx.ConnectError("refused"), httpx.Response(200, json={"data": []})]
    )
    client = ShieldLabs(api_key=API_KEY)
    fake_time.install(client._transport)
    assert client.history.search("request_id", REQUEST_ID).total == 0
    assert route.call_count == 2
    assert fake_time.sleeps == [0.5]


def test_connection_error_after_retries(mock: Any, fake_time: FakeTime) -> None:
    mock.get(host=HISTORY_HOST).mock(side_effect=httpx.ConnectError("refused"))
    client = ShieldLabs(api_key=API_KEY, max_retries=1)
    fake_time.install(client._transport)
    with pytest.raises(APIConnectionError, match="refused") as caught:
        client.history.search("request_id", REQUEST_ID)
    assert isinstance(caught.value.__cause__, httpx.ConnectError)
    assert API_KEY not in str(caught.value)


def test_timeouts_are_retried_then_raised(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=httpx.ReadTimeout("slow"))
    client = ShieldLabs(api_key=API_KEY, timeout=2.5, max_retries=2)
    fake_time.install(client._transport)
    with pytest.raises(APITimeoutError, match=r"2\.5 s"):
        client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 3
    assert fake_time.sleeps == [0.5, 1.0]


def test_max_retries_zero(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST).mock(side_effect=lambda request: httpx.Response(500))
    client = ShieldLabs(api_key=API_KEY, max_retries=0)
    fake_time.install(client._transport)
    with pytest.raises(ServerError):
        client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 1


def test_timeout_is_passed_to_each_attempt(mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json={"data": [], "total": 0})
    ShieldLabs(api_key=API_KEY, timeout=4).history.search("request_id", REQUEST_ID)
    assert route.calls.last.request.extensions["timeout"]["read"] == 4.0
