"""AsyncShieldLabs and AsyncShieldLabsManagement mirror the sync clients."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from _support import (
    API_KEY,
    DOMAIN,
    HISTORY_HOST,
    MANAGEMENT_HOST,
    REQUEST_ID,
    REQUEST_PATH,
    SECRET_KEY,
    FakeTime,
    empty_page,
    history_body,
    load_json,
    row,
    uuid_for,
)
from shieldlabs import (
    APIConnectionError,
    APITimeoutError,
    AsyncShieldLabs,
    AsyncShieldLabsManagement,
    HistoryPage,
    RateLimitError,
    ServerError,
    ValidationError,
)

pytestmark = pytest.mark.anyio


def _found() -> httpx.Response:
    page = load_json("history-page.json")
    return httpx.Response(200, json={"data": page["data"][:1], "total": 1})


@pytest.fixture
def mock() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def client(fake_time: FakeTime) -> AsyncShieldLabs:
    instance = AsyncShieldLabs(api_key=API_KEY)
    fake_time.install(instance._transport)
    return instance


async def test_search(client: AsyncShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST, path=REQUEST_PATH).respond(
        200, json=load_json("history-page.json")
    )
    page = await client.history.search("request_id", REQUEST_ID, limit=3)
    assert isinstance(page, HistoryPage)
    assert len(page.data) == 5
    assert route.calls.last.request.url.params["limit"] == "3"
    assert route.calls.last.request.headers["authorization"] == f"Bearer {API_KEY}"


async def test_search_validation_sends_nothing(client: AsyncShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    with pytest.raises(ValidationError):
        await client.history.search("user_hid", "")
    with pytest.raises(ValidationError):
        await client.history.search("request_id", REQUEST_ID, limit=101)
    with pytest.raises(ValidationError):
        client.history.iter("ip", "2001:db8::1")
    with pytest.raises(ValidationError):
        await client.identifications.get("nope")
    assert route.call_count == 0


async def test_iter_dedupes_and_stops(client: AsyncShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(200, json=history_body(row(uuid_for(1)), row(uuid_for(2)), total=4)),
            httpx.Response(200, json=history_body(row(uuid_for(2)), row(uuid_for(3)), total=4)),
        ]
    )
    items = [item async for item in client.history.iter("user_hid", "acct-1", page_size=2)]
    assert [item.request_id for item in items] == [uuid_for(1), uuid_for(2), uuid_for(3)]
    assert route.call_count == 2


async def test_iter_empty_page_and_max_items(client: AsyncShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST)
    route.side_effect = [httpx.Response(200, json=history_body(total=9))]
    assert [item async for item in client.history.iter("user_hid", "acct-1")] == []

    route.side_effect = [
        httpx.Response(200, json=history_body(*(row(uuid_for(i)) for i in range(5)), total=9))
    ]
    items = [item async for item in client.history.iter("user_hid", "acct-1", max_items=2)]
    assert len(items) == 2
    assert [item async for item in client.history.iter("user_hid", "a", max_items=0)] == []


# identifications.get waiting rules run against both clients in test_polling.py.


async def test_user_hid_escaping_and_unsearchable_values(
    client: AsyncShieldLabs, mock: Any
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    await client.history.search("user_hid", "a@b c!")
    raw_path = route.calls.last.request.url.raw_path.decode("ascii")
    assert raw_path == "/api/v1/history/user_hid/a@b%20c%21?limit=20&offset=0"
    await client.history.search("user_hid", "-._~$&+,:;=@ %?#'()*é")
    raw_path = route.calls.last.request.url.raw_path.decode("ascii")
    assert raw_path == (
        "/api/v1/history/user_hid/-._~$&+,:;=@%20%25%3F%23%27%28%29%2A%C3%A9?limit=20&offset=0"
    )
    for value in (".", "..", "a/b", "/"):
        with pytest.raises(ValidationError):
            await client.history.search("user_hid", value)
        with pytest.raises(ValidationError):
            client.history.iter("user_hid", value)
    assert route.call_count == 2


async def test_retries_and_errors(client: AsyncShieldLabs, mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=HISTORY_HOST)
    route.side_effect = [httpx.Response(500), httpx.Response(200, json=history_body())]
    assert (await client.history.search("request_id", REQUEST_ID)).total == 0
    assert fake_time.sleeps == [0.5]

    route.side_effect = httpx.ConnectError("refused")
    with pytest.raises(APIConnectionError):
        await client.history.search("request_id", REQUEST_ID)

    route.side_effect = httpx.ConnectTimeout("slow")
    with pytest.raises(APITimeoutError):
        await client.history.search("request_id", REQUEST_ID)

    route.side_effect = lambda request: httpx.Response(502, text="<html></html>")
    with pytest.raises(ServerError):
        await client.history.search("request_id", REQUEST_ID)


async def test_context_manager_and_injected_client(mock: Any) -> None:
    async with AsyncShieldLabs(api_key=API_KEY) as client:
        inner = client._transport.client
        assert repr(client) == "AsyncShieldLabs(base_url='https://account.shieldlabs.ai')"
    assert inner.is_closed

    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    http_client = httpx.AsyncClient()
    async with AsyncShieldLabs(api_key=API_KEY, http_client=http_client) as injected:
        await injected.history.search("request_id", REQUEST_ID)
    assert not http_client.is_closed
    assert route.call_count == 1
    await http_client.aclose()


async def test_async_management(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=MANAGEMENT_HOST, path="/v1/profile").respond(
        200, json=load_json("management-profile.json")
    )
    async with AsyncShieldLabsManagement(secret_key=SECRET_KEY, domain="www.example.com") as client:
        fake_time.install(client._transport)
        profile = await client.get_profile()
    assert profile.to_dict() == load_json("management-profile-expected.json")
    assert route.calls.last.request.headers["x-shield-domain"] == DOMAIN


async def test_async_management_never_retries_429(mock: Any, fake_time: FakeTime) -> None:
    route = mock.get(host=MANAGEMENT_HOST).respond(429, json={"error": "too many requests"})
    client = AsyncShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN, max_retries=5)
    fake_time.install(client._transport)
    with pytest.raises(RateLimitError):
        await client.get_profile()
    assert route.call_count == 1
    await client.aclose()


async def test_async_management_injected_client(mock: Any) -> None:
    http_client = httpx.AsyncClient()
    client = AsyncShieldLabsManagement(
        secret_key=SECRET_KEY, domain=DOMAIN, http_client=http_client
    )
    await client.aclose()
    assert not http_client.is_closed
    await http_client.aclose()


async def test_real_async_sleep_is_used_by_default(mock: Any) -> None:
    mock.get(host=HISTORY_HOST).mock(side_effect=[empty_page(), _found()])
    async with AsyncShieldLabs(api_key=API_KEY) as client:
        found = await client.identifications.get(REQUEST_ID, poll_interval=0.01)
    assert found is not None
