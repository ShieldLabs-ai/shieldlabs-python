"""History API client: requests, validation, iteration and configuration."""

from __future__ import annotations

import copy
import string
import warnings
from typing import Any
from uuid import UUID

import httpx
import pytest
import respx

from _support import (
    API_KEY,
    HISTORY_HOST,
    REQUEST_ID,
    REQUEST_PATH,
    history_body,
    load_json,
    row,
    uuid_for,
)
from shieldlabs import (
    ApiError,
    HistoryPage,
    Identification,
    ShieldLabs,
    ShieldLabsWarning,
    ValidationError,
)
from shieldlabs._http import USER_AGENT

DEVICE_ID = "D8E0F2A4-B6C8-4D0E-BF2A-4B6C8D0E2F4A"


@pytest.fixture
def client() -> ShieldLabs:
    return ShieldLabs(api_key=API_KEY)


@pytest.fixture
def mock() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield router


def test_search_sends_expected_request(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST, path=REQUEST_PATH).respond(
        200, json=load_json("history-page.json")
    )
    page = client.history.search("request_id", REQUEST_ID, limit=5, offset=10)

    assert isinstance(page, HistoryPage)
    assert page.total == 37
    assert [item.request_id for item in page.data][:2] == [
        REQUEST_ID,
        "7c1e2f4a-3b6d-4e8f-9a0b-1c2d3e4f5a6b",
    ]
    request = route.calls.last.request
    assert request.method == "GET"
    assert str(request.url) == f"https://{HISTORY_HOST}{REQUEST_PATH}?limit=5&offset=10"
    assert request.headers["authorization"] == f"Bearer {API_KEY}"
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"] == USER_AGENT
    assert USER_AGENT.startswith("shieldlabs-python/1.0.0 ")


def test_search_defaults_and_empty_page(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=load_json("history-empty.json"))
    page = client.history.search("user_hid", "anonymous")
    assert page == HistoryPage(data=(), total=0)
    assert route.calls.last.request.url.params["limit"] == "20"
    assert route.calls.last.request.url.params["offset"] == "0"


def test_uuid_values_are_sent_lowercase(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    client.history.search("device_id", DEVICE_ID)
    client.history.search("visitor_id", UUID("e9f1a3b5-c7d9-4e1f-8a3b-5c7d9e1f3a5b"))
    paths = [call.request.url.path for call in route.calls]
    assert paths == [
        f"/api/v1/history/device_id/{DEVICE_ID.lower()}",
        "/api/v1/history/visitor_id/e9f1a3b5-c7d9-4e1f-8a3b-5c7d9e1f3a5b",
    ]


@pytest.mark.parametrize(
    ("user_hid", "segment"),
    [
        # The History API matches only this canonical escaping: letters, digits, "-._~" and
        # "$&+,:;=@" as they are, everything else percent-encoded with uppercase hex.
        ("anonymous", "anonymous"),
        ("a@b", "a@b"),
        ("a+b", "a+b"),
        ("a:b=c", "a:b=c"),
        ("x$y&z", "x$y&z"),
        ("a,b", "a,b"),
        ("a;b", "a;b"),
        ("-._~", "-._~"),
        ("...", "..."),
        (".hidden", ".hidden"),
        ("a b", "a%20b"),
        ("ü", "%C3%BC"),
        ("a%2Fb", "a%252Fb"),
        ("a!b c", "a%21b%20c"),
        ("it's (1)*", "it%27s%20%281%29%2A"),
        ("Team A?c#d%e é", "Team%20A%3Fc%23d%25e%20%C3%A9"),
        ('"<>[]^`{|}\\', "%22%3C%3E%5B%5D%5E%60%7B%7C%7D%5C"),
        ("line\nbreak", "line%0Abreak"),
        ("\u00a0", "%C2%A0"),
        ("日本", "%E6%97%A5%E6%9C%AC"),
        ("\U0001f600", "%F0%9F%98%80"),
    ],
)
def test_user_hid_uses_the_escaping_the_history_api_matches(
    client: ShieldLabs, mock: Any, user_hid: str, segment: str
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    client.history.search("user_hid", user_hid)
    raw_path = route.calls.last.request.url.raw_path.decode("ascii")
    assert raw_path == f"/api/v1/history/user_hid/{segment}?limit=20&offset=0"


_KEPT_IN_PATH = frozenset(string.ascii_letters + string.digits + "-._~" + "$&+,:;=@")


def test_every_ascii_character_uses_the_canonical_path_escaping(
    client: ShieldLabs, mock: Any
) -> None:
    # Canonical form: letters, digits, "-._~" and "$&+,:;=@" as they are, every other byte as
    # %XX with uppercase hex. "/" is refused (see below), so it is not part of this check.
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    mismatches = {}
    for code in range(128):
        char = chr(code)
        if char == "/":
            continue
        client.history.search("user_hid", f"a{char}z")
        raw_path = route.calls.last.request.url.raw_path.decode("ascii")
        segment = raw_path.split("?", 1)[0].rsplit("/", 1)[1]
        expected = "a" + (char if char in _KEPT_IN_PATH else f"%{code:02X}") + "z"
        if segment != expected:
            mismatches[char] = segment
    assert mismatches == {}
    assert route.call_count == 127


@pytest.mark.parametrize(
    ("user_hid", "message"),
    [
        (".", "cannot be searched"),
        ("..", "cannot be searched"),
        ("a/b", "contain '/'"),
        ("/", "contain '/'"),
        ("acct/", "contain '/'"),
        ("../anonymous", "contain '/'"),
        ("\ud800", "unpaired surrogate"),
    ],
)
def test_user_hids_the_history_api_cannot_search_send_nothing(
    client: ShieldLabs, mock: Any, user_hid: str, message: str
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    with pytest.raises(ValidationError, match=message):
        client.history.search("user_hid", user_hid)
    with pytest.raises(ValidationError, match=message):
        client.history.iter("user_hid", user_hid)
    assert route.call_count == 0


def test_ip_lookup(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    client.history.search("ip", "203.0.113.24")
    assert route.calls.last.request.url.path == "/api/v1/history/ip/203.0.113.24"


@pytest.mark.parametrize(
    ("lookup_type", "value", "message"),
    [
        ("email", "user@example.com", "type must be one of"),
        ("auto", "anonymous", "type must be one of"),
        ("REQUEST_ID", REQUEST_ID, "type must be one of"),
        ("request_id", "not-a-uuid", "must be a UUID"),
        ("request_id", REQUEST_ID + " ", "must be a UUID"),
        ("device_id", "d8e0f2a4b6c84d0ebf2a4b6c8d0e2f4a", "must be a UUID"),
        ("session_id", "{b6c8d0e2-f4a6-4b8c-8d0e-2f4a6b8c0d2e}", "must be a UUID"),
        ("cookie_id", "", "must be a UUID"),
        ("ip", "2001:db8::1", "IPv6"),
        ("ip", "203.0.113", "dotted IPv4"),
        ("ip", "203.0.113.256", "dotted IPv4"),
        ("ip", "203.0.113.07", "dotted IPv4"),
        ("ip", "203.0.113.7\n", "dotted IPv4"),
        ("user_hid", "", "non-empty"),
        ("user_hid", 12345, "must be a string"),
        ("request_id", None, "must be a string"),
    ],
)
def test_validation_errors_send_nothing(
    client: ShieldLabs, mock: Any, lookup_type: Any, value: Any, message: str
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    with pytest.raises(ValidationError, match=message):
        client.history.search(lookup_type, value)
    assert route.call_count == 0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"limit": 0}, "between 1 and 100"),
        ({"limit": 101}, "between 1 and 100"),
        ({"limit": 20.0}, "must be an integer"),
        ({"limit": True}, "must be an integer"),
        ({"offset": -1}, "0 or greater"),
        ({"offset": "10"}, "must be an integer"),
    ],
)
def test_limit_and_offset_validation(
    client: ShieldLabs, mock: Any, kwargs: dict[str, Any], message: str
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    with pytest.raises(ValidationError, match=message):
        client.history.search("request_id", REQUEST_ID, **kwargs)
    assert route.call_count == 0


def test_limit_boundaries_are_accepted(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    client.history.search("request_id", REQUEST_ID, limit=1)
    client.history.search("request_id", REQUEST_ID, limit=100, offset=5000)
    assert [c.request.url.params["limit"] for c in route.calls] == ["1", "100"]


def test_validation_error_is_also_value_error(client: ShieldLabs) -> None:
    with pytest.raises(ValueError):
        client.history.search("request_id", "nope")


# --- iteration ---------------------------------------------------------------------------


def test_iter_dedupes_on_request_id_and_stops_at_total(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(200, json=history_body(row(uuid_for(1)), row(uuid_for(2)), total=5)),
            httpx.Response(200, json=history_body(row(uuid_for(2)), row(uuid_for(3)), total=5)),
            httpx.Response(200, json=history_body(row(uuid_for(4)), total=5)),
        ]
    )
    items = list(client.history.iter("user_hid", "acct-1", page_size=2))
    assert [item.request_id for item in items] == [uuid_for(i) for i in (1, 2, 3, 4)]
    offsets = [call.request.url.params["offset"] for call in route.calls]
    limits = {call.request.url.params["limit"] for call in route.calls}
    assert offsets == ["0", "2", "4"]
    assert limits == {"2"}


def test_iter_stops_at_empty_page(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(200, json=history_body(row(uuid_for(1)), total=100)),
            httpx.Response(200, json=history_body(total=100)),
        ]
    )
    items = list(client.history.iter("device_id", DEVICE_ID, page_size=1))
    assert len(items) == 1
    assert route.call_count == 2


def test_iter_respects_max_items(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(200, json=history_body(*(row(uuid_for(i)) for i in range(3)), total=10)),
            httpx.Response(
                200, json=history_body(*(row(uuid_for(i)) for i in range(3, 6)), total=10)
            ),
        ]
    )
    items = list(client.history.iter("ip", "203.0.113.24", page_size=3, max_items=4))
    assert [item.request_id for item in items] == [uuid_for(i) for i in range(4)]
    assert route.call_count == 2


def test_iter_max_items_zero_sends_nothing(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    assert list(client.history.iter("ip", "203.0.113.24", max_items=0)) == []
    assert route.call_count == 0


def test_iter_default_page_size_and_single_page(client: ShieldLabs, mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=load_json("history-page.json"))
    items = list(client.history.iter("user_hid", "acct-1", max_items=5))
    assert len(items) == 5
    assert route.calls.last.request.url.params["limit"] == "100"
    assert all(isinstance(item, Identification) for item in items)


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        (("user_hid", ""), {}),
        (("email", "x"), {}),
        (("ip", "2001:db8::1"), {}),
        (("user_hid", "a"), {"page_size": 0}),
        (("user_hid", "a"), {"page_size": 101}),
        (("user_hid", "a"), {"max_items": -1}),
    ],
)
def test_iter_validates_eagerly(
    client: ShieldLabs, mock: Any, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    with pytest.raises(ValidationError):
        client.history.iter(*args, **kwargs)
    assert route.call_count == 0


# --- configuration ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base_url",
    [
        "https://account.shieldlabs.ai/api",
        "https://account.shieldlabs.ai/api/",
        "https://account.shieldlabs.ai/",
        "  https://account.shieldlabs.ai  ",
    ],
)
def test_api_suffix_is_stripped(mock: Any, base_url: str) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    client = ShieldLabs(api_key=API_KEY, base_url=base_url)
    assert client.base_url == "https://account.shieldlabs.ai"
    client.history.search("request_id", REQUEST_ID)
    assert route.calls.last.request.url.path == REQUEST_PATH


def test_custom_base_url_with_prefix_and_dev_host(mock: Any) -> None:
    route = mock.get(host="dev.account.shieldlabs.ai").respond(200, json=history_body())
    client = ShieldLabs(api_key=API_KEY, base_url="https://dev.account.shieldlabs.ai")
    client.history.search("request_id", REQUEST_ID)
    assert route.call_count == 1
    proxied = ShieldLabs(api_key=API_KEY, base_url="http://localhost:8080/shield/api")
    assert proxied.base_url == "http://localhost:8080/shield"


@pytest.mark.parametrize(
    "base_url",
    ["account.shieldlabs.ai", "ftp://x", "", "https://", "http://:8080", "https://[::1"],
)
def test_invalid_base_url(base_url: str) -> None:
    with pytest.raises(ValidationError, match="must be an http"):
        ShieldLabs(api_key=API_KEY, base_url=base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://account.shieldlabs.ai",
        "HTTP://account.shieldlabs.ai/api",
        "http://10.0.0.5:8080",
        "http://localhost.example.com",
        "http://0.0.0.0:8080",
        "http://user:secret@shieldlabs.example",
    ],
)
def test_plain_http_is_refused_for_remote_hosts(base_url: str) -> None:
    with pytest.raises(ValidationError, match="must use https") as caught:
        ShieldLabs(api_key=API_KEY, base_url=base_url)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    ("base_url", "origin"),
    [
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://LOCALHOST:3000/api", "http://LOCALHOST:3000"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://127.0.0.2", "http://127.0.0.2"),
        ("http://[::1]:8080/", "http://[::1]:8080"),
        ("https://203.0.113.10:8443", "https://203.0.113.10:8443"),
    ],
)
def test_plain_http_is_accepted_for_loopback_hosts(base_url: str, origin: str) -> None:
    assert ShieldLabs(api_key=API_KEY, base_url=base_url).base_url == origin


def test_plain_http_from_the_environment_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIELDLABS_API_BASE_URL", "http://account.shieldlabs.ai")
    with pytest.raises(ValidationError, match="must use https"):
        ShieldLabs(api_key=API_KEY)


def test_env_fallbacks(monkeypatch: pytest.MonkeyPatch, mock: Any) -> None:
    monkeypatch.setenv("SHIELDLABS_API_KEY", API_KEY)
    monkeypatch.setenv("SHIELDLABS_API_BASE_URL", "https://dev.account.shieldlabs.ai/api")
    route = mock.get(host="dev.account.shieldlabs.ai").respond(200, json=history_body())
    client = ShieldLabs()
    assert client.base_url == "https://dev.account.shieldlabs.ai"
    client.history.search("request_id", REQUEST_ID)
    assert route.calls.last.request.headers["authorization"] == f"Bearer {API_KEY}"


@pytest.mark.parametrize("api_key", [None, "", "   "])
def test_missing_api_key(api_key: Any) -> None:
    with pytest.raises(ValidationError, match="SHIELDLABS_API_KEY"):
        ShieldLabs(api_key=api_key)


def test_non_string_api_key() -> None:
    with pytest.raises(ValidationError, match="api_key must be a string"):
        ShieldLabs(api_key=12345)  # type: ignore[arg-type]


def test_unusual_api_key_warns_without_leaking_it() -> None:
    with pytest.warns(ShieldLabsWarning, match="Private API Key") as record:
        ShieldLabs(api_key="0123456789abcdef0123456789abcdef")
    assert "0123456789abcdef" not in str(record[0].message)
    assert record[0].filename == __file__


def test_valid_api_key_does_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        ShieldLabs(api_key=f"  {API_KEY}\n")


def test_repr_never_contains_the_key(client: ShieldLabs) -> None:
    assert API_KEY not in repr(client)
    assert repr(client) == "ShieldLabs(base_url='https://account.shieldlabs.ai')"


@pytest.mark.parametrize(
    "kwargs",
    [{"timeout": 0}, {"timeout": -1}, {"timeout": "10"}, {"max_retries": -1}, {"max_retries": 1.5}],
)
def test_invalid_options(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ShieldLabs(api_key=API_KEY, **kwargs)


def test_context_manager_closes_owned_client() -> None:
    with ShieldLabs(api_key=API_KEY) as client:
        inner = client._transport.client
        assert not inner.is_closed
    assert inner.is_closed


def test_injected_http_client_is_used_and_left_open(mock: Any) -> None:
    route = mock.get(host=HISTORY_HOST).respond(200, json=history_body())
    http_client = httpx.Client(headers={"X-Trace": "1"})
    with ShieldLabs(api_key=API_KEY, http_client=http_client) as client:
        client.history.search("request_id", REQUEST_ID)
    assert not http_client.is_closed
    assert route.calls.last.request.headers["x-trace"] == "1"
    assert route.calls.last.request.headers["authorization"] == f"Bearer {API_KEY}"
    http_client.close()


def test_malformed_success_bodies_raise_api_error(client: ShieldLabs, mock: Any) -> None:
    mock.get(host=HISTORY_HOST).mock(
        side_effect=[
            httpx.Response(200, text="<html>maintenance</html>"),
            httpx.Response(200, json=[1, 2, 3]),
        ]
    )
    with pytest.raises(ApiError, match="not valid JSON") as first:
        client.history.search("request_id", REQUEST_ID)
    assert first.value.status == 200
    with pytest.raises(ApiError, match="not a JSON object"):
        client.history.search("request_id", REQUEST_ID)


def test_errors_survive_deepcopy(client: ShieldLabs, mock: Any) -> None:
    mock.get(host=HISTORY_HOST).respond(
        401, text='{"error":"invalid api key"}\n', headers={"content-type": "text/plain"}
    )
    with pytest.raises(ApiError) as caught:
        client.history.search("request_id", REQUEST_ID)
    restored = copy.deepcopy(caught.value)
    assert type(restored) is type(caught.value)
    assert restored.status == 401
    assert restored.message == "invalid api key"
    assert restored.headers["content-type"] == "text/plain"
    assert str(restored) == "invalid api key (HTTP 401)"


@pytest.mark.parametrize("api_key", ["sec_abc def", "sec_abc\x00def", "sec_été"])
def test_api_key_must_be_header_safe_and_is_never_echoed(api_key: str) -> None:
    with pytest.raises(ValidationError, match="HTTP header") as caught:
        ShieldLabs(api_key=api_key)
    assert api_key not in str(caught.value)


def test_non_string_base_url() -> None:
    with pytest.raises(ValidationError, match="base_url must be a string"):
        ShieldLabs(api_key=API_KEY, base_url=8080)  # type: ignore[arg-type]
