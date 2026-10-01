"""Management API client: profile, headers, domain normalization and the no-retry-on-429 rule."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
import respx

from _support import DOMAIN, MANAGEMENT_HOST, SECRET_KEY, FakeTime, load_json
from shieldlabs import (
    DomainProfile,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    ShieldLabsManagement,
    ValidationError,
)
from shieldlabs._http import USER_AGENT
from shieldlabs._validation import normalize_domain


@pytest.fixture
def mock() -> Any:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def management(fake_time: FakeTime) -> ShieldLabsManagement:
    client = ShieldLabsManagement(secret_key=SECRET_KEY, domain="https://www.Example.com/")
    fake_time.install(client._transport)
    return client


def test_get_profile_matches_expected_fixture(management: ShieldLabsManagement, mock: Any) -> None:
    route = mock.get(host=MANAGEMENT_HOST, path="/v1/profile").respond(
        200, json=load_json("management-profile.json")
    )
    profile = management.get_profile()

    assert isinstance(profile, DomainProfile)
    assert profile.to_dict() == load_json("management-profile-expected.json")
    assert profile.created_at == datetime(2026, 1, 15, 9, 0, tzinfo=timezone.utc)
    assert profile.raw["Callback"] == ""
    assert not hasattr(profile, "callback")

    request = route.calls.last.request
    assert str(request.url) == "https://api.shieldlabs.ai/v1/profile"
    assert request.headers["x-shield-domain"] == DOMAIN
    assert request.headers["authorization"] == f"Bearer {SECRET_KEY}"
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"] == USER_AGENT


def test_negative_remaining_identifications(management: ShieldLabsManagement, mock: Any) -> None:
    body = dict(load_json("management-profile.json"), Weight=-120, CreatedAt="0001-01-01T00:00:00Z")
    mock.get(host=MANAGEMENT_HOST).respond(200, json=body)
    profile = management.get_profile()
    assert profile.remaining_identifications == -120
    assert profile.created_at == datetime(1, 1, 1, tzinfo=timezone.utc)
    assert profile.to_dict()["created_at"] == "0001-01-01T00:00:00.000Z"


def test_profile_tolerates_missing_fields() -> None:
    profile = DomainProfile.from_dict({"Domain": "example.com"})
    assert profile.remaining_identifications == 0
    assert profile.public_key_masked == ""
    assert profile.created_at is None


def test_rate_limit_is_never_retried(
    management: ShieldLabsManagement, mock: Any, fake_time: FakeTime
) -> None:
    route = mock.get(host=MANAGEMENT_HOST).respond(
        429, json={"error": "too many requests"}, headers={"Retry-After": "1"}
    )
    with pytest.raises(RateLimitError, match="too many requests"):
        management.get_profile()
    assert route.call_count == 1
    assert fake_time.sleeps == []


def test_rate_limit_not_retried_even_with_many_retries(mock: Any, fake_time: FakeTime) -> None:
    client = ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN, max_retries=10)
    fake_time.install(client._transport)
    route = mock.get(host=MANAGEMENT_HOST).respond(429, json={"error": "too many requests"})
    with pytest.raises(RateLimitError):
        client.get_profile()
    assert route.call_count == 1


def test_server_busy_is_retried(
    management: ShieldLabsManagement, mock: Any, fake_time: FakeTime
) -> None:
    route = mock.get(host=MANAGEMENT_HOST).mock(
        side_effect=[
            httpx.Response(503, json={"error": "server is busy"}),
            httpx.Response(200, json=load_json("management-profile.json")),
        ]
    )
    assert management.get_profile().domain == "example.com"
    assert route.call_count == 2
    assert fake_time.sleeps == [0.5]


def test_server_busy_exhausts_retries(
    management: ShieldLabsManagement, mock: Any, fake_time: FakeTime
) -> None:
    route = mock.get(host=MANAGEMENT_HOST).respond(503, json={"error": "server is busy"})
    with pytest.raises(ServerError, match="server is busy"):
        management.get_profile()
    assert route.call_count == 3


def test_quota_exceeded_class(management: ShieldLabsManagement, mock: Any) -> None:
    mock.get(host=MANAGEMENT_HOST).respond(402)
    with pytest.raises(QuotaExceededError):
        management.get_profile()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("https://www.example.com/", "example.com"),
        ("http://www.example.com/signup?x=1#top", "example.com"),
        ("www.example.com", "example.com"),
        ("//example.com/path", "example.com"),
        ("shop.example.com", "shop.example.com"),
        ("example.com:8443", "example.com:8443"),
        ("example.com?x", "example.com"),
        ("wwwexample.com", "wwwexample.com"),
    ],
)
def test_domain_normalization(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "https://", "www.", "/path"])
def test_empty_domain_is_rejected(raw: str) -> None:
    with pytest.raises(ValidationError, match="domain"):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=raw)


def test_non_string_domain() -> None:
    with pytest.raises(ValidationError, match="domain must be a string"):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=42)  # type: ignore[arg-type]


@pytest.mark.parametrize("secret", [None, "", "  "])
def test_secret_key_is_required(secret: Any) -> None:
    with pytest.raises(ValidationError, match="SHIELDLABS_SECRET_KEY"):
        ShieldLabsManagement(secret_key=secret, domain=DOMAIN)


def test_env_fallbacks(monkeypatch: pytest.MonkeyPatch, mock: Any) -> None:
    monkeypatch.setenv("SHIELDLABS_SECRET_KEY", SECRET_KEY)
    monkeypatch.setenv("SHIELDLABS_DOMAIN", "WWW.Example.com")
    monkeypatch.setenv("SHIELDLABS_MANAGEMENT_BASE_URL", "https://dev.api.shieldlabs.ai/")
    route = mock.get(host="dev.api.shieldlabs.ai", path="/v1/profile").respond(
        200, json=load_json("management-profile.json")
    )
    with ShieldLabsManagement() as client:
        assert client.domain == "example.com"
        assert client.base_url == "https://dev.api.shieldlabs.ai"
        client.get_profile()
    assert route.calls.last.request.headers["x-shield-domain"] == "example.com"


def test_repr_hides_the_secret(management: ShieldLabsManagement) -> None:
    assert SECRET_KEY not in repr(management)
    assert "example.com" in repr(management)


def test_context_manager_closes_owned_client() -> None:
    with ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN) as client:
        inner = client._transport.client
    assert inner.is_closed


def test_injected_client_is_not_closed() -> None:
    http_client = httpx.Client()
    client = ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN, http_client=http_client)
    client.close()
    assert not http_client.is_closed
    http_client.close()


def test_invalid_management_options() -> None:
    with pytest.raises(ValidationError):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN, timeout=0)
    with pytest.raises(ValidationError):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN, base_url="api.shieldlabs.ai")


def test_plain_http_base_url_only_for_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="must use https"):
        ShieldLabsManagement(
            secret_key=SECRET_KEY, domain=DOMAIN, base_url="http://api.shieldlabs.ai"
        )
    monkeypatch.setenv("SHIELDLABS_MANAGEMENT_BASE_URL", "http://dev.api.shieldlabs.ai")
    with pytest.raises(ValidationError, match="must use https"):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN)
    monkeypatch.setenv("SHIELDLABS_MANAGEMENT_BASE_URL", "http://127.0.0.1:9000/")
    local = ShieldLabsManagement(secret_key=SECRET_KEY, domain=DOMAIN)
    assert local.base_url == "http://127.0.0.1:9000"


def test_secret_key_must_be_header_safe() -> None:
    with pytest.raises(ValidationError, match="HTTP header") as caught:
        ShieldLabsManagement(secret_key="abc\ndef", domain=DOMAIN)
    assert "abc" not in str(caught.value)


@pytest.mark.parametrize(
    ("raw", "message"),
    [("пример.рф", "punycode"), ("exa mple.com", "HTTP header")],
)
def test_domain_must_be_header_safe(raw: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ShieldLabsManagement(secret_key=SECRET_KEY, domain=raw)
    assert normalize_domain("xn--e1afmkfd.xn--p1ai") == "xn--e1afmkfd.xn--p1ai"
