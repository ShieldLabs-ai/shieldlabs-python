"""Domain-scoped entity History: path, filters, and no include_total."""

from __future__ import annotations

import httpx
import pytest
import respx

from shieldlabs import ApiError, AsyncShieldLabs, ShieldLabs, ValidationError

DOMAIN = "00000000-0000-4000-8000-000000000031"
USER = {
    "type": "user",
    "id": "customer-42",
    "domain_id": DOMAIN,
    "domain": "example.com",
    "risk": {"state": "unavailable", "band": None, "as_of": None},
    "signals": {"state": "ok", "items": []},
}


@pytest.fixture
def client() -> ShieldLabs:
    return ShieldLabs(api_key="sec_abcd1234-efgh5678-ijkl9012")


@respx.mock
def test_list_omits_include_total(client: ShieldLabs) -> None:
    route = respx.get(url__regex=r".*/api/v1/domains/.*/history/user").mock(
        return_value=httpx.Response(200, json={"data": [USER], "next_page_token": None})
    )

    page = client.entities.list(
        DOMAIN,
        "user",
        filter={"identification": {"risk_bands": ["dangerous"], "hre_min_accounts": 3}},
    )

    assert page.next_page_token is None
    assert page.data[0]["id"] == "customer-42"
    request = route.calls.last.request
    assert request.url.path == f"/api/v1/domains/{DOMAIN}/history/user"
    assert "include_total" not in request.url.params
    assert request.url.params["limit"] == "20"
    assert "risk_bands" in request.url.params["filter"]


def test_include_total_is_rejected(client: ShieldLabs) -> None:
    with pytest.raises(ValidationError, match="include_total"):
        client.entities.list(DOMAIN, "user", include_total=True)  # type: ignore[call-arg]


@pytest.mark.anyio
@respx.mock
async def test_async_list_omits_include_total() -> None:
    respx.get(url__regex=r".*/history/user").mock(
        return_value=httpx.Response(200, json={"data": [USER], "next_page_token": "next"})
    )
    async with AsyncShieldLabs(api_key="sec_abcd1234-efgh5678-ijkl9012") as client:
        page = await client.entities.list(DOMAIN, "user", page_token="next")
    assert page.next_page_token == "next"


def test_visitor_list_is_rejected(client: ShieldLabs) -> None:
    with pytest.raises(ValidationError, match="identifications and user"):
        client.entities.list(DOMAIN, "visitor")


@respx.mock
def test_get_card(client: ShieldLabs) -> None:
    route = respx.get(url__regex=r".*/history/user/customer-42").mock(
        return_value=httpx.Response(200, json={"data": USER})
    )

    card = client.entities.get(DOMAIN, "user", "customer-42")

    assert card["id"] == "customer-42"
    assert route.calls.last.request.url.path.endswith("/history/user/customer-42")


@respx.mock
def test_malformed_risk_is_not_rewritten(client: ShieldLabs) -> None:
    broken = {**USER, "risk": {"state": "ok", "band": "dangerous"}}
    respx.get(url__regex=r".*/history/user(?:\?|$)").mock(
        return_value=httpx.Response(200, json={"data": [broken], "next_page_token": None})
    )

    with pytest.raises(ApiError, match="invalid entity"):
        client.entities.list(DOMAIN, "user")
