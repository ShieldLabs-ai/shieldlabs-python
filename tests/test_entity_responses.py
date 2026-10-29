from copy import deepcopy

import httpx
import pytest

from shieldlabs import ApiError, AsyncShieldLabs, EntityPage, ShieldLabs

DOMAIN = "11111111-1111-4111-8111-111111111111"
ID = "33333333-3333-4333-8333-333333333333"
KEY = "sec_abcd1234-efgh5678-ijkl9012"
CARD = {
    "type": "identification",
    "id": ID,
    "domain_id": DOMAIN,
    "domain": "example.com",
    "created_at": "2026-10-29T09:00:00.123Z",
    "risk": {"state": "ok", "band": "suspicious", "score": 30},
    "signals": {"state": "unavailable", "items": []},
    "public_ip": "203.0.113.24",
    "local_ip": "198.51.100.1",
    "local_country": "Germany",
    "traffic": {"channel": "paid", "entry_url": "https://example.com/", "utm_source": "google"},
}


@pytest.mark.parametrize("score", [0, 30, 60, 100])
def test_get_reads_one_entity_card(score: int) -> None:
    card = deepcopy(CARD)
    card["risk"]["score"] = score
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"data": card}))
    ) as http:
        sdk = ShieldLabs(KEY, domain_id=DOMAIN, http_client=http, max_retries=0)
        result = sdk.identifications.get(ID, wait=False)
    assert result is not None
    assert result.identification_id == ID
    assert result.risk_score == score
    assert result.observed_at is not None
    assert result.observed_at.isoformat() == "2026-10-29T09:00:00.123000+00:00"
    assert result.public_ip.ip == "203.0.113.24"
    assert result.traffic_source.utm_source == "google"
    assert result.raw == card
    assert result.signals == ()


def test_lists_keep_unknown_scores_aggregate_fields_and_cursor() -> None:
    card = {
        **CARD,
        "type": "user",
        "id": "a+b% c",
        "risk": {"state": "unavailable", "band": None},
        "related_counts": None,
        "identifications": 5,
    }
    calls: list[httpx.Request] = []

    def reply(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"data": [card], "next_page_token": "opaque+/="})

    with httpx.Client(transport=httpx.MockTransport(reply)) as http:
        sdk = ShieldLabs(KEY, domain_id=DOMAIN, http_client=http)
        first = sdk.history.list("user", ids=["a+b% c"])
        second = sdk.history.list("user", ids=["a+b% c"], page_token=first.next_page_token)
    assert isinstance(first, EntityPage)
    assert first.data[0] == card
    assert "score" not in first.data[0]["risk"]
    assert not hasattr(first, "total")
    assert second.next_page_token == "opaque+/="
    assert calls[1].url.params["page_token"] == "opaque+/="
    assert calls[1].url.params["ids"] == "a+b% c"


def test_compatibility_get_does_not_turn_unavailable_risk_into_zero() -> None:
    card = {**CARD, "risk": {"state": "unavailable", "band": None}}
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"data": card}))
    ) as http:
        sdk = ShieldLabs(KEY, domain_id=DOMAIN, http_client=http)
        with pytest.raises(ApiError, match="unavailable"):
            sdk.identifications.get(ID, wait=False)


@pytest.mark.anyio
async def test_async_card_and_page_share_the_current_response_contract() -> None:
    def reply(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(ID):
            return httpx.Response(200, json={"data": CARD})
        return httpx.Response(200, json={"data": [CARD], "next_page_token": "next"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as http:
        sdk = AsyncShieldLabs(KEY, domain_id=DOMAIN, http_client=http)
        result = await sdk.identifications.get(ID, wait=False)
        page = await sdk.history.list("identifications")
    assert result is not None
    assert result.identification_id == ID
    assert result.risk_score == 30
    assert page.data[0] == CARD
    assert page.next_page_token == "next"


@pytest.mark.parametrize("body", [{"data": {}}, {"data": [{}]}, {"data": [], "next_page_token": 1}])
def test_rejects_invalid_entity_pages(body: dict) -> None:
    with pytest.raises(ApiError):
        EntityPage.from_dict(body)
