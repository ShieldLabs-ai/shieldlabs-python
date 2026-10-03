"""Exercise an installed wheel through mocked HTTP and signed synthetic webhooks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path

import httpx

import shieldlabs
from shieldlabs import (
    AsyncShieldLabs,
    IdentificationScoredEvent,
    ShieldLabs,
    ShieldLabsManagement,
    webhooks,
)


def main() -> None:
    if "site-packages" not in Path(shieldlabs.__file__).parts:
        raise RuntimeError("Run this smoke test with the installed wheel, not an editable checkout")

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/profile":
            assert request.headers["X-Shield-Domain"] == "example.com"
            return httpx.Response(200, json={"Domain": "example.com", "Weight": -9, "future": 1})
        assert request.url.path == "/api/v1/history/user_hid/anonymous"
        assert request.url.params == httpx.QueryParams({"limit": 1, "offset": 0})
        return httpx.Response(
            200,
            json={
                "total": 2,
                "data": [
                    {
                        "request_id": "02f1d973-84db-4156-a7f7-e799e6bf389b",
                        "score": 999,
                        "connection_type": "future_network",
                        "is_vpn": True,
                        "unknown": [1, 2],
                    }
                ],
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handle)) as http:
        with ShieldLabs(api_key="sec_aaaaaaaa-bbbbbbbb-cccccccc", http_client=http) as client:
            page = client.history.search("user_hid", "anonymous", limit=1)
            assert page.total == 2
            assert page.data[0].risk_score == 999
            assert page.data[0].is_rate_limited
            assert page.data[0].detection_flags.vpn
            assert page.data[0].connection_type == "future_network"
            assert page.data[0].raw["unknown"] == [1, 2]
        with ShieldLabsManagement(
            secret_key="fixture-secret", domain="example.com", http_client=http
        ) as management:
            profile = management.get_profile()
            assert profile.remaining_identifications == -9
            assert profile.raw["future"] == 1

    async def check_async() -> None:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        client = AsyncShieldLabs(api_key="sec_aaaaaaaa-bbbbbbbb-cccccccc", http_client=http)
        async with http, client:
            page = await client.history.search("user_hid", "anonymous", limit=1)
            assert page.total == 2
            assert page.data[0].risk_score == 999

    asyncio.run(check_async())
    payload = json.dumps(
        {
            "event_type": "identification.scored",
            "schema_version": "2026-06-01",
            "data": {
                "risk_score": 999,
                "detection_flags": {"vpn": True},
                "future": True,
                "signals": [{"name": "future", "weight": -30}, {"name": "future", "weight": -30}],
            },
        }
    ).encode()
    secret = "fixture-only"
    signature = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    event = webhooks.construct_event(payload, signature, secret)
    assert isinstance(event, IdentificationScoredEvent)
    assert event.data.risk_score == 999
    assert event.data.detection_flags.vpn
    assert [s.weight for s in event.data.signals] == [-30, -30]
    assert event.data.raw["future"] is True
    print("Installed wheel: sync/async History, profile, signed webhook passed")


if __name__ == "__main__":
    main()
