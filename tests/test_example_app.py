"""Smoke test of examples/fastapi_app.py. Skipped unless FastAPI is installed.

Run it with:
    pip install -e ".[dev]" -r examples/requirements.txt
    pytest tests/test_example_app.py
"""

from __future__ import annotations

import importlib.util
import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
import respx

from _support import API_KEY, HISTORY_HOST, FakeTime, load_json, sign

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "fastapi_app.py"
SECRET = "whsec_your_signing_secret"
REQUEST_ID = "3f2b8c1e-9d4a-4e6b-8a7c-2d1e0f9b6a53"


def _now_history_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000")


def _row(**changes: Any) -> dict[str, Any]:
    row = dict(load_json("history-page.json")["data"][1])  # trusted, anonymous
    row.update(request_id=REQUEST_ID, created_at=_now_history_time())
    row.update(changes)
    return row


def _load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("shieldlabs_fastapi_example", EXAMPLE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def app_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, Any]]:
    monkeypatch.setenv("SHIELDLABS_API_KEY", API_KEY)
    # Two secrets while one is rotated; the space after the comma must not break verification.
    monkeypatch.setenv("SHIELDLABS_WEBHOOK_SECRET", f"whsec_previous, {SECRET} ,")
    module = _load_example()
    with respx.mock(assert_all_called=False) as router, TestClient(module.app) as client:
        FakeTime().install(module.app.state.shieldlabs._transport)
        yield client, router


def _signup(client: TestClient, request_id: str = REQUEST_ID) -> httpx.Response:
    return client.post("/signup", json={"email": "user@example.com", "requestId": request_id})


def test_trusted_signup_is_created_once(app_client: tuple[TestClient, Any]) -> None:
    client, router = app_client
    router.get(host=HISTORY_HOST).respond(200, json={"data": [_row()], "total": 1})
    assert _signup(client).status_code == 201
    replay = _signup(client)
    assert replay.status_code == 403
    assert replay.json()["reason"] == "replayed"


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"score": 80}, "blocked_band"),
        ({"is_browser_automation": True}, "blocked_flag"),
        ({"score": 999}, "rate_limited"),
        ({"created_at": "2026-01-01 00:00:00.000"}, "stale"),
        ({"device_id": "00000000-0000-0000-0000-000000000000"}, "no_device_signals"),
    ],
)
def test_policy_refusals(
    app_client: tuple[TestClient, Any], changes: dict[str, Any], reason: str
) -> None:
    client, router = app_client
    router.get(host=HISTORY_HOST).respond(200, json={"data": [_row(**changes)], "total": 1})
    response = _signup(client)
    assert response.status_code == 403
    assert response.json() == {"error": "signup_refused", "reason": reason}


def test_missing_identification_is_refused(app_client: tuple[TestClient, Any]) -> None:
    client, router = app_client
    router.get(host=HISTORY_HOST).respond(200, json={"data": [], "total": 0})
    response = _signup(client)
    assert response.status_code == 403
    assert response.json()["reason"] == "missing"


def test_invalid_request_id_and_unavailable_api(app_client: tuple[TestClient, Any]) -> None:
    client, router = app_client
    assert _signup(client, "not-a-uuid").status_code == 400
    router.get(host=HISTORY_HOST).respond(401, text='{"error":"invalid api key"}\n')
    assert _signup(client).status_code == 503


def _deliver(client: TestClient, body: bytes, secret: Any = SECRET) -> int:
    headers = {"X-Shield-Signature": sign(secret, body)} if secret else {}
    return client.post("/webhooks/shieldlabs", content=body, headers=headers).status_code


def test_webhook_receiver(app_client: tuple[TestClient, Any]) -> None:
    client, _ = app_client
    data = Path(__file__).parent / "data"
    scored = (data / "webhook-identification-scored.raw.txt").read_bytes()
    ping = (data / "webhook-ping.raw.txt").read_bytes()
    other = json.dumps({"event_type": "other", "schema_version": "2026-06-01"}).encode()

    assert _deliver(client, scored) == 200
    assert _deliver(client, scored) == 200  # a repeated delivery is acknowledged once more
    assert _deliver(client, scored, secret="whsec_wrong") == 401
    assert _deliver(client, scored, secret=None) == 401
    assert _deliver(client, ping) == 200
    assert _deliver(client, other) == 200
    assert _deliver(client, b"not json") == 400
