"""Shared test helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Union

import httpx

from shieldlabs._http import AsyncTransport, SyncTransport

DATA_DIR = Path(__file__).parent / "data"

API_KEY = "sec_test0001-test0002-test0003"
SECRET_KEY = "0123456789abcdef0123456789abcdef"
DOMAIN = "example.com"
HISTORY_HOST = "account.shieldlabs.ai"
MANAGEMENT_HOST = "api.shieldlabs.ai"
REQUEST_ID = "a5b7c9d1-e3f5-4a7b-9c1d-3e5f7a9b1c3d"
REQUEST_PATH = f"/api/v1/history/request_id/{REQUEST_ID}"


def load_json(name: str) -> Any:
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def load_bytes(name: str) -> bytes:
    return (DATA_DIR / name).read_bytes()


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def history_body(*rows: dict[str, Any], total: Union[int, None] = None) -> dict[str, Any]:
    return {"data": list(rows), "total": len(rows) if total is None else total}


def row(request_id: str, **extra: Any) -> dict[str, Any]:
    """A minimal History row for paging tests."""
    base: dict[str, Any] = {
        "request_id": request_id,
        "device_id": "d8e0f2a4-b6c8-4d0e-bf2a-4b6c8d0e2f4a",
        "score": 10,
        "created_at": "2026-09-30 12:00:00.000",
    }
    base.update(extra)
    return base


def uuid_for(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def empty_page() -> httpx.Response:
    return httpx.Response(200, json={"data": [], "total": 0})


class FakeTime:
    """Deterministic clock, sleep and jitter for transports."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds

    async def async_sleep(self, seconds: float) -> None:
        self.sleep(seconds)

    def install(self, transport: Union[SyncTransport, AsyncTransport]) -> None:
        transport._clock = self.clock
        transport._random = lambda: 1.0
        if isinstance(transport, AsyncTransport):
            transport._sleep = self.async_sleep
        else:
            transport._sleep = self.sleep
