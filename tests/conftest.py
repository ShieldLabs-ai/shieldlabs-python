from __future__ import annotations

import pytest

from _support import FakeTime

_ENV_VARS = (
    "SHIELDLABS_API_KEY",
    "SHIELDLABS_API_BASE_URL",
    "SHIELDLABS_SECRET_KEY",
    "SHIELDLABS_DOMAIN",
    "SHIELDLABS_MANAGEMENT_BASE_URL",
    "SHIELDLABS_WEBHOOK_SECRET",
)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake_time() -> FakeTime:
    return FakeTime()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
