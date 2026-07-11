"""ShieldLabs server SDK for Python.

Talks to the ShieldLabs API and verifies inbound webhooks. Your code decides
what to do with the score: you set the rules. This SDK never makes the
decision for you.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import urlencode
from urllib.request import Request, urlopen

__version__ = "0.1.0"

WEBHOOK_SCHEMA_VERSION = "2026-06-01"

_DEFAULT_BASE_URL = "https://account.shieldlabs.ai/api"


def verify_webhook(
    payload: Union[bytes, bytearray, memoryview],
    signature: str,
    secret: str,
) -> bool:
    """Verify X-Shield-Signature against HMAC-SHA256(secret, raw body).

    ``payload`` must be the raw request body bytes. Re-serializing parsed JSON
    will fail verification. Comparison is constant-time.
    """
    if not signature or not secret:
        return False
    body = bytes(payload)
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


class ShieldLabsClient:
    """Thin client for ShieldLabs History API (account.shieldlabs.ai)."""

    def __init__(self, api_key: str, base_url: Optional[str] = None) -> None:
        self.api_key = api_key
        self.base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")

    def get_history(
        self,
        search_type: str,
        value: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /api/v1/history/{search_type}/{value} → {data, total}."""
        path = f"{self.base_url}/api/v1/history/{search_type}/{value}"
        query: Dict[str, str] = {}
        if limit is not None:
            query["limit"] = str(limit)
        if offset is not None:
            query["offset"] = str(offset)
        if query:
            path = f"{path}?{urlencode(query)}"
        req = Request(
            path,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        with urlopen(req) as resp:
            import json

            return json.loads(resp.read().decode("utf-8"))


__all__ = [
    "ShieldLabsClient",
    "WEBHOOK_SCHEMA_VERSION",
    "__version__",
    "verify_webhook",
]
