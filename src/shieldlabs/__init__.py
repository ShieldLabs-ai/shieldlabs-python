"""ShieldLabs server SDK for Python.

Talks to the ShieldLabs API and verifies inbound webhooks. Your code decides
what to do with the score: you set the rules. This SDK never makes the
decision for you.

Status: pre-launch scaffold. The surface below is a placeholder and will be
finalized from the OpenAPI specification before the first release.
"""

__version__ = "0.0.0"

_NOT_READY = "shieldlabs is not published yet. See https://shieldlabs.ai"


class ShieldLabsClient:
    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        self.api_key = api_key
        self.base_url = base_url

    def get_result(self, request_id: str) -> dict:
        """Fetch a stored identification result by request id. Not implemented yet."""
        raise NotImplementedError(_NOT_READY)


def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Verify the signature of an inbound ShieldLabs webhook. Not implemented yet."""
    raise NotImplementedError(_NOT_READY)


__all__ = ["ShieldLabsClient", "verify_webhook", "__version__"]
