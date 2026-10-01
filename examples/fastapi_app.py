"""Signup protection and a webhook receiver with FastAPI and the ShieldLabs Python SDK.

The browser runs an identification with the ShieldLabs agent and sends the resulting
``requestId`` with the signup form. This app reads the verdict for that request ID from the
History API, applies a policy, and separately receives signed ``identification.scored``
webhooks.

Environment:
    SHIELDLABS_API_KEY          Private API Key (sec_...), reads verdicts from the History API.
    SHIELDLABS_WEBHOOK_SECRET   Endpoint signing secret (whsec_...), verifies webhook deliveries.
                                Several secrets can be given, separated by commas, while you
                                rotate one.

Run from the repository root:
    pip install -r examples/requirements.txt
    uvicorn examples.fastapi_app:app --port 8000
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from shieldlabs import (
    AsyncShieldLabs,
    IdentificationScoredEvent,
    ShieldLabsError,
    SignatureVerificationError,
    ValidationError,
    WebhookParseError,
    WebhookPingEvent,
    evaluate_identification,
    webhooks,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldlabs.example")

# In-memory stores keep the example self-contained. Use your database or cache in production:
# one request ID authorizes one protected action, and the webhook handler stays idempotent on
# the request ID (one delivery per identification today; a future release retries deliveries
# with identical bytes).
used_request_ids: set[str] = set()
processed_request_ids: set[str] = set()


def _webhook_secrets() -> list[str]:
    # Several secrets, separated by commas, while you rotate one: "whsec_new, whsec_old".
    raw = os.environ.get("SHIELDLABS_WEBHOOK_SECRET", "")
    return [secret.strip() for secret in raw.split(",") if secret.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # One client for the whole process; it reads SHIELDLABS_API_KEY and is safe to share.
    app.state.shieldlabs = AsyncShieldLabs()
    try:
        yield
    finally:
        await app.state.shieldlabs.aclose()


app = FastAPI(title="ShieldLabs signup example", lifespan=lifespan)


class SignupForm(BaseModel):
    email: str
    request_id: str = Field(alias="requestId")


@app.post("/signup")
async def signup(form: SignupForm, request: Request) -> JSONResponse:
    client: AsyncShieldLabs = request.app.state.shieldlabs
    try:
        # Waits for the verdict (up to 10 s): the History row appears about 1-3 s after the
        # browser call, so the page starts the identification when the user starts filling in
        # the form rather than on submit.
        identification = await client.identifications.get(form.request_id)
    except ValidationError:
        return JSONResponse({"error": "invalid_request_id"}, status_code=400)
    except ShieldLabsError:
        # Unverified is never clean: refuse and let the user retry.
        logger.exception("ShieldLabs lookup failed")
        return JSONResponse({"error": "verification_unavailable"}, status_code=503)

    # Default policy: refuse a missing, reused or stale identification, the rate-limit marker,
    # an identification without device signals, browser automation or disabled JavaScript,
    # and the dangerous band. Tune it for your product.
    verdict = evaluate_identification(
        identification,
        is_replay=lambda request_id: request_id in used_request_ids,
    )
    if identification is not None:
        used_request_ids.add(identification.request_id)
    if not verdict.ok:
        logger.info(
            "signup refused: reason=%s band=%s flag=%s", verdict.reason, verdict.band, verdict.flag
        )
        return JSONResponse({"error": "signup_refused", "reason": verdict.reason}, status_code=403)

    # Create the account here.
    return JSONResponse({"status": "created"}, status_code=201)


@app.post("/webhooks/shieldlabs")
async def shieldlabs_webhook(request: Request) -> Response:
    payload = await request.body()  # the raw bytes: verify them before parsing anything
    try:
        event = webhooks.construct_event(
            payload, request.headers.get(webhooks.SIGNATURE_HEADER), _webhook_secrets()
        )
    except SignatureVerificationError:
        return Response(status_code=401)
    except WebhookParseError:
        return Response(status_code=400)

    if isinstance(event, IdentificationScoredEvent):
        data = event.data
        if data.request_id in processed_request_ids:
            return Response(status_code=200)  # already handled: acknowledge and stop
        processed_request_ids.add(data.request_id)
        # Answer fast (under 1 s): a slow or failed delivery is not sent again, so queue slow
        # work instead of doing it here, and read the History API when you must not miss one.
        logger.info(
            "identification.scored request_id=%s risk_score=%s band=%s flags=%s",
            data.request_id,
            data.risk_score,
            data.risk_band,
            ",".join(data.detection_flags.active()) or "none",
        )
    elif isinstance(event, WebhookPingEvent):
        logger.info("webhook.ping received")
    else:
        logger.info("ignored event_type=%s", event.event_type)
    return Response(status_code=200)
