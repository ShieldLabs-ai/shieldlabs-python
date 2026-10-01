# Examples

## `fastapi_app.py`

A FastAPI app that does both halves of a server integration:

- `POST /signup` reads the `requestId` sent by the browser, waits for the verdict with
  `identifications.get`, and refuses the signup when the identification is missing, reused,
  stale, carries the rate-limit marker, has no device signals, shows browser automation or
  disabled JavaScript, or falls in the dangerous band (`evaluate_identification` defaults).
- `POST /webhooks/shieldlabs` verifies `X-Shield-Signature` over the raw body, parses the event,
  handles each `request_id` once (so a retried delivery is harmless), and logs it.

Run it from the repository root:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r examples/requirements.txt   # before the package is on PyPI: pip install -e . first
export SHIELDLABS_API_KEY=sec_your_private_key
export SHIELDLABS_WEBHOOK_SECRET=whsec_your_signing_secret
uvicorn examples.fastapi_app:app --port 8000
```

Try the signup route with a request ID from your page:

```bash
curl -X POST http://localhost:8000/signup \
  -H 'content-type: application/json' \
  -d '{"email": "user@example.com", "requestId": "8f14e45f-ceea-4c1e-a3b2-1d2c3b4a5f60"}'
```

To receive webhooks locally, expose port 8000 with an HTTPS tunnel and register
`https://<your-tunnel>/webhooks/shieldlabs` in the analytics dashboard under
**Integration > Webhooks**. Press **Verify** to send a `webhook.ping`.

The in-memory sets keep the example short. In production, store used request IDs and processed
webhook request IDs in your database or cache.

The smoke test for this app is `tests/test_example_app.py`; it runs when FastAPI is installed:

```bash
pip install -e ".[dev]" -r examples/requirements.txt
pytest tests/test_example_app.py
```
