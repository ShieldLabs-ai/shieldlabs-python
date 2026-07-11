# shieldlabs (Python)

ShieldLabs server SDK: webhook verification and History API client.

## Install

```bash
pip install shieldlabs
```

## Verify webhooks

```python
from shieldlabs import verify_webhook

ok = verify_webhook(raw_body, request.headers["X-Shield-Signature"], secret)
```

Signature: `X-Shield-Signature: sha256=` + hex(HMAC-SHA256(secret, raw_body)). Schema `2026-06-01`.

## License

[MIT](./LICENSE)
