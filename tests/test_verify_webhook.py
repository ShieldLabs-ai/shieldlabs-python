import hashlib
import hmac

from shieldlabs import verify_webhook

SECRET = "whsec_test_secret"
BODY = b'{"event_type":"webhook.ping","schema_version":"2026-06-01","created_at":"2026-06-26T14:20:42Z"}'


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_accepts_valid_signature():
    assert verify_webhook(BODY, _sign(SECRET, BODY), SECRET) is True


def test_accepts_bytearray():
    buf = bytearray(BODY)
    assert verify_webhook(buf, _sign(SECRET, BODY), SECRET) is True


def test_rejects_wrong_secret():
    assert verify_webhook(BODY, _sign(SECRET, BODY), "other") is False


def test_rejects_tampered_body():
    assert verify_webhook(BODY + b" ", _sign(SECRET, BODY), SECRET) is False


def test_rejects_missing_header():
    assert verify_webhook(BODY, "", SECRET) is False


def test_rejects_truncated_signature():
    assert verify_webhook(BODY, "sha256=ab", SECRET) is False
