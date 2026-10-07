import hashlib
import hmac
from pathlib import Path

from shieldlabs import webhooks


def test_current_core_fixture_preserves_identity_and_results():
    raw = (Path(__file__).parent / "contracts/current.json").read_bytes()
    signature = "sha256=" + hmac.new(b"secret", raw, hashlib.sha256).hexdigest()
    event = webhooks.construct_event(raw, signature, "secret")
    assert event.event_id
    assert event.site_id == 7
    assert isinstance(event, webhooks.IdentificationScoredEvent)
    assert event.data.risk_events is None
    assert event.data.fingerprint is None
    assert event.data.detection_flags.os_mismatch2 is None
    assert event.data.hre is not None
    assert event.data.hre["account_takeover"]["reason"] == "no_history"
    encoded = event.data.to_dict()
    assert "risk_events" not in encoded
    assert encoded["hre"]["account_sharing"]["cluster_id"] is None
    assert event.data.from_dict(encoded).to_dict() == encoded
    assert not webhooks.verify_signature(raw + b" ", signature, "secret")


def test_accepted_ai_bot_owner_survives_normalization():
    raw = (Path(__file__).parent / "contracts/ai-bot.json").read_bytes()
    signature = "sha256=" + hmac.new(b"secret", raw, hashlib.sha256).hexdigest()
    event = webhooks.construct_event(raw, signature, "secret")
    assert isinstance(event, webhooks.IdentificationScoredEvent)
    assert event.data.ai_bot_owner == "OpenAI"
    assert event.data.detection_flags.ai_bot is True
    assert event.data.to_dict()["ai_bot_owner"] == "OpenAI"
