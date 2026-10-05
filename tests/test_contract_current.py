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
    assert event.data.risk_events is not None
    assert len(event.data.risk_events) == 19
    assert event.data.fingerprint is not None
    assert event.data.fingerprint["hardware_id"] == "sample-hardware"
    assert event.data.device_id != event.data.fingerprint["hardware_id"]
    assert event.data.hre is not None
    assert event.data.hre["account_takeover"]["reason"] == "no_history"
    encoded = event.data.to_dict()
    assert encoded["risk_events"][15]["weight"] == 0
    assert event.data.from_dict(encoded).to_dict() == encoded
    assert not webhooks.verify_signature(raw + b" ", signature, "secret")
