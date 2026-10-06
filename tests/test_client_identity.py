import json
from pathlib import Path

from shieldlabs import Identification

FIXTURE = json.loads((Path(__file__).parents[1] / "test-data-client-identity.json").read_text())


def test_identity_parity_and_independent_score():
    history = Identification.from_history_row({"score": 70, "client_identity": FIXTURE})
    webhook = Identification.from_webhook_data({"risk_score": 70, "client_identity": FIXTURE})
    assert history.client_identity == webhook.client_identity
    assert history.client_identity is not None
    assert history.client_identity["verified"][0]["subject"] == "provider"
    assert history.client_identity["claims"][0]["agent_name"] == "GPTBot"
    assert history.risk_score == 70
    assert history.to_dict()["client_identity"] == FIXTURE


def test_unknown_and_unavailable_identity():
    future = {**FIXTURE, "availability": "future_state", "extra": "kept"}
    assert Identification.from_history_row({"client_identity": future}).client_identity == future
    for value in (None, "bad", {}):
        model = Identification.from_history_row({"client_identity": value})
        assert model.client_identity is None
        assert "client_identity" not in model.to_dict()
