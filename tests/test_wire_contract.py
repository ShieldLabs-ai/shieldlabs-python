"""The generated boundary is used without making response parsing strict."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest

from _support import sign
from shieldlabs import (
    DomainProfile,
    HistoryPage,
    Identification,
    IdentificationScoredEvent,
    webhooks,
)
from shieldlabs import _generated_wire as wire
from shieldlabs._validation import LOOKUP_TYPES, LookupType


def test_generated_output_is_current() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/generate_wire.py", "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_lookup_validation_handles_every_declared_type() -> None:
    assert set(LOOKUP_TYPES) == set(get_args(LookupType))


def test_real_normalizers_read_generated_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    # A descriptor substitution changes actual outputs, proving it is not a sidecar.
    monkeypatch.setattr(wire.HistoryRow, "score", wire.Field("new_score"))
    monkeypatch.setattr(wire.HistoryPage, "total", wire.Field("new_total"))
    monkeypatch.setattr(wire.DomainProfile, "Weight", wire.Field("new_weight"))
    monkeypatch.setattr(wire.IdentificationScoredData, "risk_score", wire.Field("new_score"))
    monkeypatch.setattr(wire.DetectionFlags.vpn, "name", "new_vpn")
    monkeypatch.setattr(wire.LocalIpInfo, "ip", wire.Field("new_local_ip"))
    page = HistoryPage.from_dict({"new_total": 8, "data": [{"new_score": 999}]})
    assert page.total == 8
    assert page.data[0].risk_score == 999
    assert DomainProfile.from_dict({"new_weight": -5}).remaining_identifications == -5
    payload = json.dumps(
        {
            "event_type": "identification.scored",
            "schema_version": "2026-06-01",
            "data": {
                "new_score": 999,
                "detection_flags": {"new_vpn": True},
                "local_ip": {"new_local_ip": "198.51.100.2", "country": "Germany"},
            },
        }
    ).encode()
    event = webhooks.construct_event(payload, sign("fixture", payload), "fixture")
    assert isinstance(event, IdentificationScoredEvent)
    assert event.data.risk_score == 999
    assert event.data.detection_flags.vpn
    assert event.data.local_ip.ip == "198.51.100.2"
    assert event.data.local_ip.country == "Germany"


@pytest.mark.parametrize("bad", [None, "bad", [], {}, True])
def test_malformed_defaults_and_raw_are_preserved(bad: object) -> None:
    row = {"score": bad, "connection_type": "future_network", "future": bad}
    identification = Identification.from_history_row(row)
    assert identification.risk_score == 0
    assert identification.connection_type == "future_network"
    assert identification.raw == row
    data = {"risk_score": bad, "signals": bad, "public_ip": bad, "future": bad}
    result = Identification.from_webhook_data(data)
    assert result.risk_score == 0
    assert not result.signals
    assert result.public_ip.ip == ""
    assert result.raw == data
    assert DomainProfile.from_dict({"Weight": bad}).remaining_identifications == 0
