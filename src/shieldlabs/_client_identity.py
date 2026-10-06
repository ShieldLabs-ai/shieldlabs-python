"""Open string types for scoped server attribution; no global verified flag."""

from typing import Any, Optional, TypedDict, cast


class ClientIdentityClaim(TypedDict, total=False):
    profile_id: str
    provider_id: str
    provider_name: str
    agent_name: str
    client_kind: str
    purpose: str
    source: str


class ClientIdentityVerified(TypedDict, total=False):
    subject: str
    value_id: str
    evidence_ids: list[str]


class ClientIdentityAssessment(TypedDict, total=False):
    candidate_profile_id: str
    status: str
    reason: str


class ClientIdentityEvidence(TypedDict, total=False):
    id: str
    method: str
    source_id: str
    source_revision: str
    checked_at: str
    evaluated_at: str
    covered_attributes: list[str]
    covered_components: list[str]
    request_binding: str
    replay_policy: str


class ClientIdentity(TypedDict, total=False):
    schema_version: str
    classification_revision: int
    classifier_version: str
    registry_revision: str
    availability: str
    observed_at: str
    decided_at: str
    claims: list[ClientIdentityClaim]
    verified: list[ClientIdentityVerified]
    assessments: list[ClientIdentityAssessment]
    evidence: list[ClientIdentityEvidence]


def parse_client_identity(value: Any) -> Optional[ClientIdentity]:
    """Pass through stored attribution, retaining unknown values and extra fields."""
    if not isinstance(value, dict):
        return None
    for key in ("schema_version", "availability", "registry_revision", "observed_at"):
        if not isinstance(value.get(key), str):
            return None
    revision = value.get("classification_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        return None
    for key in ("claims", "verified", "assessments", "evidence"):
        if not isinstance(value.get(key), list):
            return None
    return cast(ClientIdentity, value)
