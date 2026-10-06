"""Typed models returned by the SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional

from ._client_identity import ClientIdentity, parse_client_identity
from ._normalize import (
    FLAG_KEYS,
    HISTORY_FLAG_MAP,
    NIL_UUID,
    TRAFFIC_KEYS,
    RiskBand,
    as_int,
    as_str,
    clean_ip,
    format_timestamp,
    is_rate_limited,
    parse_history_time,
    parse_rfc3339,
    risk_band,
    signal_slug,
)

__all__ = [
    "DetectionFlags",
    "DomainProfile",
    "HistoryPage",
    "Identification",
    "IdentificationSource",
    "IpInfo",
    "Signal",
    "SignalName",
    "TrafficSource",
]

IdentificationSource = Literal["webhook", "history"]
"""Where an ``Identification`` came from."""

_IP_MISMATCH_DETAIL = "IP ≠ leakIP"


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _optional_user_hid(value: object) -> Optional[str]:
    # "" becomes None; sentinels such as "anonymous", "fail", "-1" and "unknown" are kept.
    return value if isinstance(value, str) and value != "" else None


class SignalName:
    """Known risk signal names (``Signal.name``).

    The set of names is open: new names can appear at any time, so compare against these
    constants but never reject a name that is not listed. Branch on ``risk_score`` and
    ``detection_flags``; use signal names for display and logging.
    """

    TOR = "tor"
    JAVASCRIPT_DISABLED = "javascript_disabled"
    OS_MISMATCH = "os_mismatch"
    ANTIDETECT_BROWSER = "antidetect_browser"
    PROXY_ROUTED_ANTIDETECT = "proxy_routed_antidetect"
    PORT_SCAN_ROUTED_VIA_PROXY = "port_scan_routed_via_proxy"
    BROWSER_AUTOMATION = "browser_automation"
    STUN_NOT_CHECKED = "stun_not_checked"
    STUN_LATE_CORRECTION = "stun_late_correction"
    OS_NOT_DETECTED = "os_not_detected"
    BROWSER_VPN_PROXY = "browser_vpn_proxy"
    VPN = "vpn"
    PRIVACY_RELAY = "privacy_relay"
    PROXY = "proxy"
    DATACENTER_IP = "datacenter_ip"
    ABUSER = "abuser"
    TIMEZONE_MISMATCH = "timezone_mismatch"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True)
class IpInfo:
    """An IP address with the English name of its country. Both are ``""`` when unknown."""

    ip: str = ""
    country: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IpInfo:
        """Build from ``{"ip": ..., "country": ...}``. ``0.0.0.0`` becomes ``""``."""
        data = _mapping(data)
        return cls(ip=clean_ip(data.get("ip")), country=as_str(data.get("country")))

    def to_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "country": self.country}


@dataclass(frozen=True)
class TrafficSource:
    """Attribution of the visit. Every field is ``""`` when absent."""

    channel: str = ""
    referrer_domain: str = ""
    landing_url: str = ""
    click_id_type: str = ""
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    utm_content: str = ""
    utm_term: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TrafficSource:
        """Build from a webhook ``traffic_source`` object. Missing keys become ``""``."""
        data = _mapping(data)
        return cls(**{key: as_str(data.get(key)) for key in TRAFFIC_KEYS})

    def to_dict(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in TRAFFIC_KEYS}


@dataclass(frozen=True)
class Signal:
    """One weighted risk signal behind the score.

    Attributes:
        name: Signal name, an open set (see ``SignalName`` for known values). Names can repeat.
        weight: Weight in points. Can be negative (corrections) or informational.
        description: Human-readable detail. Present on identifications read from the History
            API, ``None`` on webhook deliveries.
    """

    name: str
    weight: int
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Signal:
        """Build from ``{"name": ..., "weight": ..., "description"?: ...}``."""
        data = _mapping(data)
        description = data.get("description")
        return cls(
            name=as_str(data.get("name")),
            weight=as_int(data.get("weight")),
            description=description if isinstance(description, str) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": self.weight, "description": self.description}


@dataclass(frozen=True)
class DetectionFlags:
    """The 19 detection flags. Branch on these and on ``risk_score``."""

    vpn: bool = False
    privacy_relay: bool = False
    browser_vpn_proxy: bool = False
    tor: bool = False
    proxy: bool = False
    datacenter_ip: bool = False
    abuser: bool = False
    os_mismatch: bool = False
    os_not_detected: bool = False
    timezone_mismatch: bool = False
    anti_detect_browser: bool = False
    browser_automation: bool = False
    ip_mismatch: bool = False
    incognito: bool = False
    search_bot: bool = False
    suspicious_paid_click: bool = False
    javascript_disabled: bool = False
    stun_not_checked: bool = False
    check_incomplete: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DetectionFlags:
        """Build from a webhook ``detection_flags`` object. A missing key is ``False``."""
        data = _mapping(data)
        return cls(**{key: bool(data.get(key, False)) for key in FLAG_KEYS})

    def to_dict(self) -> dict[str, bool]:
        return {key: getattr(self, key) for key in FLAG_KEYS}

    def active(self) -> tuple[str, ...]:
        """Names of the flags that are set, in wire order."""
        return tuple(key for key in FLAG_KEYS if getattr(self, key))


@dataclass(frozen=True)
class Identification:
    """One identification (one run of the browser agent), normalized.

    Webhook deliveries and History API rows produce the same model. Field names follow the
    webhook contract.
    """

    request_id: str
    visitor_id: str
    device_id: str
    session_id: str
    cookie_id: str
    user_hid: Optional[str]
    domain: str
    public_ip: IpInfo
    local_ip: IpInfo
    connection_type: str
    os: str
    browser: str
    device_type: str
    traffic_source: TrafficSource
    risk_score: int
    signals: tuple[Signal, ...]
    detection_flags: DetectionFlags
    observed_at: Optional[datetime]
    """When the identification was observed, as an aware UTC datetime. ``None`` only when the
    server value could not be parsed."""
    source: IdentificationSource
    client_identity: Optional[ClientIdentity] = None
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)
    """The original webhook ``data`` object or History row, including fields the model omits."""

    @property
    def risk_band(self) -> RiskBand:
        """Band of ``risk_score``: trusted, suspicious, dangerous, or rate_limited (marker)."""
        return risk_band(self.risk_score)

    @property
    def is_rate_limited(self) -> bool:
        """``True`` when ``risk_score`` is the rate-limit marker (above 100)."""
        return is_rate_limited(self.risk_score)

    @property
    def has_device_signals(self) -> bool:
        """``False`` when the device ID is the all-zero UUID (no usable device signals)."""
        return self.device_id not in ("", NIL_UUID)

    @classmethod
    def from_webhook_data(cls, data: Mapping[str, Any]) -> Identification:
        """Normalize the ``data`` object of an ``identification.scored`` webhook."""
        data = _mapping(data)
        flags = _mapping(data.get("detection_flags"))
        raw_signals = data.get("signals")
        signals = tuple(
            Signal(name=as_str(item.get("name")), weight=as_int(item.get("weight")))
            for item in (raw_signals if isinstance(raw_signals, list) else [])
            if isinstance(item, Mapping)
        )
        return cls(
            request_id=as_str(data.get("request_id")),
            visitor_id=as_str(data.get("visitor_id")),
            device_id=as_str(data.get("device_id")),
            session_id=as_str(data.get("session_id")),
            cookie_id=as_str(data.get("cookie_id")),
            user_hid=_optional_user_hid(data.get("user_hid")),
            domain=as_str(data.get("domain")),
            public_ip=IpInfo.from_dict(_mapping(data.get("public_ip"))),
            local_ip=IpInfo.from_dict(_mapping(data.get("local_ip"))),
            connection_type=as_str(data.get("connection_type")),
            os=as_str(data.get("os")),
            browser=as_str(data.get("browser")),
            device_type=as_str(data.get("device_type")),
            traffic_source=TrafficSource.from_dict(_mapping(data.get("traffic_source"))),
            risk_score=as_int(data.get("risk_score")),
            signals=signals,
            detection_flags=DetectionFlags.from_dict(flags),
            observed_at=parse_rfc3339(data.get("observed_at")),
            source="webhook",
            raw=dict(data),
            client_identity=parse_client_identity(data.get("client_identity")),
        )

    @classmethod
    def from_history_row(cls, row: Mapping[str, Any]) -> Identification:
        """Normalize one row of a History API response."""
        row = _mapping(row)
        leak_source = as_str(row.get("webrtc_leak_source")).strip()
        if leak_source and leak_source != "none":
            local_ip = clean_ip(row.get("webrtc_leak_ip"))
            local_country = as_str(row.get("webrtc_leak_country"))
        else:
            local_ip = clean_ip(row.get("web_rtc_ip"))
            local_country = as_str(row.get("web_rtc_country"))
        public_ip = clean_ip(row.get("ip"))

        details: Any = []
        score_details = row.get("score_details")
        if isinstance(score_details, str) and score_details:
            try:
                details = json.loads(score_details)
            except (ValueError, RecursionError):
                details = []
        if not isinstance(details, list):
            details = []

        signals: list[Signal] = []
        ip_leak_detail = False
        for detail in details:
            if not isinstance(detail, Mapping):
                continue
            description = as_str(detail.get("Description"))
            if description.startswith(_IP_MISMATCH_DETAIL):
                ip_leak_detail = True
            value = detail.get("Value", 0)
            if isinstance(value, bool) or not isinstance(value, int) or value == 0:
                continue
            signals.append(
                Signal(name=signal_slug(description), weight=value, description=description)
            )

        search_bot = bool(row.get("is_search_bot", False))
        flags: dict[str, bool] = {}
        for key in FLAG_KEYS:
            if key == "browser_vpn_proxy":
                flags[key] = row.get("connection_type") == "browser_vpn_proxy"
            elif key == "ip_mismatch":
                differs = public_ip != "" and local_ip != "" and public_ip != local_ip
                flags[key] = (not search_bot) and (ip_leak_detail or differs)
            else:
                flags[key] = bool(row.get(HISTORY_FLAG_MAP[key], False))

        return cls(
            request_id=as_str(row.get("request_id")),
            visitor_id=as_str(row.get("visitor_id")),
            device_id=as_str(row.get("device_id")),
            session_id=as_str(row.get("session_id")),
            cookie_id=as_str(row.get("cookie_id")),
            user_hid=_optional_user_hid(row.get("user_hid")),
            domain=as_str(row.get("site_domain")) or as_str(row.get("domain")),
            public_ip=IpInfo(ip=public_ip, country=as_str(row.get("country"))),
            local_ip=IpInfo(ip=local_ip, country=local_country),
            connection_type=as_str(row.get("connection_type")),
            os=as_str(row.get("os")),
            browser=as_str(row.get("browser")),
            device_type=as_str(row.get("device_type")),
            traffic_source=TrafficSource(
                channel=as_str(row.get("traffic_channel")),
                referrer_domain=as_str(row.get("referrer_domain")),
                landing_url=as_str(row.get("entry_url")),
                click_id_type=as_str(row.get("click_id_type")),
                utm_source=as_str(row.get("utm_source")),
                utm_medium=as_str(row.get("utm_medium")),
                utm_campaign=as_str(row.get("utm_campaign")),
                utm_content=as_str(row.get("utm_content")),
                utm_term=as_str(row.get("utm_term")),
            ),
            risk_score=as_int(row.get("score")),
            signals=tuple(signals),
            detection_flags=DetectionFlags(**flags),
            observed_at=parse_history_time(row.get("created_at")),
            source="history",
            raw=dict(row),
            client_identity=parse_client_identity(row.get("client_identity")),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Identification:
        """Rebuild an identification from the output of ``to_dict()``.

        Webhook ``data`` objects are accepted as well (use ``from_webhook_data`` for those).
        """
        data = _mapping(data)
        raw_signals = data.get("signals")
        observed_at = data.get("observed_at")
        source = data.get("source")
        return cls(
            request_id=as_str(data.get("request_id")),
            visitor_id=as_str(data.get("visitor_id")),
            device_id=as_str(data.get("device_id")),
            session_id=as_str(data.get("session_id")),
            cookie_id=as_str(data.get("cookie_id")),
            user_hid=_optional_user_hid(data.get("user_hid")),
            domain=as_str(data.get("domain")),
            public_ip=IpInfo.from_dict(_mapping(data.get("public_ip"))),
            local_ip=IpInfo.from_dict(_mapping(data.get("local_ip"))),
            connection_type=as_str(data.get("connection_type")),
            os=as_str(data.get("os")),
            browser=as_str(data.get("browser")),
            device_type=as_str(data.get("device_type")),
            traffic_source=TrafficSource.from_dict(_mapping(data.get("traffic_source"))),
            risk_score=as_int(data.get("risk_score")),
            signals=tuple(
                Signal.from_dict(item)
                for item in (raw_signals if isinstance(raw_signals, list) else [])
                if isinstance(item, Mapping)
            ),
            detection_flags=DetectionFlags.from_dict(_mapping(data.get("detection_flags"))),
            observed_at=observed_at
            if isinstance(observed_at, datetime)
            else parse_rfc3339(observed_at),
            source="history" if source == "history" else "webhook",
            raw=dict(data),
            client_identity=parse_client_identity(data.get("client_identity")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON-ready dict (``observed_at`` as RFC 3339 UTC with milliseconds; no ``raw``)."""
        return {
            "request_id": self.request_id,
            "visitor_id": self.visitor_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "cookie_id": self.cookie_id,
            "user_hid": self.user_hid,
            "domain": self.domain,
            "public_ip": self.public_ip.to_dict(),
            "local_ip": self.local_ip.to_dict(),
            "connection_type": self.connection_type,
            "os": self.os,
            "browser": self.browser,
            "device_type": self.device_type,
            "traffic_source": self.traffic_source.to_dict(),
            "risk_score": self.risk_score,
            "signals": [signal.to_dict() for signal in self.signals],
            "detection_flags": self.detection_flags.to_dict(),
            "observed_at": format_timestamp(self.observed_at),
            "source": self.source,
            **(
                {"client_identity": self.client_identity}
                if self.client_identity is not None
                else {}
            ),
        }


@dataclass(frozen=True)
class HistoryPage:
    """One page of History API results, newest first.

    Attributes:
        data: The identifications on this page.
        total: Number of identifications that match the lookup, across all pages.
    """

    data: tuple[Identification, ...]
    total: int

    @classmethod
    def from_dict(cls, body: Mapping[str, Any]) -> HistoryPage:
        """Build from a History API response body ``{"data": [...], "total": N}``."""
        body = _mapping(body)
        rows = body.get("data")
        data = tuple(
            Identification.from_history_row(row)
            for row in (rows if isinstance(rows, list) else [])
            if isinstance(row, Mapping)
        )
        return cls(data=data, total=as_int(body.get("total"), default=len(data)))


@dataclass(frozen=True)
class DomainProfile:
    """Management API profile of one registered domain.

    Attributes:
        domain: The registered domain.
        remaining_identifications: Included identifications left on the account. Can be
            negative when the account is over its included volume.
        public_key_masked: Public Key with every character except the last 4 replaced by ``*``.
        secret_key_masked: Secret Key masked the same way.
        created_at: When the domain was added (aware UTC datetime), ``None`` if unparsable.
        raw: The original response body.
    """

    domain: str
    remaining_identifications: int
    public_key_masked: str
    secret_key_masked: str
    created_at: Optional[datetime]
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def from_dict(cls, body: Mapping[str, Any]) -> DomainProfile:
        """Build from a ``GET /v1/profile`` response body."""
        body = _mapping(body)
        return cls(
            domain=as_str(body.get("Domain")),
            remaining_identifications=as_int(body.get("Weight")),
            public_key_masked=as_str(body.get("PublicKey")),
            secret_key_masked=as_str(body.get("Secret")),
            created_at=parse_rfc3339(body.get("CreatedAt")),
            raw=dict(body),
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON-ready dict (``created_at`` as RFC 3339 UTC with milliseconds; no ``raw``)."""
        return {
            "domain": self.domain,
            "remaining_identifications": self.remaining_identifications,
            "public_key_masked": self.public_key_masked,
            "secret_key_masked": self.secret_key_masked,
            "created_at": format_timestamp(self.created_at),
        }
