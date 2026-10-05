"""Typed models returned by the SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Optional

from . import _generated_wire as wire
from . import _wire
from ._normalize import (
    FLAG_KEYS,
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

_HISTORY_FLAGS: dict[str, wire.Field[bool]] = {
    "vpn": wire.HistoryRow.is_vpn,
    "privacy_relay": wire.HistoryRow.is_privacy_relay,
    "tor": wire.HistoryRow.is_tor,
    "proxy": wire.HistoryRow.is_proxy,
    "datacenter_ip": wire.HistoryRow.is_datacenter,
    "abuser": wire.HistoryRow.is_abuser,
    "os_mismatch": wire.HistoryRow.is_os_mismatch,
    "os_not_detected": wire.HistoryRow.is_os_not_detected,
    "timezone_mismatch": wire.HistoryRow.is_timezone_mismatch,
    "anti_detect_browser": wire.HistoryRow.is_antidetect,
    "browser_automation": wire.HistoryRow.is_browser_automation,
    "incognito": wire.HistoryRow.is_incognito,
    "search_bot": wire.HistoryRow.is_search_bot,
    "suspicious_paid_click": wire.HistoryRow.is_suspicious_paid_click,
    "javascript_disabled": wire.HistoryRow.is_js_disabled,
    "stun_not_checked": wire.HistoryRow.is_stun_not_checked,
    "check_incomplete": wire.HistoryRow.check_incomplete,
}

_FLAG_FIELDS: dict[str, wire.Field[bool]] = {
    "vpn": wire.DetectionFlags.vpn,
    "privacy_relay": wire.DetectionFlags.privacy_relay,
    "browser_vpn_proxy": wire.DetectionFlags.browser_vpn_proxy,
    "tor": wire.DetectionFlags.tor,
    "proxy": wire.DetectionFlags.proxy,
    "datacenter_ip": wire.DetectionFlags.datacenter_ip,
    "abuser": wire.DetectionFlags.abuser,
    "os_mismatch": wire.DetectionFlags.os_mismatch,
    "os_not_detected": wire.DetectionFlags.os_not_detected,
    "timezone_mismatch": wire.DetectionFlags.timezone_mismatch,
    "anti_detect_browser": wire.DetectionFlags.anti_detect_browser,
    "browser_automation": wire.DetectionFlags.browser_automation,
    "ip_mismatch": wire.DetectionFlags.ip_mismatch,
    "incognito": wire.DetectionFlags.incognito,
    "search_bot": wire.DetectionFlags.search_bot,
    "suspicious_paid_click": wire.DetectionFlags.suspicious_paid_click,
    "javascript_disabled": wire.DetectionFlags.javascript_disabled,
    "stun_not_checked": wire.DetectionFlags.stun_not_checked,
    "check_incomplete": wire.DetectionFlags.check_incomplete,
}

_TRAFFIC_FIELDS: dict[str, wire.Field[str]] = {
    "channel": wire.TrafficSource.channel,
    "referrer_domain": wire.TrafficSource.referrer_domain,
    "landing_url": wire.TrafficSource.landing_url,
    "click_id_type": wire.TrafficSource.click_id_type,
    "utm_source": wire.TrafficSource.utm_source,
    "utm_medium": wire.TrafficSource.utm_medium,
    "utm_campaign": wire.TrafficSource.utm_campaign,
    "utm_content": wire.TrafficSource.utm_content,
    "utm_term": wire.TrafficSource.utm_term,
}


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
        return cls(
            ip=clean_ip(_wire.text(wire.IpInfo.ip.read(data))),
            country=_wire.text(wire.IpInfo.country.read(data)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "country": self.country}


def _local_ip_info(value: Optional[Mapping[str, object]]) -> IpInfo:
    data = _wire.mapping(value)
    return IpInfo(
        ip=clean_ip(_wire.text(wire.LocalIpInfo.ip.read(data))),
        country=_wire.text(wire.LocalIpInfo.country.read(data)),
    )


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
        return cls(**{key: _wire.text(field.read(data)) for key, field in _TRAFFIC_FIELDS.items()})

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
            name=_wire.text(wire.Signal.name.read(data)),
            weight=_wire.integer(wire.Signal.weight.read(data)),
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
        return cls(**{key: _wire.boolean(field.read(data)) for key, field in _FLAG_FIELDS.items()})

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
        flags = _wire.mapping(wire.IdentificationScoredData.detection_flags.read(data))
        raw_signals = wire.IdentificationScoredData.signals.read(data)
        signals = tuple(
            Signal(
                name=_wire.text(wire.Signal.name.read(item)),
                weight=_wire.integer(wire.Signal.weight.read(item)),
            )
            for item in _wire.records(raw_signals)
            if isinstance(item, Mapping)
        )
        return cls(
            request_id=_wire.text(wire.IdentificationScoredData.request_id.read(data)),
            visitor_id=_wire.text(wire.IdentificationScoredData.visitor_id.read(data)),
            device_id=_wire.text(wire.IdentificationScoredData.device_id.read(data)),
            session_id=_wire.text(wire.IdentificationScoredData.session_id.read(data)),
            cookie_id=_wire.text(wire.IdentificationScoredData.cookie_id.read(data)),
            user_hid=_optional_user_hid(wire.IdentificationScoredData.user_hid.read(data)),
            domain=_wire.text(wire.IdentificationScoredData.domain.read(data)),
            public_ip=IpInfo.from_dict(
                _wire.mapping(wire.IdentificationScoredData.public_ip.read(data))
            ),
            local_ip=_local_ip_info(wire.IdentificationScoredData.local_ip.read(data)),
            connection_type=_wire.text(wire.IdentificationScoredData.connection_type.read(data)),
            os=_wire.text(wire.IdentificationScoredData.os.read(data)),
            browser=_wire.text(wire.IdentificationScoredData.browser.read(data)),
            device_type=_wire.text(wire.IdentificationScoredData.device_type.read(data)),
            traffic_source=TrafficSource.from_dict(
                _wire.mapping(wire.IdentificationScoredData.traffic_source.read(data))
            ),
            risk_score=_wire.integer(wire.IdentificationScoredData.risk_score.read(data)),
            signals=signals,
            detection_flags=DetectionFlags.from_dict(flags),
            observed_at=parse_rfc3339(
                _wire.text(wire.IdentificationScoredData.observed_at.read(data))
            ),
            source="webhook",
            raw=dict(data),
        )

    @classmethod
    def from_history_row(cls, row: Mapping[str, Any]) -> Identification:
        """Normalize one row of a History API response."""
        row = _mapping(row)
        leak_source = _wire.text(wire.HistoryRow.webrtc_leak_source.read(row)).strip()
        if leak_source and leak_source != "none":
            local_ip = clean_ip(_wire.text(wire.HistoryRow.webrtc_leak_ip.read(row)))
            local_country = _wire.text(wire.HistoryRow.webrtc_leak_country.read(row))
        else:
            local_ip = clean_ip(_wire.text(wire.HistoryRow.web_rtc_ip.read(row)))
            local_country = _wire.text(wire.HistoryRow.web_rtc_country.read(row))
        public_ip = clean_ip(_wire.text(wire.HistoryRow.ip.read(row)))

        details: Any = []
        score_details = wire.HistoryRow.score_details.read(row)
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
            description = _wire.text(wire.ScoreDetail.Description.read(detail))
            if description.startswith(_IP_MISMATCH_DETAIL):
                ip_leak_detail = True
            value = wire.ScoreDetail.Value.read(detail)
            if isinstance(value, bool) or not isinstance(value, int) or value == 0:
                continue
            signals.append(
                Signal(name=signal_slug(description), weight=value, description=description)
            )

        search_bot = _wire.boolean(wire.HistoryRow.is_search_bot.read(row))
        flags: dict[str, bool] = {}
        for key in FLAG_KEYS:
            if key == "browser_vpn_proxy":
                flags[key] = wire.HistoryRow.connection_type.read(row) == "browser_vpn_proxy"
            elif key == "ip_mismatch":
                differs = public_ip != "" and local_ip != "" and public_ip != local_ip
                flags[key] = (not search_bot) and (ip_leak_detail or differs)
            else:
                flags[key] = _wire.boolean(_HISTORY_FLAGS[key].read(row))

        return cls(
            request_id=_wire.text(wire.HistoryRow.request_id.read(row)),
            visitor_id=_wire.text(wire.HistoryRow.visitor_id.read(row)),
            device_id=_wire.text(wire.HistoryRow.device_id.read(row)),
            session_id=_wire.text(wire.HistoryRow.session_id.read(row)),
            cookie_id=_wire.text(wire.HistoryRow.cookie_id.read(row)),
            user_hid=_optional_user_hid(wire.HistoryRow.user_hid.read(row)),
            domain=_wire.text(wire.HistoryRow.site_domain.read(row))
            or _wire.text(wire.HistoryRow.domain.read(row)),
            public_ip=IpInfo(ip=public_ip, country=_wire.text(wire.HistoryRow.country.read(row))),
            local_ip=IpInfo(ip=local_ip, country=local_country),
            connection_type=_wire.text(wire.HistoryRow.connection_type.read(row)),
            os=_wire.text(wire.HistoryRow.os.read(row)),
            browser=_wire.text(wire.HistoryRow.browser.read(row)),
            device_type=_wire.text(wire.HistoryRow.device_type.read(row)),
            traffic_source=TrafficSource(
                channel=_wire.text(wire.HistoryRow.traffic_channel.read(row)),
                referrer_domain=_wire.text(wire.HistoryRow.referrer_domain.read(row)),
                landing_url=_wire.text(wire.HistoryRow.entry_url.read(row)),
                click_id_type=_wire.text(wire.HistoryRow.click_id_type.read(row)),
                utm_source=_wire.text(wire.HistoryRow.utm_source.read(row)),
                utm_medium=_wire.text(wire.HistoryRow.utm_medium.read(row)),
                utm_campaign=_wire.text(wire.HistoryRow.utm_campaign.read(row)),
                utm_content=_wire.text(wire.HistoryRow.utm_content.read(row)),
                utm_term=_wire.text(wire.HistoryRow.utm_term.read(row)),
            ),
            risk_score=_wire.integer(wire.HistoryRow.score.read(row)),
            signals=tuple(signals),
            detection_flags=DetectionFlags(**flags),
            observed_at=parse_history_time(_wire.text(wire.HistoryRow.created_at.read(row))),
            source="history",
            raw=dict(row),
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
        rows = wire.HistoryPage.data.read(body)
        data = tuple(
            Identification.from_history_row(row)
            for row in _wire.records(rows)
            if isinstance(row, Mapping)
        )
        return cls(
            data=data, total=_wire.integer(wire.HistoryPage.total.read(body), default=len(data))
        )


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
            domain=_wire.text(wire.DomainProfile.Domain.read(body)),
            remaining_identifications=_wire.integer(wire.DomainProfile.Weight.read(body)),
            public_key_masked=_wire.text(wire.DomainProfile.PublicKey.read(body)),
            secret_key_masked=_wire.text(wire.DomainProfile.Secret.read(body)),
            created_at=parse_rfc3339(_wire.text(wire.DomainProfile.CreatedAt.read(body))),
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
