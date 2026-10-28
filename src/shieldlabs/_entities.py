"""Domain-scoped entity History: lists and cards at /api/v1/domains/{uuid}/history.

Lists never send ``include_total``. The page is ``data`` plus ``next_page_token``.
The legacy ``history.search`` client is unchanged.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional
from urllib.parse import quote

from ._errors import ApiError, ValidationError
from ._http import json_object

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_RFC3339 = re.compile(r"^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$")
_RESOURCES = ("identifications", "user", "visitor", "device", "ip")
_LIST_RESOURCES = ("identifications", "user")
_TYPES = ("identification", "user", "visitor", "device", "ip")
_BANDS = ("trusted", "suspicious", "dangerous")


class EntityPage:
    """One entity History page. There is no total."""

    def __init__(self, data: list[dict[str, Any]], next_page_token: Optional[str]) -> None:
        self.data = data
        self.next_page_token = next_page_token

    def __repr__(self) -> str:
        return f"EntityPage(data={self.data!r}, next_page_token={self.next_page_token!r})"


def _invalid() -> ApiError:
    return ApiError("History API returned an invalid entity response.", status=200)


def _reject_unknown(extra: Mapping[str, Any]) -> None:
    if extra:
        raise ValidationError(
            "Unsupported entity History option. Use page_token, not offset, sort, "
            "include_total or legacy row filters."
        )


def _domain_base(domain: str, resource: str) -> str:
    if not isinstance(domain, str) or not _UUID.fullmatch(domain):
        raise ValidationError("domain must be the public domain UUID.")
    if resource not in _RESOURCES:
        raise ValidationError("Unknown History resource.")
    return f"/api/v1/domains/{domain.lower()}/history/{resource}"


def _window(from_: Optional[str], to: Optional[str]) -> dict[str, str]:
    if (from_ is None) != (to is None):
        raise ValidationError("Send both from and to, or neither.")
    if from_ is None or to is None:
        return {}
    start, end = _rfc3339(from_), _rfc3339(to)
    if start >= end:
        raise ValidationError("from must be before to.")
    return {"from": from_, "to": to}


def _rfc3339(value: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValidationError("History dates must be RFC3339.")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError("History dates must be RFC3339.") from exc
    if parsed.tzinfo is None:
        raise ValidationError("History dates must be RFC3339.")
    return parsed


def _known_filter(filter_: Mapping[str, Any]) -> None:
    if not isinstance(filter_, Mapping):
        raise ValidationError("Unsupported History filter.")
    for key in filter_:
        if key not in ("identification", "entity"):
            raise ValidationError("Unsupported History filter.")
    identification = filter_.get("identification")
    if identification is not None:
        if not isinstance(identification, Mapping):
            raise ValidationError("Unsupported History filter.")
        for key in identification:
            if key not in ("risk_bands", "hre_min_accounts", "hre_min_devices"):
                raise ValidationError(
                    "Search does not accept ids, device_id_source or chips. "
                    "Open one card by id, or filter by risk_bands."
                )
    entity = filter_.get("entity")
    if entity is not None:
        if not isinstance(entity, Mapping):
            raise ValidationError("Unsupported entity filter.")
        for key in entity:
            if key not in ("ids", "risk_bands"):
                raise ValidationError("Unsupported entity filter.")


def normalize_entity_id(resource: str, id_: str) -> str:
    """Normalize an entity id the same way the Node 1.2.0 client does."""
    if (
        not isinstance(id_, str)
        or not id_
        or len(id_) > 512
        or "/" in id_
        or "\\" in id_
        or any(ord(char) < 32 or ord(char) == 127 for char in id_)
        or id_ in (".", "..")
    ):
        raise ValidationError("Invalid entity id.")
    if resource == "ip":
        return _normalize_ip(id_)
    if resource in ("identifications", "visitor", "device"):
        if not _UUID.fullmatch(id_):
            raise ValidationError("This entity id must be a UUID.")
        return id_.lower()
    return id_


def _normalize_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError("Invalid IP entity id.") from exc
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is None:
            raise ValidationError("Pure IPv6 is not supported by History.")
        return str(mapped)
    return str(addr)


def parse_entity(value: Any) -> dict[str, Any]:
    """Validate an entity card without inventing a score or a flag."""
    if not isinstance(value, dict):
        raise _invalid()
    if value.get("type") not in _TYPES or not isinstance(value.get("id"), str) or not value["id"]:
        raise _invalid()
    domain_id = value.get("domain_id")
    if not isinstance(domain_id, str) or not _UUID.fullmatch(domain_id):
        raise _invalid()
    if not isinstance(value.get("domain"), str):
        raise _invalid()
    _risk(value.get("risk"), value["type"])
    _signals(value.get("signals"))
    count = value.get("identifications", None)
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0):
        raise _invalid()
    return value


def _risk(risk: Any, entity_type: str) -> None:
    if not isinstance(risk, dict):
        raise _invalid()
    if risk.get("state") == "ok":
        if risk.get("band") not in _BANDS or not isinstance(risk.get("as_of"), str):
            raise _invalid()
        try:
            _rfc3339(risk["as_of"])
        except ValidationError:
            raise _invalid() from None
        score = risk.get("score", None)
        if score is not None and (
            isinstance(score, bool) or not isinstance(score, int) or score < 0 or score > 100
        ):
            raise _invalid()
        if entity_type == "identification" and "score" not in risk:
            raise _invalid()
        return
    if (
        risk.get("state") != "unavailable"
        or risk.get("band") is not None
        or risk.get("as_of") is not None
        or "score" in risk
    ):
        raise _invalid()


def _signals(signals: Any) -> None:
    if not isinstance(signals, dict):
        raise _invalid()
    items = signals.get("items")
    if (
        signals.get("state") not in ("ok", "unavailable")
        or not isinstance(items, list)
        or not all(isinstance(item, str) for item in items)
    ):
        raise _invalid()


def parse_page(value: Any) -> EntityPage:
    if not isinstance(value, dict) or not isinstance(value.get("data"), list):
        raise _invalid()
    token = value.get("next_page_token")
    if token is not None and not isinstance(token, str):
        raise _invalid()
    total = value.get("total", None)
    if "total" in value and (isinstance(total, bool) or not isinstance(total, int) or total < 0):
        raise _invalid()
    return EntityPage(data=[parse_entity(row) for row in value["data"]], next_page_token=token)


def _list_params(
    domain: str,
    resource: str,
    *,
    limit: int,
    page_token: Optional[str],
    from_: Optional[str],
    to: Optional[str],
    filter_: Optional[Mapping[str, Any]],
) -> tuple[str, dict[str, str]]:
    if resource not in _LIST_RESOURCES:
        raise ValidationError("Only identifications and user have lists.")
    path = _domain_base(domain, resource)
    params = _window(from_, to)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 100:
        raise ValidationError("limit must be from 1 through 100.")
    params["limit"] = str(limit)
    if page_token is not None:
        if not isinstance(page_token, str) or not page_token or len(page_token) > 4096:
            raise ValidationError("Invalid page_token.")
        params["page_token"] = page_token
    if filter_ is not None:
        _known_filter(filter_)
        params["filter"] = json.dumps(filter_, separators=(",", ":"), sort_keys=True)
    return path, params


def _check_page(page: EntityPage, domain: str, resource: str, limit: int) -> EntityPage:
    expected = "identification" if resource == "identifications" else resource
    if len(page.data) > limit or any(
        row["domain_id"].lower() != domain.lower() or row["type"] != expected for row in page.data
    ):
        raise _invalid()
    return page


def _check_entity(body: Any, domain: str, resource: str, normalized: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise _invalid()
    entity = parse_entity(body.get("data"))
    expected = "identification" if resource == "identifications" else resource
    if (
        entity["id"] != normalized
        or entity["domain_id"].lower() != domain.lower()
        or entity["type"] != expected
    ):
        raise _invalid()
    return entity


class EntityHistory:
    """Synchronous domain-scoped entity History. Available as ``client.entities``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def list(
        self,
        domain: str,
        resource: str,
        *,
        limit: int = 20,
        page_token: Optional[str] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        filter: Optional[Mapping[str, Any]] = None,
        **rejected: Any,
    ) -> EntityPage:
        """List identifications or users. ``include_total`` is not accepted."""
        _reject_unknown(rejected)
        path, params = _list_params(
            domain, resource, limit=limit, page_token=page_token, from_=from_, to=to, filter_=filter
        )
        response = self._client._transport.get(
            self._client.base_url + path, headers=self._client._headers, params=params
        )
        return _check_page(parse_page(json_object(response)), domain, resource, limit)

    def get(
        self,
        domain: str,
        resource: str,
        id_: str,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        **rejected: Any,
    ) -> dict[str, Any]:
        """Read one entity card. The body is ``{"data": {...}}``."""
        _reject_unknown(rejected)
        path, params, normalized = _get_request(domain, resource, id_, from_, to)
        response = self._client._transport.get(
            self._client.base_url + path,
            headers=self._client._headers,
            params=params or None,
        )
        return _check_entity(json_object(response), domain, resource, normalized)


class AsyncEntityHistory:
    """Asynchronous domain-scoped entity History. Available as ``client.entities``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def list(
        self,
        domain: str,
        resource: str,
        *,
        limit: int = 20,
        page_token: Optional[str] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        filter: Optional[Mapping[str, Any]] = None,
        **rejected: Any,
    ) -> EntityPage:
        _reject_unknown(rejected)
        path, params = _list_params(
            domain, resource, limit=limit, page_token=page_token, from_=from_, to=to, filter_=filter
        )
        response = await self._client._transport.get(
            self._client.base_url + path, headers=self._client._headers, params=params
        )
        return _check_page(parse_page(json_object(response)), domain, resource, limit)

    async def get(
        self,
        domain: str,
        resource: str,
        id_: str,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        **rejected: Any,
    ) -> dict[str, Any]:
        _reject_unknown(rejected)
        path, params, normalized = _get_request(domain, resource, id_, from_, to)
        response = await self._client._transport.get(
            self._client.base_url + path,
            headers=self._client._headers,
            params=params or None,
        )
        return _check_entity(json_object(response), domain, resource, normalized)


def _get_request(
    domain: str, resource: str, id_: str, from_: Optional[str], to: Optional[str]
) -> tuple[str, dict[str, str], str]:
    path = _domain_base(domain, resource)
    normalized = normalize_entity_id(resource, id_)
    escaped = quote(normalized, safe="-_.!~*'()")
    return f"{path}/{escaped}", _window(from_, to), normalized
