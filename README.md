# ShieldLabs Python SDK

Read identification verdicts, verify webhooks and turn risk scores into decisions on your Python
backend.

[![CI](https://github.com/ShieldLabs-ai/shieldlabs-python/actions/workflows/ci.yml/badge.svg)](https://github.com/ShieldLabs-ai/shieldlabs-python/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/shieldlabs.svg)](https://pypi.org/project/shieldlabs/)

ShieldLabs identifies visitors and scores risk with device intelligence. New to ShieldLabs?
[Start free](https://app.shieldlabs.ai) and read the docs at
[docs.shieldlabs.ai](https://docs.shieldlabs.ai).

## How it fits

```
 1. Browser            2. Your backend                          3. Decision
 ShieldLabs agent ---> receives requestId with the signup,  ---> allow, step up,
 returns requestId     login or checkout; reads the verdict      review or refuse
                       with this SDK (History API) or gets it
                       as a signed identification.scored webhook
```

1. **Browser.** The ShieldLabs agent runs an identification and hands your page a request ID.
   The browser never sees a Risk Score, a visitor ID or a device ID.
2. **Your backend.** It receives the request ID together with the protected action and reads the
   verdict for it from the History API with this SDK, or receives the verdict by a signed
   webhook.
3. **Decision.** Your backend acts on `risk_score`, the three risk bands, `detection_flags` and
   the identifiers (for example, how many accounts share one `device_id`).

## Install

```bash
pip install shieldlabs
```

Python 3.9 or newer. The only dependency is [httpx](https://www.python-httpx.org/).

## Quick start

```python
import os
from typing import Optional

from shieldlabs import ShieldLabs, evaluate_identification, webhooks

client = ShieldLabs(api_key=os.environ["SHIELDLABS_API_KEY"])  # Private API Key, sec_...
used_request_ids: set[str] = set()  # use your database or cache in production


def allow_signup(request_id: str) -> bool:
    # 1. Read the identification for the request ID the browser sent with the form.
    #    Scoring is asynchronous, so this waits (up to 10 s by default) for the verdict.
    identification = client.identifications.get(request_id)

    # 2. Evaluate it: missing, reused, stale, rate-limited, automated or dangerous is refused.
    verdict = evaluate_identification(identification, is_replay=lambda rid: rid in used_request_ids)
    if identification is not None:
        used_request_ids.add(identification.request_id)
    return verdict.ok


def on_webhook(raw_body: bytes, signature_header: Optional[str]) -> None:
    # 3. Verify and parse a delivery: the raw body bytes and the X-Shield-Signature header.
    event = webhooks.construct_event(
        raw_body,
        signature_header,
        os.environ["SHIELDLABS_WEBHOOK_SECRET"],  # whsec_...
    )
    print(event.event_type)
```

A runnable FastAPI app that does all of this is in [`examples/`](examples/).

## Guide

### Wait for the verdict

Scoring is asynchronous. The History row for an identification appears about 1-3 seconds after
the browser call and can be refined for up to about 10 seconds while follow-up checks finish.
Start the identification in the browser when the user begins the action (for example when they
start filling in the signup form) rather than on submit, so the verdict is usually ready when
your backend asks for it. An identification older than `max_age` (5 minutes by default) counts
as stale, so start a new one when the user comes back later.

`identifications.get` polls the History API by `request_id` until the row appears and returns
that first version:

```python
identification = client.identifications.get(request_id)  # wait up to 10 s
identification = client.identifications.get(request_id, timeout=5)  # shorter budget
identification = client.identifications.get(request_id, wait=False)  # one lookup only

if identification is None:
    ...  # not scored in time: treat it as unverified, never as clean
```

How the wait works:

- **Total budget.** `timeout` (10 seconds by default) is the time budget of the whole call, not
  of one request.
- **Schedule.** The first poll runs immediately, then after waits of 0.25 s, 0.5 s, 1 s and
  1.5 s, then every 2 s. The last poll runs at the deadline. `poll_interval` (p, 0.25 s by
  default) sets the ladder: waits of p, 2p, 4p, 6p and 8p, then 8p again, each capped at
  2 seconds, or at p when p is longer. For example, `poll_interval=0.1` waits 0.1, 0.2, 0.4 and
  0.6 s, then every 0.8 s; `poll_interval=1` waits 1 s, then every 2 s; and `poll_interval=3`
  polls every 3 s.
- **One attempt per poll.** Each poll is a single HTTP request, never retried inside the poll.
  Its timeout is the client `timeout`, cut to the time left before the deadline but never
  shorter than 1 second.
- **Transient errors keep polling.** A `429`, a 5xx response, a connection error or a timeout
  does not end the wait: the next poll follows the schedule. If the last poll fails, its error
  is raised; if it answers without a row, the result is `None`.
- **After a `429`.** The next wait is the longest of the ladder step, 1 second (the History API
  limit is counted per second) and `Retry-After` capped at 10 seconds. A `Retry-After` of `0` or
  a date in the past counts as 0, so the 1-second minimum still applies. A wait that would pass
  the deadline is cut, and the last poll runs at the deadline. When the capped `Retry-After` is
  longer than the time left, the `RateLimitError` is raised at once.
- **Errors that stop at once.** A `400`, `401`, `403` or `404` ends the wait immediately and
  raises `BadRequestError`, `AuthenticationError` or `NotFoundError`.
- **`wait=False`** makes one lookup with the client's regular retries and returns `None` when
  there is no row yet.
- `request_id` must be a UUID. An invalid value raises `ValidationError` before any request.
- For the refined state (for example in a later review job), read the row again with
  `client.history.search("request_id", request_id, limit=1)`.

### Decide with `evaluate_identification`

`evaluate_identification` applies the checks our tutorials use before a protected action, in
this order, and reports the first one that fails:

| `reason` | Refused when |
|---|---|
| `missing` | there is no identification (unverified, never clean) |
| `replayed` | `is_replay(request_id)` returns `True` (one identification authorizes one action) |
| `stale` | `observed_at` is older than `max_age` (default 300 seconds) |
| `rate_limited` | the Risk Score is the rate-limit marker (above 100, in practice 999) |
| `no_device_signals` | the device ID is the all-zero UUID `00000000-0000-0000-0000-000000000000` |
| `blocked_flag` | a flag in `block_flags` is set (default `browser_automation`, `javascript_disabled`) |
| `blocked_band` | the risk band is in `block_bands` (default `dangerous`) |

```python
from datetime import timedelta

from shieldlabs import evaluate_identification

verdict = evaluate_identification(
    identification,
    max_age=timedelta(minutes=5),
    block_bands=["suspicious", "dangerous"],
    block_flags=["browser_automation", "javascript_disabled", "anti_detect_browser"],
    is_replay=replay_store.seen_before,
)
# Evaluation(ok=False, reason='blocked_flag', band='dangerous', flag='anti_detect_browser')
```

The defaults are a starting point: tune the bands, flags and freshness window for each action.
The SDK stores nothing, so keep used request IDs in your own store (for example a Redis
`SET key NX EX 600`) and pass a lookup as `is_replay`.

A visitor IP that sends too many identifications is blocked for 10 minutes. The block can show
up once as a separate identification with the marker 999 (`rate_limited`) and its own request
ID. Request IDs that the browser receives during the block get no History row at all, so they
end up as `missing`.

Risk bands are computed on the client from the score:

| Band | Risk Score |
|---|---|
| `trusted` | 0-29 |
| `suspicious` | 30-59 |
| `dangerous` | 60-100 |
| `rate_limited` | above 100: the rate-limit marker, not a score |

```python
from shieldlabs import is_rate_limited, risk_band

risk_band(45)  # 'suspicious'
is_rate_limited(999)  # True
identification.risk_band  # same helpers as properties
```

Branch on `risk_score` and `detection_flags`. Risk signal names (`identification.signals`) are
for display and logging: the set is open (`SignalName` lists known values), names can repeat,
and weights can be negative, so never add weights up yourself.

### The `Identification` model

Webhook deliveries and History API rows are normalized into one frozen dataclass with the webhook
field names:

| Field | Type | Notes |
|---|---|---|
| `request_id`, `visitor_id`, `device_id`, `session_id`, `cookie_id` | `str` | UUIDs; the all-zero UUID is possible |
| `user_hid` | `str` or `None` | your User HID; `"anonymous"` for anonymous checks |
| `domain` | `str` | the registered domain |
| `public_ip`, `local_ip` | `IpInfo(ip, country)` | IPv4 or `""`; `country` is an English country name such as `"Germany"`, or `""` |
| `connection_type` | `str` | `direct`, `mobile`, `vpn`, `proxy`, `tor`, `privacy_relay`, `browser_vpn_proxy`, `unknown` (unknown values are kept) |
| `os`, `browser`, `device_type` | `str` | |
| `traffic_source` | `TrafficSource` | `channel`, `referrer_domain`, `landing_url`, `click_id_type`, `utm_*`; `""` when absent |
| `risk_score` | `int` | 0-100, or 999 for the rate-limit marker |
| `signals` | `tuple[Signal, ...]` | `Signal(name, weight, description)`; `description` is set on History rows |
| `detection_flags` | `DetectionFlags` | 19 booleans; `.active()` lists the set ones |
| `observed_at` | `datetime` or `None` | timezone-aware UTC |
| `source` | `"webhook"` or `"history"` | |
| `raw` | `Mapping` | the original webhook `data` object or History row |

`identification.to_dict()` returns a JSON-ready dict and `Identification.from_dict()` reads it
back.

### Search history for account-abuse checks

`history.search` reads one page of identifications that share one identifier, newest first.
`history.iter` walks every page for you, removes rows repeated between pages (new
identifications can shift offsets) and stops at `total`, at an empty page or after `max_items`.

```python
page = client.history.search("user_hid", account_hid, limit=50)
print(page.total, len(page.data))

# How many accounts signed in from this device?
# User HID values that name no account (anonymous checks and sentinel values):
NOT_ACCOUNTS = (None, "anonymous", "fail", "-1", "unknown")

if identification.has_device_signals:  # the all-zero device ID matches unrelated rows
    accounts = {
        item.user_hid
        for item in client.history.iter("device_id", identification.device_id, max_items=500)
        if item.user_hid not in NOT_ACCOUNTS
    }
    if len(accounts) > 2:
        send_to_review(identification.request_id, accounts)
```

| `type` | `value` |
|---|---|
| `request_id`, `device_id`, `visitor_id`, `session_id`, `cookie_id` | a UUID (sent lowercase) |
| `user_hid` | a non-empty string, matched exactly and case-sensitively |
| `ip` | a dotted IPv4 address |

Arguments are validated before any request (`ValidationError`): unknown types, malformed UUIDs,
IPv6 addresses, `limit` outside 1-100, a negative `offset`, and a `user_hid` that is empty,
contains `/` or is `.` or `..`. Those User HIDs cannot be matched in the request path, so the SDK
refuses them instead of returning an empty page. Every other `user_hid` is percent-encoded in the
form the History API matches.

### User HID

Pass a stable, pseudonymous account ID to the browser agent instead of an email address or raw
account ID. `user_hid` derives one on your server:

```python
from shieldlabs import user_hid

hid = user_hid(str(account.id), user_hid_secret)  # 64 lowercase hex characters
```

It is HMAC-SHA256 keyed with a secret of your own (any server-side secret, separate from your
ShieldLabs keys). Keep it private and stable: changing it changes every User HID. The hex output
is always searchable with `history.search("user_hid", ...)`; if you build User HIDs another way,
avoid `/` (standard base64 contains it, base64url does not).

### Webhooks

ShieldLabs sends `identification.scored` to every enabled endpoint (register them in the
analytics dashboard under **Integration > Webhooks**). Each delivery carries
`X-Shield-Signature: sha256=<hex HMAC-SHA256 of the raw body>`, keyed with the endpoint signing
secret including its `whsec_` prefix.

```python
from typing import Optional

from shieldlabs import (
    IdentificationScoredEvent,
    SignatureVerificationError,
    WebhookParseError,
    WebhookPingEvent,
    webhooks,
)


def handle_delivery(raw_body: bytes, signature: Optional[str]) -> int:
    try:
        event = webhooks.construct_event(raw_body, signature, [current_secret, previous_secret])
    except SignatureVerificationError:
        return 401
    except WebhookParseError:
        return 400
    if isinstance(event, IdentificationScoredEvent):
        if already_processed(event.data.request_id):
            return 200
        enqueue(event.data)  # do slow work after responding
    elif isinstance(event, WebhookPingEvent):
        pass  # sent by the Verify button
    return 200  # unknown event types: acknowledge and ignore
```

- Verify the raw bytes exactly as received, before parsing. Re-serialized JSON does not match.
- `secret` can be a list: a delivery is valid when any secret matches, so you can rotate an
  endpoint secret without downtime.
- ShieldLabs sends one delivery per identification and endpoint, with a 1-second timeout and no
  retries. Respond with a 2xx within 1 second and do slow work afterwards.
- Make handlers idempotent on `data.request_id`: a future release retries deliveries, and a
  retry resends identical bytes.
- Use the History API for guaranteed reads and for the latest state: a delivery that fails is
  not sent again, and a History row can be refined after its webhook was sent.
- `construct_event` returns `IdentificationScoredEvent`, `WebhookPingEvent` or
  `UnknownWebhookEvent`, and never raises for an unknown event type. The **Test** delivery sent
  from the analytics dashboard parses like production traffic.

`webhooks.verify_signature(payload, signature_header, secret)` returns a bool when you only need
the check.

### Management API: domain profile

```python
from shieldlabs import ShieldLabsManagement

management = ShieldLabsManagement(
    secret_key=os.environ["SHIELDLABS_SECRET_KEY"],
    # Normalized before use: "https://www.Example.com/" becomes "example.com".
    domain=os.environ["SHIELDLABS_DOMAIN"],
)
profile = management.get_profile()
profile.remaining_identifications  # negative when the account is over its included volume
profile.public_key_masked  # "****************************a3f8"
```

The Management API allows about 15 requests per minute per caller IP and then blocks that IP
for 10 minutes. The client never retries a `429`, so call it sparingly and cache the profile.

### Rate limits

| API | Limit | What the SDK does |
|---|---|---|
| History API | about 15 requests per second per domain, shared by all your callers | `identifications.get` spaces its polls, and inside its wait a `429` waits at least 1 second (and at least `Retry-After`, up to 10 seconds). Ordinary calls (`history.search`, `history.iter`, `identifications.get` with `wait=False`) follow `Retry-After` as sent, up to 10 seconds, and wait at least 1 second after a `429` without it |
| Management API | about 15 requests per minute per IP, then a 10-minute block | raises `RateLimitError` without retrying |

### Async

`AsyncShieldLabs` and `AsyncShieldLabsManagement` mirror the sync clients:

```python
from shieldlabs import AsyncShieldLabs

async with AsyncShieldLabs() as client:  # reads SHIELDLABS_API_KEY
    identification = await client.identifications.get(request_id)
    async for item in client.history.iter("user_hid", account_hid, max_items=200):
        ...
```

### Configuration

| Option | Default | Notes |
|---|---|---|
| `api_key` | `SHIELDLABS_API_KEY` | Private API Key `sec_...`; a key of another shape triggers a `ShieldLabsWarning` |
| `base_url` | `SHIELDLABS_API_BASE_URL`, else `https://account.shieldlabs.ai` | the origin; a trailing `/api` is removed |
| `secret_key`, `domain` | `SHIELDLABS_SECRET_KEY`, `SHIELDLABS_DOMAIN` | Management client |
| `base_url` (Management) | `SHIELDLABS_MANAGEMENT_BASE_URL`, else `https://api.shieldlabs.ai` | |
| `timeout` | `10.0` | seconds per HTTP attempt |
| `max_retries` | `2` | retries for connection errors, timeouts, `429` (History only) and 5xx |
| `http_client` | a new `httpx.Client` / `httpx.AsyncClient` | pass your own for proxies or custom transports; it is not closed for you |

Base URLs must use https. Plain `http://` is accepted only for `localhost`, `127.0.0.1` and
`[::1]` (local test servers), because every request carries a key.

Clients are safe to share across threads (sync) or tasks (async): create one per process and
reuse it. Use them as context managers or call `close()` / `aclose()`.

For development and staging, register a separate domain (for example `dev.example.com`) and use
its keys with the default hosts.

## Reference

| Call | Returns |
|---|---|
| `ShieldLabs(api_key=None, base_url=None, timeout=10.0, max_retries=2, http_client=None)` | History API client |
| `client.identifications.get(request_id, wait=True, timeout=10.0, poll_interval=0.25)` | `Identification` or `None`; `timeout` is the total wait in seconds; `poll_interval` p sets the waits p, 2p, 4p, 6p, 8p, then 8p again, each at most 2 seconds, or p when p is longer |
| `client.history.search(type, value, limit=20, offset=0)` | `HistoryPage(data, total)` |
| `client.history.iter(type, value, page_size=100, max_items=None)` | iterator of `Identification`; `max_items=0` yields nothing |
| `AsyncShieldLabs(...)` | same methods as coroutines; `history.iter` is an async iterator |
| `ShieldLabsManagement(secret_key=None, domain=None, base_url=None, timeout=10.0, max_retries=2, http_client=None)` | Management API client |
| `management.get_profile()` | `DomainProfile` |
| `AsyncShieldLabsManagement(...)` | same method as a coroutine |
| `webhooks.verify_signature(payload, signature_header, secret)` | `bool` |
| `webhooks.construct_event(payload, signature_header, secret)` | `IdentificationScoredEvent`, `WebhookPingEvent` or `UnknownWebhookEvent` |
| `evaluate_identification(identification, *, max_age=300.0, now=None, block_bands=("dangerous",), block_flags=("browser_automation", "javascript_disabled"), is_replay=None)` | `Evaluation(ok, reason, band, flag)` |
| `risk_band(score)` | `"trusted"`, `"suspicious"`, `"dangerous"` or `"rate_limited"` |
| `is_rate_limited(score)` | `bool` |
| `user_hid(user_id, secret)` | 64-character lowercase hex `str` |

Models: `Identification`, `IpInfo`, `TrafficSource`, `Signal`, `SignalName`, `DetectionFlags`,
`HistoryPage`, `DomainProfile`, `Evaluation`. Type aliases: `LookupType`, `RiskBand`,
`EvaluationReason`, `WebhookEvent`.

## Errors and retries

| Exception | When |
|---|---|
| `ShieldLabsError` | base class of everything below |
| `ApiError` | any non-2xx response; has `status`, `message`, `body` (parsed JSON or text) and `headers` |
| `BadRequestError` | 400 |
| `AuthenticationError` | 401 or 403: wrong, rotated or disabled key |
| `QuotaExceededError` | 402. Neither the History API nor the Management API returns it today: an account over its included volume shows a negative `remaining_identifications` |
| `NotFoundError` | 404: usually a wrong base URL or path prefix |
| `RateLimitError` | 429; `retry_after` holds seconds when the server sent `Retry-After` |
| `ServerError` | 5xx |
| `APIConnectionError` | DNS, TCP, TLS or protocol failure |
| `APITimeoutError` | an attempt exceeded `timeout` |
| `SignatureVerificationError` | a webhook signature is missing or wrong |
| `WebhookParseError` | a verified webhook body is not an event envelope |
| `ValidationError` | an invalid argument, raised before any request (also a `ValueError`) |

Only GET requests are sent, and they are retried on connection errors, timeouts, `429` and 5xx
with exponential backoff and jitter (0.5 s base, doubling, capped at 8 s), up to `max_retries`
times. `Retry-After` is followed as sent, up to 10 seconds (`0` retries at once), and a `429`
without it waits at least 1 second (the History API limit is counted per second). `400`, `401`,
`402`, `403` and `404` are never retried, and the Management client never retries `429`. Inside
`identifications.get` a poll is never retried: the wait polls again on its schedule instead (see
[Wait for the verdict](#wait-for-the-verdict)).

```python
from shieldlabs import ApiError, AuthenticationError, RateLimitError

try:
    page = client.history.search("device_id", device_id)
except AuthenticationError:
    ...  # check SHIELDLABS_API_KEY
except RateLimitError as exc:
    ...  # exc.retry_after
except ApiError as exc:
    print(exc.status, exc.message)
```

Keys and request bodies are never logged. Each request carries
`User-Agent: shieldlabs-python/<version>` with the Python and httpx versions.

## Compatibility

- Python 3.9, 3.10, 3.11, 3.12 and 3.13 (CPython), tested in CI.
- httpx 0.25 or newer, below 1.0. The async client runs on asyncio and trio.
- Webhook `schema_version` `2026-06-01`. Other versions are parsed with a `ShieldLabsWarning`.
- Unknown fields and enum values in responses are tolerated and kept in `raw`.
- The package follows semantic versioning and ships type information (`py.typed`).

## Development

Refresh the generated client when the API description changes. This does not replace the supported library in this repository.

```bash
./sync.sh      # download the current OpenAPI description into resources/
./generate.sh  # rebuild generated/ from that file
```


```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ruff check . && ruff format --check . && mypy --strict src
pytest -q --cov=shieldlabs --cov-report=term-missing
```

`tests/data/` holds the shared test fixtures (History rows, webhook bodies, signature vectors,
error responses) that every ShieldLabs server SDK passes. See
[CONTRIBUTING.md](CONTRIBUTING.md). Questions and security reports: contact@shieldlabs.ai.

## License

[MIT](LICENSE)
