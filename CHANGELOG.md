# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-10-05

### Added

- `sync.sh` downloads the OpenAPI description. Schema-derived wire fields now drive History,
  profile and webhook normalization, with generated request parameter types and CI checks
  for stale output and incompatible schema changes. Public models and tolerant decoding stay
  unchanged. The strict reference client in `generated/` remains separate.

## [1.0.0] - 2026-09-30

First stable release. It replaces the 0.1.0 preview package completely.

### Added

- `ShieldLabs` and `AsyncShieldLabs` History API clients: `history.search`, `history.iter`
  (de-duplicated on `request_id`) and `identifications.get`, which waits for the verdict:
  - `timeout` (10 s by default) is the total budget of the call. Polls run immediately, then
    after waits of `poll_interval` times 1, 2, 4, 6 and 8, then 8 again, each capped at 2 s, or
    at `poll_interval` when that is longer (0.25 s, 0.5 s, 1 s, 1.5 s and every 2 s by default;
    every 3 s for `poll_interval=3`), and a last time at the deadline.
  - Each poll is one HTTP attempt with a timeout of the client timeout cut to the time left,
    but at least 1 s.
  - A `429`, a 5xx response, a connection error or a timeout keeps it polling. The error of the
    last poll is raised at the deadline; `None` means the last poll found no row.
  - After a `429` the next wait is the longest of the ladder step, 1 s and `Retry-After`
    capped at 10 s (`Retry-After: 0` or a past date counts as 0), cut to the deadline. A capped
    `Retry-After` longer than the time left is raised at once.
  - `400`, `401`, `403` and `404` end the wait at once.
- `ShieldLabsManagement` and `AsyncShieldLabsManagement` with `get_profile()`. The domain is
  normalized before it is sent, and a `429` is never retried.
- `webhooks.verify_signature` and `webhooks.construct_event`. Both accept one signing secret or
  a list of secrets for rotation. Events are typed: `IdentificationScoredEvent`,
  `WebhookPingEvent` and `UnknownWebhookEvent`.
- One `Identification` model for webhook data and History rows: 19 detection flags, risk
  signals (with descriptions on History rows), timezone-aware `observed_at` and the original
  payload in `raw`. Also `DomainProfile`, `HistoryPage` and `SignalName`.
- Helpers: `risk_band`, `is_rate_limited`, `evaluate_identification` and `user_hid`.
- Error hierarchy including `QuotaExceededError`; retries with jittered exponential backoff and
  `Retry-After` as sent, up to 10 s (at least 1 s after a `429` without it); a
  `User-Agent: shieldlabs-python/<version>` header.
- Client-side validation of every History lookup. User HIDs are percent-encoded in the form the
  History API matches, and values that cannot be matched in the request path (`.`, `..` and
  anything that contains `/`) raise `ValidationError` instead of returning an empty page.
- Base URLs must use https; plain http is accepted only for `localhost`, `127.0.0.1` and `::1`.
- A FastAPI example, the shared test fixtures and CI on Python 3.9 to 3.13.

### Changed

- History requests go to `https://account.shieldlabs.ai/api/v1/history/...`. A custom base URL
  that ends in `/api` is accepted and the suffix is removed, so requests never reach
  `/api/api/...` (the preview built that URL and received a 404).
- httpx is the only runtime dependency. Python 3.9 is the minimum version.

### Removed

- `verify_webhook` and `ShieldLabsClient` from the preview. Use `webhooks.verify_signature` and
  `ShieldLabs().history.search` instead.

## [0.1.0] - 2026-09-06

Preview package with `verify_webhook` and a minimal History API client.

[Unreleased]: https://github.com/ShieldLabs-ai/shieldlabs-python/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ShieldLabs-ai/shieldlabs-python/releases/tag/v1.0.0
[0.1.0]: https://github.com/ShieldLabs-ai/shieldlabs-python/commits/main
