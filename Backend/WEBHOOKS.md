# API keys and webhooks

## API-key scopes

Send API keys using `X-API-Key`. A request may use either this header or the
existing JWT `Authorization: Bearer` header, but not both.

Available scopes:

- `links:read` and `links:write` — list links, or create/update/delete links.
- `campaigns:read` and `campaigns:write` — list campaigns, or create/update/delete campaigns.
- `analytics:read` — read analytics and export click data.
- `qr_codes:read` and `qr_codes:write` — list QR configurations, or create/delete them.
- `domains:read` — list domains. Domain changes remain JWT-only.

API-key creation and management remain JWT-only. Keys are limited to 60
requests per minute. Configure a dedicated random `API_KEY_PEPPER` of at least
32 characters; do not reuse `JWT_SECRET`. Only a keyed hash is stored.

## Webhook signatures and retries

Webhook POSTs include `X-Shortie-Event-Id`, `X-Shortie-Event`,
`X-Shortie-Timestamp`, and `X-Shortie-Signature`. The signature format is
`sha256=<hex HMAC-SHA256>`, calculated over the exact raw request bytes:

```text
HMAC-SHA256(signing_secret, timestamp + "." + raw_request_body)
```

Compare signatures in constant time and reject timestamps more than five
minutes old. A test delivery uses event type `webhook.test`; production events
are `link.created`, `link.clicked`, and `link.deleted`. Delivery jobs are
persisted before the worker sends them and use bounded exponential retries.

Webhook destinations must use HTTPS on port 443 and resolve exclusively to
public IP addresses. The worker resolves and validates the destination again,
then pins the connection to the validated IP.

Configure an independent, random `WEBHOOK_SECRET_PEPPER` of at least 32
characters. Webhook signing secrets are derived from this pepper and a stored
random nonce; they are returned only once at webhook creation. Rotating this
pepper invalidates existing webhook signatures, so rotate only alongside
re-registering webhook secrets.

`WEBHOOK_WORKER_POLL_SECONDS`, `WEBHOOK_MAX_ATTEMPTS`,
`WEBHOOK_REQUEST_TIMEOUT_SECONDS`, and `WEBHOOK_WORKER_CONCURRENCY` control the
bounded worker and have safe application-side limits.
