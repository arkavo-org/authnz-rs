---
paths:
  - "src/patreon.rs"
---

# patreon.rs

- Mirrors the Apple linking contract: minimum-PII row in `identity_links`
  (`patreon#<patreon_user_id> → arkavo_user_id`, conditional put for
  cross-account uniqueness) plus encrypted token bundle in
  `patreon_tokens`.
- `POST /oauth/patreon/link`: **Auth-required** link path (the *only* new
  endpoint surface for Patreon — there is deliberately no `/me/patreon`,
  `/entitlements/...`, or status endpoint). Body:
  `{ "code": "<oauth-code>", "redirect_uri": "<a registered redirect URI>",
  "role": "creator"|"consumer" }`. Behaviour:
    1. Verifies the inbound `X-Auth-Token` CWT (`sub` is the arkavo user_id).
    2. Resolves the registered Patreon client by `redirect_uri` (Patreon
       issues one client per app) and exchanges `code` at
       `https://www.patreon.com/api/oauth2/token` with that client's
       credentials. The issuing `client_id` is persisted with the token
       bundle so refresh uses the same client's secret.
    3. Fetches `/api/oauth2/v2/identity` to discover the Patreon `user.id`
       (and, for creators, the owned `campaign.id`).
    4. Conditional put on `identity_links` for per-Patreon-account
       uniqueness — HTTP 409 if the Patreon account is already linked to a
       *different* arkavo user; idempotent re-link to the same user.
    5. Persists the encrypted token bundle (access + refresh) in
       `patreon_tokens` keyed by arkavo `user_id`.
    6. Invalidates the membership materialization cache for the user.
- **Token sealing**: AES-256-GCM under a per-row 256-bit DEK; the DEK is
  KMS-wrapped using `PATREON_KMS_KEY_ID`. One wrapped DEK per row, distinct
  GCM nonces for the access vs refresh ciphertexts (never reuse key+nonce).
- **Membership materialization**: surfaced *only* on the OIDC access_token
  CWT as the `arkavo_patreon` claim. The OIDC token endpoint
  (`handle_authorization_code_grant` and `handle_refresh_token_grant`) calls
  [`materialize_for_user`] before minting; for consumers this queries
  Patreon's `/identity?include=memberships,...` and builds an
  `ArkavoPatreon { role, patreon_user_id, campaign_id?, memberships,
  verified_at, cache_expires_at }` snapshot; for creators it just embeds the
  stored `campaign_id`. Results are cached in Redis (with in-memory
  fallback) for `PATREON_CACHE_TTL_SECONDS` (5 min).
- **Fail-closed**: when Patreon is unreachable, the link is absent, or the
  cached snapshot is stale, the mint path **omits** the `arkavo_patreon`
  claim entirely — downstream KAS / policy enforcers must treat absence of
  the claim as "no entitlement".
- Patreon support is **optional**: with no Patreon clients registered (via
  `PATREON_CLIENT_<TAG>_ID/_SECRET/_REDIRECT_URIS` tagged vars or the legacy
  `PATREON_CLIENT_ID`/`PATREON_CLIENT_SECRET`/`PATREON_REDIRECT_URIS` trio),
  or with `PATREON_KMS_KEY_ID` unset, every Patreon code path is silently
  disabled and the link endpoint returns HTTP 503 NotConfigured. Malformed
  or ambiguous registrations (a tag missing `_SECRET`/`_REDIRECT_URIS`,
  duplicate client_id, a redirect URI claimed by two clients) also disable
  Patreon entirely — loud warn, fail-closed — rather than guessing which
  credentials to use.
