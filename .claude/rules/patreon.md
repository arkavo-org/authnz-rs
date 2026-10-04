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
- **Membership materialization**: surfaced *only* in tokens, as the
  `arkavo_patreon` claim, never through an endpoint. Every human token goes
  through the one builder `oidc::arkavo_user_claims` (passkey auth CWT,
  DeviceCheck CWT, OIDC access token on code exchange and refresh), which
  calls [`materialize_for_user_bounded`] (3 s deadline) before minting. For
  **both roles** this queries Patreon's
  `/identity?include=memberships,memberships.currently_entitled_tiers,memberships.campaign`
  (refresh once on 401) and builds an `ArkavoPatreon { role,
  patreon_user_id, campaign_id?, memberships, verified_at,
  cache_expires_at }` snapshot; a creator's snapshot also keeps its stored
  owned `campaign_id`. Results are cached in Redis (with in-memory
  fallback) for `PATREON_CACHE_TTL_SECONDS` (5 min).
- **Creator links and `identity.memberships`**: a creator whose stored
  `scopes` are recorded and lack `identity.memberships` is not queried (the
  snapshot has the campaign and no memberships) and must re-link to qualify
  for membership-derived entitlements. A creator whose fetch fails gets its
  campaign claim with no memberships, **not cached**, so the next mint
  retries.
- **Creator-publishing entitlement** (#91, `src/publishing.rs`):
  `https://patreon.arkavo.com/attr/arkavo-creator/value/publish` is appended
  to `arkavo_entitlements` at mint while a membership of Arkavo's campaign
  (`PATREON_PUBLISHER_CAMPAIGN_ID`) is `active_patron` at a tier ID in
  `PATREON_PUBLISHER_TIER_IDS` and the account is not suspended. Only
  `memberships[]` counts — owning the campaign is not membership. Derived,
  never stored in `credentials.entitlements`, never in the registration
  token; a suspension (`/admin/users/:id/publishing-suspension`, moderation
  service CWT) overrides membership. The suspension GET returns the
  suspension record only, never membership state.
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
