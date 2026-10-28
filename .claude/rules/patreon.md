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
  `{ "code": "<oauth-code>", "redirect_uri": "<a registered redirect URI>" }`.
  A `role` field is accepted and **ignored** (#99): whether a link is a
  creator's is whether Patreon says the account owns a campaign. The
  response's `role` reports that. Behaviour:
    1. Verifies the inbound `X-Auth-Token` CWT (`sub` is the arkavo user_id).
    2. Resolves the registered Patreon client by `redirect_uri` (Patreon
       issues one client per app) and exchanges `code` at
       `https://www.patreon.com/api/oauth2/token` with that client's
       credentials. The issuing `client_id` is persisted with the token
       bundle so refresh uses the same client's secret.
    3. Fetches `/api/oauth2/v2/identity` to discover the Patreon `user.id`
       and, when the granted scopes include `campaigns`
       (`?include=campaign`), the owned `campaign.id`. Stored `role` is
       `creator` with a campaign, else `consumer`.
    4. Conditional put on `identity_links` for per-Patreon-account
       uniqueness — HTTP 409 if the Patreon account is already linked to a
       *different* arkavo user; idempotent re-link to the same user.
    5. Persists the encrypted token bundle (access + refresh) in
       `patreon_tokens` keyed by arkavo `user_id`.
    6. Invalidates the membership materialization cache for the user.
- **`state` is the client's to verify, never the server's.** The link
  endpoint takes no `state`, and the scheme bounce
  (`GET /oauth/:client/patreon`, `main.rs`) holds none: it forwards
  Patreon's `state` to `<scheme>://oauth/patreon?code=…&state=…` (and on
  `error=`) so the app can compare it with the one it generated before it
  posts the code here (#129). A client that skips the compare lets a forged
  `code` link the attacker's Patreon account to the signed-in user.
- **Token sealing**: AES-256-GCM under a per-row 256-bit DEK; the DEK is
  KMS-wrapped using `PATREON_KMS_KEY_ID`. One wrapped DEK per row, distinct
  GCM nonces for the access vs refresh ciphertexts (never reuse key+nonce).
- **Membership materialization**: surfaced in tokens, as the
  `arkavo_patreon` claim, which the token always carries (#128: the signed
  CWT is the carrier, and tokens never drop it), and to services through
  `GET /entities/arkavo:<uuid>` (`ENTITY_CLIENT_IDS` ∪ `ADMIN_CLIENT_IDS`),
  which returns what a fresh mint would carry. Never
  through a user-facing endpoint. Every human token goes
  through the one builder `oidc::arkavo_user_claims` (passkey auth CWT,
  DeviceCheck CWT, OIDC access token on code exchange and refresh), which
  calls [`materialize_for_user_bounded`] (3 s deadline) before minting. For
  **every link** this makes one `/identity` read (refresh once on 401):
  `include=memberships,memberships.currently_entitled_tiers,memberships.campaign`
  with `identity.memberships`, plus `campaign` when the recorded scopes
  name `campaigns` (only then: asking without it could fail the whole
  read). It builds an `ArkavoPatreon { role, patreon_user_id, campaign_id?,
  memberships, owned_tiers, verified_at, cache_expires_at }` snapshot.
  **Ownership is re-read every time** (#99): `role=creator` and
  `campaign_id` exactly when Patreon reports an owned campaign, so a patron
  who launches a campaign is picked up within the cache TTL and one who no
  longer owns one becomes `consumer`. Without `campaigns` the stored
  campaign (a link made before #99) is kept as it was. A changed answer is
  written back to the row (`put_patreon_ownership`). The claim's shape is
  unchanged. Results are cached in Redis (with in-memory fallback) for
  `PATREON_CACHE_TTL_SECONDS` (5 min).
- **Scopes and fallback**: a link whose stored `scopes` are recorded and
  lack `identity.memberships` gets no memberships, and without `campaigns`
  either it is not queried at all; it must re-link to qualify for
  membership-derived entitlements. A link last seen owning a campaign whose
  read fails or misses the mint deadline gets `owner_fallback`: its stored
  campaign and tiers, no memberships (built before the Patreon work is
  spawned), cached for `PATREON_FAILURE_CACHE_TTL_SECONDS` (60 s). Any other
  link fails closed with no claim. A refresh whose `scope` is empty or a strict subset of the stored
  scopes keeps the stored scopes. A stored copy of the publish FQN in
  `credentials.entitlements` is dropped on every read.
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
- **Campaign entitlements** (`campaign_entitlements`, same builder): every
  `active_patron` membership with a numeric campaign id yields
  `https://patreon.arkavo.com/attr/campaign/value/<cid>` and, per entitled
  tier, `.../campaign-tier/value/<cid>_<slug>` **and**
  `.../campaign-tier/value/<cid>_tier-<tier_id>` (#42: a tier rename must not
  strand content tagged with the id form). A title slug matching
  `^tier-[0-9]+$` is dropped — "Tier 10234567" would otherwise impersonate
  tier 10234567's id form; the id form already covers the non-ASCII
  fallback. An owner (`role=creator`) adds its owned campaign value and
  **every tier of that campaign** in both forms (#99: Creator gates every
  archive on a tier, so the campaign value alone opens nothing). The tiers
  come from `GET /api/oauth2/v2/campaigns/<cid>?include=tiers&fields[tier]=title`
  (needs `campaigns`; a recorded scope list without it skips the call),
  read after `/identity` with the token that worked there (so a refreshed
  one). A changed campaign or tier list is written to the `patreon_tokens`
  row (`campaign_id`, `campaign_tier_ids` / `campaign_tier_slugs`, `role`;
  one conditional `UpdateItem` on the same Patreon user and `linked_at`). A
  failed tier read keeps the stored list (of the same campaign only), as do
  the owner fallback and a missed mint deadline, so a creator is never
  locked out of their own content by a Patreon outage. The owned tier ids
  and slugs feed entitlements only; the claim lists the ladder as
  `owned_campaign` (below). The platform's arkavo-mode ERS only lowercases, so values
  must be canonical: non-numeric ids and non-`slugify_tier` slugs are
  dropped. The whole `https://patreon.arkavo.com/` namespace is derived-only
  (`constants::is_derived_only`).
- **What the claim carries** (#128): each active membership's
  `campaign_name` and `creator_sub`, a creator's `owned_campaign`, at most
  75 memberships.
  - Reads: the `/identity` read adds `fields[campaign]=name` (every included
    campaign: the memberships' and the owned one); the tier read asks
    `fields[tier]=title,amount_cents,published`. A 400 to a read asking for
    them is retried once without them (`get_patreon_json`): a refused
    display field must never fail a mint. Such a snapshot, and one whose
    `creator_sub` read failed, is cached for
    `PATREON_FAILURE_CACHE_TTL_SECONDS` (60 s), not 5 min, so the names
    return soon. Text passes `display_text` (trimmed, no control
    characters, ≤ 64 bytes).
  - The owned campaign's name and ladder are stored on the `patreon_tokens`
    row (`campaign_name`, `campaign_tiers`) with the tier lists, so the
    owner fallback carries them in an outage; a read without a name keeps
    the stored one.
  - `creator_sub`: an `identity_links` row `patreon-campaign#<cid>` →
    `user_id` (`db/patreon_campaigns.rs`), claimed on every live
    materialization that sees the account own the campaign and at link
    (`attribute_not_exists(link_pk) OR user_id = :uid`; another account's
    claim is logged and its patrons get no `creator_sub`), and given up
    (conditional on `user_id`) when Patreon says the account owns another
    campaign or none. Each live snapshot batch-reads the rows for its
    active memberships (`with_creator_subs`) and is cached with them; a
    failed read leaves them unset. Account deletion removes the rows with
    the other links.
  - The cap: `claim_snapshot` (in the one claim builder) keeps active
    memberships only, Arkavo's publisher campaign first, then Patreon's
    order, at most `MAX_CLAIM_MEMBERSHIPS`, and the campaign values are
    derived from that same list. Publishing is derived from the full
    snapshot. `owned_campaign.tiers` lists at most `MAX_CLAIM_OWNED_TIERS`
    (25, filled from the ids when the ladder was never read); the owned
    tier ids stay whole, so every owned tier keeps its entitlement values.
  - `campaign_id` stays top-level text, creators only: iroh's v2 publish
    check reads it (and `role`) and refuses a number. Never move it into
    `owned_campaign`.
- **Fail-closed**: when Patreon is unreachable, the link is absent, or the
  cached snapshot is stale, the mint path **omits** the `arkavo_patreon`
  claim entirely — downstream KAS / policy enforcers must treat absence of
  the claim as "no entitlement". `/entities` must not collapse those cases:
  `materialize_for_user_resolved` returns `NotLinked` (200 without
  `arkavo_patreon`, a fresh negative), a snapshot, or `Unavailable` (linked,
  or the link read failed, and nothing was produced: 503
  `patreon_unavailable`, so the resolver keeps its last answer).
- Patreon support is **optional**: with no Patreon clients registered (via
  `PATREON_CLIENT_<TAG>_ID/_SECRET/_REDIRECT_URIS` tagged vars or the legacy
  `PATREON_CLIENT_ID`/`PATREON_CLIENT_SECRET`/`PATREON_REDIRECT_URIS` trio),
  or with `PATREON_KMS_KEY_ID` unset, every Patreon code path is silently
  disabled and the link endpoint returns HTTP 503 NotConfigured. Malformed
  or ambiguous registrations (a tag missing `_SECRET`/`_REDIRECT_URIS`,
  duplicate client_id, a redirect URI claimed by two clients) also disable
  Patreon entirely — loud warn, fail-closed — rather than guessing which
  credentials to use.
- **The sealer is shared**: `apple_tokens.rs` seals Sign in with Apple refresh
  tokens with the same `TokenSealer` (same `PATREON_KMS_KEY_ID`). Without
  that key, Apple token revocation is off too.
