---
paths:
  - "src/publishing.rs"
  - "src/patreon.rs"
  - "src/publishing_tests.rs"
  - "src/market.rs"
  - "src/market/**/*.rs"
  - "src/app_store.rs"
  - "src/app_store_tests.rs"
  - "src/entities.rs"
  - "src/entitlements.rs"
  - "src/constants.rs"
---

# Derived entitlements, the market and the entity view

## publishing.rs: Creator-publishing entitlement (#91)

- `https://patreon.arkavo.com/attr/arkavo-creator/value/publish` is **derived
  at mint, never stored**: `oidc::arkavo_user_claims` (the one builder behind
  the passkey auth CWT, the DeviceCheck CWT and OIDC access tokens on code
  exchange *and* refresh) appends it to `arkavo_entitlements` while the
  account's Patreon snapshot shows an `active_patron` membership of
  `PATREON_PUBLISHER_CAMPAIGN_ID` at a tier in `PATREON_PUBLISHER_TIER_IDS`,
  **or** the snapshot's owned campaign (Patreon's answer, or the owner
  fallback's stored one) *is* `PATREON_PUBLISHER_CAMPAIGN_ID` (Arkavo's own
  account: Patreon does not let a creator pledge to itself),
  **or** a bound App Store Creator Membership is active (`app_store.rs`: a
  non-revoked record of a product configured for publishing, in an
  environment its app accepts, unexpired
  counting any billing-retry grace), **or** a linked market.arkavo.com
  lifetime claim still verifies (`market.rs`), and the account has no
  publishing suspension. One `get_publishing_state` read (the `credentials`
  row, strongly consistent) yields the suspension, the App Store records and
  the market links, and happens only when a source can grant. Fails closed.
- Carried in `ArkavoUserClaims::derived_entitlements`, so
  `mint_registration_token` drops it (~99-year token), and
  `entitlements::validate_fqns` refuses to store it (never delegable to
  agents). `GET /entities/arkavo:<uuid>` shows it because it derives it the
  same way a mint does, never because it is stored.
- `PUT`/`DELETE`/`GET /admin/users/:id/publishing-suspension`: service CWT on
  `MODERATION_CLIENT_IDS`; the suspension (`suspended_by`, `suspended_at`,
  `reason`, `report_id`) is a map attribute on the `credentials` row and is
  the audit record. See [docs/creator-publishing-entitlement.md](docs/creator-publishing-entitlement.md).
- **Online play (the Game Pass)**: `https://arkavo.net/attr/network/value/online-play`
  (`constants::ENTITLEMENT_ONLINE_PLAY`) is derived at the same place, on
  **its own path**: an active App Store record of a product configured as
  online-play (`app_store::Grant::OnlinePlay`) grants it and nothing else,
  and no publish source grants it. A publishing suspension does not remove
  it, and neither does a market outage (`publishing::Derived` carries what
  was granted beside `market_unavailable`; a mint keeps the former). The
  whole `https://arkavo.net/attr/network/` attribute is derived-only: never
  stored, delegated to an agent or put in the registration token, and
  **never in a token that lives longer than an hour** (a lapsed pass must
  stop within the hour; so never in a peer certificate, #143). A game
  server reads it from its own token (`game.rs`).
- **The market's prepaid terms** (`market/subscription.rs`, #151) are the
  second online-play source. With `MARKET_LOOKUP_TOKEN` set, every human
  mint asks `GET <MARKET_ISSUER>/subscriptions/<account uuid>` (bearer
  token), unless an App Store pass already grants. A `200` whose claim
  verifies (the pinned claim keys, `iss`, `aud`, `sub` = the account asked
  about, `tier` `online-play`, accepted `livemode`) grants; `404` grants
  nothing; anything else is a failure and grants nothing. The body's
  `until` is unsigned and never used. Rules:
  - An answer is cached 5 min, a failure 60 s, per account, in process.
  - **Circuit breaker:** after an **outage** (no response, a timeout, any
    status but 200 or 404, a body that is not the answer) no account is
    asked for 60 s (`Subscription::Unavailable`, never cached as "none");
    then one mint probes. A `200` whose claim does not verify is one
    account's failure: cached for that account, and the breaker stays
    closed, so one bad claim never stops everyone's lookups. So an outage costs one deadline a minute, not one per sign-in.
    A cached "active" still grants while the breaker is open.
  - **An outage withholds only the pass.** The mint succeeds, and so does
    `GET /entities` (200 without the value): unlike a linked membership
    claim that cannot be checked, a failed lookup is never a 503. No
    decision path reads the pass from `/entities`.
  - **A renewal rechecks a cached "none"** (`oidc::arkavo_user_claims_rechecking`:
    `POST /session/refresh`, a passkey sign-in, the OIDC refresh grant), at
    most `MARKET_SUBSCRIPTION_RECHECKS_PER_MINUTE` per account, so the
    refresh an app makes after a payment is not served the "none" cached
    before it. It never passes an open breaker.
  - A 401 means identity's token is wrong: logged as an error, treated as
    an outage.
  - The lookup runs beside the membership claim check and Patreon, inside
    the one mint deadline.
  - **A linked lifetime membership also grants online play**
    (`market::Tier::entitlements`), whatever the suspension.
  Contract: arkavo-com/market `docs/market-identity-interface.md`, "Account
  lookups (subscriptions)"; change it only with the market. `POST /app-store/transactions` answers the product's
  FQN as `entitlement`. See
  [docs/online-play-entitlement.md](docs/online-play-entitlement.md).
- **Patreon campaign entitlements** (`patreon::campaign_entitlements`, the
  same builder): for each `active_patron` membership with a numeric campaign
  id, `https://patreon.arkavo.com/attr/campaign/value/<campaign_id>` plus
  `.../attr/campaign-tier/value/<campaign_id>_<slug>` for every entitled tier,
  in **both** the title-slug form and the rename-proof `tier-<tier_id>` form
  (#42). A title slug shaped like the id form (`^tier-[0-9]+$`, e.g. a tier
  titled "Tier 10234567") is never emitted: it would unlock that other
  tier's id-tagged content. **Creator = owns a campaign, per Patreon** (#99):
  every materialization asks `/identity` for the owned `campaign` (when the
  link holds the `campaigns` scope) and derives `role` from the answer; the
  `role` a client sends to `/oauth/patreon/link` is ignored. An owner adds
  its campaign value and every tier of it, in both forms, so a creator can
  open their own gated content: the tiers come from
  `GET /campaigns/<cid>?include=tiers` and are saved on the `patreon_tokens`
  row (`campaign_tier_ids` / `campaign_tier_slugs`) so a failed fetch or the
  owner fallback keeps the last ones fetched.
  The only list anyone authorizes on: the platform and iroh grant from
  `arkavo_entitlements`; `arkavo_patreon` is for display (and iroh's
  publish check reads its `role` and `campaign_id`).
- **The token carries the subscription** (#128, owner decision
  2026-10-28): `arkavo_patreon` is never dropped. Each active membership
  adds `campaign_name` (Patreon `campaign.name`, ≤ 64 bytes) and
  `creator_sub` (the bare UUID of the account owning the campaign, from its
  `identity_links` row `patreon-campaign#<cid>`); a creator adds
  `owned_campaign {id, name?, tiers[{id, title?, amount_cents?,
  published?}]}` beside the unchanged top-level `campaign_id` (text) and
  `role`. A token carries at most `MAX_CLAIM_MEMBERSHIPS` (75) memberships,
  active only, Arkavo's publisher campaign first, and derives its campaign
  values from the same 75 (`patreon::claim_snapshot`, warn log when it
  drops any); the cached snapshot keeps them all. `owned_campaign.tiers`
  lists at most `MAX_CLAIM_OWNED_TIERS` (25; every owned tier still yields
  its entitlement values). A patron's CWT at the cap is about 44.8 KB, a
  creator's with 40 tiers about 56.9 KB, under the 64 KiB HTTP/2 header
  limit (`MAX_REQUEST_HEADER_LIST_BYTES`); the caps rise once the
  title-slug tier form is retired.
- **The whole `https://patreon.arkavo.com/` namespace is derived-only**
  (`constants::is_derived_only`): refused by `validate_fqns`, stripped from
  stored lists on read and from `effective_entitlements`, so none of it is
  ever stored or delegated to an agent. `GET /entities/arkavo:<uuid>` lists
  it only as the live, mint-time derivation (entities.rs), never from
  storage. So is the creator attribute below. The check ignores the host's letter case
  (`https://Patreon.arkavo.com/…` is derived-only too).
- **Creator attribute** (#117, `constants::creator_entitlement`):
  `https://arkavo.net/attr/creator/value/<uuid>`, the account's bare
  lowercase UUID (the catalog subject, never the `arkavo:` OIDC `sub`).
  `arkavo_user_claims` adds it to every account's own short-lived tokens,
  unconditionally, in `derived_entitlements` (so the registration token drops
  it); service accounts get none. App Store–only creators protect recordings
  and catalog metadata with it (tdf-iroh-s3#38). The platform defines it with
  no listed values, `anyOf` (opentdf-platform#64). No viewer is granted
  another creator's value yet.

## market.rs: market.arkavo.com lifetime membership (#141)

- Treated like Patreon (#91): identity stores only the link and asks the
  market at every mint (cached). It stores no purchase, price, refund or
  revocation, and the market pushes nothing. Contract: arkavo-com/market
  `docs/market-identity-interface.md`.
- `POST /market/link` (`X-Auth-Token` passkey CWT, live account), body
  `{"claim": "<jws>"}`: reads `jti` (`market#cs_live_…` / `market#cs_test_…`)
  from the pasted claim **unverified**, fetches the claim fresh and verifies
  that, then writes `identity_links` `market#<cs id>` → `user_id` (absent or
  already the caller's; a deleted owner's link moves) and `ADD`s the id to
  the `credentials` row's `market_links` set under `LIVE_ROW` (its failure
  deletes the link and answers 401). `identity_links` has no `user_id`
  index, so `market_links` is how a mint finds the links. 200 `{tier,
  entitlements, token_can_publish}`; 409 `already_linked` (another live
  account) or `revoked` (the market answers 410); 400 `invalid_claim` (404,
  no purchase id, a test-mode claim while test mode is off); 503
  `market_unavailable` (anything else, a fresh claim that does not verify
  included: that is an operator fault, not a bad paste; or unconfigured);
  429 `rate_limited` past `MARKET_LINK_FETCHES_PER_MINUTE` (5) link fetches
  per account (each link fetches fresh, and the market limits identity as
  one client).
- Claim checks (`verify_claim`): compact JWS, `alg` ES256, `typ` JWT, a
  pinned `kid`, the signature, `iss` = `MARKET_ISSUER`, `aud` =
  `OIDC_ISSUER`, `jti` = the link key, a known `tier` (`lifetime` ⇒ every
  paid entitlement: today the publish FQN and online play, each on its own
  path, so a publishing suspension leaves the second), `livemode` accepted and agreeing
  with the `jti` prefix. No `exp`: the claim is fetched fresh.
- At mint: each `market_links` id is fetched (`GET <issuer>/claim/<id>`,
  `Accept: application/json`, no credentials, redirects not followed,
  `MARKET_FETCH_DEADLINE_SECONDS`) **alongside** Patreon's materialization,
  not after it (`publishing::load_sources`). 200 and verified ⇒ grants; 410
  or 404 ⇒ nothing; anything else ⇒ nothing (fails closed, no last-good
  fallback, owner decision 2026-11-07). Outcomes are cached in process 5
  min, failures 60 s, a deadline miss included (a hung market must not make
  every mint wait); cached answers are read before any fetch. Asked while it can still decide publishing (no App Store membership grants it, not suspended) or online play (no App Store pass grants it): so a suspended account's links are fetched too, and `publishing::publishing` decides the suspension first, so that account's unreachable market is never a 503.
  `/entities` answers 503 `market_unavailable` when the market could not
  answer and no other source grants.
- A checkout session id is the purchase's bearer secret: never log it
  (`SessionId::log_ref`, a hash prefix, names it in logs).
- Deletion: the sweep's link step removes `market#` rows (they carry
  `user_id`); the tombstone drops `market_links`. The purchase is then free
  for another account.

## entities.rs: Service-gated entity lookup (spec §2.4)

- `GET /entities/:id`: Service-CWT gated; resolves entity by id namespace
- Id namespaces: `arkavo:<uuid>` (person), `did:key:…` (agent), `device:<key_id>` (device)
- Unknown namespace → HTTP 400 (BadId); missing entity → HTTP 404 (NotFound)
- Category mapping: Person → "subject"; Agent and Device → "environment" — with npe_type (None/"agent"/"device")
- Claims include authorization profile (entitlements, roles) and entity-specific metadata (device class, agent depth/chain)
- Gate: service CWT on `ENTITY_CLIENT_IDS` ∪ `ADMIN_CLIENT_IDS`
- **A person is the live view of a fresh mint** (0.26.0): its claims are
  what that account's own token would carry at that moment (any human
  token: Apple and Google sign-ins also carry roles `["user"]` and
  `sub` `arkavo:<uuid>`), from the same builder
  (`oidc::try_arkavo_user_claims_from`): `arkavo_entitlements` stored +
  derived (Patreon campaign/tier values, publish, creator) and
  `arkavo_patreon` as the token's map in JSON (#128's names, `creator_sub`
  and `owned_campaign` included). A service's escape hatch: no decision
  path calls it (the platform grants from the token; opentdf-platform#68
  closed unmerged). A Patreon-linked account for which nothing (cached, live or
  creator fallback) could be produced is 503 `{"error":"patreon_unavailable"}`,
  never a 200 without Patreon data: the resolver treats 503 as unavailable
  (keeps its last answer) and a 200 as a fresh negative. Likewise a failed
  publishing-state read is a 500 (`publishing::try_derived_entitlements`),
  never a 200 missing the publish value; a mint withholds it. So is a linked
  market purchase that could not be checked while no other source grants
  (#141): 503 `{"error":"market_unavailable"}`. Agents never get
  derived values. Contract agreed with the opentdf-platform session
  2026-10-27; change it only with them.
