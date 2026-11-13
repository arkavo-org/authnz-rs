# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAuthn-based authentication and authorization service built with Rust, Axum, and DynamoDB. The system provides passwordless authentication using FIDO2/WebAuthn passkeys, **CWT (COSE_Sign1, ES256) tokens for Arkavo-issued credentials, JWT for OIDC `id_token`**, and decentralized identity (DID) support.

**Protocol Support**: HTTP/1.1, HTTP/2 with TLS 1.3, and HTTP/3 (QUIC) when built with `--features http3`.
HTTP/2 accepts request header lists up to 64 KiB (`MAX_REQUEST_HEADER_LIST_BYTES`,
`main.rs` `connection_builder`, both TCP listeners); hyper's 16 KiB default
refused a patron's passkey CWT past about 37 active Patreon memberships
(about 400 bytes each); a larger list gets 431. Keep it at or above the
largest token identity mints.

## Development Commands

Local key generation and DynamoDB table setup: the `local-dev-setup` skill.

### Running the Server

```bash
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem
export AGENT_TOKEN_AUDIENCES=https://platform.arkavo.net
cargo run   # HTTP on :8080; set TLS_CERT_PATH + TLS_KEY_PATH for HTTPS
```

Production runs from `production/start.sh` (the authoritative env for
identity.arkavo.net) via `production/build.sh`; see
[docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

### Configuration Reference

All configuration is via environment variables. Only the four above are
required at boot; everything else is optional and its feature is disabled
when unset.

| Variable | Purpose |
|---|---|
| `SIGN_KEY_PATH`, `ENCODING_KEY_PATH`, `DECODING_KEY_PATH` | EC P-256 keys (attestation envelope; CWT/JWT sign + verify). Encode/decode must be the same key pair or boot fails. |
| `VERIFY_ONLY_KEY_PATHS` | Comma-separated SPKI PEM paths of extra P-256 public keys that verify but never sign: the next key, published before a rotation, or a retired one, kept while its tokens and attestations must verify (#107). Published in `cose-keys` and `jwks.json` after the current key. A key equal to the current one, a duplicate, or a file that does not parse fails startup. Runbook: [docs/key-rotation.md](docs/key-rotation.md). |
| `AGENT_TOKEN_AUDIENCES` | **Required.** Comma-separated `aud` for agent CWTs from `POST /agents/token`. Use the audience your verifier checks (normally `OIDC_PLATFORM_AUDIENCE`). **Every agent token carries the whole list**: there is no per-request audience, so adding a verifier (the market's request API wants `https://market.arkavo.com`) makes every agent token valid there too. Each verifier must therefore require its own entitlement and proof of possession. |
| `AGENT_AUTHORIZED_ACTORS`, `AGENT_TOKEN_MINUTES` | Optional `act` claim and agent CWT lifetime (clamped to 15). |
| `ADMIN_CLIENT_IDS` | OIDC client_ids (service CWT `sub` = `client:<id>`) allowed on `PUT /admin/users/:id/entitlements` and `GET /entities/:id`. Empty ⇒ 403. |
| `ENTITY_CLIENT_IDS` | client_ids whose service CWTs may call `GET /entities/:id` only (read-only; production: `opentdf-platform`, the platform ERS's live Patreon source). `ADMIN_CLIENT_IDS` are accepted there too. Never put a resolver on the admin list: that also grants `PUT` entitlements. |
| `AGENT_DELEGATE_CLIENT_IDS` | OIDC client_ids that may request the `agents:delegate` scope, and whose access tokens `POST /agents/authorize` (and quarantine, recover and appraisal) accept as `Authorization: Bearer` (production: `arkavo-edge`). Empty ⇒ the scope is refused for every client. |
| `AGENT_STATUS_CLIENT_IDS` | client_ids whose service CWTs may call `GET /agents/:did/status` (intended for the platform entity resolver's `agent_status` client). Empty ⇒ 403, and the platform withholds every agent's entitlements. |
| `AGENT_OWNER_APPRAISAL_TTL_SECONDS`, `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` | Appraisal lifetimes: owner default 43200 (12 h), at most 86400; Guardian default and maximum 900. Out of range fails startup. |
| `MODERATION_CLIENT_IDS` | client_ids whose service CWTs may set, lift and read publishing suspensions (`PUT`/`DELETE`/`GET /admin/users/:id/publishing-suspension`). Empty ⇒ 403. See `docs/creator-publishing-entitlement.md`. |
| `OWNER_KAS_RELAY_CLIENT_IDS` | client_ids whose service CWTs may read owner-KAS routes and remove unregistered push tokens (`GET /owner-kas/routes/:id/relay`, `DELETE …/relay/push`; #148). Production: `owner-kas-relay`, the relay's (arkavo-rs) own client, never `arks-media`. Empty ⇒ 403 (startup warns). |
| `PATREON_PUBLISHER_CAMPAIGN_ID`, `PATREON_PUBLISHER_TIER_IDS` | Arkavo's own Patreon campaign id and the comma-separated Patreon **tier IDs** (not titles) that grant the derived creator-publishing entitlement `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`. Both required; either unset/empty ⇒ never granted. State logged once at startup. |
| `APP_STORE_BUNDLE_ID`, `APP_STORE_APP_APPLE_ID`, `APP_STORE_PUBLISH_PRODUCT_IDS` | App Store Creator Membership. Bundle id (`com.arkavo.ArkavoCreator`), the app's numeric Apple ID (required on Production notifications) and the comma-separated auto-renewable product ids that grant the derived creator-publishing entitlement. This is the first (untagged) app; all three are required for it. With no usable app at all (this one or a tagged one, below) the feature is off (startup log line) and `POST /app-store/transactions` / `/app-store/notifications` answer 503. No new table. |
| `APP_STORE_<TAG>_BUNDLE_ID`, `_APP_APPLE_ID`, `_PUBLISH_PRODUCT_IDS`, `_ONLINE_PLAY_PRODUCT_IDS`, `_ENVIRONMENTS`; `APP_STORE_ONLINE_PLAY_PRODUCT_IDS` | Further App Store apps, one per operator-chosen `<TAG>` (never in a token), each with the untagged variables' meaning for its own bundle. **A product grants exactly one entitlement**: a `_PUBLISH_PRODUCT_IDS` product grants creator publishing, an `_ONLINE_PLAY_PRODUCT_IDS` product grants `https://arkavo.net/attr/network/value/online-play` (the Game Pass) and nothing else. An app needs its bundle id, Apple ID and at least one product. A tagged app that is incomplete, repeats a bundle id or product id of the untagged app, or lists a product in both lists is skipped (error log); two tagged apps that share a bundle id or product id are both skipped. The other apps stay on. The untagged `APP_STORE_ONLINE_PLAY_PRODUCT_IDS` adds online-play products to the untagged app. |
| `APP_STORE_ENVIRONMENTS` | Comma-separated, default `Production,Sandbox`; only those two values are accepted. Sandbox is accepted on prod by owner decision (App Review buys there); every Sandbox grant is logged with `env=Sandbox`. `Xcode` and `LocalTesting` are always refused. |
| `MARKET_ISSUER`, `MARKET_CLAIM_KEYS_PATH`, `MARKET_ACCEPT_TEST_MODE` | market.arkavo.com lifetime membership (#141, `market.rs`). `MARKET_ISSUER` (`https://market.arkavo.com`) is the claims' `iss` and the base of `<issuer>/claim/<checkoutSessionId>`. `MARKET_CLAIM_KEYS_PATH` is a JWK Set file of the **pinned** P-256 claim keys; each `kid` must be its RFC 7638 thumbprint. The market's `/.well-known/jwks.json` is a rotation channel to read, never a trust anchor. The expected `aud` is `OIDC_ISSUER`. `MARKET_ACCEPT_TEST_MODE=true` accepts Stripe test-mode claims (default off). The first two are required; either unset ⇒ off (startup log line) and `POST /market/link` answers 503. A set but unusable value also leaves it off (warn). |
| `MARKET_LOOKUP_TOKEN` | The secret identity sends the market as `Authorization: Bearer` on `GET <MARKET_ISSUER>/subscriptions/<account uuid>` (the Game Pass's prepaid terms, #151). The same value as the market's `IDENTITY_LOOKUP_TOKEN`: at least 32 printable ASCII characters, no spaces. Needs `MARKET_ISSUER` and `MARKET_CLAIM_KEYS_PATH`. Unset ⇒ no lookup (startup log line); set but unusable ⇒ no lookup (warn, the value is never logged). **Setting it turns the lookup on for every human mint.** Rotate both sides together. Never log it. |
| `GAME_TOKEN_AUDIENCES`, `GAME_TOKEN_SECONDS` | Game-server tokens (#151, `game.rs`). `GAME_TOKEN_AUDIENCES` is the comma-separated `aud` values `POST /game/token` may mint for, one per game server (production: `https://game.arkavo.net`); the client names one. Unset ⇒ off (startup log line) and the route answers 503. A value that is `arkavo`, `OIDC_PLATFORM_AUDIENCE`, an OIDC client id or an `AGENT_TOKEN_AUDIENCES` member, starts with `arkavo:` or `owner-kas:`, or is not 1–128 printable ASCII characters without space or comma fails startup: the audience is the only thing that keeps a game token out of a verifier that ignores the content type (the OpenTDF platform's does). `GAME_TOKEN_SECONDS` is the lifetime, default 900, 60 to 3600; out of range fails startup. |
| `USER_DEFAULT_ENTITLEMENTS` | Override the default entitlement FQNs written to new user rows. May not contain the creator-publishing FQN (derived only). |
| `PORT`, `BIND_ADDRESS` | Defaults `8080`, `0.0.0.0`. |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | PEM chain + key. Setting either enables HTTPS. |
| `ENABLE_HTTP3` | QUIC listener on UDP/`PORT` (binary built with `--features http3`, TLS required). |
| `DYNAMODB_*_TABLE` | `CREDENTIALS`, `HANDLES`, `DEVICE_BINDINGS`, `IDENTITY_LINKS`, `PATREON_TOKENS`, `AGENT_DELEGATIONS`, `DEVICE_ATTEST_KEYS`, `GUARDIANS`. Default to the unprefixed table names in the DynamoDB Schema section. |
| `AWS_REGION`, `AWS_ENDPOINT_URL_DYNAMODB` | Standard AWS SDK settings (`load_defaults`); the endpoint override points at local DynamoDB. |
| `REDIS_URL` | Cache for Patreon snapshots and pending Google logins; in-memory fallback when unset. |
| `OIDC_ISSUER` | Issuer URL in tokens and the discovery doc. Required to act as an OIDC IdP. |
| `OIDC_CLIENT_<TAG>_ID`, `_REDIRECT_URIS`, `_SECRET` | One relying party per tag. `<TAG>` is operator-chosen and never appears in tokens. Omit `_SECRET` for public PKCE-S256 clients. A client_id of `arkavo` (the passkey CWT audience) fails startup. `_REDIRECT_URIS` is exact-match and required even for `client_credentials` service clients (use a dummy URI). See `docs/pep-service-clients.md`, `docs/google-signin.md`. |
| `OIDC_PLATFORM_AUDIENCE` | Extra `aud` appended to every OIDC access token so any RP's token passes the OpenTDF platform's single-audience check. Also the only `resource` value (besides the client id) accepted under RFC 8707. `arkavo` (the passkey CWT audience) fails startup. |
| `APPLE_CLIENT_ID` | Comma-separated iOS bundle ids / web Service IDs whose id_tokens are accepted. |
| `APPLE_TEAM_ID`, `APPLE_SIWA_KEY_ID`, `APPLE_SIWA_PRIVATE_KEY_PATH` (or `APPLE_SIWA_PRIVATE_KEY`, the PEM itself; not both) | Sign in with Apple token revocation (TN3194, `apple_tokens.rs`). The team's Sign in with Apple key signs the ES256 client secret for Apple's `/auth/token` and `/auth/revoke`. Needs `PATREON_KMS_KEY_ID` too: the refresh tokens are sealed with the Patreon KMS sealer. All set ⇒ `POST /oauth/apple/link` requires `authorization_code` and account deletion revokes the stored tokens. Otherwise links are stored without a token, as before (startup warns; logs an error when the key is set but invalid, or the sealer is missing). The token is stored on the `identity_links` row; no table of its own. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Sign in with Google for `idp=google`. Both id and secret required or the flow fails closed. Redirect defaults to `<OIDC_ISSUER>/oauth/google/callback`. |
| `PATREON_CLIENT_<TAG>_ID`, `_SECRET`, `_REDIRECT_URIS`; `PATREON_KMS_KEY_ID` | One Patreon OAuth client per tag (legacy untagged `PATREON_CLIENT_ID/_SECRET/_REDIRECT_URIS` still works). A redirect URI may belong to one client only. Any malformed registration or missing KMS key disables Patreon entirely (link and unlink endpoints ⇒ 503). |
| `APP_ATTEST_APP_ID` | **Comma-separated set** of hex SHA-256 of `<TeamID>.<BundleID>`, one per app that registers users. An attestation is accepted when its `rpIdHash` matches any member; a single value is a one-element set. When non-empty, `POST /device-check/attest` enforces the match. Unset ⇒ recorded but not enforced (warns). **Mandatory on the registration-gate path**, where unset fails closed. |
| `WEBVH_SIGN_KEY_PATH` | Ed25519 key file for did:webvh minting and handle-binding updates (`--features webvh`). Unset ⇒ no new signed entries; existing logs still resolve. See `docs/did-handle-binding.md`. |
| `SITE_ASSETS_DIR` | Directory holding the operator's home page and site icons (`index.html`, `apple-touch-icon.png`, `favicon-32x32.png`, `favicon.ico`), served at `/` and the icon paths (`site.rs`, #138). Read once at boot. Unset ⇒ those paths answer 404. A directory that cannot be read, or holds none of the files, fails startup. |

## Architecture

Per-module detail lives in path-scoped rule files under `.claude/rules/`,
loaded when a matching file is read. Wire contracts live in `docs/`; a
contract changes only with the teams that build against it.

| Area | Source | Rules | Contract |
|---|---|---|---|
| Passkey registration and sign-in | `authn.rs` | `authn.md` | |
| OIDC provider, OAuth bounce | `oidc.rs`, `main.rs` | `oidc.md` | `docs/pep-service-clients.md` |
| Apple and Google sign-in (link-only) | `apple_signin.rs`, `apple_tokens.rs`, `google_signin.rs`, `identity.rs` | `federated-signin.md` | `docs/google-signin.md` |
| Patreon link and snapshot | `patreon.rs` | `patreon.md` | |
| Agent delegation, trust state, Guardians | `agent.rs`, `agent_state.rs`, `guardian.rs` | `agents.md` | `docs/agent-credentials-contract.md` |
| App Attest / DeviceCheck | `device_check.rs` | `device-check.md` | `docs/app-attest-preflight-contract.md` |
| Derived entitlements, App Store, market, entity view | `publishing.rs`, `app_store.rs`, `market.rs`, `market/`, `entities.rs`, `entitlements.rs` | `entitlements.md` | `docs/creator-publishing-entitlement.md`, `docs/online-play-entitlement.md` |
| Owner KAS token and routes | `owner_kas*.rs` | `owner-kas.md` | `docs/owner-kas-token.md`, `docs/owner-kas-routes.md` |
| Game-server token and game sessions | `game.rs`, `game_token.rs` | `game.md` | `docs/game-token.md` |
| Passkey sessions, credential attestations | `session.rs`, `passkeys.rs`, `credential_attestation.rs` | `sessions-passkeys.md` | `docs/session-renewal.md`, `docs/passkey-credential-attestation.md` |
| Account deletion | `account.rs`, `db/account.rs` | `account-deletion.md` | `docs/account-deletion.md` |
| DynamoDB tables and rows | `db.rs`, `db/` | `dynamodb-schema.md` | |
| Operator home page and icons | `site.rs` | `site.md` | |
| Server edge: connection, time, size and rate limits, response headers | `edge.rs`, `main.rs` | | |
| did:webvh passports, handle bindings | `webvh.rs` | `webvh.md` | `docs/did-handle-binding.md` |

Before changing a module, read its rule file even if the tool did not load
it. When a change adds a rule, put it in that file, not here; this file
holds only what applies across modules.

### Rules that apply everywhere

- **Accounts are created by passkey registration alone.** Apple and Google
  sign-in reach an account only through its `identity_links` row and never
  provision one.
- **The handle is permanent and never issued twice; the username is a
  changeable label.** Read `UserCredentials::handle`, never re-derive it.
- **Every write to a `credentials` row carries `LIVE_ROW`**
  (`attribute_exists(user_id) AND attribute_not_exists(deleted_at)`).
- **Tokens outlive the account, so every path that trusts a token re-checks
  the row** (`DynamoDBStore::is_account_live` / `get_user_by_id`). A new
  token-accepting path must do the same.
- **A "recent passkey assertion" check reads `cwt::passkey_assertion_time`**
  (`auth_time`, else `iat`), never `iat` alone: a renewed token must not
  pass for a fresh sign-in.
- **`cwt::verify` refuses any protected content type and any `typ` claim.**
  Every purpose token (owner-KAS, game, credential attestation) is typed so
  it can never pass as a sign-in token. Keep any new verifier refusing
  typed CWTs, and give any new purpose token a content type and an
  audience no untyped token carries.
- **A device or agent key signs only messages that start with a fixed
  context line**, one context per purpose.
- **Derived-only entitlements are never stored or delegated**: the whole
  `https://patreon.arkavo.com/` namespace, the creator attribute and
  `https://arkavo.net/attr/network/` are derived at mint
  (`constants::is_derived_only`). Online play rides only in tokens that
  expire within an hour.
- **Identity only entitles; it holds no purchase policy.** The market
  entitlements (`…/market/value/request`, `…/market/value/pay`) let an
  agent ask or attempt. What may be bought, for how much and how often is
  the market's, never stored, signed into a token or enforced here (owner
  decision 2026-11-10).
- **Rows that are an identity are retired or revoked, never deleted**:
  handles, passkey index rows, owner-KAS routes, agent delegations,
  Guardians.
- **No new DynamoDB table for 1:1 data**: it goes on the existing row.
- **Edge limits live in `edge.rs`.** A new unauthenticated route that
  makes the server hold state or sign joins a per-peer rate-limit group; a
  route that needs a body over 64 KiB sets its own `DefaultBodyLimit`. The
  peer is the socket address, never `X-Forwarded-For`.
- **Never log a bearer secret**: a market checkout session id
  (`SessionId::log_ref`), `MARKET_LOOKUP_TOKEN`, tokens.
- **authnz-rs carries no branding.** Any organization can deploy it; logos
  and page text come from operator files, never from the repository.
- **Test keys, claims and fixtures are generated in test setup**, never
  committed.
- **Every fix or feature bumps `Cargo.toml`'s version in the same commit**
  (patch for a fix, minor for a feature).

### Security Architecture

**Token Strategy**:
- **Arkavo-issued tokens** (registration, auth, DeviceCheck assertion, OIDC access_token):
  - **Format**: CWT (CBOR Web Token, RFC 8392) using COSE_Sign1 + ES256.
  - **Inbound JWT is rejected** on all Arkavo authentication paths (hard cutover — no dual-format support).
  - **Validation**: exp/iat enforced with ±60s skew. Algorithm restricted to ES256.
- **OIDC `id_token`**: JWT (ES256). Required by OIDC Core spec.
- **Apple `id_token`** (inbound): JWT validation against Apple's JWKS.
- **Key advertisement**:
  - `/.well-known/jwks.json` — JWKS for `id_token` verifiers (OIDC RPs).
  - `/.well-known/cose-keys` — COSE_Key Set for CWT verifiers (OpenTDF, native).
  - Same `kid` (RFC 7638 thumbprint) in both formats — JWKS advertises the base64url-encoded form; COSE_Key uses raw 32-byte hash.
  - Both list the **key set** (`keys::KeySet`): the current signing key first,
    then every `VERIFY_ONLY_KEY_PATHS` key. Every inbound CWT is verified by
    looking up its protected-header `kid` in the set (`cwt::verify`); an
    absent or unknown `kid` is `CwtError::UnknownKey`. Only the current key
    signs.
- **Discovery doc** (`/.well-known/openid-configuration`) advertises `access_token_format: "application/cwt"` and `cose_keys_uri` for CWT-aware RPs.
- **PoP**: `cnf` claim (RFC 8747) populated bound-at-issuance with the WebAuthn passkey COSE_Key, App Attest key or agent Ed25519 key. authnz-rs never verifies PoP; the platform KAS will enforce it (DPoP) for agent tokens once opentdf-platform P1 lands (a contract v1 consumer).

**WebAuthn Protection**:
- All authentication requires valid WebAuthn ceremony
- Passkeys stored in DynamoDB with user credentials
- Session-based state management prevents replay attacks
- Sessions expire after 10 minutes of inactivity

**Cryptographic Keys**:
- **TLS Keys** (optional, for HTTPS):
  - `TLS_CERT_PATH`: X.509 certificate chain in PEM format (fullchain.pem)
  - `TLS_KEY_PATH`: Private key in PEM format (privkey.pem)
  - If omitted, server runs over unencrypted HTTP
- **WebAuthn/CWT Keys** (required):
  - Signing key: ECDSA P-256 for attestation envelope signatures
  - Encoding/Decoding keys: ES256 for CWT/JWT generation and verification
  - Keys loaded from PEM files specified in environment variables

## Important Constants

When modifying token lifetimes, update these in authn.rs:
- Registration token: `chrono::Duration::weeks(5148)` (~99 years)
- Authentication token: `PASSKEY_SESSION_TOKEN_SECONDS` (3600 s; becomes
  900 s once clients renew, #108). Used only by `mint_auth_token` and the
  session renewal; DeviceCheck keeps `AUTH_TOKEN_HOURS`.
- Session: `SESSION_IDLE_SECONDS` (3600), `SESSION_MAX_SECONDS` (86400);
  the enforced `SESSION_IDLE_LIMIT_SECONDS` is never below
  `PASSKEY_SESSION_TOKEN_SECONDS` + skew + `SESSION_RENEWAL_GRACE_SECONDS`
  (asserted at compile time), or the renewal an expired token's 401
  prompts is refused as idle.
- Game session: `GAME_SESSION_SECONDS` (2592000, 30 days from the passkey
  assertion, no idle limit). Only the game-token mint may read it.
- Session timeout: `Duration::seconds(600)` (10 minutes)
- Passkey enrollment freshness: `ENROLLMENT_TOKEN_MAX_AGE_SECONDS` (300s).
  Must stay below the auth token lifetime — asserted at compile time in
  authn.rs — otherwise "freshly minted" degrades into "not yet expired".
