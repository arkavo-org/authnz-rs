# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAuthn-based authentication and authorization service built with Rust, Axum, and DynamoDB. The system provides passwordless authentication using FIDO2/WebAuthn passkeys, **CWT (COSE_Sign1, ES256) tokens for Arkavo-issued credentials, JWT for OIDC `id_token`**, and decentralized identity (DID) support.

**Protocol Support**: HTTP/1.1, HTTP/2 with TLS 1.3, and HTTP/3 (QUIC) when built with `--features http3`.

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
| `AGENT_TOKEN_AUDIENCES` | **Required.** Comma-separated `aud` for agent CWTs from `POST /agents/token`. Use the audience your verifier checks (normally `OIDC_PLATFORM_AUDIENCE`). |
| `AGENT_AUTHORIZED_ACTORS`, `AGENT_TOKEN_MINUTES` | Optional `act` claim and agent CWT lifetime (clamped to 15). |
| `ADMIN_CLIENT_IDS` | OIDC client_ids (service CWT `sub` = `client:<id>`) allowed on `PUT /admin/users/:id/entitlements` and `GET /entities/:id`. Empty ⇒ 403. |
| `ENTITY_CLIENT_IDS` | client_ids whose service CWTs may call `GET /entities/:id` only (read-only; production: `opentdf-platform`, the platform ERS's live Patreon source). `ADMIN_CLIENT_IDS` are accepted there too. Never put a resolver on the admin list: that also grants `PUT` entitlements. |
| `AGENT_DELEGATE_CLIENT_IDS` | OIDC client_ids that may request the `agents:delegate` scope, and whose access tokens `POST /agents/authorize` (and quarantine, recover and appraisal) accept as `Authorization: Bearer` (production: `arkavo-edge`). Empty ⇒ the scope is refused for every client. |
| `AGENT_STATUS_CLIENT_IDS` | client_ids whose service CWTs may call `GET /agents/:did/status` (intended for the platform entity resolver's `agent_status` client). Empty ⇒ 403, and the platform withholds every agent's entitlements. |
| `AGENT_OWNER_APPRAISAL_TTL_SECONDS`, `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` | Appraisal lifetimes: owner default 43200 (12 h), at most 86400; Guardian default and maximum 900. Out of range fails startup. |
| `MODERATION_CLIENT_IDS` | client_ids whose service CWTs may set, lift and read publishing suspensions (`PUT`/`DELETE`/`GET /admin/users/:id/publishing-suspension`). Empty ⇒ 403. See `docs/creator-publishing-entitlement.md`. |
| `PATREON_PUBLISHER_CAMPAIGN_ID`, `PATREON_PUBLISHER_TIER_IDS` | Arkavo's own Patreon campaign id and the comma-separated Patreon **tier IDs** (not titles) that grant the derived creator-publishing entitlement `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`. Both required; either unset/empty ⇒ never granted. State logged once at startup. |
| `APP_STORE_BUNDLE_ID`, `APP_STORE_APP_APPLE_ID`, `APP_STORE_PUBLISH_PRODUCT_IDS` | App Store Creator Membership. Bundle id (`com.arkavo.ArkavoCreator`), the app's numeric Apple ID (required on Production notifications) and the comma-separated auto-renewable product ids that grant the derived creator-publishing entitlement. All three required; any unset ⇒ the feature is off (startup log line) and `POST /app-store/transactions` / `/app-store/notifications` answer 503. No new table. |
| `APP_STORE_ENVIRONMENTS` | Comma-separated, default `Production,Sandbox`; only those two values are accepted. Sandbox is accepted on prod by owner decision (App Review buys there); every Sandbox grant is logged with `env=Sandbox`. `Xcode` and `LocalTesting` are always refused. |
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
| `PATREON_CLIENT_<TAG>_ID`, `_SECRET`, `_REDIRECT_URIS`; `PATREON_KMS_KEY_ID` | One Patreon OAuth client per tag (legacy untagged `PATREON_CLIENT_ID/_SECRET/_REDIRECT_URIS` still works). A redirect URI may belong to one client only. Any malformed registration or missing KMS key disables Patreon entirely (link endpoint ⇒ 503). |
| `APP_ATTEST_APP_ID` | **Comma-separated set** of hex SHA-256 of `<TeamID>.<BundleID>`, one per app that registers users. An attestation is accepted when its `rpIdHash` matches any member; a single value is a one-element set. When non-empty, `POST /device-check/attest` enforces the match. Unset ⇒ recorded but not enforced (warns). **Mandatory on the registration-gate path**, where unset fails closed. |
| `WEBVH_SIGN_KEY_PATH` | Ed25519 key file for the did:webvh log (`--features webvh`). Unset ⇒ DID doc only, no signed log. |

## Architecture

### Core Components

**authn.rs** - WebAuthn authentication flow
- `start_register`: Initiates passkey registration with DID validation
- `finish_register`: Completes registration, stores credential, issues CWT
- `start_authentication`: Initiates passkey authentication (`GET /authenticate[?account=<uuid>]`); name-free without `account`, limited to that account's passkeys with it
- `finish_authentication`: Verifies authentication, issues CWT; replies `{token, handle}`
- Account token generation with 99-year registration tokens (~5148 weeks)
- Authentication tokens expire in 1 hour
- Uses attestation envelope with ECDSA signature for registration response

**oidc.rs** - OpenID Connect (OIDC) Provider endpoints
- `/.well-known/openid-configuration`: Discovery document
- `/.well-known/jwks.json`: JWKS (advertises the EC P-256 signing key as a JWK)
- `/oauth/authorize`: Authorization endpoint (code flow with PKCE)
- `/oauth/token`: Token endpoint (issues access_token CWT + id_token JWT, both ES256-signed)
- `/oauth/userinfo`: UserInfo endpoint
- Issues OpenTDF-compatible claims: `iss`, `sub` (always `arkavo:UUID` —
  one human has one account under link-only identity, so an RP sees one
  stable subject however they signed in; `idp` records which IdP was used),
  `aud`, `email`, `email_verified`, `idp`, `arkavo_account_id`,
  `arkavo_roles`, `arkavo_entitlements`
- Authorization codes stored in an in-memory `AuthorizationCodeStore` (10-min
  lifetime, single-use). For multi-instance deployments swap for a shared store.
- Confidential clients use `client_secret`; public clients must use PKCE (S256).
- Upstream authentication: WebAuthn-issued Arkavo CWT (via `X-Auth-Token`),
  Apple id_token (via `idp=apple` + `id_token` query/`X-Apple-Id-Token` header),
  or Google via server-side redirect (`idp=google`, see google_signin.rs).
- RFC 8707 `resource` on `/oauth/authorize` and `/oauth/token`: accepted when
  it names the client itself or `OIDC_PLATFORM_AUDIENCE` (both already in
  `aud`); anything else is `invalid_target` (on the client's redirect URI
  from authorize, JSON 400 from token). Omitted ⇒ unchanged behaviour.
- Public clients (no `_SECRET`) without a `code_challenge` are refused at
  authorize (`invalid_request` on the redirect URI), not just at the token
  exchange, so an upstream (Google) login is never wasted.
- Refresh tokens carry `idp`/`email`/`email_verified`/`name` from issuance so
  refreshed access tokens and id_tokens keep the same identity claims.

**apple_signin.rs** - Sign in with Apple integration
- Validates Apple-issued id_tokens against Apple's JWKS (cached 1h with
  force-refresh on `kid` miss in case Apple rotated keys)
- Every accepted id_token must clear:
  - **Signature** vs Apple JWKS
  - **`iss`** = `https://appleid.apple.com`
  - **`aud`** ∈ comma-separated `APPLE_CLIENT_ID` list (iOS bundle + web
    Service ID can coexist on the same deployment)
  - **`nonce`** must match the server-issued nonce (verbatim or hex SHA-256;
    constant-time compare). No nonce ⇒ refuse.
  - **`exp`/`iat`** via `jsonwebtoken::Validation`
- `GET /oauth/apple/nonce`: issues a 256-bit server nonce, persists in session
- `POST /oauth/apple/idtoken`: Native flow — client must have called
  `/oauth/apple/nonce` first; server consumes session nonce (single-use) and
  validates the id_token against it
- `POST /oauth/apple/link`: **Auth-required** link path. Caller presents a
  valid Arkavo CWT via `X-Auth-Token`; server consumes the session nonce,
  validates the Apple id_token, and writes `(user_id, "apple", sub)` to the
  `identity_links` table. Idempotent on repeat; returns HTTP 409 if the same
  Apple `sub` is already linked to a different arkavo user. **Minimum-PII**:
  no email/name/relay claims are persisted, even if Apple sends them.
  With token revocation configured (`apple_tokens.rs`) the body must also
  carry `authorization_code` (400 `authorization_code_required` otherwise).
  The server exchanges it at Apple's `/auth/token` (client secret: ES256,
  `kid` = key id, `iss` = team, `sub` = the id_token's `aud`, 300 s; no
  `redirect_uri`, native codes have none), verifies the returned id_token is
  the same `sub` for the same client (`nonce` checked when present), seals
  the refresh token, writes the link and the token to the `identity_links`
  row `apple#<sub>` in **one** conditional `UpdateItem`
  (`link_apple_with_token`), then checks `is_account_live` again. Apple's `/auth/revoke` ends the whole
  authorization for that Apple ID and client, including a token stored for
  it earlier, so the cases differ:
  - binding mismatch (401 `apple_token_binding_mismatch`): the returned
    token is revoked;
  - conflict (409): nothing is revoked (the authorization is the linked
    account's; its deletion revokes it if that link stored a token);
  - the link + token write fails (500): the new token is revoked, even on
    a re-link, where that ends the existing authorization;
  - sealing fails (502 `apple_token_store_failed`): nothing is written; the
    new token is revoked only if the identity is linked to no account;
  - the exchange fails (502 `apple_token_exchange_failed`): nothing to
    revoke;
  - Apple's keys cannot be fetched or read to check the returned id_token
    (502): nothing is revoked;
  - the account was deleted while the request was in flight (the re-check
    sees a tombstone; 401): the new token is revoked and the link holding
    it deleted (kept if Apple did not revoke it). A failed re-check keeps it
    and answers 200;
  - a re-link succeeds (200): the stored token is replaced and the old one
    is not revoked (the revoke at deletion ends the whole authorization).

  Every Apple call has a 10 s timeout. The re-check, not a timing bound,
  keeps a link in flight from outliving a deletion's sweep: the request can
  take longer than `ACCOUNT_DELETION_GRACE_SECONDS` (untimed DynamoDB and
  KMS calls).
- `POST /oauth/apple/callback`: **explicitly disabled** (HTTP 501). Apple web
  callback requires both code-exchange (signed client-secret JWT against
  Apple's token endpoint) *and* state-bound nonce verification. Until both
  are implemented this endpoint always rejects, so misconfigured Apple
  Service IDs fail loudly rather than being silently accepted.
- `resolve_apple_user` resolves `apple:<sub>` to an Arkavo account **through
  the `identity_links` table only**. It never provisions: an unlinked `sub` is
  refused. Apple `sub` is the canonical join key — email is optional metadata
  and never used to locate accounts (private-relay rotation safe).
- Requires `APPLE_CLIENT_ID` to be set (one or more comma-separated values).

**google_signin.rs** - Sign in with Google (upstream IdP, redirect flow)
- `GET /oauth/authorize?...&idp=google`: validates the RP request as usual,
  parks it in Redis (`oidc:google:pending:<state>`, 10 min, single-use,
  in-memory fallback) under a fresh random Google `state`, and 307s the
  browser to `accounts.google.com` with `scope=openid email profile`,
  `prompt=select_account`, and a fresh random `nonce`. Not cookie-session based: the session cookie is
  `SameSite=Strict` and would not survive the cross-site return.
- `GET /oauth/google/callback?state&code|error`: takes the parked request,
  exchanges `code` at Google's token endpoint with `GOOGLE_CLIENT_SECRET`,
  verifies the returned id_token (JWKS signature with kid-miss refresh,
  `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`},
  `aud` = `GOOGLE_CLIENT_ID`, `nonce` constant-time match, `exp`), resolves
  `google:<sub>` → Arkavo account **via the `identity_links` table only**,
  then mints the OIDC code and redirects to the RP with `code` + the RP's own
  `state`. An unlinked `sub` is refused, never provisioned.
- `GET /oauth/google/nonce` + `POST /oauth/google/link`: the Apple pair's
  counterpart, and the only way a Google identity becomes able to sign in.
  Auth-required (`X-Auth-Token` CWT names the account), single-use session
  nonce, HTTP 409 if the `sub` is bound to a different account. Minimum-PII:
  only the `sub` is persisted.
- Failures after the RP was validated go back to the RP's redirect_uri as
  `error=` (`access_denied` for user cancel / rejected id_token,
  `server_error` for exchange or DB failure, `temporarily_unavailable` when
  Google is unconfigured). Only an unknown `state` stays on this origin (400).
- Tokens: `idp=google`, `email` (lower-cased + trimmed) and `email_verified`
  from Google, `name` on the id_token. Disabled unless `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` are set.

**identity.rs** - Federated identity resolution (link-only)
- `resolve_linked_account(db, provider, subject)`: the single policy shared by
  Apple and Google sign-in. An identity reaches an Arkavo account **only**
  through its `identity_links` row.
- Accounts are created by **passkey registration alone**. Sign-in never
  provisions. A missing link — or a link pointing at a deleted user row —
  fails closed as `NotLinked`.
- Refusal is uniform across every surface: `error=access_denied` with
  `error_description=identity_not_linked` on the RP's redirect URI
  (`/oauth/authorize?idp=apple`, `/oauth/google/callback`), or HTTP 403 with
  the same marker from `POST /oauth/apple/idtoken`. The code stays standard
  OAuth2 so existing RP handling works; the marker is what lets a client route
  the user to passkey registration.

**agent.rs** - Agent delegation (human PE → agent NPE, `did:key`)
- `/.well-known/agent-configuration`: discovery metadata
- `POST /agents/authorize`: operator auth is a passkey auth CWT
  (`X-Auth-Token`) or, when that header is absent, an `agents:delegate` OIDC
  access token (`Authorization: Bearer`, allowlisted client, `auth_time`
  within 3600 s). Creates a delegation record for `agent_did` with a subset
  of the delegator's own stored entitlements
  (`DynamoDBStore::get_user_entitlements`). Body adds `swarm` (optional: no
  `arkavo_swarm` claim until set) and `short_lived`. One identity is one key
  (the DID); authorize is the owner's bootstrap appraisal: `eligible` until
  the passkey assertion time (auth CWT `iat` / Bearer `auth_time`) +
  `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (`owner_appraisal_deadline`; 403 once
  past), with `plan_authorize` deciding the `state_version` (a swarm change
  bumps it). Refused while the key is quarantined or once it has been
  recovered; 409 while another owner's delegation of the DID is live. The
  agent quota applies only when authorize adds a delegation.
  Response `{success, message, agent, state, state_version, appraised_until}`.
- `GET /agents/delegations`, `DELETE /agents/delegations/:did` (cascade)
- `GET /agents/challenge?did=…` → `{challenge: b64(32 bytes), nonce}`; the
  challenge is stored on the delegation row (no cookie session)
- `POST /agents/token` `{did, challenge, signature, nonce}` → verifies the
  Ed25519 proof over the decoded challenge bytes, returns
  `{token, expires_at, entitlements}`. Mints only while the identity is
  `eligible` (`agent::issuable`; a row written before v2 is `unassessed`).
  `token` is a single CWT (no delegation JWT): `aud` = the
  configured `AGENT_TOKEN_AUDIENCES` list, `exp - iat` capped at
  `AGENT_TOKEN_MINUTES` (hard max 15 min; ≤ 300 s when `short_lived`; never
  past `appraised_until`), `act` = `AGENT_AUTHORIZED_ACTORS`, `arkavo_npe`
  describes the agent (type, delegation id, depth, chain),
  `arkavo_state_version` is the identity's `state_version` at mint,
  `arkavo_swarm` its kit (omitted until it has one), `cnf` is bound to the agent's
  Ed25519 `did:key`. There is no refresh — the agent re-runs the
  challenge/token exchange for a new one. This is the contract
  `arkavo-edge/crates/arkavo-agent-auth` expects (#54); its `delegation_jwt`
  field is `Option` with `#[serde(default)]`, so omitting it is
  wire-compatible.
- Extracted from PR #23; agent→agent delegation, per-agent OAuth clients
  (#50) and the ERS surface (#48) are follow-ups
- Wire contract for all of this and the endpoints below:
  [docs/agent-credentials-contract.md](docs/agent-credentials-contract.md) (v2).

**agent_state.rs** - The agent identity's trust state (quarantine, recovery,
appraisal, status)
- State lives on the `agent_delegations` row (`db/agent_state.rs`):
  `unassessed | eligible | quarantined` stored, `suspended` derived
  (`eligible` past `appraised_until`). `state_version` +1 on every stored
  state change, a swarm change, a revocation, and an authorize over a
  revoked/expired/pre-v2 row; never on a renewal. Every write is one
  conditional `UpdateItem` on the version read (quarantine and revocation also
  on the owner read; appraisal also on a live delegation).
- `POST /agents/:did/quarantine`: owner (passkey auth CWT, or an
  `agents:delegate` Bearer token with `auth_time` ≤ 3600 s old) or the owner's
  Guardian; latches whatever the delegation's liveness, idempotent per
  incident, 409 on a second incident, on the incident the last recovery
  cleared, and on a write that races a concurrent change (`Raced`; retry).
- `POST /agents/:did/recover`: owner only, passkey assertion ≤ 300 s old
  (auth CWT `iat`, or Bearer `auth_time`), cites the incident; the identity
  becomes `unassessed` with `recovered_at` set; once recovered, the key is
  Guardian-appraised for life (the owner's path back is a new key). The
  delegation is kept.
- `POST /agents/:did/appraisal`: an enrolled Guardian of the owner (≤
  `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` from now) or the owner (≤
  `AGENT_OWNER_APPRAISAL_TTL_SECONDS` from its passkey assertion, never a
  recovered key); clamps `appraised_until` to that; 403 for quarantined,
  revoked, expired, another owner's agent, a stale owner assertion, or a
  Guardian whose key is the agent's own.
- The 403 bodies in the contract's "Refusal bodies" table are part of v2
  (`agent::REFUSE_*`, `AgentError::{WorkloadQuarantined, DelegationRevoked}`);
  `agent_plane_tests::refusal_bodies_are_contract_v2` pins them.
- `GET /agents/:did/status`: service CWT from `AGENT_STATUS_CLIENT_IDS`;
  `valid_until = now + 5`, capped at `appraised_until` while eligible; 404 for
  an unknown, revoked or expired delegation unless quarantined.
- `AppraisalConfig` parses the two appraisal lifetimes at startup.

**guardian.rs** - Minimal Guardian enrollment and revocation
- `POST /guardians` (owner, passkey auth CWT): registers a 32-byte Ed25519 key
  (weak keys refused), proving possession of it — `proof` is that key's
  signature over an enrollment message naming the owner (400 if missing,
  malformed, or not a valid signature by that key for that owner).
  `guardian_id` is a UUID derived from the key's SHA-256, so a key enrolls at
  most once, ever, under any owner (409), and a revoked key can never
  re-enroll with a fresh id.
- `DELETE /guardians/:id` (owner who enrolled it, passkey auth CWT only): 204
  (idempotent on an already-revoked Guardian), 403 belongs to another owner,
  404 unknown or non-canonical id. Revocation is a marker, never a delete.
- `X-Guardian-Signature: <id>.<ts>.<sig>` over `METHOD\nPATH\nts\nhex(sha256(body))`,
  ±60 s, `verify_strict` against the enrolled key only; each Guardian's accepted
  timestamps must strictly increase (`last_signed_at`), so a replay is 401.
  Guardians get 403 on every agent-plane endpoint except quarantine and
  appraisal — that 403 is for a well-formed request; a malformed body/query on
  any other endpoint is refused by request parsing (400/415/422) before the
  Guardian check runs.

**device_check.rs** - Apple DeviceCheck/App Attest integration
- `register_challenge` / `register_attest` (**unauthenticated**, Task 5): the registration
  preflight. `GET /device-check/register-challenge` issues a challenge into the session;
  `POST /device-check/register-attest` verifies the attestation, checks the registration budget
  (advisory — takes no slot) and puts a one-shot `RegistrationTicket` (300s) in the session.
  Errors on these two routes are **JSON with a stable `error` token**, unlike the rest of
  `DeviceCheckError`, so a client can tell a permanent refusal (`attest_registration_cap`) from a
  retryable one. See [docs/app-attest-preflight-contract.md](docs/app-attest-preflight-contract.md).
  **The ticket gates registration** (Task 6): `start_register` refuses without one and
  `finish_register` consumes it, so one attestation buys exactly one account.
- `generate_challenge`: Issues random challenge for attestation (**requires a
  CWT bound to `:username`** — App Attest proves the device is genuine, never
  which account it belongs to)
- `verify_attestation(challenge, key_id, attestation_object_b64, client_data_hash_b64, &VerifyOptions)`:
  the shared verifier. Returns `AttestedKey { key_id, public_key, rp_id_hash_str, counter }`.
  `VerifyOptions.expected_app_ids` is a **set** (more than one app registers users);
  `require_app_id` decides whether an empty set warns (bound-device path) or refuses with
  `AppIdNotConfigured` (registration gate). Both paths share this one implementation — never
  write a second copy.
- `finish_attestation`: Calls `verify_attestation`, stores device binding
- `generate_assertion_challenge`: Issues challenge for existing devices (requires CWT)
- `finish_assertion`: Verifies assertion, enforces counter increment, issues CWT
- CBOR attestation object parsing ("apple-appattest" format). Apple sends **camelCase** keys
  (`attStmt`, `authData`), so the deserialization structs carry
  `#[serde(rename_all = "camelCase")]` — without it every genuine attestation fails at CBOR
  decode with `missing field att_stmt`, before any verification runs.
- Certificate chain validation: every signature from the leaf up to the pinned Apple
  App Attest root is verified, validity windows are enforced, and a leaf-only chain is
  refused (Apple always sends an intermediate). `validate_certificate_chain_at` takes the
  validity instant so the fixture tests pin the capture time; **production always passes
  `ASN1Time::now()`** — the parameter is not a way to disable expiry checking.
- Nonce binding: `SHA256(authData || clientDataHash)` is compared against the credCert's
  `1.2.840.113635.100.8.2` extension. This is what binds an attestation to the challenge
  the server issued; without it a captured attestation replays against any later one.
- Key binding: the caller-supplied `key_id` must be exactly the padded standard base64 of
  SHA256 of the credCert's **uncompressed EC point** (not the DER SPKI), and authData's
  `credentialId` must equal that hash. `key_id` keys the registration budget and the device
  binding, so an unbound one would let a genuine attestation be filed under any key.
- aaguid must be `appattest` or `appattestdevelop` on every server — not environment-selected,
  since macOS emits `appattest` even from a dev build and `rpIdHash` already pins the app.
  These checks run **before** the nonce compare: any tamper to them also breaks the nonce, and
  a check shadowed by `NonceMismatch` cannot be tested.
- Assertions (`verify_assertion`): a CBOR map `{signature, authenticatorData}` with a **DER**
  signature, never `authData || r‖s`. The signature is ECDSA-SHA256 over
  `nonce = SHA256(authData || clientDataHash)`, so the digest is `SHA256(nonce)`; `rpIdHash`
  must equal the binding's `app_id`. The counter is checked only after both pass. A real
  device's attest + first minted assert is pinned in `tests/fixtures/appattest/assertion.json`
  (#17, Mac, 2026-10-26); the synthetic tests build assertions the way the Secure Enclave does.
- Monotonic counter enforcement for replay protection
- Public key extraction and storage: a binding's `public_key` is the credCert's **DER
  SubjectPublicKeyInfo**. Every reader (`verify_assertion`, `cwt::cnf_from_app_attest`) parses
  DER, never a bare SEC1 point (#118: the mint parsed SEC1 and 401'd every real device).

**publishing.rs** - Creator-publishing entitlement (#91)
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
  non-revoked record of a configured product and environment, unexpired
  counting any billing-retry grace), and the account has no publishing
  suspension. One `get_publishing_state` read (the `credentials` row,
  strongly consistent) yields the suspension and the App Store records, and
  happens only when a source can grant. Fails closed.
- Carried in `ArkavoUserClaims::derived_entitlements`, so
  `mint_registration_token` drops it (~99-year token), and
  `entitlements::validate_fqns` refuses to store it (never delegable to
  agents). `GET /entities/arkavo:<uuid>` shows it because it derives it the
  same way a mint does, never because it is stored.
- `PUT`/`DELETE`/`GET /admin/users/:id/publishing-suspension`: service CWT on
  `MODERATION_CLIENT_IDS`; the suspension (`suspended_by`, `suspended_at`,
  `reason`, `report_id`) is a map attribute on the `credentials` row and is
  the audit record. See [docs/creator-publishing-entitlement.md](docs/creator-publishing-entitlement.md).
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
  What the platform's arkavo-mode ERS consumes in place of
  `arkavo_patreon`, which is still minted until the platform cuts over.
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

**account.rs** - Account deletion (#88, App Store guideline 5.1.1(v))
- `DELETE /account`: passkey auth CWT (`X-Auth-Token`) minted within
  `ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS` (300 s); `agent::verify_passkey_auth_token`
  (token checks only, no account lookup, so a retry still verifies). 202
  `{deletion_id, status, requested_at, completes_by}`; a retry returns the same id.
- **At once**: the `credentials` row is replaced by a tombstone (`db/account.rs`,
  one put on `LIVE_ROW`) holding only `user_id`, `deleted_at`, `deletion_id`,
  `deletion_state`, `deletion_attempts` and, until the sweep completes,
  `deletion_handle`. `get_user_by_id` reports a tombstone as absent, and with
  no `username` it leaves the `username-index` GSI, so the name is
  **reusable immediately**. The handle row is deleted in the request too.
- **Every write to a credentials row carries `LIVE_ROW`**
  (`attribute_exists(user_id) AND attribute_not_exists(deleted_at)`):
  `add_credential`, `put_user_entitlements`, `put_webvh_log` (was an upsert),
  publishing suspension set/lift. Keep it on any new write to that table.
- **Tokens outlive the account, so every path that trusts a token re-checks
  the row** (`DynamoDBStore::is_account_live` / `get_user_by_id`):
  `agent::authenticate_human` / `authenticate_operator` (whole agent plane and
  Guardians), Apple/Google/Patreon link (the Apple link with a token checks
  again after storing it), `/oauth/authorize` with `X-Auth-Token`, the code
  and refresh grants, `/oauth/userinfo`,
  `/device-check/attest`; and for agent tokens, which name the agent not the
  owner, `agent::active_delegation` and `GET /agents/:did/status` check the
  delegation's `root_user_id`. A new token-accepting path must do the same.
- **After `ACCOUNT_DELETION_GRACE_SECONDS` (60 s)**, `account::sweep` deletes
  the handle, device bindings, identity links (scan: no `user_id` GSI; an
  Apple link holding a token is left for the last step) and the
  Patreon token row (Patreon has no revocation endpoint), revokes (never
  deletes) the passkey index rows (#104), invalidates the
  Patreon cache, revokes agent delegations (+ chain cascade; also done in the
  request itself) and Guardians and blanks their `name` / `delegator_username`
  (rows stay: a revoked or
  recovered key must never come back fresh). **Last**, it revokes the
  account's Sign in with Apple refresh tokens (the `token_*` attributes of
  its Apple `identity_links` rows, scan on `user_id`) at Apple's
  `/auth/revoke` and deletes each link on 200. A 4xx
  other than 429 (a configuration problem: key, client id, secret), a stored
  token that cannot be read, or stored tokens while revocation is
  unconfigured, keeps the rows and marks the deletion `failed` at once
  (`SweepError::is_permanent`; no schedule retries). A 429, 5xx, transport or
  KMS failure keeps the rows and retries; a DynamoDB error while scanning or
  deleting a row stops the step at once and retries. Retries
  `[30, 60, 120]` s, then `failed`; `resume_unfinished` restarts
  pending/failed sweeps at boot.
  `device_attest_keys` is not touched (no account link).
- `GET /account/deletions/:id`: no token; the id is `<user_id>.<128-bit hex>`,
  compared constant-time. `pending | failed | completed`. Contract:
  [docs/account-deletion.md](docs/account-deletion.md).

**passkeys.rs** - Passkey credential attestations (#104, catalog v2)
- `POST /passkeys/credential-attestation` (passkey auth CWT, body
  `{"credentialId": b64url}`): `{attestation}` = COSE_Sign1 (tag 18, never
  61), ES256 under the CWT kid, protected `content type`
  `application/arkavo-passkey-credential+cbor`, payload a text-keyed map of
  exactly `typ` (`arkavo-passkey-credential`), `iss`, `sub` (bare UUID, as in
  the passkey CWT), `credentialId` (bytes), `publicKey` (COSE_Key kty/crv/x/y
  only), `rpId`, `iat`. **No `exp`.** 404 for a credential the account does
  not hold or that was revoked. Format and verifier in the lib module
  `credential_attestation.rs`; contract
  [docs/passkey-credential-attestation.md](docs/passkey-credential-attestation.md),
  which tdf-iroh-s3, Creator and arkavo-ios verify against: change it only
  with them.
- `cwt::verify` refuses any protected `content type` and any `typ` claim, so
  an attestation never passes as a token. Keep both.
- `GET /passkeys/credentials/:id/status` (public, `no-store`):
  `{sub, revoked, revokedAt?}`; 404 if never attested. Revoked = the index
  row's `revoked_at`, or the account is a tombstone (`revokedAt` =
  `deleted_at`), or the account no longer holds the credential.
- Index: `identity_links` row `passkey#<b64url id>` (`db/passkeys.rs`),
  written on first attestation, never deleted; the deletion sweep skips it in
  the link deletion and sets `revoked_at` = `deleted_at`. A future passkey
  removal route must revoke the row, not delete it. The signing key must stay
  in `/.well-known/cose-keys` while its attestations should verify.

**session.rs** - Passkey session renewal (#108)
- A session lets a client renew its passkey auth CWT without a new passkey
  prompt: at most `SESSION_MAX_SECONDS` (24 h) after the passkey assertion,
  and only while renewals arrive within `SESSION_IDLE_LIMIT_SECONDS` of each
  other (NIST SP 800-63B-4 AAL2). That is `SESSION_IDLE_SECONDS` (1 h), but
  never before the last token's `exp` + skew +
  `SESSION_RENEWAL_GRACE_SECONDS`, so the renewal an expired token's 401
  prompts succeeds: 3960 s while the token lasts 1 h. Contract:
  [docs/session-renewal.md](docs/session-renewal.md).
- `POST /session`: an *original* passkey auth CWT (no `auth_time`, assertion
  ≤ `SESSION_OPEN_MAX_AUTH_AGE_SECONDS` = 300 s) plus a device public key
  (65-byte X9.63 P-256, the client's Secure Enclave key) and its signature
  over the open message. One session per token (`session_id` derives from
  the token's `cti`; 409 on a second open).
- `POST /session/refresh`: the device-key signature over
  `session_id` + the current single-use credential (`<generation>.<secret>`).
  The proof is checked **before** the row is touched, then idle, absolute and
  account liveness, then one conditional `UpdateItem` on the generation and
  hash rotates the credential. A presented generation below the stored one
  is reuse (RFC 9700): the session is deleted. Re-reads entitlements and the
  publishing suspension (`oidc::arkavo_user_claims`); a suspension does not
  end the session. Every refusal is 401 `{"error":"session_ended","reason"}`.
- `POST /session/signout`: device-key signature; deletes the row (204,
  idempotent).
- **A renewed token carries `auth_time` = the session's assertion time** and
  `exp` ≤ the 24 h deadline. Every "recent passkey assertion" check reads
  `cwt::passkey_assertion_time` (`auth_time` else `iat`): enrollment,
  `oidc::webauthn_auth_time`, `agent::verify_passkey_auth_token` (delegation,
  recovery, account deletion). A new freshness check must use it, never `iat`.
- Rows: `identity_links` `session#<id>`, `provider = session`
  (`db/session.rs`); `expires_at` is written for a future TTL. The deletion
  sweep's link step removes them.
- Signatures are raw r‖s (64 bytes), never DER.

**entities.rs** - Service-gated entity lookup (spec §2.4)
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
  `arkavo_patreon` as the token's map in JSON. The platform ERS's live
  source reads it instead of token claims, so tokens can later shed the
  Patreon data. A Patreon-linked account for which nothing (cached, live or
  creator fallback) could be produced is 503 `{"error":"patreon_unavailable"}`,
  never a 200 without Patreon data: the resolver treats 503 as unavailable
  (keeps its last answer) and a 200 as a fresh negative. Likewise a failed
  publishing-state read is a 500 (`publishing::try_derived_entitlements`),
  never a 200 missing the publish value; a mint withholds it. Agents never get
  derived values. Contract agreed with the opentdf-platform session
  2026-10-27; change it only with them.
- `GET /entities/me` (0.27.0): the same person view for the caller's own
  account, for the apps (arkavo-ios, Creator), which read their Patreon
  subscription here once tokens shed it (owner decision 2026-10-27). Auth
  is a passkey auth CWT in `X-Auth-Token` (`agent::verify_passkey_auth_claims`:
  a session-renewed one is accepted; registration tokens, OIDC access
  tokens and NPE tokens are refused), then the account row: a deleted
  account is 401, never 404. `Cache-Control: no-store`. Same body, 503 and
  500 as the service route (one builder, `person_view`); `id` is the
  canonical `arkavo:<uuid>`, never `me`. The static route takes precedence
  over `/entities/:id`. Contract: [docs/entity-view.md](docs/entity-view.md).

### Key Data Flow

1. **Registration Flow**:
   - **Requires a verified App Attest registration ticket in the session**
     (`GET /device-check/register-challenge` → `POST /device-check/register-attest`).
     Checked before any lookup, so an unattested caller cannot probe which handles
     exist (HTTP 403 otherwise). `finish_register` re-checks it, charges the
     `device_attest_keys` budget, and removes it: one attestation, one account.
   - Client requests `/register/:username?handle=...&did=...`
   - Validates DID format and handle consistency
   - A deleted account's username is free at once (its tombstone has no
     `username`); a new registrant gets a new `user_id` and DID
   - Rejects the `apple-` / `google-` username namespace (HTTP 403): those rows
     are IdP-provisioned with zero credentials, and the zero-credential
     exemption below would otherwise let anyone knowing the IdP `sub` enroll a
     passkey onto a federated account
   - Adding a passkey to an account that already has one requires an
     `X-Auth-Token` CWT minted within `ENROLLMENT_TOKEN_MAX_AGE_SECONDS`
     (5 min) — i.e. fresh proof of control from `POST /authenticate`, not any
     still-valid long-lived registration token (HTTP 401 otherwise)
   - Creates user in DynamoDB with retry logic (max 3 retries)
   - Generates WebAuthn challenge and stores registration state in session
   - Client completes WebAuthn ceremony
   - Server verifies registration via `/register` POST
   - Stores credential in DynamoDB
   - Returns attestation envelope (signed with ECDSA) + CWT in X-Auth-Token header (COSE_Sign1, ES256)

2. **Authentication Flow**:
   - `GET /authenticate` starts a name-free ceremony: it reads no record and lists no credentials, and the passkey's user handle names the account at the finish. The reply includes `"mediation":"conditional"` (webauthn-rs forces it), a browser-autofill hint native clients ignore
   - `GET /authenticate?account=<uuid>` limits the ceremony to that account's passkeys (re-authentication). Only this start retrieves the account's credentials from DB (authoritative — no token-embedded fallback); a missing or tombstoned account answers 500 `User Not Found`, one with no passkey 500 `User Has No Credentials`, and a malformed `account` gets axum's query rejection (400 `Failed to deserialize query string: …`). There is no `/authenticate/:username` route
   - Both starts generate a WebAuthn challenge, store the ceremony (`PendingAuthentication`) as `auth_state` in the session, and set the session cookie the POST must carry
   - Client may send a CWT in X-Auth-Token; the server verifies it (exp/iat enforced with ±60s skew). An expired or invalid token refuses the start with 401 `CWT error: …`. A valid token for another account is refused (500 `User Not Found` at an account-scoped start, 403 `Passkey belongs to another account` at a name-free finish). Clients should not forward a cached token to the name-free start (a stale one refuses the start meant to replace it), and must not forward one to `?account=` (a token for another account there answers 500 `User Not Found`, which ArkavoKit reads as "already deleted")
   - Client completes the WebAuthn ceremony and POSTs the `PublicKeyCredential` (not a `{"challenge": …}` object) to `/authenticate`
   - `POST /authenticate` outcomes, status and exact body:
     - 200 `{"token":"<CWT>","handle":"<username>"}`: verified; the CWT expires in 1 hour
     - 400 `{"token":""}`: ceremony failure. The assertion did not verify (challenge, signature, origin, user verification, a credential the scoped start did not list); a name-free assertion's user handle is missing or not a 16-byte UUID; or a scoped assertion carries a user handle that is not the account's UUID (`finish_account_authentication` checks this itself: webauthn-rs's scoped finish ignores the user handle, which is not signed)
     - 404 `Unknown Passkey`: name-free only. The user handle names no live account, or the account does not hold that credential id. Decided before the signature check, and it carries no account data. ArkavoKit removes the passkey from the device on it, so the body must not change
     - 403 `Passkey belongs to another account`: name-free only, the X-Auth-Token mismatch above; also decided before the signature check
     - 500 `Corrupt Session`: the session holds no open ceremony (no start, a lost cookie, or a finished ceremony such as a replayed POST)
     - 500 `User Not Found`: account-scoped only; the account was deleted between start and finish. ArkavoKit maps this text to `.alreadyDeleted`, so it must not change
     - A DynamoDB error answers 500 `Database operation failed: …` and leaves the ceremony open (the record is read before `auth_state` is removed), so the client can retry the POST
   - The name-free start uses webauthn-rs's `allow_backup_eligible_upgrade = false`; the scoped start uses `true`. Neither finish saves the `AuthenticationResult` credential update (counter, backup state). So a passkey stored as not backup-eligible that now reports backup eligibility fails every name-free finish with 400 while the scoped one accepts it, and clone detection compares against the counter stored at registration

3. **OAuth Integration**:
   - Callback endpoint: `/oauth/:client/:provider`
   - Validates client (arkavo, arkavocreator) and provider parameters
   - Sanitizes OAuth codes and error messages to prevent injection
   - Redirects to app-specific deep links (e.g., `arkavo://oauth/patreon?code=...`)
   - Forwards the provider's `state` verbatim on both the code and the error
     redirect (`...?code=<code>&state=<state>`, #129) when it passes
     `validate_oauth_state` (1–100 ASCII alphanumerics, `-`, `_`); a malformed
     `state` bounces as `error=invalid_state` without it, an absent one as
     before. The **client** verifies `state`; the server never does (it holds
     none): a client that posts a bounced code to `POST /oauth/patreon/link`
     without comparing it can be made to link an attacker's Patreon account

5. **OIDC Provider Flow (for OpenTDF and other RPs)**:
   - Relying party (RP) redirects user-agent to `/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid&state=...&nonce=...`
   - User-agent must already be authenticated via an upstream source:
     - WebAuthn: present a valid Arkavo CWT via `X-Auth-Token` header
     - Apple: pass `idp=apple` + Apple `id_token` (validated against Apple
       JWKS). The OIDC `nonce` query parameter is **required** for
       `idp=apple` and doubles as the Apple nonce — the client must use the
       same value when invoking Apple Sign In so the id_token's `nonce`
       claim matches (verbatim or hex SHA-256).
   - Server resolves/provisions the Arkavo account, mints a single-use
     authorization code, redirects back to `redirect_uri` with `code` + `state`
   - RP exchanges code at `/oauth/token` (HTTP Basic or form auth; PKCE for
     public clients). Server returns `access_token` (CWT, ES256) + `id_token`
     (JWT, ES256) (both 1h lifetime) with OpenTDF-compatible claims
   - RP can call `/oauth/userinfo` with `Authorization: Bearer <access_token>`

4. **Apple DeviceCheck/App Attest Flow**:
   - **One-time Attestation**:
     - Client requests challenge: `GET /device-check/challenge/:username`
       (**requires `X-Auth-Token`**: a CWT whose `sub` resolves to `:username`)
     - Server generates random UUID challenge, stores it in session together
       with the *authenticated* user_id — the binding is written against that,
       never against the path parameter
     - Client generates Secure Enclave key via `DCAppAttestService.generateKey()`
     - Client computes clientDataHash = SHA256(challenge)
     - Client performs attestation: `DCAppAttestService.attestKey(keyId, clientDataHash)`
     - Client POSTs attestation object to `/device-check/attest`
     - Server validates:
       - CBOR format is "apple-appattest"
       - Certificate chain anchors to Apple's root CA
       - `rpIdHash` equals `APP_ATTEST_APP_ID` when that env var is set
       - aaguid is `appattest` or `appattestdevelop`
       - `key_id` and authData `credentialId` both equal SHA256(credCert public key)
       - Nonce = SHA256(authData || clientDataHash)
       - Counter is 0 (initial attestation)
     - Server stores device binding: device_id, public_key, counter=0, user_id
   - **Ongoing Assertions**:
     - Client requests assertion challenge: `GET /device-check/assert-challenge/:username` (requires CWT)
     - Server issues fresh challenge, validates CWT token
     - Client signs challenge with device key
     - Client POSTs assertion to `/device-check/assert`
     - Server validates:
       - Device binding exists **and belongs to the session's authenticated user**
       - Counter has incremented (counter > stored_counter)
       - Challenge matches expected hash
       - Signature is valid (verified against the stored public key)
     - Server updates counter, issues new CWT (aud `arkavo:devicecheck`).
       Its `arkavo_npe` names the app (#114): `app_id_hash` is the binding's
       `rpIdHash` (lowercase hex), present only while `APP_ATTEST_APP_ID`
       accepts it; `app_env` is `production` (aaguid `appattest`) or
       `development` (`appattestdevelop`), stored on the binding at attest.
       A binding from before #114 has no `app_env` and mints none until the
       device attests a new key. `GET /entities/device:<key_id>` carries the
       same two fields (`device_check::device_app_claims`).

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
- Session timeout: `Duration::seconds(600)` (10 minutes)
- Passkey enrollment freshness: `ENROLLMENT_TOKEN_MAX_AGE_SECONDS` (300s).
  Must stay below the auth token lifetime — asserted at compile time in
  authn.rs — otherwise "freshly minted" degrades into "not yet expired".
