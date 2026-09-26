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
| `AGENT_TOKEN_AUDIENCES` | **Required.** Comma-separated `aud` for agent CWTs from `POST /agents/token`. Use the audience your verifier checks (normally `OIDC_PLATFORM_AUDIENCE`). |
| `AGENT_AUTHORIZED_ACTORS`, `AGENT_TOKEN_MINUTES` | Optional `act` claim and agent CWT lifetime (clamped to 15). |
| `ADMIN_CLIENT_IDS` | OIDC client_ids (service CWT `sub` = `client:<id>`) allowed on `PUT /admin/users/:id/entitlements` and `GET /entities/:id`. Empty ⇒ 403. |
| `USER_DEFAULT_ENTITLEMENTS` | Override the default entitlement FQNs written to new user rows. |
| `PORT`, `BIND_ADDRESS` | Defaults `8080`, `0.0.0.0`. |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | PEM chain + key. Setting either enables HTTPS. |
| `ENABLE_HTTP3` | QUIC listener on UDP/`PORT` (binary built with `--features http3`, TLS required). |
| `DYNAMODB_*_TABLE` | `CREDENTIALS`, `HANDLES`, `DEVICE_BINDINGS`, `IDENTITY_LINKS`, `PATREON_TOKENS`, `AGENT_DELEGATIONS`, `DEVICE_ATTEST_KEYS`. Default to the unprefixed table names in the DynamoDB Schema section. |
| `AWS_REGION`, `AWS_ENDPOINT_URL_DYNAMODB` | Standard AWS SDK settings (`load_defaults`); the endpoint override points at local DynamoDB. |
| `REDIS_URL` | Cache for Patreon snapshots and pending Google logins; in-memory fallback when unset. |
| `OIDC_ISSUER` | Issuer URL in tokens and the discovery doc. Required to act as an OIDC IdP. |
| `OIDC_CLIENT_<TAG>_ID`, `_REDIRECT_URIS`, `_SECRET` | One relying party per tag. `<TAG>` is operator-chosen and never appears in tokens. Omit `_SECRET` for public PKCE-S256 clients. `_REDIRECT_URIS` is exact-match and required even for `client_credentials` service clients (use a dummy URI). See `docs/pep-service-clients.md`, `docs/google-signin.md`. |
| `OIDC_PLATFORM_AUDIENCE` | Extra `aud` appended to every OIDC access token so any RP's token passes the OpenTDF platform's single-audience check. Also the only `resource` value (besides the client id) accepted under RFC 8707. |
| `APPLE_CLIENT_ID` | Comma-separated iOS bundle ids / web Service IDs whose id_tokens are accepted. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` | Sign in with Google for `idp=google`. Both id and secret required or the flow fails closed. Redirect defaults to `<OIDC_ISSUER>/oauth/google/callback`. |
| `PATREON_CLIENT_<TAG>_ID`, `_SECRET`, `_REDIRECT_URIS`; `PATREON_KMS_KEY_ID` | One Patreon OAuth client per tag (legacy untagged `PATREON_CLIENT_ID/_SECRET/_REDIRECT_URIS` still works). A redirect URI may belong to one client only. Any malformed registration or missing KMS key disables Patreon entirely (link endpoint ⇒ 503). |
| `APP_ATTEST_APP_ID` | **Comma-separated set** of hex SHA-256 of `<TeamID>.<BundleID>`, one per app that registers users. An attestation is accepted when its `rpIdHash` matches any member; a single value is a one-element set. When non-empty, `POST /device-check/attest` enforces the match. Unset ⇒ recorded but not enforced (warns). **Mandatory on the registration-gate path**, where unset fails closed. |
| `WEBVH_SIGN_KEY_PATH` | Ed25519 key file for the did:webvh log (`--features webvh`). Unset ⇒ DID doc only, no signed log. |

## Architecture

### Core Components

**authn.rs** - WebAuthn authentication flow
- `start_register`: Initiates passkey registration with DID validation
- `finish_register`: Completes registration, stores credential, issues CWT
- `start_authentication`: Initiates passkey authentication
- `finish_authentication`: Verifies authentication, issues CWT
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
- `POST /agents/authorize` (human CWT via `X-Auth-Token`): create a
  delegation record for `agent_did` with a subset of the delegator's own
  stored entitlements (`DynamoDBStore::get_user_entitlements`)
- `GET /agents/delegations`, `DELETE /agents/delegations/:did` (cascade)
- `GET /agents/challenge?did=…` → `{challenge: b64(32 bytes), nonce}`; the
  challenge is stored on the delegation row (no cookie session)
- `POST /agents/token` `{did, challenge, signature, nonce}` → verifies the
  Ed25519 proof over the decoded challenge bytes, returns
  `{token, expires_at, entitlements}`. `token` is a single CWT (no
  delegation JWT): `aud` = the configured `AGENT_TOKEN_AUDIENCES` list,
  `exp - iat` capped at `AGENT_TOKEN_MINUTES` (hard max 15 min), `act` =
  `AGENT_AUTHORIZED_ACTORS`, `arkavo_npe` describes the agent (type, delegation
  id, depth, chain), `cnf` is bound to the agent's Ed25519 `did:key`. There is
  no refresh — the agent re-runs the challenge/token exchange for a new one.
  This is the contract `arkavo-edge/crates/arkavo-agent-auth` expects (#54);
  its `delegation_jwt` field is `Option` with `#[serde(default)]`, so
  omitting it is wire-compatible.
- Extracted from PR #23; agent→agent delegation, per-agent OAuth clients
  (#50) and the ERS surface (#48) are follow-ups

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
- Monotonic counter enforcement for replay protection
- Public key extraction and storage

**entities.rs** - Service-gated entity lookup (spec §2.4)
- `GET /entities/:id`: Service-CWT gated; resolves entity by id namespace
- Id namespaces: `arkavo:<uuid>` (person), `did:key:…` (agent), `device:<key_id>` (device)
- Unknown namespace → HTTP 400 (BadId); missing entity → HTTP 404 (NotFound)
- Category mapping: Person → "subject"; Agent and Device → "environment" — with npe_type (None/"agent"/"device")
- Claims include authorization profile (entitlements, roles) and entity-specific metadata (device class, agent depth/chain)

### Key Data Flow

1. **Registration Flow**:
   - **Requires a verified App Attest registration ticket in the session**
     (`GET /device-check/register-challenge` → `POST /device-check/register-attest`).
     Checked before any lookup, so an unattested caller cannot probe which handles
     exist (HTTP 403 otherwise). `finish_register` re-checks it, charges the
     `device_attest_keys` budget, and removes it: one attestation, one account.
   - Client requests `/register/:username?handle=...&did=...`
   - Validates DID format and handle consistency
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
   - Client sends CWT in X-Auth-Token header to `/authenticate/:username`
   - Server decodes inbound CWT (exp/iat enforced with ±60s skew)
   - Retrieves credentials from DB (authoritative — no token-embedded fallback)
   - Generates WebAuthn challenge, stores auth state in session
   - Client completes WebAuthn ceremony
   - Server verifies authentication via `/authenticate` POST
   - Issues new CWT with 1-hour expiration

3. **OAuth Integration**:
   - Callback endpoint: `/oauth/:client/:provider`
   - Validates client (arkavo, arkavocreator) and provider parameters
   - Sanitizes OAuth codes and error messages to prevent injection
   - Redirects to app-specific deep links (e.g., `arkavo://oauth/patreon?code=...`)

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
     - Server updates counter, issues new CWT (aud `arkavo:devicecheck`)

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
- **Discovery doc** (`/.well-known/openid-configuration`) advertises `access_token_format: "application/cwt"` and `cose_keys_uri` for CWT-aware RPs.
- **PoP**: `cnf` claim (RFC 8747) populated bound-at-issuance with the WebAuthn passkey COSE_Key or App Attest key where available. Not verifier-enforced in this release.

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
- Authentication token: `chrono::Duration::hours(1)`
- Session timeout: `Duration::seconds(600)` (10 minutes)
- Passkey enrollment freshness: `ENROLLMENT_TOKEN_MAX_AGE_SECONDS` (300s).
  Must stay below the auth token lifetime — asserted at compile time in
  authn.rs — otherwise "freshly minted" degrades into "not yet expired".
