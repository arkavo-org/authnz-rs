# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAuthn-based authentication and authorization service built with Rust, Axum, and DynamoDB. The system provides passwordless authentication using FIDO2/WebAuthn passkeys, **CWT (COSE_Sign1, ES256) tokens for Arkavo-issued credentials, JWT for OIDC `id_token`**, and decentralized identity (DID) support.

**Protocol Support**: HTTP/1.1, HTTP/2 with TLS 1.3 (HTTP/3 infrastructure ready but disabled due to dependency issues)

## Development Commands

### Build and Test
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with clippy lints
cargo clippy

# Format code
cargo fmt
```

### Running the Server

#### Development (HTTP)
```bash
# Set required environment variables
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem

# Optional: Set DynamoDB table names
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=handles
export DYNAMODB_DEVICE_BINDINGS_TABLE=device_bindings
export DYNAMODB_IDENTITY_LINKS_TABLE=identity_links
export DYNAMODB_PATREON_TOKENS_TABLE=patreon_tokens
export DYNAMODB_AGENT_DELEGATIONS_TABLE=agent_delegations

# Agent NPE access tokens (spec §1): aud is required, act/minutes are optional.
export AGENT_TOKEN_AUDIENCES=https://platform.arkavo.net,https://kas.arkavo.net,https://kg.arkavo.net
export AGENT_AUTHORIZED_ACTORS=https://kg.arkavo.net
export AGENT_TOKEN_MINUTES=15   # hard cap 15

# Optional: Set port (defaults to 8080)
export PORT=8080

# Optional: OIDC provider configuration (required to act as an OIDC IdP).
# Issuer URL appears in tokens and the discovery doc.
export OIDC_ISSUER=https://identity.arkavo.net

# Register one or more relying parties (RPs) using tagged env vars. <TAG> is
# an operator-chosen identifier (typically the upper-cased client_id) used
# only to group each RP's three vars together — it does not appear in tokens.
# Each RP needs an _ID and _REDIRECT_URIS; _SECRET is optional (omit or
# leave blank for public PKCE-only clients).
export OIDC_CLIENT_OPENTDF_ID=opentdf
export OIDC_CLIENT_OPENTDF_SECRET=<shared-secret-or-omit-for-public-PKCE-clients>
export OIDC_CLIENT_OPENTDF_REDIRECT_URIS=https://opentdf.example/callback,https://opentdf.example/oauth/cb
# Additional RPs follow the same pattern with a different tag:
# export OIDC_CLIENT_ARKAVOIOS_ID=arkavo-ios
# export OIDC_CLIENT_ARKAVOIOS_REDIRECT_URIS=arkavo://oauth/cb
# AuthZEN PEPs (service CWT, client_credentials): see docs/pep-service-clients.md.
# catalog-node and mcp-edge are registered in production (401 without secret).
# Mint on the identity host with scripts/mint-pep-cwt.py — do not paste secrets.
# _REDIRECT_URIS is required even for client_credentials (parser). Use a dummy URI.

# Optional: shared resource audience appended to every OIDC access token
# (RFC 8707-style). Set this to the OpenTDF platform's configured audience so
# tokens minted for any RP (apps, service accounts) pass the platform's
# single-audience CWT verification. Unset = single-audience tokens.
export OIDC_PLATFORM_AUDIENCE=https://platform.arkavo.net

# Optional: Sign in with Apple. Accepts a comma-separated list so the same
# AuthNZ instance can serve an iOS bundle id + web Service ID.
export APPLE_CLIENT_ID=com.arkavo.app,com.arkavo.web

# Optional: Patreon linking + membership materialization. Patreon issues one
# OAuth client per app, so clients are registered with tagged env vars
# (mirroring OIDC_CLIENT_<TAG>_*). Each client needs _ID, _SECRET, and
# _REDIRECT_URIS; the link request's redirect_uri selects which client's
# credentials perform the code exchange, so a redirect URI may belong to only
# one client. The legacy untagged trio (PATREON_CLIENT_ID/_SECRET/
# PATREON_REDIRECT_URIS) still registers a single client and may be combined
# with tagged ones. Any malformed/ambiguous registration, or a missing
# PATREON_KMS_KEY_ID, disables all Patreon code paths (POST
# /oauth/patreon/link returns HTTP 503 NotConfigured).
export PATREON_CLIENT_ARKAVO_ID=<patreon-oauth-client-id>
export PATREON_CLIENT_ARKAVO_SECRET=<patreon-oauth-client-secret>
export PATREON_CLIENT_ARKAVO_REDIRECT_URIS=https://identity.arkavo.net/oauth/arkavo/patreon
# export PATREON_CLIENT_ARKAVOCREATOR_ID=...
# export PATREON_CLIENT_ARKAVOCREATOR_SECRET=...
# export PATREON_CLIENT_ARKAVOCREATOR_REDIRECT_URIS=https://identity.arkavo.net/oauth/arkavocreator/patreon
export PATREON_KMS_KEY_ID=alias/arkavo-patreon-token-key

# Run the server
cargo run
```

#### Production (HTTPS)
```bash
# Set bind address and port
export BIND_ADDRESS=192.0.2.6  # Specific IP to bind to (defaults to 0.0.0.0 if not set)
export PORT=443

# Set TLS certificate paths
export TLS_CERT_PATH=/etc/letsencrypt/live/identity.arkavo.net/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/identity.arkavo.net/privkey.pem

# Set required cryptographic keys
export SIGN_KEY_PATH=/etc/authnz-rs/keys/signkey.pem
export ENCODING_KEY_PATH=/etc/authnz-rs/keys/encodekey.pem
export DECODING_KEY_PATH=/etc/authnz-rs/keys/decodekey.pem

# DynamoDB configuration
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=handles
export DYNAMODB_DEVICE_BINDINGS_TABLE=device_bindings
export DYNAMODB_IDENTITY_LINKS_TABLE=identity_links
export DYNAMODB_PATREON_TOKENS_TABLE=patreon_tokens
export DYNAMODB_AGENT_DELEGATIONS_TABLE=agent_delegations
export AWS_REGION=us-east-1

# Agent NPE access tokens (spec §1): aud is required, act/minutes are optional.
export AGENT_TOKEN_AUDIENCES=https://platform.arkavo.net,https://kas.arkavo.net,https://kg.arkavo.net
export AGENT_AUTHORIZED_ACTORS=https://kg.arkavo.net
export AGENT_TOKEN_MINUTES=15   # hard cap 15

# Run the server
cargo run --release
```

For complete production deployment instructions, see [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

### Generate Required Cryptographic Keys
```bash
# Generate signing key for attestation envelope
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem

# Generate CWT/JWT encoding key (PKCS8 format)
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem

# Extract public key for CWT/JWT decoding
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

### DynamoDB Setup

#### Local Development
```bash
# Start local DynamoDB
docker run -p 8000:8000 amazon/dynamodb-local

# Create credentials table
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name credentials \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=username,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"username-index\",
            \"KeySchema\": [{\"AttributeName\":\"username\",\"KeyType\":\"HASH\"}],
            \"Projection\":{\"ProjectionType\":\"ALL\"},
            \"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
        }]" \
    --billing-mode PAY_PER_REQUEST

# Create handles table
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name handles \
    --attribute-definitions AttributeName=handle,AttributeType=S \
    --key-schema AttributeName=handle,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create device_bindings table (for Apple DeviceCheck/App Attest)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name device_bindings \
    --attribute-definitions AttributeName=device_id,AttributeType=S \
    --key-schema AttributeName=device_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create patreon_tokens table (KMS-encrypted Patreon access/refresh tokens)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name patreon_tokens \
    --attribute-definitions AttributeName=user_id,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create agent_delegations table (human PE → agent NPE delegations)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name agent_delegations \
    --attribute-definitions \
        AttributeName=agent_did,AttributeType=S \
        AttributeName=root_user_id,AttributeType=S \
    --key-schema AttributeName=agent_did,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"root_user_id-index\",
            \"KeySchema\": [{\"AttributeName\":\"root_user_id\",\"KeyType\":\"HASH\"}],
            \"Projection\":{\"ProjectionType\":\"ALL\"}
        }]" \
    --billing-mode PAY_PER_REQUEST
```

## Architecture

### Core Components

**main.rs** - Application entry point and routing
- Server configuration with optional TLS/HTTPS support (rustls)
- TLS enabled when TLS_CERT_PATH or TLS_KEY_PATH environment variables are set
- Axum router with WebAuthn endpoints
- Session management (10-minute timeout, in-memory store)
- OAuth callback handling for multiple providers (Patreon, Twitch, Discord, Reddit)
- Loads EC keys for CWT/JWT signing/verification and attestation envelope creation
- WebAuthn RP origin: `https://identity.arkavo.net` (main.rs:84-85)

**authn.rs** - WebAuthn authentication flow
- `start_register`: Initiates passkey registration with DID validation
- `finish_register`: Completes registration, stores credential, issues CWT
- `start_authentication`: Initiates passkey authentication
- `finish_authentication`: Verifies authentication, issues CWT
- Account token generation with 99-year registration tokens (~5148 weeks)
- Authentication tokens expire in 1 hour
- Uses attestation envelope with ECDSA signature for registration response

**db.rs** - DynamoDB persistence layer
- `UserCredentials` model: user_id, username, credentials[], did
- `DeviceBinding` model: device_id, user_id, public_key, counter, app_id, timestamps
- Username-based queries via GSI (username-index)
- Credential storage as JSON-serialized passkeys in DynamoDB list
- DID format validation (must start with "did:key:")
- Graceful handling of missing handles table during user creation
- Device binding CRUD operations for App Attest

**oidc.rs** - OpenID Connect (OIDC) Provider endpoints
- `/.well-known/openid-configuration`: Discovery document
- `/.well-known/jwks.json`: JWKS (advertises the EC P-256 signing key as a JWK)
- `/oauth/authorize`: Authorization endpoint (code flow with PKCE)
- `/oauth/token`: Token endpoint (issues access_token CWT + id_token JWT, both ES256-signed)
- `/oauth/userinfo`: UserInfo endpoint
- Issues OpenTDF-compatible claims: `iss`, `sub` (e.g. `apple:APPLE_SUB` or
  `arkavo:UUID`), `aud`, `email`, `email_verified`, `idp`,
  `arkavo_account_id`, `arkavo_roles`, `arkavo_entitlements`
- Authorization codes stored in an in-memory `AuthorizationCodeStore` (10-min
  lifetime, single-use). For multi-instance deployments swap for a shared store.
- Confidential clients use `client_secret`; public clients must use PKCE (S256).
- Upstream authentication: WebAuthn-issued Arkavo CWT (via `X-Auth-Token`) or
  Apple id_token (via `idp=apple` + `id_token` query/`X-Apple-Id-Token` header).

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
- `map_apple_user` persists `apple:<sub> → arkavo_account_id` in DynamoDB
  (credentials table, keyed by `apple-<sanitized_sub>` username). Apple `sub`
  is the canonical join key — email is optional metadata and never used to
  locate accounts (private-relay rotation safe).
- Requires `APPLE_CLIENT_ID` to be set (one or more comma-separated values).

**patreon.rs** - Patreon identity linking + membership materialization
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
- `generate_challenge`: Issues random challenge for attestation/assertion
- `finish_attestation`: Validates attestation object, stores device binding
- `generate_assertion_challenge`: Issues challenge for existing devices (requires CWT)
- `finish_assertion`: Verifies assertion, enforces counter increment, issues CWT
- CBOR attestation object parsing ("apple-appattest" format)
- Certificate chain validation to Apple's root CA
- Nonce calculation: SHA256(authData || SHA256(clientData))
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
   - Client requests `/register/:username?handle=...&did=...`
   - Validates DID format and handle consistency
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
     - Server generates random UUID challenge, stores in session
     - Client generates Secure Enclave key via `DCAppAttestService.generateKey()`
     - Client computes clientDataHash = SHA256(challenge)
     - Client performs attestation: `DCAppAttestService.attestKey(keyId, clientDataHash)`
     - Client POSTs attestation object to `/device-check/attest`
     - Server validates:
       - CBOR format is "apple-appattest"
       - Certificate chain anchors to Apple's root CA
       - Nonce = SHA256(authData || clientDataHash)
       - Counter is 0 (initial attestation)
       - rpIdHash matches expected App ID
     - Server stores device binding: device_id, public_key, counter=0, user_id
   - **Ongoing Assertions**:
     - Client requests assertion challenge: `GET /device-check/assert-challenge/:username` (requires CWT)
     - Server issues fresh challenge, validates CWT token
     - Client signs challenge with device key
     - Client POSTs assertion to `/device-check/assert`
     - Server validates:
       - Device binding exists
       - Counter has incremented (counter > stored_counter)
       - Challenge matches expected hash
       - Signature is valid (TODO: implement signature verification)
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

### Session Management
- Memory-based session store (MemoryStore)
- 10-minute inactivity timeout
- Strict SameSite policy
- Session keys: `reg_state` (registration), `auth_state` (authentication)
- Sessions cleaned up immediately after use to prevent reuse

### Error Handling

The codebase uses thiserror for structured error handling:
- `WebauthnError`: Authentication/registration errors with HTTP status mapping
- `DynamoDBError`: Database operation errors with table existence checks
- `DeviceCheckError`: App Attest validation errors (attestation, assertion, counter, certificate chain)
- Errors include helpful context (e.g., "Service setup incomplete: credentials table not configured")

## Testing Patterns

- Unit tests in respective modules:
  - `main.rs`: OAuth callback validation, provider parsing, input sanitization (9 tests)
  - `authn.rs`: DID validation, handle validation, token expiration, error responses (8 tests)
  - `db.rs`: DID format, error conversions, JSON serialization, error messages (8 tests)
  - `device_check.rs`: Challenge generation, authenticator data parsing, counter validation, error responses (10 tests)
  - `oidc.rs`: JWK serialization/thumbprint, PKCE S256 verifier, authorization code
    store lifecycle, discovery/JWKS endpoint shape, claim serialization (26 tests)
  - `apple_signin.rs`: id_token claim deserialization, error status mapping,
    username sanitization, hash stability (6 tests)
  - `cwt.rs`: CWT encoder/decoder, mint/verify, cnf helpers, transport, and strictness (30 tests)
- Test app routing with tower::ServiceExt::oneshot for request simulation
- Mock requests use axum::body::Body::empty()
- Critical test coverage focuses on:
  - Security: DID format validation, handle/username matching
  - Error handling: All error types and conversions
  - Data integrity: JSON serialization roundtrips
  - Configuration: Token expiration constants

## Important Constants

When modifying token lifetimes, update these in authn.rs:
- Registration token: `chrono::Duration::weeks(5148)` (~99 years)
- Authentication token: `chrono::Duration::hours(1)`
- Session timeout: `Duration::seconds(600)` (10 minutes)

## DynamoDB Schema

### credentials table
- **Primary Key**: user_id (String/UUID)
- **Attributes**: username (String), credentials (List of JSON strings), did (String)
- **GSI**: username-index (partition key: username)

### handles table
- **Primary Key**: handle (String)
- **Attributes**: did (String)
- **Format**: Handles are "{username}.arkavo.social"

### device_bindings table
- **Primary Key**: device_id (String) - Key ID from App Attest
- **Attributes**:
  - user_id (String/UUID) - Links to UserCredentials
  - public_key (Binary) - Attested public key from certificate
  - counter (Number) - Monotonic counter for replay protection
  - app_id (String) - rpIdHash for App ID validation
  - created_at (Number) - Unix timestamp
  - updated_at (Number) - Unix timestamp (updated on each assertion)

### identity_links table
- **Primary Key**: link_pk (String) - Format: `<provider>#<subject>` (e.g. `apple#001234.abc...`, `patreon#12345`)
- **Attributes**:
  - user_id (String/UUID) - The arkavo account bound to this third-party identity
  - provider (String) - IdP name (`apple`, `patreon`, future: `google`, etc.)
  - subject (String) - The IdP's stable subject identifier
  - linked_at (Number) - Unix timestamp
- **Uniqueness**: Conditional put on `link_pk` enforces per-(provider, subject) uniqueness.
  Re-linking the same identity to the same user is idempotent; binding to a
  different user returns `DynamoDBError::LinkConflict` (HTTP 409 upstream).
- **PII**: Deliberately minimal. No email, display name, relay address, or
  `real_user_status` is stored here, even if the IdP returns them.
- **Future GSI** `user_id-index`: Add when an endpoint needs to enumerate
  "which providers has this user linked?" — not required by the current
  endpoint surface.

### agent_delegations table
- **Primary Key**: agent_did (String) - `did:key:z6Mk…`
- **Attributes**: delegator_type (`human`|`agent`), delegator_id (String),
  delegator_username (String, optional), entitlements (List of String),
  name (String), depth (Number), root_user_id (String/UUID), chain (List of
  String), created_at / expires_at / revoked_at (Number), and the transient
  challenge triple `challenge`, `challenge_nonce`, `challenge_issued_at`
  (set by `/agents/challenge`, removed atomically by `/agents/token`)
- **GSI**: root_user_id-index (partition key: root_user_id) — list/count a
  user's agents

### patreon_tokens table
- **Primary Key**: user_id (String/UUID) - One row per arkavo user; re-link
  overwrites in place.
- **Attributes**:
  - role (String) - `creator` or `consumer`
  - client_id (String) - The Patreon OAuth client that performed the code
    exchange; refresh must present the same client's secret. Empty on rows
    written before multi-client support (tolerated only while exactly one
    client is configured).
  - patreon_user_id (String) - Patreon's stable `data.id` from `/identity`;
    duplicated here so the materialization read path doesn't need a second
    lookup against `identity_links`
  - campaign_id (String, optional) - Creator only; the Patreon `campaign.id`
    discovered at link time
  - scopes (String) - Space-separated OAuth scopes granted on the token
  - access_token_ct (Binary) - AES-256-GCM ciphertext of the Patreon access
    token under the row's DEK
  - access_token_nonce (Binary) - 12-byte GCM nonce for access_token_ct
  - refresh_token_ct (Binary) - AES-256-GCM ciphertext of the Patreon
    refresh token under the same DEK
  - refresh_token_nonce (Binary) - 12-byte GCM nonce for refresh_token_ct
    (always distinct from access_token_nonce — never reuse key+nonce)
  - wrapped_dek (Binary) - KMS-wrapped 256-bit DEK; decrypt with
    `kms:Decrypt` on `PATREON_KMS_KEY_ID`
  - token_expires_at (Number) - Unix timestamp the Patreon access token
    expires at (per Patreon's `expires_in`)
  - linked_at (Number) - Unix timestamp of original link
- **Encryption**: Envelope. A DynamoDB-only compromise yields ciphertext
  blobs but no plaintext tokens — recovery additionally requires
  `kms:Decrypt` on the configured key.
- **No GSI**: per-Patreon-account uniqueness is enforced via the
  `identity_links` row (`patreon#<patreon_user_id>`), not via a secondary
  index here. The forward `user_id → patreon` lookup uses the table's
  primary key directly.

## Common Development Patterns

### Adding a new WebAuthn endpoint:
1. Add route in main.rs router
2. Implement handler in authn.rs
3. Use Session for state management
4. Return WebauthnError for error handling
5. Clean up session state after completion

### Adding DynamoDB operations:
1. Implement method in DynamoDBStore (db.rs)
2. Use SdkError pattern matching for table existence checks
3. Return DynamoDBError with context
4. Log operations with info!/error! macros

### Token generation pattern:
- Use `cwt::mint(claims, &encoding_key)` for Arkavo-issued tokens (CWT, COSE_Sign1, ES256)
- Use `encode(&header, &claims, &encoding_key)` with ES256 for OIDC `id_token` (JWT only)
- Include sub (user_id) and exp (expiration timestamp) in claims
- Return tokens in X-Auth-Token header or JSON response body

### Adding Apple DeviceCheck endpoints:
1. Add route in main.rs router (e.g., `/device-check/...`)
2. Implement handler in device_check.rs
3. Use Session for challenge storage (attest_state/assert_state keys)
4. Return DeviceCheckError for error handling
5. Validate attestation format, certificate chain, counter, nonce
6. Store device bindings in DynamoDB device_bindings table
7. Enforce monotonic counter increments for assertions

## Apple DeviceCheck Implementation Details

### Security Guarantees
- **Hardware-backed keys**: Secure Enclave generates per-app, per-device keys
- **Certificate chain validation**: Attestation anchored to Apple's root CA
- **Replay protection**: Monotonic counter must increment with each assertion
- **Nonce binding**: Challenge bound to attestation/assertion via SHA256
- **Device verification**: Proves request comes from genuine Apple device running unmodified app
- Assertion CWT carries `arkavo_npe = {type: device, class, attestation_expiry, device_id}` and, when `OIDC_PLATFORM_AUDIENCE` is set, that audience.

### Requirements
- iOS 14+ with Secure Enclave support
- Entitlement: `com.apple.developer.devicecheck.appattest-environment` (development or production)
- Not available in iOS Simulator

### Known Limitations
- Certificate chain validation is incomplete (TODO: implement full chain verification)
- Signature verification not implemented (TODO: verify assertion signatures with stored public key)
- Does not validate certificate extension 1.2.840.113635.100.8.2 (nonce)

### Integration with NTDF
The device binding can be used as the NPE (non-person entity) device/app proof key, enabling:
- Device-bound CWT tokens (proof-of-possession via `cnf` claim, RFC 8747)
- Hardware-backed attestation for NTDF authorization
- Per-device, per-app cryptographic binding to user credentials
