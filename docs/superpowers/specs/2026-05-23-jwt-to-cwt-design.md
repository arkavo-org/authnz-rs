# JWT → CWT Migration Design

**Date:** 2026-05-23
**Branch:** `feature/jwt-to-cwt`
**Author:** Paul Flynn (with Claude)
**Status:** Approved design, awaiting implementation plan

## Summary

Migrate all Arkavo-issued authentication tokens from JWT (JOSE) to CWT (CBOR Web Token, RFC 8392). This replaces the unmerged NTDF direction with the IETF-standard equivalent.

**In scope:**
- Registration tokens, auth tokens, DeviceCheck assertion tokens, and OIDC `access_token` become CWT (COSE_Sign1, ES256).
- All inbound JWT acceptance on Arkavo authentication paths is removed (hard cutover).
- `cnf` (RFC 8747) claim is populated as bound-at-issuance metadata where a key exists.

**Out of scope (deferred to future work):**
- DPoP / per-request proof-of-possession signing.
- OIDC `id_token` (stays JWT — required by OIDC Core spec).
- Apple `id_token` validation (stays JWT — Apple controls the format).
- Refresh token format (stays opaque, Redis-backed).
- Key rotation.
- Token revocation lists (`cti` reserved for future use).

## Motivation

1. **Size and parsing performance** for upcoming constrained-channel use cases (NFC, BLE, embedded).
2. **Defense in depth** — narrower parser attack surface than JOSE/JSON. The class of bug that produced `jsonwebtoken` CVE-2026-25537 (Type Confusion) becomes structurally harder.
3. **PoP / hardware-key alignment** — COSE_Key is the native shape for App Attest and WebAuthn credentials. Including `cnf` now (even unenforced) makes future DPoP-equivalent work additive rather than a schema break.
4. **Replaces NTDF.** The `feature/transactional-account-linking` draft branch experimented with NTDF tokens layered on OpenTDF nano-TDF. CWT is the IETF-standardized alternative; this migration supersedes that work.

## Architecture

A single new module `src/cwt.rs` owns every CWT-specific concern. Existing modules import from it and never touch `coset` or `ciborium` directly.

```
src/cwt.rs                  (new, ~400 LOC)
├── ArkavoClaims            strongly-typed claims struct
├── TokenKind enum          Registration | Auth | DeviceCheckAssertion | OidcAccess
├── fn mint(claims, key)    → Vec<u8> COSE_Sign1 bytes
├── fn verify(bytes, key)   → Result<ArkavoClaims, CwtError>
├── fn encode_for_header()  → String (base64url for X-Auth-Token / Bearer)
├── fn decode_from_header() → Result<Vec<u8>, CwtError>
├── COSE_Key advertisement helper (P-256 EC key → coset::CoseKey)
└── cnf_from_passkey() / cnf_from_app_attest() helpers

src/authn.rs                — JWT calls replaced with cwt::mint / cwt::verify
src/device_check.rs         — same
src/oidc.rs                 — access_token uses cwt::mint; id_token stays JWT;
                              new /.well-known/cose-keys endpoint
src/main.rs                 — AppState gains cwt_signing_key; existing
                              EncodingKey/DecodingKey kept ONLY for id_token

Cargo.toml
├── + coset = "0.3"
├── + ciborium = "0.2"
└── jsonwebtoken stays (id_token issuance + Apple validation)
```

The `jsonwebtoken` dependency narrows from "all our auth" to "OIDC `id_token` issuance + Apple `id_token` validation" — a strict reduction in attack surface even though the crate stays present.

## Claim Schema

CWT claims are a CBOR map. Registered claims use integer labels (RFC 8392); arkavo-specific claims use string labels for debuggability.

### Standard claims (integer labels)

| Label | Name | Type | Notes |
|------:|------|------|-------|
| 1 | `iss` | tstr | `https://identity.arkavo.net` (or `OIDC_ISSUER`) |
| 2 | `sub` | tstr | `arkavo:UUID`, `apple:APPLE_SUB`, or `client:CLIENT_ID` for client-credentials grants |
| 3 | `aud` | tstr or tstr[] | `arkavo` (auth/registration), RP `client_id` (OIDC access), `arkavo:devicecheck` (DeviceCheck assertion) |
| 4 | `exp` | uint (NumericDate) | required |
| 6 | `iat` | uint (NumericDate) | required |
| 7 | `cti` | bstr | 16 random bytes — `jti` equivalent, reserved for future revocation |
| 8 | `cnf` | map | RFC 8747 — see below |

### `cnf` claim (RFC 8747 — bound-at-issuance, not verifier-enforced in this phase)

```
cnf = {
  1 (COSE_Key): { ... P-256 EC key ... },
  2 (kid): <credential_id-or-key_id as bstr>
}
```

Populated per token kind:

| Token kind | `cnf` content |
|------------|---------------|
| Registration token (WebAuthn) | COSE_Key from the registered passkey credential; kid = credential_id |
| Auth token (WebAuthn) | Same as registration |
| DeviceCheck assertion | COSE_Key from the attested App Attest key; kid = device_id |
| OIDC access_token (WebAuthn user) | COSE_Key from the passkey used in the upstream ceremony |
| OIDC access_token (Apple-only user) | **Omitted** (no hardware key available) |
| OIDC access_token (client_credentials grant) | **Omitted** |

### Custom claims (string labels)

| Label | Type | Used in |
|------|------|---------|
| `"idp"` | tstr (`apple` \| `arkavo`) | OIDC access token |
| `"email"` / `"email_verified"` | tstr / bool | OIDC access token |
| `"arkavo_account_id"` | tstr | OIDC access token |
| `"arkavo_roles"` | tstr[] | OIDC access token |
| `"arkavo_entitlements"` | tstr[] | OIDC access token |

DeviceCheck assertion tokens identify the device via `cnf.kid` (the device_id is the key ID of the App Attest key); no separate `"device_id"` string claim.

### Removed claims

The current JWT registration token carries a `passkey` claim — the full `webauthn-rs` `Passkey` struct, used as a fallback when the DynamoDB credentials lookup misses (`authn.rs:283`). This claim is **removed**. The `cnf` claim carries the COSE_Key + credential_id, which is the cryptographic identity of the credential; the rest of the `Passkey` state (counter, AAGUID, transports, extensions) lives in DynamoDB only.

**Consequence:** the JWT-embedded-passkey fallback path goes away. If DynamoDB is unavailable the request fails, rather than silently authenticating from a stale embedded credential. This is a deliberate cleanup — the fallback was always redundant and could mask a counter desync.

### Design rationale

- **Strings for custom labels, not private-use integers.** Not yet in size-constrained contexts; debuggability and grep-friendly logs win. Adding integer aliases later is non-breaking (CWT decoders are required to accept both).
- **`cti` mandatory now.** Cheap to include; expensive to retrofit. Unblocks future revocation work.
- **No `nonce` claim in CWT.** OIDC `nonce` lives only in `id_token`, which stays JWT.

## Issuance Paths

Each existing JWT-minting site moves to `cwt::mint`. Mapping:

| Site | Current | After |
|------|---------|-------|
| `authn.rs:417` (auth token, 1h) | `encode(&header, &claims, &encoding_key)` | `cwt::mint(ArkavoClaims::auth(...), &cwt_key)` |
| `authn.rs:~200` (registration token, ~99y) | same | `cwt::mint(ArkavoClaims::registration(...), &cwt_key)` |
| `device_check.rs:575` (assertion token, 1h) | same | `cwt::mint(ArkavoClaims::devicecheck(...), &cwt_key)` |
| `oidc.rs:882` (access_token, WebAuthn flow) | same | `cwt::mint(ArkavoClaims::oidc_access(...), &cwt_key)` |
| `oidc.rs:1026` (access_token, Apple flow) | same | `cwt::mint(ArkavoClaims::oidc_access(...).without_cnf(), &cwt_key)` |
| `oidc.rs:1202` (access_token, refresh / client-credentials) | same | `cwt::mint(ArkavoClaims::oidc_access(...).without_cnf(), &cwt_key)` |
| `oidc.rs:871, 1015, 1191` (id_token, 1h) | same | **unchanged** — stays JWT |

### Transport encoding

- `X-Auth-Token` header (Arkavo native flows): base64url-encoded CWT bytes, no padding. Header length is roughly the same as today's JWT (CBOR savings on the claim map roughly offset COSE_Sign1's envelope overhead — typical claims fit in 300–500 bytes).
- OIDC `Authorization: Bearer <token>`: same base64url encoding. RFC 6750 does not require JWT; opaque bytes are conforming. RPs discover the format via the discovery extension below.

### Builder ergonomics

```rust
let token = cwt::mint(
    ArkavoClaims::auth(user_id, AUTH_TOKEN_HOURS)
        .with_cnf_from_passkey(&credential),
    &app_state.cwt_signing_key,
)?;
```

## Verification Path

`cwt::verify(bytes, &cwt_verifying_key) → Result<ArkavoClaims, CwtError>`:

1. Parse COSE_Sign1 envelope (`coset::CoseSign1::from_slice`).
2. Reject if `alg` ≠ ES256 (COSE label `-7`).
3. Reject if no `alg` in the **protected** header (no header injection via unprotected map).
4. Verify signature against key.
5. Decode payload as CBOR claims map (strict mode — duplicate keys rejected, non-canonical encodings rejected).
6. Validate: `iss` matches expected, `exp > now − 60s`, `iat ≤ now + 60s`.
7. Return strongly-typed `ArkavoClaims`.

### Deliberate strictness choices

- **No `alg = none` equivalent.** COSE has no `none` algorithm, but missing protected-header `alg` is the moral equivalent. Rejected.
- **Single accepted algorithm.** Only ES256. Forecloses algorithm-confusion attacks at the parser.
- **Strict CBOR mode.** `ciborium` configured to reject duplicate map keys and non-canonical encodings.
- **`exp` / `iat` enforced.** Current JWT code intentionally disables these (the comment in CLAUDE.md notes "security relies on WebAuthn ceremony, not token expiration"). CWT re-enables them. Registration tokens still have a 99-year `exp` so they keep working; short-lived tokens (auth, access, assertion) start enforcing actual lifetimes.
- **Clock skew tolerance:** ±60 seconds, declared as a constant in `src/cwt.rs`.

### Call-site updates

| Site | Purpose | Behavior change |
|------|---------|-----------------|
| `authn.rs:~265` (auth ceremony — decoding inbound X-Auth-Token) | Get user_id + (today) embedded passkey | Read cnf; full Passkey from DB only |
| `device_check.rs:334` (assertion challenge — validating inbound JWT) | Confirm caller is authenticated | CWT verify; sub from claim 2 |
| `oidc.rs:~1427` (`/oauth/token`, upstream WebAuthn auth) | Validate X-Auth-Token from authorize step | CWT verify |
| `apple_signin.rs:321` (Apple id_token) | Apple JWT validation | **unchanged** |

## Key Advertisement

One physical EC P-256 key signs both JWT (`id_token`) and CWT (everything else). Two endpoints prevent client-side format conversion.

| Path | Format | Consumers |
|------|--------|-----------|
| `/.well-known/jwks.json` | JWKS (existing) | OIDC RPs verifying `id_token` |
| `/.well-known/cose-keys` | COSE_Key Set, CBOR (new) | OpenTDF + Arkavo native verifying CWT |

### Key ID consistency

The same `kid` (base64url SHA-256 of the SPKI, scheme unchanged from today) appears in:

- JWK `kid` field
- COSE_Key label `2` (`kid`)
- JWT protected header `kid`
- CWT protected header label `4` (`kid`)

So a verifier holding either format can resolve the same physical key, and future rotation works identically in both ecosystems.

### `/.well-known/cose-keys` response

- `Content-Type: application/cose-key-set+cbor` (RFC 9052 §7)
- Body: CBOR array of COSE_Key maps. Initially one entry; the structure accommodates multiple during future rotation.
- `Cache-Control: public, max-age=600` — matches JWKS.

### Discovery doc additions (`/.well-known/openid-configuration`)

```json
{
  "...existing fields unchanged...": "...",
  "id_token_signing_alg_values_supported": ["ES256"],
  "arkavo_access_token_format": "application/cwt",
  "arkavo_cose_keys_uri": "https://identity.arkavo.net/.well-known/cose-keys"
}
```

`arkavo_*` extensions are non-disruptive — conforming OIDC RPs ignore unknown fields. CWT-aware RPs can auto-detect rather than rely on out-of-band docs.

## Migration & Error Handling

### Cutover behavior

| Behavior | Before | After |
|----------|--------|-------|
| Inbound `X-Auth-Token` to any auth endpoint | JWT decode; JWT-payload fallback if DB misses | CWT decode. **JWT inbound → 401, `cwt_required`.** No fallback. |
| Inbound `Authorization: Bearer …` to `/oauth/userinfo` and protected OIDC endpoints | JWT decode | CWT decode. Pre-existing JWT access tokens → 401. |
| `exp` / `iat` enforcement | Disabled | Enforced with ±60s skew |
| Apple `id_token` validation | JWT | JWT (unchanged) |
| OIDC `id_token` issued | JWT | JWT (unchanged) |
| OIDC `access_token` issued | JWT | **CWT** (breaking for RPs that parse it as JWT) |
| Passkey fallback in `authn.rs:283` | JWT-embedded passkey used if DB lookup misses | Removed; DB lookup miss → error |

### Error model

```rust
pub enum CwtError {
    Malformed,                  // Not valid COSE_Sign1 / CBOR
    UnsupportedAlg,             // alg != ES256 or missing
    InvalidSignature,
    Expired,                    // exp ≤ now − skew
    NotYetValid,                // iat > now + skew
    MissingClaim(&'static str), // required claim absent
    IssuerMismatch,
    AudienceMismatch,
}
```

HTTP mapping:

- `Malformed`, `UnsupportedAlg`, `MissingClaim`, `IssuerMismatch`, `AudienceMismatch` → 400
- `InvalidSignature`, `Expired`, `NotYetValid` → 401 (with `WWW-Authenticate: Bearer error="invalid_token", error_description="…"` for OIDC paths)

OIDC `/oauth/token` error responses follow RFC 6749 codes (`invalid_token`, `invalid_request`); CWT failures map onto these.

### User-facing migration

- **All existing users re-register.** No accounts deleted server-side; DynamoDB `credentials` rows remain intact. Old JWT registration tokens stop working, so the only way in is a fresh WebAuthn ceremony.
- **Recommended in-app flow** (out of scope for this repo, but flagged for Arkavo iOS/macOS releases): on first launch after upgrade, detect JWT vs CWT in stored token; if JWT, trigger `start_authentication`. After one passkey ceremony the client gets a fresh CWT — the underlying credential is preserved.
- **OpenTDF coordination.** Externally-visible breaking change. Sequence:
  1. Land this branch in `main`.
  2. Before deploying to production OpenTDF integrations, ship `tdf-rs` updates that handle CWT access tokens.
  3. Discovery doc's `arkavo_access_token_format` field gives future RP integrators a programmatic signal.

### Rollout

Single deploy, no feature flag. The hard-cutover decision is the basis for the simpler verifier code path; a flag would re-add the JWT verifier we set out to remove. Rollback = revert the branch.

## Testing Strategy

### `src/cwt.rs` unit tests (~15 new tests)

**Roundtrip:**

- Mint each token kind (`registration`, `auth`, `devicecheck`, `oidc_access`) and roundtrip claims byte-for-byte.
- `cnf` present where expected (WebAuthn, DeviceCheck) and absent where expected (Apple-only access, client_credentials).
- `cti` is 16 random bytes and differs across mints (entropy sanity).

**Strictness:**

- `alg = ES256 (-7)` accepted; other algs in protected header → `UnsupportedAlg`.
- Missing `alg` in protected header → `UnsupportedAlg`.
- Duplicate map keys in CBOR payload → `Malformed`.
- Tampered signature → `InvalidSignature`.
- Tampered payload (1 bit) → `InvalidSignature`.
- Wrong key → `InvalidSignature`.
- `exp ≤ now − 60s` → `Expired`.
- `iat > now + 60s` → `NotYetValid`.
- Within ±60s skew → accepted.
- `iss` mismatch → `IssuerMismatch`.
- `aud` mismatch (tstr and tstr[] variants) → `AudienceMismatch`.
- Missing required claim (`sub`, `exp`, `iat`) → `MissingClaim`.

**Transport:**

- `encode_for_header` produces base64url with no padding; round-trips through `decode_from_header`.
- Header-bytes-length sanity (regression catcher if claim schema balloons).

### Updates to existing module tests (~10 modifications)

- `authn.rs::tests`: fixtures move to `cwt::mint`. New test: legacy JWT inbound → 401 `cwt_required`. Drop tests that exercised the JWT-embedded-passkey fallback.
- `device_check.rs::tests`: same — fixture tokens become CWTs; JWT-rejection test added.
- `oidc.rs::tests`:
  - `test_jwks_endpoint_returns_single_key` unchanged.
  - New `test_cose_keys_endpoint_returns_single_key`.
  - `test_discovery_endpoint_returns_expected_shape` extended for `arkavo_access_token_format` and `arkavo_cose_keys_uri`.
  - Three access-token issuance tests (WebAuthn / Apple / refresh flows) assert the token parses as COSE_Sign1, not JWT.
  - New: JWT-format access token presented to `/oauth/userinfo` → 401.

### Integration test (`tests/integration_test.rs`)

One end-to-end test: spin up the app with a temporary EC key, complete WebAuthn registration → auth → present CWT to a protected endpoint, all via `tower::ServiceExt::oneshot`. Assert tokens emitted are CWT; JWT presented anywhere → 401.

Full OIDC-flow integration testing stays out of this branch (matches current repo discipline — OIDC is unit-tested only).

### Manual verification before merge

1. `cargo test` — all green (existing 68 + new ~20–30).
2. `cargo clippy --tests` — clean.
3. Local `curl /.well-known/cose-keys` returns valid CBOR; decoded key matches `/.well-known/jwks.json` (same x/y/kid).
4. Local end-to-end with a feature branch of the Arkavo iOS client that can verify CWT.

### Not tested in this branch

- Cross-repo OpenTDF / tdf-rs compatibility — tracked as a pre-merge checklist item, coordinated release.
- CWT performance benchmarks — motivation is sufficient; no perf gate.

## Open questions

None at design time. All decisions captured above.
