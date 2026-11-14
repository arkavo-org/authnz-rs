---
paths:
  - "src/session.rs"
  - "src/session_tests.rs"
  - "src/db/session.rs"
  - "src/passkeys.rs"
  - "src/passkeys_tests.rs"
  - "src/credential_attestation.rs"
  - "src/db/passkeys.rs"
---

# Passkey sessions and credential attestations

## session.rs: Passkey session renewal (#108)

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
- A renewed token carries `arkavo_apple_linked` from the `credentials` row
  it re-reads (`passkey_auth_claims`), so a link or unlink on another Mac
  shows on the next renewal.
- **A renewed token carries `auth_time` = the session's assertion time** and
  `exp` ≤ the 24 h deadline. Every "recent passkey assertion" check reads
  `cwt::passkey_assertion_time` (`auth_time` else `iat`): enrollment,
  `oidc::webauthn_auth_time`, `agent::verify_passkey_auth_token` (delegation,
  recovery, account deletion). A new freshness check must use it, never `iat`.
- Rows: `identity_links` `session#<id>`, `provider = session`
  (`db/session.rs`); `expires_at` is written for a future TTL. The deletion
  sweep's link step removes them.
- Signatures are raw r‖s (64 bytes), never DER.

## passkeys.rs: Passkey credential attestations (#104, catalog v2)

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
