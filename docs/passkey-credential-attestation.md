# Passkey credential attestations

Issue: [#104](https://github.com/arkavo-org/authnz-rs/issues/104). Consumer:
catalog v2 ([tdf-iroh-s3#27](https://github.com/arkavo-org/tdf-iroh-s3/issues/27)),
Creator and arkavo-ios.

A creator signs a catalog pointer with their passkey (a WebAuthn assertion,
RP ID `identity.arkavo.net`). Whoever verifies the pointer (the node on
write, a viewer on read) has to learn which Arkavo account the passkey
belongs to without trusting the node. The IdP already holds that binding, so
it signs a statement of it: a **credential attestation**. A public route says
whether the passkey has since been revoked.

## Issuing: `POST /passkeys/credential-attestation`

- `X-Auth-Token`: the account's **passkey auth CWT** (`aud = arkavo`, from
  `POST /authenticate`). The ~99-year registration token and OIDC access
  tokens are refused (401), as everywhere a passkey auth CWT is required. The
  token's age is not checked beyond its 1 h lifetime.
- Body: `{"credentialId": "<base64url, no padding>"}`. Unknown fields are
  refused. A body that is not that JSON is refused by request parsing
  (400/415/422).
- `200 {"attestation": "<base64url, no padding, of the COSE_Sign1 bytes>"}`,
  `Cache-Control: no-store`.

Every error body is `{"error": "<token>", "error_description": "…"}`:

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_credential_id` | Not canonical base64url without padding (no `=`, URL-safe alphabet, zero trailing bits), or not 1–1023 bytes |
| 401 | `unauthorized` | Missing or invalid passkey auth CWT, or a deleted account |
| 404 | `unknown_credential` | The account does not hold this credential, or it was revoked |
| 409 | `credential_conflict` | The credential is already indexed to another account |
| 422 | `unsupported_key_type` | Not a P-256 (ES256) key, e.g. an RS256 passkey, which registration also admits. Catalog v2 verifies ES256 only |
| 500 | `server_error` | Storage failure; retry |

An account with several passkeys asks once per credential, whenever it
likes. Each call signs a fresh attestation with a new `iat`; any of them is
valid.

## The attestation

**Envelope:** COSE_Sign1 with tag 18 (`0xD2`). Verifiers accept it tagged
or untagged. It is **never** tagged 61 (CWT). External AAD: empty.

**Protected header:**

| Label | Value |
|---|---|
| 1 (`alg`) | -7 (ES256) |
| 4 (`kid`) | the kid of a key in `/.well-known/cose-keys` (today the CWT signing key) |
| 3 (`content type`) | text `"application/arkavo-passkey-credential+cbor"` |

No `crit`. Nothing unprotected.

**Payload:** a CBOR map with text-string keys, exactly these seven, no others:

| Key | Type | Value |
|---|---|---|
| `typ` | text | `"arkavo-passkey-credential"` |
| `iss` | text | `https://identity.arkavo.net` (the IdP's `OIDC_ISSUER`) |
| `sub` | text | the account's `sub` exactly as in its **passkey auth CWT**: the bare account UUID (`0a1b2c3d-…`), not the OIDC `arkavo:<uuid>` form |
| `credentialId` | bytes | the raw credential id |
| `publicKey` | map | COSE_Key: `1` (kty) = 2 (EC2), `-1` (crv) = 1 (P-256), `-2` (x) = 32 bytes, `-3` (y) = 32 bytes. The key stored at registration; no `alg`, no `kid` |
| `rpId` | text | `"identity.arkavo.net"` |
| `iat` | integer | issue time, Unix seconds |

There is **no `exp`**. It states that the credential belonged to `sub` at
`iat`, so a pointer signed later, while the creator is offline, still
verifies. Whether the credential is still good is the status route's
question.

**Never a token.** It has no `aud`, `exp` or `scope`. Every CWT verifier
must refuse it; authnz-rs's own (`cwt::verify`) refuses three ways: no tag 61,
a protected `content type` (no CWT here carries one), a `typ` claim (no CWT
carries one). tdf-iroh-s3's `auth.rs` should refuse a payload with `typ`
too.

### Verifying

1. Decode the COSE_Sign1 (tag 18 or none; refuse tag 61). Protected `alg` must
   be ES256 and `content type` the text above; refuse `crit`.
2. Find `kid` in `https://identity.arkavo.net/.well-known/cose-keys` and verify
   the ES256 signature (`Sig_structure` with empty external AAD).
3. Parse the payload strictly: exactly the seven keys, each once, with the
   types above; `typ` as given; `iss` = `https://identity.arkavo.net`;
   `rpId` = `identity.arkavo.net`; `publicKey` a valid P-256 point.
4. Then the caller's own binding (catalog v2: `sub == pointer.owner`,
   `credentialId == assertion.credentialId`), and verify the WebAuthn
   assertion against `publicKey`.

The WebAuthn relying party accepts exactly one origin,
`https://identity.arkavo.net`, for RP ID `identity.arkavo.net`
(`constants::WEBAUTHN_RP_ORIGIN` / `WEBAUTHN_RP_ID`), so a verifier requires
`clientDataJSON.origin == "https://identity.arkavo.net"` and
`authenticatorData.rpIdHash == SHA-256("identity.arkavo.net")`. Synced
passkeys report `signCount` 0: ignore it.

`credential_attestation::verify` in this repo implements steps 1–3 against
one key and is what the tests pin.

### Key rotation

Because an attestation has no expiry, the key that signed it must stay
listed in `/.well-known/cose-keys` for as long as pointers signed under it
should verify. `cose-keys` serves one key today; a rotation must keep
serving the retired key (verification only) alongside the new one.

## Status: `GET /passkeys/credentials/{credentialId}/status`

Public, no token. `{credentialId}` is base64url without padding, the same
canonical form as above.

- `200 {"sub": "<uuid>", "revoked": false}`
- `200 {"sub": "<uuid>", "revoked": true, "revokedAt": <unix secs>}` (`revokedAt`
  omitted when the time is not known)
- `404 {"error": "unknown_credential", …}`: no attestation was ever issued for
  this credential (so no pointer can cite it).
- `400 {"error": "invalid_credential_id", …}`
- `Cache-Control: no-store` on every answer: the node checks it on write to
  refuse a revoked passkey, which a cache would defeat.

A credential is revoked when its index row is marked revoked, when the
account has been deleted (reported from the moment of deletion, with
`revokedAt` = the deletion time, before and after the deletion sweep), or
when the account no longer holds it. There is no passkey-removal route yet;
account deletion is today's only removal. A route added later must mark the
row revoked, never delete it.

The node refuses a publish on 404 or `revoked: true`, and an unreachable IdP
is its 502.

## Storage

One `identity_links` row per attested credential (no new table):
`link_pk = passkey#<base64url credentialId>`, `user_id`, `provider =
passkey`, `subject = <base64url credentialId>`, `linked_at` (first
attestation), `revoked_at` (optional). Written by the first attestation of
the credential, conditional on no row or this account's unrevoked row, so it
never moves to another account or comes back from revocation. Passkeys
registered before #104 get their row on their first attestation.

Account deletion's sweep leaves these rows in place (the identity-link
deletion skips `provider = passkey`) and sets `revoked_at` to the deletion
time if it is not set. No sign-in path reads them: federated sign-in
resolves only `apple` and `google` rows.
