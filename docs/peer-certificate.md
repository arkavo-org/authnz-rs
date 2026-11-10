# Peer certificate (`POST /peer/certificate`)

authnz-rs#143. **Proposed 2026-11-09: not yet agreed with ArkavoKit or with
any app that verifies it.** Once agreed, change it only together with them.

## Why

Two devices on a local network, with no internet and no server between them,
must each prove which account they are. No token identity mints today can do
that: each lives an hour at most, and none is bound to a key that can sign
a peer protocol's messages.

A peer certificate is identity's dated statement that a key belonged to an
account. The app holds the key (a Secure Enclave P-256 key that signs
arbitrary bytes). A peer checks the certificate offline, against a copy of
identity's keys it stored earlier, and then has the other side prove it holds
the key.

It is not a session token. No online service accepts it, and identity
refuses it everywhere. It carries no entitlement.

## Request

```
POST /peer/certificate
X-Auth-Token: <passkey auth CWT>
Content-Type: application/json

{ "audience": "<peer audience>", "cnf_key": "<base64url>", "proof": "<base64url>" }
```

- **`X-Auth-Token`**: the account's passkey auth CWT. Both the original
  (from `POST /authenticate`) and a renewed one (`POST /session/refresh`) are
  accepted. The check requires `aud` `arkavo`, no `scope`, a lifetime of at
  most 1 h, and a live account. OIDC access tokens, DeviceCheck tokens and
  the registration token are refused.
- **`audience`**: the peer protocol the certificate is for. It must be one of
  the values the operator lists in `PEER_AUDIENCES`. Each app's peer protocol
  has its own, so a certificate for one is refused by another.
- **`cnf_key`**: the peer key. Base64url without padding of the 65-byte SEC1
  uncompressed point `04‖X‖Y`. It must be a valid P-256 point.
- **`proof`**: possession of the peer key. Base64url without padding of the
  raw 64-byte `r‖s` ECDSA P-256 SHA-256 signature (never DER) by the peer
  key over the UTF-8 bytes of:

  ```
  arkavo-peer-certificate-v1
  <sub>
  <cti>
  <audience>
  <cnf_key>
  ```

  Five lines joined by `\n`, with no trailing newline. `<sub>` and `<cti>`
  are the `sub` claim of the `X-Auth-Token` (the bare lowercase account UUID)
  and its `cti` claim as base64url without padding. `<audience>` and
  `<cnf_key>` are the request's strings exactly as sent.

The mint stores nothing.

## Responses

| Status | Body | When |
|---|---|---|
| 200 | `{"certificate": "<base64url>", "expires_at": <unix s>}` | minted |
| 503 | `{"error":"peer_certificates_unavailable"}` | the operator has not set `PEER_AUDIENCES` |
| 401 | `{"error":"unauthorized"}` | no valid passkey auth CWT, or the account is deleted |
| 400 | `{"error":"invalid_request"}` | the body is not `{audience, cnf_key, proof}` |
| 400 | `{"error":"invalid_audience"}` | not a listed audience |
| 400 | `{"error":"invalid_cnf_key"}` | not an unpadded base64url P-256 point |
| 400 | `{"error":"invalid_proof"}` | not a valid signature by `cnf_key` over the message above |
| 429 | `{"error":"rate_limited"}`, `Retry-After` | more than 10 mints by the account in a minute |
| 500 | `{"error":"server_error"}` | the account could not be read, or signing failed |

Every response is `Cache-Control: no-store`. The 503 is decided first, then
the 401 for the token, then the 400s, all before the account is read. The
rate limit is per account and in process.

## The certificate

`certificate` is base64url (no padding) of CBOR tag 61 (CWT) around a
COSE_Sign1:

- **Protected header**: `alg` (1) ES256, `kid` (4) the signing key's id in
  `/.well-known/cose-keys`, `content type` (3)
  **`application/peer-certificate+cwt`**. Unprotected header empty; external
  AAD empty.
- **Payload**: a CBOR map with exactly these keys, in this (deterministic,
  RFC 8949 §4.2.1) order:

| Key | Claim | Value |
|---|---|---|
| 1 | `iss` | the issuer (`OIDC_ISSUER`, `https://identity.arkavo.net`) |
| 2 | `sub` | the account's bare lowercase UUID, as in the passkey CWT |
| 3 | `aud` | the requested audience, one text string |
| 4 | `exp` | `iat` + `PEER_CERT_SECONDS` (default and maximum 604800, 7 days) |
| 6 | `iat` | mint time, unix seconds |
| 7 | `cti` | 16 random bytes |
| 8 | `cnf` | `{1: {1: 2, -1: 1, -2: x, -3: y}}`: a COSE_Key (kty EC2, crv P-256) with no `kid` and no `alg` |
| `"auth_time"` | | when the account last asserted its passkey, unix seconds: the session's assertion time for a renewed token, else the token's `iat` |
| `"arkavo_handle"` | | the account's permanent handle, full and lowercase (`alice.arkavo.social`). It is the handle, never the changeable username (#132). Always present |

Nothing else. There is no entitlement, Patreon data, email or app
attestation. An entitlement must never be added: the certificate lives far
longer than any token an entitlement may ride in, and it is shown to other
users' devices.

## Verifying (the peer, offline)

1. Strip tag 61. Require ES256, exactly the content type above, a `kid` in
   the stored copy of identity's COSE key set, and a valid signature.
2. Require exactly the payload keys above, `iss` equal to the issuer, `aud`
   equal to the verifier's own peer audience, and `exp - iat` ≤ 604800.
3. Check `exp` and `iat` against the device's clock, with 60 s of skew.
4. **Have the other side prove it holds the `cnf` key** (below). A
   certificate alone proves nothing: anyone on the network who saw it can
   send it again.
5. Optionally apply a stricter rule from `auth_time` (for example, refuse a
   peer that last used its passkey more than N days ago).

`peer_certificate::verify` in this repository is a reference implementation
of steps 1–3.

### The live proof

The peer protocol, not identity, defines it. It must have these properties:

- Each side sends the other a fresh random challenge, and each signs with its
  `cnf` key.
- The signed message starts with a fixed context string of the protocol's
  own, and covers both challenges and both certificates (or their hashes), so
  a signature cannot be replayed in another session or relayed between two
  sessions.
- A device never signs bytes a peer supplied as they are. The peer key
  signs only messages built by the app under that context string. The mint's
  own proof message starts with `arkavo-peer-certificate-v1` for the same
  reason: a peer cannot get a device to sign a mint request.
- If the transport has a channel binding (a TLS exporter, a Noise handshake
  hash), sign it too.

### Identity's keys, offline

- Fetch `/.well-known/cose-keys` whenever the device is online and store it
  on disk. Select the key by `kid`. The response's 600 s cache lifetime is
  for online consumers; a peer keeps its copy until it can fetch a newer
  one.
- Identity keeps a signing key in the set for at least 7 days after it stops
  signing, and publishes a new key at least 7 days before it signs
  ([key-rotation.md](key-rotation.md)). So a device that fetched the set
  within the last 7 days can verify every certificate that has not expired.
  A device offline for longer may meet a `kid` it does not know: it refuses
  that peer until it has been online.
- A leaked key is removed at once. A device keeps trusting it until it
  fetches the set again.

## When the client mints

- After sign-in, and again whenever it renews its auth token
  ([session-renewal.md](session-renewal.md)) and the certificate has used
  more than a day of its life. Never on a background timer: the renewal rule
  applies here too. Minting does not extend the session.
- One peer key per device and account. Keep the same key across mints. A new
  key needs only a new mint.
- On sign-out and on account deletion, delete the peer key and the
  certificate. Deleting the key ends the certificate on that device.

## What it does not do

- **It cannot be revoked.** Identity keeps no record of certificates, and an
  offline peer could not check one anyway. After an account is deleted, or a
  device is lost unlocked, its certificate verifies until `exp`. The
  lifetime is the revocation lag; the operator can shorten it with
  `PEER_CERT_SECONDS`.
- **It outlives the session that minted it.** A session ends 24 h after the
  passkey assertion; the certificate lasts up to 7 days. This is deliberate.
  It is safe only because no online service accepts the certificate.
- **A stolen auth token can mint one.** Whoever holds a valid passkey auth
  CWT (1 h) can mint a certificate for a key of their own and then pass as
  that account to peers for up to 7 days. The auth token is not bound to a
  device key on this route. This is accepted for now; binding the mint to
  the session's device key or to App Attest (#81) would close it.
- **It does not prove where the key lives.** Identity cannot tell a Secure
  Enclave key from a software key.
- **It says nothing about what the account may do.** A peer that needs an
  entitlement decision gets it another way.

## Other verifiers

A service that verifies identity's CWTs must refuse this one. The protected
content type marks it: identity's own `cwt::verify` refuses any content type.
As a second guard, identity refuses to start if a `PEER_AUDIENCES` value is
the passkey audience (`arkavo`), the platform audience, an OIDC client id or
an agent token audience, or starts with `arkavo:` or `owner-kas:`.
