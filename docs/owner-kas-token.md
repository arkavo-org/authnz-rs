# Owner-KAS token (`POST /owner-kas/token`)

authnz-rs#146. Agreed with arkavo-ios on 2026-11-08 and approved by the owner
the same day. The design it serves is arkavo-ios's owner-KAS design, §4.1, at
https://github.com/arkavo-org/arkavo-ios/blob/7d11e02/docs/superpowers/specs/2026-11-08-owner-kas-design.md
(arkavo-ios#78), which names this file as the source of the same contract.
Change this contract only together with arkavo-ios and arkavo-rs.

## Why

In arkavo-ios's owner KAS, the owner's iPhone, not a server, decides each
key release. The owner KAS answers OpenTDF's standard Rewrap at its KAS URL on
the relay (arkavo-rs#163, platform.arkavo.net):
`https://platform.arkavo.net/owner-kas/v1/routes/<route_id>/kas.AccessService/Rewrap`.
The relay forwards the request to the owner's phone.

The receiver's session token must never reach another user's device
(arkavo-ios ADR-0072), so it goes only to `POST /owner-kas/token`. This token
is the Rewrap's bearer token (`Authorization: Bearer`). The Rewrap's
`signed_request_token` is an ES256 JWT signed by the `cnf` key: OpenTDF's
token-plus-signed-request (DPoP) pattern. The token is bound to one owner
route and to the receiver's per-attempt request key, and it lives 900 s.

## Request

```
POST /owner-kas/token
X-Auth-Token: <passkey auth CWT>
Content-Type: application/json

{ "route_id": "01JC5Z8Q4M7N2P3R6S9T0V1W2X", "cnf_key": "<base64url>" }
```

- **`X-Auth-Token`**: the receiver's passkey auth CWT. Both the original
  (from `POST /authenticate`) and a renewed one (`POST /session/refresh`) are
  accepted. The check requires `aud` `arkavo`, no `scope`, a lifetime of at
  most 1 h, and a live account. OIDC access tokens, DeviceCheck tokens and
  the registration token are refused.
- **`route_id`**: a canonical ULID: 26 uppercase Crockford base-32
  characters (`0-9`, `A-Z` without `I`, `L`, `O`, `U`), the first `0`–`7`.
  It is never normalized: lowercase is refused.
- **`cnf_key`**: base64url without padding of the 65-byte SEC1 uncompressed
  point `04‖X‖Y`. It must be a valid P-256 point.

Identity does not check that the route exists, and stores nothing.

## Responses

| Status | Body | When |
|---|---|---|
| 200 | `{"token": "<base64url>", "expires_at": <unix s>}` | minted |
| 401 | `{"error":"unauthorized"}` | no valid passkey auth CWT, or the account is deleted |
| 400 | `{"error":"invalid_request"}` | the body is not `{route_id, cnf_key}` |
| 400 | `{"error":"invalid_route_id"}` | not a canonical ULID |
| 400 | `{"error":"invalid_cnf_key"}` | not an unpadded base64url P-256 point |
| 429 | `{"error":"rate_limited"}`, `Retry-After` | more than 30 mints by the account in a minute |
| 500 | `{"error":"server_error"}` | the account could not be read, or signing failed |

Every response is `Cache-Control: no-store`. The 400s are decided before the
account is read. The rate limit is per account and in process. The app mints
only on Open and "Try again", never while polling.

## The token

`token` is base64url (no padding) of CBOR tag 61 (CWT) around a COSE_Sign1:

- **Protected header**: `alg` (1) ES256, `kid` (4) the signing key's id in
  `/.well-known/cose-keys`, `content type` (3)
  **`application/owner-kas+cwt`**. Unprotected header empty; external AAD
  empty.
- **Payload**: a CBOR map with exactly these keys, in this (deterministic,
  RFC 8949 §4.2.1) order:

| Key | Claim | Value |
|---|---|---|
| 1 | `iss` | `https://identity.arkavo.net` (`OIDC_ISSUER`) |
| 2 | `sub` | the receiver's bare lowercase account UUID, as in the passkey CWT |
| 3 | `aud` | `owner-kas:<route_id>`, one text string |
| 4 | `exp` | `iat` + 900 |
| 6 | `iat` | mint time, unix seconds |
| 7 | `cti` | 16 random bytes |
| 8 | `cnf` | `{1: {1: 2, -1: 1, -2: x, -3: y}}`: a COSE_Key (kty EC2, crv P-256) with no `kid` and no `alg` |
| `"arkavo_handle"` | | the receiver's permanent handle, full and lowercase (`alice.arkavo.social`). It is the handle, never the changeable username (#132). Always present |

Nothing else. There is no entitlement, Patreon data or email, because the
token lands on another user's phone.

## Verifying

1. Strip tag 61. Require ES256, exactly the content type above, a `kid` in
   identity's COSE key set, and a valid signature.
2. Require exactly the payload keys above, `iss` as above, `aud` equal to
   `owner-kas:` + the owner's own route id, and `exp - iat` ≤ 900.
3. Check `exp` and `iat` against the phone's clock when it services the
   request, with 60 s of skew. The phone has no trusted submission time, so
   900 s is the owner's window to answer.
4. The owner's phone verifies the Rewrap's `signed_request_token` under the
   `cnf` key.

The relay verifies the token too, on its owner-KAS receiver routes (Rewrap,
polling, the route-record read). It applies steps 1–3, with `aud` equal to
`owner-kas:` + the route id in the path, uses `sub` to identify the submitter,
and decides no access.

`owner_kas_token::verify` in this repository is a reference implementation
of steps 1–3.

## What refuses it

- **Identity**: `cwt::verify` refuses any protected content type, so the
  token passes no identity route. `GET /oauth/userinfo` also takes only an
  access token whose `aud` names a registered OIDC client.
- **Every relying party except the relay's owner-KAS receiver routes on
  platform.arkavo.net** must refuse the `owner-kas:` audience. Only the
  owner's phone checks the `cnf` signature, so a verifier that checks neither
  the audience nor the content type would take this token as the receiver for
  up to 900 s.
