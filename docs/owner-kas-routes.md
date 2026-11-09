# Owner-KAS routes at identity

authnz-rs#148, approved by the owner on 2026-11-09 and built in 0.31.0. The
design it serves is arkavo-ios's owner-KAS design, §4.1 and §4.3, at
https://github.com/arkavo-org/arkavo-ios/blob/43bbd68/docs/superpowers/specs/2026-11-08-owner-kas-design.md
(arkavo-ios#78). The relay side is arkavo-rs#163. Change this contract only
together with arkavo-ios and arkavo-rs. The token is in
[owner-kas-token.md](owner-kas-token.md).

## Why here

An owner's route record and APNs push token first lived at the relay. The
relay never learns of an account deletion, so both would outlive the account.
Identity owns deletion, so it stores them, and the relay reads them.

## Retired, never deleted

Every recipient of a shared file knows its `route_id` from the TDF's policy.
If turning sharing off or deleting the account freed the id, a recipient
could register it under their own account. They could not unwrap anything,
but they would receive later Rewraps for the old owner's files (who asks for
which asset), and could answer them.

So `DELETE` and the account-deletion sweep **retire** the route. They set
`retired_at`, remove the bundle and the push token, and keep the owner. A
retired route takes no further write (410). Handles (#132) and passkey index
rows (#104) follow the same rule.

The sweep runs 60 s after a deletion. Until it does, the mint and the relay
read treat a route whose owner is not live as retired, so deletion takes
effect at once.

## Owner routes

Each owner route takes the owner's passkey auth CWT in `X-Auth-Token`, either
the original or one renewed by `POST /session/refresh`, and requires a live
account. Every refusal is JSON `{"error": <code>}` with
`Cache-Control: no-store`.

### `PUT /owner-kas/routes/{route_id}`

Creates the route, or replaces its bundle with one of a higher `seq`.

**Body.** At most 8 KiB. Every value is unpadded base64url, and unknown
members are refused:

```
{ "record": "…",
  "assertion": { "credentialId": "…", "authenticatorData": "…",
                 "clientDataJSON": "…", "signature": "…" },
  "credential": "…" }
```

**`record`** is a deterministic CBOR map (RFC 8949 §4.2.1: shortest forms,
keys in bytewise order of their encodings, no trailing bytes). It has exactly
these text keys:

| Key | Value |
|---|---|
| `v` | 1 |
| `route_id` | the path's route id (a canonical ULID) |
| `owner_sub` | the session's account, a bare lowercase UUID |
| `kas_key` | 65-byte SEC1 P-256 point |
| `kas_kid` | text, 1–256 bytes |
| `service_key` | 65-byte SEC1 P-256 point |
| `seq` | 1 … 2^53 − 1 |
| `issued_at` | Unix seconds, ≥ 0 |

**`assertion`** is the owner's passkey assertion over the record. Identity
checks it itself, because webauthn-rs only verifies challenges it issued:

- `clientDataJSON`: type `webauthn.get`, challenge base64url(SHA-256(record
  bytes)), origin `https://identity.arkavo.net`, and `crossOrigin` not true;
- `authenticatorData`: rpIdHash = SHA-256(`identity.arkavo.net`), with the
  user-present (UP) and user-verified (UV) flags;
- `signature`: ES256, DER, over authenticatorData ‖ SHA-256(clientDataJSON),
  under the passkey with that `credentialId` stored on the session's account;
- the sign count is not checked, because synced passkeys report 0.

**`credential`** is identity's credential attestation of that passkey
(`POST /passkeys/credential-attestation`). It must verify under identity's
key set and name the same `iss`, `sub`, credential id, key and RP ID. The
credential's passkey index row must not be revoked.

| Status | Body | When |
|---|---|---|
| 200 | `{"route_id", "seq"}` | stored |
| 400 | `invalid_request` | not the bundle's shape, too large, or not base64url |
| 400 | `invalid_route_id` | the path is not a canonical ULID |
| 400 | `invalid_record` | the record is off the contract, or names another route or owner |
| 400 | `invalid_assertion` | the assertion or the attestation does not verify for this account |
| 401 | `unauthorized` | no valid passkey auth CWT, or a deleted account |
| 403 | `not_route_owner` | another account's route |
| 409 | `stale_seq` | `seq` is not above the stored one |
| 410 | `route_retired` | retired |

The bundle is stored as received, re-serialized as JSON with the same values.
If the account is deleted while the request runs, the route is retired and
the answer is 401.

### `DELETE /owner-kas/routes/{route_id}`

The owner turns sharing off: the route is retired.

- 204, also when it was already retired;
- 401;
- 403 `not_route_owner`;
- 404 `unknown_route`.

### `PUT` / `DELETE /owner-kas/routes/{route_id}/push`

`PUT` takes `{"apns_token", "environment"}`:
- `apns_token`: lowercase hex, 64–200 characters;
- `environment`: `"production"` only, because the APNs key is
  production-only.

`PUT` replaces the stored token; `DELETE` removes it. Answers:
- 204;
- 400 `invalid_request` / `invalid_route_id` / `invalid_push`;
- 401;
- 403 `not_route_owner`;
- 404 `unknown_route`;
- 410 `route_retired`.

## Relay routes

**Credential.** A service CWT in `X-Auth-Token`, not `Authorization`.
1. Get it from `POST /oauth/token` with `grant_type=client_credentials`, for
   a client on `OWNER_KAS_RELAY_CLIENT_IDS` (production: `owner-kas-relay`).
2. Identity checks the `service-account` role and that `sub` is
   `client:<id>` for a client on that list. It does not check `aud`.

No token, or an invalid one, is 401 `unauthorized`. A valid service token
whose client isn't on the list, or a person's token, is 403 `forbidden`.

### `GET /owner-kas/routes/{route_id}/relay`

| Status | Body |
|---|---|
| 200 | `{"owner_sub", "apns_token"?, "environment"?}`, `Cache-Control: no-store`. The push fields appear only while the owner has a token |
| 400 | `invalid_route_id` |
| 404 | `unknown_route`: never registered |
| 410 | `route_retired`: retired, or the owner is not live |

The relay caches a 200 for about 60 s and stores `owner_sub` with each queued
request.

### `DELETE /owner-kas/routes/{route_id}/relay/push`

Body `{"apns_token"}`: the token APNs reported unregistered. Identity removes
it only if it is still the stored token, so a token the owner set meanwhile
survives. 204 whether or not it was removed; 400 `invalid_request` /
`invalid_route_id`.

## The mint (`POST /owner-kas/token`)

After the account read, the mint reads the route:
- missing: 404 `unknown_route`;
- retired, or its owner not live: 410 `route_retired`;
- otherwise 200 `{"token", "expires_at", "route"}`, with `route` the bundle
  exactly as put.

## Storage

Each route is one `identity_links` row, `link_pk = owner-kas-route#<route_id>`
and `provider = owner-kas-route`, with these attributes:
- `user_id`;
- `seq`;
- `bundle` (the JSON);
- `apns_token` and `apns_environment`, optional;
- `created_at` and `updated_at`;
- `retired_at`, optional.

Every write is one conditional `UpdateItem`. A `PUT` is conditioned on
`attribute_not_exists(link_pk) OR (user_id = :uid AND seq < :seq AND
attribute_not_exists(retired_at))`. A refused condition is read back to tell
403, 409 and 410 apart. No new table.
