---
paths:
  - "src/owner_kas.rs"
  - "src/owner_kas_token.rs"
  - "src/owner_kas_tests.rs"
  - "src/owner_kas_routes.rs"
  - "src/owner_kas_route.rs"
  - "src/owner_kas_routes_tests.rs"
  - "src/db/owner_kas.rs"
---

# Owner KAS token and routes

## owner_kas.rs: Owner KAS token (#146)

- arkavo-ios's owner KAS (design §4.1, ADR-0072) has the owner's
  phone decide each key release. A receiver's request reaches it through a
  relay and must not carry the receiver's session token, so identity mints a
  dedicated one. Contract: [docs/owner-kas-token.md](docs/owner-kas-token.md),
  agreed with arkavo-ios 2026-11-08; change it only with them.
- `POST /owner-kas/token` (passkey auth CWT in `X-Auth-Token`, original or
  renewed; live account), body `{route_id, cnf_key}`: `route_id` a canonical
  ULID (26 uppercase Crockford, first `0`–`7`, never normalized), `cnf_key`
  unpadded base64url of a 65-byte P-256 point on the curve. 200
  `{token, expires_at}`; 401 `unauthorized`; 400 `invalid_request` /
  `invalid_route_id` / `invalid_cnf_key` (decided before the account read);
  429 `rate_limited` + `Retry-After` past `OWNER_KAS_MINTS_PER_MINUTE` (30,
  in process). Stateless; the route's existence is not checked.
- Format (`authnz_rs::owner_kas_token`): tag 61 + COSE_Sign1, ES256, protected
  **content type `application/owner-kas+cwt`**, so `cwt::verify` refuses it
  everywhere in identity. Claims exactly `iss`, `sub` (bare UUID), `aud`
  `owner-kas:<route_id>`, `exp` = `iat` + 900, `iat`, `cti`, `cnf` `{1:
  {1:2, -1:1, -2:x, -3:y}}` (no `kid`), `arkavo_handle` (the permanent
  handle, lowercase, never the username), in deterministic CBOR order. No
  entitlement, Patreon data or email: it lands on another user's phone.
  Keep any new identity verifier refusing typed CWTs.
- From 0.31.0 the mint also needs the route (#148): 404 `unknown_route`,
  410 `route_retired` (retired, or its owner is not live), else the
  response carries `route`, the owner's bundle exactly as put.

## owner_kas_routes.rs: Owner-KAS routes at identity (#148)

- Identity owns account deletion, so the owner's route record and APNs push
  token live here, not at the relay (which never learns of a deletion).
  Contract: [docs/owner-kas-routes.md](docs/owner-kas-routes.md); format and
  assertion check in the lib module `owner_kas_route.rs`.
- `PUT /owner-kas/routes/:route_id` (owner, passkey auth CWT, live account),
  body ≤ 8 KiB `{record, assertion{credentialId, authenticatorData,
  clientDataJSON, signature}, credential}`, all unpadded base64url, unknown
  members refused. `record` is deterministic CBOR with exactly `v` (1),
  `route_id` (= the path), `owner_sub` (= the session's bare UUID),
  `kas_key`, `kas_kid`, `service_key`, `seq` (1…2^53−1), `issued_at`.
  Identity checks the WebAuthn assertion itself (webauthn-rs only verifies
  challenges it issued):
  - `webauthn.get`, with challenge = base64url(SHA-256(record));
  - origin `https://identity.arkavo.net`, no `crossOrigin`;
  - rpIdHash of `identity.arkavo.net`, with UP and UV;
  - an ES256 DER signature under the account's stored passkey;
  - no sign-count check.

  `credential` must be identity's own attestation of that passkey for the
  same `sub`, and the passkey index row must not be revoked. Answers:
  - 200 `{route_id, seq}`;
  - 400 `invalid_request` / `invalid_route_id` / `invalid_record` /
    `invalid_assertion`;
  - 403 `not_route_owner`;
  - 409 `stale_seq`;
  - 410 `route_retired`.
- `DELETE` it (sharing off) retires it. `PUT`/`DELETE …/push`
  `{apns_token (lowercase hex 64–200), environment: "production"}`.
- The relay (`OWNER_KAS_RELAY_CLIENT_IDS` service CWT in `X-Auth-Token`)
  has two routes:
  - `GET …/relay` → `{owner_sub, apns_token?, environment?}`, 404 / 410;
  - `DELETE …/relay/push {apns_token}`, removed only if still stored, 204.
- **A route id is retired, never deleted** (`db/owner_kas.rs`): every
  recipient of a shared file knows it, and a freed id could be registered by
  one of them to receive later requests for the owner's files. `DELETE` and
  the deletion sweep (`retire_owner_kas_routes_of`; the link step skips these
  rows like passkey rows) set `retired_at`, remove the bundle and push token
  and keep `user_id`. A retired row takes no write (410). Until the sweep
  runs, the mint and the relay read treat a route whose owner is not live as
  retired (`owner_kas_routes::in_service`).
