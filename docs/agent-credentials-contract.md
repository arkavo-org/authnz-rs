# Agent credentials contract

**Version:** v2 (2026-09-28)
**Owner:** authnz-rs (identity.arkavo.net)
**Design:** the agent trust state machine amendment of 2026-09-27, tracked at [arkavo-org/arkavo-edge#711](https://github.com/arkavo-org/arkavo-edge/issues/711).

Other repos cite this file as "authnz-rs docs/agent-credentials-contract.md v2". Any change to a name, shape, header, status code or bound below is a new version.

## What changed from v1

v1 was never deployed. v2 replaces it:

- **An agent identity is one key.** The identity is the agent DID (the CWT `sub`). The `agent_workloads` table, `wl-…` ids, `workload_name` and the `arkavo_workload` claim are gone. `name` is a label.
- **Trust state on the identity:** `unassessed`, `eligible` (until `appraised_until`), `quarantined`, and `suspended` (derived: `eligible` whose appraisal has expired).
- **Appraisal.** `POST /agents/authorize` is the owner's bootstrap appraisal. `POST /agents/{did}/appraisal` renews it (the owner, or an enrolled Guardian).
- **Token/version binding.** Agent tokens carry `arkavo_state_version`; the platform withholds a token whose version differs from the identity's current `state_version`.
- **Endpoints move** from `/agents/workloads/{workload_id}/…` to `/agents/{did}/…`.

## States

| State | Stored? | Tokens minted? | Entered by |
|---|---|---|---|
| `unassessed` | yes | no | a delegation row written before v2; owner recovery |
| `eligible` | yes, with `appraised_until` | yes, until `appraised_until` | an appraisal: the owner (authorize, or `/appraisal`) or an enrolled Guardian (`/appraisal`) |
| `suspended` | no: `eligible` with `now ≥ appraised_until` | no | time |
| `quarantined` | yes, a latch | no | the owner or an enrolled Guardian (`/quarantine`) |

- `state_version` is server-assigned and never decreases. It increases by exactly 1 when the stored state changes (`unassessed` → `eligible`, any → `quarantined`, `quarantined` → `unassessed`), when the swarm changes, when the delegation is revoked (`DELETE /agents/delegations/{did}`), and when an authorize starts a new delegation over one that was revoked, expired, or written before v2. A renewal (`eligible` → `eligible`, including out of `suspended`) and a change of entitlements or `short_lived` leave it unchanged, so a renewal never invalidates the tokens the identity already holds. A swarm change does invalidate them: a token minted in an earlier swarm never matches again, even after the agent moves back.
- An appraisal (owner or Guardian) never clears a quarantine, and never extends the delegation itself: the delegation expires `AGENT_DELEGATION_DAYS` (30) days after the identity's last authorize, and only an owner re-authorize (not `/appraisal`) resets that clock.
- Recovery is owner-only and moves the identity to `unassessed`. Once recovered, the key is Guardian-appraised for the rest of its delegation; the owner's authorize and `/appraisal` are refused for that key from then on, so the owner cannot change its entitlements, swarm, or delegation lifetime either. Because a recovered key can never be re-authorized, it stops minting at most 30 days after its last authorize even while a Guardian keeps appraising it — the owner's path from there is a new key. A Guardian's appraisals (each at most 15 min) renew the appraisal, not the delegation, as for any key.

## Configuration

| Variable | Meaning | Default | Allowed |
|---|---|---|---|
| `AGENT_OWNER_APPRAISAL_TTL_SECONDS` | how long an owner appraisal lasts, counted from the owner's passkey assertion (`auth_time`), not from the request | 43200 (12 h) | 1 to 86400 (24 h) |
| `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` | the latest `appraised_until` a Guardian may set, from now | 900 (15 min) | 1 to 900 |

A value outside its range stops the server at startup. The bounds follow NIST SP 800-63B-4 reauthentication: 12 h is the AAL3 bound (§2.3.3), 24 h the AAL2 bound (§2.3.2, a synced passkey is at most AAL2), and 15 min the AAL3 inactivity bound, which is also the agent token's maximum lifetime.

**Operating without a Guardian.** Until a Guardian is enrolled for an owner, every agent of that owner needs an owner appraisal at least every `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (12 h by default), counted from the owner's passkey tap; otherwise it becomes `suspended` and stops minting. The owner renews with `POST /agents/{did}/appraisal`, which resends no entitlements (authorizing again works too).

## Agent token (CWT)

Minted by `POST /agents/token` after the agent signs the challenge from `GET /agents/challenge` (wire unchanged from the identity-plane end state). COSE_Sign1, ES256, CBOR tag 61, sent base64url without padding.

The challenge signature is verified with strict Ed25519 verification against the key in the DID. A DID whose key is not a valid Ed25519 point, or is a small-order (weak) point, is refused (400) at `/agents/authorize`, `/agents/challenge`, `/agents/token` and on the `/agents/{did}/…` endpoints: under such a key a signature nobody made could verify.

| Claim | CBOR key | Value |
|---|---|---|
| `iss` | 1 | `https://identity.arkavo.net` |
| `sub` | 2 | the agent's `did:key` (Ed25519): the agent identity |
| `aud` | 3 | array: `AGENT_TOKEN_AUDIENCES` |
| `exp`, `iat` | 4, 6 | `exp − iat ≤ 900`; `≤ 300` when the delegation is `short_lived`; `exp ≤ appraised_until`; and `exp ≤` the delegation's `expires_at` |
| `cti` | 7 | 16 random bytes |
| `cnf` | 8 | `{1: COSE_Key (OKP, Ed25519, the agent key), 2: kid = the DID bytes}` |
| `act` | `"act"` | `[{"sub": <each AGENT_AUTHORIZED_ACTORS entry>}]`, omitted when empty |
| `arkavo_account_id` | text | the owner's account UUID |
| `arkavo_roles` | text | `["agent"]` |
| `arkavo_entitlements` | text | delegated FQNs ∩ what the owner holds now |
| `arkavo_npe` | text | `{type: "agent", delegation_id: <DID>, depth: 0, chain: []}` |
| `arkavo_state_version` | text | **new in v2:** unsigned integer, the identity's `state_version` when the token was minted |
| `arkavo_swarm` | text | the SwarmKit `kit_id` of the delegation. **Omitted** while the agent has no swarm (an agent onboarded by trust QR before specialization); the platform then withholds its entitlements. |

`arkavo_workload` (v1) is not minted.

A token is minted (and a challenge issued) only while the identity is `eligible`: the delegation exists, is not revoked or expired, and `now < appraised_until`. Every `AGENT_TOKEN_AUDIENCES` verifier accepts the token and only the platform asks for status, so issuance itself refuses every other state.

The token is minted from a strongly consistent read of the identity taken after every other lookup the request makes, so a quarantine, revocation, expiry, appraisal change or re-authorize that lands while the request is in flight applies to it: it carries the entitlements, lifetime (`short_lived`), swarm and `state_version` of that read, and its `exp` is bounded by that read's `appraised_until`. A token whose `exp` would not be after its `iat` is never minted: the request is refused with `Forbidden: agent appraisal expired; it needs a fresh appraisal` when the appraisal has ended, or `Delegation expired` when the delegation has.

## Refusal bodies (part of v2)

Every error response from the endpoints below has a `text/plain` body. Clients such as arkavo-edge sort 403s by this text, so the bodies below are part of this contract: changing any of them is a new contract version.

| Body (exact, no trailing newline) | Since | Status | Returned by | Meaning |
|---|---|---|---|---|
| `Workload quarantined` | v1 | 403 | `/agents/challenge`, `/agents/token`, `/agents/authorize`, `/agents/{did}/appraisal` | The identity's quarantine latch is set. Unchanged from v1: "workload" now means the agent identity. Takes precedence over `Delegation revoked` and `Delegation expired`: a latched key gets this body whatever its delegation's liveness. |
| `Delegation revoked` | v1 | 403 | `/agents/challenge`, `/agents/token`, `/agents/{did}/appraisal` | Revoked by `DELETE /agents/delegations/{did}`. |
| `Forbidden: agent is unassessed; it needs an appraisal` | v2 | 403 | `/agents/challenge`, `/agents/token` | No current appraisal: a row written before v2 (the owner authorizes again), or a recovered identity (a Guardian appraises it). |
| `Forbidden: agent appraisal expired; it needs a fresh appraisal` | v2 | 403 | `/agents/challenge`, `/agents/token` | Suspended: the owner (authorize or `/appraisal`) or a Guardian (`/appraisal`) renews it. |
| `Forbidden: agent was recovered; only a Guardian may appraise it` | v2 | 403 | `/agents/authorize`, `/agents/{did}/appraisal` (owner) | The owner may not appraise a key it has recovered; the owner's path back is a new key. |
| `Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again` | v2 | 403 | `/agents/authorize`, `/agents/{did}/appraisal` (owner) | The owner's passkey assertion is older than `AGENT_OWNER_APPRAISAL_TTL_SECONDS`: sign in again (a fresh passkey tap) and retry. |

v1's `Forbidden: delegation predates workloads; …` and `Forbidden: agent DID is not the workload's current binding` are not returned. Other 4xx bodies are informative and may change within v2. A client that sorts 403s by text (arkavo-edge) treats the two "v1" rows as it did under v1 and must add the four "v2" rows.

## Operator authorization (owner bootstrap appraisal)

`POST /agents/authorize`

Authentication, first match wins:
- `X-Auth-Token: <passkey auth CWT>` (the 1-hour CWT from `POST /authenticate`); or
- `Authorization: Bearer <OIDC access token>` carrying scope `agents:delegate` (see below). Considered only when `X-Auth-Token` is absent.

Request (JSON):

| Field | Type | Rule |
|---|---|---|
| `agent_did` | string | `did:key:z6Mk…` (Ed25519): the identity. The key must be a valid Ed25519 point that is not small-order (weak); any other key is 400. |
| `name` | string | a label for people; not an identifier |
| `entitlements` | string[] | each held by the owner now; empty is refused (403) |
| `swarm` | string | optional, 1–128 chars when present: the SwarmKit `kit_id`. Omit it (or send `null`) before the agent has a kit; an empty string is 400. |
| `short_lived` | bool | optional, default `false`: tokens for this delegation live ≤ 300 s |

A v1 `workload_name` field is ignored.

Response 200: `{"success": true, "message": "Agent authorized successfully", "agent": "did:key:…", "state": "eligible", "state_version": 1, "appraised_until": 1790043200}`

The per-owner agent limit (`MAX_AGENTS_PER_USER` live delegations) applies only when an authorize adds a delegation; re-authorizing a live one the owner already holds (including a row written before v2) is never refused for it.

Semantics:
- Authorize writes the delegation and the owner's appraisal: `state = eligible`, `appraised_by = owner`, and `appraised_until` = the owner's passkey assertion time + `AGENT_OWNER_APPRAISAL_TTL_SECONDS`, never later than now + that. The assertion time is the passkey auth CWT's `iat`, or the Bearer token's `auth_time` (a refreshed token keeps the original). Once that moment has passed, authorize is refused (403 `Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again`).
- A new DID starts at `state_version = 1`.
- Authorizing the same DID again as its owner, while its delegation is live, replaces the delegation (entitlements, `short_lived`, `swarm`) and renews the appraisal. Omitting `swarm` keeps the current one. `state_version` is unchanged if the identity was `eligible` (or `suspended`) and the swarm stays the same; it increases by 1 if the swarm changes (including the first specialization, no swarm → a kit) or the identity was `unassessed`.
- Authorizing a DID whose delegation was revoked or has expired starts a new delegation: `state_version` increases by 1, so no token of the old delegation passes the platform again. This also applies to a revoked or expired delegation of another owner.
- The write is conditioned on the row the server read, not only its `state_version` (a renewal keeps that): a renewal lands only while the delegation is still the owner's and live, and a new delegation replaces a revoked or expired one only while it is still revoked or expired and still its previous owner's. When the row changed in between, the server reads it again and decides again, so another owner's concurrent renewal is answered 409, never taken over.
- Refused (403 `Workload quarantined`) while the DID's latch is set, whatever its delegation's liveness: revoking or letting a delegation expire is no way out of quarantine.
- Refused (403 `Forbidden: agent was recovered; only a Guardian may appraise it`) once the DID has been recovered.
- Refused (409) while another owner's delegation of the DID is live, including one written before v2.
- A delegation row written before v2 has no state: it reads as `unassessed` at `state_version = 0`, cannot mint, and its own owner's authorize upgrades it (`state_version = 1`).

Errors: 400 invalid DID or field, or the owner already holds `MAX_AGENTS_PER_USER` live delegations (a new delegation only); 422 missing required JSON field (`agent_did`, `name`, `entitlements`); 401 missing, invalid or stale operator credential; 403 entitlements empty or not held, scope or client not allowed, quarantined, recovered, or a passkey assertion older than the appraisal lifetime; 409 live delegation of another owner, or `agent changed concurrently; retry`.

## The `agents:delegate` OIDC scope

Unchanged from v1.

- Requested at `GET /oauth/authorize` as part of `scope` (e.g. `openid offline_access agents:delegate`) by a client listed in `AGENT_DELEGATE_CLIENT_IDS` (production: `arkavo-edge`). Other clients get `error=invalid_scope` on their redirect URI.
- The user must authenticate with `X-Auth-Token: <passkey auth CWT>`. `idp=google`, `idp=apple` or a registration CWT get `error=invalid_scope`.
- The access token carries `scope` (text key, the granted space-separated scope string) and `auth_time` (text key, integer seconds: the `iat` of the passkey auth CWT, i.e. the WebAuthn assertion time). Refreshed access tokens carry the original `auth_time`; refresh never renews it.
- `/agents/authorize`, quarantine, recover and appraisal accept the token, as `Authorization: Bearer`, when: signature and `iss` verify; `exp` has not passed; `scope` contains `agents:delegate` (else 403); `aud` contains an `AGENT_DELEGATE_CLIENT_IDS` entry (else 403); `idp = "webauthn"` (else 403); `auth_time` is present and `now − auth_time` is within the endpoint's limit (else 401: run the passkey ceremony again). Limits: authorize, quarantine and appraisal 3600 s; recover 300 s.
- On every one of those endpoints `X-Auth-Token` takes precedence: the Bearer token is considered only when `X-Auth-Token` is absent.
- An access token sent as `X-Auth-Token` is refused (401 `Unauthorized: X-Auth-Token must be a passkey auth CWT`): a token carrying `scope` or `auth_time` is never a passkey auth CWT, whatever its audience.
- `GET /oauth/authorize` honours the OIDC `max_age` parameter (integer seconds, ≥ 0) for passkey sign-in: when the presented passkey auth CWT's `iat` is more than `max_age` seconds old, it answers `401 {"error": "login_required", …}`, and the client runs a new passkey authentication and retries. `max_age` with `idp=google` or an Apple id_token is refused (`invalid_request` on the redirect URI). Clients that need a fresh assertion — e.g. before `recover`, which needs `auth_time` ≤ 300 s old — send `max_age=300`.

## Appraisal

`POST /agents/{did}/appraisal`

Callers:
- an enrolled Guardian of the agent's owner (`X-Guardian-Signature`, below), checked first; or
- the owner, with `X-Auth-Token: <passkey auth CWT>` or, when that header is absent, `Authorization: Bearer <agents:delegate access token>` with `now − auth_time ≤ 3600`.

Request: `{"appraised_until": <unix seconds> | null, "evidence_ref": string (1–1024 chars, no control characters) | null}`. Both fields are optional.

- The caller's latest: for the owner, its passkey assertion time (auth CWT `iat` or Bearer `auth_time`) + `AGENT_OWNER_APPRAISAL_TTL_SECONDS`, never later than now + that, and refused (403 `Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again`) once past; for a Guardian, `now + AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS`.
- `appraised_until` omitted: the caller's latest.
- `appraised_until` present: must be later than now (else 400); a value beyond the caller's latest is lowered to it. The response reports the value stored.
- `evidence_ref` is recorded for audit and not returned.
- The most recent appraisal wins: an appraisal sets `appraised_until` outright, not by extending whatever value is stored, so a Guardian renewal of an owner-appraised agent can shorten a 12 h owner appraisal down to at most 15 min — and it changes `appraised_by` to `guardian`.
- The owner may also use this endpoint to move a track-1 (pre-v2) row from `unassessed` straight to `eligible`, the same as any other owner appraisal. Re-authorizing (`POST /agents/authorize`) does the same and also refreshes the delegation (entitlements, `short_lived`, `swarm`).

Response 200: the status body (below) after the call: `state = eligible`, `appraised_by` = `owner` or `guardian`.

- `unassessed` → `eligible`: `state_version + 1`.
- `eligible` (or `suspended`) → `eligible`: `state_version` unchanged.

Errors: 400 bad body, bad DID, or an `appraised_until` not in the future; 401 bad or missing credential, stale `auth_time`, or a replayed, unknown or revoked Guardian signature; 403 the agent belongs to another owner, `Workload quarantined`, `Delegation revoked`, `Delegation expired`, the owner appraising a recovered key (`Forbidden: agent was recovered; only a Guardian may appraise it`), an owner assertion older than the appraisal lifetime (`Forbidden: passkey assertion is older than the owner appraisal lifetime; sign in again`), or a Guardian whose enrolled key is the agent's own key (`Forbidden: an agent cannot appraise itself`); 404 unknown DID; 409 `agent changed concurrently; read its status and retry` (the write is conditioned on the version read and on the delegation being live, so a concurrent revocation or quarantine makes it re-read).

## Quarantine

`POST /agents/{did}/quarantine`

Callers:
- the owner, with `X-Auth-Token: <passkey auth CWT>` or, when that header is absent, `Authorization: Bearer <agents:delegate access token>` with `now − auth_time ≤ 3600`; or
- a Guardian enrolled by that owner (`X-Guardian-Signature`, below). `X-Guardian-Signature` is checked before either owner credential.

Request: `{"incident": string (1–256 chars, no control characters), "evidence_ref": string (1–1024 chars, no control characters) | null}`. `evidence_ref` is optional: omit it or send `null`; an empty string is refused (400).

Response 200: the status body after the call.
- Not latched → `quarantined`: latches, `state_version + 1`, records `incident`, `evidence_ref`, who and when. This applies whatever the delegation's liveness: the latch is on the key. The write is conditioned on the owner and the `state_version` the server read: a key reassigned to another owner in between is refused (403), and a concurrent state change is re-read (up to three times, then 409).
- Already quarantined with the same `incident`: 200, nothing changes (same `state_version`).
- Already quarantined with a different `incident`: 409, nothing changes.
- Not latched, and `incident` equals the incident the last recovery cleared (`last_cleared_incident`): 409, nothing changes. A cleared incident cannot re-latch; report a new incident id.

Errors: 400 bad body or DID; 401 bad or missing credential, stale `auth_time`, or a replayed Guardian signature; 403 caller is neither the owner nor one of the owner's Guardians, or the Bearer token lacks the scope or the client; 404 unknown DID; 409 as above, or `agent changed concurrently; retry` when the write raced a concurrent change (e.g. a recovery landing between the read and the write) — retry the request.

The latch holds until recovery. While quarantined, `/agents/challenge`, `/agents/token`, `/agents/authorize` and `/agents/{did}/appraisal` refuse the DID with 403 `Workload quarantined`, also once its delegation is revoked or expired.

## Recovery

`POST /agents/{did}/recover`

Caller: the owner only, with a passkey assertion at most 300 s old: `X-Auth-Token: <passkey auth CWT>` whose `iat` is at most 300 s old or, when that header is absent, `Authorization: Bearer <agents:delegate access token>` with `now − auth_time ≤ 300`. Guardians, agent tokens and service CWTs cannot recover.

Request: `{"incident": string (1–256 chars, no control characters)}` — must equal the latched incident.

Effect, in one conditional write: `state = unassessed`, `state_version + 1`, `incident` cleared and recorded as `last_cleared_incident`, `recovered_at` set, the appraisal removed. The delegation itself is kept, and `recovered_at` is never removed. **Once recovered, the key is Guardian-appraised for the rest of its delegation; the owner's path back is a new key.** The identity mints again only after a Guardian appraises it, and Guardian renewals (each at most 15 min) keep it eligible, as for any key — but an appraisal never extends the delegation itself: the owner may not re-authorize this key (authorize and `/appraisal` answer 403 `Forbidden: agent was recovered; only a Guardian may appraise it` for that key from now on, so the owner cannot change its entitlements, swarm, or delegation lifetime either), so a recovered key stops minting at most `AGENT_DELEGATION_DAYS` (30) days after its last authorize, even while a Guardian keeps appraising it — the owner's path from there is a new key. Until a Guardian is enrolled for the owner, a recovered identity stays `unassessed`; the owner authorizes a new key instead.

Response 200: the status body. Errors: 400 malformed or empty JSON body, bad DID, or a bad `incident`; 401 missing, invalid or stale credential; 403 not the owner, or the Bearer token lacks the scope or the client; 404 unknown DID; 409 not quarantined, incident mismatch, or concurrent change; 415 if `Content-Type` isn't `application/json`; 422 missing or mistyped `incident` field.

## Revocation

`DELETE /agents/delegations/{did}` (the owner, `X-Auth-Token` passkey auth CWT; unchanged from v1 apart from this) sets `revoked_at` and increases `state_version` by 1, in one write conditioned on the owner and the version the server read, so no concurrent renewal or appraisal can clear the revocation and keep its version. Response 204, also for an already revoked delegation (which moves the version again). The cascade to child delegations (none while every delegation is depth 0) moves each child's version too.

## Agent status

`GET /agents/{did}/status`

Authentication: `X-Auth-Token: <service CWT>` — an access token from `POST /oauth/token` `grant_type=client_credentials` (so `arkavo_roles` contains `service-account` and `sub = client:<client_id>`) for a client listed in `AGENT_STATUS_CLIENT_IDS`. Not `Authorization: Bearer`.

Response 200 (`Cache-Control: no-store`):

```json
{ "agent": "did:key:…", "owner": "<owner account UUID>", "swarm": "<kit_id>",
  "state": "eligible", "state_version": 42,
  "appraised_until": 1790000900, "appraised_by": "guardian",
  "incident": null, "valid_until": 1790000005 }
```

- Read with a strongly consistent read of the identity's row.
- `state` is `unassessed`, `eligible`, `suspended` or `quarantined`; authnz-rs derives `suspended`.
- `valid_until = now + 5` (seconds), and no later than `appraised_until` while `eligible`. A consumer caches for at most `min(valid_until − now, 5)` seconds. The status lease and the appraisal are different clocks: the lease bounds how stale an answer may be, the appraisal how long the identity stays eligible.
- `state_version` as defined under **States**. `appraised_until` and `appraised_by` (`owner` or `guardian`) are `null` until the identity is appraised, and again after recovery. `swarm` is `""` while the agent has no swarm.
- `owner` equals the agent token's `arkavo_account_id`.
- A DID with no delegation, or whose delegation is revoked or expired, answers 404 — unless its quarantine latch is set, which is reported (200, `quarantined`, with the incident) whatever the delegation's liveness.

Errors: 400 malformed DID; 401 missing or invalid token; 403 not a service CWT or client not allowlisted; 404 as above.

Platform rule (informative; opentdf-platform, arkavo entity resolver): withhold an agent token's entitlements when the status call fails or is non-200, `state ≠ eligible`, `state_version` is 0 or lower than the last one seen for the DID (the per-DID high-water mark), the token's `arkavo_state_version` is missing or differs from `state_version` in either direction, `agent ≠ sub`, the token has no `arkavo_swarm`, `swarm ≠ arkavo_swarm`, or `owner ≠ arkavo_account_id`. A token carrying `arkavo_state_version` is checked as an agent's whatever else it carries.

## Guardians

`POST /guardians`

Caller: the owner (`X-Auth-Token` passkey auth CWT). Request: `{"public_key": "<base64url, no padding, 32-byte Ed25519 public key>", "name": string (1–64 chars), "proof": "<base64url, no padding, Ed25519 signature>"}`. `proof` is the Guardian key's signature, verified strictly, over the UTF-8 bytes `"arkavo-guardian-enroll" "\n" owner_uuid "\n" public_key`, where `owner_uuid` is the enrolling owner's account UUID (hyphenated, lower case; the account the auth CWT authenticates, not an `arkavo:` prefixed form) and `public_key` is the base64url string sent. Proof of possession stops anyone who merely learns a Guardian's public key from enrolling it first, and binding the owner stops a captured proof from being replayed by another owner. `guardian_id` is not chosen by the caller: it is a UUID derived from the enrolled key's SHA-256, so the same key always enrolls under the same id. Response 200: `{"guardian_id": "<uuid>"}`. Errors: 400 key not 32 bytes, not a valid point, or weak (small-order), or `proof` missing, malformed, or not a valid signature by that key over that owner's enrollment; 401; 409 the key is already enrolled — by any owner, including a Guardian since revoked. A key enrolls at most once, so it has exactly one replay clock, and a revoked key cannot come back with a fresh one; enroll a new key instead.

`DELETE /guardians/{guardian_id}`

Caller: the owner who enrolled the Guardian (`X-Auth-Token` passkey auth CWT). No body. Response 204, also when the Guardian is already revoked. Errors: 401 missing or invalid credential; 403 the Guardian was enrolled by another owner, or the request carries `X-Guardian-Signature`; 404 unknown `guardian_id` (including one that is not a canonical UUID). From then on the Guardian's requests are refused with 401 and the same body as an unknown `guardian_id`, however they are signed. Quarantines it already latched stay latched (recovery clears them) and keep `guardian:<guardian_id>` as who latched them; appraisals it made stay until they expire.

Guardian request authentication:

```
X-Guardian-Signature: <guardian_id>.<unix_ts>.<base64url-no-pad Ed25519 signature>
signed bytes (UTF-8): METHOD "\n" PATH "\n" unix_ts "\n" hex(sha256(body))
```

- `METHOD` upper case (`POST`); `PATH` is the request path exactly as sent, without query string (for example `/agents/did:key:z6Mk…/appraisal`); `unix_ts` decimal seconds; `hex` lower case; `body` the exact request body bytes (empty body hashes the empty string).
- `|now − unix_ts| ≤ 60` s.
- Verified with strict Ed25519 verification against the public key enrolled under `guardian_id`, never a key carried by the request. A `guardian_id` that is not a canonical UUID (hyphenated, lower case), unknown, or revoked is refused (401) exactly as a signature that does not verify.
- Replay protection: the server stores `last_signed_at`, the `unix_ts` of the most recent request from that Guardian whose signature verified — the clock advances whenever a request's signature verifies, regardless of whether the request then succeeds or is refused for another reason. A request whose `unix_ts` is not strictly greater than `last_signed_at` is refused (401), even inside the ±60 s window. A Guardian therefore sends at most one request per second, with increasing timestamps; a Guardian renewing appraisals for several agents spaces its requests accordingly.
- Guardian throughput: because a Guardian's signed requests all share this one replay clock with whole-second timestamps that must strictly increase, a Guardian makes at most one signed request per second — about 900 agents at the 15-minute Guardian appraisal cap, fewer if it keeps headroom for quarantines. A Guardian client should allocate timestamps monotonically (`max(now, last + 1)`) and never send signed requests in parallel; a renewal and a quarantine stamped with the same second collide, and the second one to reach the server gets 401.
- A Guardian may call only quarantine and appraisal, only for its owner's agents. Any other agent-plane request carrying `X-Guardian-Signature` (`/agents/authorize`, `/agents/delegations`, `/agents/challenge`, `/agents/token`, recover, status, `POST /guardians`, `DELETE /guardians/{guardian_id}`) gets 403 whether or not the signature verifies. That 403 applies to a well-formed request: a malformed JSON body or query string on one of those endpoints is rejected by request parsing (400/415/422) before the handler runs — quarantine and appraisal are the exception, since they read the raw body themselves and authenticate the caller (Guardian or owner) before parsing it as JSON.
- Out of scope in v2: the Guardian's own health state, its observation pipeline, and escalation to the owner (the Guardian notifies the owner through its own channel, arkavo-edge#630 CAEP/SSF).

## Discovery

`GET /.well-known/agent-configuration` carries `agent_state_endpoint` (`<issuer>/agents/{did}`: a template; append `/quarantine`, `/recover`, `/appraisal` or `/status`), `guardian_registration_endpoint` (`<issuer>/guardians`), `short_lived_token_lifetime_seconds` (`min(agent_token_lifetime_seconds, 300)`), `agent_status_lease_seconds` (5), `owner_appraisal_ttl_seconds`, `guardian_appraisal_max_seconds` and `contract_version` (`"v2"`). v1's `agent_workloads_endpoint` and `workload_status_lease_seconds` are gone.
