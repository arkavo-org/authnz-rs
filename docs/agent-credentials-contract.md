# Agent credentials contract

**Version:** v1 (2026-09-26)
**Owner:** authnz-rs (identity.arkavo.net)
**Design:** arkavo-edge `docs/superpowers/specs/2026-09-26-agent-credentials-quarantine-design.md` (local), amending the identity-plane end state of 2026-08-27.

Other repos cite this file as "authnz-rs docs/agent-credentials-contract.md v1". Any change to a name, shape, header, status code or bound below is a new version.

## Agent token (CWT)

Minted by `POST /agents/token` after the agent signs the challenge from `GET /agents/challenge` (wire unchanged from the identity-plane end state). COSE_Sign1, ES256, CBOR tag 61, sent base64url without padding.

| Claim | CBOR key | Value |
|---|---|---|
| `iss` | 1 | `https://identity.arkavo.net` |
| `sub` | 2 | the agent's `did:key` (Ed25519) |
| `aud` | 3 | array: `AGENT_TOKEN_AUDIENCES` |
| `exp`, `iat` | 4, 6 | `exp − iat ≤ 900`; `≤ 300` when the delegation is `short_lived` |
| `cti` | 7 | 16 random bytes |
| `cnf` | 8 | `{1: COSE_Key (OKP, Ed25519, the agent key), 2: kid = the DID bytes}` |
| `act` | `"act"` | `[{"sub": <each AGENT_AUTHORIZED_ACTORS entry>}]`, omitted when empty |
| `arkavo_account_id` | text | the owner's account UUID |
| `arkavo_roles` | text | `["agent"]` |
| `arkavo_entitlements` | text | delegated FQNs ∩ what the owner holds now |
| `arkavo_npe` | text | `{type: "agent", delegation_id: <DID>, depth: 0, chain: []}` |
| `arkavo_workload` | text | **new:** the workload id, e.g. `wl-6f1c…` (`wl-` + 32 lowercase hex) |
| `arkavo_swarm` | text | **new:** the SwarmKit `kit_id` the workload is bound to. **Omitted** while the workload has no swarm (an agent onboarded by trust QR before specialization). KAS rule (informative; opentdf-platform P2, see below): once that rule lands, the platform denies agent rewraps whose token lacks it, so such an agent holds a token but cannot unwrap sealed keys. |

A token is only minted while its workload is `eligible` and the token's `sub` is the workload's `current_did`.

## Refusal bodies (part of v1)

Every error response from the endpoints below has a `text/plain` body. Clients such as arkavo-edge sort 403s by this text, so the four bodies below are part of this contract: changing any of them is a new contract version.

| Body (exact, no trailing newline) | Status | Returned by | Meaning |
|---|---|---|---|
| `Workload quarantined` | 403 | `/agents/challenge`, `/agents/token`, `/agents/authorize` | The workload's quarantine latch is set. |
| `Forbidden: delegation predates workloads; authorize again with workload_name and swarm` | 403 | `/agents/challenge`, `/agents/token` | The delegation row has no workload. |
| `Forbidden: agent DID is not the workload's current binding` | 403 | `/agents/challenge`, `/agents/token` | The workload is bound to a different DID. (After recovery, or a rebind, the old DID's delegation is revoked while it still names this workload, so it gets `Delegation revoked` instead; a DID since authorized into another workload is untouched and mints for that workload.) |
| `Delegation revoked` | 403 | `/agents/challenge`, `/agents/token` | The delegation was revoked: by DELETE, by a rebind to another DID (while it still named this workload), or by recovery (while it still named this workload). |

Other 4xx bodies are informative and may change within v1.

## Operator authorization

`POST /agents/authorize`

Authentication, first match wins:
- `X-Auth-Token: <passkey auth CWT>` (the 1-hour CWT from `POST /authenticate`), unchanged; or
- `Authorization: Bearer <OIDC access token>` carrying scope `agents:delegate` (see below). Considered only when `X-Auth-Token` is absent.

Request (JSON):

| Field | Type | Rule |
|---|---|---|
| `agent_did` | string | `did:key:z6Mk…` (Ed25519) |
| `name` | string | agent display name |
| `entitlements` | string[] | each held by the owner now; empty is refused (403) |
| `workload_name` | string | required, 1–128 chars, no control chars. Selects the owner's workload of that name, creating it if absent. |
| `swarm` | string | optional, 1–128 chars when present: the SwarmKit `kit_id`. Omit it (or send `null`) before the agent has a kit; an empty string is 400. |
| `short_lived` | bool | optional, default `false`: tokens for this delegation live ≤ 300 s |

Response 200: `{"success": true, "message": "Agent authorized successfully", "workload_id": "wl-…"}`

Semantics:
- The workload id is derived server-side from `(owner, workload_name)`; the same owner and name always select the same workload.
- A new workload starts `eligible`, `generation = 1`, bound to `agent_did` and `swarm`.
- A new workload authorized without `swarm` has `swarm = ""`: its tokens omit `arkavo_swarm` and its status shows `"swarm": ""`.
- Authorizing a different DID, or a `swarm` different from the workload's, rebinds it: `generation + 1`; when the DID changes, the previously bound DID's delegation is revoked in the same write, but only while it still names this workload (if it has since been authorized elsewhere, it is left alone). Omitting `swarm` for an existing workload keeps its current swarm.
- Authorizing the DID that already holds an active delegation for the same workload replaces that delegation (e.g. to add the swarm once the agent is specialized, or to change entitlements or `short_lived`); this is not a 409.
- Any authorize against a quarantined workload is refused (403). Rebinding is not a way out of quarantine.
- A delegation row from before workloads existed (no `workload_id`) cannot mint and is replaced by a new authorize for the same DID, without a prior DELETE, only by its own owner (`root_user_id`): a legacy row's owner may re-authorize it straight into a workload; a different owner authorizing the same DID gets 409 instead.

Errors: 400 invalid DID or field; 422 missing required JSON field (`agent_did`, `name`, `entitlements`, `workload_name`); 401 missing, invalid or stale operator credential; 403 entitlements empty or not held, scope or client not allowed, workload quarantined; 409 DID already has an active delegation for a different workload or for a legacy row owned by someone else, or a concurrent change (retry).

## The `agents:delegate` OIDC scope

- Requested at `GET /oauth/authorize` as part of `scope` (e.g. `openid offline_access agents:delegate`) by a client listed in `AGENT_DELEGATE_CLIENT_IDS` (production: `arkavo-edge`). Other clients get `error=invalid_scope` on their redirect URI.
- The user must authenticate with `X-Auth-Token: <passkey auth CWT>`. `idp=google`, `idp=apple` or a registration CWT get `error=invalid_scope`.
- The access token carries `scope` (text key, the granted space-separated scope string) and `auth_time` (text key, integer seconds: the `iat` of the passkey auth CWT, i.e. the WebAuthn assertion time). Refreshed access tokens carry the original `auth_time`; refresh never renews it.
- `/agents/authorize`, quarantine and recover accept the token, as `Authorization: Bearer`, when: signature and `iss` verify; `exp` has not passed; `scope` contains `agents:delegate` (else 403); `aud` contains an `AGENT_DELEGATE_CLIENT_IDS` entry (else 403); `idp = "webauthn"` (else 403); `auth_time` is present and `now − auth_time` is within the endpoint's limit (else 401: run the passkey ceremony again). Limits: authorize and quarantine 3600 s; recover 300 s.
- On every one of those endpoints `X-Auth-Token` takes precedence: the Bearer token is considered only when `X-Auth-Token` is absent.
- `GET /oauth/authorize` honours the OIDC `max_age` parameter (integer seconds, ≥ 0) for passkey sign-in: when the presented passkey auth CWT's `iat` is more than `max_age` seconds old, it answers `401 {"error": "login_required", …}` (the same shape as a missing credential), and the client runs a new passkey authentication and retries. The minted access token's `auth_time` is then within `max_age`. `max_age` with `idp=google` or an Apple id_token is refused (`invalid_request` on the redirect URI; there is no passkey assertion to age). Clients that need a fresh assertion — e.g. before `recover`, which needs `auth_time` ≤ 300 s old — send `max_age=300`.

## Quarantine

`POST /agents/workloads/{workload_id}/quarantine`

Callers:
- the owner, with `X-Auth-Token: <passkey auth CWT>` or, when that header is absent, `Authorization: Bearer <agents:delegate access token>` with `now − auth_time ≤ 3600`; or
- a Guardian enrolled by that owner (`X-Guardian-Signature`, below). `X-Guardian-Signature` is checked before either owner credential.

Request: `{"incident": string (1–256 chars), "evidence_ref": string (1–1024 chars, no control characters) | null}`

`evidence_ref` is optional: omit it or send `null` to leave it unset. When present it must be 1–1024 characters with no control characters — an empty string (`""`) is refused (400).

Response 200: the status body (below) after the call.
- Eligible → `quarantined`: latches, `generation + 1`, records `incident`, `evidence_ref`, who and when.
- Already quarantined with the same `incident`: 200, nothing changes (same `generation`).
- Already quarantined with a different `incident`: 409, nothing changes.
- Eligible, and `incident` equals the incident the last recovery cleared (stored as `last_cleared_incident`): 409, nothing changes. A cleared incident cannot re-latch; report a new incident id.

Errors: 400 bad body (including an empty `evidence_ref`); 401 bad or missing credential, stale `auth_time`, or a replayed Guardian signature; 403 caller is neither the owner nor one of the owner's Guardians, or the Bearer token lacks the scope or the client; 404 unknown workload; 409 as above, or `workload changed concurrently; retry` when the conditional write raced a concurrent change (e.g. a recovery landing between the read and the write) — retry the request.

The latch holds until recovery. While quarantined, `/agents/challenge`, `/agents/token` and `/agents/authorize` refuse the workload with 403.

## Recovery

`POST /agents/workloads/{workload_id}/recover`

Caller: the owner only, with a passkey assertion at most 300 s old: `X-Auth-Token: <passkey auth CWT>` whose `iat` is at most 300 s old or, when that header is absent, `Authorization: Bearer <agents:delegate access token>` with `now − auth_time ≤ 300`. Guardians, agent tokens and service CWTs cannot recover.

Request: `{"incident": string (1–256 chars, no control characters)}` — must equal the latched incident.

Effect, in one write: `state = eligible`, `current_did = ""`, `incident = null`, `generation + 1`, and the delegation of the previously bound DID is revoked **only while that delegation still names this workload**; if the DID has since been authorized into another workload (or revoked another way), its delegation is left alone. Nothing can mint for this workload until the owner authorizes again (`POST /agents/authorize`).

Response 200: the status body. The cleared incident is recorded; a later quarantine citing it is refused (409). Errors: request body is parsed by axum's `Json` extractor before the handler runs — 400 malformed or empty JSON body, or a bad `incident` (empty, over 256 characters, or containing control characters); 401 missing, invalid or stale credential; 403 not the owner, or the Bearer token lacks the scope or the client; 404 unknown workload; 409 not quarantined, incident mismatch, or concurrent change; 415 if `Content-Type` isn't `application/json`; 422 missing or mistyped `incident` field.

## Workload status

`GET /agents/workloads/{workload_id}/status`

Authentication: `X-Auth-Token: <service CWT>` — an access token from `POST /oauth/token` `grant_type=client_credentials` (so `arkavo_roles` contains `service-account` and `sub = client:<client_id>`) for a client listed in `AGENT_STATUS_CLIENT_IDS`. Not `Authorization: Bearer`.

Response 200 (`Cache-Control: no-store`):

```json
{ "workload": "wl-…", "owner": "<owner account UUID>", "current_did": "did:key:…",
  "swarm": "<kit_id>", "state": "eligible", "generation": 42,
  "incident": null, "valid_until": 1790000005 }
```

- Read with a strongly consistent read of the latched record.
- `valid_until = now + 5` (seconds). A consumer caches for at most `min(valid_until − now, 5)` seconds.
- `generation` starts at 1 and increases by exactly 1 on every change to `current_did`, `swarm` or `state`; repeats that change nothing do not increase it. The server assigns it.
- `owner` equals the agent token's `arkavo_account_id`. `current_did` is `""` after recovery until the next authorize. `swarm` is `""` while the workload has no swarm.

Errors: 401 missing or invalid token; 403 not a service CWT or client not allowlisted; 404 unknown workload.

KAS rule (informative; opentdf-platform P2): deny an agent-token rewrap when the status call fails or is non-200, `state = quarantined`, `generation` is lower than the last one seen for the workload, `current_did ≠ sub`, `workload ≠ arkavo_workload`, the token has no `arkavo_swarm`, `swarm ≠ arkavo_swarm`, or `owner ≠ arkavo_account_id`.

## Guardians

`POST /guardians`

Caller: the owner (`X-Auth-Token` passkey auth CWT). Request: `{"public_key": "<base64url, no padding, 32-byte Ed25519 public key>", "name": string (1–64 chars), "proof": "<base64url, no padding, Ed25519 signature>"}`. `proof` is the Guardian key's signature, verified strictly, over the UTF-8 bytes `"arkavo-guardian-enroll" "\n" owner_uuid "\n" public_key`, where `owner_uuid` is the enrolling owner's account UUID (hyphenated, lower case; the account the auth CWT authenticates, not an `arkavo:` prefixed form) and `public_key` is the base64url string sent. Proof of possession stops anyone who merely learns a Guardian's public key from enrolling it first, and binding the owner stops a captured proof from being replayed by another owner. `guardian_id` is not chosen by the caller: it is a UUID derived from the enrolled key's SHA-256, so the same key always enrolls under the same id (and a key's identity is not the signed-bytes owner, only the storage row). Response 200: `{"guardian_id": "<uuid>"}`. Errors: 400 key not 32 bytes, not a valid point, or weak (small-order), or `proof` missing, malformed, or not a valid signature by that key over that owner's enrollment; 401; 409 the key is already enrolled — by any owner, including a Guardian since revoked. A key enrolls at most once, so it has exactly one replay clock (the signed bytes do not name the Guardian), and a revoked key cannot come back with a fresh one; enroll a new key instead.

`DELETE /guardians/{guardian_id}`

Caller: the owner who enrolled the Guardian (`X-Auth-Token` passkey auth CWT). No body. Response 204, also when the Guardian is already revoked. Errors: 401 missing or invalid credential; 403 the Guardian was enrolled by another owner, or the request carries `X-Guardian-Signature`; 404 unknown `guardian_id` (including one that is not a canonical UUID). From then on the Guardian's requests are refused with 401 and the same body as an unknown `guardian_id`, however they are signed. Quarantines it already latched stay latched (recovery clears them) and keep `guardian:<guardian_id>` as who latched them.

Guardian request authentication:

```
X-Guardian-Signature: <guardian_id>.<unix_ts>.<base64url-no-pad Ed25519 signature>
signed bytes (UTF-8): METHOD "\n" PATH "\n" unix_ts "\n" hex(sha256(body))
```

- `METHOD` upper case (`POST`); `PATH` is the request path exactly as sent, without query string; `unix_ts` decimal seconds; `hex` lower case; `body` the exact request body bytes (empty body hashes the empty string).
- `|now − unix_ts| ≤ 60` s.
- Verified with strict Ed25519 verification against the public key enrolled under `guardian_id`, never a key carried by the request. A `guardian_id` that is not a canonical UUID (hyphenated, lower case), unknown, or revoked is refused (401) exactly as a signature that does not verify.
- Replay protection: the server stores `last_signed_at`, the `unix_ts` of the most recent request from that Guardian whose signature verified — the clock advances whenever a request's signature verifies, regardless of whether the request then succeeds or is refused for another reason. A request whose `unix_ts` is not strictly greater than `last_signed_at` is refused (401), even inside the ±60 s window. A Guardian therefore sends at most one request per second, with increasing timestamps.
- A Guardian may call only quarantine, only for its owner's workloads. Any other agent-plane request carrying `X-Guardian-Signature` (`/agents/authorize`, `/agents/delegations`, `/agents/challenge`, `/agents/token`, recover, status, `POST /guardians`, `DELETE /guardians/{guardian_id}`) gets 403 whether or not the signature verifies. That 403 applies to a well-formed request: a malformed JSON body or query string on one of those endpoints is rejected by request parsing (400/415/422) before the handler runs and checks for a Guardian header — quarantine is the exception, since it reads the raw body itself and authenticates the caller (Guardian or owner) before parsing it as JSON.

## Discovery

`GET /.well-known/agent-configuration` adds `agent_workloads_endpoint` (`<issuer>/agents/workloads`), `guardian_registration_endpoint` (`<issuer>/guardians`), `short_lived_token_lifetime_seconds` (300), `workload_status_lease_seconds` (5) and `contract_version` (`"v1"`).
