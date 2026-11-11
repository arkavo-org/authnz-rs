---
paths:
  - "src/agent.rs"
  - "src/agent_state.rs"
  - "src/guardian.rs"
  - "src/agent_plane_tests.rs"
  - "src/db/agent_state.rs"
  - "src/db/guardians.rs"
---

# Agent delegation, trust state and Guardians

## agent.rs: Agent delegation (human PE → agent NPE, `did:key`)

- `/.well-known/agent-configuration`: discovery metadata
- `POST /agents/authorize`: operator auth is a passkey auth CWT
  (`X-Auth-Token`) or, when that header is absent, an `agents:delegate` OIDC
  access token (`Authorization: Bearer`, allowlisted client, `auth_time`
  within 3600 s). Creates a delegation record for `agent_did` with a subset
  of the delegator's own stored entitlements
  (`DynamoDBStore::get_user_entitlements`). Body adds `swarm` (optional: no
  `arkavo_swarm` claim until set) and `short_lived`. One identity is one key
  (the DID); authorize is the owner's bootstrap appraisal: `eligible` until
  the passkey assertion time (auth CWT `iat` / Bearer `auth_time`) +
  `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (`owner_appraisal_deadline`; 403 once
  past), with `plan_authorize` deciding the `state_version` (a swarm change
  bumps it). Refused while the key is quarantined or once it has been
  recovered; 409 while another owner's delegation of the DID is live. The
  agent quota applies only when authorize adds a delegation.
  Response `{success, message, agent, state, state_version, appraised_until}`.
- **The market request entitlement**
  `https://arkavo.net/attr/market/value/request`
  (`constants::ENTITLEMENT_MARKET_REQUEST`): an agent holding it may ask
  market.arkavo.com for a purchase for its owner, who still pays. **Every
  live account holds it without a stored copy**
  (`constants::is_held_by_every_account`, exact match), so any account
  holder can delegate it: `agent::holds_entitlement` is the one rule behind
  the authorize subset check and the mint intersection. The whole
  `https://arkavo.net/attr/market/` attribute is refused by `validate_fqns`
  (`EntitlementError::NeverStored`), so it is never in a human's token. It
  is **not** derived-only: `strip_derived_only` must keep it on a
  delegation. The market's contract: arkavo-com/market
  `docs/market-identity-interface.md`, "Requests: the tokens identity
  issues".
- `GET /agents/delegations`, `DELETE /agents/delegations/:did` (cascade).
  The DELETE takes the owner's passkey auth CWT or, from 0.37.0, an
  `agents:delegate` Bearer token under quarantine's rule (allowlisted
  client, `auth_time` within 3600 s): revoking only removes power, so an
  owner can end an agent's authority from Edge or Creator.
- **The market pay entitlement**
  `https://arkavo.net/attr/market/value/pay`
  (`constants::ENTITLEMENT_MARKET_PAY`, 0.37.0): an agent holding it may
  *attempt* a purchase at the market by itself. Held by every live account
  without a stored copy, exactly like the request entitlement below, and
  separate from it so an agent that may ask for payment links cannot
  spend. **Identity only entitles the attempt** (owner decision
  2026-11-10): what may be bought, for how much and how often is the
  market's purchase authority, never stored, signed into a token or
  enforced here.
- `GET /agents/challenge?did=…` → `{challenge: b64(32 bytes), nonce}`; the
  challenge is stored on the delegation row (no cookie session)
- `POST /agents/token` `{did, challenge, signature, nonce}` → verifies the
  Ed25519 proof over the decoded challenge bytes, returns
  `{token, expires_at, entitlements}`. Mints only while the identity is
  `eligible` (`agent::issuable`; a row written before v2 is `unassessed`).
  `token` is a single CWT (no delegation JWT): `aud` = the
  configured `AGENT_TOKEN_AUDIENCES` list, `exp - iat` capped at
  `AGENT_TOKEN_MINUTES` (hard max 15 min; ≤ 300 s when `short_lived`; never
  past `appraised_until`), `act` = `AGENT_AUTHORIZED_ACTORS`, `arkavo_npe`
  describes the agent (type, delegation id, depth, chain),
  `arkavo_state_version` is the identity's `state_version` at mint,
  `arkavo_swarm` its kit (omitted until it has one), `cnf` is bound to the agent's
  Ed25519 `did:key`. There is no refresh — the agent re-runs the
  challenge/token exchange for a new one. This is the contract
  `arkavo-edge/crates/arkavo-agent-auth` expects (#54); its `delegation_jwt`
  field is `Option` with `#[serde(default)]`, so omitting it is
  wire-compatible.
- Extracted from PR #23; agent→agent delegation, per-agent OAuth clients
  (#50) and the ERS surface (#48) are follow-ups
- Wire contract for all of this and the endpoints below:
  [docs/agent-credentials-contract.md](docs/agent-credentials-contract.md) (v2).

## agent_state.rs: The agent identity's trust state (quarantine, recovery, appraisal, status)

- State lives on the `agent_delegations` row (`db/agent_state.rs`):
  `unassessed | eligible | quarantined` stored, `suspended` derived
  (`eligible` past `appraised_until`). `state_version` +1 on every stored
  state change, a swarm change, a revocation, and an authorize over a
  revoked/expired/pre-v2 row; never on a renewal. Every write is one
  conditional `UpdateItem` on the version read (quarantine and revocation also
  on the owner read; appraisal also on a live delegation).
- `POST /agents/:did/quarantine`: owner (passkey auth CWT, or an
  `agents:delegate` Bearer token with `auth_time` ≤ 3600 s old) or the owner's
  Guardian; latches whatever the delegation's liveness, idempotent per
  incident, 409 on a second incident, on the incident the last recovery
  cleared, and on a write that races a concurrent change (`Raced`; retry).
- `POST /agents/:did/recover`: owner only, passkey assertion ≤ 300 s old
  (auth CWT `iat`, or Bearer `auth_time`), cites the incident; the identity
  becomes `unassessed` with `recovered_at` set; once recovered, the key is
  Guardian-appraised for life (the owner's path back is a new key). The
  delegation is kept.
- `POST /agents/:did/appraisal`: an enrolled Guardian of the owner (≤
  `AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` from now) or the owner (≤
  `AGENT_OWNER_APPRAISAL_TTL_SECONDS` from its passkey assertion, never a
  recovered key); clamps `appraised_until` to that; 403 for quarantined,
  revoked, expired, another owner's agent, a stale owner assertion, or a
  Guardian whose key is the agent's own.
- The 403 bodies in the contract's "Refusal bodies" table are part of v2
  (`agent::REFUSE_*`, `AgentError::{WorkloadQuarantined, DelegationRevoked}`);
  `agent_plane_tests::refusal_bodies_are_contract_v2` pins them.
- `GET /agents/:did/status`: service CWT from `AGENT_STATUS_CLIENT_IDS`;
  `valid_until = now + 5`, capped at `appraised_until` while eligible; 404 for
  an unknown, revoked or expired delegation unless quarantined.
- `AppraisalConfig` parses the two appraisal lifetimes at startup.

## guardian.rs: Minimal Guardian enrollment and revocation

- `POST /guardians` (owner, passkey auth CWT): registers a 32-byte Ed25519 key
  (weak keys refused), proving possession of it — `proof` is that key's
  signature over an enrollment message naming the owner (400 if missing,
  malformed, or not a valid signature by that key for that owner).
  `guardian_id` is a UUID derived from the key's SHA-256, so a key enrolls at
  most once, ever, under any owner (409), and a revoked key can never
  re-enroll with a fresh id.
- `DELETE /guardians/:id` (owner who enrolled it, passkey auth CWT only): 204
  (idempotent on an already-revoked Guardian), 403 belongs to another owner,
  404 unknown or non-canonical id. Revocation is a marker, never a delete.
- `X-Guardian-Signature: <id>.<ts>.<sig>` over `METHOD\nPATH\nts\nhex(sha256(body))`,
  ±60 s, `verify_strict` against the enrolled key only; each Guardian's accepted
  timestamps must strictly increase (`last_signed_at`), so a replay is 401.
  Guardians get 403 on every agent-plane endpoint except quarantine and
  appraisal — that 403 is for a well-formed request; a malformed body/query on
  any other endpoint is refused by request parsing (400/415/422) before the
  Guardian check runs.
