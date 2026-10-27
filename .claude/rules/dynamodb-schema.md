---
paths:
  - "src/db.rs"
  - "src/db/**/*.rs"
---

## DynamoDB Schema

### credentials table
- **Primary Key**: user_id (String/UUID)
- **Attributes**: username (String), credentials (List of JSON strings), did (String),
  entitlements (List of String, attribute FQNs; never contains the derived
  creator-publishing FQN), webvh_log (String, optional)
- **publishing_suspension** (Map, optional; #91): present only while a
  moderator has suspended publishing. Keys: `reason` (String),
  `report_id` (String, optional), `suspended_by` (String, the service
  client's `client:<id>`), `suspended_at` (Number). The map is the audit
  record. Set by one conditional `UpdateItem` on `LIVE_ROW AND
  attribute_not_exists(publishing_suspension)` (a repeat keeps the first
  record); lifted by a `REMOVE` conditional on `LIVE_ROW` (returns the old
  map for the audit log). Read
  with `consistent_read(true)` on every mint whose membership qualifies.
- **app_store** (Map, optional): the account's App Store subscriptions, keyed
  by `original_transaction_id` (a numeric string, so addressed through an
  expression attribute name). Each value: `product_id` (String),
  `environment` (`Production`|`Sandbox`), `expires_at` (Number),
  `grace_expires_at` (Number, optional), `revoked_at` (Number, optional),
  `last_signed_at` (Number); all times unix seconds. Written by
  `put_app_store_state` in two conditional `UpdateItem`s (DynamoDB rejects
  overlapping paths in one expression): `SET app_store = :empty` on `LIVE_ROW
  AND attribute_not_exists(app_store)`, then `SET app_store.#otid = :rec` on
  `LIVE_ROW AND (attribute_not_exists(app_store.#otid) OR
  app_store.#otid.last_signed_at <= :signed)`. Order is by `last_signed_at`
  (Apple's `signedDate`) per otid, never by JWS bytes (an ECDSA signature is
  malleable); the JWS is not stored. Read with the suspension in one
  `consistent_read(true)` `GetItem` (`get_publishing_state`). The entitlement
  derived from it is never stored.
- **Tombstone** (#88): a deleted account's row is replaced, in one put on
  `attribute_exists(user_id) AND attribute_not_exists(deleted_at)`, by
  `user_id`, `deleted_at` (Number; its presence makes the row a tombstone),
  `deletion_id` (String, `<user_id>.<32 hex>`), `deletion_state`
  (`pending`|`failed`|`completed`), `deletion_attempts` (Number),
  `deletion_completed_at` (Number) and `deletion_handle` (String, removed when
  the sweep completes). No `username`, so it is not in `username-index`.
  `get_user_by_id` / `get_user_by_name` read a tombstone as absent. **Every
  write to this table is conditional on `LIVE_ROW`** (same expression), so
  nothing lands on a tombstone or recreates a deleted row.
- **GSI**: username-index (partition key: username)

### handles table
- **Primary Key**: handle (String)
- **Attributes**: did (String), user_id (String/UUID, the owning account;
  `put_handle` and the deletion sweep's delete are both conditional on it)
- **Format**: Handles are "{username}.arkavo.social"

### device_bindings table
- **Primary Key**: device_id (String) - Key ID from App Attest
- **Attributes**:
  - user_id (String/UUID) - Links to UserCredentials
  - public_key (Binary) - Attested public key from certificate
  - counter (Number) - Monotonic counter for replay protection
  - app_id (String) - rpIdHash for App ID validation
  - app_env (String, optional; #114) - `production` | `development`, from the
    attestation's aaguid. Absent on bindings written before #114; read as
    absent (never an error) when missing or unreadable, so the token carries
    no `app_env`
  - created_at (Number) - Unix timestamp
  - updated_at (Number) - Unix timestamp (updated on each assertion)

### identity_links table
- **Primary Key**: link_pk (String) - Format: `<provider>#<subject>` (e.g. `apple#001234.abc...`, `patreon#12345`)
- **Attributes**:
  - user_id (String/UUID) - The arkavo account bound to this third-party identity
  - provider (String) - IdP name (`apple`, `patreon`, future: `google`, etc.)
  - subject (String) - The IdP's stable subject identifier
  - linked_at (Number) - Unix timestamp
- **Read path**: `DynamoDBStore::get_identity_link(provider, subject)`. This is
  how *every* federated sign-in reaches an account — see `identity.rs`.
- **Cardinality**: one account may link several subjects of the same provider
  (work + personal Google). The reverse — one subject on two accounts — is
  refused.
- **Uniqueness**: Conditional put on `link_pk` enforces per-(provider, subject) uniqueness.
  Re-linking the same identity to the same user is idempotent; binding to a
  different user returns `DynamoDBError::LinkConflict` (HTTP 409 upstream).
- **Sign in with Apple token** (optional, Apple rows only; `db/apple_tokens.rs`):
  token_client_id (String, the bundle id / Service ID the token was issued
  to; revocation presents it), token_wrapped_dek (Binary, DEK wrapped by
  `PATREON_KMS_KEY_ID`), token_nonce (Binary, 12-byte GCM nonce), token_ct
  (Binary, AES-256-GCM ciphertext of Apple's refresh token), token_stored_at
  (Number). Present only when the link was made with revocation configured.
  - **Writes**: `POST /oauth/apple/link` writes the link and the token in one
    conditional `UpdateItem` (same condition as the link). A re-link replaces
    the token without revoking the old one (Apple's revoke is
    authorization-wide; the deletion-time revoke covers it). `link_identity`
    is an `UpdateItem` too, so a re-link without a token keeps a stored one.
  - **Deletion**: the sweep's link step deletes every link of the account
    *except* one holding any `token_*` attribute. Its last step revokes each
    token with Apple, then deletes that link, conditional on `user_id`. A link
    whose token Apple did not revoke stays (the deletion is `failed` or
    retried); sign-in through it fails closed, since the account is a
    tombstone, and it 409s a new account linking the same Apple ID until
    revoked. A row with some but not all `token_*` attributes is unreadable
    and keeps the deletion `failed` (permanent).
- **App Store subscription link** (`appstore#<original_transaction_id>`; no
  Apple token): attributes `user_id` and `created_at` (Number, unix seconds;
  kept on a re-bind). Written by `bind_app_store_link` as one `UpdateItem` on
  `attribute_not_exists(link_pk) OR user_id = :uid`, followed by an
  `is_account_live` re-check that deletes the link if the account died
  meanwhile. It holds no `token_*` attribute, so the sweep's
  `delete_identity_links_of` removes it. Read with `app_store_link_owner`
  (consistent). The state lives on the `credentials` row, not here.
- **Passkey index** (#104; `db/passkeys.rs`): `link_pk = passkey#<base64url
  credential id>`, `provider = passkey`, `subject` = the id, `user_id`,
  `linked_at` (first attestation), `revoked_at` (Number, optional). Written by
  `POST /passkeys/credential-attestation` on `attribute_not_exists(link_pk) OR
  (user_id = :uid AND attribute_not_exists(revoked_at))`. Never deleted: the
  deletion sweep's link step skips `provider = passkey`
  (`(attribute_not_exists(provider) OR provider <> :passkey)`, in the scan
  filter and the delete condition) and `revoke_passkey_links_of` sets
  `revoked_at = if_not_exists(revoked_at, deleted_at)`. Read by
  `GET /passkeys/credentials/:id/status` (consistent), never by sign-in.
- **Passkey session** (#108; `db/session.rs`): `link_pk = session#<session
  id>`, `provider = session`, `subject` = the id, `user_id`, `public_key` (B,
  65-byte X9.63 device key), `assertion_at`, `created_at`, `last_renewed_at`,
  `generation` (N), `credential_hash` (B, SHA-256 of the current
  credential), `expires_at` (N, `assertion_at + SESSION_MAX_SECONDS`, for a
  TTL that is not enabled yet). Written by `POST /session` on
  `attribute_not_exists(link_pk)`, then an `is_account_live` re-check that
  deletes it if the account died meanwhile. Renewal rotates it with one
  `UpdateItem` on `generation = :gen AND credential_hash = :old`. Deleted on
  sign-out and on a refused renewal that ends it (idle, expired, reused,
  account deleted). No `token_*` attribute and not `provider = passkey`, so
  the sweep's `delete_identity_links_of` removes it. Read consistently by
  `get_session`, never by sign-in.
- **PII**: Deliberately minimal. No email, display name, relay address, or
  `real_user_status` is stored here, even if the IdP returns them. A sealed
  Apple refresh token is not PII.
- **Future GSI** `user_id-index`: Add when an endpoint needs to enumerate
  "which providers has this user linked?". Account deletion (#88) finds a
  user's links with a paginated scan instead (deletions are rare); add the
  GSI if the table grows enough for that to matter.

### agent_delegations table
- **Primary Key**: agent_did (String) - `did:key:z6Mk…`
- **Attributes**: delegator_type (`human`|`agent`), delegator_id (String),
  delegator_username (String, optional), entitlements (List of String),
  name (String, a label), depth (Number), root_user_id (String/UUID), chain
  (List of String), created_at / expires_at / revoked_at (Number),
  short_lived (Boolean), swarm (String, absent while the agent has no kit —
  never an empty string), and the transient challenge triple `challenge`,
  `challenge_nonce`, `challenge_issued_at` (set by `/agents/challenge` only
  while the row is `eligible` with `appraised_until` in the future, unrevoked
  and unexpired; removed atomically by `/agents/token`)
- **Trust state** (contract v2; the row is the agent identity, one key):
  state (`unassessed`|`eligible`|`quarantined`; absent on a row written before
  v2, which reads as `unassessed`), state_version (Number, +1 on every change
  of `state`, a swarm change, a revocation, and an authorize over a revoked,
  expired or pre-v2 row, never on a renewal; absent = 0 on a pre-v2 row),
  appraised_until (Number),
  appraised_by (String, `owner:<uuid>` | `guardian:<id>`),
  appraisal_evidence_ref (String, the evidence an appraisal cited; removed
  by the next appraisal without one, an authorize and a recovery),
  incident / evidence_ref / quarantined_by
  (String, present only while quarantined), quarantined_at (Number, present
  only while quarantined), last_cleared_incident (String, the incident the
  most recent recovery cleared), recovered_at (Number, never removed: the
  owner may not appraise a recovered key), updated_at (Number). A pre-v2
  `workload_id` attribute is removed by the next authorize.
- **Reads**: `get_agent_delegation` is `consistent_read(true)` (issuance and
  the status lease must see the latch).
- **Writes**: every trust-state change is one conditional `UpdateItem` —
  authorize on what it read: a create on no row at all; a renewal of the
  owner's own delegation on the `state_version` read (`attribute_not_exists`
  when 0), not quarantined, the same owner, not revoked and not expired; a
  new delegation over a revoked or expired one on the version read, not
  quarantined, its previous owner, and still revoked or expired; quarantine on
  the owner and version read, not quarantined and the incident not being
  the one last cleared; recover on quarantined, the latched incident and the
  version read; appraisal on the version read, not quarantined and a live
  delegation; revocation (`revoked_at`, `state_version + 1`) on the owner and
  version read. No `TransactWriteItems`.
- **GSI**: root_user_id-index (partition key: root_user_id) — list/count a
  user's agents

### guardians table
- **Primary Key**: guardian_id (String/UUID) - a UUID (version 8) derived
  from the enrolled key's SHA-256, so the same key always enrolls under the
  same id and an id is never caller-chosen
- **Attributes**: owner (String/UUID), public_key (Binary, 32-byte Ed25519),
  name (String), created_at (Number), last_signed_at (Number, optional — the
  `unix_ts` of the most recently accepted `X-Guardian-Signature`; advanced
  only strictly forward and only while unrevoked, enforcing both the replay
  window and revocation in one conditional update), revoked_at (Number,
  optional — set `if_not_exists` so the first revocation time sticks; the row
  is never deleted, so a revoked key's id can never be reused)
- **Writes**: enrollment is `attribute_not_exists(guardian_id)` (one key, one
  row, forever); revocation and the signature-clock advance are conditional
  updates keyed on `guardian_id` and (for revocation) `owner`.

### patreon_tokens table
- **Primary Key**: user_id (String/UUID) - One row per arkavo user; re-link
  overwrites in place.
- **Attributes**:
  - role (String) - `creator` or `consumer`: whether Patreon last reported
    an owned campaign (#99), never the client's word. Rewritten with
    `campaign_id` by materialization when the answer changes.
  - client_id (String) - The Patreon OAuth client that performed the code
    exchange; refresh must present the same client's secret. Empty on rows
    written before multi-client support (tolerated only while exactly one
    client is configured).
  - patreon_user_id (String) - Patreon's stable `data.id` from `/identity`;
    duplicated here so the materialization read path doesn't need a second
    lookup against `identity_links`
  - campaign_id (String, optional) - Creator only; the Patreon `campaign.id`
    the account owns, discovered at link time and re-read on every
    materialization when the link holds the `campaigns` scope
  - scopes (String) - Space-separated OAuth scopes granted on the token
  - access_token_ct (Binary) - AES-256-GCM ciphertext of the Patreon access
    token under the row's DEK
  - access_token_nonce (Binary) - 12-byte GCM nonce for access_token_ct
  - refresh_token_ct (Binary) - AES-256-GCM ciphertext of the Patreon
    refresh token under the same DEK
  - refresh_token_nonce (Binary) - 12-byte GCM nonce for refresh_token_ct
    (always distinct from access_token_nonce — never reuse key+nonce)
  - wrapped_dek (Binary) - KMS-wrapped 256-bit DEK; decrypt with
    `kms:Decrypt` on `PATREON_KMS_KEY_ID`
  - token_expires_at (Number) - Unix timestamp the Patreon access token
    expires at (per Patreon's `expires_in`)
  - linked_at (Number) - Unix timestamp of original link
  - campaign_tier_ids / campaign_tier_slugs (List of String, optional;
    creator only, #99) - The owned campaign's tiers as last fetched from
    `GET /campaigns/<cid>?include=tiers` (ids; deduplicated title slugs).
    Written with `role` and `campaign_id` by one conditional `UpdateItem` on
    `attribute_exists(user_id) AND patreon_user_id = :pid AND linked_at =
    :la` (`put_patreon_ownership`) when the campaign or list changed; an
    account owning none gets all three removed and `role = consumer`.
    Carried forward by every whole-row put (token rotation). Absent or
    malformed reads as empty. A re-link writes them empty until the next
    fetch.
- **Encryption**: Envelope. A DynamoDB-only compromise yields ciphertext
  blobs but no plaintext tokens — recovery additionally requires
  `kms:Decrypt` on the configured key.
- **No GSI**: per-Patreon-account uniqueness is enforced via the
  `identity_links` row (`patreon#<patreon_user_id>`), not via a secondary
  index here. The forward `user_id → patreon` lookup uses the table's
  primary key directly.

### device_attest_keys table
- **Primary Key**: key_id (String) - App Attest key identifier
- **Attributes**:
  - registrations (Number) - Lifetime count of registrations by this key
  - window_base (Number) - `registrations` when the current window opened
  - window_started_at (Number) - Unix timestamp the current window opened
  - first_seen_at (Number) - Unix timestamp of first attestation
  - last_reg_at (Number) - Unix timestamp of most recent registration
- **Purpose**: rate-limits registrations per attested `key_id`, and records
  the history that makes an abusive key visible.
- **Scope — bounds a key, not a device**: App Attest keys are free and carry
  no device identity, and `attestKey` is once-per-key, so a client mints a
  fresh `key_id` per attestation. An attacker generating keys in a loop never
  reaches these limits. Admission control is the attestation itself (genuine
  device, genuine app); this table is defence in depth plus an abuse signal.
- **Conditional updates**: slot reservation is conditional on the observed
  `registrations`, so concurrent attests cannot both take the last slot.
