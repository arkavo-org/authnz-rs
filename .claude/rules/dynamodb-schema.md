---
paths:
  - "src/db.rs"
---

## DynamoDB Schema

### credentials table
- **Primary Key**: user_id (String/UUID)
- **Attributes**: username (String), credentials (List of JSON strings), did (String)
- **GSI**: username-index (partition key: username)

### handles table
- **Primary Key**: handle (String)
- **Attributes**: did (String)
- **Format**: Handles are "{username}.arkavo.social"

### device_bindings table
- **Primary Key**: device_id (String) - Key ID from App Attest
- **Attributes**:
  - user_id (String/UUID) - Links to UserCredentials
  - public_key (Binary) - Attested public key from certificate
  - counter (Number) - Monotonic counter for replay protection
  - app_id (String) - rpIdHash for App ID validation
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
- **PII**: Deliberately minimal. No email, display name, relay address, or
  `real_user_status` is stored here, even if the IdP returns them.
- **Future GSI** `user_id-index`: Add when an endpoint needs to enumerate
  "which providers has this user linked?" — not required by the current
  endpoint surface.

### agent_delegations table
- **Primary Key**: agent_did (String) - `did:key:z6Mk…`
- **Attributes**: delegator_type (`human`|`agent`), delegator_id (String),
  delegator_username (String, optional), entitlements (List of String),
  name (String), depth (Number), root_user_id (String/UUID), chain (List of
  String), created_at / expires_at / revoked_at (Number), and the transient
  challenge triple `challenge`, `challenge_nonce`, `challenge_issued_at`
  (set by `/agents/challenge`, removed atomically by `/agents/token`)
- **GSI**: root_user_id-index (partition key: root_user_id) — list/count a
  user's agents

### patreon_tokens table
- **Primary Key**: user_id (String/UUID) - One row per arkavo user; re-link
  overwrites in place.
- **Attributes**:
  - role (String) - `creator` or `consumer`
  - client_id (String) - The Patreon OAuth client that performed the code
    exchange; refresh must present the same client's secret. Empty on rows
    written before multi-client support (tolerated only while exactly one
    client is configured).
  - patreon_user_id (String) - Patreon's stable `data.id` from `/identity`;
    duplicated here so the materialization read path doesn't need a second
    lookup against `identity_links`
  - campaign_id (String, optional) - Creator only; the Patreon `campaign.id`
    discovered at link time
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
