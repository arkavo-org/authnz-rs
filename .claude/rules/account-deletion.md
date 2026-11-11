---
paths:
  - "src/account.rs"
  - "src/account_tests.rs"
  - "src/db/account.rs"
---

# Account deletion

## account.rs: Account deletion (#88, App Store guideline 5.1.1(v))

- `DELETE /account`: passkey auth CWT (`X-Auth-Token`) minted within
  `ACCOUNT_DELETION_TOKEN_MAX_AGE_SECONDS` (300 s); `agent::verify_passkey_auth_token`
  (token checks only, no account lookup, so a retry still verifies). 202
  `{deletion_id, status, requested_at, completes_by}`; a retry returns the same id.
- **At once**: the `credentials` row is replaced by a tombstone (`db/account.rs`,
  one put on `LIVE_ROW`) holding only `user_id`, `deleted_at`, `deletion_id`,
  `deletion_state`, `deletion_attempts` and, until the sweep completes,
  `deletion_handle`. `get_user_by_id` reports a tombstone as absent, and with
  no `username` it leaves the `username-index` GSI. **Before** the tombstone,
  `claim_handle_row` makes sure the handle has a row naming the account (a
  failure fails the request), so registration, which refuses a handle with
  any row, cannot issue it in the gap. After it, the row is **retired**
  (best effort, and again by the sweep): `retire_handle_if_owned` removes
  `did` and `user_id` and sets `retired_at`, so the resolveHandle Lambda
  answers 404 and the handle, and with it the username, is never issued
  again (#132). Retirement never writes a missing row.
- **Every write to a credentials row carries `LIVE_ROW`**
  (`attribute_exists(user_id) AND attribute_not_exists(deleted_at)`):
  `add_credential`, `put_user_entitlements`, `put_webvh_log` (was an upsert),
  publishing suspension set/lift. Keep it on any new write to that table.
- **Tokens outlive the account, so every path that trusts a token re-checks
  the row** (`DynamoDBStore::is_account_live` / `get_user_by_id`):
  `agent::authenticate_human` / `authenticate_operator` (whole agent plane and
  Guardians), Apple/Google/Patreon link (the Apple link with a token checks
  again after storing it), `/oauth/authorize` with `X-Auth-Token`, the code
  and refresh grants, `/oauth/userinfo`,
  `/device-check/attest`; and for agent tokens, which name the agent not the
  owner, `agent::active_delegation` and `GET /agents/:did/status` check the
  delegation's `root_user_id`. A new token-accepting path must do the same.
- **After `ACCOUNT_DELETION_GRACE_SECONDS` (60 s)**, `account::sweep` retires
  the handle, deletes device
  bindings, identity links (scan: no `user_id` GSI; an
  Apple link holding a token is left for the last step) and the
  Patreon token row (Patreon has no revocation endpoint), revokes (never
  deletes) the passkey index rows (#104), retires (never deletes) the
  owner-KAS routes (#148), invalidates the
  Patreon cache, revokes agent delegations (+ chain cascade; also done in the
  request itself) and Guardians and blanks their `name` / `delegator_username`
  (rows stay: a revoked or
  recovered key must never come back fresh). **Last**, it revokes the
  account's Sign in with Apple refresh tokens (the `token_*` attributes of
  its Apple `identity_links` rows, scan on `user_id`) at Apple's
  `/auth/revoke` and deletes each link on 200. A 4xx
  other than 429 (a configuration problem: key, client id, secret), a stored
  token that cannot be read, or stored tokens while revocation is
  unconfigured, keeps the rows and marks the deletion `failed` at once
  (`SweepError::is_permanent`; no schedule retries). A 429, 5xx, transport or
  KMS failure keeps the rows and retries; a DynamoDB error while scanning or
  deleting a row stops the step at once and retries. Retries
  `[30, 60, 120]` s, then `failed`; `resume_unfinished` restarts
  pending/failed sweeps at boot.
  `device_attest_keys` is not touched (no account link).
- `GET /account/deletions/:id`: no token; the id is `<user_id>.<128-bit hex>`,
  compared constant-time. `pending | failed | completed`. Contract:
  [docs/account-deletion.md](docs/account-deletion.md).
