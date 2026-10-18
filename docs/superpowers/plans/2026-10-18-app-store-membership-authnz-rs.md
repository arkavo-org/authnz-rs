# App Store Creator Membership — authnz-rs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An account with an active App Store Creator Membership gets `ENTITLEMENT_CREATOR_PUBLISH` at every short-lived token mint, exactly as a qualifying Patreon member does.

**Architecture:** A new `app_store` module verifies StoreKit 2 JWS (signed transactions, renewal info, Server Notifications V2) against a pinned Apple Root CA – G3.

- **No new table.** An `identity_links` row `appstore#<original_transaction_id>` → `user_id` gives one-subscription-one-account, the 409, and freeing on deletion; the existing sweep already deletes an account's links. Subscription state is an `app_store` map on the `credentials` row, keyed by `original_transaction_id`. Writes to it are conditional on `LIVE_ROW`, so nothing can land on a tombstone.
- **Two routes write it:** `POST /app-store/transactions` (client, authenticated) and `POST /app-store/notifications` (Apple, signature-verified).
- **Grant at mint.** `publishing::derived_entitlements` grants the FQN if Patreon qualifies **or** an App Store record is active, and the account is not suspended. The suspension and the App Store state come from **one** strongly consistent read of the `credentials` row.

**Tech Stack:** Rust, axum, DynamoDB (aws-sdk), `x509-parser` (`verify`), `p256`/`ecdsa`, `base64`, `serde_json` (all existing). New dev-dependency: `rcgen`, for test certificate chains.

**Design:** this plan is self-contained; the binding rules are in "Rules" below. The full design (rollout, Creator side) is `/Users/arkavo/Projects/Creator/docs/superpowers/specs/2026-10-18-app-store-creator-membership-design.md`. You don't need it to run this plan.

Work in a worktree off `origin/main` (6ff7799, version 0.19.0), branch `feat/app-store-membership`. Commit this plan to `docs/superpowers/plans/` on that branch.

## Rules (binding; owner decisions marked)

- **Product.** Owner: auto-renewable subscription `com.arkavo.ArkavoCreator.membership.monthly`, $129.99/month, group `22491436`. Family Sharing is off.
- **Entitlement.** The membership grants the existing `constants::ENTITLEMENT_CREATOR_PUBLISH` (`https://patreon.arkavo.com/attr/arkavo-creator/value/publish`).
  - No new FQN. tdf-iroh-s3, arkavo-rs and the platform ERS stay unchanged.
  - The FQN stays derived-only through the existing `is_derived_only` namespace rule.
- **Signature (verification checklist).** All of these must hold:
  - the compact JWS has `alg` = `ES256`;
  - `x5c` has exactly 3 certificates (standard base64 DER), and `x5c[2]` is byte-equal to the pinned Apple Root CA – G3;
  - leaf ← intermediate ← root signatures verify;
  - the leaf carries the extension OID `1.2.840.113635.100.6.11.1`, and the intermediate carries `1.2.840.113635.100.6.2.1`;
  - all three certificates are valid at the payload's `signedDate` (now, if absent). There is no online OCSP check;
  - the ES256 (JOSE r‖s) signature over `header.payload` verifies with the leaf key.

  These follow Apple's App Store Server Library.
- **Payload checks.**
  - `bundleId` = `com.arkavo.ArkavoCreator`.
  - Production notifications also need `data.appAppleId` = `6738845556`.
  - `productId` ∈ `APP_STORE_PUBLISH_PRODUCT_IDS`.
  - `inAppOwnershipType` = `PURCHASED` (`FAMILY_SHARED` is refused).
- **Environments.** Owner decision: always accept `Production` and `Sandbox` on prod.
  - App Review buys in Sandbox. TestFlight testers can therefore get publishing for free; suspension and the content filter still apply.
  - Every Sandbox grant is logged with `env=Sandbox`, so abuse is visible.
  - `Xcode` and `LocalTesting` are always refused. Their payloads are unsigned.
- **Active.** A stored record is active iff:
  - `product_id` ∈ config;
  - `environment` ∈ config;
  - `revoked_at` is none;
  - `now < max(expires_at, grace_expires_at)`.

  Any read error means no entitlement (fails closed).
- **Binding (client post).** The transaction's `appAccountToken` is required.
  - Missing → 422 `invalid transaction`.
  - Equal to the caller → bind to the caller.
  - Names an account that isn't live (deleted or unknown) → bind to the caller. My call: a deleted account's still-billing subscription can move to the person's new account. The exposure is limited to transactions of deleted accounts.
  - Names another live account → 403 `transaction belongs to another account`.
  - `appstore#<otid>` already bound to another account → 409 `subscription belongs to another account`.
- **Binding (notification).**
  - Unknown otid whose `appAccountToken` names a live account → bind to that account.
  - Unknown otid otherwise → acknowledge (200) and drop.
- **Ordering.** A state write applies only if the incoming `signedDate` ≥ the stored `last_signed_at`. The state always comes from the transaction snapshot (`expiresDate`, `revocationDate`) plus `gracePeriodExpiresDate` from the renewal info. The notification type is logged, not interpreted (`TEST` is acknowledged).
- **Deletion.**
  - The sweep's existing `delete_identity_links_of` removes `appstore#` links.
  - The tombstoned `credentials` row refuses `app_store` writes (`LIVE_ROW`).
  - A bind re-checks `is_account_live` after writing the link and deletes the link if the account died meanwhile, as the Apple link does.

## Global Constraints

- **Bundle and product.** Bundle ID `com.arkavo.ArkavoCreator`; app Apple ID `6738845556`.
- **Env vars.**
  - `APP_STORE_BUNDLE_ID`, `APP_STORE_APP_APPLE_ID`, `APP_STORE_PUBLISH_PRODUCT_IDS` (comma-separated).
  - `APP_STORE_ENVIRONMENTS` (comma-separated, default `Production,Sandbox`; only those two values are accepted).
  - The feature is off unless the first three are set: a startup log line, and the routes answer 503.
  - No new table env var.
- **Units.** Apple dates are milliseconds since the epoch; store unix **seconds** (`i64`). Response, record and map field names are snake_case.
- **Error bodies, exactly:**
  - 403 `transaction belongs to another account`
  - 409 `subscription belongs to another account`
  - 422 `invalid transaction`
  - 503 `app store purchases unavailable`
- **Root pin.** Pin Apple Root CA – G3 as PEM (`APPLE_ROOT_CA_G3`, beside `APPLE_APP_ATTEST_ROOT_CA`), from `https://www.apple.com/certificateauthority/AppleRootCA-G3.cer`.
  - A unit test asserts SHA-256 of the DER = `63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179`.
  - That value was read from macOS `/System/Library/Keychains/SystemRootCertificates.keychain` ("Apple Root CA - G3"), a source independent of the download.
- **Existing rules (CLAUDE.md).**
  - Every token-accepting path calls `is_account_live`.
  - Every `credentials` write carries `LIVE_ROW`.
  - Derived entitlements are never stored.
  - Never log a JWS, a token or an `appAccountToken`. Log `original_transaction_id`, product, environment and notification type only.
- **Version and commits.** Version `0.20.0` in `Cargo.toml`. Commit titles are conventional; `(#<PR>)` is added at PR time.

## Review Focus

1. **Stale token.** A purchase posted with an expired `X-Auth-Token` gets 401, so the client can re-auth and re-post. Pinned in Task 4.
2. **Out-of-order notifications.** An older `EXPIRED` arriving after a newer `DID_RENEW` must not end an active membership. Pinned in Tasks 3 and 5.
3. **Same Apple ID, second account.** It gets 409. Deleting the first account frees it, and a notification racing the sweep can't write onto the tombstone. Pinned in Tasks 3, 4 and 6.
4. **Refund.** A refund (`revocationDate`) removes the entitlement at the very next mint, even with `expiresDate` in the future. The read is consistent, so no stale GSI is involved. Pinned in Task 6.
5. **Leaked transaction.** A JWS replayed by another live account gets 403. Pinned in Task 4.

---

### Task 1: JWS signature and chain verification

**Files:**
- Create: `src/app_store.rs`, `src/app_store_tests.rs`
- Modify: `src/main.rs` (`mod app_store;` and `#[cfg(test)] mod app_store_tests;`), `Cargo.toml` (`[dev-dependencies] rcgen`)

**Interfaces:**
- Produces:
  - `pub(crate) fn verify_jws(jws: &str, root_der: &[u8]) -> Result<serde_json::Value, AppStoreError>`: returns the payload object.
  - `pub(crate) enum AppStoreError { Malformed, InvalidChain, InvalidSignature, WrongApp, WrongEnvironment, NotPurchased, NotConfigured }`. Its `Display` never includes payload bytes.
  - `pub(crate) const APPLE_ROOT_CA_G3: &str` and `pub(crate) fn apple_root_g3_der() -> &'static [u8]` (parsed once, as `APPLE_ROOT_CERT_DER` is).

- [ ] **Step 1: Write failing tests** in `src/app_store_tests.rs`.
  - **Fixture.** An `rcgen` chain: a test root; an intermediate with extension OID `1.2.840.113635.100.6.2.1`; a leaf with `1.2.840.113635.100.6.11.1`; all ES256. A helper `sign_jws(payload, chain)` produces compact JWS with header `{"alg":"ES256","x5c":[leaf,int,root]}`.
  - **Tests:**
    - `accepts_a_valid_three_certificate_chain` → `Ok(payload)` equal to the input JSON.
    - `refuses_a_two_certificate_chain` → `InvalidChain`.
    - `refuses_a_chain_to_another_root` → `InvalidChain`.
    - `refuses_a_leaf_without_the_receipt_signing_oid`, `refuses_an_intermediate_without_the_wwdr_oid` → `InvalidChain`.
    - `refuses_a_tampered_payload` → `InvalidSignature`.
    - `refuses_alg_other_than_es256` → `Malformed`.
    - `checks_validity_at_signed_date`: a leaf expired now but valid at `signedDate` → `Ok`. A leaf not yet valid at `signedDate` → `InvalidChain`.
    - `apple_root_g3_is_the_published_root`: `hex(sha256(apple_root_g3_der()))` equals the pinned fingerprint, compared case-insensitively.
- [ ] **Step 2: Run** `cargo test app_store_tests` → FAIL.
- [ ] **Step 3: Implement `verify_jws`** per the Rules checklist. Follow the parsing idioms of `device_check::validate_certificate_chain_at`, and leave that function unchanged.
- [ ] **Step 4: Run** `cargo test app_store_tests` → PASS. Then `cargo clippy --all-targets -- -D warnings`.
- [ ] **Step 5: Commit** `feat(app-store): verify StoreKit JWS against Apple Root CA G3`.

### Task 2: Config and semantic decoding

**Files:**
- Modify:
  - `src/app_store.rs` and `src/app_store_tests.rs`.
  - `src/main.rs`: add the `AppState` field and the env read. Every test `AppState { … }` literal (the 5 sites with `publisher:`) gets `app_store: Arc::new(None)`.

**Interfaces:**
- Consumes: `verify_jws`.
- Produces:
  - `pub struct AppStoreConfig { pub bundle_id: String, pub app_apple_id: i64, pub product_ids: HashSet<String>, pub environments: HashSet<Environment> }`.
    - `pub fn from_env() -> Option<Self>` logs ENABLED/DISABLED as `PublisherConfig::from_env` does.
    - `#[cfg(test)] fn for_tests(root_der: Vec<u8>) -> Self` sets an overriding root.
  - `#[derive(Serialize, Deserialize)] pub enum Environment { Production, Sandbox }`.
  - `pub struct VerifiedTransaction { pub original_transaction_id: String, pub product_id: String, pub environment: Environment, pub app_account_token: Option<Uuid>, pub expires_at: i64, pub revoked_at: Option<i64>, pub signed_at: i64 }`.
  - `pub(crate) fn decode_transaction(cfg: &AppStoreConfig, jws: &str) -> Result<VerifiedTransaction, AppStoreError>`.
  - `pub(crate) fn decode_renewal_grace(cfg: &AppStoreConfig, jws: &str) -> Result<Option<i64>, AppStoreError>` reads `gracePeriodExpiresDate`.
  - `pub struct VerifiedNotification { pub notification_type: String, pub transaction: Option<VerifiedTransaction>, pub grace_expires_at: Option<i64> }`.
  - `pub(crate) fn decode_notification(cfg: &AppStoreConfig, signed_payload: &str) -> Result<VerifiedNotification, AppStoreError>`.
  - `AppState.app_store: Arc<Option<app_store::AppStoreConfig>>`.

- [ ] **Step 1: Write failing tests:**
  - `decodes_a_production_transaction`: ms→s, and `appAccountToken` parses as a UUID.
  - `refuses_wrong_bundle_id` and `refuses_product_not_configured` → `WrongApp`.
  - `refuses_family_shared` (`inAppOwnershipType` `FAMILY_SHARED`) → `NotPurchased`.
  - `accepts_sandbox_by_default`.
  - `refuses_sandbox_when_only_production`.
  - `refuses_xcode_and_localtesting` → `WrongEnvironment`.
  - `production_notification_requires_app_apple_id` → `WrongApp`.
  - `sandbox_notification_skips_app_apple_id`.
  - `notification_decodes_nested_transaction_and_grace`.
  - `test_notification_has_no_transaction`.
  - `from_env_disabled_without_bundle_id`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
  - Notification fields: `notificationType`, `data.bundleId`, `data.appAppleId`, `data.environment`. `data.signedTransactionInfo` and `data.signedRenewalInfo` are nested JWS, each verified the same way.
  - Transaction fields: `originalTransactionId`, `productId`, `bundleId`, `environment`, `inAppOwnershipType`, `appAccountToken`, `expiresDate`, `revocationDate`, `signedDate`.
- [ ] **Step 4: Run** `cargo test` → PASS. Clippy is clean.
- [ ] **Step 5: Commit** `feat(app-store): decode transactions and V2 notifications with app, ownership and environment checks`.

### Task 3: Storage on existing tables

**Files:**
- Modify:
  - `src/db.rs`.
  - `.claude/rules/dynamodb-schema.md`: record the `appstore` link provider and the `credentials.app_store` map.
  - `docs/DEPLOYMENT_GUIDE.md`: state "no new table or IAM grant", as the Apple-link docs do.
- Test: `db.rs`'s DynamoDB-backed test module (needs `AUTHNZ_TEST_DYNAMODB_ENDPOINT`).

**Interfaces:**
- **The link.** An `identity_links` item with `link_pk = "appstore#<original_transaction_id>"`, `user_id` and `created_at`. It holds no tokens, so the sweep's Apple-token skip doesn't apply.
- **The state.** A `credentials` attribute `app_store` (map). Its key is the otid; its value is `{product_id, environment, expires_at, grace_expires_at?, revoked_at?, last_signed_at}`.
- Produces:
  - `pub struct AppStoreRecord { pub original_transaction_id: String, pub product_id: String, pub environment: Environment, pub expires_at: i64, pub grace_expires_at: Option<i64>, pub revoked_at: Option<i64>, pub last_signed_at: i64 }`.
  - `pub enum LinkOutcome { Bound, AlreadyYours, BoundElsewhere }`.
  - `pub async fn bind_app_store_link(&self, otid: &str, user_id: &Uuid) -> Result<LinkOutcome, DbError>`.
    - A conditional put: `attribute_not_exists(link_pk) OR user_id = :uid`.
    - Then `is_account_live(user_id)`. If the account is not live, delete the link and return `DbError` (the caller answers 401).
  - `pub async fn app_store_link_owner(&self, otid: &str) -> Result<Option<Uuid>, DbError>`: a consistent `GetItem`.
  - `pub enum StateOutcome { Applied, Stale, AccountGone }`.
  - `pub async fn put_app_store_state(&self, user_id: &Uuid, rec: &AppStoreRecord) -> Result<StateOutcome, DbError>`.
    - First ensure the map exists: `SET app_store = :empty`, condition `LIVE_ROW AND attribute_not_exists(app_store)`. Ignore its ConditionalCheckFailed.
    - Then `SET app_store.#otid = :rec`, condition `LIVE_ROW AND (attribute_not_exists(app_store.#otid) OR app_store.#otid.last_signed_at <= :signed)`.
    - DynamoDB rejects overlapping paths in one expression, hence two updates.
    - On a condition failure, a consistent read tells `Stale` from `AccountGone` (no live row).
  - `pub struct PublishingState { pub suspension: Option<PublishingSuspension>, pub app_store: Vec<AppStoreRecord> }`.
  - `pub async fn get_publishing_state(&self, user_id: &Uuid) -> Result<Option<PublishingState>, DbError>`.
    - One `consistent_read(true)` `GetItem` of the `credentials` row, projecting the suspension attributes and `app_store`.
    - `None` means no live row.
    - Keep `get_publishing_suspension` for its other callers, or implement it on top of this.

- [ ] **Step 1: Write failing DynamoDB tests:**
  - `bind_link_new_then_already_yours_then_elsewhere`;
  - `bind_link_for_tombstoned_account_is_removed`;
  - `state_put_creates_map_then_applies`;
  - `state_put_older_signed_is_stale` (record unchanged);
  - `state_put_on_tombstone_is_account_gone`;
  - `publishing_state_returns_suspension_and_records_in_one_read`;
  - `delete_identity_links_of_removes_appstore_links`.
- [ ] **Step 2: Run** `AWS_ENDPOINT_URL_DYNAMODB=http://localhost:8001 bash scripts/dynamodb-local-tables.sh && AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8001 cargo test app_store` → FAIL.
  - Confirm the tests really ran and didn't early-return. Each test asserts on a value it read back, and the run lists them as executed.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same command → PASS. Then run the full `cargo test` with the endpoint set.
- [ ] **Step 5: Commit** `feat(app-store): bind subscriptions via identity_links and keep state on the credentials row`.

### Task 4: `POST /app-store/transactions`

**Files:**
- Modify:
  - `src/authn.rs`: shared helper.
  - `src/app_store.rs`: `transactions_handler`.
  - `src/main.rs`: `.route("/app-store/transactions", post(app_store::transactions_handler))`.
  - `src/app_store_tests.rs`.

**Interfaces:**
- **New shared helper:** `pub(crate) async fn authenticated_live_account(app_state: &AppState, headers: &HeaderMap) -> Result<Uuid, StatusCode>`. It wraps `verify_inbound_account_token`, parses `sub` as a UUID, and calls `is_account_live`; any failure is 401.
  - Leave the two private `extract_authenticated_user_id` copies (`apple_signin.rs`, `patreon.rs`) unchanged. Their consolidation is a follow-up; note it in the PR body.
- Consumes: `decode_transaction`, `bind_app_store_link`, `put_app_store_state`, `is_account_live`.
- **Request:** `X-Auth-Token: <CWT>`, with JSON `{"signed_transaction": "<jws>"}`.
- **Response 200:** `{"active": bool, "expires_at": i64, "environment": "Production"|"Sandbox"}`. The state is read back from the stored record after the write, so grace from earlier notifications counts.
- **Errors:** 401; 403, 409, 422 and 503 per the Rules. A missing `appAccountToken` is 422.
- **Order:** auth → decode → `appAccountToken` rule → bind the link → write the state.
  - `Stale` still answers 200 with the stored state.
  - `AccountGone` answers 401.

- [ ] **Step 1: Write failing handler tests** (using the rcgen root via `AppStoreConfig::for_tests`):
  - `binds_and_reports_active`;
  - `expired_token_is_401`;
  - `deleted_caller_is_401`;
  - `missing_app_account_token_is_422`;
  - `token_for_other_live_account_is_403` (Review Focus 5);
  - `token_for_deleted_account_binds_to_caller`;
  - `second_account_same_otid_is_409`;
  - `bad_signature_is_422`;
  - `feature_off_is_503`;
  - `stale_post_returns_stored_state`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Log one line: `app_store transaction outcome=<bound|stale|elsewhere|refused> otid=<id> env=<env>`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(app-store): POST /app-store/transactions binds a subscription to the caller`.

### Task 5: `POST /app-store/notifications`

**Files:**
- Modify: `src/app_store.rs` (`notifications_handler`), `src/main.rs` (route), `src/app_store_tests.rs`

**Interfaces:**
- Consumes: `decode_notification`, `app_store_link_owner`, `bind_app_store_link`, `put_app_store_state`, `is_account_live`.
- **Request:** JSON `{"signedPayload": "<jws>"}` (Apple's field name). There is no auth header; the only trust is the signature.
- **Responses:**
  - 200 for every verified payload, applied or ignored.
  - 400 for a missing or unparseable body, or a failed verification. Apple retries non-2xx.
  - 503 when the feature is off.
- **Behaviour:**
  - `TEST` → log and answer 200.
  - Otid linked → `put_app_store_state` for the owner.
  - Unlinked and the `appAccountToken` names a live account → bind, then put.
  - Otherwise → log `ignored=unbound` and answer 200.
  - `AccountGone` → log `ignored=account_gone` and answer 200.

- [ ] **Step 1: Write failing tests:**
  - `renewal_extends_expiry`;
  - `refund_sets_revoked_at`;
  - `older_expired_after_newer_renew_is_ignored` (Review Focus 2);
  - `grace_period_is_stored`;
  - `unlinked_with_live_token_binds`;
  - `unlinked_without_live_token_is_dropped`;
  - `notification_after_sweep_writes_nothing` (Review Focus 3);
  - `unverified_payload_is_400`;
  - `empty_body_is_400`;
  - `test_notification_is_200`;
  - `production_wrong_app_apple_id_is_400`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Log `app_store notification type=<t> otid=<id> env=<env> outcome=<applied|stale|bound|ignored>`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(app-store): App Store Server Notifications V2 endpoint`.

### Task 6: Grant at mint, docs, version

**Files:**
- Modify: `src/publishing.rs`, `src/publishing_tests.rs`, `src/account_tests.rs`, `README.md` (endpoint table), `CLAUDE.md` (env table), `docs/creator-publishing-entitlement.md` (two sources, plus lapse and refund behaviour), `Cargo.toml` (0.20.0).

**Interfaces:**
- Consumes: `get_publishing_state`, `AppState.app_store`.
- Produces: `pub(crate) fn app_store_active(cfg: &AppStoreConfig, records: &[AppStoreRecord], now: i64) -> bool`. It is pure, and implements the Active rule.
- **The new `derived_entitlements`.** Remove **both** early returns: when `app_state.publisher` is None, and when there is no snapshot. The logic becomes:
  - `patreon_ok` = config set ∧ snapshot present ∧ `qualifies(..)`;
  - if neither `patreon_ok` nor the App Store config is set → no read, empty result;
  - otherwise do one `get_publishing_state` read, and grant iff (`patreon_ok` ∨ (config set ∧ `app_store_active(state.app_store)`)) ∧ `state.suspension` is none;
  - a read error → empty, with a `warn!` (fails closed).
- The extra read happens only when the App Store feature is configured. That is one consistent `GetItem` on the row the suspension check already reads, and it replaces the suspension read.

- [ ] **Step 1: Write failing tests:**
  - In `publishing_tests`:
    - `app_store_only_member_gets_publish_without_patreon_config_or_snapshot`;
    - `expired_membership_grants_nothing`;
    - `grace_period_still_grants`;
    - `refunded_membership_grants_nothing_at_next_mint` (Review Focus 4);
    - `suspended_app_store_member_grants_nothing`;
    - `patreon_and_app_store_member_gets_one_fqn`;
    - `sandbox_record_ignored_when_only_production_configured`;
    - `state_read_error_fails_closed`;
    - `neither_source_configured_does_no_read`.
  - In `account_tests`: `sweep_frees_the_subscription_for_another_account`.
- [ ] **Step 2: Run** with the DynamoDB endpoint → FAIL.
- [ ] **Step 3: Implement.** Update the docs and the version.
- [ ] **Step 4: Run** `AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8001 cargo test`, then `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` → all green.
- [ ] **Step 5: Commit** `feat(publishing): App Store Creator Membership grants the publishing entitlement`.

## Ops (not code; for the PR body)

- **`production/start.sh`:** add `APP_STORE_BUNDLE_ID=com.arkavo.ArkavoCreator`, `APP_STORE_APP_APPLE_ID=6738845556` and `APP_STORE_PUBLISH_PRODUCT_IDS=com.arkavo.ArkavoCreator.membership.monthly`. `APP_STORE_ENVIRONMENTS` stays at its default.
- **App Store Connect → App Information → App Store Server Notifications:** Version 2, with the Production and Sandbox URLs both `https://identity.arkavo.net/app-store/notifications`.
- **Verify after deploy:** `POST /app-store/notifications` with `{}` answers 400, not 404.
