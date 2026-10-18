# Name-free passkey sign-in (identity server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `GET /authenticate/:username` with a name-free passkey sign-in (`GET /authenticate`) and an account-scoped re-authentication (`GET /authenticate?account=<uuid>`). Both are finished by `POST /authenticate`, which now also returns the account's alias.

**Architecture:**
- The session key `"auth_state"` holds a `PendingAuthentication` enum:
  - **Discoverable:** webauthn-rs `DiscoverableAuthentication`, plus the inbound `X-Auth-Token` subject.
  - **Account:** `PasskeyAuthentication` for one account UUID.
- `finish_authentication` branches on that enum.
- The discoverable branch identifies the account from the assertion's user handle, which is the account UUID that registration has always used.

**Tech Stack:** Rust 2024, axum, tower-sessions, webauthn-rs 0.5.5 (adds the `conditional-ui` feature), DynamoDB Local for tests, and webauthn-authenticator-rs `SoftPasskey`.

**Spec:** `docs/superpowers/specs/2026-10-17-passkey-sign-in-design.md`

## Global Constraints

- `Cargo.toml`: `webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation", "conditional-ui"] }`.
- **Routes after this plan:**
  - `GET /authenticate`, with optional query `account=<UUID>`.
  - `POST /authenticate`.
  - `GET /authenticate/:username` no longer exists, and a request to it answers 404.
- **POST success:** 200 `{"token": "<CWT>", "handle": "<record.username>"}`.
- **POST ceremony-verification failure:** 400 `{"token": ""}`, the same body as today with no `handle` key.
- **Errors:**

  | Case | Variant | Status | Body |
  |---|---|---|---|
  | Account-scoped start for a missing or tombstoned account | `UserNotFound` | 500 | `User Not Found` (unchanged; ArkavoKit maps this text to `.alreadyDeleted`) |
  | Discoverable finish: user handle with no live account, or credential id not in that account's record | new `UnknownPasskey` | 404 | `Unknown Passkey` |
  | Discoverable finish: start carried a valid `X-Auth-Token` whose `sub` is not the identified account | new `PasskeyAccountMismatch` | 403 | `Passkey belongs to another account` |
  | Discoverable finish: user handle missing or not a 16-byte UUID | none (ceremony failure) | 400 | `{"token": ""}` |

- **The token mint is unchanged:**
  - `oidc::AuthenticatedUser::webauthn(record.user_id, record.entitlements)`
  - then `oidc::arkavo_user_claims`
  - then `mint_auth_token(&app_state, &user_id, Some(&arkavo_user), None)`.
- Keep today's ordering: read the DynamoDB record before removing `"auth_state"`, so a transient DynamoDB error leaves the state for a retried POST.
- Never log a token, a challenge or an assertion body.
- **DynamoDB-backed tests return early and pass when `AUTHNZ_TEST_DYNAMODB_ENDPOINT` is unset.**
  - A run without it proves nothing.
  - Every verification step below runs with DynamoDB Local up and the variable set.
  - The run must show the new tests executing, not just compiling.

## Review Focus

1. **A deleted account's passkey is picked.** The answer is 404 `Unknown Passkey` and nothing is minted. Test `a_passkey_of_a_deleted_account_is_an_unknown_passkey` (Task 1).
2. **A passkey from one account is used against an account-scoped start for another.** The ceremony fails with 400 and nothing is minted. Test `an_account_scoped_start_refuses_another_accounts_passkey` (Task 2).
3. **A replayed POST after a successful sign-in** answers 500 `Corrupt Session`, so a second token is never minted. Test `a_replayed_finish_mints_nothing` (Task 1).
4. **The start's `X-Auth-Token` names account A, and B's passkey answers.** The answer is 403. Test `an_inbound_token_for_another_account_is_refused_at_finish` (Task 1).
5. **The old named route** answers 404 after the cutover. Test `the_named_route_is_gone` (Task 2).

---

### Task 1: Name-free sign-in

**Files:**
- Modify: `Cargo.toml`, the `webauthn-rs` features.
- Modify: `src/authn.rs`:
  - `start_authentication` (currently 469-538);
  - `finish_authentication` (541-598);
  - `AuthResponse` (~600);
  - `WebauthnError` (728-773) and its `IntoResponse` (775-860).
- Modify: `src/main.rs`, the routes at 706-707 (add `GET /authenticate`).
- Modify: `src/registration_gate_tests.rs`:
  - `ceremony_router` (269) gains `.route("/authenticate", get(crate::authn::start_authentication).post(crate::authn::finish_authentication))`;
  - `ceremony_router`, `Ceremony` and its methods become `pub(super)`.
- Create: `src/authentication_tests.rs`, declared in `src/main.rs` next to `mod registration_gate_tests;` (77) as `#[cfg(test)] mod authentication_tests;`.

**Interfaces:**
- Produces:
  - `pub struct AuthenticateQuery { pub account: Option<uuid::Uuid> }` (`Deserialize`).
  - `pub async fn start_authentication(Extension(app_state): Extension<AppState>, session: Session, Query(query): Query<AuthenticateQuery>, headers: HeaderMap) -> Result<impl IntoResponse, WebauthnError>`.
    - This task handles only `query.account == None`. `Some` stays unimplemented until Task 2 and answers `WebauthnError::Unknown`.
    - The old `Path(username)` handler is renamed `start_named_authentication` and keeps its route until Task 2. It now stores `PendingAuthentication::Account`.
  - `#[derive(Serialize, Deserialize)] pub(crate) enum PendingAuthentication`, with variants:
    - `Discoverable { state: DiscoverableAuthentication, inbound_user_id: Option<Uuid> }`
    - `Account { user_id: Uuid, state: PasskeyAuthentication }`
  - `AuthResponse { token: String, #[serde(skip_serializing_if = "String::is_empty")] handle: String }`.
  - New `WebauthnError` variants: `UnknownPasskey` and `PasskeyAccountMismatch`, mapped as in Global Constraints.
- Test helpers in `src/authentication_tests.rs`, used by Task 2:
  - `async fn registered_account(username: &str) -> Option<(Ceremony, WebauthnAuthenticator<SoftPasskey>, Uuid, Base64UrlSafeData)>`:
    - It registers through the ticketed `Ceremony`, keeping the same `SoftPasskey` instance.
    - It returns the session, the authenticator, the account UUID (from `store.get_user_by_name`) and the credential id (the registration's `raw_id`).
    - It returns `None` without DynamoDB Local.
  - `fn answer_discoverable(auth: &mut WebauthnAuthenticator<SoftPasskey>, options: RequestChallengeResponse, credential_id: &Base64UrlSafeData, user_handle: Option<Uuid>) -> PublicKeyCredential`:
    - `SoftPasskey` cannot answer an empty allow-list and never returns a user handle. So the helper copies `options`, sets `public_key.allow_credentials` to that one credential and `mediation` to `None`, and runs `do_authentication(Url::parse("https://identity.arkavo.net"), …)`.
    - It then sets `response.user_handle` to the UUID's 16 bytes. WebAuthn does not sign the user handle, so this is a faithful discoverable assertion.

- [ ] **Step 1: Write the failing tests** in `src/authentication_tests.rs`. Each `#[tokio::test]` starts `let Some((c, mut auth, user_id, cred)) = registered_account(&unique_name()).await else { return; };`.
  - `a_name_free_sign_in_returns_the_token_and_the_handle`:
    - `GET /authenticate` gives 200, and the options' `allowCredentials` is empty.
    - POST of `answer_discoverable(…, Some(user_id))` gives 200.
    - The body's `handle` equals the registered username.
    - The body's `token` verifies with `crate::cwt::verify` and has `sub == user_id.to_string()`.
  - `a_passkey_of_a_deleted_account_is_an_unknown_passkey`: after `GET`, tombstone the account as `DELETE /account` does, then POST. Expect 404 with body `Unknown Passkey`. Tombstone with `store.tombstone_account(&user_id, &format!("{user_id}.{}", "a".repeat(32)), None, 1)`, as `src/apple_tokens_tests.rs:591` does.
  - `a_credential_missing_from_the_account_is_an_unknown_passkey`: answer with the right user handle but a credential id from a second registered account. Expect 404 `Unknown Passkey`.
  - `a_missing_user_handle_fails_the_ceremony`: `user_handle: None`. Expect 400 with body `{"token":""}`.
  - `an_inbound_token_for_another_account_is_refused_at_finish`:
    - Register A and B.
    - `GET /authenticate` with `X-Auth-Token: <A's registration token>` (the `X-Auth-Token` response header of A's `POST /register`).
    - Answer with B's passkey. Expect 403 `Passkey belongs to another account`.
  - `a_replayed_finish_mints_nothing`: POST the same successful assertion twice. The second answers 500 `Corrupt Session`.
- [ ] **Step 2: Run them to verify they fail.**
  - `docker run -d --rm -p 8001:8000 amazon/dynamodb-local`
  - `AWS_ENDPOINT_URL_DYNAMODB=http://localhost:8001 bash scripts/dynamodb-local-tables.sh`
  - `AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8001 cargo test authentication_tests -- --nocapture`

  Use port 8000 if it is free; 8001 avoids a clash seen locally. Expect a FAIL: a compile error on `AuthenticateQuery` or the missing route, then the assertions.
- [ ] **Step 3: Implement.**
  - Enable `conditional-ui`.
  - **Name-free start:** remove any old `"auth_state"`. Read the optional `X-Auth-Token` exactly as today into `inbound_user_id`. Call `webauthn.start_discoverable_authentication()`, store `PendingAuthentication::Discoverable`, and return `Json(rcr)`.
  - **Finish, `Discoverable` arm:**
    1. `identify_discoverable_authentication(&auth)`. An error gives the 400 empty-token reply.
    2. If `inbound_user_id` is `Some(id)` and `id != user_handle`, return `PasskeyAccountMismatch`.
    3. `get_user_by_id`. `None` means remove `"auth_state"` and return `UnknownPasskey`.
    4. If the credential id is not among `record.credentials`, remove `"auth_state"` and return `UnknownPasskey`.
    5. Remove `"auth_state"`.
    6. `finish_discoverable_authentication(&auth, state, &record.credentials.iter().map(DiscoverableKey::from).collect::<Vec<_>>())`.
    7. Mint as today, and reply with `handle = record.username`.
  - **Finish, `Account` arm:** today's flow, with the reply gaining `handle`.
- [ ] **Step 4: Run the tests to verify they pass.** Same command as Step 2. Expect all 6 to pass, with `--nocapture` output showing they ran (no early return). Also run `cargo test`: the existing suites stay green.
- [ ] **Step 5: Commit.** `git commit -m "feat(authn): name-free passkey sign-in returns the account's handle"`

### Task 2: Account-scoped re-authentication; remove the named route

**Files:**
- Modify: `src/authn.rs` (`start_authentication`'s `Some(account)` arm; delete `start_named_authentication`).
- Modify: `src/main.rs`: delete the `/authenticate/:username` route and its import.
- Modify: `README.md` (the curl examples at 93 and 97) and `CLAUDE.md` (70-71, 460, 470, 475), so they describe `GET /authenticate[?account=<uuid>]` and the `{token, handle}` reply.
- Test: `src/authentication_tests.rs`.

**Interfaces:**
- Consumes: Task 1's `PendingAuthentication::Account`, `AuthenticateQuery`, `registered_account` and `answer_discoverable`.
- Produces: `GET /authenticate?account=<uuid>`, whose options list only that account's credentials. A missing or tombstoned account answers `UserNotFound`. ArkavoKit's plan relies on both.

- [ ] **Step 1: Write the failing tests.**
  - `an_account_scoped_start_lists_only_that_accounts_passkeys`: `GET /authenticate?account=<A>` gives 200, and `allowCredentials` equals exactly A's credential id. Answering with A's passkey (`answer_discoverable` with A's id; the user handle is optional here) gives 200 with A's handle.
  - `an_account_scoped_start_refuses_another_accounts_passkey`: start for A, answer with B's passkey. Expect 400 `{"token":""}`.
  - `an_account_scoped_start_for_a_deleted_account_is_user_not_found`: tombstone A (the same `tombstone_account` call as in Task 1), then `GET /authenticate?account=<A>` answers 500 `User Not Found`.
  - `an_inbound_token_for_another_account_is_refused_at_an_account_scoped_start`: start for A with B's `X-Auth-Token`. Expect 500 `User Not Found`, the same behaviour the named start had.
  - `the_named_route_is_gone`: `GET /authenticate/<A's username>` gives 404.
- [ ] **Step 2: Run to verify they fail.** Same command as Task 1 Step 2. Expect a FAIL.
- [ ] **Step 3: Implement.** The `Some(account)` arm is today's named start keyed by `get_user_by_id(&account)`, not by name:
  - The same `X-Auth-Token` check (a mismatch gives `UserNotFound`).
  - `UserHasNoCredentials`.
  - `start_passkey_authentication(&record.credentials)`.
  - Store `PendingAuthentication::Account`.

  Delete the named handler and its route. Update README and CLAUDE.md.
- [ ] **Step 4: Run.** `AUTHNZ_TEST_DYNAMODB_ENDPOINT=http://localhost:8001 cargo test`. Expect everything to pass, with the 11 authentication tests shown running. Then `cargo build --release`, which must succeed.
- [ ] **Step 5: Commit.** `git commit -m "feat(authn)!: account-scoped re-authentication replaces sign-in by name"`
