---
paths:
  - "src/authn.rs"
  - "src/authentication_tests.rs"
  - "src/registration_gate_tests.rs"
---

# Passkey registration and sign-in

## authn.rs: WebAuthn authentication flow

- `start_register`: Initiates passkey registration with DID validation
- `finish_register`: Completes registration, stores credential, issues CWT
- `start_authentication`: Initiates passkey authentication (`GET /authenticate[?account=<uuid>]`); name-free without `account`, limited to that account's passkeys with it
- `finish_authentication`: Verifies authentication, issues CWT; replies `{token, handle}`
- Account token generation with 99-year registration tokens (~5148 weeks)
- Authentication tokens expire in 1 hour
- Uses attestation envelope with ECDSA signature for registration response

## Registration Flow

- **Requires a verified App Attest registration ticket in the session**
  (`GET /device-check/register-challenge` → `POST /device-check/register-attest`).
  Checked before any lookup, so an unattested caller cannot probe which handles
  exist (HTTP 403 otherwise). `finish_register` re-checks it, charges the
  `device_attest_keys` budget, and removes it: one attestation, one account.
- Client requests `/register/:username?handle=...&did=...`
- Validates DID format and handle consistency
- **The handle is permanent; the username is a changeable label** (owner
  decision 2026-11-03, #132). The handle `<username>.arkavo.social` is
  stored on the `credentials` row at `create_user` (`handle`; a row from
  before 0.27.1 reads as `<username>.arkavo.social`), and every reader
  uses `UserCredentials::handle` (deletion, webvh `alsoKnownAs`, the
  `prod-handles` row), never re-deriving it from the username
- **A handle is never issued twice.** A new username (no live user row) is
  refused with 409 `Username is not available` when its handle already has
  a `handles` row of any kind: retired by a deletion, another account's, or
  a legacy seed. Checked after the ticket and before `create_user`, so a
  refused registrant leaves no row. So a deleted account's username is not
  registrable again until registration can issue a handle different from
  the username
- Legacy DIDs embed the username (`dids:<username>`). Since 0.39.0
  `/dids/:id/…` resolves a legacy name path through the permanent handle
  row, never the current username (`.claude/rules/webvh.md`). A rename
  must still first persist `handle` on rows from before 0.27.1, whose
  `handle` is otherwise read back from the username
- A passkey sign-in calls `webvh::refresh_handle_binding` before minting
  its token (non-fatal; `.claude/rules/webvh.md`)
- Rejects the `apple-` / `google-` username namespace (HTTP 403): those rows
  are IdP-provisioned with zero credentials, and the zero-credential
  exemption below would otherwise let anyone knowing the IdP `sub` enroll a
  passkey onto a federated account
- Adding a passkey to an account that already has one requires an
  `X-Auth-Token` CWT minted within `ENROLLMENT_TOKEN_MAX_AGE_SECONDS`
  (5 min) — i.e. fresh proof of control from `POST /authenticate`, not any
  still-valid long-lived registration token (HTTP 401 otherwise)
- Creates user in DynamoDB with retry logic (max 3 retries)
- Generates WebAuthn challenge and stores registration state in session
- Client completes WebAuthn ceremony
- Server verifies registration via `/register` POST
- Stores credential in DynamoDB
- Returns attestation envelope (signed with ECDSA) + CWT in X-Auth-Token header (COSE_Sign1, ES256)

## Authentication Flow

- `GET /authenticate` starts a name-free ceremony: it reads no record and lists no credentials, and the passkey's user handle names the account at the finish. The reply includes `"mediation":"conditional"` (webauthn-rs forces it), a browser-autofill hint native clients ignore
- `GET /authenticate?account=<uuid>` limits the ceremony to that account's passkeys (re-authentication). Only this start retrieves the account's credentials from DB (authoritative — no token-embedded fallback); a missing or tombstoned account answers 500 `User Not Found`, one with no passkey 500 `User Has No Credentials`, and a malformed `account` gets axum's query rejection (400 `Failed to deserialize query string: …`). There is no `/authenticate/:username` route
- Both starts generate a WebAuthn challenge, store the ceremony (`PendingAuthentication`) as `auth_state` in the session, and set the session cookie the POST must carry
- Client may send a CWT in X-Auth-Token; the server verifies it (exp/iat enforced with ±60s skew). An expired or invalid token refuses the start with 401 `CWT error: …`. A valid token for another account is refused (500 `User Not Found` at an account-scoped start, 403 `Passkey belongs to another account` at a name-free finish). Clients should not forward a cached token to the name-free start (a stale one refuses the start meant to replace it), and must not forward one to `?account=` (a token for another account there answers 500 `User Not Found`, which ArkavoKit reads as "already deleted")
- Client completes the WebAuthn ceremony and POSTs the `PublicKeyCredential` (not a `{"challenge": …}` object) to `/authenticate`
- `POST /authenticate` outcomes, status and exact body:
  - 200 `{"token":"<CWT>","handle":"<username>"}`: verified; the CWT expires in 1 hour. It always carries `arkavo_apple_linked` (CBOR bool, `true` or `false`, never omitted; `UserCredentials::apple_linked`): Creator offers "Unlink Apple" from it on every Mac. `passkey_auth_claims` requires it, so a new passkey mint cannot leave it out. The registration token carries it too (its value at mint), unless the row could not be read
  - 400 `{"token":""}`: ceremony failure. The assertion did not verify (challenge, signature, origin, user verification, a credential the scoped start did not list); a name-free assertion's user handle is missing or not a 16-byte UUID; or a scoped assertion carries a user handle that is not the account's UUID (`finish_account_authentication` checks this itself: webauthn-rs's scoped finish ignores the user handle, which is not signed)
  - 404 `Unknown Passkey`: name-free only. The user handle names no live account, or the account does not hold that credential id. Decided before the signature check, and it carries no account data. ArkavoKit removes the passkey from the device on it, so the body must not change
  - 403 `Passkey belongs to another account`: name-free only, the X-Auth-Token mismatch above; also decided before the signature check
  - 500 `Corrupt Session`: the session holds no open ceremony (no start, a lost cookie, or a finished ceremony such as a replayed POST)
  - 500 `User Not Found`: account-scoped only; the account was deleted between start and finish. ArkavoKit maps this text to `.alreadyDeleted`, so it must not change
  - A DynamoDB error answers 500 `Database operation failed: …` and leaves the ceremony open (the record is read before `auth_state` is removed), so the client can retry the POST
- The name-free start uses webauthn-rs's `allow_backup_eligible_upgrade = false`; the scoped start uses `true`. Neither finish saves the `AuthenticationResult` credential update (counter, backup state). So a passkey stored as not backup-eligible that now reports backup eligibility fails every name-free finish with 400 while the scoped one accepts it, and clone detection compares against the counter stored at registration
