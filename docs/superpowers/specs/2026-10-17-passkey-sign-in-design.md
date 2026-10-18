# Sign in with Passkey (no alias) — design

## Intent

Signing in to Arkavo should be one button: **Sign in with Passkey**. The
system passkey sheet lists every Arkavo passkey the device holds, the person
picks one, and they are signed in. Nobody types an alias to sign in.

Why now: typing the alias let the Mac's Arkavo Creator sit signed in to the
wrong account without anyone noticing. On 2026-10-17 the Mac's session was
account `f120a83b…`, which has no Patreon link, while the creator's account
was in use on the iPhone. The platform correctly refused that session a KAS
rewrap, and it took a token diagnostic to see why. A picker that lists the
device's accounts by name makes the choice visible.

## What the owner decided

- The signed-out screen in both apps (Arkavo Creator on macOS, Arkavo on iOS)
  shows a **Sign in with Passkey** button. Tapping it presents the system
  passkey sheet with every Arkavo passkey on the device (several if there are
  several). Pick one and you are signed in. Owner's words: "Sign in with
  Passkey button, pick account, done."
- The alias field stays, but only for creating an account ("New? Create
  account").
- Hard cutover: the server's sign-in-by-alias endpoint is removed, not kept
  alongside. We are pre-release.

## Goals

1. **Identity server (authnz-rs):** a name-free passkey sign-in. The ceremony
   starts without an account, and the server identifies the account from the
   passkey the person picked. The person ends up with the same one-hour auth
   CWT that sign-in mints today, with the same claims.
2. **Remove** `GET /authenticate/:username`.
3. **ArkavoKit (`ArkavoSocial.ArkavoClient`):** a name-free sign-in replaces
   `connect(accountName:)`'s ceremony. The client learns the account's alias
   from the server's reply and stores it as it does today
   (`KeychainManager.saveArkavoHandle`).
4. **Arkavo Creator (macOS) and Arkavo (iOS):** the signed-out form's alias
   field and "Sign in" button are replaced by **Sign in with Passkey**. Create
   account keeps its alias field.

## Non-goals

- Account creation (alias + passkey registration, the App Attest ticket gate)
  is unchanged.
- Sign in with Apple, Google sign-in, the OIDC endpoints, and the Patreon link
  are unchanged.
- The session after sign-in is unchanged: a cached token still signs in
  without a prompt (ArkavoKit's fast path), and Sign out still clears it.
- No change to token contents, lifetimes or the platform.

## Anti-goals

- No sign-in path that falls back to typing an alias.
- No state that survives a cancelled sheet. Cancelling leaves the person
  signed out, with nothing half-done.

## Facts the design rests on (verified)

- **The server signs in by alias only.** It has `GET /authenticate/:username`
  (`src/main.rs:706`), which looks the user up by name and calls
  `webauthn.start_passkey_authentication(&credentials)`, and
  `POST /authenticate` (`finish_authentication`, `src/authn.rs`), which reads
  `(user_id, PasskeyAuthentication)` from the session.
- **The library supports name-free sign-in.** webauthn-rs 0.5.5 provides
  `start_discoverable_authentication`, `identify_discoverable_authentication`
  and `finish_discoverable_authentication` behind its `conditional-ui` cargo
  feature. Today `Cargo.toml` enables only `danger-allow-state-serialisation`.
- **Existing passkeys already work.** Registration passes the account's UUID
  as the WebAuthn user handle
  (`start_passkey_registration(user.user_id, &username, &username, …)`), so a
  picked passkey's `userHandle` is the account UUID. `get_user_by_id` exists.
  Apple passkeys (iCloud Keychain) are discoverable, so nobody needs to
  re-create one.
- **The client already sends the user handle.** ArkavoKit's assertion request
  restricts the sheet to the server-listed credentials
  (`passkeyAssertionRequest(…, allowCredentialIDs:)`). An empty list leaves
  the sheet open to every passkey for the relying party. The finish body
  already carries `response.userHandle`.
- **The apps need the alias after sign-in.** Creator derives the creator
  identity from it (`ArkavoIdentity.publicID(for:)` is SHA-256 of the raw
  alias, and it feeds the stream path). Account deletion takes it
  (`deleteAccount(accountName:)`), and both Account screens show it. The auth
  token carries `sub` (the UUID) but not the alias. So the sign-in reply must
  return it.
- **The hard cutover has these callers:**
  - ArkavoKit `ArkavoClient.authenticateUser(accountName:)`, which serves
    Creator and arkavo-ios. It is reached from two places:
    - `connect(accountName:)`, which is sign-in.
    - `deleteAccount(accountName:)`, through the `authenticator` seam in
      `freshDeletionToken`. This is the fresh re-authentication that
      Creator's in-app deletion requires (App Store 5.1.1(v)). It also
      detects `.alreadyDeleted` from the route's "User Not Found".
      arkavo-ios's production deleter is a stub (`UnavailableAccountDeleter`),
      so only Creator uses it.
  - The legacy `arkavo-org/app` (`Arkavo/Arkavo/AuthenticationManager.swift`
    and its vendored ArkavoKit; last commit 2026-08-26).

  Nothing else in the workspace calls it: arkavo-rs, arkavo-edge,
  arkavo-node, arkavo-agent and the identity web pages were checked.
- **Two flows re-authenticate an account the app already knows:**
  - **Account deletion.** CRE-267 limits the sheet to the passkeys of the
    account the dialog named. `DELETE /account` deletes whichever account the
    token's `sub` names, so a sheet that lists every passkey would let the
    person delete a different account from the one they confirmed.
  - **Creator's Edge OAuth broker.** `EdgeOAuthBroker` sets `accountHandle`
    before `reauthenticate`, and the consent sheet's "Account" row shows that
    value (CRE-193).

  `verify_inbound_account_token` enforces `exp`, so an expired session token
  cannot scope the re-authentication on the server.

## Design

### Server (authnz-rs)

- Enable webauthn-rs's `conditional-ui` feature.
- `GET /authenticate` (no path parameter) calls
  `start_discoverable_authentication()`, stores the `DiscoverableAuthentication`
  state in the session, and returns the request options. The options carry
  no allow-credentials list.
- `POST /authenticate` finishes it:
  1. `identify_discoverable_authentication` gives the account UUID.
  2. `get_user_by_id` loads the record.
  3. `finish_discoverable_authentication` runs against that record's
     credentials (as `DiscoverableKey`s).
  4. The token is minted exactly as today: `oidc::arkavo_user_claims`, then
     `mint_auth_token`.
- The reply becomes `{"token": …, "handle": <the account's alias>}`.
- The ordering rule in today's `finish_authentication` stays: read the record
  before consuming the session state, so a transient DynamoDB error lets the
  client retry the POST.
- **Re-authentication of a known account** *(my call; the owner can
  veto)*:
  - `GET /authenticate?account=<account UUID>` starts a ceremony limited to
    that account's credentials, as the alias route does today, but keyed by
    the account's UUID.
  - It answers "User Not Found" for an account that no longer exists.
  - `POST /authenticate` finishes it, and also refuses an assertion whose
    user handle is not that account.

  The app never asks a person for this identifier. ArkavoKit reads it from
  the stored token's `sub`, which needs no signature check, because the
  passkey proves control. It exists only so deletion and the broker
  re-authenticate the account they named. It is not a sign-in path.
- `GET /authenticate/:username` is deleted. A request to it is no longer
  routed (404).
- Update README and CLAUDE.md, which document the routes.

### ArkavoKit

- `connect(accountName:)` becomes name-free (pre-release API break, matching
  the hard cutover).
  - Its fast path is unchanged.
  - Its ceremony branch fetches `GET /authenticate` and presents the
    assertion request with no allowed credentials.
  - It posts the assertion, then saves both the token and the returned alias
    (`saveArkavoHandle`).
- **Account deletion** keeps its behaviour:
  - `freshDeletionToken` re-authenticates through the account-scoped start,
    using the UUID from the stored token's `sub`.
  - The sheet shows only that account's passkeys (CRE-267 holds).
  - "User Not Found" still maps to `.alreadyDeleted`.
  - With no stored token there is no UUID. Deletion then needs a sign-in
    first, which is the same as being signed out today.
- `registerUser(handle:did:)` is unchanged.
- Ship as a new ArkavoKit minor release.

### Apps

- **Arkavo Creator** (`ContentView.swift` Dashboard Arkavo card,
  `ArkavoAuthState`):
  - The signed-out card shows **Sign in with Passkey** in place of the
    "Account name" field and "Sign in".
  - "New? Create account" reveals the alias field and the existing create
    flow.
  - After sign-in, `accountName` is the alias the server returned.
  - **Edge OAuth broker** *(my call)*:
    - With a known account, `reauthenticate` uses the account-scoped
      ceremony. The consent sheet's "Account" row stays true, and a person
      cannot approve for one account while the sheet names another (CRE-193).
    - With no known account (CRE-155's no-handle branch), the broker starts
      the name-free sign-in itself instead of expanding a sign-in form. The
      consent sheet then shows the account picked.
- **Arkavo iOS** (`AccountView.swift`, `AccountAuthModel`): the same change to
  the Account tab's signed-out form.
- Copy and styling follow each app's design system (Creator's
  `DesignSystem.swift`, the iOS `DS`).

## Rollout (hard cutover)

1. Merge authnz-rs, then ArkavoKit (release), then Creator and arkavo-ios on
   the new ArkavoKit.
2. Deploy identity.
3. Ship app builds (Creator `1.1-beta.N` tag; arkavo-ios TestFlight).

Between the identity deploy and the person installing the new build,
sign-in fails on older builds and on the legacy app. A session cached in the
Keychain keeps working until its token expires. The owner accepted that
window by choosing the hard cutover. As of 2026-10-17, no Creator or Arkavo
build is in App Review or about to be submitted (owner), so the identity
deploy need not wait on an App Review approval.

## Edge cases the builder must handle

- **The picked passkey's account no longer exists** (the account was deleted
  and the passkey stayed in iCloud Keychain). The server refuses, and the app
  says the account for that passkey no longer exists. It must not hang and
  must not show raw server text.
- **The person cancels the sheet.** They stay signed out with no error
  banner. Today's cancellation handling applies.
- **The device has no Arkavo passkey.** The system sheet offers a passkey from
  another device (QR code). We add nothing.
- **The same account has passkeys on several devices.** The sheet may list
  it more than once, and any of them works.
- **A stale cached token.** The fast path fails, and the name-free ceremony
  runs.
- **The session cookie is lost between GET and POST.** The server reports a
  corrupt session, and the client fails that attempt cleanly. A second tap
  starts over.

## Specs and records to revise first (each repo's own rules)

- **Creator:**
  - `specs/edge-oauth.spec.yaml`: the Arkavo session lifecycle, CRE-155 and
    CRE-193.
  - `specs/arkavo-account.spec.yaml`: CRE-267's scoped deletion
    re-authentication is kept, and its refs move to the account-scoped
    start.
  - Revise the spec, then the tests, then the code (CLAUDE.md).
- **arkavo-ios:**
  - `specs/auth.spec.yaml` (the sign-in scenario uses the `account.handle`
    field) and `specs/design-system.spec.yaml` (the signed-out form).
  - A new ADR that supersedes ADR-0030's alias sign-in.
- **authnz-rs:** README and CLAUDE.md route lists, plus server tests for the
  new routes. The webauthn-authenticator-rs softpasskey is already a
  dev-dependency.

## Left to the builder

The endpoint handler names, the session key name, error enums, test
structure, the ArkavoKit version number, exact button copy within each
design system, and how the iOS and Creator view models are restructured.
