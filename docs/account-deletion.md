# Account deletion

Issue [#88](https://github.com/arkavo-org/authnz-rs/issues/88) (App Store
guideline 5.1.1(v)). Code: `src/account.rs`, `src/db/account.rs`.

## Request

```
DELETE /account
X-Auth-Token: <passkey auth CWT>
```

- The token must be the CWT returned by `POST /authenticate`, minted **within
  the last 300 seconds**. The app runs a fresh passkey assertion immediately
  before asking. The long-lived registration token, OIDC access tokens and
  older auth tokens are refused.
- **202 Accepted** on success and on every retry:

  ```json
  {
    "deletion_id": "3f2c…-…-….9a1b4c…",
    "status": "pending",
    "requested_at": 1791200000,
    "completes_by": 1791200300
  }
  ```

  A retry (network failure, double tap) with any fresh auth token for the same
  account returns the same `deletion_id`. Persist it before showing success.
- **401** `{"error": "unauthorized", …}`: no token, an invalid or stale one, or
  an account that does not exist. The app re-authenticates and retries; if the
  account was already deleted, sign-in fails and there is nothing left to
  delete.
- **409**: a concurrent change raced the deletion; retry.

## Status

```
GET /account/deletions/<deletion_id>
```

No token: the account's tokens no longer work. The `deletion_id` is the
credential (128 random bits), so keep it private.

- **200** `{deletion_id, status, requested_at, completes_by, completed_at?}`
  - `pending`: the account is deleted; the data bound to it is still being
    removed.
  - `completed`: everything is removed.
  - `failed`: the remaining cleanup stopped. Either it ran out of retries, or
    it hit a problem that retrying cannot fix. The permanent causes all concern
    the Sign in with Apple tokens, which are revoked last: Apple refused a
    revocation (a 4xx other than 429, which means a server configuration
    problem: key, client id or secret), the account has stored tokens but the
    server has no revocation configured, or a stored token row is unreadable.
    In each case the account itself is deleted and stays deleted, and every
    other datum is already removed; only the sealed Apple tokens remain. The
    server retries at its next restart, once an operator has fixed the problem,
    and logs the failure. Tell the person their account is deleted and the
    remaining cleanup is in progress.
- **404**: unknown id.

## What happens, and when

**Immediately** (before the 202 returns):

- The account record is deleted: passkeys, username, DID and DID log
  (`/dids/<username>/did.json` and `did.jsonl` return 404), entitlements, and
  any moderation record.
- The handle `<username>.arkavo.social` is released.
- **Every token the account holds stops working**, in every app, whatever its
  expiry: the long-lived registration token, auth tokens, OIDC access and
  refresh tokens, and agent credentials. The account's agent delegations are
  revoked in the same request, and the agent status the platform checks
  (`GET /agents/:did/status`) refuses any agent whose owner is deleted, so an
  agent token minted before the deletion stops working too.
- The username can be registered again by anyone. A new registrant gets a new
  account id and a new DID; nothing of the old account carries over.

**Within 5 minutes** (`completes_by`; normally about 1 minute):

- App Attest device bindings, and every Apple, Google and Patreon identity
  link, are deleted. Each of those identities can be linked to another
  account afterwards.
- The server-held Patreon access and refresh tokens are deleted with the key
  that encrypted them. Patreon has no token-revocation endpoint, so the
  authorization also remains listed on the person's Patreon account until
  they remove Arkavo under Patreon's connected apps.
- Guardians the account set up are revoked, and the labels of its agents and
  Guardians and the owner's username are erased. The revoked records stay,
  holding only the agent's or Guardian's public key, so those keys can never
  be reused to impersonate a fresh identity.
- **Sign in with Apple** (last, after everything above): for every Apple ID
  the account linked with an authorization code, the server revokes the
  refresh token it holds at Apple, then deletes it. Revocation removes the
  app from the person's Apple Account → Sign in with Apple list (TN3194).
  A link made before the server held tokens (no authorization code) is
  removed without a revocation. The app should tell the person they can
  remove it in their Apple Account settings.

**Kept:** a tombstone holding the random account id, the deletion id, its
status and timestamps. It holds no personal data; it is what makes the
account's old tokens fail and what the status endpoint reads. App Attest
registration counters (keyed by device key, not by account) are kept for abuse
prevention.

## Sign in with Apple links

So that the server has an Apple token to revoke when the account is deleted,
an app that links Sign in with Apple sends the ceremony's authorization code
with the id_token:

```
POST /oauth/apple/link
X-Auth-Token: <Arkavo CWT>
{"id_token": "<Apple id_token>", "authorization_code": "<UTF-8 of credential.authorizationCode>"}
```

When the server has token revocation configured:

- **200**: linked, and the token is kept for revocation. Linking the same
  Apple ID again replaces the stored token and does not revoke the old one:
  Apple's revoke ends the whole authorization, and account deletion revokes
  it.
- **400** `authorization_code_required`: the code is missing or empty.
  Nothing is stored. The request used up the session nonce, so a retry is a
  new ceremony (`GET /oauth/apple/nonce`, then a new code). A build that does
  not send the code cannot link Apple.
- **401** `apple_token_binding_mismatch`: the id_token Apple returned for the
  code could not be verified as this Apple ID in this ceremony (another Apple
  ID, another ceremony, audience or signature). The token Apple issued is
  revoked, and nothing is stored.
- **401** `Invalid X-Auth-Token`: among the other auth failures, the Arkavo
  account does not exist, also when it was deleted while the link was in
  flight. A token already exchanged for the code is revoked, and the link
  goes with the account.
- **409**: that Apple ID is linked to another Arkavo account. Nothing is
  stored or revoked.
- **502** `apple_token_exchange_failed`: Apple did not take the code (codes
  are single-use and expire after 5 minutes) or could not be reached.
  Nothing is stored. Run the ceremony again (new nonce, new code).
- **502** `apple_token_store_failed`: the token could not be sealed or
  stored. If this request created the link, the new token is revoked and the
  link taken back. On a re-link of an already linked Apple ID nothing is
  revoked, and the existing link stays, with its stored token if it has one
  (a link made before the server held tokens has none). Run the ceremony
  again.
- **502** when Apple's keys could not be fetched or read to check the
  returned id_token (a transient failure): nothing is stored or revoked. Run
  the ceremony again.
- **500** when the link itself could not be written: the new token is
  revoked and nothing is stored. Apple's revoke ends the whole
  authorization, so on a re-link this also ends the existing link's: Arkavo
  leaves the person's Sign in with Apple list until they link again. Run the
  ceremony again.

Without that configuration the code is ignored and the link behaves as
before.

## Other Arkavo apps

There is one Arkavo account per person, shared by the viewer and Creator
(Creator reads the same session from the keychain). **Deleting it from either
app deletes it for both.** The other app's stored token is refused (401) the
next time it is used; that app should then clear its keychain entry and show
signed-out state. The app that deletes should say so before the person
confirms, for example: "This deletes your Arkavo account in every Arkavo app."
