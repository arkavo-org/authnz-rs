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
  - `failed`: removal ran out of retries. The account itself is deleted and
    stays deleted; the server retries at its next restart and the failure is
    logged for an operator. Tell the person their account is deleted and the
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

**Kept:** a tombstone holding the random account id, the deletion id, its
status and timestamps. It holds no personal data; it is what makes the
account's old tokens fail and what the status endpoint reads. App Attest
registration counters (keyed by device key, not by account) are kept for abuse
prevention.

## Other Arkavo apps

There is one Arkavo account per person, shared by the viewer and Creator
(Creator reads the same session from the keychain). **Deleting it from either
app deletes it for both.** The other app's stored token is refused (401) the
next time it is used; that app should then clear its keychain entry and show
signed-out state. The app that deletes should say so before the person
confirms, for example: "This deletes your Arkavo account in every Arkavo app."
