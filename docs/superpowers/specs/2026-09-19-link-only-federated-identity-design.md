# Link-only federated identity

**Date:** 2026-09-19
**Status:** implemented

## Problem

`map_apple_user` and `map_google_user` called `create_user` on first sight of
an unseen IdP `sub`, creating a credential-less account addressable by a
synthetic `apple-<sub>` / `google-<sub>` username.

Two consequences:

1. The IdP subject — published as the OIDC `sub` in every id_token handed to
   every relying party — was sufficient to bring an Arkavo account into
   existence. Until the registration namespace was closed (PR #64), it was
   also sufficient to enroll a passkey onto one, because `start_register`
   waives its token requirement for accounts holding zero credentials.
2. `identity_links`, written by `POST /oauth/apple/link` since linking
   landed, had **no reader**. A user who linked Apple to their passkey
   account still got the separate auto-provisioned account when they signed
   in with `idp=apple`. Two accounts, one human.

The intended model is the inverse: accounts are created by passkey
registration, and a federated identity is *linked* to an account that already
exists.

## Design

### Resolution

`identity::resolve_linked_account(db, provider, subject)` is the single shared
policy. `db::get_identity_link` is the read side of `link_identity`. Both
`resolve_apple_user` and `resolve_google_user` go through it and cannot create
anything. A missing link, or a link pointing at a deleted user row, both fail
closed as `NotLinked`.

### Subject

`sub` is `arkavo:<uuid>` on every path, replacing `apple:<sub>` /
`google:<sub>`. One human has one account under link-only, so a relying party
must see one stable subject however they signed in; `idp` still records which
IdP was used. Contained because OpenTDF keys off `arkavo_account_id`, which
was already the UUID everywhere.

### Linking

Apple already had `GET /oauth/apple/nonce` + `POST /oauth/apple/link`. Google
gets the identical pair, which is the only way a Google identity becomes able
to sign in. One account may link several subjects of the same provider; one
subject on two accounts is refused with HTTP 409.

### Refusal

Uniform across surfaces: `error=access_denied` with
`error_description=identity_not_linked` on the RP's redirect URI, or HTTP 403
with the same marker from the native Apple endpoint. Standard OAuth2 code so
existing RP error handling keeps working; the marker is what lets a client
route the user to passkey registration.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Existing `google-*` / `apple-*` rows | **Hard cutover, no migration** | Owner's call. Those accounts stop resolving on deploy; users re-register and link. |
| Google linking | Native id_token, mirroring Apple | Smallest surface, symmetric contract, reuses `verify_id_token`. Requires the client to obtain a Google ID token natively. |
| Refusal code | `access_denied` + marker | Invents no vocabulary; every existing RP error handler keeps working. |
| In-flight refresh tokens | **Let them expire** | Owner's call. See below. |

## Accepted consequences

**Cut-over accounts keep refreshing for up to 30 days.**
`handle_refresh_token_grant` re-resolves entitlements from the recorded
`arkavo_account_id` and never re-checks the link, and the underlying
credentials row is not deleted. So the cutover ends *new* federated sign-ins
immediately but not existing sessions. Flushing `oidc:refresh:*` would close
that window at the cost of logging out every passkey user; it was explicitly
decided not to.

**No backfill.** Accepted deliberately, not overlooked.

## Testing

Resolution, linking, conflict, and the dangling-link case run against real
DynamoDB (DynamoDB Local) via `AUTHNZ_TEST_DYNAMODB_ENDPOINT`, wired into the
CI `test` job. Tests skip when the endpoint is absent so `cargo test` stays
green without Docker.

`DynamoDBStore::with_client` exists because the suite shares one process
environment and several tests mutate `AWS_*` — including one that points
`AWS_ENDPOINT_URL_DYNAMODB` at a dead port — so an env-derived client is not
reproducible. The test endpoint variable is deliberately distinct for the
same reason.

Not covered: the full browser redirect flow through a real Google, and the
HTTP layer of `POST /oauth/google/link` (handler-level tests would need a
session store and a minted CWT).
