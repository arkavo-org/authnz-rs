---
paths:
  - "src/apple_signin.rs"
  - "src/apple_tokens.rs"
  - "src/apple_tokens_tests.rs"
  - "src/google_signin.rs"
  - "src/identity.rs"
---

# Sign in with Apple and Google (link-only)

## identity.rs: Federated identity resolution (link-only)

- `resolve_linked_account(db, provider, subject)`: the single policy shared by
  Apple and Google sign-in. An identity reaches an Arkavo account **only**
  through its `identity_links` row.
- Accounts are created by **passkey registration alone**. Sign-in never
  provisions. A missing link — or a link pointing at a deleted user row —
  fails closed as `NotLinked`.
- Refusal is uniform across every surface: `error=access_denied` with
  `error_description=identity_not_linked` on the RP's redirect URI
  (`/oauth/authorize?idp=apple`, `/oauth/google/callback`), or HTTP 403 with
  the same marker from `POST /oauth/apple/idtoken`. The code stays standard
  OAuth2 so existing RP handling works; the marker is what lets a client route
  the user to passkey registration.

## apple_signin.rs: Sign in with Apple integration

- Validates Apple-issued id_tokens against Apple's JWKS (cached 1h with
  force-refresh on `kid` miss in case Apple rotated keys)
- Every accepted id_token must clear:
  - **Signature** vs Apple JWKS
  - **`iss`** = `https://appleid.apple.com`
  - **`aud`** ∈ comma-separated `APPLE_CLIENT_ID` list (iOS bundle + web
    Service ID can coexist on the same deployment)
  - **`nonce`** must match the server-issued nonce (verbatim or hex SHA-256;
    constant-time compare). No nonce ⇒ refuse.
  - **`exp`/`iat`** via `jsonwebtoken::Validation`
- `GET /oauth/apple/nonce`: issues a 256-bit server nonce, persists in session
- `POST /oauth/apple/idtoken`: Native flow — client must have called
  `/oauth/apple/nonce` first; server consumes session nonce (single-use) and
  validates the id_token against it
- `POST /oauth/apple/link`: **Auth-required** link path. Caller presents a
  valid Arkavo CWT via `X-Auth-Token`; server consumes the session nonce,
  validates the Apple id_token, and writes `(user_id, "apple", sub)` to the
  `identity_links` table. Idempotent on repeat; returns HTTP 409 if the same
  Apple `sub` is already linked to a different arkavo user. **Minimum-PII**:
  no email/name/relay claims are persisted, even if Apple sends them.
  Once the id_token is verified, and before anything is linked, the
  account's `apple_linked_at` is set (`mark_apple_linked`, `LIVE_ROW`; 401
  on a deleted account), so no passkey token says
  `arkavo_apple_linked: false` while a link exists. Every Apple link write
  must come after it, and is followed by a second mark
  (`mark_linked_again`): an unlink from another device during the code
  exchange finds no link and clears the first. A link that fails leaves
  the mark.
  With token revocation configured (`apple_tokens.rs`) the body must also
  carry `authorization_code` (400 `authorization_code_required` otherwise).
  The server exchanges it at Apple's `/auth/token` (client secret: ES256,
  `kid` = key id, `iss` = team, `sub` = the id_token's `aud`, 300 s; no
  `redirect_uri`, native codes have none), verifies the returned id_token is
  the same `sub` for the same client (`nonce` checked when present), seals
  the refresh token, writes the link and the token to the `identity_links`
  row `apple#<sub>` in **one** conditional `UpdateItem`
  (`link_apple_with_token`), then checks `is_account_live` again. Apple's `/auth/revoke` ends the whole
  authorization for that Apple ID and client, including a token stored for
  it earlier, so the cases differ:
  - binding mismatch (401 `apple_token_binding_mismatch`): the returned
    token is revoked;
  - conflict (409): nothing is revoked (the authorization is the linked
    account's; its deletion revokes it if that link stored a token);
  - the link + token write fails (500): the new token is revoked, even on
    a re-link, where that ends the existing authorization;
  - sealing fails (502 `apple_token_store_failed`): nothing is written; the
    new token is revoked only if the identity is linked to no account;
  - the exchange fails (502 `apple_token_exchange_failed`): nothing to
    revoke;
  - Apple's keys cannot be fetched or read to check the returned id_token
    (502): nothing is revoked;
  - the account was deleted while the request was in flight (the re-check
    sees a tombstone; 401): the new token is revoked and the link holding
    it deleted (kept if Apple did not revoke it). A failed re-check keeps it
    and answers 200;
  - a re-link succeeds (200): the stored token is replaced and the old one
    is not revoked (the revoke at deletion ends the whole authorization).

  Every Apple call has a 10 s timeout. The re-check, not a timing bound,
  keeps a link in flight from outliving a deletion's sweep: the request can
  take longer than `ACCOUNT_DELETION_GRACE_SECONDS` (untimed DynamoDB and
  KMS calls).
- `DELETE /oauth/apple/link` (0.40.0): unlink **every** Apple ID of the
  signed-in account without deleting it. Same auth as the link (passkey CWT,
  live account), no body, at most `APPLE_UNLINKS_PER_MINUTE` (5) per account
  (each one scans `identity_links`: no `user_id` index). In order: the scan
  (`apple_tokens_of`, which also lists token-less links); `apple_unlinked_at`
  on the `credentials` row, **before** anything is removed; each token-less
  link deleted on `user_id = :uid AND HOLDS_NO_TOKEN` (one that gained a
  token meanwhile stays); each stored token revoked with Apple, then its
  link deleted (`delete_apple_link`); once no Apple link is left (also
  when there was none), `apple_linked_at` is removed unless a link was
  marked since the unlink began (`clear_apple_linked`; a failure there is
  logged and the answer is still 204). Answers:
  - 204 unlinked, or nothing linked;
  - 401 bad token or deleted account (the sweep removes a deleted
    account's links);
  - 429 `rate_limited` + `Retry-After`;
  - 502 `apple_token_revoke_failed` (Apple did not revoke or was
    unreachable; that link stays, the rest are gone; retry);
  - 500 storage failure, an unreadable token, or stored tokens while
    revocation is not configured (`apple_token_revocation_unavailable`).
  Audit `identity_unlink outcome=unlinked|not_linked|rate_limited|failed`,
  with a link count, never a subject.
- **An Apple or Google session ends with its link.** Sign-in records the
  IdP's `sub` as `AuthenticatedUser::upstream_subject` (never in a token),
  the refresh token keeps it, and the refresh grant
  (`oidc::upstream_link_ended`) fails with `invalid_grant` once
  `<idp>#<sub>` no longer names the account. An Apple refresh record from
  before 0.40.0 names no `sub`; it ends once the account has
  `apple_unlinked_at`. Access tokens already issued run out (1 h).
  `get_identity_link` is a consistent read, so nothing signs in through a
  link just deleted.
- `POST /oauth/apple/callback`: **explicitly disabled** (HTTP 501). Apple web
  callback requires both code-exchange (signed client-secret JWT against
  Apple's token endpoint) *and* state-bound nonce verification. Until both
  are implemented this endpoint always rejects, so misconfigured Apple
  Service IDs fail loudly rather than being silently accepted.
- `resolve_apple_user` resolves `apple:<sub>` to an Arkavo account **through
  the `identity_links` table only**. It never provisions: an unlinked `sub` is
  refused. Apple `sub` is the canonical join key — email is optional metadata
  and never used to locate accounts (private-relay rotation safe).
- Requires `APPLE_CLIENT_ID` to be set (one or more comma-separated values).

## google_signin.rs: Sign in with Google (upstream IdP, redirect flow)

- `GET /oauth/authorize?...&idp=google`: validates the RP request as usual,
  parks it in Redis (`oidc:google:pending:<state>`, 10 min, single-use,
  in-memory fallback) under a fresh random Google `state`, and 307s the
  browser to `accounts.google.com` with `scope=openid email profile`,
  `prompt=select_account`, and a fresh random `nonce`. Not cookie-session based: the session cookie is
  `SameSite=Strict` and would not survive the cross-site return.
- `GET /oauth/google/callback?state&code|error`: takes the parked request,
  exchanges `code` at Google's token endpoint with `GOOGLE_CLIENT_SECRET`,
  verifies the returned id_token (JWKS signature with kid-miss refresh,
  `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`},
  `aud` = `GOOGLE_CLIENT_ID`, `nonce` constant-time match, `exp`), resolves
  `google:<sub>` → Arkavo account **via the `identity_links` table only**,
  then mints the OIDC code and redirects to the RP with `code` + the RP's own
  `state`. An unlinked `sub` is refused, never provisioned.
- `GET /oauth/google/nonce` + `POST /oauth/google/link`: the Apple pair's
  counterpart, and the only way a Google identity becomes able to sign in.
  Auth-required (`X-Auth-Token` CWT names the account), single-use session
  nonce, HTTP 409 if the `sub` is bound to a different account. Minimum-PII:
  only the `sub` is persisted.
- Failures after the RP was validated go back to the RP's redirect_uri as
  `error=` (`access_denied` for user cancel / rejected id_token,
  `server_error` for exchange or DB failure, `temporarily_unavailable` when
  Google is unconfigured). Only an unknown `state` stays on this origin (400).
- Tokens: `idp=google`, `email` (lower-cased + trimmed) and `email_verified`
  from Google, `name` on the id_token. Disabled unless `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` are set.
