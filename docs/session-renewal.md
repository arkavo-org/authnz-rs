# Passkey session renewal (#108)

A **session** lets a client renew its passkey auth CWT without asking for
the passkey again. It follows NIST SP 800-63B-4 at AAL2:

- it lasts at most **24 h** after the passkey assertion that opened it;
- it ends after **1 h** without a renewal.

The renewal is bound to a non-exportable P-256 key the client holds in the
Secure Enclave (the **device key**), and its credential rotates on every use
(RFC 9700). A refused renewal means a passkey sign-in.

Rollout order: this route ships first, then client renewal (ArkavoKit,
Creator, iOS), and only then does the auth CWT shorten from 1 h to 15 min.
Until then a renewed token lasts as long as a fresh one.

## Encodings

- `publicKey`: the device key's public key as the 65-byte uncompressed X9.63
  point (`04 || x || y`), what `SecKeyCopyExternalRepresentation` returns for
  an EC key. Base64url, no padding.
- Signatures: ECDSA P-256 over SHA-256 of the message bytes, as **raw
  `r || s` (64 bytes)**. Base64url, no padding. Not DER:
  `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` returns DER,
  which the client must convert to `r || s`.
- Messages are UTF-8, lines joined by `\n`, no trailing newline.
- Times are unix seconds.

## Open: `POST /session`

Call it right after `POST /authenticate`, with the token it returned.

- `X-Auth-Token`: a passkey auth CWT from `POST /authenticate`, minted at
  most **300 s** ago. A renewed token (one carrying `auth_time`) cannot open
  a session.
- Body:

  ```json
  {"publicKey": "<b64url X9.63>", "proof": "<b64url r||s>"}
  ```

  `proof` signs:

  ```
  arkavo-session-open-v1
  <sub of the token: the account UUID>
  <b64url of the token's cti>
  <publicKey exactly as sent>
  ```

- `201`:

  ```json
  {"sessionId": "<uuid>", "credential": "<generation>.<secret>",
   "sessionExpiresAt": 1790086400, "idleTimeoutSeconds": 3600}
  ```

  `sessionExpiresAt` is the assertion time + 86400. The client keeps
  `sessionId` and `credential`.

| Status | Body `error` | Meaning |
|---|---|---|
| 401 | `passkey_assertion_required` | No token, an invalid or expired one, a renewed one, one more than 300 s old, or a deleted account. Sign in with the passkey. |
| 400 | `invalid_public_key` | Not a 65-byte uncompressed P-256 point on the curve. |
| 400 | `invalid_proof` | Not 64 bytes, or not a valid signature by `publicKey` over the open message. |
| 409 | `session_exists` | This token already opened a session (`sessionId` is derived from its `cti`). |

## Renew: `POST /session/refresh`

No token. Body:

```json
{"sessionId": "<uuid>", "credential": "<generation>.<secret>", "signature": "<b64url r||s>"}
```

`signature` signs:

```
arkavo-session-refresh-v1
<sessionId>
<credential>
```

`200`:

```json
{"token": "<passkey auth CWT>", "expiresAt": 1790003600,
 "credential": "<next generation>.<secret>", "sessionExpiresAt": 1790086400}
```

- The old credential is now spent. Store the new one before using the token.
- `token` is a passkey auth CWT, the same shape as `POST /authenticate`'s,
  with the entitlements, roles and publishing suspension read again now. It
  adds `auth_time` = the time of the assertion that opened the session. Its
  `exp` never passes `sessionExpiresAt`.
- A renewed token never counts as a recent passkey assertion: adding a
  passkey, account deletion, agent recovery and delegation, and OIDC
  `max_age` all read `auth_time`, not `iat`. Those still need a real sign-in.

Every refusal is `401 {"error": "session_ended", "reason": "<reason>"}`,
and the client signs in with the passkey:

| `reason` | |
|---|---|
| `not_found` | No such session: never opened, signed out, or ended earlier. |
| `invalid_proof` | `signature` is not a valid signature by the session's device key. The session is kept. |
| `invalid_credential` | The credential is not the session's current one and not an older one. The session is kept. |
| `reused` | An already-spent credential: the session is ended (RFC 9700). |
| `idle` | No renewal for 1 h. Ended. |
| `expired` | 24 h since the assertion. Ended. |
| `account_deleted` | The account was deleted. Ended. |

A malformed body is `400` or `422` (request parsing). A server failure is
`500` with the session unchanged: retry with the same credential.

**Serialize renewals.** Two renewals with the same credential end the
session: the second one presents a spent credential. A response lost in
transit has the same effect, so after a network error the client signs in
with the passkey again. Strict reuse detection is intended (owner decision,
#108).

## Sign out: `POST /session/signout`

```json
{"sessionId": "<uuid>", "signature": "<b64url r||s>"}
```

over

```
arkavo-session-signout-v1
<sessionId>
```

`204` once the session is gone, also when it did not exist. `401
{"error": "session_ended", "reason": "invalid_proof"}` when the signature
does not verify against the session's device key.

## When the client renews

Only while the user is using the app: it is frontmost with user input in
the last 15 min, or a recording, stream, publish or playback is running.
Renew before `expiresAt`, and once on a 401 from a resource server. Never
renew on a background timer: that keeps an idle session alive and defeats
the idle timeout.

## Server notes

- Row: `identity_links` `session#<sessionId>`, `provider = session`,
  `user_id`, `public_key` (B), `assertion_at`, `created_at`,
  `last_renewed_at`, `generation` (N), `credential_hash` (B, SHA-256 of the
  credential string), `expires_at` (= `assertion_at + 86400`, for a future
  DynamoDB TTL; TTL is not enabled on `prod-identity-links` today). Ended
  sessions are deleted when a renewal is refused; the account-deletion sweep
  deletes them with the other link rows.
- `sessionId` = UUID v8 from the first 16 bytes of
  SHA-256(`arkavo-session-id-v1` || cti).
- Renewal order: read the row; verify the signature (before anything that
  can end the session, so a caller without the device key cannot end it);
  check the credential, the deadlines and the account; then one conditional
  `UpdateItem` on `generation` and `credential_hash` rotates it. A
  conditional failure whose row now has a higher generation is reuse.
- A publishing suspension does not end a session (owner decision, #108):
  the renewed token simply lacks the publish entitlement.
