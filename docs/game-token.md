# Game-server token (`POST /game/token`)

authnz-rs#151. Approved by the owner on 2026-11-09 and reviewed the same day
by the Roadfall session (the game server and app) and the ArkavoKit session
(the client library). Change it only together with them.

## Why

A game server on the internet (`https://game.arkavo.net`) must know which
account is calling and whether it holds the Game Pass
([online-play-entitlement.md](online-play-entitlement.md)). The passkey auth
CWT cannot serve: its audience is shared by every Arkavo service, so a game
server that accepted it could replay a player's token elsewhere, and a token
lifted elsewhere would work at the game server.

So identity mints a token for the game server alone:

- its audience is exactly the game server's, and it is typed, so nothing
  else accepts it;
- it is bound to a key the device holds, and the game server requires each
  request to be signed with that key, so a copied token is useless;
- it carries the account, its handle, and the online-play entitlement when
  the account holds the pass. Nothing else.

## What authenticates the mint

**The passkey session, not a token** ([session-renewal.md](session-renewal.md)).
The caller proves it holds the session's device key, and the token's `cnf`
is that key, read from the session identity stored when it was opened. The
caller never sends a key. So a stolen auth CWT cannot mint a game token, and
a game token ends with the session whose key it is bound to.

A client without an open session signs in with the passkey and opens one
first.

A passkey session goes idle after about an hour without a renewal and ends
24 hours after the sign-in, which would put a passkey prompt before most
play. So the mint also takes a **game session** (below): opened from a
passkey session, bound to the same device key, good for 30 days, and
accepted by this mint only.

## Game sessions

A game session lets one device mint game tokens for **30 days after the
passkey sign-in, with no idle limit** (owner decision 2026-11-10). It is
outside the limits the passkey session keeps, on purpose, and so it does
exactly one thing: `POST /game/token` accepts it. It renews no session,
yields no passkey auth token, and no other route reads it. Account changes,
deletion and purchases keep needing the passkey session or a fresh passkey
sign-in.

### Open: `POST /game/session`

```
POST /game/session
Content-Type: application/json

{ "sessionId": "<uuid>", "issuedAt": 1794268800, "signature": "<base64url>" }
```

`sessionId` is the passkey session. `signature` is its device key's
signature (raw `r‖s`, as for the mint) over:

```
arkavo-game-session-open-v1
<sessionId>
<issuedAt>
```

The passkey session must be in service, exactly as for a mint with it:
inside its 24 h deadline and its idle limit, its account live. So open the
game session right after `POST /session`.

| Status | Body | When |
|---|---|---|
| 200 | `{"gameSessionId": "<uuid>", "sub": "<account uuid>", "expiresAt": <unix s>, "serverTime": <unix s>}` | opened, or already open |
| 400 | `{"error":"invalid_request"}` / `{"error":"invalid_issued_at", "serverTime": …}` | as for the mint |
| 401 | `{"error":"unauthorized"}` | no such passkey session, the signature does not verify, the session is over or idle, or its account is deleted |
| 429 | `{"error":"rate_limited"}`, `Retry-After` | counted with the account's mints |
| 503 | `{"error":"game_tokens_unavailable"}` | `GAME_TOKEN_AUDIENCES` unset |

- **`sub`** is the account, the same bare UUID the token carries. The
  client stores `gameSessionId`, `sub` and `expiresAt` together, so it
  knows whose game session it holds, and when it ends, without a request
  and after the passkey session and its token are gone.
- **`expiresAt`** is the passkey assertion's time + 2592000 s (30 days). It
  counts from the sign-in, never from the open.
- **One passkey session has one game session.** `gameSessionId` is derived
  from `sessionId`, so opening again (a lost answer, a retry) returns the
  same id and the same `expiresAt`. Nothing extends a game session; a new
  one needs a new passkey sign-in. An open that fails or is refused never
  ends a game session that was already open.
- **The key.** The game session is bound to the passkey session's device
  key as identity stored it; the caller sends no key. The client must
  **keep that key for as long as it keeps the game session**, also after
  the passkey session has ended (idle, expired, a refused renewal).
- **A new passkey sign-in on the same device** opens a new passkey session,
  with a new device key, and so a new game session. Identity cannot tell
  that the two are one device. The client opens the new game session, ends
  the old one (below) and then discards the old key, so that it holds one
  game session.

### What ends a game session

- Its deadline.
- `POST /game/session/end`.
- `POST /session/signout` of the passkey session that opened it. This works
  after that session has ended too (the usual case for a game: the session
  went idle the day before): the game session holds the same device key,
  so the same sign-out request, with the passkey session's id and the same
  signature, ends it. A client needs only one of the two calls.
- Deletion of the account: mints are refused at once, and the row is
  removed with the account's other rows.

The passkey session going idle, expiring or being ended for credential
reuse does **not** end it: that is its purpose.

### End: `POST /game/session/end`

```
{ "gameSessionId": "<uuid>", "issuedAt": 1794268800, "signature": "<base64url>" }
```

signed by the device key over:

```
arkavo-game-session-end-v1
<gameSessionId>
<issuedAt>
```

204 when ended, and 204 again for one already gone (or never opened). 400
and 503 as above. A game session past its deadline can still be ended.

**A signature that is not the device key's is also 204, and ends nothing.**
The route takes no token, so it does not say whether an id names a game
session. A client that signed with the right key has ended it; the proof,
if it wants one, is that a mint with that id answers 401.

**Signing out offline.** A client that signs out with no network deletes the
device key and its stored ids, and need not reach identity later. The row
then stays (refused once past its deadline, and removed only with the
account, or by a DynamoDB TTL once one is enabled), but nothing can use it:
every mint needs a signature by the deleted key. A client that can reach identity should end
the game session before it deletes the key.

## Request

```
POST /game/token
Content-Type: application/json

{ "sessionId": "<uuid>", "audience": "https://game.arkavo.net",
  "issuedAt": 1794268800, "signature": "<base64url>" }
```

- **`sessionId`**: the session, as `POST /session` returned it. **Or
  `gameSessionId`**, as `POST /game/session` returned it: exactly one of
  the two. With `gameSessionId` the first line of the signed message is
  `arkavo-game-session-token-v1` and its second line is the game session
  id; everything else is the same.
- **`audience`**: the game server the token is for. It must be one of the
  values the operator lists in `GAME_TOKEN_AUDIENCES`.
- **`issuedAt`**: unix seconds, as a JSON integer (no fraction, no
  exponent). It must be within 60 seconds of identity's clock. A client
  that has a `serverTime` from an earlier answer sends its own clock
  corrected by that offset.
- **`signature`**: base64url without padding of the raw 64-byte `r‖s` ECDSA
  P-256 SHA-256 signature (never DER) by the session's device key over the
  UTF-8 bytes of:

  ```
  arkavo-game-token-v1
  <sessionId>
  <audience>
  <issuedAt>
  ```

  Four lines joined by `\n`, with no trailing newline. `<sessionId>` is the
  lowercase hyphenated UUID, `<audience>` the request's string exactly as
  sent, `<issuedAt>` the integer in decimal digits.

No `X-Auth-Token` is needed, and none is read.

The mint reads the session and never writes it. It is not a renewal: it
does not rotate the session credential, and it does not keep an idle session
alive. A request can be sent again, and a lost answer costs nothing; a
replay within the 60 seconds only yields another token bound to the same
device key.

## Responses

| Status | Body | When |
|---|---|---|
| 200 | `{"token": "<base64url>", "expiresAt": <unix s>, "onlinePlay": <bool>, "serverTime": <unix s>}` | minted. `onlinePlay` says whether the token carries the entitlement, so the app need not parse it. `serverTime` is identity's clock |
| 503 | `{"error":"game_tokens_unavailable"}` | the operator has not set `GAME_TOKEN_AUDIENCES` |
| 200 | the same, plus `"gameSessionExpiresAt": <unix s>` | minted with a `gameSessionId`: the game session's deadline, as `POST /game/session` returned it |
| 400 | `{"error":"invalid_request"}` | the body is not `{sessionId, audience, issuedAt, signature}`, or it names both sessions or neither |
| 400 | `{"error":"invalid_audience"}` | not a listed audience |
| 400 | `{"error":"invalid_issued_at", "serverTime": <unix s>}` | `issuedAt` is more than 60 s from identity's clock. Decided before the session is read: it needs no secret. Correct the clock offset from `serverTime` and send again; do **not** renew the session for it |
| 401 | `{"error":"unauthorized"}` | no such session or game session; the signature does not verify; the passkey session is past its 24 h deadline or its idle limit; or the account is deleted |
| 401 | `{"error":"game_session_ended"}` | `gameSessionId` only: the game session is past its deadline. Told only to a caller whose signature verified, for a live account, and counted by the rate limit like a mint. The person signs in with the passkey again |
| 429 | `{"error":"rate_limited"}`, `Retry-After` | more than 30 mints by the account in a minute |
| 500 | `{"error":"server_error"}` | a read or signing failed |

Every response is `Cache-Control: no-store`.

**A 401 here never ends the session**, and the body does not say which check
failed. On a 401 the client renews the session (`POST /session/refresh`),
which answers with the definite reason if the session is over, and then
tries the mint once more. A 429 is answered here (unlike the session
routes): wait `Retry-After`.

**With a `gameSessionId`, do not renew the passkey session on a 401.** It is
usually over by then, and the renewal has nothing to do with the game
session. `game_session_ended` means sign in again; `unauthorized` means the
game session is gone (ended, signed out, the account deleted) or the key is
not its key, and the answer is the same: sign in again. The mint never
removes the row, so `game_session_ended` is answered every time until the
client ends the game session or signs in again.

**Clocks.** Every 200 and every `invalid_issued_at` carries `serverTime`.
A client keeps the offset between it and its own clock and uses the
corrected time for `issuedAt` and for `t` in the request proof below, so a
device whose clock is wrong still works. A game server whose clock is kept
right then sees `t` within its window.

**The mint succeeds without a pass.** The token then has no
`arkavo_entitlements`, and the game server can answer "Game Pass needed"
apart from "not signed in".

## The token

`token` is base64url (no padding) of CBOR tag 61 (CWT) around a COSE_Sign1:

- **Protected header**: `alg` (1) ES256, `kid` (4) the signing key's id in
  `/.well-known/cose-keys`, `content type` (3) **`application/game+cwt`**.
  Unprotected header empty; external AAD empty.
- **Payload**: a CBOR map with exactly these keys, in this (deterministic,
  RFC 8949 §4.2.1) order:

| Key | Claim | Value |
|---|---|---|
| 1 | `iss` | the issuer (`OIDC_ISSUER`, `https://identity.arkavo.net`) |
| 2 | `sub` | the account's bare lowercase UUID, as in the passkey CWT |
| 3 | `aud` | the requested audience, one text string |
| 4 | `exp` | `iat` + `GAME_TOKEN_SECONDS` (default 900), and never later than the deadline of the session it was minted with (a passkey session: 24 h after its passkey assertion; a game session: 30 days after it) |
| 6 | `iat` | mint time, unix seconds |
| 7 | `cti` | 16 random bytes |
| 8 | `cnf` | `{1: {1: 2, -1: 1, -2: x, -3: y}}`: the session's device key as a COSE_Key (kty EC2, crv P-256), no `kid`, no `alg`. A game session's key is its passkey session's |
| `"arkavo_handle"` | | the account's permanent handle, full and lowercase (`alice.arkavo.social`). Always present |
| `"arkavo_entitlements"` | | **present only while the account holds the pass**: an array of exactly one text string, `https://arkavo.net/attr/network/value/online-play`. Absent otherwise |

Nothing else: no other entitlement, Patreon data or email.

The pass is worked out at the mint, as for any token: an App Store pass, a
prepaid market term, or a lifetime membership. A mint asks the market again
when its cached answer is "none" (as a renewal does), so a token minted
right after a payment is not answered from before it. That recheck is
limited to 6 a minute per account; past it the cached answer is used. So
every mint for an account without the pass can reach the market, not only
one that follows a payment.

## Verifying (the game server)

1. Strip tag 61. Require ES256, exactly the content type above, a `kid` in
   identity's COSE key set (`/.well-known/cose-keys`, cached; fetch again on
   an unknown `kid`), and a valid signature.
2. Require the payload keys above and no others (`arkavo_entitlements` may be
   absent), `iss` equal to the issuer, `aud` equal to the server's own
   audience as one string, and `exp - iat` ≤ 3600.
3. Check `exp` and `iat` against the server's clock, with 60 s of skew.
4. **Require the request's proof** (below). A token without its proof is
   refused: it is not a bearer token.
5. The account is `sub`. It holds the pass when `arkavo_entitlements`
   contains the online-play value.

`game_token::verify` and `game_token::request_proof_verifies` in this
repository are reference implementations.

**Test vectors.** A verifier written elsewhere can be checked against bytes
this repository produces:

```bash
cargo run --example game_token_vectors -- <output directory> \
    https://identity.arkavo.net https://game.arkavo.net
```

It writes `game-token-vectors.json`: a key set as `/.well-known/cose-keys`
serves it, a token with the pass and one without, the device key their
`cnf` names, request proofs with every input stated (an empty body, a
query, the path `/`), and tokens that must be refused (another audience,
expired, not yet valid, too long-lived, an unknown `kid`, a wrong key under
a known `kid`, no content type, another content type, no CBOR tag). Every
key is generated by that run and written into the file, so the file is
never committed.

A lapsed pass stops within the token's life (15 minutes by default), plus up
to 5 minutes of identity's cache.

## The request proof (app to game server)

Every request to the game server carries the token and a signature by the
`cnf` key over the UTF-8 bytes of:

```
arkavo-game-request-v1
<audience>
<METHOD>
<path>
<t>
<body hash>
<token hash>
```

Seven lines joined by `\n`, with no trailing newline:

- `<audience>`: the token's `aud`.
- `<METHOD>`: the HTTP method in uppercase.
- `<path>`: the request target exactly as sent on the wire, still
  percent-encoded: the path (`/` when it is empty), and `?` plus the query
  when there is one. The game server verifies the raw target it received.
  Anything in front of it that rewrites a target (merging slashes, decoding
  escapes) breaks the proof, so its API should avoid paths that need
  escaping.
- `<t>`: unix seconds as decimal digits, from the device's clock corrected
  by `serverTime` (above). The server accepts it within 60 seconds of its
  own clock.
- `<body hash>`: base64url without padding of SHA-256 of the request body
  bytes (of the empty string for no body).
- `<token hash>`: base64url without padding of SHA-256 of the token's text,
  exactly as it is sent.

The signature is the raw 64-byte `r‖s`, base64url without padding. How the
token, `t` and the signature travel (header names) is the game server's to
define; this contract fixes the signed bytes.

Rules:

- **The device key signs only messages that start with a fixed context
  line.** The same key signs the session messages (`arkavo-session-open-v1`,
  `-refresh-v1`, `-signout-v1`) and the mint (`arkavo-game-token-v1`). A
  client library must never offer "sign these bytes" for it: a game server
  could then ask for a session sign-out.
- A proof can be replayed for 60 seconds against the same method, path and
  body. A server that must not act twice (starting a run, finishing a run)
  makes the operation idempotent or remembers `(cti, t)` for that long.
- For a long-lived connection, sign its handshake, not each message. The
  server then closes the connection at the token's `exp`, or asks for a
  fresh token and proof on it before then; otherwise the token's lifetime
  would not bound the connection.
- The key signs only while the device is unlocked.

## When the client mints

- When it is about to call the game server and holds no token, or one that
  expires within a minute. Never on a background timer.
- After a 401 from the game server for an expired token.
- **Near the session's deadline** `exp` is capped, so a new token can expire
  in under a minute. A client must not mint again when the token it just
  got expires no later than the one it had: the session is ending, and the
  person signs in again.
- **After a purchase, poll the mint, not the session renewal.** The mint
  asks the market again and rotates nothing, so a lost answer costs nothing.
  Mint every 20 seconds, for about a minute and a half, until `onlinePlay`
  is `true`. The market's payment search lags a payment by a minute or more.
- On sign-out the session ends, and the device key with it: the token is
  then useless.

**A game server sees no difference.** A token minted with a game session
has the same claims, content type, lifetime bound and proof as one minted
with a passkey session. Its `cnf` key stays the same for the whole game
session, up to 30 days.

**Without a game session, keep the passkey session alive while playing.**
The mint is not a renewal, and with a `sessionId` it answers 401 once the
session is idle. A person who plays for more than an
hour and talks only to the game server must still renew the session
(`POST /session/refresh`) within its idle limit, under the usual rule: only
while the app is in use (frontmost with recent input; active play counts).
Otherwise the next mint fails and the person meets a passkey prompt
mid-game. The device key, and so `cnf`, stays the same across renewals of
one session. A new passkey sign-in opens a new session with a new key; the
`sub` is the same, so a game server keys what it stores by `sub`, never by
`cnf`.

## Configuration

| Variable | Purpose |
|---|---|
| `GAME_TOKEN_AUDIENCES` | Comma-separated audiences `POST /game/token` may mint for, one per game server. Unset ⇒ the route answers 503. |
| `GAME_TOKEN_SECONDS` | Token lifetime. Default 900; 60 to 3600. Out of range fails startup. |

The game session's 30 days is a constant (`GAME_SESSION_SECONDS`), not
configuration. Its row is `identity_links` `game-session#<gameSessionId>`,
`provider = game-session`, with `user_id`, `public_key`, `assertion_at`,
`created_at` and `expires_at` (for a future DynamoDB TTL, which is not
enabled today: a row past its deadline stays, refused, until it is ended or
the account is deleted). `gameSessionId` = UUID v8 from the first 16 bytes
of SHA-256(`arkavo-game-session-id-v1` || the passkey session id's 16
bytes). The game session routes answer 503 while `GAME_TOKEN_AUDIENCES` is
unset.

Identity refuses to start if an audience is the passkey audience (`arkavo`),
the platform audience, an OIDC client id or an agent token audience, or
starts with `arkavo:` or `owner-kas:`. Some verifiers of identity's tokens
check the audience but not the content type (the OpenTDF platform's does),
so a game audience must never be one they accept.

## What it does not do

- **It is not accepted by identity or any other Arkavo service.** Identity's
  own verifier refuses any typed CWT.
- **It cannot be renewed.** The client mints a new one.
- **It cannot be revoked.** It lasts 15 minutes; an account deleted
  meanwhile stays a valid caller until `exp`.
- **It does not prove the app is genuine.** That is App Attest's job
  (#81), not this token's.
