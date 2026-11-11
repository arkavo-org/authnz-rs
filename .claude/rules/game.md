---
paths:
  - "src/game.rs"
  - "src/game_token.rs"
  - "src/game_tests.rs"
  - "src/db/game_session.rs"
---

# Game-server token and game sessions

## game.rs: Game-server token (#151)

- A game server must be able to pin a token to itself, and the passkey auth
  CWT (`aud` `arkavo` plus the platform audience) is accepted everywhere.
  So identity mints a dedicated one. Contract:
  [docs/game-token.md](docs/game-token.md), agreed in outline with Roadfall
  and ArkavoKit 2026-11-09 and approved by the owner the same day; change it
  only with them.
- `POST /game/token`, body `{sessionId, audience, issuedAt, signature}`:
  **authenticated by the passkey session, not by a token**. `signature` is
  the session device key's raw r‖s over
  `arkavo-game-token-v1\n<sessionId>\n<audience>\n<issuedAt>` (`issuedAt`
  an integer, unix seconds within `GAME_TOKEN_PROOF_SKEW_SECONDS` = 60 of
  identity's clock, else 400 `invalid_issued_at` with `serverTime`, decided
  before the session is read so a wrong clock never costs a renewal). The session must be
  inside its 24 h deadline and its idle limit, and its account live. The
  mint reads the session and never writes it: it is not a renewal and does
  not keep an idle session alive. 200 `{token, expiresAt, onlinePlay, serverTime}`;
  401 `unauthorized` (every session or proof failure, one body; the session
  is never ended here); 400 `invalid_request` / `invalid_audience`; 429
  `rate_limited` + `Retry-After` past `GAME_TOKEN_MINTS_PER_MINUTE`; 503
  `game_tokens_unavailable` when unconfigured.
- Format (`authnz_rs::game_token`): tag 61 + COSE_Sign1, ES256, protected
  **content type `application/game+cwt`**, so `cwt::verify` refuses it
  everywhere in identity. Claims exactly `iss`, `sub` (bare UUID), `aud`
  (the one requested audience), `exp`, `iat`, `cti`, `cnf` (**the session's
  stored device key, never a key the caller sends**: a stolen auth token
  cannot mint a game token for another key), `arkavo_handle`, and
  `arkavo_entitlements` = `[online-play]` **only while the account holds the
  pass**. The mint succeeds without a pass, so a server can tell "Game Pass
  needed" from "not signed in". No other entitlement, no Patreon data.
- `exp` = `iat` + `GAME_TOKEN_SECONDS`, never past the session's deadline.
- The pass is derived as at any mint (`publishing::load_sources` with
  recheck, then `derive`), without Patreon: no publishing source grants it.
- **Game sessions** (0.36.0, owner decision 2026-11-10): a passkey session
  goes idle in about an hour and ends in a day, which would put a passkey
  prompt before most play. `POST /game/session` `{sessionId, issuedAt,
  signature}` (the passkey session's device key over
  `arkavo-game-session-open-v1\n<sessionId>\n<issuedAt>`; the session in
  service as for a mint) opens that session's game session: the same
  account and stored device key, good until the passkey assertion +
  `GAME_SESSION_SECONDS` (30 days, **no idle limit**; outside AAL2 on
  purpose). 200 `{gameSessionId, sub, expiresAt, serverTime}`; the id is
  derived from the passkey session id, so the open is idempotent and never
  extends. **Only `POST /game/token` accepts it**: `gameSessionId` in place
  of `sessionId` (exactly one), signed under
  `arkavo-game-session-token-v1`; the 200 adds `gameSessionExpiresAt`, and
  a session past its deadline answers 401 `game_session_ended`, only after
  the proof verifies. Never let another route accept a game session: it
  must not renew a session or yield a passkey auth CWT. Ended by its
  deadline, `POST /game/session/end` (device key; 204 for ended, unknown
  **and a wrong signature alike**, so the route is no existence oracle),
  `POST /session/signout` of its passkey session (also after that session's
  row is gone: the signature is then checked against the game session's
  key), and account deletion (the mint's liveness check, then the sweep's
  link step); **not** by the passkey session going idle, expiring or being
  reused. The open takes a row back only if **that request wrote it**
  (`open_game_session` says so) and the passkey session or the account is
  gone on a second look; sign-out deletes the game session before and
  after the passkey session. Together these close the open/sign-out race;
  an already-open game session is never ended by a repeated open. Row:
  `identity_links` `game-session#<id>` (`db/game_session.rs`), never
  written after the open, so the mint stays read-only. The `sessionId` mint
  is unchanged.
- The game server requires proof of possession: each request is signed by
  the `cnf` key over `arkavo-game-request-v1\n…` (`game_token::request_message`).
  The device key also signs the session messages, so it must only ever sign
  messages that start with a fixed context line.
