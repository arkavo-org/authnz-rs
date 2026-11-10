# Market app token (`POST /market/token`)

authnz-rs#151. Built to the market's contract, arkavo-com/market
`docs/market-identity-interface.md`, "Requests: the tokens identity issues"
(the app token). Approved by the owner on 2026-11-09 as a third token of the
owner-KAS kind; authnz-rs#156 would later fold the three into one mint
without changing this route. Change this contract only together with the
market.

## Why

A prepaid term (the Game Pass, 3 or 12 months) is asked for at the market's
request API, `POST <market>/api/requests`. The market must know the caller is
the account. The passkey auth CWT is a bearer token that every service
accepts (`aud` `arkavo`), so the market does not take it. An app exchanges it
here for a token that names only the market and is bound to a key the app
holds. The market then requires a signature by that key on every request.

An AI agent uses its agent token instead: see "Entitlements every account
holds" in [agent-credentials-contract.md](agent-credentials-contract.md).

## Request

```
POST /market/token
X-Auth-Token: <passkey auth CWT>
Content-Type: application/json

{ "cnf_key": "<base64url>" }
```

- **`X-Auth-Token`**: the account's passkey auth CWT, original
  (`POST /authenticate`) or renewed (`POST /session/refresh`), for a live
  account. OIDC access tokens, DeviceCheck tokens, agent tokens, the
  registration token and every typed token are refused.
- **`cnf_key`**: the app's public key, base64url without padding of the
  65-byte uncompressed P-256 point `04‖X‖Y`, on the curve. The app keeps the
  private key (the Secure Enclave or Android Keystore, where it can) and may
  reuse it across mints.
- No other member is accepted. The audience is not the caller's to choose.

## Answers

| Status | Body | When |
|---|---|---|
| 200 | `{"token", "expires_at", "audience", "server_time"}` | minted |
| 400 | `{"error":"invalid_request"}` | not that JSON object |
| 400 | `{"error":"invalid_cnf_key"}` | not such a key |
| 401 | `{"error":"unauthorized"}` | no acceptable auth CWT, or the account is not live |
| 429 | `{"error":"rate_limited"}` + `Retry-After` | more than 10 mints a minute for the account |
| 500 | `{"error":"server_error"}` | identity's fault |
| 503 | `{"error":"market_unavailable"}` | this identity has no market configured |

Every answer carries `Cache-Control: no-store`. `token` is base64url without
padding. `expires_at` is the token's `exp` (unix seconds). `audience` is the
market the token is for; send the token nowhere else. `server_time` is
identity's clock at the mint (unix seconds, the token's `iat`): the market
accepts a request signed within 60 seconds of its own clock and explains no
refusal, so a device whose clock is wrong should sign with a time corrected
by the difference, and read `expires_at` against it. A 400 is decided
before the account is read.

## The token

CBOR tag 61 around a COSE_Sign1, ES256, empty external AAD.

Protected header: `alg` ES256, `kid` (a key in
`https://identity.arkavo.net/.well-known/cose-keys`), and **content type
(label 3) `application/market+cwt`**. Identity's own verifier refuses any
content type, so this token is never a session token at identity, and from
their next releases neither arks nor the OpenTDF platform accepts a typed
CWT.

Payload, exactly these keys, in deterministic order (RFC 8949 §4.2.1):

| Claim | Key | Value |
|---|---|---|
| `iss` | 1 | identity's issuer |
| `sub` | 2 | the account's bare lowercase UUID |
| `aud` | 3 | one text string: the market (`MARKET_ISSUER`, in production `https://market.arkavo.com`) |
| `exp` | 4 | `iat` + 900 |
| `iat` | 6 | mint time |
| `cti` | 7 | 16 random bytes |
| `cnf` | 8 | `{1: {1: 2, -1: 1, -2: x, -3: y}}`: the app key, EC2 P-256, no `kid`, no `alg` |
| `arkavo_roles` | text | `["user"]`. Never contains `agent`, which selects the market's agent rules |
| `arkavo_account_id` | text | the same UUID as `sub`. The market reads the account from this claim |

Nothing else: no entitlement, handle, Patreon data or email. The bearer is
the account, so the market needs no entitlement from it.

## Proof of possession

Identity does not ask the app to prove the key at the mint. The market does,
on every request: the `Arkavo-Signature` header, ECDSA P-256 SHA-256 with a
64-byte `r‖s` signature by the `cnf` key (the market's contract, "Proof of
possession").

So a stolen auth CWT can mint a market token for the thief's own key. What
that buys is asking the market for a payment link in the account's name,
which someone still has to pay; it grants nothing by itself. It is the same
exposure the auth CWT already has at every other service for its hour.

## Operator notes

- No variable of its own: the route is on whenever the market is configured
  (`MARKET_ISSUER` and `MARKET_CLAIM_KEYS_PATH`), and `aud` is `MARKET_ISSUER`.
- The mint is stateless and stores nothing. One audit line per outcome names
  the account, never the token.
- Identity's clock must stay within 60 seconds of the market's, or the market
  refuses every token.

## Reference

Format, mint and a reference verifier: `authnz_rs::market_token`
(`src/market_token.rs`). Handler: `src/market/token.rs`.
