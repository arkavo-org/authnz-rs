# Online-play entitlement (the Game Pass)

From 0.32.0. The entitlement is

```
https://arkavo.net/attr/network/value/online-play
```

It means the account has paid for play over the operator's network between
players who are not together. A game server checks for it in the caller's own
token. Local play never needs it.

Three sources grant it: an App Store product (0.32.0), a prepaid term bought
at the market, and a linked market lifetime membership (both 0.33.0). A token
scoped to a game server is not built.

## Rules

- **Its own path.** Only a source configured to grant online play grants it.
  Nothing that grants creator publishing grants it, and an online-play
  purchase never grants publishing.
- **Derived at mint, never stored.** It is computed when a token is minted,
  like the publishing entitlement
  ([creator-publishing-entitlement.md](creator-publishing-entitlement.md)).
  The whole attribute `https://arkavo.net/attr/network/` is derived-only: it
  is refused in a stored entitlement list, so it cannot be delegated to an
  agent.
- **Only in tokens that expire within an hour.** The passkey auth CWT, the
  DeviceCheck CWT and OIDC access tokens carry it in `arkavo_entitlements`.
  The registration token never does, and no longer-lived credential may (a
  peer certificate, #143): a lapsed pass must stop within the hour.
- **A publishing suspension does not remove it.** The suspension is about
  publishing; the pass is paid network access.
- **A market outage withholds only what the market would have granted.** A
  mint always succeeds and keeps what the other sources grant. Two cases
  differ for `GET /entities/arkavo:<uuid>`:
  - a linked **membership claim** that cannot be checked, with no other
    publishing source: 503 `market_unavailable`, as before (it must not
    report an unknown publishing answer as "not entitled");
  - a **subscription lookup** that fails: 200 without the online-play value.
    No decision path reads the pass from `/entities`, and the lookup runs
    for every account, so an outage must not fail that route for everyone.
- `GET /entities/arkavo:<uuid>` lists it while it holds, because a person's
  entity is the live view of a fresh mint.

## The App Store source

A product grants exactly one entitlement. Which one is configuration:

| Variable | Purpose |
|---|---|
| `APP_STORE_BUNDLE_ID`, `APP_STORE_APP_APPLE_ID`, `APP_STORE_PUBLISH_PRODUCT_IDS`, `APP_STORE_ENVIRONMENTS` | The first app, unchanged: its products grant creator publishing. |
| `APP_STORE_ONLINE_PLAY_PRODUCT_IDS` | Optional. Products of the first app that grant online play. |
| `APP_STORE_<TAG>_BUNDLE_ID` | A further app's bundle id. `<TAG>` is the operator's choice (letters, digits, `_`) and appears in no token. |
| `APP_STORE_<TAG>_APP_APPLE_ID` | That app's numeric Apple ID; its Production notifications must carry it. |
| `APP_STORE_<TAG>_PUBLISH_PRODUCT_IDS` | Optional. That app's products that grant creator publishing. |
| `APP_STORE_<TAG>_ONLINE_PLAY_PRODUCT_IDS` | Optional. That app's products that grant online play. |
| `APP_STORE_<TAG>_ENVIRONMENTS` | Optional; default `Production,Sandbox`. With `Sandbox` accepted, TestFlight and App Review purchases grant the entitlement at no charge; each such grant is logged with `env=Sandbox`. |

- An app needs its bundle id, its Apple ID and at least one product.
- A bundle id belongs to one app, and so does a product id. A stored record
  names its product, and the product names the app and the entitlement.
- A product may not be in both lists.
- A tagged app that breaks one of these rules is left out and logged as an
  error at startup (`App Store app left out: …`). The first app always keeps
  its bundle id and products. Two tagged apps that share a bundle id or a
  product id are **both** left out: a new app's variables can never take over
  an existing app's purchases, but a clash does stop both until it is fixed,
  so read the startup log after adding an app.
- Startup logs one `App Store purchases ENABLED` line per app, with its
  count of publish and online-play products.

Example, a game beside the first app:

```bash
export APP_STORE_GAME_BUNDLE_ID=com.example.game
export APP_STORE_GAME_APP_APPLE_ID=1234567890
export APP_STORE_GAME_ONLINE_PLAY_PRODUCT_IDS=com.example.game.pass.monthly
```

In App Store Connect, set that app's App Store Server Notifications V2 URL
(Production and Sandbox) to `https://<identity>/app-store/notifications`, the
same route every app uses.

## The market source: prepaid terms

The market sells prepaid terms of the pass and records which account each is
for. Identity stores nothing about them: at each mint it asks the market
about the account. Contract: arkavo-com/market
`docs/market-identity-interface.md`, "Account lookups (subscriptions)".

| Variable | Purpose |
|---|---|
| `MARKET_ISSUER`, `MARKET_CLAIM_KEYS_PATH`, `MARKET_ACCEPT_TEST_MODE` | As for the lifetime membership: the market's base URL, the pinned claim keys, and whether test-mode claims are accepted. |
| `MARKET_LOOKUP_TOKEN` | The secret identity sends as `Authorization: Bearer`. The same value as `IDENTITY_LOOKUP_TOKEN` in the market's `commerce.env`: at least 32 printable ASCII characters, no spaces. Unset, or set but unusable ⇒ no lookup (startup log line; the value is never logged). |

**Setting `MARKET_LOOKUP_TOKEN` turns the lookup on for every human mint.**

```
GET <MARKET_ISSUER>/subscriptions/<account uuid>
Authorization: Bearer <MARKET_LOOKUP_TOKEN>
Accept: application/json
```

The account id is the bare lowercase UUID, never the `arkavo:` OIDC `sub`.

| The market answers | Identity |
|---|---|
| `200` with a claim that verifies | grants online play |
| `404` | grants nothing: no term covers now |
| `200` with a claim that does not verify, `401`, `429`, `5xx`, a redirect, a timeout, a network error | a failure: grants nothing, and is never taken for "none" |

A claim verifies when it is signed by a pinned claim key (`alg` ES256, `typ`
JWT), its `iss` is `MARKET_ISSUER`, its `aud` is `OIDC_ISSUER`, its `sub` is
the account identity asked about, its `tier` is `online-play`, and its
`livemode` is `true` (or test mode is accepted). The body's `until` is not
signed and is not used. A membership claim never verifies as a lookup answer,
and a lookup answer never links as a membership.

How the lookup is kept from slowing sign-in or hiding a payment:

- **Not asked when an App Store pass already grants.**
- **Cache**, per account, in process: an answer (`200` or `404`) 5 minutes, a
  failure 60 seconds.
- **Circuit breaker.** After a failure no account is asked for 60 seconds,
  then one mint probes. Meanwhile the answer is unknown for accounts with
  nothing cached, and a cached "active" still grants. An outage costs one
  3-second deadline a minute, not one per sign-in.
- **A renewal rechecks a cached "none".** `POST /session/refresh`, a passkey
  sign-in and the OIDC refresh grant ask the market again when the cached
  answer is "none", at most 6 times a minute per account. So the refresh an
  app makes after a payment is not answered from before it. The market's
  payment search lags a payment by a minute or more, so the app should keep
  renewing for about that long (every 10 seconds fits the budget).
- **One deadline.** The lookup runs beside the membership claim check and
  Patreon; a mint waits for the slowest, never for each in turn.
- A `401` means the two tokens differ. It is logged as an error (`market
  subscription lookup refused (401)`) and treated as an outage. To rotate,
  change both sides and restart identity.

Lapse: at most about an hour and five minutes after a term ends (the cache,
then the token's life).

## The lifetime membership

A market lifetime membership linked to the account
([creator-publishing-entitlement.md](creator-publishing-entitlement.md))
covers every paid entitlement, so it grants online play as well as
publishing. The two stay separate paths:

- a publishing suspension withholds publishing and leaves online play;
- the membership's claim is checked whenever it can still decide either
  entitlement, so also for a suspended account and for one whose App Store
  membership already grants publishing;
- `POST /market/link` lists both values in `entitlements`.

When the market cannot be reached, a lifetime member's mint goes without
both until it answers again (60 seconds of failure cache at most between
tries).

## What the app does (App Store)

Exactly what an app does for a publishing membership:

1. Buy with `appAccountToken` set to the account's UUID (the bare `sub` of
   its passkey auth CWT). A purchase without one is refused.
2. `POST /app-store/transactions` with `X-Auth-Token` (the passkey auth CWT)
   and `{"signed_transaction": "<StoreKit 2 JWS>"}`.
3. The answer is `{active, expires_at, environment, entitlement,
   token_can_publish}`. `entitlement` is the attribute FQN the product
   grants; `active` says whether the stored record grants it now.
4. Renew the session (`POST /session/refresh`) or sign in again. The new
   token carries the entitlement in `arkavo_entitlements`.

What is checked on a transaction:

- its `bundleId` is a configured app;
- its `productId` is one of **that** app's products (another app's product
  id under this bundle is refused);
- its environment is one that app accepts;
- the rest as before: Apple's signature chain, a direct purchase, the
  account it names.

A notification is checked against its own app's Apple ID, and its nested
transaction must be that app's.

## Lapse

A record grants while it is not revoked and now is before the later of its
expiry and any billing-retry grace Apple's notifications recorded. After
that the next mint goes without the entitlement, so a lapsed pass stops
within the life of the last token: one hour.
