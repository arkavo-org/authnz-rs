# Online-play entitlement (the Game Pass)

From 0.32.0. The entitlement is

```
https://arkavo.net/attr/network/value/online-play
```

It means the account has paid for play over the operator's network between
players who are not together. A game server checks for it in the caller's own
token. Local play never needs it.

This document covers what identity does today: the App Store source. The
market sources (prepaid terms, the lifetime membership) and a token scoped to
a game server are not built.

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
- **A market outage does not remove it.** When a linked market purchase
  cannot be checked, a mint goes without what the market would have granted
  and keeps the rest. `GET /entities/arkavo:<uuid>` still answers 503
  `market_unavailable` in that case, as before: it must not report an unknown
  as "not entitled".
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
  error at startup (`App Store app left out: …`). The other apps stay on: a
  mistake in one app's variables never ends another app's memberships.
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

## What the app does

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
