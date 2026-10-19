# Creator Membership as an App Store subscription — design

Date: 2026-10-18. Owner request: sell the Arkavo creator-publishing membership inside Creator as an
auto-renewable subscription at $129.99/month, alongside the ~$99/month Patreon membership, so
Creator meets App Store guideline 3.1.3(b) (Creator#68). The owner skipped the design questions
("the experience is straightforward"); every decision below not attributed to the owner is
**my call**, marked so.

## What the owner decided

- Sell the membership as an in-app auto-renewable subscription; price $129.99/month (US).
- The subscription exists in App Store Connect (app 6738845556):
  - group "Arkavo Creator Membership", id `22491436`;
  - subscription id `6824320369`, product ID `com.arkavo.ArkavoCreator.membership.monthly`, 1 month;
  - Family Sharing off, single seat, App Store only;
  - all regions, Apple-equalized prices.
- Pre-release: prefer hard cutovers, no compat phases.

## The answer on ERS (arkavo-rs / opentdf-platform)

**No ERS, arkavo-rs or tdf-iroh-s3 code changes.**

- **Who enforces publishing.** Only tdf-iroh-s3 decides publishing. Its gate is an exact string
  match of `arkavo_entitlements` in the verified CWT against `[publishing] entitlement`. The
  default is `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`.
- **arkavo-rs.** It already drops that FQN from what it forwards.
- **ERS.** The platform's `identity-core` source lists it, but it is inert, and ERS/KAS never
  decide publishing.
- **The decision.** The App Store source emits the **same FQN** (my call).
- **The neutral-FQN alternative was declined.** It would have cost a config change on every
  gated node, a wider `is_derived_only` in authnz-rs, and a dual-emit rollout, all for a cosmetic
  name.
- **A side benefit of the same FQN.** Because it is in the `patreon.arkavo.com/` namespace, it is
  automatically derived-only: never stored, never delegated to agents, never in `GET /entities`.

## Facts that shape the work (from code, 2026-10-18)

- **Prod publishing is ungated today.** `POST https://iroh.arkavo.net/publish/sessions` returns
  404, so prod runs `[publishing] required = false`. Any signed-in account can publish. Until the
  gate is on, the membership unlocks nothing (rollout step R6).
- **Where authnz-rs derives the entitlement.** `publishing::derived_entitlements(app_state,
  user_id, snap)` derives it at every mint of a short-lived token: the passkey auth CWT (1 h),
  OIDC access/refresh, and the DeviceCheck assertion. It returns early when `app_state.publisher`
  (the Patreon config) is unset, so the App Store path must not sit behind that early return.
- **Tokens don't update after a purchase.** A token keeps the claims it was minted with. Creator
  has no silent re-mint: `ArkavoClient.connect` reuses a cached token, and the only forced re-mint
  is `ArkavoAuthState.reauthenticate(account:)`, one passkey prompt.
- **authnz-rs has no App Store code.** It does have reusable pieces:
  - x5c chain validation with `x509-parser` (`device_check.rs`, App Attest root);
  - ES256 verification with `p256`.
- **Creator has no StoreKit purchase code.** macOS StoreKit 2 needs no entitlement key.

## Design

### Flow

1. **Buy.** The creator, signed in to Arkavo, opens Settings → Account → Creator Membership →
   "Become a Member…", or the same button on the "Publish Error" alert. StoreKit's
   `SubscriptionStoreView` for group `22491436` shows the price, the term, auto-renew, Restore
   Purchases, and the Terms and Privacy links. The purchase carries
   `appAccountToken = UUID(token sub)`.
2. **Bind.** Creator posts the verified transaction's JWS (`jwsRepresentation`) to identity:
   `POST /app-store/transactions`. identity verifies Apple's signature, then binds
   `originalTransactionId` → the account and answers `{active, expires_at, environment}`.
   Creator calls `transaction.finish()` only after a 200.
3. **Refresh the token.** Creator prompts "Membership active. Confirm with your passkey to start
   publishing." and calls `reauthenticate(account:)`. The new token carries the publish FQN.
   - **My call:** the passkey tap is the v1 re-mint.
   - **Follow-up:** a claims-refresh that keeps the old `exp`.
4. **Renewals, lapses and refunds.** These reach identity through App Store Server Notifications V2
   at `POST /app-store/notifications`. Creator also re-posts
   `Transaction.currentEntitlements` at launch, at sign-in and on `Transaction.updates`.
5. **Mint.** At every mint the account gets the publish FQN if it qualifies through Patreon (as
   today) **or** has an active App Store record, and publishing isn't suspended.

### Rules (my calls unless noted)

- **Active.** A record counts if all of these hold:
  - `product_id` ∈ `APP_STORE_PUBLISH_PRODUCT_IDS`;
  - `environment` ∈ `APP_STORE_ENVIRONMENTS`;
  - no `revoked_at`;
  - `now < max(expires_at, grace_expires_at)`.

  Anything that fails, a lookup error included, means no entitlement (fails closed).
- **One subscription, one account.**
  - One `original_transaction_id` binds to one `user_id`, through an `identity_links` row
    `appstore#<otid>` (no new table). The first bind wins.
  - Binding it to a different account answers 409 "subscription belongs to another account".
  - Deleting the account removes its links (the existing sweep), which frees the subscription.
  - Subscription state lives in an `app_store` map on the `credentials` row. Writes are
    conditional on `LIVE_ROW`, so nothing lands on a tombstone. At mint, one consistent read
    returns both the suspension and the membership.
- **`appAccountToken` is required** (authnz-rs review). With it, a leaked transaction can't be
  claimed by another account.
  - Missing → 422 "invalid transaction".
  - Equal to the caller → bind to the caller.
  - Names a deleted or unknown account → bind to the caller. My call: a deleted account's
    still-billing subscription can move to the person's new account.
  - Names another live account → 403 "transaction belongs to another account".
- **Family Sharing.** `inAppOwnershipType` must be `PURCHASED`. Family Sharing is off on the
  product anyway.
- **Notifications.**
  - **Unknown `original_transaction_id`:** if the `appAccountToken` names a live account, bind it
    to that account; otherwise acknowledge (200) and drop it. The client post binds it later.
  - **Ordering:** an update applies only if its `signedDate` ≥ the stored `last_signed_at`. Apple
    can deliver notifications out of order.
  - **State:** the record's state always comes from the transaction snapshot (`expiresDate`,
    `revocationDate`) plus `gracePeriodExpiresDate` from the renewal info. The notification type
    is logged, not interpreted (`TEST` is acknowledged).
- **Environments.** Owner decision: prod always accepts `Production` and `Sandbox`, because App
  Review buys in Sandbox.
  - Accepted consequence: any TestFlight tester can get publishing for free, repeatedly, by buying
    in Sandbox.
  - Suspension and the content filter still apply, and every Sandbox grant is logged with
    `env=Sandbox`.
  - Production notifications must also carry `appAppleId` = `6738845556`.
  - `Xcode` and `LocalTesting` are always refused.
- **Root pin.** Apple Root CA – G3, SHA-256
  `63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179`. The value was read from the
  macOS system root keychain, so it doesn't depend on the download.
- **Signature checks** (Apple's App Store Server Library rules, verified 2026-10-18):
  - x5c has exactly 3 certificates;
  - the chain verifies leaf → intermediate → the pinned Apple Root CA – G3;
  - the leaf has the extension OID `1.2.840.113635.100.6.11.1`;
  - the intermediate has OID `1.2.840.113635.100.6.2.1`;
  - validity is checked at the payload's `signedDate`, with no online OCSP check;
  - ES256 over `header.payload` with the leaf key;
  - `bundleId` = `com.arkavo.ArkavoCreator`.
- **Account deletion.**
  - The existing sweep deletes the `appstore#` links. The tombstoned row refuses further state
    writes.
  - Apple keeps billing until the user cancels, so the Delete Account dialog adds: "If you have an
    App Store Creator Membership, it keeps renewing until you cancel it in your App Store
    subscriptions."
- **Where the client lives.** The identity call is Creator-local (`AppStoreMembershipClient`, the
  same pattern as `IrohPublisher`'s own HTTP), not ArkavoKit. That keeps an ArkavoKit tag off the
  1.1 critical path.
- **Streamlined Purchasing.** Turn it off in App Store Connect, so every purchase starts in
  Creator and carries `appAccountToken`. This is a hard precondition: identity refuses a
  transaction without `appAccountToken` (422), so there is no safety net for purchases that start
  outside Creator.

### Non-goals

- No purchase flow in the arkavo-ios viewer (ADR-0042 Decision 3 stands).
- No US-storefront external link to Patreon.
- No App Store Server API client (outbound calls, an In-App Purchase key) in v1. Notifications plus
  client posts cover state. Reconciliation through the Server API is a follow-up.
- No introductory or promotional offers. No price parity with Patreon.

## Plans

- authnz-rs: `docs/superpowers/plans/2026-10-18-app-store-membership-authnz-rs.md`, 6 tasks, version 0.20.0. It is self-contained, with its own copy of the Rules, so the authnz-rs session doesn't need this file.
- Creator: `docs/superpowers/plans/2026-10-18-app-store-membership-creator.md`, 4 tasks.
- No plan for tdf-iroh-s3, arkavo-rs, opentdf-platform or ArkavoKit.

## Rollout (owner / ops; R-steps are not code tasks)

- **R1.** Confirm prod identity has `PATREON_PUBLISHER_CAMPAIGN_ID` and `PATREON_PUBLISHER_TIER_IDS`.
  If they're unset, the Patreon path has never granted publishing either.
- **R2.** Deploy authnz-rs 0.20.0. There is no new table and no IAM change. Add env vars in
  `production/start.sh`: `APP_STORE_BUNDLE_ID=com.arkavo.ArkavoCreator`,
  `APP_STORE_APP_APPLE_ID=6738845556`,
  `APP_STORE_PUBLISH_PRODUCT_IDS=com.arkavo.ArkavoCreator.membership.monthly`.
  `APP_STORE_ENVIRONMENTS` keeps its default, `Production,Sandbox`.
  - Verify: `POST /app-store/notifications` with `{}` answers 400, not 404.
- **R3.** In App Store Connect → App Information → App Store Server Notifications, set Version 2
  with both the Production and Sandbox URL `https://identity.arkavo.net/app-store/notifications`.
  Then turn Streamlined Purchasing off. This must happen before any real sale. Last, run "Request a
  Test Notification" for Production: a 400 means Apple's TEST payload lacks `appAppleId`.
- **R4.** Creator beta (1.1-beta.14), then on TestFlight:
  - buy in Sandbox;
  - check Settings shows Active;
  - re-authenticate;
  - check the token carries the FQN (`testDiagnoseSessionTokenClaims`).
- **R5.** In App Store Connect:
  - upload the purchase-sheet screenshot to the subscription's Review Information;
  - add the subscription to the 1.1 version;
  - rewrite the App Review notes: passkey account, Sandbox purchase, and that Publish needs the
    membership.
- **R6. Done 2026-10-18 23:10 UTC.** The prod publish gate is on.
  - `POST /publish/sessions` without a token answers 401.
  - Launch template v6 is gated and is the default; v5 is the ungated rollback.
  - Only Patreon campaign 13167240 patrons on tiers 24457359, 24457368 or 24457378 can publish
    until the App Store membership ships.
  - Consequence: until then, App Review's account can't publish, and Creator offers nothing to
    buy. Submit 1.1 with the subscription, or with Publish hidden.
- **R7.** arkavo-ios docs:
  - a new ADR refining ADR-0042 Decision 1: the entitlement comes from the Arkavo Patreon
    membership **or** the Creator Membership App Store subscription; same FQN; the viewer sells
    nothing;
  - a `docs/contracts/first-release.md` row update.
- **R8.** Close Creator#68 with this decision.

Critical path for 1.1: R1 → R2 → R3 → Creator plan → R4 → R5 → submit. R6 before release.
