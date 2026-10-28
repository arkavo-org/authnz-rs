# Creator-publishing entitlement

Issue [#91](https://github.com/arkavo-org/authnz-rs/issues/91). Code: `src/publishing.rs`,
`src/app_store.rs`, `src/db/app_store.rs`, `src/db/publishing.rs`, `oidc::arkavo_user_claims`, `patreon::materialize_from_link`.

## Behaviour

An account may publish while it holds either of two memberships:

- its linked Patreon identity is a paying patron of Arkavo's own campaign at a
  qualifying tier; or
- it has an active App Store Creator Membership (the auto-renewable
  subscription, bought in Arkavo Creator and bound to the account through
  `POST /app-store/transactions`).

authnz-rs proves this with the entitlement

```
https://patreon.arkavo.com/attr/arkavo-creator/value/publish
```

It is the same FQN whichever source grants it, and one FQN even when both do.
The entitlement is **computed when a token is minted, and never stored**.

- **Granted when all of these hold:**
  - at least one source qualifies:
    - **Patreon**: the feature is configured, and the account's Patreon
      snapshot either lists a membership whose `campaign_id` is
      `PATREON_PUBLISHER_CAMPAIGN_ID`, whose `patron_status` is
      `active_patron`, and whose currently entitled tier IDs include at least
      one ID from `PATREON_PUBLISHER_TIER_IDS`, or **owns**
      `PATREON_PUBLISHER_CAMPAIGN_ID` (below); or
    - **App Store**: the feature is configured (`APP_STORE_*`) and a
      subscription record bound to the account is active (below);
  - the account has no publishing suspension.

  **The publisher campaign's owner qualifies** (0.21.1). That is Arkavo's own
  account, linked as the *creator* of the campaign: Patreon does not let a
  creator pledge to its own campaign, so no membership could ever qualify it.
  The owned campaign is the one Patreon reports (`campaign_id` on the
  snapshot, #99), or, while Patreon is unreachable, the one stored from its
  last answer (the 60 s owner fallback below). Owning any *other* campaign
  grants nothing, and a suspension withholds it as it does for a member.
  The two sources are independent: an account with no Patreon link, or with
  Patreon not configured at all, still gets the entitlement from an active App
  Store membership.
- **Link role does not matter.** Consumer and creator links qualify in the same
  way: every link fetches memberships with the same `/identity` call and the
  same refresh-on-401 path. A creator's `arkavo_patreon` claim keeps its owned
  `campaign_id` (and, since #128, `owned_campaign` beside it) and also lists
  its memberships. A token carries at most 75 active memberships, Arkavo's
  campaign always first, so the publish entitlement never drops. Since #99 the role is not the
  client's: it is `creator` when Patreon reports an owned campaign.
- **Where it appears:** it is appended to `arkavo_entitlements`, after the
  stored list, on:
  - the passkey auth CWT (`POST /authenticate`);
  - the DeviceCheck assertion CWT (`POST /device-check/assert`);
  - OIDC access tokens, on code exchange and on refresh.

  The OIDC `id_token` and `/oauth/userinfo` carry it too, so the three
  OIDC-facing views of `arkavo_entitlements` agree. `/oauth/userinfo` reads the
  claims of the access token it is given. The id_token is a 1-hour token minted
  in the same request from the same builder.
- **Where it never appears:**
  - the ~99-year registration token (`mint_registration_token` drops derived
    entitlements, including when an existing account adds a passkey);
  - `credentials.entitlements`. `PUT /admin/users/:id/entitlements` and
    `USER_DEFAULT_ENTITLEMENTS` refuse this FQN, so it cannot be delegated to
    agents. `GET /entities/arkavo:<uuid>` shows it only as the live
    derivation, the same one a mint makes. A copy already stored
    on a row from before this change is dropped whenever the list is read
    (tokens, agent delegation and re-mint, `/entities`), with a warning in
    the log; only the mint-time derivation can emit the FQN.
- **Fails closed.** Each source fails closed on its own. These withhold the
  **Patreon source** only; the App Store source is unaffected, so an account
  with an active App Store membership still gets the entitlement:
  - Patreon is unreachable;
  - the 3 s materialization deadline passes;
  - the snapshot is stale.

  These withhold the entitlement whichever source would have granted it:
  - the read of the account's publishing state (suspension and App Store
    records) fails;
  - the suspension record is malformed.

### App Store membership

A stored subscription record is **active** when all of these hold:

- its `product_id` is in `APP_STORE_PUBLISH_PRODUCT_IDS`;
- its `environment` is in `APP_STORE_ENVIRONMENTS`;
- it has no `revoked_at`;
- now is before the later of its `expires_at` and its `grace_expires_at`.

One active record is enough. The record's state comes from the signed
transaction (`expiresDate`, `revocationDate`) and, for the grace period, the
renewal info of App Store Server Notifications V2 (`gracePeriodExpiresDate`);
an older notification never overwrites a newer one of the same period.

- **Order.** Snapshots apply in `signedDate` order, except a newer period
  (below). Two signed in the same second apply in arrival order, except that
  one without a `revocationDate` never replaces one that has it.
- **Past periods.** Each record keeps the `transactionId` of the billing
  period it describes. A snapshot of *another* transaction that ends before
  the stored one is a past period and never changes the record: it can't
  shorten `expires_at` and can't set `revoked_at`. Apple signs a
  notification when it sends it, so a `REFUND`, `CONSUMPTION_REQUEST`,
  `REFUND_DECLINED` or `REFUND_REVERSED` of last month's transaction is
  signed after this month's renewal; without this rule it would end the
  current period, and Creator's re-post of the current transaction would be
  stale. The notification is acknowledged (`200`, logged
  `outcome=ignored=past_period`); a client post of it answers with the
  stored record, as a stale post does.
- **Newer periods.** A snapshot of *another* transaction that ends later than
  the stored one is a newer period and applies whatever its `signedDate`:
  the stored snapshot may be a later-signed one of the previous period (a
  `REFUND_DECLINED` sent after the renewal), and the renewal must not wait
  for a later signature. Every later snapshot of that period carries its
  transaction, so it follows the order above and its own refund still
  revokes. A different transaction ending at the same time as the stored one
  and every snapshot of the stored transaction, a refund of it included,
  follow the order above. A record stored before transaction ids
  were kept follows the order alone. The rule is part of the write's
  DynamoDB condition, so it holds under concurrent deliveries.
- **Environment.** A snapshot never changes a record of the other
  environment, so a Sandbox snapshot can't flip a Production record. The
  notification is acknowledged (`outcome=ignored=environment`); a client post
  answers `422 invalid transaction`.

- **Lapse.** When a subscription is not renewed, the entitlement ends at the
  first mint after `expires_at`. No notification is needed, the stored date
  decides.
- **Grace (billing retry).** While Apple retries a failed renewal and reports
  a grace period, the entitlement continues until the grace period ends.
  Without a recorded grace period there is none. Only a notification's
  renewal info sets or clears it: a notification without renewal info, and a
  client post, leave it as it is.
- **Refund or revocation.** A `revocationDate` removes the entitlement at the
  very next mint, even if `expires_at` is still in the future. The read is
  strongly consistent, so no stale index is involved. Already-issued tokens
  keep it until they expire, at most 1 hour.
- **Suspension** withholds it exactly as for Patreon.
- **Sandbox.** Owner decision: Production and Sandbox are both accepted on
  production, because App Review buys in Sandbox. TestFlight testers can
  therefore get publishing for free; suspension and the content filter still
  apply. Every Sandbox grant is logged with `env=Sandbox`, so abuse is
  visible. Set `APP_STORE_ENVIRONMENTS=Production` to refuse Sandbox. `Xcode`
  and `LocalTesting` payloads are unsigned and always refused.
- **One subscription, one account.** The subscription
  (`original_transaction_id`) is bound to one account by an `appstore#<id>`
  identity link. Deleting the account removes the link (the account-deletion
  sweep), which frees the subscription for another account.
- **Resubscribing for another account.** A lapsed subscription resubscribed
  with the same Apple ID while signed in to another account keeps its
  `original_transaction_id`. The link moves to the new account (the caller
  of `POST /app-store/transactions`, or the live account a notification's
  `appAccountToken` names) only when either holds:
  - the linked account is not live (deleted but not yet swept); or
  - the transaction is Sandbox and its `appAccountToken` names the new
    account. App Review reuses Sandbox Apple IDs with fresh accounts.

  Otherwise the link stays: a second live account posting a Production
  subscription of another live account gets `409`, and notifications keep
  feeding the linked account. A purchase whose `appAccountToken` names a
  third account never moves it (`403` while that account is live). The move
  is conditional on the previous owner, and the new owner is checked again
  after it, as a bind is. The previous owner's record is not touched; a
  Sandbox one expires on its own (Sandbox renewals take minutes). In Sandbox,
  whichever account posts a transaction bought for it holds the link.
- **Setup.** Env vars are in the table below; the client posts the
  transaction after a purchase, and App Store Server Notifications keep the
  state current. See [Deploy](#deploy).

### Lapse timing

When a membership lapses (cancelled, `declined_patron`, or moved to a tier
outside the set), the entitlement disappears at the first token mint after the
5-minute membership cache expires. Tokens already issued keep it until they
expire, which is at most 1 hour.

- There is no grace period for `declined_patron`.
- A suspension takes effect at the very next mint, because the suspension is
  read with a strongly consistent read. Already-issued tokens still keep the
  entitlement until they expire, up to 1 hour.
- Content that is already published stays up until a moderator takes it down
  (tdf-iroh-s3#17).

### Creators that must re-link

The Patreon token needs the `identity.memberships` scope to return
memberships.

- A link whose stored `patreon_tokens.scopes` lacks that scope gets no
  memberships. An owner's snapshot still carries the owned campaign, so it
  qualifies only if that campaign is `PATREON_PUBLISHER_CAMPAIGN_ID`. The
  creator must re-link (`POST /oauth/patreon/link`), and
  the app must request `identity.memberships` in the authorize step.
- An empty `scopes` value (not recorded) is still queried.
- If the creator fetch fails, or misses the 3 s mint deadline, the creator
  keeps its campaign claim with no memberships (as before creator memberships
  were fetched). That fallback is cached for 60 s
  (`PATREON_FAILURE_CACHE_TTL_SECONDS`), so a creator with a dead refresh
  token or a slow Patreon does not pay the Patreon round-trips on every mint.
  It has no memberships, so nothing membership-derived qualifies from it. A
  background fetch that later succeeds replaces it with the real snapshot.
- When a Patreon token refresh answers with an empty `scope`, or a strict
  subset of the stored scopes, the stored scopes are kept, so a creator does
  not silently stop being queried for memberships.

## Configuration

Every setting is an environment variable. In production they go in
`production/start.sh`; never commit secrets.

| Variable | Purpose |
|---|---|
| `PATREON_PUBLISHER_CAMPAIGN_ID` | Arkavo's Patreon campaign id. |
| `PATREON_PUBLISHER_TIER_IDS` | Comma-separated Patreon **tier IDs** (not titles; titles are editable, see #42) that qualify. |
| `MODERATION_CLIENT_IDS` | Comma-separated OIDC client_ids whose service CWTs may use the suspension endpoints. Empty ⇒ 403. |
| `APP_STORE_BUNDLE_ID` | Bundle id the purchase must be signed for (`com.arkavo.ArkavoCreator`). |
| `APP_STORE_APP_APPLE_ID` | The app's numeric Apple ID (`6738845556`); Production notifications must carry it. |
| `APP_STORE_PUBLISH_PRODUCT_IDS` | Comma-separated product ids that grant publishing (`com.arkavo.ArkavoCreator.membership.monthly`). |
| `APP_STORE_ENVIRONMENTS` | Optional; default `Production,Sandbox`. |

- If either `PATREON_PUBLISHER_*` variable is unset or empty, Patreon never
  grants the entitlement. If any of the first three `APP_STORE_*` variables is
  unset, the App Store never grants it and the two `/app-store/*` routes answer
  503. The sources are configured separately; with neither configured a mint
  makes no extra DynamoDB read.
- Startup logs the feature state once: `Creator publishing entitlement
  ENABLED: …` or `… DISABLED: …`. It warns when only one of the two variables
  is set.
- For the Patreon source, Patreon itself must also be configured
  (`PATREON_CLIENT_*` and `PATREON_KMS_KEY_ID`). Otherwise there is no
  snapshot and Patreon never grants it. The App Store source does not need
  Patreon.

## Suspension API

A staff operator can suspend publishing for an account whatever its
membership.

- The caller presents a service CWT in `X-Auth-Token`. This is a
  `client_credentials` access token whose client_id is on
  `MODERATION_CLIENT_IDS`. `ADMIN_CLIENT_IDS` does **not** grant access.
- `:id` is the Arkavo account UUID, which is the `arkavo_account_id` claim.

| Method | Effect | Responses |
|---|---|---|
| `PUT /admin/users/:id/publishing-suspension` | Suspend. Body `{"reason": "...", "reportId": "..."}`. `reportId` is optional. Limits: `reason` ≤ 1024 characters; `reportId` 1-128 characters of `[A-Za-z0-9._:-]` (it is written to audit log lines). | `201` with the new record. `200` with the **original** record if already suspended (a repeat never overwrites the audit record). `400` for a bad body, `401`/`403` for auth, `404` for an unknown account. |
| `DELETE /admin/users/:id/publishing-suspension` | Lift. Idempotent. A malformed stored record is still removed. | `204` (lifted, malformed record removed, or not suspended), or `404` for an unknown account. |
| `GET /admin/users/:id/publishing-suspension` | Read the suspension record. | `200` `{user_id, suspended, suspension?}`, or `404`. Returns nothing about Patreon membership: there is deliberately no Patreon status endpoint. |

The record is stored on the account's `credentials` row as the map
`publishing_suspension`, with fields `reason`, `report_id`, `suspended_by`
(`client:<id>`) and `suspended_at`. That record is the audit. Each change also
writes one log line:

```
audit publishing_suspension outcome=suspended user_id=<uuid> suspended_by=client:<id> report_id=<id|->
audit publishing_suspension outcome=already_suspended user_id=<uuid> requested_by=… suspended_by=… report_id=…
audit publishing_suspension outcome=lifted user_id=<uuid> lifted_by=… suspended_by=… suspended_at=… report_id=…
audit publishing_suspension outcome=lifted user_id=<uuid> lifted_by=… previous_record=malformed
audit publishing_suspension outcome=not_suspended user_id=<uuid> lifted_by=…
```

The free-text reason is kept in the record only. It is never written to the log.

### Example

```bash
# Service CWT for the moderation client: a client_credentials access token.
# MOD_ID / MOD_SECRET come from the env file on the identity host. The form
# goes on stdin (printf is a shell builtin), so the secret never reaches argv
# or shell history (see docs/pep-service-clients.md).
TOKEN=$(printf 'grant_type=client_credentials&client_id=%s&client_secret=%s' \
          "$MOD_ID" "$MOD_SECRET" \
        | curl -sS -X POST https://identity.arkavo.net/oauth/token --data @- \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -sS -X PUT "https://identity.arkavo.net/admin/users/$ACCOUNT_ID/publishing-suspension" \
  -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"Upheld copyright report","reportId":"rpt-2026-0412"}'

curl -sS "https://identity.arkavo.net/admin/users/$ACCOUNT_ID/publishing-suspension" \
  -H "X-Auth-Token: $TOKEN"

curl -sS -X DELETE "https://identity.arkavo.net/admin/users/$ACCOUNT_ID/publishing-suspension" \
  -H "X-Auth-Token: $TOKEN"
```

## Deploy

1. **No table changes.** The suspension and the App Store records are
   attributes on the existing `credentials` table (DynamoDB is schemaless for
   non-key attributes), the App Store links are `appstore#<id>` rows of
   `identity_links`, and no new table, GSI or IAM grant is needed.
2. Register a moderation service client, if you don't have one:
   - `OIDC_CLIENT_<TAG>_ID`, `_SECRET` and a dummy `_REDIRECT_URIS`, as
     described in `docs/pep-service-clients.md`;
   - add its client_id to `MODERATION_CLIENT_IDS`.
3. In `production/start.sh`, set:
   - `PATREON_PUBLISHER_CAMPAIGN_ID=<Arkavo campaign id>`;
   - `PATREON_PUBLISHER_TIER_IDS=<tier id>[,<tier id>…]`, taken from Patreon
     (the tier's `id`, not its title);
   - `MODERATION_CLIENT_IDS=<moderation client id>`;
   - `APP_STORE_BUNDLE_ID=com.arkavo.ArkavoCreator`,
     `APP_STORE_APP_APPLE_ID=6738845556` and
     `APP_STORE_PUBLISH_PRODUCT_IDS=com.arkavo.ArkavoCreator.membership.monthly`
     (`APP_STORE_ENVIRONMENTS` is optional; the default is
     `Production,Sandbox`).
4. Check that the Patreon apps' authorize URLs request `identity.memberships`
   for **creator** links as well as consumer links. Creators linked before that
   change must re-link.
5. Restart. Confirm that the startup log reports `Creator publishing
   entitlement ENABLED` and `App Store purchases ENABLED`.
6. Check that the notification route is live:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
     https://identity.arkavo.net/app-store/notifications \
     -H 'Content-Type: application/json' -d '{}'
   ```

   It must answer `400`. A `404` means the running binary has no such route;
   a `503` means the `APP_STORE_*` variables are not all set.
7. In App Store Connect → App Information → App Store Server Notifications,
   select Version 2 and set both the **Production** and the **Sandbox**
   Server URL to `https://identity.arkavo.net/app-store/notifications`.
8. Turn **Streamlined Purchasing** off in App Store Connect before any real
   sale. Only a purchase that starts in Creator carries `appAccountToken`, and
   identity refuses a transaction without one (`422 invalid transaction`; a
   notification for it binds to no account). There is no fallback for a
   purchase that starts on the App Store.
9. First rollout only: run "Request a Test Notification" for Production
   (App Store Server API, `POST /inApps/v1/notifications/test`). The log must
   show `app_store notification type=TEST otid=- env=Production
   outcome=ignored=no_transaction`. A `400` means the TEST payload was
   refused, for example because it lacks `appAppleId`.
10. Check end to end:
    - a qualifying account's passkey auth CWT lists the FQN in
      `arkavo_entitlements`;
    - after `PUT …/publishing-suspension`, the next auth CWT does not list it;
    - a Sandbox purchase in Creator answers `POST /app-store/transactions`
      with `"active":true`, logs `app_store transaction outcome=bound …
      env=Sandbox`, and the next auth CWT lists the FQN.

**Rollback:** unset the two `PATREON_PUBLISHER_*` variables (Patreon) and one
of the first three `APP_STORE_*` variables (App Store). No more tokens get the
entitlement from that source. Stored suspensions are harmless and can stay.
