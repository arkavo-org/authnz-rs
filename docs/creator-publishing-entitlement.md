# Creator-publishing entitlement

Issue [#91](https://github.com/arkavo-org/authnz-rs/issues/91). Code: `src/publishing.rs`,
`src/db/publishing.rs`, `oidc::arkavo_user_claims`, `patreon::materialize_from_link`.

## Behaviour

An account may publish while its linked Patreon identity is a paying patron of
Arkavo's own campaign at a qualifying tier. authnz-rs proves this with the
entitlement

```
https://patreon.arkavo.com/attr/arkavo-creator/value/publish
```

The entitlement is **computed when a token is minted, and never stored**.

- **Granted when all of these hold:**
  - the feature is configured;
  - the account's Patreon snapshot lists a membership whose `campaign_id` is
    `PATREON_PUBLISHER_CAMPAIGN_ID`, whose `patron_status` is `active_patron`,
    and whose currently entitled tier IDs include at least one ID from
    `PATREON_PUBLISHER_TIER_IDS`;
  - the account has no publishing suspension.

  Only memberships count. A staff account linked as the *creator* of Arkavo's
  campaign owns that campaign but is not a patron of it, so it does not qualify.
- **Link role does not matter.** Consumer and creator links qualify in the same
  way. Creator links now fetch memberships with the same `/identity` call and
  the same refresh-on-401 path as consumer links. A creator's `arkavo_patreon`
  claim keeps its owned `campaign_id` and now also lists its memberships.
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
    agents and does not appear in `GET /entities/:id`. A copy already stored
    on a row from before this change is dropped whenever the list is read
    (tokens, agent delegation and re-mint, `/entities`), with a warning in
    the log; only the mint-time derivation can emit the FQN.
- **Fails closed.** Any of the following withholds the entitlement:
  - Patreon is unreachable;
  - the 3 s materialization deadline passes;
  - the snapshot is stale;
  - the suspension read fails;
  - the suspension record is malformed.

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

- A creator link whose stored `patreon_tokens.scopes` lacks that scope is not
  queried. Its snapshot carries the owned campaign and no memberships, so it
  never qualifies. The creator must re-link (`POST /oauth/patreon/link`), and
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

- If either `PATREON_PUBLISHER_*` variable is unset or empty, the entitlement is
  never granted.
- Startup logs the feature state once: `Creator publishing entitlement
  ENABLED: …` or `… DISABLED: …`. It warns when only one of the two variables
  is set.
- Patreon itself must also be configured (`PATREON_CLIENT_*` and
  `PATREON_KMS_KEY_ID`). Otherwise there is no snapshot and the entitlement is
  never granted.

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

1. **No table changes.** The suspension is an attribute on the existing
   `credentials` table (DynamoDB is schemaless for non-key attributes), and no
   new table or GSI is needed.
2. Register a moderation service client, if you don't have one:
   - `OIDC_CLIENT_<TAG>_ID`, `_SECRET` and a dummy `_REDIRECT_URIS`, as
     described in `docs/pep-service-clients.md`;
   - add its client_id to `MODERATION_CLIENT_IDS`.
3. In `production/start.sh`, set:
   - `PATREON_PUBLISHER_CAMPAIGN_ID=<Arkavo campaign id>`;
   - `PATREON_PUBLISHER_TIER_IDS=<tier id>[,<tier id>…]`, taken from Patreon
     (the tier's `id`, not its title);
   - `MODERATION_CLIENT_IDS=<moderation client id>`.
4. Check that the Patreon apps' authorize URLs request `identity.memberships`
   for **creator** links as well as consumer links. Creators linked before that
   change must re-link.
5. Restart. Confirm that the startup log reports `Creator publishing
   entitlement ENABLED`.
6. Check end to end:
   - a qualifying account's passkey auth CWT lists the FQN in
     `arkavo_entitlements`;
   - after `PUT …/publishing-suspension`, the next auth CWT does not list it.

**Rollback:** unset the two `PATREON_PUBLISHER_*` variables. No more tokens get
the entitlement. Stored suspensions are harmless and can stay.
