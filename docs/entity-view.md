# Entity view: a person

A person's entity view is what that account's own token would carry if it
were minted at that moment. The same builder produces both, so the two
cannot drift. Two routes serve it:

| Route | Caller | Auth |
|---|---|---|
| `GET /entities/arkavo:<uuid>` | Service resolvers (the OpenTDF platform ERS's live source, opentdf-platform#68) | Service CWT (`client_credentials`) in `X-Auth-Token`, `sub` = `client:<id>` on `ENTITY_CLIENT_IDS` ∪ `ADMIN_CLIENT_IDS` |
| `GET /entities/me` | The account itself (arkavo-ios, Creator) | Passkey auth CWT in `X-Auth-Token` |

**The subscription travels here, not in the token** (owner decision,
2026-10-27). Tokens still carry `arkavo_patreon` and the Patreon FQNs. They
drop them only after three things happen:

- the platform serves its decisions from `/entities`;
- the apps read `/entities/me`;
- iroh's v2 publish check, which reads `{role, campaign_id}` from creator
  tokens, has a replacement.

Each consumer is told before the drop.

## `GET /entities/me`

- `X-Auth-Token` must be a passkey auth CWT:
  - one from `POST /authenticate` or a session renewal (`POST /session/refresh`) is accepted;
  - the 99-year registration token, an OIDC access token, and an agent or device token are refused.
- The account row is re-read on every call. A deleted account is 401.
- `Cache-Control: no-store`.
- The body is the same as the service route's for that account. `id` is
  the canonical `arkavo:<uuid>`, never `me`.

## Body

```json
{
  "id": "arkavo:6f1c…",
  "category": "subject",
  "npe_type": null,
  "claims": {
    "sub": "arkavo:6f1c…",
    "arkavo_account_id": "6f1c…",
    "username": "alice",
    "did": "did:key:…",
    "arkavo_roles": ["user"],
    "arkavo_entitlements": ["…"],
    "arkavo_patreon": {
      "role": "consumer",
      "patreon_user_id": "123",
      "campaign_id": "456",
      "memberships": [
        {"campaign_id": "789", "patron_status": "active_patron",
         "tier_ids": ["11"], "tier_slugs": ["gold"]}
      ],
      "verified_at": 1793145600,
      "cache_expires_at": 1793145900
    }
  }
}
```

### `arkavo_entitlements`

The list a mint would put in the token: stored values plus derived ones.
The derived values are:

- the Patreon `campaign` and `campaign-tier` values, in both tier forms;
- a campaign owner's own campaign and every tier of it;
- `arkavo-creator/value/publish`;
- `creator/value/<uuid>`.

Grant from this list. Never re-derive grants from `arkavo_patreon`.

### `arkavo_patreon`

Present only when the account has a Patreon link and a snapshot.

| Key | Meaning |
|---|---|
| `role` | `creator` when Patreon reports an owned campaign, else `consumer`. |
| `patreon_user_id` | The linked Patreon user. |
| `campaign_id` | The owned campaign. Present for creators only. |
| `memberships` | Omitted when empty. Each entry has `campaign_id`, `patron_status` (absent when Patreon sent none; only `active_patron` entitles), `tier_ids`, and `tier_slugs` (omitted when empty). |
| `verified_at`, `cache_expires_at` | When the snapshot was read, and when it goes stale (Unix seconds). |

Readers must ignore keys they do not know: new keys are added without
notice.

## Errors

| Status | Body | Meaning |
|---|---|---|
| 401 | text | Missing or invalid token, a token of the wrong kind (`/entities/me`), or a deleted account (`/entities/me`). |
| 403 | text | Service route only: the caller is not on the allowlist, or is not a service account. |
| 404 | `Entity not found` | Service route only: no such account, or the account was deleted. |
| 503 | `{"error":"patreon_unavailable"}` | The account is Patreon-linked and no snapshot could be produced (cached, live or creator fallback). Keep your last answer. This is never a 200 without `arkavo_patreon`. |
| 500 / 503 | text | A DynamoDB or publishing-state read failed. The view is never sent without a value a mint would carry. |

A 200 without `arkavo_patreon` means the account has no Patreon link.
