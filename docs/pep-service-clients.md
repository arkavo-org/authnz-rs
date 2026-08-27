# PEP service clients (AuthZEN facade)

`arks` on `platform.arkavo.net` authenticates AuthZEN PEPs with a **service
CWT** from this IdP (`client_credentials`). Subject CWTs stay in SARC
`subject`; they are not the AuthZEN `Authorization` Bearer.

Probed 2026-08-27 against `https://identity.arkavo.net/oauth/token`
(`grant_type=client_credentials`, no secret):

| `client_id` | HTTP | Meaning |
|---|---|---|
| `catalog-node` | **401** `Invalid client credentials` | Already registered. Retrieve the existing secret; do **not** create a second client. |
| `opentdf` | **401** `Invalid client credentials` | Already registered. Leave it. |
| `mcp-edge` | **400** `Unknown client_id` | Not registered. Add it. |
| any never-seen id | **400** `Unknown client_id` | Distinguishes unknown from "secret missing/wrong". |

Unknown is **400**. Known-but-wrong-or-missing-secret is **401**. That split is
in `handle_client_credentials_grant` (`src/oidc.rs`).

## What the token must look like

`POST /oauth/token` with a confidential client's secret mints:

- CWT (`access_token_format: application/cwt`), TTL 3600s
- `sub` = `client:{id}`
- `arkavo_roles` contains `service-account`
- `iss` = `https://identity.arkavo.net`
- `aud` = `[client_id, https://platform.arkavo.net]` when `OIDC_PLATFORM_AUDIENCE` is set (RFC 8707; production)
- no `cnf`

`OIDC_PLATFORM_AUDIENCE` on this host must stay `https://platform.arkavo.net`.
The platform sidecar's `CWTVerifier` checks that audience. The facade does not
require a single `aud`.

No static long-lived tokens. Catalog already refreshes from
`CATALOG_AUTHZ_CLIENT_SECRET` (~1h).

## 1. `catalog-node` — retrieve, do not recreate

Already in the IdP env (`OIDC_CLIENT_<TAG>_ID=catalog-node` plus `_SECRET`).
The catalog node reads the same secret as `CATALOG_AUTHZ_CLIENT_SECRET` (or
SSM `client_secret_param`). Copy it from there; do not mint a new client id.

Confirm `OIDC_PLATFORM_AUDIENCE=https://platform.arkavo.net` is set (no restart
needed to *read* it; a restart is needed only if you change it).

Mint (secret on stdin / env, not argv):

```sh
# identity.arkavo.net — uses the existing catalog-node registration
curl -sS -X POST https://identity.arkavo.net/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=catalog-node' \
  --data-urlencode "client_secret=${CATALOG_AUTHZ_CLIENT_SECRET}"
```

Expect HTTP 200, `token_type=Bearer`, `expires_in=3600`, `access_token` a
base64url CWT (no `.` JWT dots). `id_token` is still JWT (OIDC Core); PEPs
use `access_token`.

Wrong secret → 401 `Invalid client credentials`.

## 2. `mcp-edge` — register

Clients are env-only, loaded at process start. There is no admin API.
`<TAG>` groups the three vars and does not appear in tokens. `_REDIRECT_URIS`
is **required even for `client_credentials`** (parser). Use a dummy URI; this
client must not run the authorize code flow.

In `/etc/authnz-rs/production.env` (or the unit's `EnvironmentFile`):

```sh
OIDC_CLIENT_MCPEDGE_ID=mcp-edge
OIDC_CLIENT_MCPEDGE_SECRET=<generate a new confidential secret; store only in env>
OIDC_CLIENT_MCPEDGE_REDIRECT_URIS=https://identity.arkavo.net/oauth/unused
```

Restart authnz-rs. Then:

```sh
# unknown → 400 before restart; 401 without secret after restart
curl -sS -X POST https://identity.arkavo.net/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=mcp-edge'
```

Mint with `--data-urlencode "client_secret=${MCP_EDGE_CLIENT_SECRET}"` the same
way as catalog-node. Put that secret on the MCP host as `AUTHZEN_CLIENT_SECRET`
when arkavo-edge #659 lands — not in `arks`.

## 3. Missing platform row (after catalog-node mint)

On any host that can reach `platform.arkavo.net`:

```sh
curl -sS -D - -X POST https://platform.arkavo.net/access/v1/evaluation \
  -H "authorization: Bearer ${SERVICE_CWT}" \
  -H 'content-type: application/json' \
  -d '{
    "subject": {"type":"user","id":"arkavo:00000000-0000-0000-0000-000000000000"},
    "action": {"name":"read"},
    "resource": {"type":"catalog_item","id":"probe"}
  }'
```

Expect **200** and `"decision": true` or `false` (deny is success). **401**
means the CWT is not a service token the sidecar will accept (`aud` / `iss` /
`roles`). **403** will not happen until the allowlist below is set.

`/ws` and both rewrap paths must stay unchanged.

## 4. Tighten the facade allowlist

Only after both clients exist and the 200 row is green. On the **platform**
host (`arks`), not this host:

```sh
AUTHZEN_PEP_CLIENT_IDS=catalog-node,mcp-edge
```

Restart arks. A valid service CWT for some other registered client (`opentdf`)
must then be HTTP **403**. Keep `AUTHZEN_UPSTREAM_BEARER` unset.

Until that allowlist is set, any valid `service-account` CWT from this issuer
is an authenticated PEP.

## Do not

- Recreate `catalog-node` or rotate its secret as part of this enable (catalog
  already uses it for `AUTHZ_PROXY` GetDecision).
- Put client secrets in git, PR bodies, or `arks` env.
- Use a user / WebAuthn CWT as the AuthZEN Bearer (facade → 401).
- Point `AUTHZEN_TOKEN_URL` at `/token` (404). The path is `/oauth/token`.
