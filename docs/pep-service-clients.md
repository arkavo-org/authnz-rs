# PEP service clients (AuthZEN facade)

`arks` on `platform.arkavo.net` authenticates AuthZEN PEPs with a **service
CWT** from this IdP (`client_credentials`). Subject CWTs stay in SARC
`subject`; they are not the AuthZEN `Authorization` Bearer.

Probed `https://identity.arkavo.net/oauth/token` with
`grant_type=client_credentials` and **no secret**:

| `client_id` | When | HTTP | Meaning |
|---|---|---|---|
| `catalog-node` | 2026-08-27 | **401** `Invalid client credentials` | Already registered. Do **not** recreate. |
| `opentdf` | 2026-08-27 | **401** `Invalid client credentials` | Already registered. Leave it. |
| `mcp-edge` | before pid 2499 | **400** `Unknown client_id` | Was missing. |
| `mcp-edge` | after pid 2499 @ 10:38:03 | **401** `Invalid client credentials` | Restart picked up `OIDC_CLIENT_MCPEDGE_*`. |
| never-seen id | both | **400** `Unknown client_id` | Control: unknown is still 400. |

Unknown is **400**. Known-but-wrong-or-missing-secret is **401**. That split is
in `handle_client_credentials_grant` (`src/oidc.rs`).

Secret round-trip is also proven: both `catalog-node` and `mcp-edge` minted
**HTTP 200** on 2026-08-27 against pid 2499, each returning a dotless CWT with
`sub = client:<id>` and `https://platform.arkavo.net` in `aud`. Do not paste the
secret into chat, a PR, or `curl …&client_secret=…` (argv + transcript).

## What the token must look like

`POST /oauth/token` with a confidential client's secret mints:

- CWT (`access_token_format: application/cwt`), TTL 3600s
- `sub` = `client:{id}`
- `arkavo_roles` contains `service-account`
- `iss` = `https://identity.arkavo.net`
- `aud` = `[client_id, https://platform.arkavo.net]` when `OIDC_PLATFORM_AUDIENCE` is set (RFC 8707; production)
- `arkavo_entitlements` = `["tdf:create", "tdf:decrypt"]` — **hardcoded for
  every `client_credentials` token** (`src/oidc.rs`, `handle_client_credentials_grant`),
  not per-client config. So `mcp-edge` carries standing TDF decrypt entitlement
  it has no use for as a decision-point PEP. Not currently load-bearing (the
  facade gates on `service-account` in `arkavo_roles`, not on entitlements), but
  every future service account inherits it and it is invisible at registration.
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

Mint **on the identity host** so the secret never leaves the env file.
`scripts/mint-pep-cwt.py` reads `OIDC_CLIENT_<TAG>_ID` / `_SECRET`, POSTs the
form on a pipe (not argv), and prints only status metadata — not the secret
and not the token:

```sh
# on 71.179.48.230
python3 scripts/mint-pep-cwt.py catalog-node --eval
python3 scripts/mint-pep-cwt.py mcp-edge
```

**Where the env actually lives.** `docs/DEPLOYMENT_GUIDE.md` describes a
systemd deployment with `EnvironmentFile=/etc/authnz-rs/production.env`. The
current identity host is not that: it is a macOS box running authnz-rs from a
foreground `sudo ./start.sh`, with **no** `/etc/authnz-rs`, no unit file, and no
supervisor — the process does not survive a reboot or the terminal closing. Its
env source of truth is **`production/start.sh`** (gitignored). The script tries
`/etc/authnz-rs/production.env` first and falls back to `production/start.sh`,
so it works on either; `--env-file` / `AUTHNZ_ENV_FILE` override both.

Expect mint JSON:

```json
{"mint_http": 200, "token_type": "Bearer", "expires_in": 3600,
 "access_token_len": <n>, "access_token_has_dot": false, "id_token_has_dot": true}
```

`access_token_has_dot: false` is the CWT check (OIDC `id_token` is still JWT).
`--eval` then POSTs `/access/v1/evaluation` and prints
`{"eval_http": 200, "decision": true|false}` (deny is success).

Wrong secret → `mint_http: 401`. Missing env file / tag → process exits before
the POST.

## 2. `mcp-edge` — registered (pid 2499)

Env-only, loaded at process start. There is no admin API. `<TAG>` groups the
three vars and does not appear in tokens. `_REDIRECT_URIS` is required even
for `client_credentials` (parser); dummy URI is fine.

Already in the env file (`production/start.sh` on the current host) and live
since the 10:38:03 restart:

```sh
OIDC_CLIENT_MCPEDGE_ID=mcp-edge
OIDC_CLIENT_MCPEDGE_SECRET=<confidential; never paste>
OIDC_CLIENT_MCPEDGE_REDIRECT_URIS=https://identity.arkavo.net/oauth/unused
```

**Appending to `production/start.sh` with `>>` does not work.** The file ends
in `exec ./authnz-rs`, which replaces the shell — anything after it never runs,
so an appended `export` is silently dead and the client stays 400 after a
restart. Insert new registrations **above** that line. (This bit us once during
the `mcp-edge` enable; the 400→401 probe is what caught it.)

Mint the same way as catalog-node (`python3 scripts/mint-pep-cwt.py mcp-edge`).
When arkavo-edge #659 lands, that secret goes on the MCP host as
`AUTHZEN_CLIENT_SECRET` — not in `arks`.

## 3. Missing platform row (after catalog-node mint)

Prefer `scripts/mint-pep-cwt.py catalog-node --eval`, which mints and evaluates
in one process and keeps the token out of argv. The equivalent by hand, on any
host that can reach `platform.arkavo.net`:

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
`roles`). **403** `pep client not allowlisted` is the allowlist (below), now live.

**Result 2026-08-27**, run from the identity host against pid 2499:
`{"eval_http": 200, "decision": false}`. The row is green — the sidecar
accepts a `catalog-node` service CWT and returns a decision. `false` is the
expected deny for the all-zeros probe subject.

`/ws` and both rewrap paths must stay unchanged.

## 4. Facade allowlist — live

On the **platform** host (`arks`), in the file arks actually sources **above**
any `exec` (same trap as identity `production/start.sh`).
`AUTHZEN_UPSTREAM_BEARER` stays unset.

```sh
AUTHZEN_PEP_CLIENT_IDS=catalog-node,mcp-edge
```

**Result 2026-08-27:** allowlist is enforcing. `catalog-node` and `mcp-edge`
are the only client ids that get past `/access/v1/evaluation*`. Any other valid
`service-account` CWT from `identity.arkavo.net` (including `opentdf`) gets
HTTP **403** `pep client not allowlisted`.

Re-check from the identity host (keeps secrets and CWTs off argv):

```sh
python3 scripts/mint-pep-cwt.py catalog-node --eval   # 200, decision false
python3 scripts/mint-pep-cwt.py mcp-edge --eval       # 200
python3 scripts/mint-pep-cwt.py opentdf --eval        # 403
```

A user CWT / garbage Bearer stays **401** (not a PEP). Catalog `AUTHZ_PROXY`
GetDecision is a different path and must keep working — the allowlist is
AuthZEN-only.

## Do not

- Recreate `catalog-node` or rotate its secret as part of this enable (catalog
  already uses it for `AUTHZ_PROXY` GetDecision).
- Put client secrets in git, PR bodies, or `arks` env.
- Use a user / WebAuthn CWT as the AuthZEN Bearer (facade → 401).
- Point `AUTHZEN_TOKEN_URL` at `/token` (404). The path is `/oauth/token`.
