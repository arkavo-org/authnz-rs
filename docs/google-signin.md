# Sign in with Google + the ClosureKB Android client

This documents the `idp=google` path on `/oauth/authorize` and the
registration that the ClosureKB Android app (closurekb/closurekb PR #40)
asked for. Code: `src/google_signin.rs`, `src/oidc.rs`.

## Flow

```text
App (Custom Tab) ──► GET /oauth/authorize?response_type=code&client_id=closurekb-android
                       &redirect_uri=com.closurekb:/oauth2redirect&scope=openid email profile offline_access
                       &code_challenge=…&code_challenge_method=S256&state=S&nonce=N
                       &idp=google&resource=https://platform.arkavo.net
identity ──────────► validate client / redirect_uri / PKCE / scope / resource
                     park {client_id, redirect_uri, scope, S, N, challenge} in Redis under G (random)
                     307 https://accounts.google.com/o/oauth2/v2/auth?client_id=<GOOGLE_CLIENT_ID>
                       &redirect_uri=https://identity.arkavo.net/oauth/google/callback
                       &response_type=code&scope=openid email profile&state=G&nonce=Ng
Google ────────────► user picks account; 302 /oauth/google/callback?state=G&code=C
identity ──────────► take(G)  (single use, 10 min)
                     POST oauth2.googleapis.com/token  {code=C, client_id, client_secret, redirect_uri}
                     verify id_token: JWKS sig, iss, aud=GOOGLE_CLIENT_ID, nonce=Ng, exp
                     map google:<sub> → Arkavo account (credentials table, username google-<sub>)
                     307 com.closurekb:/oauth2redirect?code=<authz code>&state=S
App ───────────────► POST /oauth/token  grant_type=authorization_code … code_verifier
                     ◄ access_token (CWT), id_token (ES256 JWT), refresh_token
```

Errors after the RP request was validated go back to the RP as
`error=…&error_description=…&state=S` on its redirect URI (RFC 6749 §4.1.2.1):

| Situation                                  | `error`                 |
|--------------------------------------------|-------------------------|
| User cancelled at Google                   | `access_denied`         |
| Google id_token failed verification        | `access_denied`         |
| Code exchange or account lookup failed     | `server_error`          |
| `GOOGLE_CLIENT_ID`/`_SECRET` not set       | `temporarily_unavailable` |
| `resource` names an audience we don't mint | `invalid_target` (400 JSON, before redirect) |

An unknown/expired Google `state` on the callback is the one failure that has
no RP to report to; it returns 400 JSON on this origin.

## Server configuration

```bash
# Google Cloud Console → Credentials → OAuth client (Web application).
# Authorized redirect URI: https://identity.arkavo.net/oauth/google/callback
GOOGLE_CLIENT_ID=<…>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<…>
# GOOGLE_REDIRECT_URI defaults to <OIDC_ISSUER>/oauth/google/callback

# ClosureKB Android — public PKCE client, custom-scheme redirect (exact match)
OIDC_CLIENT_CLOSUREKB_ID=closurekb-android
OIDC_CLIENT_CLOSUREKB_REDIRECT_URIS=com.closurekb:/oauth2redirect

# Already set in production; makes every access token carry this audience.
OIDC_PLATFORM_AUDIENCE=https://platform.arkavo.net
```

No new DynamoDB tables. Google accounts are rows in the credentials table
keyed by the `google-<sub>` username, exactly like `apple-<sub>`.

## What the ClosureKB request asked for, and the answer

| Ask                                            | Status |
|------------------------------------------------|--------|
| `client_id` `closurekb-android`, public, `token_endpoint_auth_method=none` | Config above. Public clients must send PKCE S256 on the code exchange (enforced). |
| `redirect_uris` `com.closurekb:/oauth2redirect` (exact) | Config above. Exact string match; query is appended with `?` (or `&` if one exists). |
| `grant_types` `authorization_code`, `refresh_token` | Supported. `offline_access` scope ⇒ refresh token; rotated on every refresh (old one revoked). |
| `scopes` `openid email profile offline_access` | Accepted. `openid` is mandatory. |
| Google on the hosted login | `idp=google` redirects straight to Google. There is no chooser page yet; the hint parameter is `idp`, exactly as the app sends. |
| Access token CWT, `aud` includes `https://platform.arkavo.net` | Yes: `aud = [closurekb-android, https://platform.arkavo.net]` from `OIDC_PLATFORM_AUDIENCE`. |
| `resource=https://platform.arkavo.net` on authorize + token | Honoured (RFC 8707): accepted because it equals the platform audience. Any other value ⇒ `invalid_target`. |
| Access token `iss`, `sub`, `exp`, `iat`, `cti`, `email`, `email_verified`, `idp=google` | All present. `email`/`email_verified` are Google's values, and they now survive refresh (previously refreshed tokens dropped them). |
| id_token ES256, `kid` in JWKS, `aud` = client_id, `sub` stable, `email`, `email_verified` boolean, `name` optional | Yes. `sub` is `google:<google sub>`. `email_verified` is a JSON boolean. `name` is included when Google supplies it (needs `profile`). |
| Refresh response may omit `refresh_token` | We always return a rotated one; the app's keep-previous behaviour is compatible. |
| 400/401 on refresh ⇒ sign out                 | Expired/rotated/unknown refresh tokens return `400 invalid_grant`. |

### Things to tell ClosureKB when registering

1. Final `client_id` is `closurekb-android`; redirect URI stored verbatim as
   `com.closurekb:/oauth2redirect`.
2. The hint parameter is `idp=google`, as shipped. The authorize URL redirects
   directly to Google's account picker; there is no intermediate page.
3. Access tokens carry `aud = ["closurekb-android", "https://platform.arkavo.net"]`
   and `resource=https://platform.arkavo.net` is accepted on both endpoints.
4. `sub` on both tokens is `google:<sub>`; `idp` is `google`.
5. Email is whatever Google asserts; `email_verified` is passed through
   unchanged, so a Google account with an unverified address will get
   `email_verified: false` and their API will (correctly) refuse it.

### Not in scope here

- Bearer enforcement on `platform.arkavo.net/kas/v2/rewrap` (the arks shim)
  is a platform change, not an identity one.
- A hosted chooser page for requests that arrive with no `idp` and no
  credential still returns `401 login_required` JSON.
