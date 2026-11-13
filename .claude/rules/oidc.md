---
paths:
  - "src/oidc.rs"
  - "src/main.rs"
---

# OIDC provider and the OAuth bounce

## oidc.rs: OpenID Connect (OIDC) Provider endpoints

- `/.well-known/openid-configuration`: Discovery document
- `/.well-known/jwks.json`: JWKS (advertises the EC P-256 signing key as a JWK)
- `/oauth/authorize`: Authorization endpoint (code flow with PKCE)
- `/oauth/token`: Token endpoint (issues access_token CWT + id_token JWT, both ES256-signed)
- `/oauth/userinfo`: UserInfo endpoint. Takes only an access token whose
  `aud` names a registered OIDC client (#146); any other identity CWT is 401
- Issues OpenTDF-compatible claims: `iss`, `sub` (always `arkavo:UUID` —
  one human has one account under link-only identity, so an RP sees one
  stable subject however they signed in; `idp` records which IdP was used),
  `aud`, `email`, `email_verified`, `idp`, `arkavo_account_id`,
  `arkavo_roles`, `arkavo_entitlements`
- Authorization codes stored in an in-memory `AuthorizationCodeStore` (10-min
  lifetime, single-use). For multi-instance deployments swap for a shared store.
- Confidential clients use `client_secret`; public clients must use PKCE (S256).
- Upstream authentication: WebAuthn-issued Arkavo CWT (via `X-Auth-Token`),
  Apple id_token (via `idp=apple` + `id_token` query/`X-Apple-Id-Token` header),
  or Google via server-side redirect (`idp=google`, see google_signin.rs).
- RFC 8707 `resource` on `/oauth/authorize` and `/oauth/token`: accepted when
  it names the client itself or `OIDC_PLATFORM_AUDIENCE` (both already in
  `aud`); anything else is `invalid_target` (on the client's redirect URI
  from authorize, JSON 400 from token). Omitted ⇒ unchanged behaviour.
- Public clients (no `_SECRET`) without a `code_challenge` are refused at
  authorize (`invalid_request` on the redirect URI), not just at the token
  exchange, so an upstream (Google) login is never wasted.
- Refresh tokens carry `idp`/`email`/`email_verified`/`name` from issuance so
  refreshed access tokens and id_tokens keep the same identity claims. They
  live 30 days (`REFRESH_TOKEN_LIFETIME_SECONDS`) in Redis, with that email.
- A refresh fails `invalid_grant` once the account is deleted, and, for an
  Apple or Google session, once the IdP identity it was signed in with no
  longer links to the account (`upstream_link_ended`; see
  `federated-signin.md`, `DELETE /oauth/apple/link`).

## OIDC Provider Flow (for OpenTDF and other RPs)

- Relying party (RP) redirects user-agent to `/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid&state=...&nonce=...`
- User-agent must already be authenticated via an upstream source:
  - WebAuthn: present a valid Arkavo CWT via `X-Auth-Token` header
  - Apple: pass `idp=apple` + Apple `id_token` (validated against Apple
    JWKS). The OIDC `nonce` query parameter is **required** for
    `idp=apple` and doubles as the Apple nonce — the client must use the
    same value when invoking Apple Sign In so the id_token's `nonce`
    claim matches (verbatim or hex SHA-256).
- Server resolves/provisions the Arkavo account, mints a single-use
  authorization code, redirects back to `redirect_uri` with `code` + `state`
- RP exchanges code at `/oauth/token` (HTTP Basic or form auth; PKCE for
  public clients). Server returns `access_token` (CWT, ES256) + `id_token`
  (JWT, ES256) (both 1h lifetime) with OpenTDF-compatible claims
- RP can call `/oauth/userinfo` with `Authorization: Bearer <access_token>`

## OAuth Integration

- Callback endpoint: `/oauth/:client/:provider`
- Validates client (arkavo, arkavocreator) and provider parameters
- Sanitizes OAuth codes and error messages to prevent injection
- Redirects to app-specific deep links (e.g., `arkavo://oauth/patreon?code=...`)
- Forwards the provider's `state` verbatim on both the code and the error
  redirect (`...?code=<code>&state=<state>`, #129) when it passes
  `validate_oauth_state` (1–100 ASCII alphanumerics, `-`, `_`); a malformed
  `state` bounces as `error=invalid_state` without it, an absent one as
  before. The **client** verifies `state`; the server never does (it holds
  none): a client that posts a bounced code to `POST /oauth/patreon/link`
  without comparing it can be made to link an attacker's Patreon account
