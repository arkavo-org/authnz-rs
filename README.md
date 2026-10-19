# authnz-rs

Authentication and Entitlement WebAuthn and Smart Contract

## Deployment

### Environment Variables

```env
# Server Configuration
export PORT=8443
export TLS_CERT_PATH=/path/to/fullchain.pem
export TLS_KEY_PATH=/path/to/privkey.pem

# Cryptographic Keys
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem

# DynamoDB Configuration
export DYNAMODB_CREDENTIALS_TABLE=prod-credentials
export DYNAMODB_HANDLES_TABLE=prod-handles
export DYNAMODB_AGENT_DELEGATIONS_TABLE=prod-agent-delegations
export DYNAMODB_GUARDIANS_TABLE=prod-guardians   # create the table under this name

# Sign in with Apple token revocation on account deletion (needs PATREON_KMS_KEY_ID)
export APPLE_TEAM_ID=M8GS7ZT95Y
export APPLE_SIWA_KEY_ID=<key id>
export APPLE_SIWA_PRIVATE_KEY_PATH=/path/to/AuthKey_<key id>.p8
# or the PEM itself: export APPLE_SIWA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
# (not both: setting both is rejected and revocation stays off)
export AWS_REGION=your-region
```

### DynamoDB

```shell
aws dynamodb create-table \
    --table-name credentials \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=username,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"username-index\",
            \"KeySchema\": [{\"AttributeName\":\"username\",\"KeyType\":\"HASH\"}],
            \"Projection\":{\"ProjectionType\":\"ALL\"}
        }]" \
    --billing-mode PAY_PER_REQUEST
```


## Testing

### Unit Tests

Run the unit test suite:
```shell
cargo test
```

### Integration Tests

1. Set up local DynamoDB:
```shell
docker run -p 8000:8000 amazon/dynamodb-local
```

2. Run integration tests:
```shell
export DYNAMODB_ENDPOINT=http://localhost:8000
cargo test --test '*' --features integration
```

### Manual Testing

1. Register a new user:

```shell
curl http://localhost:8080/register/testuser
```

```shell
curl -X POST http://localhost:8080/register/testuser \
  -H "Content-Type: application/json" \
  -d '{"challenge": "..."}'
```

2. Authenticate:

A `GET /authenticate` starts a ceremony, keeps it in the session and sets the
session cookie. The `POST /authenticate` that finishes it must carry that
cookie.

Without `account`, the ceremony is name-free: the options list no
credentials, and the passkey the person picks names the account. The reply
carries `"mediation":"conditional"`, a browser-autofill hint (webauthn-rs
forces it) that native clients ignore.

```shell
curl -c cookies.txt http://localhost:8080/authenticate
```

To re-authenticate a known account, limit the ceremony to its passkeys with
`account=<uuid>`. A missing or deleted account answers 500 `User Not Found`,
and an account with no passkey 500 `User Has No Credentials`. A malformed
`account` gets axum's query rejection: 400
`Failed to deserialize query string: …`.

```shell
curl -c cookies.txt "http://localhost:8080/authenticate?account=<uuid>"
```

Either start may carry an Arkavo CWT in `X-Auth-Token`:

- An expired or invalid token refuses the start with 401 `CWT error: …`.
- A valid token for another account is refused: 500 `User Not Found` at an
  account-scoped start, 403 `Passkey belongs to another account` at a
  name-free finish.
- Clients should not forward a cached token to the name-free start. A stale
  one refuses the start that should replace it, and a valid one for account
  A turns a pick of B's passkey into the 403.
- Clients must not forward a token to `?account=`. A token for another
  account there answers 500 `User Not Found`, which ArkavoKit reads as "the
  account is already deleted".

The POST body is the WebAuthn `PublicKeyCredential` the authenticator returned
for those options (`id`, `rawId`, `type`, and a `response` with
`authenticatorData`, `clientDataJSON`, `signature` and `userHandle`):

```shell
curl -b cookies.txt -X POST http://localhost:8080/authenticate \
  -H "Content-Type: application/json" \
  -d @assertion.json
```

| Status | Body | When |
|---|---|---|
| 200 | `{"token":"<CWT>","handle":"<username>"}` | The assertion verified. The CWT expires in 1 hour. |
| 400 | `{"token":""}` | Ceremony failure. The assertion did not verify (challenge, signature, origin, user verification, or a credential the account-scoped start did not list). Or a name-free assertion's user handle is missing or not a 16-byte UUID. Or an account-scoped assertion carries a user handle that is not that account's UUID. |
| 404 | `Unknown Passkey` | Name-free only. The user handle names no live account, or the account does not hold that credential id. This is decided before the signature check, and the body carries no account data. Clients remove the passkey from the device on it, so the body must not change. |
| 403 | `Passkey belongs to another account` | Name-free only. The start carried a valid `X-Auth-Token`, and the passkey's user handle names another account. Also decided before the signature check. |
| 500 | `Corrupt Session` | The session holds no open ceremony: no start, a lost cookie, or a ceremony already finished (a replayed POST). |
| 500 | `User Not Found` | Account-scoped only. The account was deleted between the start and the finish. ArkavoKit maps this text to "already deleted", so it must not change. |

A DynamoDB error at the finish answers 500 `Database operation failed: …` and
leaves the ceremony open, so the client can retry the POST. A body that is not
a `PublicKeyCredential` gets axum's JSON rejection.

Two webauthn-rs details:

- The name-free start uses `allow_backup_eligible_upgrade = false`, and the
  account-scoped start uses `true`. A passkey stored as not backup-eligible
  that now reports backup eligibility fails the name-free finish with 400,
  and the account-scoped finish accepts it.
- Neither finish saves the credential update in webauthn-rs's
  `AuthenticationResult` (signature counter, backup state). So that
  difference never heals, and clone detection compares the counter with the
  value stored at registration.

## Development

### Setup

#### Generate Cryptographic Keys

1. Create signing key (SIGN_KEY_PATH):
```shell
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem
```

2. Create encoding key (ENCODING_KEY_PATH):
```shell
openssl ecparam -genkey -noout -name prime256v1 \
    | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem
```

3. Create decoding key (DECODING_KEY_PATH):
```shell
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

4. Verify keys:
```shell
openssl ec -in signkey.pem -text -noout
openssl ec -in encodekey.pem -text -noout
openssl ec -in decodekey.pem -text -noout
```

#### Set Up DynamoDB Tables

1. Create Credentials Table:
```shell
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name credentials \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=username,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"username-index\",
            \"KeySchema\": [{\"AttributeName\":\"username\",\"KeyType\":\"HASH\"}],
            \"Projection\":{\"ProjectionType\":\"ALL\"},
            \"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}
        }]" \
    --billing-mode PAY_PER_REQUEST
```

2. Create Handles Table:
```shell
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name handles \
    --attribute-definitions \
        AttributeName=handle,AttributeType=S \
    --key-schema AttributeName=handle,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

### AWS Configuration

Configure AWS credentials using one of:

1. Environment variables:
```shell
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
```

2. AWS credentials file (~/.aws/credentials)
3. IAM role when running on AWS services
4. AWS SSO configuration

### Code Style

Format code using:
```shell
cargo fmt
```

Run clippy lints:
```shell
cargo clippy
```

### Security Considerations

1. Always use HTTPS in production
2. Keep AWS credentials secure and rotate regularly
3. Monitor DynamoDB table usage and costs
4. Consider enabling DynamoDB encryption at rest
5. Use VPC endpoints for DynamoDB in production
6. Implement proper request rate limiting
7. Monitor and log authentication attempts
8. Regularly update dependencies

## OIDC Provider

This service can act as an OpenID Connect identity provider for OpenTDF and
other relying parties.

| Endpoint                              | Purpose                                       |
| ------------------------------------- | --------------------------------------------- |
| `GET /.well-known/openid-configuration` | OIDC discovery document                     |
| `GET /.well-known/jwks.json`            | Public ES256 signing key as a JWK           |
| `GET /oauth/authorize`                  | Authorization endpoint (code flow)          |
| `POST /oauth/token`                     | Token endpoint                              |
| `GET /oauth/userinfo`                   | UserInfo endpoint                           |
| `GET /oauth/apple/nonce`                | Issue server-side nonce for Apple native flow |
| `POST /oauth/apple/idtoken`             | Native Sign in with Apple (id_token + nonce)|
| `POST /oauth/apple/link`                | Link Sign in with Apple to the signed-in account (`X-Auth-Token`); with revocation configured, also exchanges `authorization_code` and keeps the refresh token so account deletion can revoke it |
| `POST /oauth/apple/callback`            | Web-flow Apple callback — **disabled (501)** until full code-exchange + state-bound nonce land |

### App Store Creator Membership

An active App Store Creator Membership grants the same derived publishing
entitlement as a qualifying Patreon membership (see
[docs/creator-publishing-entitlement.md](docs/creator-publishing-entitlement.md)).

| Endpoint | Auth | Purpose and status codes |
| --- | --- | --- |
| `POST /app-store/transactions` | `X-Auth-Token` (passkey auth CWT of a live account) | Body `{"signed_transaction":"<StoreKit JWS>"}`. Binds the subscription to the caller and answers `{active, expires_at, environment, token_can_publish}`. `200` on success; `401` for a missing, expired or deleted-account token (re-authenticate and post again); `403` `transaction belongs to another account` (its `appAccountToken` names another live account); `409` `subscription belongs to another account` (already bound elsewhere); `422` `invalid transaction` (does not verify, wrong app, product or ownership, or no `appAccountToken`); `503` `app store purchases unavailable` (feature not configured); `500` for a storage failure. |
| `POST /app-store/notifications` | None: the signature of the App Store Server Notification V2 `signedPayload` is the only trust | Body `{"signedPayload":"<JWS>"}`. `200` for every verified payload, applied or ignored; `400` for a body or payload that does not verify or is not for this app (Apple retries); `503` when the feature is not configured; `500` for a storage failure (Apple retries). |

### Apple Sign In security gates

Every accepted Apple id_token must clear all of:

1. **Signature** against Apple's JWKS (`https://appleid.apple.com/auth/keys`),
   cached for 1 hour with force-refresh on `kid` miss.
2. **Issuer**: `iss == https://appleid.apple.com`.
3. **Audience**: `aud` must equal one of the configured `APPLE_CLIENT_ID`
   values. `APPLE_CLIENT_ID` accepts a comma-separated list so an iOS bundle
   id and a web Service ID can coexist on the same deployment.
4. **Nonce**: a server-issued nonce is **required**. For the native flow the
   client must first call `GET /oauth/apple/nonce` (session-bound, single-use,
   10-minute TTL). For `GET /oauth/authorize?idp=apple` the OIDC `nonce`
   query parameter is reused as the Apple nonce. In both cases the id_token's
   `nonce` claim must match the raw nonce verbatim *or* its hex SHA-256 (per
   Apple's recommended client-side hashing pattern). Comparison is
   constant-time.
5. **`exp`/`iat`** via `jsonwebtoken::Validation`.

The web callback (`POST /oauth/apple/callback`) is intentionally rejected
with HTTP 501 until full code-exchange (signed client-secret JWT against
Apple's `/auth/token`) and state-bound nonce verification are implemented.
This is a deliberate "fail loudly" choice: a misconfigured Apple Service ID
that posts a code-only callback returns a clear error instead of being
silently accepted.

Identity mapping is persistent: `map_apple_user` writes an `apple-<sub>` row
to the DynamoDB credentials table on first login, and every subsequent login
re-fetches the row. The Apple `sub` is the canonical account key; email is
treated as optional metadata so private-relay address rotation does not
break identity continuity.

Token claims issued for OpenTDF compatibility:

```json
{
  "iss": "https://identity.arkavo.net",
  "sub": "apple:APPLE_SUB",
  "aud": "opentdf",
  "email": "user@privaterelay.appleid.com",
  "email_verified": true,
  "idp": "apple",
  "arkavo_account_id": "uuid",
  "arkavo_roles": ["user"],
  "arkavo_entitlements": ["https://arkavo.ai/attr/tdf/value/create", "https://arkavo.ai/attr/tdf/value/decrypt"]
}
```

Configure OpenTDF to trust this issuer:

```
issuer = https://identity.arkavo.net
jwks_uri = https://identity.arkavo.net/.well-known/jwks.json
username_claim = sub
group_claim = arkavo_roles
```

### Required configuration

```env
export OIDC_ISSUER=https://identity.arkavo.net          # default

# Register one or more relying parties using tagged env vars. <TAG> is an
# operator-chosen identifier (typically the upper-cased client_id) used only
# to group each RP's three vars; it does not appear in tokens.
export OIDC_CLIENT_OPENTDF_ID=opentdf
export OIDC_CLIENT_OPENTDF_SECRET=...                           # optional; public clients use PKCE
export OIDC_CLIENT_OPENTDF_REDIRECT_URIS=https://opentdf.example/cb,https://opentdf.example/oauth/cb
# Additional RPs follow the same OIDC_CLIENT_<TAG>_{ID,SECRET,REDIRECT_URIS} pattern.
# AuthZEN PEP service accounts: docs/pep-service-clients.md
# (`catalog-node` and `mcp-edge` are registered; mint with scripts/mint-pep-cwt.py).

export APPLE_CLIENT_ID=com.arkavo.app,com.arkavo.web    # comma-separated; iOS bundle + web Service ID

# Agent NPE access tokens (spec §1): aud is required, act/minutes are optional.
# Never list the KAS (https://kas.arkavo.net) or "arkavo": startup refuses both.
export AGENT_TOKEN_AUDIENCES=https://platform.arkavo.net,https://kg.arkavo.net
export AGENT_AUTHORIZED_ACTORS=https://kg.arkavo.net
export AGENT_TOKEN_MINUTES=15   # hard cap 15
export ADMIN_CLIENT_IDS=catalog-node

# Agent credentials, appraisal and quarantine (docs/agent-credentials-contract.md v2).
export AGENT_DELEGATE_CLIENT_IDS=arkavo-edge        # may request agents:delegate
export AGENT_STATUS_CLIENT_IDS=<platform agent_status client_id>   # reads agent status
# ... and register that client (client_credentials; the redirect URI is unused):
# export OIDC_CLIENT_PLATFORMSTATUS_ID=<platform agent_status client_id>
# export OIDC_CLIENT_PLATFORMSTATUS_SECRET=...
# export OIDC_CLIENT_PLATFORMSTATUS_REDIRECT_URIS=https://identity.arkavo.net/oauth/unused
# export AGENT_OWNER_APPRAISAL_TTL_SECONDS=43200     # default 12 h, at most 24 h, from the owner's passkey tap
# export AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS=900    # default and maximum 15 min
# Without an enrolled Guardian, every agent needs an owner passkey appraisal at
# least every AGENT_OWNER_APPRAISAL_TTL_SECONDS (12 h by default) or it is
# suspended and stops minting; renew with POST /agents/{did}/appraisal (no
# entitlements resent).

# export USER_DEFAULT_ENTITLEMENTS=https://arkavo.ai/attr/tdf/value/decrypt
```

## Future Improvements

- Implement key rotation (JWKS currently exposes a single static key derived
  from `DECODING_KEY_PATH`; rotation requires multi-key issuance with overlap)
- Apple OAuth code-exchange flow (client-secret JWT signed with Apple
  developer private key)
- Persist OIDC roles/entitlements per Arkavo account (today defaults are baked
  into the upstream-auth resolution)
- Replace in-memory OIDC `AuthorizationCodeStore` with a shared store
  (DynamoDB/Redis) for multi-instance deployments
- Refresh tokens / `offline_access` scope
- Implement signature verification on the client-side
- Enhance error handling and logging for key operations
- Consider using a key management service for production environments
- Implement secure key deletion
- Add support for additional cryptographic algorithms as needed
- Implement a mechanism to revoke or update signed tokens if necessary
- Add table backups and point-in-time recovery for DynamoDB tables
- Implement DynamoDB auto-scaling policies
- Add monitoring and alerting for DynamoDB operations
- Configure DynamoDB DAX for caching if needed
- Add retries and circuit breakers for DynamoDB operations