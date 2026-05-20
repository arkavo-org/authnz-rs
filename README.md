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

```shell
curl  http://localhost:8080/authenticate/testuser
```

```shell
curl -X POST http://localhost:8080/authenticate/testuser \
  -H "Content-Type: application/json" \
  -d '{"challenge": "..."}'
```

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

| Endpoint                              | Purpose                                  |
| ------------------------------------- | ---------------------------------------- |
| `GET /.well-known/openid-configuration` | OIDC discovery document                |
| `GET /.well-known/jwks.json`            | Public ES256 signing key as a JWK      |
| `GET /oauth/authorize`                  | Authorization endpoint (code flow)     |
| `POST /oauth/token`                     | Token endpoint                         |
| `GET /oauth/userinfo`                   | UserInfo endpoint                      |
| `POST /oauth/apple/idtoken`             | Native Sign in with Apple (id_token)   |
| `POST /oauth/apple/callback`            | Web-flow Sign in with Apple callback   |

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
  "arkavo_entitlements": ["tdf:create", "tdf:decrypt"]
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
export OIDC_CLIENT_ID=opentdf
export OIDC_CLIENT_SECRET=...                           # optional; public clients use PKCE
export OIDC_REDIRECT_URIS=https://opentdf.example/cb,https://opentdf.example/oauth/cb
export APPLE_CLIENT_ID=com.arkavo.app                   # only needed for Sign in with Apple
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