# authnz-rs

Authentication and Entitlement WebAuthn and Smart Contract

## Getting Started

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
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=dev-handles
export AWS_REGION=your-region
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
curl -X POST https://localhost:8443/register/testuser \
  -H "Content-Type: application/json" \
  -d '{"challenge": "..."}'
```

2. Authenticate:
```shell
curl -X POST https://localhost:8443/authenticate/testuser \
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

## Future Improvements

- Implement key rotation
- Add an endpoint to retrieve public keys
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