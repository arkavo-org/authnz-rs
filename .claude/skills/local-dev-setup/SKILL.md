---
name: local-dev-setup
description: Generate the EC P-256 signing/encoding/decoding keys and create the local DynamoDB tables (credentials, handles, device_bindings, patreon_tokens, agent_delegations, device_attest_keys) needed to run authnz-rs locally.
---

# Local development setup

## Generate Required Cryptographic Keys
```bash
# Generate signing key for attestation envelope
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem

# Generate CWT/JWT encoding key (PKCS8 format)
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem

# Extract public key for CWT/JWT decoding
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

## DynamoDB Setup

### Local Development
```bash
# Start local DynamoDB
docker run -p 8000:8000 amazon/dynamodb-local

# Create credentials table
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

# Create handles table
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name handles \
    --attribute-definitions AttributeName=handle,AttributeType=S \
    --key-schema AttributeName=handle,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create device_bindings table (for Apple DeviceCheck/App Attest)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name device_bindings \
    --attribute-definitions AttributeName=device_id,AttributeType=S \
    --key-schema AttributeName=device_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create patreon_tokens table (KMS-encrypted Patreon access/refresh tokens)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name patreon_tokens \
    --attribute-definitions AttributeName=user_id,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST

# Create agent_delegations table (human PE → agent NPE delegations)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name agent_delegations \
    --attribute-definitions \
        AttributeName=agent_did,AttributeType=S \
        AttributeName=root_user_id,AttributeType=S \
    --key-schema AttributeName=agent_did,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"root_user_id-index\",
            \"KeySchema\": [{\"AttributeName\":\"root_user_id\",\"KeyType\":\"HASH\"}],
            \"Projection\":{\"ProjectionType\":\"ALL\"}
        }]" \
    --billing-mode PAY_PER_REQUEST

# Create device_attest_keys table (App Attest registration rate limiting)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name device_attest_keys \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```
