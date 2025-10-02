# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAuthn-based authentication and authorization service built with Rust, Axum, and DynamoDB. The system provides passwordless authentication using FIDO2/WebAuthn passkeys, JWT token generation, and decentralized identity (DID) support.

## Development Commands

### Build and Test
```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with clippy lints
cargo clippy

# Format code
cargo fmt
```

### Running the Server
```bash
# Set required environment variables
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem

# Optional: Set DynamoDB table names (defaults to "credentials" and "handles")
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=handles

# Optional: Set port (defaults to 8080)
export PORT=8080

# Run the server
cargo run
```

### Generate Required Cryptographic Keys
```bash
# Generate signing key for attestation envelope
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem

# Generate JWT encoding key (PKCS8 format)
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem

# Extract public key for JWT decoding
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

### DynamoDB Setup

#### Local Development
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
```

## Architecture

### Core Components

**main.rs** - Application entry point and routing
- Server configuration and TLS setup
- Axum router with WebAuthn endpoints
- Session management (10-minute timeout, in-memory store)
- OAuth callback handling for multiple providers (Patreon, Twitch, Discord, Reddit)
- Loads EC keys for JWT signing/verification and attestation envelope creation

**authn.rs** - WebAuthn authentication flow
- `start_register`: Initiates passkey registration with DID validation
- `finish_register`: Completes registration, stores credential, issues JWT
- `start_authentication`: Initiates passkey authentication
- `finish_authentication`: Verifies authentication, issues JWT
- Account token generation with 99-year registration tokens (~5148 weeks)
- Authentication tokens expire in 1 hour
- Uses attestation envelope with ECDSA signature for registration response

**db.rs** - DynamoDB persistence layer
- `UserCredentials` model: user_id, username, credentials[], did
- Username-based queries via GSI (username-index)
- Credential storage as JSON-serialized passkeys in DynamoDB list
- DID format validation (must start with "did:key:")
- Graceful handling of missing handles table during user creation

### Key Data Flow

1. **Registration Flow**:
   - Client requests `/register/:username?handle=...&did=...`
   - Validates DID format and handle consistency
   - Creates user in DynamoDB with retry logic (max 3 retries)
   - Generates WebAuthn challenge and stores registration state in session
   - Client completes WebAuthn ceremony
   - Server verifies registration via `/register` POST
   - Stores credential in DynamoDB
   - Returns attestation envelope (signed with ECDSA) + JWT in X-Auth-Token header

2. **Authentication Flow**:
   - Client sends JWT in X-Auth-Token header to `/authenticate/:username`
   - Server decodes JWT (with exp/nbf validation disabled - see Security Notes)
   - Retrieves credentials from DB or falls back to JWT payload
   - Generates WebAuthn challenge, stores auth state in session
   - Client completes WebAuthn ceremony
   - Server verifies authentication via `/authenticate` POST
   - Issues new JWT with 1-hour expiration

3. **OAuth Integration**:
   - Callback endpoint: `/oauth/:client/:provider`
   - Validates client (arkavo, arkavocreator) and provider parameters
   - Sanitizes OAuth codes and error messages to prevent injection
   - Redirects to app-specific deep links (e.g., `arkavo://oauth/patreon?code=...`)

### Security Architecture

**JWT Token Strategy**:
- **Registration tokens**: Very long-lived (~99 years via 5148 weeks)
- **Authentication tokens**: Short-lived (1 hour)
- **Validation**: exp/nbf checks disabled on purpose
  - Security relies on WebAuthn ceremony validation, not token expiration
  - Tokens are cryptographically signed with ES256 (ECDSA with P-256)

**WebAuthn Protection**:
- All authentication requires valid WebAuthn ceremony
- Passkeys stored in DynamoDB with user credentials
- Session-based state management prevents replay attacks
- Sessions expire after 10 minutes of inactivity

**Cryptographic Keys**:
- Signing key: ECDSA P-256 for attestation envelope signatures
- Encoding/Decoding keys: ES256 for JWT generation and verification
- Keys loaded from PEM files specified in environment variables

### Session Management
- Memory-based session store (MemoryStore)
- 10-minute inactivity timeout
- Strict SameSite policy
- Session keys: `reg_state` (registration), `auth_state` (authentication)
- Sessions cleaned up immediately after use to prevent reuse

### Error Handling

The codebase uses thiserror for structured error handling:
- `WebauthnError`: Authentication/registration errors with HTTP status mapping
- `DynamoDBError`: Database operation errors with table existence checks
- Errors include helpful context (e.g., "Service setup incomplete: credentials table not configured")

## Testing Patterns

- Unit tests in respective modules (main.rs has OAuth tests)
- Integration test skeleton in tests/integration_test.rs
- Test app routing with tower::ServiceExt::oneshot for request simulation
- Mock requests use axum::body::Body::empty()

## Important Constants

When modifying token lifetimes, update these in authn.rs:
- Registration token: `chrono::Duration::weeks(5148)` (~99 years)
- Authentication token: `chrono::Duration::hours(1)`
- Session timeout: `Duration::seconds(600)` (10 minutes)

## DynamoDB Schema

### credentials table
- **Primary Key**: user_id (String/UUID)
- **Attributes**: username (String), credentials (List of JSON strings), did (String)
- **GSI**: username-index (partition key: username)

### handles table
- **Primary Key**: handle (String)
- **Attributes**: did (String)
- **Format**: Handles are "{username}.arkavo.social"

## Common Development Patterns

### Adding a new WebAuthn endpoint:
1. Add route in main.rs router
2. Implement handler in authn.rs
3. Use Session for state management
4. Return WebauthnError for error handling
5. Clean up session state after completion

### Adding DynamoDB operations:
1. Implement method in DynamoDBStore (db.rs)
2. Use SdkError pattern matching for table existence checks
3. Return DynamoDBError with context
4. Log operations with info!/error! macros

### Token generation pattern:
- Use `encode(&header, &claims, &encoding_key)` with ES256 algorithm
- Include sub (user_id) and exp (expiration timestamp) in claims
- Return tokens in X-Auth-Token header or JSON response body
