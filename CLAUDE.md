# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAuthn-based authentication and authorization service built with Rust, Axum, and DynamoDB. The system provides passwordless authentication using FIDO2/WebAuthn passkeys, JWT token generation, and decentralized identity (DID) support.

**Protocol Support**: HTTP/1.1, HTTP/2 with TLS 1.3 (HTTP/3 infrastructure ready but disabled due to dependency issues)

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

#### Development (HTTP)
```bash
# Set required environment variables
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem

# Optional: Set DynamoDB table names
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=handles
export DYNAMODB_DEVICE_BINDINGS_TABLE=device_bindings

# Optional: Set port (defaults to 8080)
export PORT=8080

# Run the server
cargo run
```

#### Production (HTTPS)
```bash
# Set bind address and port
export BIND_ADDRESS=192.0.2.6  # Specific IP to bind to (defaults to 0.0.0.0 if not set)
export PORT=443

# Set TLS certificate paths
export TLS_CERT_PATH=/etc/letsencrypt/live/identity.arkavo.net/fullchain.pem
export TLS_KEY_PATH=/etc/letsencrypt/live/identity.arkavo.net/privkey.pem

# Set required cryptographic keys
export SIGN_KEY_PATH=/etc/authnz-rs/keys/signkey.pem
export ENCODING_KEY_PATH=/etc/authnz-rs/keys/encodekey.pem
export DECODING_KEY_PATH=/etc/authnz-rs/keys/decodekey.pem

# DynamoDB configuration
export DYNAMODB_CREDENTIALS_TABLE=credentials
export DYNAMODB_HANDLES_TABLE=handles
export DYNAMODB_DEVICE_BINDINGS_TABLE=device_bindings
export AWS_REGION=us-east-1

# Run the server
cargo run --release
```

For complete production deployment instructions, see [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md).

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

# Create device_bindings table (for Apple DeviceCheck/App Attest)
aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name device_bindings \
    --attribute-definitions AttributeName=device_id,AttributeType=S \
    --key-schema AttributeName=device_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

## Architecture

### Core Components

**main.rs** - Application entry point and routing
- Server configuration with optional TLS/HTTPS support (rustls)
- TLS enabled when TLS_CERT_PATH or TLS_KEY_PATH environment variables are set
- Axum router with WebAuthn endpoints
- Session management (10-minute timeout, in-memory store)
- OAuth callback handling for multiple providers (Patreon, Twitch, Discord, Reddit)
- Loads EC keys for JWT signing/verification and attestation envelope creation
- WebAuthn RP origin: `https://identity.arkavo.net` (main.rs:84-85)

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
- `DeviceBinding` model: device_id, user_id, public_key, counter, app_id, timestamps
- Username-based queries via GSI (username-index)
- Credential storage as JSON-serialized passkeys in DynamoDB list
- DID format validation (must start with "did:key:")
- Graceful handling of missing handles table during user creation
- Device binding CRUD operations for App Attest

**device_check.rs** - Apple DeviceCheck/App Attest integration
- `generate_challenge`: Issues random challenge for attestation/assertion
- `finish_attestation`: Validates attestation object, stores device binding
- `generate_assertion_challenge`: Issues challenge for existing devices (requires JWT)
- `finish_assertion`: Verifies assertion, enforces counter increment, issues JWT
- CBOR attestation object parsing ("apple-appattest" format)
- Certificate chain validation to Apple's root CA
- Nonce calculation: SHA256(authData || SHA256(clientData))
- Monotonic counter enforcement for replay protection
- Public key extraction and storage

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

4. **Apple DeviceCheck/App Attest Flow**:
   - **One-time Attestation**:
     - Client requests challenge: `GET /device-check/challenge/:username`
     - Server generates random UUID challenge, stores in session
     - Client generates Secure Enclave key via `DCAppAttestService.generateKey()`
     - Client computes clientDataHash = SHA256(challenge)
     - Client performs attestation: `DCAppAttestService.attestKey(keyId, clientDataHash)`
     - Client POSTs attestation object to `/device-check/attest`
     - Server validates:
       - CBOR format is "apple-appattest"
       - Certificate chain anchors to Apple's root CA
       - Nonce = SHA256(authData || clientDataHash)
       - Counter is 0 (initial attestation)
       - rpIdHash matches expected App ID
     - Server stores device binding: device_id, public_key, counter=0, user_id
   - **Ongoing Assertions**:
     - Client requests assertion challenge: `GET /device-check/assert-challenge/:username` (requires JWT)
     - Server issues fresh challenge, validates JWT token
     - Client signs challenge with device key
     - Client POSTs assertion to `/device-check/assert`
     - Server validates:
       - Device binding exists
       - Counter has incremented (counter > stored_counter)
       - Challenge matches expected hash
       - Signature is valid (TODO: implement signature verification)
     - Server updates counter, issues new JWT (1-hour expiration)

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
- **TLS Keys** (optional, for HTTPS):
  - `TLS_CERT_PATH`: X.509 certificate chain in PEM format (fullchain.pem)
  - `TLS_KEY_PATH`: Private key in PEM format (privkey.pem)
  - If omitted, server runs over unencrypted HTTP
- **WebAuthn/JWT Keys** (required):
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
- `DeviceCheckError`: App Attest validation errors (attestation, assertion, counter, certificate chain)
- Errors include helpful context (e.g., "Service setup incomplete: credentials table not configured")

## Testing Patterns

- Unit tests in respective modules:
  - `main.rs`: OAuth callback validation, provider parsing, input sanitization (9 tests)
  - `authn.rs`: DID validation, handle validation, token expiration, error responses (5 tests)
  - `db.rs`: DID format, error conversions, JSON serialization, error messages (8 tests)
  - `device_check.rs`: Challenge generation, authenticator data parsing, counter validation, error responses (6 tests)
- Integration test skeleton in tests/integration_test.rs
- Test app routing with tower::ServiceExt::oneshot for request simulation
- Mock requests use axum::body::Body::empty()
- Critical test coverage focuses on:
  - Security: DID format validation, handle/username matching
  - Error handling: All error types and conversions
  - Data integrity: JSON serialization roundtrips
  - Configuration: Token expiration constants

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

### device_bindings table
- **Primary Key**: device_id (String) - Key ID from App Attest
- **Attributes**:
  - user_id (String/UUID) - Links to UserCredentials
  - public_key (Binary) - Attested public key from certificate
  - counter (Number) - Monotonic counter for replay protection
  - app_id (String) - rpIdHash for App ID validation
  - created_at (Number) - Unix timestamp
  - updated_at (Number) - Unix timestamp (updated on each assertion)

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

### Adding Apple DeviceCheck endpoints:
1. Add route in main.rs router (e.g., `/device-check/...`)
2. Implement handler in device_check.rs
3. Use Session for challenge storage (attest_state/assert_state keys)
4. Return DeviceCheckError for error handling
5. Validate attestation format, certificate chain, counter, nonce
6. Store device bindings in DynamoDB device_bindings table
7. Enforce monotonic counter increments for assertions

## Apple DeviceCheck Implementation Details

### Security Guarantees
- **Hardware-backed keys**: Secure Enclave generates per-app, per-device keys
- **Certificate chain validation**: Attestation anchored to Apple's root CA
- **Replay protection**: Monotonic counter must increment with each assertion
- **Nonce binding**: Challenge bound to attestation/assertion via SHA256
- **Device verification**: Proves request comes from genuine Apple device running unmodified app

### Requirements
- iOS 14+ with Secure Enclave support
- Entitlement: `com.apple.developer.devicecheck.appattest-environment` (development or production)
- Not available in iOS Simulator

### Known Limitations
- Certificate chain validation is incomplete (TODO: implement full chain verification)
- Signature verification not implemented (TODO: verify assertion signatures with stored public key)
- Does not validate certificate extension 1.2.840.113635.100.8.2 (nonce)

### Integration with NTDF
The device binding can be used as the NPE (non-person entity) device/app proof key, enabling:
- Device-bound JWT tokens (proof-of-possession similar to DPoP)
- Hardware-backed attestation for NTDF authorization
- Per-device, per-app cryptographic binding to user credentials
