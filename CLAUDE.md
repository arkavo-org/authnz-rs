# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a WebAuthn-based authentication and authorization server written in Rust using Axum. It implements passkey registration and authentication flows with JWT token generation, EC signing, and session management.

## Required Environment Setup

Before running the server, three EC keys must be generated:

```bash
# SIGN_KEY_PATH - EC private key for signing attestations
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem

# ENCODING_KEY_PATH - PKCS8 format for JWT encoding
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem

# DECODING_KEY_PATH - Public key for JWT decoding
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

Environment variables:
```bash
export PORT=8443
export TLS_CERT_PATH=/path/to/fullchain.pem
export TLS_KEY_PATH=/path/to/privkey.pem
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem
```

TLS is optional - if `TLS_CERT_PATH` is not set, the server runs in HTTP mode.

## Commands

```bash
# Build
cargo build --release

# Run
cargo run

# Test
cargo test --verbose

# Run single test
cargo test check_addition
```

## Architecture

### Core Components

**main.rs** - Server setup and configuration
- `AppState`: Shared application state containing WebAuthn instance, account data, and cryptographic keys
- `AccountData`: In-memory storage mapping usernames to UUIDs and passkeys (no persistent database)
- Loads three EC keys: signing key (for attestations), encoding key (JWT creation), decoding key (JWT verification)
- Configures Axum routes with session middleware and TLS support

**authn.rs** - WebAuthn authentication handlers
- Implements full WebAuthn passkey registration and authentication flows
- Session-based state management for registration/authentication challenges
- JWT token generation with ES256 algorithm (ECDSA with P-256)
- Custom `AttestationEnvelope` wrapping `AccountToken` with ECDSA signature using SHA-256

### Authentication Flow

**Registration:**
1. `GET /register/:username` → `start_register()` - Creates WebAuthn challenge, stores reg_state in session
2. `POST /register` → `finish_register()` - Verifies credential, stores passkey, returns JWT in `X-Auth-Token` header and `AttestationEnvelope` in body

**Authentication:**
1. `GET /authenticate/:username` → `start_authentication()` - Accepts optional JWT in `X-Auth-Token` header to retrieve user passkey, creates challenge
2. `POST /authenticate` → `finish_authentication()` - Verifies signature, updates credential counter, returns new JWT

### Key Data Structures

- `AccountToken`: Contains user UUID, credential ID, passkey, and JWT claims (sub, exp). Serialized to JWT with 5148-week expiration for registration tokens.
- `AttestationEnvelope`: Wraps `AccountToken` with ECDSA signature over SHA-256 hash of payload, returned from registration.
- `Claims`: Standard JWT claims (sub, exp) with 1-hour expiration for authentication tokens.

### Security Notes

- Session state stored server-side in `MemoryStore` (safe from replay attacks)
- JWT validation disables `nbf` and `exp` checks during authentication token verification (see src/authn.rs:258-259)
- Credential counter updated post-authentication but not yet validated for replay protection (see FIXME at src/authn.rs:336)
- All account data stored in-memory only; no persistence layer

### WebAuthn Configuration

- Relying Party ID: `webauthn.arkavo.net`
- Relying Party Name: `Arkavo`
- Origin: `https://webauthn.arkavo.net`

### Apple App Site Association

The server serves `.well-known/apple-app-site-association` from `apple-app-site-association.json` for iOS WebAuthn integration.
