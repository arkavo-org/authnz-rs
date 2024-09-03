# authnz-rs

Authentication and Entitlement WebAuthn and Smart Contract

## Getting Started

### Prerequisites

#### Create keys

SIGN_KEY_PATH

```shell
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem
```

ENCODING_KEY_PATH

```shell
openssl ecparam -genkey -noout -name prime256v1 \
    | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem
```

DECODING_KEY_PATH

```shell
openssl ec -in encodekey.pem -pubout -out decodekey.pem
```

#### Verify keys

```shell
openssl ec -in signkey.pem -text -noout
openssl ec -in encodekey.pem -text -noout
openssl ec -in decodekey.pem -text -noout
```

## Usage

```env
export PORT=8443
export TLS_CERT_PATH=/path/to/fullchain.pem
export TLS_KEY_PATH=/path/to/privkey.pem
export SIGN_KEY_PATH=/path/to/signkey.pem
export ENCODING_KEY_PATH=/path/to/encodekey.pem
export DECODING_KEY_PATH=/path/to/decodekey.pem
```

## Notes

The next steps to further improve the server:

- Implement key rotation
- Add an endpoint to retrieve public keys
- Implement signature verification on the client-side
- Enhance error handling and logging for key operations
- Consider using a key management service for production environments
- Implement secure key deletion
- Add support for additional cryptographic algorithms as needed
- Implement a mechanism to revoke or update signed tokens if necessary
