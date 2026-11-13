---
paths:
  - "src/device_check.rs"
  - "src/registration_gate_tests.rs"
---

## Apple DeviceCheck Implementation Details

### Security Guarantees
- **Hardware-backed keys**: Secure Enclave generates per-app, per-device keys
- **Certificate chain validation**: Attestation anchored to Apple's root CA
- **Replay protection**: Monotonic counter must increment with each assertion
- **Nonce binding**: Challenge bound to attestation/assertion via SHA256
- **Device verification**: Proves request comes from genuine Apple device running unmodified app
- Assertion CWT carries `arkavo_npe = {type: device, class, attestation_expiry, device_id, app_id_hash?, app_env?}` and, when `OIDC_PLATFORM_AUDIENCE` is set, that audience.
  `app_id_hash` (lowercase hex `rpIdHash`) only while `APP_ATTEST_APP_ID` accepts it;
  `app_env` (`production`|`development`, from the aaguid) only on bindings attested since #114.

### Requirements
- iOS 14+ with Secure Enclave support
- Entitlement: `com.apple.developer.devicecheck.appattest-environment` (development or production)
  on iOS/visionOS/tvOS; macOS grants `com.apple.developer.devicecheck.app-attest-opt-in`
  instead and has **no sandbox** — every Mac attestation is a production one
- Not available in iOS Simulator

### Known Limitations
- Re-attesting an existing `key_id` under the same account resets `counter` to
  0, which reopens a replay window for assertions captured before the
  re-attest (bindings can no longer be repointed to a *different* account —
  `create_device_binding` writes conditionally)
- The per-`key_id` registration budget bounds a **key, not a device** — see the
  `device_attest_keys` schema note. Admission control is the attestation itself.

### Integration with NTDF
The device binding can be used as the NPE (non-person entity) device/app proof key, enabling:
- Device-bound CWT tokens (proof-of-possession via `cnf` claim, RFC 8747)
- Hardware-backed attestation for NTDF authorization
- Per-device, per-app cryptographic binding to user credentials

## device_check.rs: Apple DeviceCheck/App Attest integration

- `register_challenge` / `register_attest` (**unauthenticated**, Task 5): the registration
  preflight. `GET /device-check/register-challenge` issues a challenge into the session;
  `POST /device-check/register-attest` verifies the attestation, checks the registration budget
  (advisory — takes no slot) and puts a one-shot `RegistrationTicket` (300s) in the session.
  Errors on these two routes are **JSON with a stable `error` token**, unlike the rest of
  `DeviceCheckError`, so a client can tell a permanent refusal (`attest_registration_cap`) from a
  retryable one. See [docs/app-attest-preflight-contract.md](docs/app-attest-preflight-contract.md).
  **The ticket gates registration** (Task 6): `start_register` refuses without one and
  `finish_register` consumes it, so one attestation buys exactly one account.
- `generate_challenge`: Issues random challenge for attestation (**requires a
  CWT bound to `:username`** — App Attest proves the device is genuine, never
  which account it belongs to)
- `verify_attestation(challenge, key_id, attestation_object_b64, client_data_hash_b64, &VerifyOptions)`:
  the shared verifier. Returns `AttestedKey { key_id, public_key, rp_id_hash_str, counter }`.
  `VerifyOptions.expected_app_ids` is a **set** (more than one app registers users);
  `require_app_id` decides whether an empty set warns (bound-device path) or refuses with
  `AppIdNotConfigured` (registration gate). Both paths share this one implementation — never
  write a second copy.
- `finish_attestation`: Calls `verify_attestation`, stores device binding
- `generate_assertion_challenge`: Issues challenge for existing devices (requires CWT)
- `finish_assertion`: Verifies assertion, enforces counter increment, issues CWT
- CBOR attestation object parsing ("apple-appattest" format). Apple sends **camelCase** keys
  (`attStmt`, `authData`), so the deserialization structs carry
  `#[serde(rename_all = "camelCase")]` — without it every genuine attestation fails at CBOR
  decode with `missing field att_stmt`, before any verification runs.
- Certificate chain validation: every signature from the leaf up to the pinned Apple
  App Attest root is verified, validity windows are enforced, and a leaf-only chain is
  refused (Apple always sends an intermediate). `validate_certificate_chain_at` takes the
  validity instant so the fixture tests pin the capture time; **production always passes
  `ASN1Time::now()`** — the parameter is not a way to disable expiry checking.
- Nonce binding: `SHA256(authData || clientDataHash)` is compared against the credCert's
  `1.2.840.113635.100.8.2` extension. This is what binds an attestation to the challenge
  the server issued; without it a captured attestation replays against any later one.
- Key binding: the caller-supplied `key_id` must be exactly the padded standard base64 of
  SHA256 of the credCert's **uncompressed EC point** (not the DER SPKI), and authData's
  `credentialId` must equal that hash. `key_id` keys the registration budget and the device
  binding, so an unbound one would let a genuine attestation be filed under any key.
- aaguid must be `appattest` or `appattestdevelop` on every server — not environment-selected,
  since macOS emits `appattest` even from a dev build and `rpIdHash` already pins the app.
  These checks run **before** the nonce compare: any tamper to them also breaks the nonce, and
  a check shadowed by `NonceMismatch` cannot be tested.
- Assertions (`verify_assertion`): a CBOR map `{signature, authenticatorData}` with a **DER**
  signature, never `authData || r‖s`. The signature is ECDSA-SHA256 over
  `nonce = SHA256(authData || clientDataHash)`, so the digest is `SHA256(nonce)`; `rpIdHash`
  must equal the binding's `app_id`. The counter is checked only after both pass. A real
  device's attest + first minted assert is pinned in `tests/fixtures/appattest/assertion.json`
  (#17, Mac, 2026-10-26); the synthetic tests build assertions the way the Secure Enclave does.
- Monotonic counter enforcement for replay protection
- Public key extraction and storage: a binding's `public_key` is the credCert's **DER
  SubjectPublicKeyInfo**. Every reader (`verify_assertion`, `cwt::cnf_from_app_attest`) parses
  DER, never a bare SEC1 point (#118: the mint parsed SEC1 and 401'd every real device).

## Apple DeviceCheck/App Attest Flow

- **One-time Attestation**:
  - Client requests challenge: `GET /device-check/challenge/:username`
    (**requires `X-Auth-Token`**: a CWT whose `sub` resolves to `:username`)
  - Server generates random UUID challenge, stores it in session together
    with the *authenticated* user_id — the binding is written against that,
    never against the path parameter
  - Client generates Secure Enclave key via `DCAppAttestService.generateKey()`
  - Client computes clientDataHash = SHA256(challenge)
  - Client performs attestation: `DCAppAttestService.attestKey(keyId, clientDataHash)`
  - Client POSTs attestation object to `/device-check/attest`
  - Server validates:
    - CBOR format is "apple-appattest"
    - Certificate chain anchors to Apple's root CA
    - `rpIdHash` equals `APP_ATTEST_APP_ID` when that env var is set
    - aaguid is `appattest` or `appattestdevelop`
    - `key_id` and authData `credentialId` both equal SHA256(credCert public key)
    - Nonce = SHA256(authData || clientDataHash)
    - Counter is 0 (initial attestation)
  - Server stores device binding: device_id, public_key, counter=0, user_id
- **Ongoing Assertions**:
  - Client requests assertion challenge: `GET /device-check/assert-challenge/:username` (requires CWT)
  - Server issues fresh challenge, validates CWT token
  - Client signs challenge with device key
  - Client POSTs assertion to `/device-check/assert`
  - Server validates:
    - Device binding exists **and belongs to the session's authenticated user**
    - Counter has incremented (counter > stored_counter)
    - Challenge matches expected hash
    - Signature is valid (verified against the stored public key)
  - Server updates counter, issues new CWT (aud `arkavo:devicecheck`).
    Its `arkavo_npe` names the app (#114): `app_id_hash` is the binding's
    `rpIdHash` (lowercase hex), present only while `APP_ATTEST_APP_ID`
    accepts it; `app_env` is `production` (aaguid `appattest`) or
    `development` (`appattestdevelop`), stored on the binding at attest.
    A binding from before #114 has no `app_env` and mints none until the
    device attests a new key. `GET /entities/device:<key_id>` carries the
    same two fields (`device_check::device_app_claims`).
