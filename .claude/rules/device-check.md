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
- Assertion CWT carries `arkavo_npe = {type: device, class, attestation_expiry, device_id}` and, when `OIDC_PLATFORM_AUDIENCE` is set, that audience.

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
