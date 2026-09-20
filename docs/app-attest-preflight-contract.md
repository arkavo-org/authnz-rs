# App Attest registration preflight — wire contract

**Status: specified, not implemented.** `POST /device-check/register-challenge` and
`/device-check/register-attest` return **404** today. This document pins the wire format so
ArkavoKit can code against exact values instead of guessing, and so Task 5 has one definition to
implement rather than inventing one at the keyboard.

**Audience:** ArkavoKit, and whoever implements Task 5.
**Plan:** `docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md` (Task 5)
**Runbook:** `docs/app-attest-gate-deployment.md`

> **This contract is the client's dependency, not the gate.** Task 5 makes these endpoints exist
> and issue a ticket. **Task 6** is what makes `/register` *require* one. They ship separately and
> Task 5 may land first — see "What this does not do".

---

## The two calls

Both are **unauthenticated**. That is the point: the caller has no account yet.

### 1. `GET /device-check/register-challenge`

Request: no body, no auth, no parameters.

```http
HTTP/2 200
content-type: application/json
set-cookie: authnz-rs=<id>; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=600

{"challenge": "<string>"}
```

> **The session cookie carries the state.** The challenge is held server-side against the session,
> not encoded in the value. A client that drops the cookie between the two calls gets
> `session_invalid` on the second, which reads like a server bug and is not one. Use one cookie jar
> across both calls, and across the `/register` ceremony that follows.

`challenge` is opaque. Do not parse it. Hash it as bytes:
`clientDataHash = SHA256(challenge_utf8)`.

### 2. `POST /device-check/register-attest`

```json
{
  "key_id": "<base64, from DCAppAttestService.generateKey()>",
  "attestation_object": "<standard base64, from attestKey(_:clientDataHash:)>",
  "client_data_hash": "<standard base64 of SHA256(challenge)>"
}
```

Field names and base64 flavour match the existing `AttestationRequest`
(`device_check.rs:113`) — standard base64, **not** base64url, and not padded-stripped.

```http
HTTP/2 200
content-type: application/json

{"expires_at": 1790000300}
```

`expires_at` is a Unix timestamp. The ticket itself is **server-side, in the session** — it is
never sent to the client and there is nothing to store. `expires_at` exists so the client can tell
that its window has closed without a round trip.

**One challenge, one attempt.** The challenge is consumed whether or not attestation succeeds. Any
retry starts again at call 1.

**Ticket lifetime: 300 seconds.** One-shot; spending it in `/register` consumes it.

---

## Error responses

**Every non-2xx from these two endpoints is JSON with a stable `error` code:**

```json
{"error": "attest_registration_cap", "error_description": "human text, may change"}
```

Branch on `error`. **Never branch on `error_description` or on the status code alone** — the
description is for logs and is not part of this contract.

> This is a change from the current `DeviceCheckError` rendering, which returns a plain-text body
> (`device_check.rs:815`). Task 5 must emit JSON on these two routes. Without a stable token there
> is nothing for a client to discriminate on, which is how a misconfiguration becomes a permanent
> verdict — see below.

| `error` | Status | Meaning | Client should |
|---|---|---|---|
| `attest_rate_limited` | 429 | Per-key window budget spent. `Retry-After` header carries seconds. | **Retryable.** Surface the wait. |
| `attest_registration_cap` | 403 | Lifetime cap for this `key_id`. Never clears. | **Permanent.** The only code that may mean "this key is spent". |
| `app_id_mismatch` | 400 | `rpIdHash` is not in `APP_ATTEST_APP_ID`. Wrong app, or server misconfigured. | **Retryable.** Not the user's fault. |
| `app_id_not_configured` | 503 | `APP_ATTEST_APP_ID` unset; the gate refuses to admit anything. | **Retryable.** Server misconfiguration. |
| `attestation_invalid` | 400 | Attestation failed verification. | **Retryable.** |
| `session_invalid` | 400 | No challenge in session — cookie dropped, or already consumed. | **Retryable** from call 1. |
| `attest_unavailable` | 503 | Backing store unreachable. | **Retryable.** |

### The one rule that matters

**`attest_registration_cap` is the only permanent refusal.** Everything else is retryable.

A 403 alone must not be read as permanent. `app_id_not_configured` is deliberately **503 rather
than 403** so a server misconfiguration cannot be mistaken for a barred device: at the first
enforcing deploy, an unset `APP_ATTEST_APP_ID` fails closed for *every* user simultaneously, and a
client that maps that to "this device can never register" tells the entire user base their hardware
is permanently rejected. The status code and the token both have to make that impossible.

ArkavoKit `138a82c` already matches loosely on the distinguishing word pending this document —
that match can now be tightened to exactly `attest_registration_cap`.

---

## What this does not do

Task 5 alone changes **nothing** about who may register. `/register` does not check for a ticket
until **Task 6**. In between:

- These endpoints exist and issue tickets.
- Registration remains exactly as open as it is today.
- A 200 from `register-attest` is **not** evidence that registration is protected.

That gap is deliberate — it unblocks client integration without shipping a gate whose verifier is
still missing the hardening in Tasks 1–3. Do not read it as the gate being live, and do not set
`APP_ATTEST_APP_ID` in production on the strength of Task 5 landing.

## Open, and not settled by this document

- **Whether macOS can be gated at all.** If Creator's `rpIdHash` is a CDhash it is per-build and no
  static `APP_ATTEST_APP_ID` entry pins it. Since all apps share this host and the gate is
  server-side on `/register`, the outcomes are: macOS registration stops, or a path is exempted and
  the gate provides no admission control at all. There is no third option. Decide before Task 6.
- **Whether the per-key budget means anything.** `attestKey` is once-per-key, so a client mints a
  fresh `key_id` per attestation and never meets the limit. `attest_rate_limited` and
  `attest_registration_cap` are therefore near-unreachable through the normal client path today.
  They are specified because the contract must be stable before the policy is decided, not because
  the policy is decided.
