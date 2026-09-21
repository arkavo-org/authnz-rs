# App Attest registration preflight — wire contract

**Status: implemented and enforcing.** `GET /device-check/register-challenge` and
`POST /device-check/register-attest` exist (Task 5, v0.11.0), and `/register` **requires** the
ticket they issue (Task 6, v0.12.0). The wire format below is what the server does, not what it
intends to do.

**Audience:** ArkavoKit, and anyone else registering users against this server.
**Plan:** `docs/superpowers/plans/2026-09-20-app-attest-registration-gate.md` (Tasks 5 and 6)
**Runbook:** `docs/app-attest-gate-deployment.md`

> **The deploy is one-way for clients.** A build that does not run this preflight cannot register
> once the enforcing version is live — there is no shadow mode. Sequence the client release
> first; see the runbook.

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

ArkavoKit is aligned to this contract as of `561fd60`: `attest_registration_cap`, matched exactly,
is the only path to a permanent verdict. Unrecognized or absent tokens stay retryable.

### Acceptance criterion for Task 5 — the JSON body is not optional

**A Task 5 that ships without JSON error bodies silently disables the client's discrimination.**
With a plain-text body the client reads no token, falls back to "retryable", and the permanent case
becomes unreachable — so a genuinely spent `key_id` is told to retry, forever, with no signal that
anything is wrong. That failure is silent on both sides: the server looks correct, the client looks
correct, and only the user is stuck.

So Task 5 is not complete when the endpoints return the right status codes. It is complete when
they return the right `error` token in a JSON body. Test it by asserting on the parsed `error`
field, never on the status alone.

---

## What a 200 from `register-attest` now means

The ticket lives in the session for **300 seconds** and is spent by exactly one `/register`
ceremony. Consequences a client must handle:

- **`GET /register/:username` answers 403** (`Device attestation required: …`) with no ticket, or
  with an expired one. It is checked before any database lookup, so the refusal is identical for
  a handle that exists and one that does not — do not read a 403 as "this handle is free".
- **The ticket must outlive the ceremony.** `POST /register` re-checks it. A user who leaves the
  passkey sheet open for more than 300s gets a 403 at the end; re-run the preflight and the
  ceremony together, not the ceremony alone.
- **One ticket, one account.** It is removed at `finish_register`, so a second registration needs
  a second attestation — and `attestKey` is once-per-key, so that means a fresh `key_id`.
- **A 403 at finish can also mean the budget was spent** by a concurrent registration between
  attest and finish. The remedy is the same: attest again. The `registrationCapExceeded` path
  already handles it.

`APP_ATTEST_APP_ID` is now **mandatory in production**: unset, `register-attest` answers
`app_id_not_configured` (503) and nobody can register at all.

## Open, and not settled by this document

- ~~**Whether macOS can be gated at all.**~~ **Settled 2026-09-20.** Creator's `rpIdHash` is
  `SHA256("M8GS7ZT95Y.com.arkavo.ArkavoCreator")`, not a CDhash: binding is per App ID, so a static
  `APP_ATTEST_APP_ID` entry pins it and both platforms are gateable. Both hashes must be in the
  set — a single value would refuse the other app outright.
- **Whether the per-key budget means anything.** `attestKey` is once-per-key, so a client mints a
  fresh `key_id` per attestation and never meets the limit. `attest_rate_limited` and
  `attest_registration_cap` are therefore near-unreachable through the normal client path today.
  They are specified because the contract must be stable before the policy is decided, not because
  the policy is decided.
