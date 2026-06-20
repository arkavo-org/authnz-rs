# zerortt-probe

A standalone manual probe that checks whether the `authnz-rs` HTTP/3 server
offers **TLS 1.3 0-RTT (early data)**.

0-RTT early data is **replayable** by a network attacker (RFC 9001 §9.2,
RFC 8470). This service's endpoints are overwhelmingly non-idempotent (token
exchange, registration, authentication, identity linking) and have no
per-request replay protection, so 0-RTT is **deliberately disabled** on the
server:

```rust
// src/main.rs, run_h3_server()
server_config.max_early_data_size = 0; // 0 = disabled (rustls)
```

This tool verifies that decision end-to-end instead of trusting the flag.

> ⚠️ Local testing tool only: it does **not** verify the server certificate.

## Isolation

Self-contained crate (empty `[workspace]` table). It is **not** built or run by
`cargo build` / `cargo test` in the repo root. Build it explicitly:

```bash
cargo build --manifest-path tests/zerortt-probe/Cargo.toml
```

## How it works

1. Connect once (full 1-RTT handshake) so the server issues a TLS session ticket.
2. Reconnect on the same endpoint and call `quinn::Connecting::into_0rtt()`,
   which succeeds only when the client holds 0-RTT keys — and it only gets those
   if the resumed session granted early data (server `max_early_data_size != 0`).

```
Exit 0  →  RESULT: 0-RTT DISABLED   (expected, safe)
Exit 1  →  RESULT: 0-RTT AVAILABLE  (server granted/accepted early data)
```

## Usage

```
zerortt-probe [addr] [server_name]
  addr         default 127.0.0.1:8443
  server_name  SNI / cert name, default localhost
```

Bring up the server with HTTP/3 enabled (see `tests/h3-smoke-client/README.md`
for key/cert generation), then:

```bash
cargo run --manifest-path tests/zerortt-probe/Cargo.toml
# RESULT: 0-RTT DISABLED — no early-data keys; resumption falls back to 1-RTT.
```

### Confirming the probe discriminates (A/B)

To prove the probe isn't always reporting "disabled", temporarily set
`max_early_data_size = 0xffffffff` in `run_h3_server`, rebuild, and re-run — it
then reports `0-RTT AVAILABLE` / `ZeroRttAccepted = true`. Revert to `0`
afterwards.
