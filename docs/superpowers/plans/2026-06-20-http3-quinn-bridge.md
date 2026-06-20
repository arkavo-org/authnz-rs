# HTTP/3 (QUIC) Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the feature-gated HTTP/3 (QUIC) server compile and route real requests through the existing Axum `Router`, alongside HTTP/2, with `Alt-Svc` advertisement.

**Architecture:** Bump the `h3`/`h3-quinn` dependency set so `h3-quinn` builds against the `quinn 0.11.9` that resolves today (clears the private-`StreamId` error and the `h3` version skew). Port the three feature-gated H3 functions in `src/main.rs` from the `h3 0.0.6` API to `0.0.8` (`accept()` → `RequestResolver::resolve_request()`, new `RequestStream<BidiStream<Bytes>, Bytes>` generics, `quinn::Endpoint::new`). Replace the stub `handle_h3_request` with a real H3→Axum bridge: collect the request body, drive the `Router` via `tower::ServiceExt::oneshot`, stream status/headers/body back over the H3 stream. Advertise `Alt-Svc: h3` from the TCP (HTTP/1.1+HTTP/2) response path when H3 is actually serving.

**Tech Stack:** Rust 1.95 (MSRV), Axum 0.7, Tower 0.5, h3 0.0.8, h3-quinn 0.0.10, quinn 0.11.9, hyper/hyper-util, rustls 0.23.

## Global Constraints

- MSRV: Rust 1.95 (`Cargo.toml` `rust-version = "1.95"`) — do not use APIs newer than this.
- The default build (no `http3` feature) and the existing HTTP/1.1 + HTTP/2 paths MUST remain byte-for-byte unchanged in behavior. All new code is `#[cfg(feature = "http3")]`-gated except the runtime-gated `Alt-Svc` layer, which is a no-op unless the `http3` feature is compiled AND `ENABLE_HTTP3` is on AND TLS is enabled.
- `Cargo.lock` is gitignored — do not attempt to commit it.
- All H3 dependency declarations stay `optional = true` under the `http3` feature.
- Do not use `--release` during development (`opt-level`/codegen settings make it slow); use plain `cargo build --features http3`.
- Verified facts (2026-06-20, `main` @ 48f9120, Rust 1.96.0 toolchain, MSRV 1.95): `h3 0.0.8` + `h3-quinn 0.0.10` (requires `h3 ^0.0.8`, `quinn ^0.11.7`) + `quinn 0.11` collapse to a single `h3 0.0.8` / `quinn 0.11.9` / `quinn-proto 0.11.13`; `h3-quinn 0.0.10` compiles cleanly against `quinn 0.11.9` (no `StreamId` error).

---

### Task 1: Bump the HTTP/3 dependency set (clears Blocker 1)

**Files:**
- Modify: `Cargo.toml:22-25` (`h3`, `h3-quinn` version strings)
- Modify: `Cargo.toml:3` (package version bump)

**Interfaces:**
- Produces: a dependency graph where `cargo tree --features http3` shows a single `h3 0.0.8`, `h3-quinn 0.0.10`, `quinn 0.11.9`.

- [ ] **Step 1: Bump the dep versions**

```toml
# HTTP/3 support (optional - enable with "http3" feature)
h3 = { version = "0.0.8", optional = true }
h3-quinn = { version = "0.0.10", optional = true }
quinn = { version = "0.11", optional = true }
```

- [ ] **Step 2: Bump the package version (new feature → minor bump)**

```toml
version = "0.7.0"
```

- [ ] **Step 3: Verify the tree collapses to a single h3**

Run: `cargo tree --features http3 2>/dev/null | grep -oE "h3 v[0-9.]+" | sort -u`
Expected: exactly `h3 v0.0.8` (one line).

- [ ] **Step 4: Verify h3-quinn compiles against quinn (the StreamId error is gone)**

Run: `cargo build --features http3 2>&1 | grep -E "StreamId|could not compile .h3-quinn"`
Expected: NO output (h3-quinn compiles; remaining errors are in `authnz-rs` itself and are fixed in Tasks 2–3).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml
git commit -m "build(http3): bump h3 0.0.8 / h3-quinn 0.0.10 to compile against quinn 0.11.9; bump to 0.7.0"
```

---

### Task 2: Port the H3 server functions to the 0.0.8 API

**Files:**
- Modify: `src/main.rs:96-103` (`quinn::Endpoint` construction in `run_h3_server`)
- Modify: `src/main.rs:123-149` (`handle_h3_connection` accept loop)
- Modify: `src/main.rs:151-155` (`handle_h3_request` signature)

**Interfaces:**
- Consumes: the bumped deps from Task 1.
- Produces: `handle_h3_request(req: http::Request<()>, stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>, app: Router)` — the exact stream type Task 3's bridge body relies on.

API changes being applied (verified against the installed crate sources):
- `quinn::Endpoint::new_with_abstract_socket(cfg, Some(scfg), socket.try_into()?, rt)` → `quinn::Endpoint::new(cfg, Some(scfg), socket, rt)` (takes `std::net::UdpSocket` directly; `new_with_abstract_socket` now requires `Arc<dyn AsyncUdpSocket>`).
- `h3_conn.accept()` now returns `Result<Option<RequestResolver<C, B>>, ConnectionError>` (was the `(Request, RequestStream)` tuple). Call `resolver.resolve_request().await` → `Result<(Request<()>, RequestStream<...>), StreamError>`.
- `RequestStream`'s first generic is the buffer type: `h3_quinn::BidiStream<bytes::Bytes>` (was `h3_quinn::BidiStream<h3_quinn::RecvStream>`).

- [ ] **Step 1: Fix the Endpoint construction in `run_h3_server`**

Replace `src/main.rs:97-103`:

```rust
    // Bind UDP socket
    let socket = std::net::UdpSocket::bind(addr)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
```

- [ ] **Step 2: Port the accept loop in `handle_h3_connection`**

Replace the body of the `loop` in `src/main.rs:130-146`:

```rust
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, app).await {
                                eprintln!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => eprintln!("HTTP/3 request resolve error: {}", e),
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("HTTP/3 accept error: {}", e);
                break;
            }
        }
    }
```

- [ ] **Step 3: Fix the `handle_h3_request` signature (buffer generic)**

Replace `src/main.rs:152-156`:

```rust
#[cfg(feature = "http3")]
async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
```

(The body is replaced by Task 3; after this step it still references the stub return.)

- [ ] **Step 4: Verify only the stub-body errors remain**

Run: `cargo build --features http3 2>&1 | grep -E "error\[|error:" | grep -v "handle_h3_request" | head`
Expected: the `Endpoint`, `accept`, and signature errors are gone. (The build may still fail inside `handle_h3_request`'s old stub body — that is fixed in Task 3.)

---

### Task 3: Implement the H3 → Axum bridge (replaces the stub)

**Files:**
- Modify: `src/main.rs:156-170` (body of `handle_h3_request`)
- Modify: `src/main.rs:25` area (add `use tower::ServiceExt;` for `oneshot`)

**Interfaces:**
- Consumes: `handle_h3_request` signature from Task 2; `app: Router` implements `Service<Request<axum::body::Body>>`.
- Produces: real HTTP responses over H3 for every route.

Bridge design (verified APIs): `RequestStream::recv_data()` → `Result<Option<impl Buf>, StreamError>`; `send_response(Response<()>)`, `send_data(Bytes)`, `finish()`. Drive the router with `tower::ServiceExt::oneshot` (error type `Infallible`). Collect the response body with `axum::body::to_bytes` (no extra dependency; auth/OIDC responses are small). Cap the request body to guard memory.

- [ ] **Step 1: Add the `oneshot` import**

Near the other `tower` imports (`src/main.rs:25-26`):

```rust
use tower::Service;
use tower::ServiceBuilder;
use tower::ServiceExt; // for Router::oneshot in the HTTP/3 bridge
```

- [ ] **Step 2: Replace the stub body of `handle_h3_request`**

Replace everything from the comment `// Convert H3 request to Axum request` through `Ok(())` (the old `src/main.rs:157-169`) with:

```rust
    use bytes::Buf;

    // 1. Collect the H3 request body into an axum Body (bounded).
    const MAX_H3_BODY: usize = 2 * 1024 * 1024; // 2 MiB — auth/OIDC payloads are tiny
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        if body_bytes.len() + remaining > MAX_H3_BODY {
            // Refuse oversized bodies rather than buffering unbounded.
            let resp = http::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
        body_bytes.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    let (parts, _) = req.into_parts();
    let axum_req = http::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    // 2. Drive the Axum router as a tower::Service (error is Infallible).
    let response = app
        .oneshot(axum_req)
        .await
        .map_err(|e| format!("router error: {e}"))?;

    // 3. Stream status + headers + body back over the H3 stream.
    let (resp_parts, resp_body) = response.into_parts();
    let h3_response = http::Response::from_parts(resp_parts, ());
    stream.send_response(h3_response).await?;

    let body_bytes = axum::body::to_bytes(resp_body, usize::MAX).await?;
    if !body_bytes.is_empty() {
        stream.send_data(body_bytes).await?;
    }
    stream.finish().await?;

    Ok(())
```

- [ ] **Step 3: Verify the http3 build now succeeds**

Run: `cargo build --features http3 2>&1 | tail -5`
Expected: `Finished ...` (no errors).

- [ ] **Step 4: Verify the default build is unchanged**

Run: `cargo build 2>&1 | tail -3`
Expected: `Finished ...` (no errors, no new warnings introduced by H3 code, which is feature-gated out).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(http3): port h3 server to 0.0.8 API and bridge H3 requests to the Axum router"
```

---

### Task 4: Advertise `Alt-Svc` + unit test + clean up the `h3_addr` move bug

**Files:**
- Modify: `src/main.rs` — add `alt_svc_header_value` helper + conditional middleware layer
- Modify: `src/main.rs:435-445` — fix the pre-existing `borrow of moved value: h3_addr` (clone before the spawned closure consumes it)
- Modify: `src/main.rs` `#[cfg(test)] mod tests` — add a unit test for the Alt-Svc helper

**Interfaces:**
- Consumes: `settings.port` for the advertised port.
- Produces: `alt_svc_header_value(port: u16) -> http::HeaderValue`.

- [ ] **Step 1: Write the failing test for the Alt-Svc helper**

Add to the `#[cfg(test)] mod tests` block in `src/main.rs`:

```rust
    #[test]
    fn alt_svc_header_advertises_h3_on_port() {
        let v = alt_svc_header_value(443);
        assert_eq!(v.to_str().unwrap(), "h3=\":443\"; ma=86400");
        let v8443 = alt_svc_header_value(8443);
        assert_eq!(v8443.to_str().unwrap(), "h3=\":8443\"; ma=86400");
    }
```

- [ ] **Step 2: Run it to confirm it fails to compile (helper undefined)**

Run: `cargo test alt_svc_header_advertises_h3_on_port 2>&1 | grep -E "cannot find function|error\[E0425\]" | head`
Expected: an error that `alt_svc_header_value` is not found.

- [ ] **Step 3: Add the helper (always compiled — it is plain axum/http, no h3 deps)**

Add near `handler_fallback` in `src/main.rs`:

```rust
/// Build the `Alt-Svc` header value advertising HTTP/3 on the given port.
fn alt_svc_header_value(port: u16) -> http::HeaderValue {
    // `ma` (max-age) is advisory; 86400s = 24h is a common, conservative value.
    http::HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", port))
        .expect("alt-svc header value is always valid ASCII")
}
```

- [ ] **Step 4: Run the test to confirm it passes**

Run: `cargo test alt_svc_header_advertises_h3_on_port 2>&1 | tail -5`
Expected: `test ... ok` / `test result: ok`.

- [ ] **Step 5: Fix the pre-existing `h3_addr` move bug and apply the layer conditionally**

In the TLS branch, fix the move (clone `h3_addr` for the `println!` after the spawn), `src/main.rs:435-446`:

```rust
            let h3_addr = format!("{}:{}", settings.bind_address, settings.port);
            let h3_app = app.clone();
            let h3_cert_path = settings.tls_cert_path.clone();
            let h3_key_path = settings.tls_key_path.clone();

            let log_addr = h3_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = run_h3_server(&h3_addr, h3_app, &h3_cert_path, &h3_key_path).await {
                    eprintln!("HTTP/3 server error: {}", e);
                }
            });
            println!("HTTP/3 (QUIC) enabled on UDP {}", log_addr);
```

Then, right after the `app` router is fully built (after the `.fallback(handler_fallback);` at `src/main.rs:424`), add the conditional Alt-Svc layer. Because the layer must wrap the same `app` that both the TCP and H3 paths clone, add it before `let addr = ...`:

```rust
    // Advertise HTTP/3 via Alt-Svc on the TCP (HTTP/1.1+HTTP/2) responses, but
    // only when H3 is actually serving: feature compiled in, runtime toggle on,
    // and TLS enabled (H3 only runs in the TLS branch). No-op for the default
    // build, keeping the non-http3 path unchanged.
    let advertise_h3 = cfg!(feature = "http3")
        && settings.tls_enabled
        && env::var("ENABLE_HTTP3").unwrap_or_else(|_| "true".to_string()) == "true";
    let app = if advertise_h3 {
        let alt_svc = alt_svc_header_value(settings.port);
        app.layer(axum::middleware::from_fn(
            move |req: Request, next: axum::middleware::Next| {
                let alt_svc = alt_svc.clone();
                async move {
                    let mut res = next.run(req).await;
                    res.headers_mut().insert(http::header::ALT_SVC, alt_svc);
                    res
                }
            },
        ))
    } else {
        app
    };
```

- [ ] **Step 6: Verify both builds and the test suite**

Run: `cargo build --features http3 2>&1 | tail -2 && cargo build 2>&1 | tail -2 && cargo test 2>&1 | tail -5`
Expected: both builds `Finished`; all tests pass.

- [ ] **Step 7: Run clippy on the http3 feature**

Run: `cargo clippy --features http3 2>&1 | grep -E "warning|error" | head`
Expected: no new warnings from the H3 code.

- [ ] **Step 8: Commit**

```bash
git add src/main.rs
git commit -m "feat(http3): advertise Alt-Svc when H3 is serving; fix h3_addr move; test alt-svc helper"
```

---

### Task 5: Manual integration verification (acceptance gate)

**Files:** none (runtime verification only).

This task is not automatable in CI (needs a QUIC-capable client and TLS certs). Document the result in the PR.

- [ ] **Step 1: Build with the feature**

Run: `cargo build --features http3`
Expected: `Finished`.

- [ ] **Step 2: Run with TLS + H3 enabled** (requires `TLS_CERT_PATH`/`TLS_KEY_PATH` and the signing keys per CLAUDE.md)

```bash
ENABLE_HTTP3=true cargo run --features http3
```

- [ ] **Step 3: Confirm Alt-Svc is advertised over HTTP/2**

Run: `curl -sI --http2 https://<host>:<port>/health | grep -i alt-svc`
Expected: `alt-svc: h3=":<port>"; ma=86400`.

- [ ] **Step 4: Confirm a real H3 round-trip** (curl built with HTTP/3 support)

Run: `curl -s --http3 https://<host>:<port>/health`
Expected: `ok` (routed through the Axum `Router`, not an empty 200 stub).

- [ ] **Step 5: Confirm an authenticated H3 round-trip**

Drive any authenticated route (e.g. an OIDC discovery / a CWT-protected endpoint) over `--http3` and confirm the real JSON body returns — proving the bridge passes headers + body, not the old stub.

---

## Acceptance criteria mapping (from issue #15)

- `cargo check/build --features http3` succeed → Tasks 1–3 (Step verifications).
- H3 handler routes through the Axum `Router`, bodies included → Task 3.
- H3 runs alongside HTTP/2 on the same `:443` (TCP+UDP) → unchanged spawn wiring + Task 2.
- `Alt-Svc` advertises HTTP/3 → Task 4.
- Real client completes an authenticated H3 round-trip → Task 5.
- Default build + HTTP/1.1+HTTP/2 unchanged → Task 3 Step 4, Task 4 `advertise_h3` runtime gate.
