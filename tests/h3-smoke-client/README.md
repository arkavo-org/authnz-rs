# h3-smoke-client

A minimal standalone HTTP/3 (QUIC) client for **manually** exercising the
`authnz-rs` server's HTTP/3 path (the `http3` Cargo feature). It exists because
the `curl` shipped on macOS/most dev machines is built without HTTP/3, so there
is otherwise no easy way to drive a real h3 round-trip against the server.

It is the acceptance-gate tool for [issue #15] / PR #45 (the H3 → Axum bridge).

> ⚠️ This client **does not verify the server certificate** — it accepts any
> cert so it works with the self-signed certs used in local testing. It is a
> testing tool, not a general-purpose client.

## Isolation

This is a self-contained crate (its `Cargo.toml` has an empty `[workspace]`
table). It is **not** built or run by `cargo build` / `cargo test` in the
repo root, and `tests/<subdir>/` projects are not picked up as integration
tests (only `tests/*.rs` files are). Build it explicitly:

```bash
cargo build --manifest-path tests/h3-smoke-client/Cargo.toml
```

## Usage

```
h3-smoke-client <url> [body] [header]
```

- `<url>` — request URL (default `https://127.0.0.1:8443/health`)
- `[body]` — optional request body. Non-empty ⇒ `POST` with
  `Content-Type: application/x-www-form-urlencoded`. Empty/omitted ⇒ `GET`.
- `[header]` — optional extra request header, `"Name: Value"`
  (e.g. `"X-Auth-Token: <cwt>"`).

The request method defaults to `POST` when a body is given, otherwise `GET`.
Override it with the `H3_METHOD` env var, e.g. `H3_METHOD=HEAD` to confirm a
HEAD response carries headers (incl. `Content-Length`) but no body.

It prints the response status, headers, and body to stdout.

## Running the full gate

Bring up the server with HTTP/3 enabled (see the repo `CLAUDE.md` for key
generation; a self-signed cert on `127.0.0.1` is fine):

```bash
# keys + self-signed cert (example)
openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem
openssl ecparam -genkey -noout -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out encodekey.pem
openssl ec -in encodekey.pem -pubout -out decodekey.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout privkey.pem -out fullchain.pem -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo '{"applinks":{"apps":[],"details":[]}}' > apple-app-site-association.json

# run the server (http3)
SIGN_KEY_PATH=signkey.pem ENCODING_KEY_PATH=encodekey.pem DECODING_KEY_PATH=decodekey.pem \
TLS_CERT_PATH=fullchain.pem TLS_KEY_PATH=privkey.pem \
BIND_ADDRESS=127.0.0.1 PORT=8443 ENABLE_HTTP3=true OIDC_ISSUER=https://localhost:8443 \
cargo run --features http3
```

Then, from another shell:

```bash
C="cargo run --quiet --manifest-path tests/h3-smoke-client/Cargo.toml --"

# real Axum response over H3 (not the old empty-200 stub)
$C https://127.0.0.1:8443/health
# real JSON body streamed over H3
$C https://127.0.0.1:8443/.well-known/openid-configuration
# status passthrough
$C https://127.0.0.1:8443/nonexistent
# request body reaches the handler (400 unsupported_grant_type vs 422 for empty)
$C https://127.0.0.1:8443/oauth/token "grant_type=foobar"
# auth-gated handler executes over H3, custom header carried
$C "https://127.0.0.1:8443/oauth/authorize?response_type=code&client_id=foo&redirect_uri=https://x/cb&scope=openid&state=s" "" "X-Auth-Token: bad"
```

To confirm `Alt-Svc` advertisement over HTTP/2 (system curl is fine for this):

```bash
curl -ksI --http2 https://127.0.0.1:8443/health | grep -i alt-svc
# alt-svc: h3=":8443"; ma=86400
```

[issue #15]: https://github.com/arkavo-org/authnz-rs/issues/15
