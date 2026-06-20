//! Minimal HTTP/3 (QUIC) smoke-test client for authnz-rs.
//!
//! macOS/dev `curl` is typically built without HTTP/3, so this client drives the
//! `--features http3` server over a real QUIC/h3 connection to confirm the
//! H3 -> Axum bridge routes real requests (see issue #15 / PR #45).
//!
//! It does NOT verify the server certificate (accepts any cert) — it is a local
//! testing tool only, intended for self-signed certs on `127.0.0.1`.
//!
//! Usage:
//!   h3-smoke-client <url> [body] [header]
//!
//!   <url>     request URL, e.g. https://127.0.0.1:8443/health  (default if omitted)
//!   [body]    optional request body. Non-empty => POST with
//!             `Content-Type: application/x-www-form-urlencoded`. Empty/omitted => GET.
//!   [header]  optional extra request header as "Name: Value", e.g. "X-Auth-Token: <cwt>"
//!
//! Examples:
//!   h3-smoke-client https://127.0.0.1:8443/health
//!   h3-smoke-client https://127.0.0.1:8443/oauth/token "grant_type=foobar"
//!   h3-smoke-client https://127.0.0.1:8443/oauth/authorize?... "" "X-Auth-Token: bad"
//!
//! Prints the response status and body to stdout; connection diagnostics to stderr.

use std::sync::Arc;

use bytes::Buf;

/// Certificate verifier that accepts everything. Local testing only — never use
/// this against a server whose identity you need to trust.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://127.0.0.1:8443/health".to_string());
    let uri: http::Uri = url.parse()?;
    let host = uri.host().unwrap_or("127.0.0.1").to_string();
    let port = uri.port_u16().unwrap_or(443);
    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse()?;

    // Non-empty arg 2 => POST that body; arg 3 => extra "Name: Value" header.
    let post_body = std::env::args().nth(2).filter(|s| !s.is_empty());
    let extra_header = std::env::args().nth(3);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_client));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    eprintln!("[client] connecting to {} (sni={})", addr, host);
    let conn = endpoint.connect(addr, &host)?.await?;
    eprintln!("[client] QUIC connected, ALPN h3 negotiated");

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    let drive = async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        eprintln!("[client] connection closed: {:?}", err);
    };

    // Optional method override via H3_METHOD (e.g. H3_METHOD=HEAD). Defaults to
    // POST when a body is given, otherwise GET.
    let method_override = std::env::var("H3_METHOD").ok();

    let request = async move {
        let method = method_override
            .clone()
            .unwrap_or_else(|| if post_body.is_some() { "POST" } else { "GET" }.to_string());
        let mut builder = http::Request::builder().method(method.as_str()).uri(&uri);
        if let Some(ref b) = post_body {
            builder = builder
                .header("content-type", "application/x-www-form-urlencoded")
                .header("content-length", b.len().to_string());
        }
        if let Some(ref h) = extra_header {
            if let Some((name, value)) = h.split_once(':') {
                builder = builder.header(name.trim(), value.trim());
            }
        }
        let req = builder.body(())?;

        let mut stream = send_request.send_request(req).await?;
        if let Some(ref b) = post_body {
            stream.send_data(bytes::Bytes::from(b.clone())).await?;
        }
        stream.finish().await?;

        let resp = stream.recv_response().await?;
        println!("STATUS: {}", resp.status());
        let mut hdrs: Vec<String> = resp
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<binary>")))
            .collect();
        hdrs.sort();
        println!("HEADERS:\n{}", hdrs.join("\n"));

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            let n = chunk.remaining();
            body.extend_from_slice(chunk.copy_to_bytes(n).as_ref());
        }
        println!(
            "BODY ({} bytes): {}",
            body.len(),
            String::from_utf8_lossy(&body)
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    tokio::select! {
        _ = drive => {}
        r = request => { r?; }
    }

    endpoint.wait_idle().await;
    Ok(())
}
