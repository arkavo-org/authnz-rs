//! Manual probe: does the HTTP/3 server offer TLS 1.3 0-RTT (early data)?
//!
//! 0-RTT early data is replayable by a network attacker (RFC 9001 §9.2,
//! RFC 8470), so this service disables it (`src/main.rs`:
//! `max_early_data_size = 0`). This tool verifies that end-to-end:
//!
//! 1. Connect once (full 1-RTT handshake) to obtain a session ticket.
//! 2. Reconnect on the same endpoint and attempt 0-RTT via
//!    `quinn::Connecting::into_0rtt`. That returns `Ok` only when the client
//!    holds 0-RTT keys, which it gets only if the resumed session granted early
//!    data — i.e. the server's rustls `max_early_data_size` was non-zero.
//!
//! Exit code 0 = 0-RTT DISABLED (the expected, safe state); 1 = 0-RTT AVAILABLE.
//! It does NOT verify the server certificate (local testing tool only).
//!
//! Usage: `zerortt-probe [addr] [server_name]`
//!   addr         default `127.0.0.1:8443`
//!   server_name  SNI / cert name, default `localhost`

use std::sync::Arc;
use std::time::Duration;

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
    let addr: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".to_string())
        .parse()?;
    let server_name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".to_string());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // The client WANTS 0-RTT: it keeps early-data keys whenever the server's
    // session ticket grants them. (Default resumption store is in-memory.)
    tls.enable_early_data = true;

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);

    // --- Connection 1: full handshake, collect a session ticket. ---
    eprintln!(
        "[1] connecting to {} (sni={}) for a session ticket...",
        addr, server_name
    );
    let conn1 = endpoint.connect(addr, &server_name)?.await?;
    eprintln!("[1] handshake complete; waiting for NewSessionTicket...");
    // Hold the connection open so the server's post-handshake ticket arrives and
    // is stored in the client's resumption cache.
    tokio::time::sleep(Duration::from_millis(500)).await;
    conn1.close(0u32.into(), b"done");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- Connection 2: attempt 0-RTT on resumption. ---
    eprintln!("[2] reconnecting and attempting 0-RTT (early data)...");
    let connecting = endpoint.connect(addr, &server_name)?;
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            println!(
                "RESULT: 0-RTT AVAILABLE — client holds early-data keys (server granted early data)."
            );
            let was_accepted = accepted.await;
            println!(
                "       ZeroRttAccepted = {} (server {} the 0-RTT data)",
                was_accepted,
                if was_accepted { "ACCEPTED" } else { "rejected" }
            );
            conn.close(0u32.into(), b"done");
            endpoint.wait_idle().await;
            std::process::exit(1);
        }
        Err(_connecting) => {
            println!(
                "RESULT: 0-RTT DISABLED — no early-data keys; resumption falls back to 1-RTT."
            );
            endpoint.wait_idle().await;
            std::process::exit(0);
        }
    }
}
