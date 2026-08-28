//! Seeds a fixed test user row directly in DynamoDB (Local, via
//! `AWS_ENDPOINT_URL_DYNAMODB`, or otherwise) and mints the CWTs
//! `tests/agent_flow.rs` needs against a running `authnz-rs` server.
//!
//! Output contract (deliberately stdout/file split so CI's
//! `> human.cwt` capture isn't corrupted by a second line):
//!   - the human CWT is printed to stdout only (`AUTHNZ_TEST_HUMAN_CWT`)
//!   - a service CWT (`arkavo_roles: ["service-account"]`) is written to
//!     `service.cwt` in the current directory (`AUTHNZ_TEST_SERVICE_CWT`)
//!
//! Usage: seed-test-user --encoding-key <pem-path> --decoding-key <pem-path> --issuer <issuer-url>

use authnz_rs::{constants, cwt, keys};
use aws_sdk_dynamodb::types::AttributeValue;
use uuid::Uuid;

/// Fixed test user — must match `tests/agent_flow.rs` and the CI/local-run
/// instructions in the task brief.
const TEST_USER_ID: &str = "00000000-0000-0000-0000-0000000000aa";
const TEST_USERNAME: &str = "it-user";
const TEST_DID: &str = "did:key:z6Mkit";

const USAGE: &str = "usage: seed-test-user --encoding-key <pem-path> --decoding-key <pem-path> --issuer <issuer-url>";

fn usage_error(msg: &str) -> ! {
    eprintln!("seed-test-user: {msg}");
    eprintln!("{USAGE}");
    std::process::exit(2);
}

struct Args {
    encoding_key: String,
    decoding_key: String,
    issuer: String,
}

fn parse_args() -> Args {
    let mut encoding_key = None;
    let mut decoding_key = None;
    let mut issuer = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--encoding-key" => encoding_key = args.next(),
            "--decoding-key" => decoding_key = args.next(),
            "--issuer" => issuer = args.next(),
            other => usage_error(&format!("unrecognized argument '{other}'")),
        }
    }
    Args {
        encoding_key: encoding_key.unwrap_or_else(|| usage_error("--encoding-key is required")),
        decoding_key: decoding_key.unwrap_or_else(|| usage_error("--decoding-key is required")),
        issuer: issuer.unwrap_or_else(|| usage_error("--issuer is required")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = parse_args();

    let encoding_pem = std::fs::read_to_string(&args.encoding_key)
        .map_err(|e| format!("Failed to read encoding key '{}': {e}", args.encoding_key))?;
    let decoding_pem = std::fs::read_to_string(&args.decoding_key)
        .map_err(|e| format!("Failed to read decoding key '{}': {e}", args.decoding_key))?;
    let (signing_key, _verifying_key, kid) = keys::load_cwt_keys(&encoding_pem, &decoding_pem)?;

    // Write the user row directly (mirrors DynamoDBStore::create_user's item
    // shape in src/db.rs, but with a fixed user_id/did rather than random).
    let table =
        std::env::var("DYNAMODB_CREDENTIALS_TABLE").unwrap_or_else(|_| "credentials".to_string());
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_dynamodb::Client::new(&config);

    let entitlements: Vec<AttributeValue> = constants::DEFAULT_USER_ENTITLEMENTS
        .iter()
        .map(|s| AttributeValue::S((*s).to_string()))
        .collect();

    client
        .put_item()
        .table_name(&table)
        .item("user_id", AttributeValue::S(TEST_USER_ID.to_string()))
        .item("username", AttributeValue::S(TEST_USERNAME.to_string()))
        .item("credentials", AttributeValue::L(vec![]))
        .item("did", AttributeValue::S(TEST_DID.to_string()))
        .item("entitlements", AttributeValue::L(entitlements))
        .send()
        .await
        .map_err(|e| format!("Failed to seed test user row in '{table}': {e}"))?;

    let user_id = Uuid::parse_str(TEST_USER_ID).expect("TEST_USER_ID is a valid UUID literal");

    // Human CWT. `sub` is a bare UUID with no "arkavo:" prefix and no
    // `arkavo_account_id` claim — the exact shape `authn::mint_auth_token`
    // mints for a real WebAuthn auth token, and what `authenticate_human`
    // (src/agent.rs) actually accepts. Minting the "arkavo:<uuid>" shape here
    // would let this test pass without proving the real token shape works.
    let human_claims = cwt::ArkavoClaims::auth(&args.issuer, &user_id.to_string(), 1, None);
    let human_cwt = cwt::mint(&human_claims, &signing_key, &kid)?;
    println!("{}", cwt::encode_for_header(&human_cwt));

    // Service CWT: gates PUT /admin/users/:id/entitlements and GET /entities/:id.
    let service_claims = cwt::ArkavoClaims::auth(&args.issuer, "client:it", 1, None)
        .with_arkavo_roles(vec!["service-account".to_string()]);
    let service_cwt = cwt::mint(&service_claims, &signing_key, &kid)?;
    std::fs::write("service.cwt", cwt::encode_for_header(&service_cwt))
        .map_err(|e| format!("Failed to write service.cwt: {e}"))?;

    Ok(())
}
