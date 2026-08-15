use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_crypto::{Ed25519Identity, body_sha256_base64, canonical_request, sign_request};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningFixture {
    input: SigningInput,
    key: SigningKey,
    expected: SigningExpected,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningInput {
    agent_id: String,
    method: String,
    path_with_query: String,
    timestamp: u64,
    nonce_base64: String,
    body_utf8: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningKey {
    private_seed_hex: String,
    public_key_base64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningExpected {
    body_sha256_base64: String,
    canonical_utf8: String,
    signature_base64: String,
}

#[test]
fn signing_matches_the_frozen_typescript_and_dotnet_vector_byte_for_byte() {
    let fixture: SigningFixture =
        serde_json::from_str(include_str!("../../../contracts/v1/request-signing.json"))
            .expect("signing fixture");
    let seed = hex::decode(&fixture.key.private_seed_hex).expect("seed hex");
    let identity = Ed25519Identity::from_seed(seed).expect("signing identity");

    assert_eq!(
        STANDARD.encode(identity.public_key()),
        fixture.key.public_key_base64
    );
    assert_eq!(
        body_sha256_base64(fixture.input.body_utf8.as_bytes()),
        fixture.expected.body_sha256_base64
    );
    let canonical = canonical_request(
        &fixture.input.method,
        &fixture.input.path_with_query,
        fixture.input.timestamp,
        &fixture.input.nonce_base64,
        fixture.input.body_utf8.as_bytes(),
    )
    .expect("canonical request");
    assert_eq!(canonical, fixture.expected.canonical_utf8);

    let headers = sign_request(
        &fixture.input.agent_id,
        &identity,
        &fixture.input.method,
        &fixture.input.path_with_query,
        fixture.input.timestamp,
        &fixture.input.nonce_base64,
        fixture.input.body_utf8.as_bytes(),
    )
    .expect("signature");
    assert_eq!(headers.signature_base64, fixture.expected.signature_base64);
}
