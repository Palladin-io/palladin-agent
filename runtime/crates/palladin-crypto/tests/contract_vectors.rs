use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_crypto::{
    CryptoError, Ed25519Identity, EncryptedCredential, X25519Identity, body_sha256_base64,
    canonical_request, decrypt_credential, sign_request,
};
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeFixture {
    key_fixture: EnvelopeKey,
    plaintext_utf8: String,
    envelope: EncryptedCredential,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeKey {
    public_key_base64: String,
    private_key_base64: String,
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

#[test]
fn decrypts_the_frozen_libsodium_envelope_byte_for_byte() {
    let fixture: EnvelopeFixture = serde_json::from_str(include_str!(
        "../../../contracts/v1/encrypted-envelope.json"
    ))
    .expect("envelope fixture");
    let private_key = STANDARD
        .decode(&fixture.key_fixture.private_key_base64)
        .expect("private key base64");
    let identity = X25519Identity::from_private_bytes(private_key).expect("X25519 identity");
    assert_eq!(
        STANDARD.encode(identity.public_key()),
        fixture.key_fixture.public_key_base64
    );

    let plaintext = decrypt_credential(&fixture.envelope, &identity).expect("decrypt envelope");
    assert!(
        plaintext.expose_for_authorized_operation() == fixture.plaintext_utf8.as_bytes(),
        "decrypted credential payload diverged"
    );
}

#[test]
fn envelope_tamper_and_wrong_key_fail_closed() {
    let fixture: EnvelopeFixture = serde_json::from_str(include_str!(
        "../../../contracts/v1/encrypted-envelope.json"
    ))
    .expect("envelope fixture");
    let private_key = STANDARD
        .decode(&fixture.key_fixture.private_key_base64)
        .expect("private key base64");
    let identity = X25519Identity::from_private_bytes(private_key).expect("X25519 identity");

    let mut tampered = fixture.envelope.clone();
    let mut ciphertext = STANDARD
        .decode(&tampered.re_encrypted_blob)
        .expect("ciphertext base64");
    ciphertext[0] ^= 0x80;
    tampered.re_encrypted_blob = STANDARD.encode(ciphertext);
    assert_eq!(
        decrypt_credential(&tampered, &identity).expect_err("tamper must fail"),
        CryptoError::AuthenticationFailed
    );

    let wrong_identity = X25519Identity::from_private_bytes(vec![0x55; 32]).expect("wrong key");
    assert_eq!(
        decrypt_credential(&fixture.envelope, &wrong_identity).expect_err("wrong key must fail"),
        CryptoError::AuthenticationFailed
    );
}
