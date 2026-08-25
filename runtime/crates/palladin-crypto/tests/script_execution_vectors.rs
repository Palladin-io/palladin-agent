use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_crypto::{
    EncodedSuitePayload, EnvelopeScope, ExpectedScriptExecutionPackageContext, RecipientKeyKind,
    ScriptExecutionEncryptedPackage, SealedWrappedKey, SignatureProfile, WrapperContext,
    WrapperPurpose, X25519_WRAPPER_V1, X25519Identity, X25519SealedBoxSuite, XChaChaVaultSuite,
    compute_key_fingerprint, decode_base64url, open_script_execution_package,
    verify_domain_signature,
};
use secrecy::ExposeSecret;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const FIXTURE: &[u8] = include_bytes!("../../../contracts/script-execution/v1/wire-fixture.json");
const FIXTURE_SHA256: [u8; 32] = [
    0x27, 0x1e, 0x8d, 0xb8, 0x53, 0xd6, 0x97, 0x4e, 0x58, 0xcc, 0x2d, 0x9c, 0x52, 0xdf, 0x38, 0x33,
    0x1c, 0xd9, 0xa0, 0x67, 0xd5, 0x75, 0xb1, 0xb5, 0x2d, 0x25, 0x34, 0xa6, 0x54, 0x4b, 0x8c, 0xda,
];

#[test]
fn public_script_execution_fixture_verifies_and_opens_byte_exactly() {
    assert_eq!(<[u8; 32]>::from(Sha256::digest(FIXTURE)), FIXTURE_SHA256);
    let fixture: Value = serde_json::from_slice(FIXTURE).expect("public Script fixture");
    assert_eq!(fixture["syntheticOnly"], true);
    let expected = &fixture["expected"];
    let package: ScriptExecutionEncryptedPackage =
        serde_json::from_value(expected["encryptedPackage"].clone()).expect("encrypted package");
    let signer_public_key: [u8; 32] = decode_base64url(
        fixture["publicKeys"]["vaultSigningEd25519"]
            .as_str()
            .expect("Vault signer"),
    )
    .expect("signer encoding")
    .try_into()
    .expect("signer length");
    let recipient_private_key = hex::decode(
        fixture["deterministicInputs"]["recipientX25519PrivateKey"]
            .as_str()
            .expect("synthetic recipient private key"),
    )
    .expect("recipient key encoding");
    let recipient =
        X25519Identity::from_private_bytes(recipient_private_key).expect("synthetic recipient key");
    assert_eq!(
        URL_SAFE_NO_PAD.encode(recipient.public_key()),
        fixture["publicKeys"]["recipientAgentX25519"],
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(compute_key_fingerprint(
            recipient.public_key(),
            RecipientKeyKind::AgentX25519,
        )),
        expected["encryptedPackage"]["recipientAgentKeyFingerprint"],
    );
    let mut unsigned = expected["encryptedPackage"].clone();
    let producer_signature = unsigned
        .as_object_mut()
        .expect("package object")
        .remove("producerSignature")
        .and_then(|value| value.as_str().map(str::to_owned))
        .expect("producer signature");
    verify_domain_signature(
        SignatureProfile::ScriptExecutionPackage,
        2,
        &serde_jcs::to_vec(&unsigned).expect("canonical package"),
        &signer_public_key,
        &decode_base64url(&producer_signature).expect("signature encoding"),
    )
    .expect("producer signature");

    let encoded_package_ciphertext = unsigned["encodedPackageCiphertext"]
        .as_str()
        .expect("package ciphertext");
    let container_bytes =
        Zeroizing::new(decode_base64url(encoded_package_ciphertext).expect("container encoding"));
    let container: Value = serde_json::from_slice(&container_bytes).expect("container JSON");
    assert_eq!(
        serde_jcs::to_vec(&container).expect("canonical container"),
        container_bytes.as_slice(),
    );
    let mut transport = unsigned.clone();
    transport
        .as_object_mut()
        .expect("transport object")
        .remove("encodedPackageCiphertext");
    let aad = Zeroizing::new(serde_jcs::to_vec(&transport).expect("transport AAD"));
    let mut parent_hash = Sha256::new();
    parent_hash.update(b"PLDNSCRIPTAAD1");
    parent_hash.update(&aad);
    let recipient_fingerprint =
        compute_key_fingerprint(recipient.public_key(), RecipientKeyKind::AgentX25519);
    let wrapped = SealedWrappedKey::from_bytes(
        decode_base64url(
            container["encodedSealedPackageDek"]
                .as_str()
                .expect("sealed DEK"),
        )
        .expect("sealed DEK encoding"),
    )
    .expect("sealed DEK shape");
    let package_dek = X25519SealedBoxSuite::unwrap(
        &wrapped,
        &recipient,
        &WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::ScriptExecutionDek,
            scope: EnvelopeScope {
                organization_id: uuid::Uuid::parse_str("66666666-6666-4666-8666-666666666666")
                    .expect("organization")
                    .into_bytes(),
                vault_id: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                    .expect("Vault")
                    .into_bytes(),
                entry_id: Some(
                    uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                        .expect("Script")
                        .into_bytes(),
                ),
                grant_or_request_id: Some(
                    uuid::Uuid::parse_str("44444444-4444-4444-8444-444444444444")
                        .expect("Grant")
                        .into_bytes(),
                ),
                agent_id: Some(
                    uuid::Uuid::parse_str("77777777-7777-4777-8777-777777777777")
                        .expect("Agent")
                        .into_bytes(),
                ),
                member_id: None,
            },
            resource_revision: 8,
            wrapped_key_version: 1,
            member_key_generation: None,
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: 2,
            recipient_fingerprint,
            parent_descriptor_hash: Some(parent_hash.finalize().into()),
        },
    )
    .expect("sealed package DEK");
    let suite_payload = EncodedSuitePayload::from_bytes(
        decode_base64url(
            container["encodedSuitePayload"]
                .as_str()
                .expect("suite payload"),
        )
        .expect("suite payload encoding"),
    )
    .expect("suite payload shape");
    let plaintext = XChaChaVaultSuite::open(&package_dek, &suite_payload, &aad)
        .expect("encrypted package payload");
    let payload: Value = serde_json::from_slice(plaintext.expose_secret()).expect("payload JSON");
    let payload_matches = payload == expected["decryptedPayload"];
    assert!(payload_matches, "decrypted public fixture payload diverged");

    let opened = open_script_execution_package(
        package,
        &recipient,
        &ExpectedScriptExecutionPackageContext {
            organization_id: "66666666-6666-4666-8666-666666666666".to_owned(),
            vault_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            grant_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            agent_id: "77777777-7777-4777-8777-777777777777".to_owned(),
            agent_access_epoch: 3,
            script_entry_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            script_revision: "7".to_owned(),
            package_revision: "8".to_owned(),
            recipient_agent_key_version: 2,
            vault_signing_key_version: 5,
            vault_signing_key_fingerprint: "eIlglh_0MHyCt47BrH6DP4PXTIzG1V_QT6L96VxCk_A".to_owned(),
            vault_signing_public_key: signer_public_key,
        },
    )
    .expect("authenticated Script package");

    assert_eq!(
        serde_json::to_value(&opened.binding).expect("binding"),
        expected["decryptedPayload"]["binding"],
    );
    assert_eq!(
        serde_json::to_value(&opened.manifest).expect("manifest"),
        expected["decryptedPayload"]["manifest"],
    );
    let expected_entries = expected["decryptedPayload"]["entries"]
        .as_array()
        .expect("fixture entries");
    assert_eq!(opened.entries.len(), expected_entries.len());
    for entry in &opened.entries {
        let expected_entry = expected_entries
            .iter()
            .find(|candidate| candidate["entryId"] == entry.entry_id)
            .expect("matching fixture Entry");
        assert_eq!(expected_entry["entryRevision"], entry.entry_revision);
        let encoded_payload = Zeroizing::new(
            URL_SAFE_NO_PAD.encode(entry.encoded_grant_payload.expose_for_crypto_operation()),
        );
        let payload_matches =
            expected_entry["encodedGrantPayload"].as_str() == Some(encoded_payload.as_str());
        assert!(
            payload_matches,
            "opened projection diverged from public fixture"
        );
    }
}
