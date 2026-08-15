use std::{collections::HashMap, fs, path::PathBuf};

use palladin_crypto::{
    AadField, AadProfile, AadValue, CryptoError, EnvelopeHeader, HkdfContext, SignatureProfile,
    X25519Identity, decode_base64url, decrypt_envelope, derive_projection_key, encode_aad,
    key_fingerprint, open_sealed_box, verify_domain_signature,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const FIXTURES: &str = "../../contracts/vault-v2/fixtures/v2";

fn fixture(relative: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES)
        .join(relative);
    serde_json::from_slice(&fs::read(path).expect("fixture must exist"))
        .expect("fixture must parse")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex")
}

fn profile(value: &str) -> AadProfile {
    match value {
        "member-vault-metadata" => AadProfile::MemberVaultMetadata,
        "member-index" => AadProfile::MemberIndex,
        "member-secret" => AadProfile::MemberSecret,
        "agent-discovery" => AadProfile::AgentDiscovery,
        "entry-key-wrapper" => AadProfile::EntryKeyWrapper,
        "vault-private-key" => AadProfile::VaultPrivateKey,
        "vault-discovery-key" => AadProfile::VaultDiscoveryKey,
        "encrypted-reason" => AadProfile::EncryptedReason,
        "grant-payload" => AadProfile::GrantPayload,
        other => panic!("unknown fixture profile {other}"),
    }
}

fn aad_fields(value: &Value) -> Vec<AadField> {
    value
        .as_array()
        .expect("aad fields")
        .iter()
        .map(|field| {
            let tag = field["tag"].as_u64().expect("tag") as u8;
            let typed = match field["type"].as_str().expect("type") {
                "u16" => AadValue::U16(field["value"].as_u64().expect("u16") as u16),
                "u32" => AadValue::U32(field["value"].as_u64().expect("u32") as u32),
                "u64" => AadValue::U64(
                    field["value"]
                        .as_str()
                        .expect("u64 string")
                        .parse()
                        .expect("u64"),
                ),
                "uuid" => AadValue::Uuid(
                    Uuid::parse_str(field["value"].as_str().expect("uuid")).expect("valid uuid"),
                ),
                "bytes" => AadValue::Bytes(hex_bytes(field["valueHex"].as_str().expect("bytes"))),
                "instant" => {
                    AadValue::Instant(field["value"].as_str().expect("instant").to_owned())
                }
                other => panic!("unknown AAD type {other}"),
            };
            AadField { tag, value: typed }
        })
        .collect()
}

fn envelope_header(envelope: &Value) -> EnvelopeHeader {
    let header = &envelope["header"];
    EnvelopeHeader {
        protocol_version: header["protocolVersion"].as_u64().expect("protocol") as u16,
        algorithm_suite: header["algorithmSuite"].as_u64().expect("suite") as u16,
        resource_kind: header["resourceKind"].as_u64().expect("resource") as u16,
        projection_kind: header["projectionKind"].as_u64().expect("projection") as u16,
        resource_revision: header["resourceRevision"]
            .as_str()
            .expect("revision")
            .parse()
            .expect("u64 revision"),
        key_version: header["keyVersion"].as_u64().expect("key version") as u32,
        member_key_generation: header["memberKeyGeneration"].as_u64().expect("generation") as u32,
    }
}

fn decrypt_vector(vector: &Value, envelope: &Value, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let header = envelope_header(envelope);
    let mut fields = aad_fields(&vector["aadFields"]);
    for field in &mut fields {
        field.value = match field.tag {
            1 => AadValue::U16(header.protocol_version),
            2 => AadValue::U16(header.algorithm_suite),
            3 => AadValue::U16(header.resource_kind),
            4 => AadValue::Uuid(
                Uuid::parse_str(envelope["organizationId"].as_str().expect("organization"))
                    .map_err(|_| CryptoError::InvalidEncoding)?,
            ),
            5 => AadValue::Uuid(
                Uuid::parse_str(envelope["vaultId"].as_str().expect("vault"))
                    .map_err(|_| CryptoError::InvalidEncoding)?,
            ),
            6 => AadValue::Uuid(
                Uuid::parse_str(envelope["entryId"].as_str().expect("entry"))
                    .map_err(|_| CryptoError::InvalidEncoding)?,
            ),
            7 => AadValue::U16(header.projection_kind),
            8 => AadValue::U64(header.resource_revision),
            9 => AadValue::U32(header.key_version),
            10 => AadValue::U32(header.member_key_generation),
            20 => AadValue::U16(envelope["operation"].as_u64().expect("operation") as u16),
            _ => field.value.clone(),
        };
    }
    let nonce = decode_base64url(envelope["header"]["nonce"].as_str().expect("nonce"))?;
    let ciphertext_field = vector["ciphertextField"]
        .as_str()
        .expect("ciphertext field");
    let ciphertext = decode_base64url(envelope[ciphertext_field].as_str().expect("ciphertext"))?;
    decrypt_envelope(
        profile(vector["aadProfile"].as_str().expect("profile")),
        header,
        key,
        &nonce,
        &fields,
        &ciphertext,
    )
    .map(|plaintext| plaintext.expose_for_crypto_operation().to_vec())
}

#[test]
fn vendored_fixture_manifest_is_pinned_and_every_file_digest_matches() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
    let manifest_bytes = fs::read(root.join("manifest.json")).expect("manifest bytes");
    assert_eq!(
        hex::encode(Sha256::digest(&manifest_bytes)),
        "13c43defd459e95d50bf2f0a76a5a5446ca41903c36a38beef8b8af3aa208050"
    );
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("manifest");
    for file in manifest["files"].as_array().expect("files") {
        let path = file["path"].as_str().expect("path");
        let expected = file["sha256"].as_str().expect("digest");
        assert_eq!(
            hex::encode(Sha256::digest(
                fs::read(root.join(path)).expect("fixture bytes")
            )),
            expected,
            "vendored fixture {path} diverged"
        );
    }
}

#[test]
fn every_canonical_aad_vector_matches_byte_for_byte() {
    let vectors = fixture("vectors/aad.json");
    for vector in vectors["vectors"].as_array().expect("vectors") {
        let encoded = encode_aad(
            profile(vector["profile"].as_str().expect("profile")),
            &aad_fields(&vector["fields"]),
        )
        .expect("valid AAD");
        assert_eq!(
            hex::encode(encoded),
            vector["aadHex"].as_str().expect("AAD hex")
        );
    }
}

#[test]
fn every_hkdf_and_public_key_fingerprint_vector_matches() {
    let vectors = fixture("vectors/key-derivation.json");
    for vector in vectors["hkdfVectors"].as_array().expect("HKDF vectors") {
        let derived = derive_projection_key(
            &hex_bytes(vector["baseKeyHex"].as_str().expect("base key")),
            HkdfContext {
                resource_kind: match vector["resourceKind"].as_str().expect("resource") {
                    "vault" => 1,
                    "entry" => 2,
                    other => panic!("unknown resource {other}"),
                },
                organization_id: Uuid::parse_str(
                    vector["organizationId"].as_str().expect("organization"),
                )
                .expect("uuid"),
                vault_id: Uuid::parse_str(vector["vaultId"].as_str().expect("vault"))
                    .expect("uuid"),
                entry_id: vector["entryId"]
                    .as_str()
                    .map(|value| Uuid::parse_str(value).expect("entry uuid")),
                key_version: vector["keyVersion"].as_u64().expect("key version") as u32,
                member_key_generation: vector["memberKeyGeneration"].as_u64().expect("generation")
                    as u32,
                purpose_id: vector["purposeId"].as_u64().expect("purpose") as u16,
            },
        )
        .expect("HKDF");
        assert!(
            hex::encode(derived.expose_for_crypto_operation())
                == vector["outputHex"].as_str().expect("output"),
            "derived key diverged"
        );
    }
    for vector in vectors["fingerprintVectors"]
        .as_array()
        .expect("fingerprints")
    {
        assert_eq!(
            hex::encode(
                key_fingerprint(
                    vector["keyKind"].as_u64().expect("kind") as u16,
                    &hex_bytes(vector["publicKeyHex"].as_str().expect("public key")),
                )
                .expect("fingerprint")
            ),
            vector["fingerprintHex"].as_str().expect("fingerprint")
        );
    }
}

#[test]
fn every_aead_and_sealed_box_vector_decrypts_inside_rust() {
    let vectors = fixture("vectors/envelopes.json");
    for vector in vectors["aeadVectors"].as_array().expect("AEAD vectors") {
        let plaintext = decrypt_vector(
            vector,
            &vector["envelope"],
            &hex_bytes(vector["decryptionKeyHex"].as_str().expect("key")),
        )
        .expect("AEAD vector");
        assert!(
            hex::encode(plaintext) == vector["plaintextHex"].as_str().expect("plaintext"),
            "decrypted fixture payload diverged"
        );
    }
    for vector in vectors["sealedBoxVectors"]
        .as_array()
        .expect("sealed vectors")
    {
        let identity = X25519Identity::from_private_bytes(hex_bytes(
            vector["recipientPrivateKeyHex"]
                .as_str()
                .expect("private key"),
        ))
        .expect("identity");
        let sealed_field = vector["envelope"]
            .as_object()
            .expect("envelope")
            .iter()
            .find(|(name, _)| name.starts_with("sealed") || name.starts_with("agentWrapped"))
            .expect("sealed field")
            .1
            .as_str()
            .expect("sealed value");
        let plaintext =
            open_sealed_box(&decode_base64url(sealed_field).expect("sealed"), &identity)
                .expect("sealed box");
        assert!(
            plaintext.expose_for_crypto_operation()
                == vector["plaintextCanonical"]
                    .as_str()
                    .expect("plaintext")
                    .as_bytes(),
            "opened sealed package diverged"
        );
    }
}

#[test]
fn every_signature_vector_verifies_and_tampering_fails() {
    let vectors = fixture("vectors/signatures.json");
    for vector in vectors["vectors"].as_array().expect("signature vectors") {
        let signature_profile = match vector["domainPrefixAscii"].as_str().expect("domain") {
            "PLDNV2SIG:VAULT-MANIFEST:" => SignatureProfile::VaultManifest,
            "PLDNV2SIG:ENCRYPTED-REASON:" => SignatureProfile::EncryptedReason,
            other => panic!("unknown signature profile {other}"),
        };
        let canonical = vector["canonicalUnsignedObject"]
            .as_str()
            .expect("canonical");
        let public_key = hex_bytes(vector["publicKeyHex"].as_str().expect("public key"));
        let signature = hex_bytes(vector["signatureHex"].as_str().expect("signature"));
        verify_domain_signature(
            signature_profile,
            2,
            canonical.as_bytes(),
            &public_key,
            &signature,
        )
        .expect("valid signature");
        let mut tampered = canonical.as_bytes().to_vec();
        tampered[0] ^= 1;
        assert_eq!(
            verify_domain_signature(signature_profile, 2, &tampered, &public_key, &signature),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

#[test]
fn every_corruption_fixture_fails_closed() {
    let envelopes = fixture("vectors/envelopes.json");
    let source: HashMap<&str, &Value> = envelopes["aeadVectors"]
        .as_array()
        .expect("AEAD vectors")
        .iter()
        .map(|vector| (vector["id"].as_str().expect("id"), vector))
        .collect();
    let corruption = fixture("negative/corruption.json");
    for case in corruption["cases"].as_array().expect("cases") {
        match case["category"].as_str().expect("category") {
            "invalid-signature" => {
                let signed = &case["signedObject"];
                let signature = decode_base64url(signed["signature"].as_str().expect("signature"))
                    .expect("signature encoding");
                let signatures = fixture("vectors/signatures.json");
                let canonical = signatures["vectors"][0]["canonicalUnsignedObject"]
                    .as_str()
                    .expect("canonical");
                let public_key = hex_bytes(
                    signatures["vectors"][0]["publicKeyHex"]
                        .as_str()
                        .expect("public key"),
                );
                assert!(
                    verify_domain_signature(
                        SignatureProfile::VaultManifest,
                        2,
                        canonical.as_bytes(),
                        &public_key,
                        &signature,
                    )
                    .is_err()
                );
            }
            "wrong-key" if case["envelope"].get("header").is_none() => {
                let sealed_source = &envelopes["sealedBoxVectors"][0];
                let sealed_field = case["envelope"]
                    .as_object()
                    .expect("envelope")
                    .iter()
                    .find(|(name, _)| {
                        name.starts_with("sealed") || name.starts_with("agentWrapped")
                    })
                    .expect("sealed")
                    .1
                    .as_str()
                    .expect("sealed");
                let identity = X25519Identity::from_private_bytes(hex_bytes(
                    sealed_source["recipientPrivateKeyHex"]
                        .as_str()
                        .expect("private key"),
                ))
                .expect("identity");
                assert!(
                    open_sealed_box(
                        &decode_base64url(sealed_field).expect("encoding"),
                        &identity
                    )
                    .is_err()
                );
            }
            _ => {
                let source_vector = source[case["sourceVector"].as_str().expect("source")];
                let key = case["decryptionKeyHex"]
                    .as_str()
                    .or_else(|| source_vector["decryptionKeyHex"].as_str())
                    .map(hex_bytes)
                    .expect("decryption key");
                assert!(
                    decrypt_vector(source_vector, &case["envelope"], &key).is_err(),
                    "negative fixture {} unexpectedly decrypted",
                    case["id"].as_str().expect("id")
                );
            }
        }
    }
}

#[test]
fn aad_rejects_unknown_duplicate_out_of_order_and_noncanonical_values() {
    let aad = fixture("vectors/aad.json");
    let mut fields = aad_fields(&aad["vectors"][0]["fields"]);
    fields.swap(0, 1);
    assert_eq!(
        encode_aad(AadProfile::MemberVaultMetadata, &fields),
        Err(CryptoError::InvalidProfile)
    );
    let mut fields = aad_fields(&aad["vectors"][0]["fields"]);
    fields.push(AadField {
        tag: 99,
        value: AadValue::U16(1),
    });
    assert_eq!(
        encode_aad(AadProfile::MemberVaultMetadata, &fields),
        Err(CryptoError::InvalidProfile)
    );
}

#[test]
fn profile_size_and_key_purpose_limits_fail_before_decryption() {
    let envelopes = fixture("vectors/envelopes.json");
    let vector = &envelopes["aeadVectors"][0];
    let envelope = &vector["envelope"];
    let fields = aad_fields(&vector["aadFields"]);
    let nonce = decode_base64url(envelope["header"]["nonce"].as_str().expect("nonce"))
        .expect("nonce encoding");
    let oversized = vec![0u8; 16 * 1024 + 1];
    assert_eq!(
        decrypt_envelope(
            AadProfile::MemberVaultMetadata,
            envelope_header(envelope),
            &hex_bytes(vector["decryptionKeyHex"].as_str().expect("key")),
            &nonce,
            &fields,
            &oversized,
        )
        .expect_err("oversized ciphertext"),
        CryptoError::InvalidLength
    );

    let mut mismatched_fields = fields.clone();
    mismatched_fields
        .iter_mut()
        .find(|field| field.tag == 8)
        .expect("revision tag")
        .value = AadValue::U64(envelope_header(envelope).resource_revision + 1);
    assert_eq!(
        decrypt_envelope(
            AadProfile::MemberVaultMetadata,
            envelope_header(envelope),
            &hex_bytes(vector["decryptionKeyHex"].as_str().expect("key")),
            &nonce,
            &mismatched_fields,
            &decode_base64url(envelope["ciphertext"].as_str().expect("ciphertext"))
                .expect("ciphertext encoding"),
        )
        .expect_err("detached AAD/header binding"),
        CryptoError::InvalidProfile
    );

    let derivation = fixture("vectors/key-derivation.json");
    let vector = &derivation["hkdfVectors"][0];
    assert_eq!(
        derive_projection_key(
            &hex_bytes(vector["baseKeyHex"].as_str().expect("base key")),
            HkdfContext {
                resource_kind: 1,
                organization_id: Uuid::parse_str(
                    vector["organizationId"].as_str().expect("organization"),
                )
                .expect("uuid"),
                vault_id: Uuid::parse_str(vector["vaultId"].as_str().expect("vault"))
                    .expect("uuid"),
                entry_id: None,
                key_version: 1,
                member_key_generation: 1,
                purpose_id: 3,
            },
        )
        .expect_err("Member Secret purpose cannot use a Vault scope"),
        CryptoError::InvalidProfile
    );
}

#[test]
fn secret_bearing_errors_never_include_input_material() {
    let synthetic_secret = "synthetic=secret-that-must-not-appear";
    let error = decode_base64url(synthetic_secret).expect_err("invalid base64url");
    let rendered = error.to_string();
    assert!(!rendered.contains(synthetic_secret));
    assert_eq!(rendered, "cryptographic input has an invalid encoding");
}
