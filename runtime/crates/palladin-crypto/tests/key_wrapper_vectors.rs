use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_crypto::{
    EncryptionIdentity, EnvelopeScope, RecipientKeyKind, WrapperContext, WrapperError,
    WrapperPurpose, WrapperSuite,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const REGISTRY: &str = include_str!("../../../contracts/key-wrapper/v1/registry.json");
const VECTORS: &str = include_str!("../../../contracts/key-wrapper/v1/vectors.json");
const XWING_SUITE: &str =
    include_str!("../../../contracts/key-wrapper/v1/suites/palladin-xwing-v1.json");
const X25519_SUITE: &str =
    include_str!("../../../contracts/key-wrapper/v1/suites/palladin-x25519-sealed-box-v1.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    protocol_version: u16,
    wrapper_suite_id: String,
    purpose: u16,
    scope: Scope,
    resource_revision: String,
    wrapped_key_version: u32,
    member_key_generation: Option<u32>,
    recipient_key_kind: u16,
    recipient_key_version: u32,
    recipient_fingerprint: String,
    parent_descriptor_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    organization_id: Option<String>,
    vault_id: Option<String>,
    entry_id: Option<String>,
    grant_or_request_id: Option<String>,
    agent_id: Option<String>,
    member_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    directory_suite_id: String,
    key_kind: u16,
    key_version: u32,
    public_key_hex: String,
    private_key_hex: String,
}

fn uuid(value: Option<&str>) -> Result<Option<[u8; 16]>, WrapperError> {
    value
        .map(|value| {
            let parsed =
                uuid::Uuid::parse_str(value).map_err(|_| WrapperError::MalformedDescriptor)?;
            // Wire UUIDs are canonical lowercase; any other spelling is a different descriptor.
            if parsed.hyphenated().to_string() != value {
                return Err(WrapperError::MalformedDescriptor);
            }
            Ok(parsed.into_bytes())
        })
        .transpose()
}

fn base64_32(value: &str) -> Result<[u8; 32], WrapperError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WrapperError::MalformedDescriptor)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(WrapperError::MalformedDescriptor);
    }
    bytes
        .try_into()
        .map_err(|_| WrapperError::MalformedDescriptor)
}

/// Mirrors the registry's check order: suite, purpose, then the full descriptor.
fn context(value: &Value) -> Result<WrapperContext, WrapperError> {
    let suite_id = value["wrapperSuiteId"]
        .as_str()
        .ok_or(WrapperError::MalformedDescriptor)?;
    WrapperSuite::from_id(suite_id)?;
    let purpose = value["purpose"]
        .as_u64()
        .and_then(|code| u16::try_from(code).ok())
        .ok_or(WrapperError::MalformedDescriptor)?;
    let purpose = WrapperPurpose::from_code(purpose)?;
    let descriptor: Descriptor =
        serde_json::from_value(value.clone()).map_err(|_| WrapperError::MalformedDescriptor)?;
    let revision = &descriptor.resource_revision;
    if descriptor.purpose != purpose as u16
        || revision.starts_with('0')
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WrapperError::MalformedDescriptor);
    }
    let scope = &descriptor.scope;
    Ok(WrapperContext {
        protocol_version: descriptor.protocol_version,
        wrapper_suite_id: descriptor.wrapper_suite_id,
        purpose,
        scope: EnvelopeScope {
            organization_id: uuid(scope.organization_id.as_deref())?
                .ok_or(WrapperError::MalformedDescriptor)?,
            vault_id: uuid(scope.vault_id.as_deref())?.unwrap_or([0; 16]),
            entry_id: uuid(scope.entry_id.as_deref())?,
            grant_or_request_id: uuid(scope.grant_or_request_id.as_deref())?,
            agent_id: uuid(scope.agent_id.as_deref())?,
            member_id: uuid(scope.member_id.as_deref())?,
        },
        resource_revision: revision
            .parse()
            .map_err(|_| WrapperError::MalformedDescriptor)?,
        wrapped_key_version: descriptor.wrapped_key_version,
        member_key_generation: descriptor.member_key_generation,
        recipient_key_kind: RecipientKeyKind::from_code(descriptor.recipient_key_kind)?,
        recipient_key_version: descriptor.recipient_key_version,
        recipient_fingerprint: base64_32(&descriptor.recipient_fingerprint)?,
        parent_descriptor_hash: descriptor
            .parent_descriptor_hash
            .as_deref()
            .map(base64_32)
            .transpose()?,
    })
}

/// The recipient's key-directory entry: its registered suite, key kind and version.
fn identity(recipient: &Recipient) -> EncryptionIdentity {
    let suite = recipient.directory_suite_id.as_bytes();
    let mut stored = b"PLDNEK01".to_vec();
    stored.push(u8::try_from(suite.len()).expect("suite id length"));
    stored.extend_from_slice(suite);
    stored.extend_from_slice(&hex::decode(&recipient.private_key_hex).expect("private key"));
    EncryptionIdentity::from_secure_storage(&stored).expect("registered suite")
}

fn bind_directory(context: &WrapperContext, recipient: &Recipient) -> Result<(), WrapperError> {
    if context.recipient_key_kind as u16 != recipient.key_kind
        || context.recipient_key_version != recipient.key_version
    {
        return Err(WrapperError::RecipientMismatch);
    }
    Ok(())
}

fn open(vector: &Value) -> Result<SecretBox<[u8; 32]>, WrapperError> {
    let recipient: Recipient =
        serde_json::from_value(vector["recipient"].clone()).expect("recipient");
    let context = context(&vector["descriptor"])?;
    context
        .canonical_bytes()
        .map_err(|_| WrapperError::MalformedDescriptor)?;
    bind_directory(&context, &recipient)?;
    let encoded = vector["encodedSealedKeyPackage"].as_str().expect("package");
    let package = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| WrapperError::MalformedPackage)?;
    context.open(&package, &identity(&recipient))
}

#[test]
fn vendored_contract_files_match_pinned_digests() {
    let digest = |bytes: &str| hex::encode(Sha256::digest(bytes.as_bytes()));
    assert_eq!(
        digest(REGISTRY),
        "511890576c74b1f78439e10838c4e074a80186179f9ca17f98fb754a84fa223e"
    );
    assert_eq!(
        digest(VECTORS),
        "c5a3fa98287def283527d15407d6aa44fd034af7a6014785637df1e697c9b83a"
    );
    assert_eq!(
        digest(XWING_SUITE),
        "ffcd71cc171c70e9a0a2f3e5f2f85573946b1c300a906c583aeafc4c5d49d604"
    );
    assert_eq!(
        digest(X25519_SUITE),
        "197ff3929b10e02c1aebc7e147088f187a18101f242546bf6b3b9645ef4bb0c7"
    );
}

#[test]
fn compiled_registry_matches_the_contract_registry() {
    let registry: Value = serde_json::from_str(REGISTRY).expect("registry");
    for suite in registry["suites"].as_array().expect("suites") {
        let id = suite["id"].as_str().expect("suite id");
        let compiled = WrapperSuite::from_id(id).expect("registered suite is compiled in");
        assert_eq!(compiled.can_seal(), suite["status"] == "active", "{id}");
        let specification: Value = serde_json::from_str(if id == "palladin-xwing-v1" {
            XWING_SUITE
        } else {
            X25519_SUITE
        })
        .expect("suite specification");
        assert_eq!(
            compiled.public_key_bytes() as u64,
            specification["recipientKey"]["publicKeyBytes"]
                .as_u64()
                .expect("public key bytes")
        );
        for purpose in suite["purposes"].as_array().expect("purposes") {
            let code = u16::try_from(purpose.as_u64().expect("purpose")).expect("u16");
            WrapperPurpose::from_code(code).expect("registered purpose is compiled in");
        }
    }
    assert_eq!(
        WrapperSuite::from_id("palladin-xwing-v2"),
        Err(WrapperError::UnsupportedSuite)
    );
    for kind in registry["recipientKeyKinds"]
        .as_array()
        .expect("key kinds")
        .iter()
        .chain(registry["reservedKeyKinds"].as_array().expect("reserved"))
    {
        let code = u16::try_from(kind["id"].as_u64().expect("kind")).expect("u16");
        assert_eq!(
            RecipientKeyKind::from_code(code).expect("kind") as u16,
            code
        );
    }
}

#[test]
fn every_positive_vector_opens_and_active_suites_round_trip() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let positives = vectors["positive"].as_array().expect("positive");
    let legacy = vectors["legacy"].as_array().expect("legacy");
    assert_eq!(positives.len(), 20);
    for vector in positives.iter().chain(legacy) {
        let name = vector["name"].as_str().expect("name");
        let opened = open(vector).unwrap_or_else(|error| panic!("{name}: {error}"));
        let expected = hex::decode(vector["wrappedKeyHex"].as_str().expect("key")).expect("hex");
        assert_eq!(opened.expose_secret().as_slice(), expected, "{name}");

        let context = context(&vector["descriptor"]).expect("descriptor");
        assert_eq!(
            hex::encode(context.canonical_bytes().expect("context")),
            vector["expectedContextHex"].as_str().expect("context hex"),
            "{name}"
        );
        let recipient: Recipient =
            serde_json::from_value(vector["recipient"].clone()).expect("recipient");
        let identity = identity(&recipient);
        assert_eq!(
            hex::encode(identity.public_key()),
            recipient.public_key_hex,
            "{name}"
        );
        let public_key = identity.recipient_public_key();
        let sealed = context.seal(&opened, &public_key);
        if WrapperSuite::from_id(&context.wrapper_suite_id)
            .expect("suite")
            .can_seal()
        {
            let sealed = sealed.unwrap_or_else(|error| panic!("{name}: {error}"));
            let reopened = context.open(sealed.as_bytes(), &identity).expect("reopen");
            assert_eq!(reopened.expose_secret(), opened.expose_secret(), "{name}");
        } else {
            assert_eq!(sealed.expect_err(name), WrapperError::SuiteNotWritable);
        }
    }
}

#[test]
fn every_negative_vector_fails_with_its_contract_error() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let negatives = vectors["negative"].as_array().expect("negative");
    assert_eq!(negatives.len(), 30);
    for vector in negatives {
        let name = vector["name"].as_str().expect("name");
        let expected = vector["expectedError"].as_str().expect("error");
        let error = match vector["operation"].as_str().expect("operation") {
            "seal" => {
                let recipient: Recipient =
                    serde_json::from_value(vector["recipient"].clone()).expect("recipient");
                let key: [u8; 32] = hex::decode(vector["wrappedKeyHex"].as_str().expect("key"))
                    .expect("hex")
                    .try_into()
                    .expect("32 bytes");
                context(&vector["descriptor"])
                    .and_then(|context| {
                        context.seal(
                            &SecretBox::new(Box::new(key)),
                            &identity(&recipient).recipient_public_key(),
                        )
                    })
                    .map(|_| ())
                    .expect_err(name)
            }
            _ => open(vector).map(|_| ()).expect_err(name),
        };
        if name == "wrong-recipient-private-key" {
            // The reference opener takes the directory public key and the private key
            // separately. An EncryptionIdentity derives its public key from its private key, so
            // a foreign private key never matches the directory fingerprint and is rejected
            // before decapsulation.
            assert_eq!(error, WrapperError::RecipientMismatch, "{name}");
            assert_eq!(expected, "open-failed");
            continue;
        }
        assert_eq!(error.code(), expected, "{name}");
    }
}

#[test]
fn legacy_vector_is_the_frozen_vault_v2_sealed_box_fixture() {
    let frozen: Value =
        serde_json::from_str(include_str!("../../../contracts/v2/x25519-sealed-box.json"))
            .expect("frozen fixture");
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let legacy = &vectors["legacy"][0];
    let package = URL_SAFE_NO_PAD
        .decode(legacy["encodedSealedKeyPackage"].as_str().expect("package"))
        .expect("base64url");
    assert_eq!(hex::encode(package), frozen["sealedPackageHex"]);
    assert_eq!(legacy["expectedContextHex"], frozen["expectedContextHex"]);
}
