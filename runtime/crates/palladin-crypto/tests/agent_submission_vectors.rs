use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey};
use palladin_crypto::{
    AgentEntrySubmission, Ed25519Identity, EnvelopeScope, OrganizationApproverManifest,
    PinnedApproverTrust, RecipientKeyKind, SubmissionAuthority, SubmissionBuildContext,
    SubmissionContent, SubmissionEntryType, SubmissionError, SubmissionIdentity,
    SubmissionRecipient, SubmissionTarget, WrapperContext, WrapperPurpose, X25519_WRAPPER_V1,
    X25519Identity, build_agent_submission, compute_key_fingerprint, open_agent_submission,
    open_sealed_box, rewrap_agent_submission, verify_approver_manifest_chain, verify_rewrap,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;

const CONTRACT: &str = include_str!("../../../contracts/agent-submission/v1/contract.json");
const FIXTURE: &str = include_str!("../../../contracts/agent-submission/v1/fixture.json");
const AGENT_SUBMISSION_DOMAIN: &str = "PLDNSUB1SIG:AGENT-SUBMISSION:";
const MANIFEST_DOMAIN: &str = "PLDNSUB1SIG:APPROVER-MANIFEST:";
const CONTINUITY_DOMAIN: &str = "PLDNSUB1SIG:APPROVER-CONTINUITY:";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("frozen Agent Submission fixture")
}

fn seed(fixture: &Value, name: &str) -> [u8; 32] {
    hex_32(fixture["deterministicInputs"][name].as_str().expect("seed"))
}

fn hex_32(value: &str) -> [u8; 32] {
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect::<Vec<_>>();
    bytes.try_into().expect("32 bytes")
}

/// libsodium `crypto_box_seed_keypair` derives the X25519 secret as SHA-512(seed)[..32].
fn box_identity(seed: [u8; 32]) -> X25519Identity {
    X25519Identity::from_private_bytes(Sha512::digest(seed)[..32].to_vec()).expect("X25519")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).expect("base64url")
}

fn uuid(value: &Value) -> Uuid {
    Uuid::parse_str(value.as_str().expect("uuid")).expect("uuid")
}

struct Keys {
    agent_box: X25519Identity,
    agent_sign: SigningKey,
    approver_v1_box: X25519Identity,
    approver_v1_sign: SigningKey,
    approver_v2_box: X25519Identity,
    approver_v2_sign: SigningKey,
}

fn keys(fixture: &Value) -> Keys {
    Keys {
        agent_box: box_identity(seed(fixture, "agentX25519Seed")),
        agent_sign: SigningKey::from_bytes(&seed(fixture, "agentEd25519Seed")),
        approver_v1_box: box_identity(seed(fixture, "approverV1X25519Seed")),
        approver_v1_sign: SigningKey::from_bytes(&seed(fixture, "approverV1Ed25519Seed")),
        approver_v2_box: box_identity(seed(fixture, "approverV2X25519Seed")),
        approver_v2_sign: SigningKey::from_bytes(&seed(fixture, "approverV2Ed25519Seed")),
    }
}

fn sign_value(domain: &str, value: &Value, key: &SigningKey) -> String {
    let mut unsigned = value.as_object().expect("object").clone();
    for field in ["signature", "continuitySignature", "agentSignature"] {
        unsigned.remove(field);
    }
    let mut input = domain.as_bytes().to_vec();
    input.extend_from_slice(&2_u16.to_be_bytes());
    input.extend_from_slice(&serde_jcs::to_vec(&Value::Object(unsigned)).expect("JCS"));
    b64(&key.sign(&input).to_bytes())
}

fn resign(mut submission: Value, keys: &Keys) -> Value {
    submission["agentSignature"] = json!(sign_value(
        AGENT_SUBMISSION_DOMAIN,
        &submission,
        &keys.agent_sign
    ));
    submission
}

fn sign_manifest(mut manifest: Value, key: &SigningKey, previous: Option<&SigningKey>) -> Value {
    let object = manifest.as_object_mut().expect("manifest");
    object.remove("signature");
    object.remove("continuitySignature");
    let unsigned = manifest.clone();
    manifest["signature"] = json!(sign_value(MANIFEST_DOMAIN, &unsigned, key));
    if let Some(previous) = previous {
        manifest["continuitySignature"] = json!(sign_value(CONTINUITY_DOMAIN, &unsigned, previous));
    }
    manifest
}

fn flip_last_byte(value: &Value) -> Value {
    let mut bytes = unb64(value.as_str().expect("base64url"));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    json!(b64(&bytes))
}

fn parse(value: &Value) -> Result<AgentEntrySubmission, SubmissionError> {
    AgentEntrySubmission::from_value(value)
}

fn manifests(values: &[Value]) -> Result<Vec<OrganizationApproverManifest>, SubmissionError> {
    values
        .iter()
        .map(OrganizationApproverManifest::from_value)
        .collect()
}

fn organization(fixture: &Value) -> Uuid {
    uuid(&fixture["context"]["organizationId"])
}

fn verify_chain(fixture: &Value, values: &[Value]) -> Result<PinnedApproverTrust, SubmissionError> {
    verify_approver_manifest_chain(&manifests(values)?, organization(fixture), None)
        .map(|pin| pin.expect("non-empty chain"))
}

fn agent_signing_public_key(fixture: &Value) -> [u8; 32] {
    unb64(
        fixture["context"]["agentEd25519PublicKey"]
            .as_str()
            .expect("key"),
    )
    .try_into()
    .expect("32 bytes")
}

fn approver_authority<'a>(
    fixture: &Value,
    agent_key: &'a [u8; 32],
    key_version: u32,
    identity: &'a X25519Identity,
) -> SubmissionAuthority<'a> {
    SubmissionAuthority {
        organization_id: organization(fixture),
        agent_id: uuid(&fixture["context"]["agentId"]),
        agent_signing_public_key: agent_key,
        recipient: SubmissionRecipient::ApproverGroup {
            key_version,
            identity,
        },
    }
}

fn agent_authority<'a>(
    fixture: &Value,
    agent_key: &'a [u8; 32],
    identity: &'a X25519Identity,
) -> SubmissionAuthority<'a> {
    SubmissionAuthority {
        organization_id: organization(fixture),
        agent_id: uuid(&fixture["context"]["agentId"]),
        agent_signing_public_key: agent_key,
        recipient: SubmissionRecipient::Agent {
            key_version: u32::try_from(fixture["context"]["agentKeyVersion"].as_u64().unwrap())
                .unwrap(),
            identity,
        },
    }
}

fn opened_as_value(opened: &palladin_crypto::OpenedSubmission) -> Value {
    let content = match &opened.content {
        SubmissionContent::Credential {
            username,
            password,
            url,
            notes,
        } => {
            let mut content = json!({
                "username": username.expose_secret(),
                "password": password.expose_secret(),
            });
            if let Some(url) = url {
                content["url"] = json!(url);
            }
            if let Some(notes) = notes {
                content["notes"] = json!(notes.expose_secret());
            }
            content
        }
        SubmissionContent::Key { .. } => panic!("fixture is a credential"),
    };
    json!({
        "schema": "palladin.agent-submission-payload.v1",
        "identity": serde_json::from_slice::<Value>(&opened.identity.canonical().unwrap()).unwrap(),
        "label": opened.label,
        "content": content,
    })
}

fn expect_error<T>(result: Result<T, SubmissionError>, expected: &str, case: &str) {
    match result {
        Ok(_) => panic!("{case}: expected {expected}, but the input was accepted"),
        Err(error) => assert_eq!(error.code(), expected, "{case}"),
    }
}

#[test]
fn vendored_contract_files_match_pinned_digests() {
    let digest = |bytes: &str| hex::encode(Sha256::digest(bytes.as_bytes()));
    assert_eq!(
        digest(CONTRACT),
        "f945d201a18b7cc1d3ea828cebe11f51a71ef962063246fcdbb2f7e6304ed1fd"
    );
    assert_eq!(
        digest(FIXTURE),
        "4778ca29b0bee27e8d73c71838f9c51d51ecd59962f7f263272370e53dcf4101"
    );
}

#[test]
fn deterministic_keys_match_the_fixture_context() {
    let fixture = fixture();
    let keys = keys(&fixture);
    assert_eq!(
        b64(keys.agent_box.public_key()),
        fixture["context"]["agentX25519PublicKey"]
    );
    assert_eq!(
        b64(keys.agent_sign.verifying_key().as_bytes()),
        fixture["context"]["agentEd25519PublicKey"]
    );
}

#[test]
fn approver_manifest_chain_is_accepted_and_pins_the_rotated_key() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let values = fixture["approverManifests"].as_array().unwrap();
    let pin = verify_chain(&fixture, values).expect("valid chain");
    assert_eq!(pin.key_version, 2);
    assert_eq!(pin.manifest_revision, 2);
    assert_eq!(&pin.message_public_key, keys.approver_v2_box.public_key());
    assert_eq!(
        b64(&pin.message_key_fingerprint()),
        values[1]["messageKeyFingerprint"]
    );

    let first = verify_chain(&fixture, &values[..1]).expect("first introduction");
    let resumed = verify_approver_manifest_chain(
        &manifests(&values[1..]).unwrap(),
        organization(&fixture),
        Some(&first),
    )
    .unwrap();
    assert_eq!(resumed, Some(pin.clone()));
    assert_eq!(
        verify_approver_manifest_chain(&[], organization(&fixture), Some(&pin)).unwrap(),
        Some(pin)
    );
}

#[test]
fn wrapper_context_hashes_and_identity_aad_are_byte_identical() {
    let fixture = fixture();
    let keys = keys(&fixture);
    for (value, approver) in fixture["submissions"]
        .as_array()
        .unwrap()
        .iter()
        .zip([&keys.approver_v1_box, &keys.approver_v2_box])
    {
        let submission = parse(value).expect("fixture submission");
        let identity_value = json!({
            "contractVersion": value["contractVersion"],
            "protocolVersion": value["protocolVersion"],
            "organizationId": value["organizationId"],
            "submissionId": value["submissionId"],
            "agentId": value["agentId"],
            "submissionKind": value["submissionKind"],
            "entryType": value["entryType"],
            "target": value["target"],
        });
        let canonical_identity = serde_jcs::to_vec(&identity_value).unwrap();
        assert_eq!(submission.identity.canonical().unwrap(), canonical_identity);
        assert_eq!(
            submission.identity.payload_aad().unwrap(),
            [b"PLDNSUB1AAD".as_slice(), &canonical_identity].concat()
        );
        let descriptor_hash: [u8; 32] =
            Sha256::digest([b"PLDNSUB1ID".as_slice(), &canonical_identity].concat()).into();
        assert_eq!(
            submission.identity.descriptor_hash().unwrap(),
            descriptor_hash
        );

        for (field, kind, identity, version, fingerprint) in [
            (
                "encodedAgentWrappedDek",
                RecipientKeyKind::AgentX25519,
                &keys.agent_box,
                &value["agentKeyVersion"],
                &value["agentKeyFingerprint"],
            ),
            (
                "encodedApproverWrappedDek",
                RecipientKeyKind::OrganizationApproverX25519,
                approver,
                &value["approverKeyVersion"],
                &value["approverMessageKeyFingerprint"],
            ),
        ] {
            assert_eq!(
                b64(&compute_key_fingerprint(identity.public_key(), kind)),
                *fingerprint
            );
            let context = WrapperContext {
                protocol_version: 2,
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                purpose: WrapperPurpose::SubmissionDek,
                scope: EnvelopeScope {
                    organization_id: *organization(&fixture).as_bytes(),
                    vault_id: [0; 16],
                    entry_id: None,
                    grant_or_request_id: Some(*uuid(&value["submissionId"]).as_bytes()),
                    agent_id: Some(*uuid(&value["agentId"]).as_bytes()),
                    member_id: None,
                },
                resource_revision: value["submissionRevision"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                wrapped_key_version: 1,
                member_key_generation: None,
                recipient_key_kind: kind,
                recipient_key_version: u32::try_from(version.as_u64().unwrap()).unwrap(),
                recipient_fingerprint: unb64(fingerprint.as_str().unwrap()).try_into().unwrap(),
                parent_descriptor_hash: Some(descriptor_hash),
            };
            let expected_hash: [u8; 32] = Sha256::digest(
                [
                    b"PLDNX2CTX".as_slice(),
                    &context.canonical_bytes().expect("wrapper context"),
                ]
                .concat(),
            )
            .into();
            let package = open_sealed_box(&unb64(value[field].as_str().unwrap()), identity)
                .expect("fixture wrap opens");
            let package = package.expose_for_crypto_operation();
            assert_eq!(package.len(), 72);
            assert_eq!(&package[..8], b"PLDNX2K1");
            assert_eq!(package[8..40], seed(&fixture, "submissionDek"));
            assert_eq!(package[40..], expected_hash, "{field}");
        }

        let sealed = unb64(value["encodedPayload"].as_str().unwrap());
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(&seed(&fixture, "submissionDek")))
            .decrypt(
                XNonce::from_slice(&sealed[..24]),
                Payload {
                    msg: &sealed[24..],
                    aad: &submission.identity.payload_aad().unwrap(),
                },
            )
            .expect("identity AAD authenticates the fixture payload");
        assert_eq!(
            plaintext,
            serde_jcs::to_vec(&fixture["expectedPlaintext"]).unwrap()
        );
    }
}

#[test]
fn fixture_submissions_round_trip_and_open_for_agent_and_approver() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let agent_key = agent_signing_public_key(&fixture);
    let values = fixture["submissions"].as_array().unwrap();
    let first = parse(&values[0]).unwrap();
    let second = parse(&values[1]).unwrap();
    assert_eq!(
        first.to_value(),
        values[0],
        "transport encoding is canonical"
    );
    assert_eq!(second.to_value(), values[1]);
    first.verify_agent_signature(&agent_key).unwrap();
    second.verify_agent_signature(&agent_key).unwrap();

    for submission in [&first, &second] {
        let opened = open_agent_submission(
            submission,
            &agent_authority(&fixture, &agent_key, &keys.agent_box),
        )
        .expect("Agent opens its own submission");
        assert_eq!(opened_as_value(&opened), fixture["expectedPlaintext"]);
    }
    let opened = open_agent_submission(
        &first,
        &approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
    )
    .unwrap();
    assert_eq!(opened_as_value(&opened), fixture["expectedPlaintext"]);
    let opened = open_agent_submission(
        &second,
        &approver_authority(&fixture, &agent_key, 2, &keys.approver_v2_box),
    )
    .unwrap();
    assert_eq!(opened_as_value(&opened), fixture["expectedPlaintext"]);

    verify_rewrap(&first, &second, 2).expect("fixture re-wrap is accepted");
    expect_error(
        open_agent_submission(
            &second,
            &approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
        ),
        "recipient-key-mismatch",
        "rotated submission is not openable with the previous approver key",
    );
}

#[test]
fn every_contract_negative_submission_case_fails_closed_with_its_code() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let agent_key = agent_signing_public_key(&fixture);
    let submission = fixture["submissions"][0].clone();
    let with = |field: &str, value: Value| {
        let mut changed = submission.clone();
        changed[field] = value;
        changed
    };
    let target = |field: &str, value: Value| {
        let mut changed = submission.clone();
        changed["target"][field] = value;
        changed
    };
    let mut unknown = submission.clone();
    unknown["note"] = json!("x");
    let mut flipped = with("submissionKind", json!(1));
    flipped["target"] = json!({ "kind": "new" });
    let cases = [
        (
            "backend substitutes organization",
            with(
                "organizationId",
                json!("1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"),
            ),
            "invalid-agent-signature",
        ),
        (
            "agent substitutes organization",
            resign(
                with(
                    "organizationId",
                    json!("1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"),
                ),
                &keys,
            ),
            "context-mismatch",
        ),
        (
            "agent replays under another submission id",
            resign(
                with(
                    "submissionId",
                    json!("1d1d1d1d-1d1d-4d1d-8d1d-1d1d1d1d1d1d"),
                ),
                &keys,
            ),
            "wrapper-context-mismatch",
        ),
        (
            "agent retargets update to another entry",
            resign(
                target("entryId", json!("1f1f1f1f-1f1f-4f1f-8f1f-1f1f1f1f1f1f")),
                &keys,
            ),
            "wrapper-context-mismatch",
        ),
        (
            "agent rewrites expected revision",
            resign(target("expectedEntryRevision", json!("8")), &keys),
            "wrapper-context-mismatch",
        ),
        (
            "agent flips update to new",
            resign(flipped, &keys),
            "wrapper-context-mismatch",
        ),
        (
            "agent changes entry type",
            resign(with("entryType", json!(0)), &keys),
            "wrapper-context-mismatch",
        ),
        (
            "script entry type is rejected",
            resign(with("entryType", json!(2)), &keys),
            "unsupported-entry-type",
        ),
        (
            "unknown transport field",
            resign(unknown, &keys),
            "unknown-field",
        ),
        (
            "stale approver key version",
            resign(with("approverKeyVersion", json!(0)), &keys),
            "recipient-key-mismatch",
        ),
        (
            "revision replay inside wrapper",
            resign(with("submissionRevision", json!("2")), &keys),
            "wrapper-context-mismatch",
        ),
        (
            "approver wrap corruption",
            resign(
                with(
                    "encodedApproverWrappedDek",
                    flip_last_byte(&submission["encodedApproverWrappedDek"]),
                ),
                &keys,
            ),
            "wrapper-open-failed",
        ),
        (
            "approver wrap swapped with agent wrap",
            resign(
                with(
                    "encodedApproverWrappedDek",
                    submission["encodedAgentWrappedDek"].clone(),
                ),
                &keys,
            ),
            "wrapper-open-failed",
        ),
        (
            "payload ciphertext corruption",
            resign(
                with(
                    "encodedPayload",
                    flip_last_byte(&submission["encodedPayload"]),
                ),
                &keys,
            ),
            "payload-auth-failed",
        ),
        (
            "signature corruption",
            with(
                "agentSignature",
                flip_last_byte(&submission["agentSignature"]),
            ),
            "invalid-agent-signature",
        ),
    ];
    for (case, candidate, code) in cases {
        let opened = parse(&candidate).and_then(|parsed| {
            open_agent_submission(
                &parsed,
                &approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
            )
        });
        expect_error(opened, code, case);
    }

    let reencrypt = |mutate: &dyn Fn(&mut Value)| {
        let mut payload = fixture["expectedPlaintext"].clone();
        mutate(&mut payload);
        let parsed = parse(&submission).unwrap();
        let nonce = hex_24(
            fixture["deterministicInputs"]["payloadNonce"]
                .as_str()
                .unwrap(),
        );
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&seed(&fixture, "submissionDek")))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &serde_jcs::to_vec(&payload).unwrap(),
                    aad: &parsed.identity.payload_aad().unwrap(),
                },
            )
            .unwrap();
        resign(
            with(
                "encodedPayload",
                json!(b64(&[nonce.as_slice(), &ciphertext].concat())),
            ),
            &keys,
        )
    };
    for (case, candidate, code) in [
        (
            "inner identity must equal outer identity",
            reencrypt(&|payload| {
                payload["identity"]["agentId"] = json!("1b1b1b1b-1b1b-4b1b-8b1b-1b1b1b1b1b1b");
            }),
            "identity-mismatch",
        ),
        (
            "v1 payload excludes TOTP",
            reencrypt(&|payload| payload["content"]["totp"] = json!("JBSWY3DPEHPK3PXP")),
            "unknown-field",
        ),
    ] {
        for recipient in [
            approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
            agent_authority(&fixture, &agent_key, &keys.agent_box),
        ] {
            expect_error(
                parse(&candidate).and_then(|parsed| open_agent_submission(&parsed, &recipient)),
                code,
                case,
            );
        }
    }
}

fn hex_24(value: &str) -> [u8; 24] {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[test]
fn every_contract_negative_manifest_case_fails_closed_with_its_code() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let v1 = fixture["approverManifests"][0].clone();
    let v2 = fixture["approverManifests"][1].clone();
    let with = |manifest: &Value, field: &str, value: Value| {
        let mut changed = manifest.clone();
        changed[field] = value;
        changed
    };
    let mut skipped = v2.clone();
    skipped["keyVersion"] = json!(3);
    let skipped = sign_manifest(
        skipped,
        &keys.approver_v2_sign,
        Some(&keys.approver_v1_sign),
    );
    let attacker = SigningKey::from_bytes(&[0x99; 32]);
    let mut forged = v2.clone();
    forged["signingPublicKey"] = json!(b64(attacker.verifying_key().as_bytes()));
    forged["signingKeyFingerprint"] = json!(b64(&compute_key_fingerprint(
        attacker.verifying_key().as_bytes(),
        RecipientKeyKind::OrganizationApproverEd25519
    )));
    let forged = sign_manifest(forged, &attacker, Some(&attacker));
    let mut without_continuity = v2.clone();
    without_continuity
        .as_object_mut()
        .unwrap()
        .remove("continuitySignature");

    for (case, chain, code) in [
        (
            "same revision replay",
            vec![v1.clone(), v1.clone()],
            "manifest-rollback",
        ),
        (
            "foreign organization",
            vec![with(
                &v1,
                "organizationId",
                json!("1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"),
            )],
            "manifest-organization-mismatch",
        ),
        (
            "self signature",
            vec![with(&v1, "signature", flip_last_byte(&v1["signature"]))],
            "manifest-signature-invalid",
        ),
        (
            "continuity signature",
            vec![
                v1.clone(),
                with(
                    &v2,
                    "continuitySignature",
                    flip_last_byte(&v2["continuitySignature"]),
                ),
            ],
            "manifest-continuity-invalid",
        ),
        (
            "skipped key version",
            vec![v1.clone(), skipped],
            "manifest-key-version-skip",
        ),
        (
            "server-forged rotation",
            vec![v1.clone(), forged],
            "manifest-continuity-invalid",
        ),
        (
            "rotated manifest needs continuity",
            vec![without_continuity],
            "manifest-continuity-invalid",
        ),
    ] {
        expect_error(verify_chain(&fixture, &chain), code, case);
    }

    let pin_v2 = verify_chain(&fixture, &[v1.clone(), v2.clone()]).unwrap();
    expect_error(
        verify_approver_manifest_chain(
            &manifests(&[v1]).unwrap(),
            organization(&fixture),
            Some(&pin_v2),
        ),
        "manifest-rollback",
        "a pinned profile rejects an older manifest",
    );
    expect_error(
        verify_approver_manifest_chain(
            &manifests(&[v2]).unwrap(),
            Uuid::parse_str("1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a").unwrap(),
            Some(&pin_v2),
        ),
        "manifest-organization-mismatch",
        "a pin never moves to another organization",
    );
}

#[test]
fn every_contract_negative_rewrap_case_fails_closed_with_its_code() {
    let fixture = fixture();
    let first = parse(&fixture["submissions"][0]).unwrap();
    let second = parse(&fixture["submissions"][1]).unwrap();
    let mut changed_value = fixture["submissions"][1].clone();
    changed_value["encodedPayload"] = flip_last_byte(&changed_value["encodedPayload"]);
    let changed = parse(&changed_value).unwrap();
    expect_error(
        verify_rewrap(&second, &first, 1),
        "revision-replay",
        "older revision",
    );
    expect_error(
        verify_rewrap(&first, &changed, 2),
        "rewrap-changed-payload",
        "re-wrap must not change payload",
    );
    expect_error(
        verify_rewrap(&first, &second, 3),
        "recipient-key-mismatch",
        "re-wrap must target current key",
    );
}

#[test]
fn built_submission_opens_for_agent_and_approver_and_rewraps_without_touching_the_payload() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let agent_signing = Ed25519Identity::from_seed(seed(&fixture, "agentEd25519Seed").to_vec())
        .expect("Agent signing identity");
    let agent_key = *agent_signing.public_key();
    let values = fixture["approverManifests"].as_array().unwrap();
    let pin_v1 = verify_chain(&fixture, &values[..1]).unwrap();
    let pin_v2 = verify_chain(&fixture, values).unwrap();
    let identity = SubmissionIdentity {
        organization_id: organization(&fixture),
        submission_id: Uuid::from_u128(0x1111_2222_4333_8444_9555_6666_7777_8888),
        agent_id: uuid(&fixture["context"]["agentId"]),
        entry_type: SubmissionEntryType::Credential,
        target: SubmissionTarget::New {
            suggested_vault_id: Some(uuid(&json!("0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"))),
        },
    };
    let content = SubmissionContent::Credential {
        username: SecretString::from("builder@example.invalid".to_owned()),
        password: SecretString::from("builder-Synthetic-Only-7!".to_owned()),
        url: Some("https://example.invalid/login".to_owned()),
        notes: None,
    };
    let built = build_agent_submission(
        &SubmissionBuildContext {
            identity: identity.clone(),
            agent_access_epoch: 4,
            agent_key_version: 3,
            agent_encryption_public_key: keys.agent_box.public_key(),
            agent_signing: &agent_signing,
            approver: &pin_v1,
        },
        "Builder Account",
        &content,
    )
    .expect("build");
    let reparsed = parse(&built.to_value()).expect("built transport is strictly valid");
    assert_eq!(reparsed, built);
    assert_eq!(built.submission_revision, 1);
    assert_eq!(built.approver_key_version, 1);
    assert_eq!(built.approver_manifest_revision, 1);
    assert!(
        !serde_json::to_string(&built.to_value())
            .unwrap()
            .contains("builder-Synthetic")
    );

    let agent = open_agent_submission(
        &built,
        &agent_authority(&fixture, &agent_key, &keys.agent_box),
    )
    .expect("Agent opens");
    let approver = open_agent_submission(
        &built,
        &approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
    )
    .expect("approver opens");
    for opened in [&agent, &approver] {
        assert_eq!(opened.identity, identity);
        assert_eq!(opened.label, "Builder Account");
        assert_eq!(opened.content.username(), Some("builder@example.invalid"));
    }

    let rewrapped =
        rewrap_agent_submission(&built, &keys.agent_box, &agent_signing, &pin_v2).expect("rewrap");
    verify_rewrap(&built, &rewrapped, 2).unwrap();
    assert_eq!(rewrapped.submission_revision, 2);
    assert_eq!(rewrapped.approver_manifest_revision, 2);
    assert_eq!(
        rewrapped.to_value()["encodedPayload"],
        built.to_value()["encodedPayload"]
    );
    assert_ne!(
        rewrapped.to_value()["encodedAgentWrappedDek"],
        built.to_value()["encodedAgentWrappedDek"]
    );
    open_agent_submission(
        &rewrapped,
        &approver_authority(&fixture, &agent_key, 2, &keys.approver_v2_box),
    )
    .expect("rotated approver opens the re-wrap");
    expect_error(
        open_agent_submission(
            &rewrapped,
            &approver_authority(&fixture, &agent_key, 1, &keys.approver_v1_box),
        ),
        "recipient-key-mismatch",
        "previous approver key cannot open the re-wrap",
    );
    expect_error(
        rewrap_agent_submission(&rewrapped, &keys.agent_box, &agent_signing, &pin_v2),
        "recipient-key-mismatch",
        "re-wrap requires a newer approver key",
    );

    let fresh = build_agent_submission(
        &SubmissionBuildContext {
            identity: identity.clone(),
            agent_access_epoch: 4,
            agent_key_version: 3,
            agent_encryption_public_key: keys.agent_box.public_key(),
            agent_signing: &agent_signing,
            approver: &pin_v1,
        },
        "Builder Account",
        &content,
    )
    .unwrap();
    assert_ne!(
        fresh.to_value()["encodedPayload"],
        built.to_value()["encodedPayload"],
        "every build uses a fresh DEK and nonce"
    );
}

#[test]
fn builder_rejects_invalid_input_before_encryption() {
    let fixture = fixture();
    let keys = keys(&fixture);
    let agent_signing =
        Ed25519Identity::from_seed(seed(&fixture, "agentEd25519Seed").to_vec()).unwrap();
    let pin = verify_chain(
        &fixture,
        &fixture["approverManifests"].as_array().unwrap()[..1],
    )
    .unwrap();
    let identity = |organization_id: Uuid, entry_type| SubmissionIdentity {
        organization_id,
        submission_id: Uuid::from_u128(0x1111_2222_4333_8444_9555_6666_7777_8888),
        agent_id: uuid(&fixture["context"]["agentId"]),
        entry_type,
        target: SubmissionTarget::New {
            suggested_vault_id: None,
        },
    };
    let credential = |url: Option<&str>| SubmissionContent::Credential {
        username: SecretString::from("user".to_owned()),
        password: SecretString::from("password".to_owned()),
        url: url.map(str::to_owned),
        notes: None,
    };
    let build = |identity: SubmissionIdentity, label: &str, content: &SubmissionContent| {
        build_agent_submission(
            &SubmissionBuildContext {
                identity,
                agent_access_epoch: 4,
                agent_key_version: 3,
                agent_encryption_public_key: keys.agent_box.public_key(),
                agent_signing: &agent_signing,
                approver: &pin,
            },
            label,
            content,
        )
    };
    let org = organization(&fixture);
    let cred = SubmissionEntryType::Credential;
    expect_error(
        build(identity(org, cred), "", &credential(None)),
        "invalid-input",
        "empty label",
    );
    expect_error(
        build(identity(org, cred), &"x".repeat(257), &credential(None)),
        "invalid-input",
        "label limit",
    );
    expect_error(
        build(identity(org, cred), "Cafe\u{301}", &credential(None)),
        "invalid-input",
        "label must be NFC",
    );
    expect_error(
        build(
            identity(org, cred),
            "Label",
            &credential(Some("http://example.invalid")),
        ),
        "invalid-input",
        "credential URL must be https",
    );
    expect_error(
        build(
            identity(org, SubmissionEntryType::Key),
            "Label",
            &credential(None),
        ),
        "invalid-input",
        "content must match the declared entry type",
    );
    expect_error(
        build(
            identity(
                Uuid::from_u128(0x2a2a_2a2a_2a2a_4a2a_8a2a_2a2a_2a2a_2a2a),
                cred,
            ),
            "Label",
            &credential(None),
        ),
        "context-mismatch",
        "approver key must belong to the submission organization",
    );
    let oversized = SubmissionContent::Credential {
        username: SecretString::from("user".to_owned()),
        password: SecretString::from("p".repeat(4097)),
        url: None,
        notes: None,
    };
    expect_error(
        build(identity(org, cred), "Label", &oversized),
        "invalid-input",
        "password limit",
    );
}
