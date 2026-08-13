use palladin_crypto::{
    ExpectedGrantContext, GrantEnvelopeV2, X25519Identity, decrypt_grant_payload,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

fn fixture() -> GrantEnvelopeV2 {
    let root: Value = serde_json::from_str(include_str!(
        "../../../contracts/vault-v2/fixtures/v2/vectors/envelopes.json"
    ))
    .unwrap();
    let envelope = root["aeadVectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["aadProfile"] == "grant-payload")
        .unwrap()["envelope"]
        .clone();
    GrantEnvelopeV2 {
        organization_id: uuid(&envelope, "organizationId"),
        vault_id: uuid(&envelope, "vaultId"),
        grant_id: uuid(&envelope, "grantId"),
        agent_id: uuid(&envelope, "agentId"),
        entry_id: uuid(&envelope, "entryId"),
        approved_methods: 1,
        grant_envelope_revision: number(&envelope, "grantEnvelopeRevision"),
        entry_revision: number(&envelope, "entryRevision"),
        protocol_version: envelope["header"]["protocolVersion"].as_u64().unwrap() as u16,
        algorithm_suite: envelope["header"]["algorithmSuite"].as_u64().unwrap() as u16,
        grant_key_version: envelope["grantKeyVersion"].as_u64().unwrap() as u32,
        member_key_generation: envelope["header"]["memberKeyGeneration"].as_u64().unwrap() as u32,
        recipient_agent_key_version: envelope["recipientAgentKeyVersion"].as_u64().unwrap() as u32,
        field_ids: vec!["password".into(), "username".into()],
        ciphertext: string(&envelope, "ciphertext"),
        nonce: string(&envelope["header"], "nonce"),
        agent_wrapped_grant_dek: string(&envelope, "agentWrappedGrantDek"),
        agent_wrapper_suite: 1,
        agent_key_fingerprint: string(&envelope, "recipientAgentKeyFingerprint"),
        envelope_expires_at: Some(string(&envelope, "expiresAt")),
        envelope_remaining_uses: Some(envelope["remainingUses"].as_u64().unwrap() as u32),
    }
}

fn decrypt(envelope: &GrantEnvelopeV2) -> Result<Vec<u8>, palladin_crypto::CryptoError> {
    let identity = X25519Identity::from_private_bytes(
        hex::decode("d2bfcbd8f8dadf5996863e0d62d9b6b6906e532aba030b9a82a296865d06c21a").unwrap(),
    )
    .unwrap();
    decrypt_grant_payload(
        envelope,
        &identity,
        ExpectedGrantContext {
            organization_id: envelope.organization_id,
            vault_id: envelope.vault_id,
            entry_id: envelope.entry_id,
            agent_id: envelope.agent_id,
            requested_method: 1,
            now: OffsetDateTime::from_unix_timestamp(1_752_732_000).unwrap(),
        },
    )
    .map(|payload| payload.expose_for_authorized_operation().to_vec())
}

#[test]
fn frozen_grant_payload_decrypts_and_exposes_only_filtered_fields() {
    assert_eq!(
        decrypt(&fixture()).unwrap(),
        br#"{"password":"not-a-real-password","username":"fixture-user"}"#
    );
}

#[test]
fn grant_scope_expiry_methods_and_fields_fail_closed() {
    let mut envelope = fixture();
    envelope.approved_methods = 2;
    assert!(decrypt(&envelope).is_err());
    let mut envelope = fixture();
    envelope.field_ids = vec!["password".into()];
    assert!(decrypt(&envelope).is_err());
    let mut envelope = fixture();
    envelope.envelope_expires_at = Some("2020-01-01T00:00:00Z".into());
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.organization_id = Uuid::nil();
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.entry_revision += 1;
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.recipient_agent_key_version += 1;
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.agent_key_fingerprint = "invalid".into();
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.nonce = "invalid".into();
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.ciphertext = "invalid".into();
    assert!(decrypt(&envelope).is_err());

    let mut envelope = fixture();
    envelope.envelope_remaining_uses = Some(0);
    assert!(decrypt(&envelope).is_err());
}

#[test]
fn requested_method_must_be_an_approved_single_method() {
    let envelope = fixture();
    let identity = X25519Identity::from_private_bytes(
        hex::decode("d2bfcbd8f8dadf5996863e0d62d9b6b6906e532aba030b9a82a296865d06c21a").unwrap(),
    )
    .unwrap();
    let context = ExpectedGrantContext {
        organization_id: envelope.organization_id,
        vault_id: envelope.vault_id,
        entry_id: envelope.entry_id,
        agent_id: envelope.agent_id,
        requested_method: 2,
        now: OffsetDateTime::from_unix_timestamp(1_752_732_000).unwrap(),
    };

    assert!(decrypt_grant_payload(&envelope, &identity, context).is_err());
}

fn string(value: &Value, field: &str) -> String {
    value[field].as_str().unwrap().to_owned()
}
fn uuid(value: &Value, field: &str) -> Uuid {
    Uuid::parse_str(value[field].as_str().unwrap()).unwrap()
}
fn number(value: &Value, field: &str) -> u64 {
    value[field].as_str().unwrap().parse().unwrap()
}
