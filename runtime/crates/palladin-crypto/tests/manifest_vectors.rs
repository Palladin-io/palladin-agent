use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_crypto::{
    AgentIdentityBinding, CryptoError, MemberPairingConfirmation, PairingRelayStatus,
    VaultManifestV2, confirm_pairing, confirm_pairing_from_relay, prepare_pairing,
    verify_current_manifest, verify_manifest_update,
};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingFixture {
    signed_manifests: Vec<VaultManifestV2>,
    vectors: Vec<PairingVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingVector {
    transcript: TranscriptIdentity,
    canonical_transcript: String,
    short_authentication_string: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TranscriptIdentity {
    activation_id: String,
    organization_id: String,
    agent_id: String,
    agent_x25519_fingerprint: String,
    agent_ed25519_fingerprint: String,
}

fn fixture() -> PairingFixture {
    serde_json::from_str(include_str!(
        "../../../contracts/vault-v2/fixtures/v2/vectors/pairing.json"
    ))
    .expect("frozen pairing fixture")
}

fn decode_32(value: &str) -> [u8; 32] {
    URL_SAFE_NO_PAD.decode(value).unwrap().try_into().unwrap()
}

fn identity(vector: &PairingVector) -> AgentIdentityBinding {
    AgentIdentityBinding {
        organization_id: Uuid::parse_str(&vector.transcript.organization_id).unwrap(),
        agent_id: Uuid::parse_str(&vector.transcript.agent_id).unwrap(),
        x25519_fingerprint: decode_32(&vector.transcript.agent_x25519_fingerprint),
        ed25519_fingerprint: decode_32(&vector.transcript.agent_ed25519_fingerprint),
    }
}

#[test]
fn pairing_transcript_and_sas_are_byte_identical_to_frozen_fixture() {
    let fixture = fixture();
    let vector = &fixture.vectors[0];
    let candidate = prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity(vector),
        &fixture.signed_manifests,
    )
    .expect("prepare pairing");

    assert_eq!(
        serde_json::to_string(candidate.transcript()).unwrap(),
        vector.canonical_transcript
    );
    assert_eq!(
        candidate.short_authentication_string(),
        vector.short_authentication_string
    );
    let digest = candidate.transcript_digest().to_owned();
    assert_eq!(
        confirm_pairing(
            candidate,
            &MemberPairingConfirmation {
                transcript_digest: digest,
                short_authentication_string: vector.short_authentication_string.clone(),
            },
        )
        .expect("confirmed")
        .len(),
        2
    );
}

#[test]
fn pairing_rejects_wrong_agent_and_wrong_sas() {
    let fixture = fixture();
    let vector = &fixture.vectors[0];
    let mut wrong = identity(vector);
    wrong.agent_id = Uuid::parse_str("66666666-6666-4666-8666-666666666666").unwrap();
    assert!(matches!(
        prepare_pairing(
            Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
            &wrong,
            &fixture.signed_manifests,
        ),
        Err(CryptoError::InvalidProfile)
    ));

    let candidate = prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity(vector),
        &fixture.signed_manifests,
    )
    .unwrap();
    let digest = candidate.transcript_digest().to_owned();
    assert!(matches!(
        confirm_pairing(
            candidate,
            &MemberPairingConfirmation {
                transcript_digest: digest,
                short_authentication_string: "0000-0000-0000".to_owned(),
            },
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    let candidate = prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity(vector),
        &fixture.signed_manifests,
    )
    .unwrap();
    assert!(matches!(
        confirm_pairing(
            candidate,
            &MemberPairingConfirmation {
                transcript_digest: URL_SAFE_NO_PAD.encode([0_u8; 32]),
                short_authentication_string: vector.short_authentication_string.clone(),
            },
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    let mut reversed = fixture.signed_manifests.clone();
    reversed.reverse();
    assert!(matches!(
        prepare_pairing(
            Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
            &identity(vector),
            &reversed,
        ),
        Err(CryptoError::InvalidProfile)
    ));
}

#[test]
fn pinned_anchor_rejects_replay_and_embedded_key_substitution() {
    let fixture = fixture();
    let vector = &fixture.vectors[0];
    let identity = identity(vector);
    let candidate = prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity,
        &fixture.signed_manifests,
    )
    .unwrap();
    let digest = candidate.transcript_digest().to_owned();
    let anchors = confirm_pairing(
        candidate,
        &MemberPairingConfirmation {
            transcript_digest: digest,
            short_authentication_string: vector.short_authentication_string.clone(),
        },
    )
    .unwrap();
    let manifest = &fixture.signed_manifests[1];
    let anchor = anchors
        .iter()
        .find(|anchor| anchor.vault_id.to_string() == manifest.vault_id)
        .unwrap();

    let current = verify_current_manifest(manifest, &identity, anchor)
        .expect("the pinned revision must remain usable after signature verification");
    assert_eq!(current, *anchor);

    let mut previous_anchor = anchor.clone();
    previous_anchor.manifest_revision = 13;
    let advanced = verify_manifest_update(manifest, &identity, &previous_anchor)
        .expect("signature must verify against the previously pinned key");
    assert_eq!(advanced.manifest_revision, 14);

    assert!(matches!(
        verify_manifest_update(manifest, &identity, anchor),
        Err(CryptoError::StaleInput)
    ));

    let mut substituted = manifest.clone();
    substituted.manifest_revision = "15".into();
    substituted.vault_signing_public_key = URL_SAFE_NO_PAD.encode([42_u8; 32]);
    assert!(verify_manifest_update(&substituted, &identity, anchor).is_err());
}

#[test]
fn relay_status_is_bound_to_activation_digest_terminal_state_and_expiry() {
    let fixture = fixture();
    let vector = &fixture.vectors[0];
    let activation_id = Uuid::parse_str(&vector.transcript.activation_id).unwrap();
    let candidate =
        prepare_pairing(activation_id, &identity(vector), &fixture.signed_manifests).unwrap();
    let digest = candidate.transcript_digest().to_owned();
    let relay = PairingRelayStatus {
        activation_id: activation_id.to_string(),
        status: "confirmed".to_owned(),
        expires_at: "2026-07-27T00:00:00Z".to_owned(),
        confirmed_pairing_digest: Some(digest),
    };
    let now = OffsetDateTime::parse(
        "2026-07-26T23:59:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(
        confirm_pairing_from_relay(candidate, &relay, now)
            .unwrap()
            .len(),
        2
    );

    let candidate =
        prepare_pairing(activation_id, &identity(vector), &fixture.signed_manifests).unwrap();
    let after_deadline = OffsetDateTime::parse(
        "2026-07-27T00:00:01Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(
        confirm_pairing_from_relay(candidate, &relay, after_deadline)
            .unwrap()
            .len(),
        2
    );

    for mutation in ["pending", "expired", "stale"] {
        let candidate =
            prepare_pairing(activation_id, &identity(vector), &fixture.signed_manifests).unwrap();
        let mut invalid = relay.clone();
        invalid.status = mutation.to_owned();
        assert!(confirm_pairing_from_relay(candidate, &invalid, now).is_err());
    }
}

#[test]
fn empty_candidate_set_requires_the_same_independent_digest_confirmation() {
    let fixture = fixture();
    let vector = &fixture.vectors[0];
    let candidate = prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity(vector),
        &[],
    )
    .expect("empty organization pairing");
    assert!(candidate.transcript().vaults.is_empty());
    let digest = candidate.transcript_digest().to_owned();
    assert!(
        confirm_pairing(
            candidate,
            &MemberPairingConfirmation {
                transcript_digest: digest,
                short_authentication_string: candidate_sas_for_empty(vector),
            },
        )
        .unwrap()
        .is_empty()
    );
}

fn candidate_sas_for_empty(vector: &PairingVector) -> String {
    prepare_pairing(
        Uuid::parse_str(&vector.transcript.activation_id).unwrap(),
        &identity(vector),
        &[],
    )
    .unwrap()
    .short_authentication_string()
    .to_owned()
}
