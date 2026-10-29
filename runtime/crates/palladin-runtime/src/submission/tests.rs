use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use palladin_api::{ApiClient, SigningContext};
use palladin_core::host::ApiHost;
use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicDiscoveryCacheCommitment, PublicProfileConfig,
    PublicVaultTrustAnchor,
};
use palladin_core::secret::OrganizationApiKey;
use palladin_credential::generator::{CharacterClass, PasswordPolicy};
use palladin_crypto::{Ed25519Identity, X25519Identity, compute_key_fingerprint, verify_rewrap};
use palladin_platform::secure_store::{OperationAuthorization, OperationLease, OperationScope};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::Sha512;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::discovery::LocalDiscoveryIndex;
use crate::{ManifestRevisionPersistence, RuntimeOperation};

const FIXTURE: &str = include_str!("../../../../contracts/agent-submission/v1/fixture.json");
const ORGANIZATION_ID: &str = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a";
const AGENT_ID: &str = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b";
const FIXTURE_SUBMISSION_ID: &str = "0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d";

type Handler = Box<dyn FnOnce(&str) -> (u16, String) + Send>;
type TrustCase = (
    Vec<Handler>,
    Option<PublicApproverTrustAnchor>,
    Option<&'static str>,
    SubmissionNotSaved,
);

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture")
}

fn seed(name: &str) -> [u8; 32] {
    hex::decode(fixture()["deterministicInputs"][name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn box_identity(name: &str) -> X25519Identity {
    X25519Identity::from_private_bytes(Sha512::digest(seed(name))[..32].to_vec()).unwrap()
}

fn agent_signing() -> Ed25519Identity {
    Ed25519Identity::from_seed(seed("agentEd25519Seed").to_vec()).unwrap()
}

fn manifest(index: usize) -> Value {
    fixture()["approverManifests"][index].clone()
}

fn manifests_response(manifests: &[Value]) -> String {
    json!({
        "organizationId": ORGANIZATION_ID,
        "agentKeyVersion": 3,
        "agentAccessEpoch": "4",
        "manifests": manifests,
    })
    .to_string()
}

fn respond(status: u16, body: String) -> Handler {
    Box::new(move |_| (status, body))
}

fn accept_post() -> Handler {
    Box::new(|request| {
        let body = request_body(request);
        (
            201,
            json!({
                "submissionId": body["submissionId"],
                "state": "pending",
                "submissionRevision": "1",
            })
            .to_string(),
        )
    })
}

fn request_body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").expect("body").1).expect("JSON body")
}

async fn server(handlers: Vec<Handler>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    tokio::spawn(async move {
        for handler in handlers {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_request(&mut stream).await;
            let (status, body) = handler(&request);
            captured.lock().unwrap().push(request);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        }
    });
    (format!("http://{address}"), requests)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await.expect("read");
        assert!(read > 0, "request ended early");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.trim().parse::<usize>().unwrap());
            if bytes.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(bytes).expect("UTF-8 request")
}

#[derive(Default)]
struct RecordingPersistence {
    anchors: Mutex<Vec<(Option<PublicApproverTrustAnchor>, PublicApproverTrustAnchor)>>,
}

impl ManifestRevisionPersistence for RecordingPersistence {
    fn persist_approver_anchor(
        &self,
        _identity_id: &str,
        expected: Option<&PublicApproverTrustAnchor>,
        next: &PublicApproverTrustAnchor,
        _signing: &Ed25519Identity,
        _lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        self.anchors
            .lock()
            .unwrap()
            .push((expected.cloned(), next.clone()));
        Ok(())
    }

    fn persist_manifest_batch(
        &self,
        _: &str,
        _: &[PublicVaultTrustAnchor],
        _: &[PublicVaultTrustAnchor],
        _: &Ed25519Identity,
        _: &OperationLease,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::IntegrityViolation)
    }

    fn load_discovery_cache(
        &self,
        _: &str,
        _: &str,
        _: Option<&PublicDiscoveryCacheCommitment>,
        _: &X25519Identity,
    ) -> Result<LocalDiscoveryIndex, RuntimeError> {
        Err(RuntimeError::IntegrityViolation)
    }

    fn persist_discovery_batch(
        &self,
        _: &str,
        _: &str,
        _: &[PublicVaultTrustAnchor],
        _: &[PublicVaultTrustAnchor],
        _: Option<&PublicDiscoveryCacheCommitment>,
        _: &PublicDiscoveryCacheCommitment,
        _: &[u8],
        _: &Ed25519Identity,
        _: &OperationLease,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::IntegrityViolation)
    }
}

fn lease() -> OperationLease {
    let scope = OperationScope::new(
        "11111111111111111111111111111111",
        std::iter::empty::<String>(),
    )
    .unwrap();
    OperationAuthorization::for_current_platform(&scope, b"submission-test-operation")
        .unwrap()
        .into_lease()
        .unwrap()
}

fn anchor_from_manifest(manifest: &Value) -> PublicApproverTrustAnchor {
    PublicApproverTrustAnchor {
        organization_id: ORGANIZATION_ID.to_owned(),
        key_version: u32::try_from(manifest["keyVersion"].as_u64().unwrap()).unwrap(),
        manifest_revision: manifest["manifestRevision"].as_str().unwrap().to_owned(),
        signing_public_key: manifest["signingPublicKey"].as_str().unwrap().to_owned(),
        message_public_key: manifest["messagePublicKey"].as_str().unwrap().to_owned(),
    }
}

fn test_session<'a>(
    host: &str,
    operation: RuntimeOperation,
    persistence: &'a RecordingPersistence,
    approver_anchor: Option<PublicApproverTrustAnchor>,
    vault_organization: Option<&str>,
) -> RuntimeSession<'a> {
    let encryption = box_identity("agentX25519Seed");
    let api = ApiClient::new(
        ApiHost::parse(host).unwrap(),
        OrganizationApiKey::new("pl_submission_fixture".to_owned()),
        &encryption,
        "fixture-host",
        Some(SigningContext {
            agent_id: AGENT_ID.to_owned(),
            identity: agent_signing(),
        }),
    )
    .unwrap();
    RuntimeSession {
        profile: PublicAgentEntry {
            name: "fixture".to_owned(),
            identity_id: "11111111111111111111111111111111".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            agent_type: None,
            config_digest: None,
        },
        config: PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host: host.to_owned(),
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some(AGENT_ID.to_owned()),
            agent_active: true,
            encryption_public_key: None,
            signing_public_key: None,
            vault_trust_anchors: vault_organization
                .map(|organization_id| PublicVaultTrustAnchor {
                    organization_id: organization_id.to_owned(),
                    vault_id: "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e".to_owned(),
                    agent_access_epoch: 4,
                    vault_signing_public_key: "A".repeat(43),
                    vault_signing_key_fingerprint: "A".repeat(43),
                    manifest_revision: "1".to_owned(),
                    manifest_signing_key_version: 1,
                    vdk_version: 1,
                })
                .into_iter()
                .collect(),
            discovery_cache: None,
            approver_trust_anchor: approver_anchor,
            binding_signature: String::new(),
        },
        api,
        encryption,
        lease: lease(),
        operation,
        consumed: AtomicBool::new(false),
        pairing_activation_id: None,
        discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
        manifest_persistence: Some(persistence),
        profile_signing: Some(agent_signing()),
        form_map_root: std::path::PathBuf::new(),
        approver_anchor: Mutex::new(None),
    }
}

fn new_credential_request() -> SubmissionRequest<'static> {
    SubmissionRequest {
        target: SubmissionRequestTarget::New {
            suggested_vault_id: Some("0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"),
        },
        entry_type: Some(SubmissionEntryType::Credential),
        label: Some("Example Account"),
        url: Some("https://example.invalid/login"),
        username: Some("agent@example.invalid"),
    }
}

fn policy() -> PasswordPolicy {
    PasswordPolicy {
        length: 40,
        ..PasswordPolicy::default()
    }
}

/// Opens a captured POST/PUT body as the approver group and returns the submitted password.
fn approver_password(body: &Value, approver_seed: &str, key_version: u32) -> String {
    let submission = AgentEntrySubmission::from_value(body).expect("strict transport");
    let signing = agent_signing();
    let approver = box_identity(approver_seed);
    let opened = open_agent_submission(
        &submission,
        &SubmissionAuthority {
            organization_id: Uuid::parse_str(ORGANIZATION_ID).unwrap(),
            agent_id: Uuid::parse_str(AGENT_ID).unwrap(),
            agent_signing_public_key: signing.public_key(),
            recipient: SubmissionRecipient::ApproverGroup {
                key_version,
                identity: &approver,
            },
        },
    )
    .expect("approver opens the submitted payload");
    match opened.content {
        SubmissionContent::Credential { password, .. } => password.expose_secret().to_owned(),
        SubmissionContent::Key { value, .. } => value.expose_secret().to_owned(),
    }
}

#[tokio::test]
async fn generated_submission_is_pinned_encrypted_saved_and_never_leaks_the_secret() {
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        accept_post(),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        Some(ORGANIZATION_ID),
    );

    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Generate(policy()),
        )
        .await
        .expect("submission");

    let saved = result.outcome.as_ref().expect("saved");
    assert_eq!(saved.state, "pending");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/agent/approver-manifests HTTP/1.1"));
    assert!(requests[1].starts_with("POST /api/agent/submissions HTTP/1.1"));
    let body = request_body(&requests[1]);
    assert_eq!(
        body["submissionId"].as_str(),
        result.submission_id.as_deref()
    );
    assert_eq!(body["submissionRevision"], "1");
    assert_eq!(body["agentKeyVersion"], 3);
    assert_eq!(body["agentAccessEpoch"], "4");
    assert_eq!(body["approverKeyVersion"], 1);
    assert_eq!(
        body["target"]["suggestedVaultId"],
        "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"
    );

    let password = approver_password(&body, "approverV1X25519Seed", 1);
    assert_eq!(password.len(), 40);
    for class in [
        CharacterClass::Lowercase,
        CharacterClass::Uppercase,
        CharacterClass::Digit,
    ] {
        assert!(password.chars().any(|character| match class {
            CharacterClass::Lowercase => character.is_ascii_lowercase(),
            CharacterClass::Uppercase => character.is_ascii_uppercase(),
            _ => character.is_ascii_digit(),
        }));
    }
    for request in requests.iter() {
        assert!(
            !request.contains(&password),
            "plaintext never leaves the runtime"
        );
    }
    assert!(!format!("{result:?}").contains(&password));

    let anchors = persistence.anchors.lock().unwrap();
    assert_eq!(*anchors, vec![(None, anchor_from_manifest(&manifest(0)))]);
}

#[tokio::test]
async fn unsatisfiable_policy_is_rejected_before_any_request() {
    let (host, requests) = server(Vec::new()).await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Generate(PasswordPolicy {
                length: 2,
                ..PasswordPolicy::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        result.outcome,
        Err(SubmissionNotSaved::PasswordPolicyUnsatisfiable)
    );
    assert!(result.submission_id.is_none());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_new_requests_are_rejected_before_any_request() {
    let base = new_credential_request();
    let cases = [
        SubmissionRequest {
            url: Some("http://example.invalid"),
            ..base
        },
        SubmissionRequest {
            username: None,
            ..base
        },
        SubmissionRequest {
            label: Some("  "),
            ..base
        },
        SubmissionRequest {
            entry_type: Some(SubmissionEntryType::Key),
            ..base
        },
        SubmissionRequest {
            target: SubmissionRequestTarget::New {
                suggested_vault_id: Some("not-a-uuid"),
            },
            ..base
        },
        SubmissionRequest {
            target: SubmissionRequestTarget::Update {
                vault_id: "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e",
                entry_id: "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f",
            },
            ..base
        },
    ];
    for request in cases {
        let (host, requests) = server(Vec::new()).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::SubmitEntry,
            &persistence,
            None,
            None,
        );
        let result = session
            .submit_entry(request, SubmissionSecret::Generate(policy()))
            .await
            .unwrap();
        assert_eq!(
            result.outcome,
            Err(SubmissionNotSaved::InvalidInput),
            "{request:?}"
        );
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn approver_trust_failures_stop_before_secret_generation_or_upload() {
    let mut forged = manifest(1);
    let attacker = SigningKey::from_bytes(&[0x99; 32]);
    forged["signingPublicKey"] = json!(URL_SAFE_NO_PAD.encode(attacker.verifying_key().as_bytes()));
    forged["signingKeyFingerprint"] = json!(URL_SAFE_NO_PAD.encode(compute_key_fingerprint(
        attacker.verifying_key().as_bytes(),
        palladin_crypto::RecipientKeyKind::OrganizationApproverEd25519,
    )));
    let mut unsigned = forged.as_object().unwrap().clone();
    unsigned.remove("signature");
    unsigned.remove("continuitySignature");
    let mut input = b"PLDNSUB1SIG:APPROVER-MANIFEST:\x00\x02".to_vec();
    input.extend(serde_jcs::to_vec(&Value::Object(unsigned.clone())).unwrap());
    forged["signature"] = json!(URL_SAFE_NO_PAD.encode(attacker.sign(&input).to_bytes()));
    let mut continuity = b"PLDNSUB1SIG:APPROVER-CONTINUITY:\x00\x02".to_vec();
    continuity.extend(serde_jcs::to_vec(&Value::Object(unsigned)).unwrap());
    forged["continuitySignature"] =
        json!(URL_SAFE_NO_PAD.encode(attacker.sign(&continuity).to_bytes()));

    let cases: Vec<TrustCase> = vec![
        (
            vec![respond(404, json!({ "code": "no-approvers" }).to_string())],
            None,
            None,
            SubmissionNotSaved::NoApprovers,
        ),
        (
            vec![respond(200, manifests_response(&[forged]))],
            Some(anchor_from_manifest(&manifest(0))),
            None,
            SubmissionNotSaved::ApproverKeyUntrusted,
        ),
        (
            vec![respond(200, manifests_response(&[manifest(0)]))],
            Some(anchor_from_manifest(&manifest(1))),
            None,
            SubmissionNotSaved::ApproverKeyUntrusted,
        ),
        (
            vec![respond(200, manifests_response(&[manifest(0)]))],
            None,
            Some("1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"),
            SubmissionNotSaved::ApproverKeyUntrusted,
        ),
        (
            vec![respond(200, manifests_response(&[]))],
            None,
            None,
            SubmissionNotSaved::ApproverKeyUnavailable,
        ),
        (
            vec![
                respond(503, String::new()),
                respond(503, String::new()),
                respond(503, String::new()),
            ],
            None,
            None,
            SubmissionNotSaved::ServiceUnavailable,
        ),
    ];
    for (handlers, anchor, vault_organization, expected) in cases {
        let count = handlers.len();
        let (host, requests) = server(handlers).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::SubmitEntry,
            &persistence,
            anchor,
            vault_organization,
        );
        let result = session
            .submit_entry(
                new_credential_request(),
                SubmissionSecret::Generate(policy()),
            )
            .await
            .unwrap();
        assert_eq!(result.outcome, Err(expected));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), count, "{expected:?}");
        assert!(requests.iter().all(|request| !request.starts_with("POST")));
        assert!(
            persistence.anchors.lock().unwrap().is_empty(),
            "{expected:?}"
        );
    }
}

#[tokio::test]
async fn rotated_approver_key_is_verified_by_continuity_and_the_submission_is_rebuilt_once() {
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[])),
        respond(409, json!({ "code": "approver-key-rotated" }).to_string()),
        respond(200, manifests_response(&[manifest(1)])),
        accept_post(),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let v1 = anchor_from_manifest(&manifest(0));
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        Some(v1.clone()),
        None,
    );
    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Provided(SecretString::from("human-Provided-Secret-1".to_owned())),
        )
        .await
        .unwrap();
    assert!(result.outcome.is_ok());
    let requests = requests.lock().unwrap();
    assert!(requests[0].starts_with("GET /api/agent/approver-manifests?afterRevision=1 "));
    assert!(requests[2].starts_with("GET /api/agent/approver-manifests?afterRevision=1 "));
    let first = request_body(&requests[1]);
    let second = request_body(&requests[3]);
    assert_eq!(first["approverKeyVersion"], 1);
    assert_eq!(second["approverKeyVersion"], 2);
    assert_eq!(first["submissionId"], second["submissionId"]);
    assert_eq!(
        approver_password(&second, "approverV2X25519Seed", 2),
        "human-Provided-Secret-1"
    );
    assert_eq!(
        *persistence.anchors.lock().unwrap(),
        vec![(Some(v1), anchor_from_manifest(&manifest(1)))]
    );
}

#[tokio::test]
async fn backend_rejections_map_to_value_free_not_saved_codes() {
    for (status, code, expected) in [
        (
            403,
            "update-not-granted",
            SubmissionNotSaved::UpdateNotGranted,
        ),
        (
            409,
            "submission-conflict",
            SubmissionNotSaved::SubmissionConflict,
        ),
        (404, "no-approvers", SubmissionNotSaved::NoApprovers),
        (400, "invalid-input", SubmissionNotSaved::InvalidInput),
        (
            400,
            "unsupported-entry-type",
            SubmissionNotSaved::UnsupportedEntryType,
        ),
        (
            409,
            "agent-key-mismatch",
            SubmissionNotSaved::ServiceUnavailable,
        ),
        (
            409,
            "approver-key-unavailable",
            SubmissionNotSaved::ServiceUnavailable,
        ),
        (
            403,
            "agent-not-active",
            SubmissionNotSaved::ServiceUnavailable,
        ),
    ] {
        let (host, _) = server(vec![
            respond(200, manifests_response(&[manifest(0)])),
            respond(status, json!({ "code": code }).to_string()),
        ])
        .await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::SubmitEntry,
            &persistence,
            None,
            None,
        );
        let result = session
            .submit_entry(
                new_credential_request(),
                SubmissionSecret::Generate(policy()),
            )
            .await
            .unwrap();
        assert_eq!(result.outcome, Err(expected));
    }
}

#[tokio::test]
async fn ambiguous_post_is_reconciled_by_id_and_never_resent() {
    let reconciled = Arc::new(Mutex::new(String::new()));
    let seen = Arc::clone(&reconciled);
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        Box::new(move |request| {
            *seen.lock().unwrap() = request_body(request)["submissionId"]
                .as_str()
                .unwrap()
                .to_owned();
            (500, String::new())
        }),
        Box::new(move |_| {
            let id = reconciled.lock().unwrap().clone();
            (
                200,
                json!({ "items": [{
                    "submissionId": id, "submissionKind": 1, "entryType": 1,
                    "target": { "kind": "new" }, "state": "pending", "agentUseSuspended": false,
                    "submissionRevision": "1", "approverKeyVersion": 1,
                    "currentApproverKeyVersion": 1, "createdAt": "2026-10-29T08:00:00Z"
                }]})
                .to_string(),
            )
        }),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Generate(policy()),
        )
        .await
        .unwrap();
    assert_eq!(result.outcome.unwrap().state, "pending");
    let posts = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.starts_with("POST"))
        .count();
    assert_eq!(posts, 1);

    let (host, _) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        respond(502, String::new()),
        respond(200, json!({ "items": [] }).to_string()),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Generate(policy()),
        )
        .await
        .unwrap();
    assert_eq!(result.outcome, Err(SubmissionNotSaved::ServiceUnavailable));
    assert!(
        result.submission_id.is_some(),
        "the operator can check the unconfirmed ID"
    );
}

#[tokio::test]
async fn submit_requires_its_exact_operation_authorization() {
    let (host, requests) = server(Vec::new()).await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::GetCredential,
        &persistence,
        None,
        None,
    );
    assert!(matches!(
        session
            .submit_entry(
                new_credential_request(),
                SubmissionSecret::Generate(policy())
            )
            .await,
        Err(RuntimeError::OperationAuthorizationMismatch)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

fn summary(id: &str, approver_key_version: u32, current: u32, state: &str) -> Value {
    json!({
        "submissionId": id, "submissionKind": 2, "entryType": 1,
        "target": { "kind": "update", "vaultId": "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e",
                    "entryId": "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f", "expectedEntryRevision": "7" },
        "state": state, "agentUseSuspended": false, "submissionRevision": "1",
        "approverKeyVersion": approver_key_version, "currentApproverKeyVersion": current,
        "createdAt": "2026-10-29T08:00:00Z"
    })
}

#[tokio::test]
async fn status_rewraps_pending_submissions_for_a_continuity_verified_rotated_key() {
    let stored = fixture()["submissions"][0].clone();
    let (host, requests) = server(vec![
        respond(
            200,
            json!({ "items": [
                summary(FIXTURE_SUBMISSION_ID, 1, 2, "pending"),
                summary("1d1d1d1d-1d1d-4d1d-8d1d-1d1d1d1d1d1d", 1, 2, "approved"),
            ]})
            .to_string(),
        ),
        respond(200, manifests_response(&[manifest(1)])),
        respond(200, stored.to_string()),
        Box::new(|request| {
            let body = request_body(request);
            (
                200,
                json!({
                    "submissionId": body["submissionId"],
                    "state": "pending",
                    "submissionRevision": body["submissionRevision"],
                })
                .to_string(),
            )
        }),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmissionStatus,
        &persistence,
        Some(anchor_from_manifest(&manifest(0))),
        None,
    );
    let items = session.submission_status(None).await.expect("status");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0].rewrap,
        RewrapOutcome::Rewrapped {
            submission_revision: 2
        }
    );
    assert_eq!(items[1].rewrap, RewrapOutcome::NotRequired);
    let requests = requests.lock().unwrap();
    assert!(requests[3].starts_with(&format!(
        "PUT /api/agent/submissions/{FIXTURE_SUBMISSION_ID}/wrap HTTP/1.1"
    )));
    let candidate = AgentEntrySubmission::from_value(&request_body(&requests[3])).unwrap();
    verify_rewrap(
        &AgentEntrySubmission::from_value(&stored).unwrap(),
        &candidate,
        2,
    )
    .expect("re-wrap keeps the payload and advances the revision");
    assert_eq!(
        approver_password(&request_body(&requests[3]), "approverV2X25519Seed", 2),
        "synthetic-Fixture-Only-9!q"
    );
}

#[tokio::test]
async fn submission_inject_delivers_only_a_verified_fresh_own_submission() {
    let stored = fixture()["submissions"][0].clone();
    let (host, requests) = server(vec![respond(200, stored.to_string())]).await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::InjectCredential,
        &persistence,
        Some(anchor_from_manifest(&manifest(0))),
        None,
    );
    let delivered = session
        .deliver_submission_for_inject(FIXTURE_SUBMISSION_ID)
        .await
        .expect("delivery");
    assert_eq!(delivered.grant_id, FIXTURE_SUBMISSION_ID);
    assert_eq!(delivered.entry_id, "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f");
    assert_eq!(delivered.entry_revision(), 7);
    assert_eq!(delivered.authenticated_domain(), Some("example.invalid"));
    assert_eq!(
        delivered.authenticated_field("credential.username"),
        Some("synthetic-user@example.invalid")
    );
    let plaintext: Value =
        serde_json::from_slice(delivered.expose_for_authorized_operation()).unwrap();
    assert_eq!(plaintext["password"], "synthetic-Fixture-Only-9!q");
    assert!(!format!("{delivered:?}").contains("synthetic-Fixture"));
    assert!(requests.lock().unwrap()[0].starts_with(&format!(
        "GET /api/agent/submissions/{FIXTURE_SUBMISSION_ID} HTTP/1.1"
    )));
}

#[tokio::test]
async fn submission_inject_rejects_unusable_substituted_or_tampered_submissions() {
    let stored = fixture()["submissions"][0].clone();
    let mut tampered = stored.clone();
    tampered["target"]["entryId"] = json!("1f1f1f1f-1f1f-4f1f-8f1f-1f1f1f1f1f1f");
    let cases: Vec<(String, Handler, &str)> = vec![
        (
            FIXTURE_SUBMISSION_ID.to_owned(),
            respond(403, json!({ "code": "submission-not-usable" }).to_string()),
            "not-usable",
        ),
        (
            "1d1d1d1d-1d1d-4d1d-8d1d-1d1d1d1d1d1d".to_owned(),
            respond(200, stored.to_string()),
            "context-mismatch",
        ),
        (
            FIXTURE_SUBMISSION_ID.to_owned(),
            respond(200, tampered.to_string()),
            "invalid-agent-signature",
        ),
    ];
    for (id, handler, expected) in cases {
        let (host, _) = server(vec![handler]).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::InjectCredential,
            &persistence,
            Some(anchor_from_manifest(&manifest(0))),
            None,
        );
        let error = session
            .deliver_submission_for_inject(&id)
            .await
            .expect_err(expected);
        match (expected, error) {
            ("not-usable", RuntimeError::SubmissionNotUsable) => {}
            (code, RuntimeError::Submission(error)) if error.code() == code => {}
            (expected, error) => panic!("expected {expected}, got {error:?}"),
        }
    }

    for operation in [
        RuntimeOperation::GetCredential,
        RuntimeOperation::ExecWithCredential,
    ] {
        let (host, requests) = server(Vec::new()).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            operation,
            &persistence,
            Some(anchor_from_manifest(&manifest(0))),
            None,
        );
        assert!(matches!(
            session
                .deliver_submission_for_inject(FIXTURE_SUBMISSION_ID)
                .await,
            Err(RuntimeError::OperationAuthorizationMismatch)
        ));
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[test]
fn request_digest_binds_every_non_secret_field_and_the_secret_source() {
    let base = new_credential_request();
    let digest = base.digest(true);
    assert_ne!(digest, base.digest(false));
    for changed in [
        SubmissionRequest {
            label: Some("Other"),
            ..base
        },
        SubmissionRequest {
            url: Some("https://other.invalid"),
            ..base
        },
        SubmissionRequest {
            username: Some("other"),
            ..base
        },
        SubmissionRequest {
            entry_type: Some(SubmissionEntryType::Key),
            ..base
        },
        SubmissionRequest {
            target: SubmissionRequestTarget::New {
                suggested_vault_id: None,
            },
            ..base
        },
    ] {
        assert_ne!(changed.digest(true), digest, "{changed:?}");
    }
}

const VAULT_ID: &str = "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e";
const ENTRY_ID: &str = "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f";

fn submission_target(entry_type: u16, entry_revision: &str) -> String {
    json!({
        "vaultId": VAULT_ID,
        "entryId": ENTRY_ID,
        "entryType": entry_type,
        "entryRevision": entry_revision,
    })
    .to_string()
}

fn update_request<'a>(
    label: Option<&'a str>,
    url: Option<&'a str>,
    username: Option<&'a str>,
) -> SubmissionRequest<'a> {
    SubmissionRequest {
        target: SubmissionRequestTarget::Update {
            vault_id: VAULT_ID,
            entry_id: ENTRY_ID,
        },
        entry_type: None,
        label,
        url,
        username,
    }
}

/// Opens an uploaded body as the approver and returns the exact decrypted `{label?, content}`.
fn approver_payload(body: &Value) -> Value {
    let submission = AgentEntrySubmission::from_value(body).expect("strict transport");
    let signing = agent_signing();
    let approver = box_identity("approverV1X25519Seed");
    let opened = open_agent_submission(
        &submission,
        &SubmissionAuthority {
            organization_id: Uuid::parse_str(ORGANIZATION_ID).unwrap(),
            agent_id: Uuid::parse_str(AGENT_ID).unwrap(),
            agent_signing_public_key: signing.public_key(),
            recipient: SubmissionRecipient::ApproverGroup {
                key_version: 1,
                identity: &approver,
            },
        },
    )
    .expect("approver opens");
    let mut content = serde_json::Map::new();
    match opened.content {
        SubmissionContent::Credential {
            username,
            password,
            url,
            notes,
        } => {
            content.insert("password".into(), json!(password.expose_secret()));
            if let Some(username) = username {
                content.insert("username".into(), json!(username.expose_secret()));
            }
            if let Some(url) = url {
                content.insert("url".into(), json!(url));
            }
            assert!(notes.is_none());
        }
        SubmissionContent::Key { value, url, notes } => {
            content.insert("value".into(), json!(value.expose_secret()));
            if let Some(url) = url {
                content.insert("url".into(), json!(url));
            }
            assert!(notes.is_none());
        }
    }
    json!({ "label": opened.label, "content": content })
}

fn assert_never_requested_credential_delivery(requests: &[String]) {
    for request in requests {
        let line = request.lines().next().unwrap_or_default();
        assert!(
            !line.contains("/credential") && !line.contains("/request-access"),
            "{line}"
        );
    }
}

#[tokio::test]
async fn update_with_generated_secret_uploads_only_the_new_password() {
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        respond(200, submission_target(1, "7")),
        accept_post(),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            update_request(None, None, None),
            SubmissionSecret::Generate(policy()),
        )
        .await
        .unwrap();
    assert_eq!(result.kind, SubmissionKind::Update);
    assert!(result.outcome.is_ok());
    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/agent/approver-manifests "));
    assert!(requests[1].starts_with(&format!(
        "GET /api/agent/vaults/{VAULT_ID}/entries/{ENTRY_ID}/submission-target HTTP/1.1"
    )));
    assert!(requests[2].starts_with("POST /api/agent/submissions "));
    assert_never_requested_credential_delivery(&requests);

    let body = request_body(&requests[2]);
    assert_eq!(body["submissionKind"], 2);
    assert_eq!(body["entryType"], 1);
    assert_eq!(
        body["target"],
        json!({ "kind": "update", "vaultId": VAULT_ID, "entryId": ENTRY_ID, "expectedEntryRevision": "7" })
    );
    let payload = approver_payload(&body);
    let password = payload["content"]["password"].as_str().unwrap().to_owned();
    assert_eq!(password.len(), 40);
    assert_eq!(
        payload,
        json!({ "label": null, "content": { "password": password } }),
        "an update carries exactly the changed password"
    );
    for request in &requests {
        assert!(!request.contains(&password));
    }
}

#[tokio::test]
async fn update_with_prompted_secret_carries_only_the_provided_optional_fields() {
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        respond(200, submission_target(1, "12")),
        accept_post(),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            update_request(
                Some("Renamed Account"),
                Some("https://example.invalid/new-login"),
                Some("renamed@example.invalid"),
            ),
            SubmissionSecret::Provided(SecretString::from("human-Provided-Secret-2".to_owned())),
        )
        .await
        .unwrap();
    assert!(result.outcome.is_ok());
    let requests = requests.lock().unwrap().clone();
    assert_never_requested_credential_delivery(&requests);
    let body = request_body(&requests[2]);
    assert_eq!(body["target"]["expectedEntryRevision"], "12");
    assert_eq!(
        approver_payload(&body),
        json!({
            "label": "Renamed Account",
            "content": {
                "password": "human-Provided-Secret-2",
                "username": "renamed@example.invalid",
                "url": "https://example.invalid/new-login",
            }
        })
    );
}

#[tokio::test]
async fn update_uses_the_target_entry_type_for_a_key() {
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        respond(200, submission_target(0, "3")),
        accept_post(),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    let result = session
        .submit_entry(
            update_request(None, None, None),
            SubmissionSecret::Provided(SecretString::from("new-api-token".to_owned())),
        )
        .await
        .unwrap();
    assert!(result.outcome.is_ok());
    let body = request_body(&requests.lock().unwrap()[2]);
    assert_eq!(body["entryType"], 0);
    assert_eq!(
        approver_payload(&body),
        json!({ "label": null, "content": { "value": "new-api-token" } })
    );
}

#[tokio::test]
async fn update_target_failures_never_upload_or_deliver_a_credential() {
    let cases: Vec<(
        Vec<Handler>,
        SubmissionRequest<'static>,
        Result<(), SubmissionNotSaved>,
    )> = vec![
        (
            vec![respond(
                403,
                json!({ "code": "update-not-granted" }).to_string(),
            )],
            update_request(None, None, None),
            Err(SubmissionNotSaved::UpdateNotGranted),
        ),
        (
            vec![respond(200, submission_target(2, "4"))],
            update_request(None, None, None),
            Err(SubmissionNotSaved::UnsupportedEntryType),
        ),
        (
            vec![respond(200, submission_target(0, "4"))],
            update_request(None, None, Some("not-for-a-key")),
            Err(SubmissionNotSaved::InvalidInput),
        ),
    ];
    for (handlers, request, expected) in cases {
        let mut all = vec![respond(200, manifests_response(&[manifest(0)]))];
        all.extend(handlers);
        let (host, requests) = server(all).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::SubmitEntry,
            &persistence,
            None,
            None,
        );
        let result = session
            .submit_entry(request, SubmissionSecret::Generate(policy()))
            .await
            .unwrap();
        assert_eq!(result.outcome.map(|_| ()), expected);
        let requests = requests.lock().unwrap().clone();
        assert!(requests.iter().all(|request| !request.starts_with("POST")));
        assert_never_requested_credential_delivery(&requests);
    }

    let mut other = serde_json::from_str::<Value>(&submission_target(1, "4")).unwrap();
    other["entryId"] = json!("1f1f1f1f-1f1f-4f1f-8f1f-1f1f1f1f1f1f");
    let (host, requests) = server(vec![
        respond(200, manifests_response(&[manifest(0)])),
        respond(200, other.to_string()),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        None,
        None,
    );
    assert!(matches!(
        session
            .submit_entry(
                update_request(None, None, None),
                SubmissionSecret::Generate(policy())
            )
            .await,
        Err(RuntimeError::Api(ApiError::InvalidResponse))
    ));
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.starts_with("POST")),
        "a target for another Entry is never used"
    );
}

/// The fixture's v2 key re-bootstrapped: same key, no continuity from v1.
fn re_bootstrap_manifest() -> Value {
    let mut manifest = manifest(1);
    let object = manifest.as_object_mut().unwrap();
    for field in [
        "signature",
        "continuitySignature",
        "previousSigningKeyFingerprint",
    ] {
        object.remove(field);
    }
    let mut input = b"PLDNSUB1SIG:APPROVER-MANIFEST:\x00\x02".to_vec();
    input.extend(serde_jcs::to_vec(&manifest).unwrap());
    let signer = SigningKey::from_bytes(&seed("approverV2Ed25519Seed"));
    manifest["signature"] = json!(URL_SAFE_NO_PAD.encode(signer.sign(&input).to_bytes()));
    manifest
}

fn short_fingerprint(manifest: &Value) -> String {
    palladin_core::terminal::shorten_identifier(manifest["signingKeyFingerprint"].as_str().unwrap())
}

#[tokio::test]
async fn re_bootstrapped_approver_key_is_never_accepted_automatically() {
    let (host, requests) = server(vec![respond(
        200,
        manifests_response(&[re_bootstrap_manifest()]),
    )])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmitEntry,
        &persistence,
        Some(anchor_from_manifest(&manifest(0))),
        None,
    );
    let result = session
        .submit_entry(
            new_credential_request(),
            SubmissionSecret::Generate(policy()),
        )
        .await
        .unwrap();
    assert_eq!(
        result.outcome,
        Err(SubmissionNotSaved::ApproverKeyUntrusted)
    );
    assert_eq!(
        result.hints,
        vec![SubmissionHint::ApproverReintroduction {
            signing_key_fingerprint: short_fingerprint(&re_bootstrap_manifest()),
        }]
    );
    assert_eq!(requests.lock().unwrap().len(), 1, "no upload");
    assert!(persistence.anchors.lock().unwrap().is_empty(), "no re-pin");
}

#[tokio::test]
async fn explicit_re_trust_pins_only_the_confirmed_re_bootstrap() {
    let v1 = anchor_from_manifest(&manifest(0));
    let fingerprint = short_fingerprint(&re_bootstrap_manifest());

    let rejected: [(Value, &str); 3] = [
        (re_bootstrap_manifest(), "AAAAAAAA…AAAAAA"),
        (manifest(1), fingerprint.as_str()),
        (manifest(1), &short_fingerprint(&manifest(1))),
    ];
    for (offered, confirmed) in rejected {
        let (host, _) = server(vec![respond(200, manifests_response(&[offered]))]).await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::TrustApprovers,
            &persistence,
            Some(v1.clone()),
            None,
        );
        assert!(matches!(
            session.trust_approvers(confirmed).await,
            Err(RuntimeError::ApproverReintroductionNotPending)
        ));
        assert!(persistence.anchors.lock().unwrap().is_empty());
    }

    let (host, requests) = server(vec![respond(
        200,
        manifests_response(&[re_bootstrap_manifest()]),
    )])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::TrustApprovers,
        &persistence,
        Some(v1.clone()),
        None,
    );
    let key = session
        .trust_approvers(&fingerprint)
        .await
        .expect("re-trust");
    assert_eq!(key.key_version, 2);
    assert_eq!(key.signing_key_fingerprint, fingerprint);
    assert!(
        requests.lock().unwrap()[0]
            .starts_with("GET /api/agent/approver-manifests?afterRevision=1 ")
    );
    assert_eq!(
        *persistence.anchors.lock().unwrap(),
        vec![(Some(v1), anchor_from_manifest(&re_bootstrap_manifest()))]
    );

    let (host, requests) = server(Vec::new()).await;
    let persistence = RecordingPersistence::default();
    for (operation, anchor) in [
        (RuntimeOperation::TrustApprovers, None),
        (
            RuntimeOperation::SubmitEntry,
            Some(anchor_from_manifest(&manifest(0))),
        ),
    ] {
        let session = test_session(&host, operation, &persistence, anchor, None);
        assert!(matches!(
            session.trust_approvers(&fingerprint).await,
            Err(RuntimeError::ApproverReintroductionNotPending
                | RuntimeError::OperationAuthorizationMismatch)
        ));
    }
    assert!(
        requests.lock().unwrap().is_empty(),
        "first introduction is automatic and other operations cannot re-trust"
    );
}

#[tokio::test]
async fn status_after_re_trust_rewraps_pending_submissions_for_the_new_key() {
    let stored = fixture()["submissions"][0].clone();
    let (host, requests) = server(vec![
        respond(
            200,
            json!({ "items": [summary(FIXTURE_SUBMISSION_ID, 1, 2, "pending")] }).to_string(),
        ),
        respond(200, manifests_response(&[])),
        respond(200, stored.to_string()),
        Box::new(|request| {
            let body = request_body(request);
            (
                200,
                json!({
                    "submissionId": body["submissionId"],
                    "state": "pending",
                    "submissionRevision": body["submissionRevision"],
                })
                .to_string(),
            )
        }),
    ])
    .await;
    let persistence = RecordingPersistence::default();
    let session = test_session(
        &host,
        RuntimeOperation::SubmissionStatus,
        &persistence,
        Some(anchor_from_manifest(&re_bootstrap_manifest())),
        None,
    );
    let items = session.submission_status(None).await.expect("status");
    assert_eq!(
        items[0].rewrap,
        RewrapOutcome::Rewrapped {
            submission_revision: 2
        }
    );
    let body = request_body(&requests.lock().unwrap()[3]);
    assert_eq!(
        approver_password(&body, "approverV2X25519Seed", 2),
        "synthetic-Fixture-Only-9!q",
        "the Agent's own DEK wrap re-encrypts nothing and regenerates no secret"
    );
}

#[tokio::test]
async fn update_without_username_carries_an_autofill_hint() {
    for (username, expected) in [
        (None, vec![SubmissionHint::UsernameNeededForAutofill]),
        (Some("agent@example.invalid"), Vec::new()),
    ] {
        let (host, _) = server(vec![
            respond(200, manifests_response(&[manifest(0)])),
            respond(200, submission_target(1, "7")),
            accept_post(),
        ])
        .await;
        let persistence = RecordingPersistence::default();
        let session = test_session(
            &host,
            RuntimeOperation::SubmitEntry,
            &persistence,
            None,
            None,
        );
        let result = session
            .submit_entry(
                update_request(None, None, username),
                SubmissionSecret::Generate(policy()),
            )
            .await
            .unwrap();
        assert!(result.outcome.is_ok());
        assert_eq!(result.hints, expected);
    }
}
