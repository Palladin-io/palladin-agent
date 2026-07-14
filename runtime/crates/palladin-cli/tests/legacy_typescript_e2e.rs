use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex};

use base64::{Engine, engine::general_purpose::STANDARD};
use blake2::{Blake2b, Digest, digest::consts::U24};
use crypto_secretbox::{Kdf, KeyInit, XSalsa20Poly1305, aead::Aead};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use palladin_api::{AgentRegistrationResult, CredentialAccess};
use palladin_cli::output::{
    RenderedOutput, render_connect, render_legacy_cleanup, render_legacy_cutover, render_status,
};
use palladin_cli::{CredentialDelivery, CredentialDeliveryRequest, RuntimeError, RuntimeService};
use palladin_core::host::ApiHost;
use palladin_core::legacy_typescript::{LegacyTypeScriptRepository, LegacyTypeScriptStatus};
use palladin_core::profiles::ProfileRepository;
use palladin_core::secret::OrganizationApiKey;
use palladin_credential::wait::WaitOptions;
use palladin_crypto::{
    CryptoError, EncryptedCredential, X25519Identity, canonical_request, decrypt_credential,
};
use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
use salsa20::Salsa20;
use secrecy::SecretSlice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

const ORGANIZATION_API_KEY: &str = "pl_new_shared_e2e_organization_key";
const CREDENTIAL_CANARY: &str = "credential_plaintext_output_canary_must_stay_scoped";
const ENVIRONMENT_CANARY: &str = "environment_secret_canary_must_never_be_emitted";
const LEGACY_CANARIES: &[&str] = &[
    "pl_legacy_config_canary_must_never_be_read_or_emitted",
    "legacy_x25519_file_canary_must_never_be_read_or_emitted",
    "legacy_ed25519_file_canary_must_never_be_read_or_emitted",
    "pl_build_config_canary_must_never_be_read_or_emitted",
    "build_x25519_file_canary_must_never_be_read_or_emitted",
    "build_ed25519_file_canary_must_never_be_read_or_emitted",
];

#[derive(Clone, Default)]
struct MemoryStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    secrets: BTreeMap<(String, SecretSlot), Vec<u8>>,
    operations: Vec<StoreOperation>,
    fail_set: Option<SecretSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoreOperation {
    Get(String, SecretSlot),
    Set(String, SecretSlot),
    Delete(String, SecretSlot),
}

impl MemoryStore {
    fn secret(&self, owner: &str, slot: SecretSlot) -> Vec<u8> {
        self.state
            .lock()
            .expect("memory store")
            .secrets
            .get(&(owner.to_owned(), slot))
            .cloned()
            .expect("secret fixture")
    }

    fn count_slot(&self, slot: SecretSlot) -> usize {
        self.state
            .lock()
            .expect("memory store")
            .secrets
            .keys()
            .filter(|(_, candidate)| *candidate == slot)
            .count()
    }

    fn len(&self) -> usize {
        self.state.lock().expect("memory store").secrets.len()
    }

    fn operations(&self) -> Vec<StoreOperation> {
        self.state.lock().expect("memory store").operations.clone()
    }

    fn fail_set(&self, slot: SecretSlot) {
        self.state.lock().expect("memory store").fail_set = Some(slot);
    }

    fn clear_failure(&self) {
        self.state.lock().expect("memory store").fail_set = None;
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let mut state = self.state.lock().expect("memory store");
        state
            .operations
            .push(StoreOperation::Get(owner_id.to_owned(), slot));
        Ok(state
            .secrets
            .get(&(owner_id.to_owned(), slot))
            .cloned()
            .map(Into::into))
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("memory store");
        state
            .operations
            .push(StoreOperation::Set(owner_id.to_owned(), slot));
        if state.fail_set == Some(slot) {
            return Err(StoreError::Unavailable);
        }
        state
            .secrets
            .insert((owner_id.to_owned(), slot), secret.to_vec());
        Ok(())
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("memory store");
        state
            .operations
            .push(StoreOperation::Delete(owner_id.to_owned(), slot));
        state.secrets.remove(&(owner_id.to_owned(), slot));
        Ok(())
    }
}

#[tokio::test]
async fn legacy_fixture_completes_fresh_signed_lifecycle_and_purges_without_leaks() {
    let fixture = LegacyFixture::copy();
    let root = fixture.root();
    let legacy = LegacyTypeScriptRepository::new(&root).expect("legacy repository");
    assert_eq!(
        legacy.status().expect("legacy status"),
        LegacyTypeScriptStatus::Detected {
            source_directory: ".palladin".to_owned(),
            profiles: 2,
            file_fallback: true,
        }
    );

    let store = MemoryStore::default();
    let runtime = service(&root, store.clone());
    let cutover = runtime
        .cutover_legacy_typescript(true)
        .expect("legacy cutover");
    assert_eq!(cutover.created, 2);
    assert_eq!(cutover.profile_names, ["default", "build"]);
    assert!(matches!(
        LegacyTypeScriptRepository::new(&root)
            .expect("legacy repository")
            .status()
            .expect("cutover status"),
        LegacyTypeScriptStatus::CutoverPending(_)
    ));

    let registry = runtime.registry().expect("fresh registry");
    let default = registry
        .agents
        .iter()
        .find(|profile| profile.name == "default")
        .expect("default profile")
        .clone();
    let build = registry
        .agents
        .iter()
        .find(|profile| profile.name == "build")
        .expect("build profile")
        .clone();
    assert_ne!(default.identity_id, build.identity_id);
    assert!(
        store.secret(&default.identity_id, SecretSlot::X25519PrivateKey)
            != store.secret(&build.identity_id, SecretSlot::X25519PrivateKey)
    );
    assert!(
        store.secret(&default.identity_id, SecretSlot::Ed25519SecretKey)
            != store.secret(&build.identity_id, SecretSlot::Ed25519SecretKey)
    );
    assert_no_legacy_secret_reads(&store.operations());

    let api = ScriptedApi::start().await;
    for _ in 0..3 {
        api.enqueue(MockResponse::DropConnection);
    }
    let lost = runtime
        .connect(
            Some("default"),
            OrganizationApiKey::new(ORGANIZATION_API_KEY.to_owned()),
            ApiHost::parse(api.host()).expect("API host"),
            None,
            None,
            "e2e-host",
        )
        .await
        .expect("transport loss is a clean registration result");
    assert!(matches!(
        lost.registration,
        AgentRegistrationResult::Unreachable { .. }
    ));
    assert!(lost.config_saved);
    let default_x25519_before_restart =
        store.secret(&default.identity_id, SecretSlot::X25519PrivateKey);
    drop(runtime);

    let restarted = service(&root, store.clone());
    api.enqueue(MockResponse::pending("agent-default-fresh"));
    let default_connect = restarted
        .connect(
            Some("default"),
            OrganizationApiKey::new(ORGANIZATION_API_KEY.to_owned()),
            ApiHost::parse(api.host()).expect("API host"),
            None,
            None,
            "e2e-host",
        )
        .await
        .expect("default reconnect after response loss");
    api.enqueue(MockResponse::pending("agent-build-fresh"));
    let build_connect = restarted
        .connect(
            Some("build"),
            OrganizationApiKey::new(ORGANIZATION_API_KEY.to_owned()),
            ApiHost::parse(api.host()).expect("API host"),
            None,
            None,
            "e2e-host",
        )
        .await
        .expect("build connect");
    assert!(matches!(
        default_connect.registration,
        AgentRegistrationResult::Pending { ref agent_id } if agent_id == "agent-default-fresh"
    ));
    assert!(matches!(
        build_connect.registration,
        AgentRegistrationResult::Pending { ref agent_id } if agent_id == "agent-build-fresh"
    ));
    assert!(
        default_x25519_before_restart
            == store.secret(&default.identity_id, SecretSlot::X25519PrivateKey)
    );

    let default_config = restarted
        .repository()
        .load_config(&default.identity_id)
        .expect("default config");
    let build_config = restarted
        .repository()
        .load_config(&build.identity_id)
        .expect("build config");
    assert_eq!(
        default_config.organization_credential_id,
        build_config.organization_credential_id
    );
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
    assert_ne!(
        default_config.encryption_public_key,
        build_config.encryption_public_key
    );
    assert_ne!(
        default_config.signing_public_key,
        build_config.signing_public_key
    );
    drop(restarted);

    let restarted = service(&root, store.clone());
    api.enqueue(MockResponse::active(
        "agent-default-fresh",
        "Default fresh Agent",
    ));
    let default_status = restarted
        .status(Some("default"), "e2e-host")
        .await
        .expect("default active status");
    api.enqueue(MockResponse::active(
        "agent-build-fresh",
        "Build fresh Agent",
    ));
    let build_status = restarted
        .status(Some("build"), "e2e-host")
        .await
        .expect("build active status");
    assert!(matches!(
        default_status.registration,
        AgentRegistrationResult::Active { ref agent_id, .. } if agent_id == "agent-default-fresh"
    ));
    assert!(matches!(
        build_status.registration,
        AgentRegistrationResult::Active { ref agent_id, .. } if agent_id == "agent-build-fresh"
    ));
    assert_ne!(default_status.config.agent_id, build_status.config.agent_id);

    api.enqueue(MockResponse::json(
        200,
        r#"{"items":[{"entryId":"entry-e2e","vaultId":"vault-e2e","label":"Synthetic entry","urlDomain":"example.test","description":null,"agentFields":[]}],"nextCursor":null}"#,
    ));
    let session = restarted
        .open_session(Some("default"), "e2e-host")
        .expect("default session");
    let discovery = session
        .search_entries("synthetic", None, Some(10))
        .await
        .expect("entry discovery");
    assert_eq!(discovery.items.len(), 1);
    assert_eq!(discovery.items[0].entry_id, "entry-e2e");

    api.enqueue(MockResponse::json(
        202,
        r#"{"access":"pending","grantId":"grant-e2e","created":true,"pollIntervalMs":5000,"maxWaitMs":30000}"#,
    ));
    let pending = session
        .deliver_for_get(delivery_request(0), &CancellationToken::new(), |_| {})
        .await
        .expect("pending grant");
    assert!(matches!(
        pending,
        CredentialDelivery::NotGranted(CredentialAccess::Pending { ref grant_id, .. })
            if grant_id == "grant-e2e"
    ));

    let envelope = encrypt_for_recipient(
        default_status
            .config
            .encryption_public_key
            .as_deref()
            .expect("default encryption key"),
        CREDENTIAL_CANARY.as_bytes(),
    );
    api.enqueue(MockResponse::json(
        200,
        &serde_json::json!({
            "access": "granted",
            "entryId": "entry-e2e",
            "label": "Synthetic entry",
            "urlDomain": "example.test",
            "reEncryptedBlob": envelope.re_encrypted_blob,
            "nonce": envelope.nonce,
            "agentWrappedDek": envelope.agent_wrapped_dek,
        })
        .to_string(),
    ));
    let granted = session
        .deliver_for_get(delivery_request(0), &CancellationToken::new(), |_| {})
        .await
        .expect("granted delivery");
    let granted_debug = format!("{granted:?}");
    let CredentialDelivery::Granted(delivered) = granted else {
        panic!("expected granted credential")
    };
    assert!(delivered.expose_for_authorized_operation() == CREDENTIAL_CANARY.as_bytes());
    assert!(!granted_debug.contains(CREDENTIAL_CANARY));

    let build_identity = X25519Identity::from_private_bytes(
        store.secret(&build.identity_id, SecretSlot::X25519PrivateKey),
    )
    .expect("build X25519 identity");
    assert_eq!(
        decrypt_credential(&envelope, &build_identity)
            .expect_err("one Agent must not decrypt another Agent's envelope"),
        CryptoError::AuthenticationFailed
    );

    let requests = api.requests();
    assert_signed_lifecycle_requests(&requests, &default_status.config, &build_status.config);
    assert_canaries_absent(&requests.join("\n"), LEGACY_CANARIES);

    let deleted_profiles = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&deleted_profiles);
    let cleanup = restarted
        .cleanup_legacy_typescript(true, &cutover.cutover_id, move |profile| {
            captured
                .lock()
                .expect("deleted profiles")
                .push(profile.to_owned());
            Ok(())
        })
        .expect("legacy cleanup");
    assert_eq!(
        *deleted_profiles.lock().expect("deleted profiles"),
        ["Default", "build"]
    );
    assert_eq!(
        LegacyTypeScriptRepository::new(&root)
            .expect("legacy repository")
            .status()
            .expect("clear status"),
        LegacyTypeScriptStatus::Clear
    );

    let rendered = [
        render_legacy_cutover(&cutover),
        render_connect(&lost.registration, lost.config_saved, "Convenience"),
        render_connect(
            &default_connect.registration,
            default_connect.config_saved,
            "Convenience",
        ),
        render_status(
            &default_status.profile.name,
            &default_status.config.host,
            &default_status.registration,
            "Convenience",
        ),
        render_legacy_cleanup(&cleanup),
    ];
    assert_rendered_output_is_secretless(&rendered);
    assert_canaries_absent(&read_public_files(&root), LEGACY_CANARIES);

    drop(session);
    restarted.purge().expect("final native purge");
    assert!(!root.exists());
    assert_eq!(store.len(), 0);
}

#[tokio::test]
async fn concurrent_cutover_and_cleanup_are_serialized_and_idempotent() {
    let fixture = LegacyFixture::copy();
    let root = fixture.root();
    let store = MemoryStore::default();
    let barrier = Arc::new(Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        let first_root = root.clone();
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = scope.spawn(move || {
            first_barrier.wait();
            service(&first_root, first_store).cutover_legacy_typescript(true)
        });
        let second_root = root.clone();
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = scope.spawn(move || {
            second_barrier.wait();
            service(&second_root, second_store).cutover_legacy_typescript(true)
        });
        (
            first.join().expect("first cutover thread"),
            second.join().expect("second cutover thread"),
        )
    });
    let first = outcomes.0.expect("first concurrent cutover");
    let second = outcomes.1.expect("second concurrent cutover");
    assert_eq!(first.cutover_id, second.cutover_id);
    assert_eq!(first.created + second.created, 2);
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 2);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 2);

    let runtime = service(&root, store.clone());
    let api = ScriptedApi::start().await;
    api.enqueue(MockResponse::pending("agent-default-concurrent"));
    api.enqueue(MockResponse::pending("agent-build-concurrent"));
    for profile in ["default", "build"] {
        runtime
            .connect(
                Some(profile),
                OrganizationApiKey::new(ORGANIZATION_API_KEY.to_owned()),
                ApiHost::parse(api.host()).expect("API host"),
                None,
                None,
                "e2e-host",
            )
            .await
            .expect("connect before concurrent cleanup");
    }
    drop(runtime);

    let cleanup_calls = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(Barrier::new(2));
    let cutover_id = first.cutover_id.clone();
    let cleanup_results = std::thread::scope(|scope| {
        let first_root = root.clone();
        let first_store = store.clone();
        let first_barrier = Arc::clone(&barrier);
        let first_calls = Arc::clone(&cleanup_calls);
        let first_id = cutover_id.clone();
        let first = scope.spawn(move || {
            first_barrier.wait();
            service(&first_root, first_store).cleanup_legacy_typescript(
                true,
                &first_id,
                move |profile| {
                    first_calls
                        .lock()
                        .expect("cleanup calls")
                        .push(profile.to_owned());
                    Ok(())
                },
            )
        });
        let second_root = root.clone();
        let second_store = store.clone();
        let second_barrier = Arc::clone(&barrier);
        let second_calls = Arc::clone(&cleanup_calls);
        let second_id = cutover_id.clone();
        let second = scope.spawn(move || {
            second_barrier.wait();
            service(&second_root, second_store).cleanup_legacy_typescript(
                true,
                &second_id,
                move |profile| {
                    second_calls
                        .lock()
                        .expect("cleanup calls")
                        .push(profile.to_owned());
                    Ok(())
                },
            )
        });
        (
            first.join().expect("first cleanup thread"),
            second.join().expect("second cleanup thread"),
        )
    });
    let successes = [&cleanup_results.0, &cleanup_results.1]
        .into_iter()
        .filter(|result| result.is_ok())
        .count();
    let already_completed = [&cleanup_results.0, &cleanup_results.1]
        .into_iter()
        .filter(|result| matches!(result, Err(RuntimeError::LegacyCutoverNotPending)))
        .count();
    assert_eq!(successes, 1);
    assert_eq!(already_completed, 1);
    assert_eq!(
        *cleanup_calls.lock().expect("cleanup calls"),
        ["Default", "build"]
    );
    assert_eq!(
        LegacyTypeScriptRepository::new(&root)
            .expect("legacy repository")
            .status()
            .expect("legacy status"),
        LegacyTypeScriptStatus::Clear
    );
}

#[tokio::test]
async fn injected_store_and_cleanup_failures_resume_across_process_boundaries() {
    let fixture = LegacyFixture::copy();
    let root = fixture.root();
    let store = MemoryStore::default();
    store.fail_set(SecretSlot::Ed25519SecretKey);
    assert!(
        service(&root, store.clone())
            .cutover_legacy_typescript(true)
            .is_err()
    );
    assert!(
        fixture
            .home
            .path()
            .join(".palladin-typescript-legacy")
            .is_dir()
    );
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);

    store.clear_failure();
    let restarted = service(&root, store.clone());
    let cutover = restarted
        .cutover_legacy_typescript(true)
        .expect("restart cutover");
    assert_eq!(cutover.created, 2);
    let api = ScriptedApi::start().await;
    api.enqueue(MockResponse::pending("agent-default-resumed"));
    api.enqueue(MockResponse::pending("agent-build-resumed"));
    for profile in ["default", "build"] {
        restarted
            .connect(
                Some(profile),
                OrganizationApiKey::new(ORGANIZATION_API_KEY.to_owned()),
                ApiHost::parse(api.host()).expect("API host"),
                None,
                None,
                "e2e-host",
            )
            .await
            .expect("connect resumed profile");
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let interrupted_calls = Arc::clone(&calls);
    assert!(
        restarted
            .cleanup_legacy_typescript(true, &cutover.cutover_id, move |profile| {
                interrupted_calls
                    .lock()
                    .expect("cleanup calls")
                    .push(profile.to_owned());
                if profile == "build" {
                    Err(StoreError::Unavailable)
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert!(
        fixture
            .home
            .path()
            .join(".palladin-typescript-legacy")
            .is_dir()
    );
    drop(restarted);

    let final_calls = Arc::clone(&calls);
    service(&root, store)
        .cleanup_legacy_typescript(true, &cutover.cutover_id, move |profile| {
            final_calls
                .lock()
                .expect("cleanup calls")
                .push(profile.to_owned());
            Ok(())
        })
        .expect("restart cleanup");
    assert_eq!(
        *calls.lock().expect("cleanup calls"),
        ["Default", "build", "Default", "build"]
    );
    assert!(
        !fixture
            .home
            .path()
            .join(".palladin-typescript-legacy")
            .exists()
    );
}

#[test]
fn diagnostic_environment_value_never_reaches_cli_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_palladin"))
        .env_clear()
        .env("PALLADIN_PRIVATE_KEY", ENVIRONMENT_CANARY)
        .arg("doctor")
        .output()
        .expect("run diagnostic command");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(ENVIRONMENT_CANARY));
}

fn delivery_request(wait_ms: u64) -> CredentialDeliveryRequest<'static> {
    CredentialDeliveryRequest {
        vault_id: "vault-e2e",
        entry_id: "entry-e2e",
        reason: Some("E2E migration validation"),
        wait: WaitOptions {
            wait_ms: Some(wait_ms),
            ..WaitOptions::default()
        },
    }
}

fn assert_signed_lifecycle_requests(
    requests: &[String],
    default: &palladin_core::public_store::PublicProfileConfig,
    build: &palladin_core::public_store::PublicProfileConfig,
) {
    let signed = requests
        .iter()
        .filter(|request| request_header(request, "x-agent-signature").is_some())
        .collect::<Vec<_>>();
    assert_eq!(signed.len(), 5);
    let mut default_requests = 0;
    let mut build_requests = 0;
    let mut credential_requests = 0;
    let mut search_requests = 0;
    let mut first_signature_by_agent = BTreeMap::new();
    for request in signed {
        let agent_id = request_header(request, "x-agent-id").expect("signed Agent ID");
        first_signature_by_agent
            .entry(agent_id.to_owned())
            .or_insert_with(|| {
                request_header(request, "x-agent-signature")
                    .expect("Agent signature")
                    .to_owned()
            });
        let config = if agent_id == "agent-default-fresh" {
            default_requests += 1;
            default
        } else if agent_id == "agent-build-fresh" {
            build_requests += 1;
            build
        } else {
            panic!("unexpected signed Agent ID")
        };
        let expected_encryption_key = config
            .encryption_public_key
            .as_deref()
            .expect("encryption public key");
        assert_eq!(
            request_header(request, "x-agent-key").expect("encryption header"),
            expected_encryption_key
        );
        verify_request_signature(
            request,
            config
                .signing_public_key
                .as_deref()
                .expect("signing public key"),
        );
        let (_, path, _) = request_parts(request);
        if path.starts_with("/api/agent/entries?") {
            search_requests += 1;
        }
        if path.contains("/credential") {
            credential_requests += 1;
        }
    }
    assert_eq!(default_requests, 4);
    assert_eq!(build_requests, 1);
    assert_eq!(search_requests, 1);
    assert_eq!(credential_requests, 2);
    assert_ne!(
        first_signature_by_agent
            .get("agent-default-fresh")
            .expect("default signature"),
        first_signature_by_agent
            .get("agent-build-fresh")
            .expect("build signature")
    );
}

fn verify_request_signature(request: &str, signing_public_key: &str) {
    let (method, path, body) = request_parts(request);
    let timestamp = request_header(request, "x-agent-timestamp")
        .expect("signature timestamp")
        .parse::<u64>()
        .expect("numeric signature timestamp");
    let nonce = request_header(request, "x-agent-nonce").expect("signature nonce");
    let signature = STANDARD
        .decode(request_header(request, "x-agent-signature").expect("request signature"))
        .expect("signature base64");
    let public_key: [u8; 32] = STANDARD
        .decode(signing_public_key)
        .expect("public key base64")
        .try_into()
        .expect("Ed25519 public key length");
    let canonical = canonical_request(method, path, timestamp, nonce, body.as_bytes())
        .expect("canonical request");
    VerifyingKey::from_bytes(&public_key)
        .expect("Ed25519 public key")
        .verify(
            canonical.as_bytes(),
            &Signature::from_slice(&signature).expect("Ed25519 signature"),
        )
        .expect("valid Agent signature");
}

fn request_parts(request: &str) -> (&str, &str, &str) {
    let (head, body) = request.split_once("\r\n\r\n").expect("HTTP request");
    let request_line = head.lines().next().expect("request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().expect("request method");
    let path = parts.next().expect("request path");
    (method, path, body)
}

fn request_header<'a>(request: &'a str, expected: &str) -> Option<&'a str> {
    let (head, _) = request.split_once("\r\n\r\n")?;
    head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected).then(|| value.trim())
    })
}

fn encrypt_for_recipient(recipient_public_key: &str, plaintext: &[u8]) -> EncryptedCredential {
    let recipient_bytes: [u8; 32] = STANDARD
        .decode(recipient_public_key)
        .expect("recipient public key base64")
        .try_into()
        .expect("X25519 public key length");
    let recipient = PublicKey::from(recipient_bytes);
    let ephemeral = StaticSecret::from([0x42; 32]);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&recipient);
    let precomputed = <Salsa20 as Kdf>::kdf(shared.as_bytes().into(), &Default::default());
    let seal_nonce = seal_nonce(&ephemeral_public, &recipient_bytes);
    let dek = [0x24; 32];
    let sealed_dek = XSalsa20Poly1305::new(&precomputed)
        .encrypt((&seal_nonce).into(), dek.as_slice())
        .expect("seal DEK");
    let mut wrapped_dek = ephemeral_public.to_vec();
    wrapped_dek.extend_from_slice(&sealed_dek);

    let nonce = [0x11; 24];
    let encrypted = XSalsa20Poly1305::new((&dek).into())
        .encrypt((&nonce).into(), plaintext)
        .expect("encrypt credential");
    EncryptedCredential {
        re_encrypted_blob: STANDARD.encode(encrypted),
        nonce: STANDARD.encode(nonce),
        agent_wrapped_dek: STANDARD.encode(wrapped_dek),
    }
}

fn seal_nonce(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32]) -> [u8; 24] {
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.finalize().into()
}

fn assert_rendered_output_is_secretless(outputs: &[RenderedOutput]) {
    let combined = outputs
        .iter()
        .map(|output| format!("{}{}", output.stdout, output.stderr))
        .collect::<String>();
    assert_canaries_absent(&combined, LEGACY_CANARIES);
    for canary in [ORGANIZATION_API_KEY, CREDENTIAL_CANARY, ENVIRONMENT_CANARY] {
        assert!(!combined.contains(canary));
    }
}

fn assert_canaries_absent(output: &str, canaries: &[&str]) {
    for canary in canaries {
        assert!(!output.contains(canary));
    }
}

fn assert_no_legacy_secret_reads(operations: &[StoreOperation]) {
    assert!(operations.iter().all(|operation| !matches!(
        operation,
        StoreOperation::Get(
            _,
            SecretSlot::LegacyX25519PrivateKeyV2
                | SecretSlot::LegacyEd25519SecretKeyV2
                | SecretSlot::LegacyOrganizationApiKeyV2
        )
    )));
}

fn service(path: &Path, store: MemoryStore) -> RuntimeService<MemoryStore> {
    RuntimeService::new(
        ProfileRepository::new(path.to_path_buf()).expect("profile repository"),
        store,
    )
}

struct LegacyFixture {
    home: tempfile::TempDir,
}

impl LegacyFixture {
    fn copy() -> Self {
        let home = tempfile::tempdir().expect("fixture home");
        make_private_directory(home.path());
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/legacy-typescript/v1/multi-profile/.palladin");
        copy_tree(&source, &home.path().join(".palladin"));
        Self { home }
    }

    fn root(&self) -> PathBuf {
        self.home.path().join(".palladin")
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    make_private_directory(destination);
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy fixture file");
            make_private_file(&target);
        }
    }
}

fn make_private_directory(path: &Path) {
    fs::create_dir_all(path).expect("create private directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private directory permissions");
    }
}

fn make_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("private file permissions");
    }
}

fn read_public_files(root: &Path) -> String {
    fn walk(path: &Path, output: &mut String) {
        for entry in fs::read_dir(path).expect("read public directory") {
            let entry = entry.expect("public entry");
            if entry.path().is_dir() {
                walk(&entry.path(), output);
            } else if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                output.push_str(&fs::read_to_string(entry.path()).expect("public JSON"));
            }
        }
    }
    let mut output = String::new();
    walk(root, &mut output);
    output
}

enum MockResponse {
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    DropConnection,
}

impl MockResponse {
    fn pending(agent_id: &str) -> Self {
        Self::Http {
            status: 401,
            headers: vec![("X-Agent-Id".to_owned(), agent_id.to_owned())],
            body: String::new(),
        }
    }

    fn active(agent_id: &str, name: &str) -> Self {
        Self::json(
            200,
            &serde_json::json!({
                "agentId": agent_id,
                "name": name,
                "status": "active",
            })
            .to_string(),
        )
    }

    fn json(status: u16, body: &str) -> Self {
        Self::Http {
            status,
            headers: Vec::new(),
            body: body.to_owned(),
        }
    }
}

struct ScriptedApi {
    host: String,
    responses: mpsc::UnboundedSender<MockResponse>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ScriptedApi {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind API");
        let address = listener.local_addr().expect("API address");
        let (responses, mut receiver) = mpsc::unbounded_channel();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Some(response) = receiver.recv().await {
                let (mut stream, _) = listener.accept().await.expect("accept API request");
                let request = read_http_request(&mut stream).await;
                captured.lock().expect("API requests").push(request);
                let MockResponse::Http {
                    status,
                    headers,
                    body,
                } = response
                else {
                    continue;
                };
                let reason = match status {
                    200 => "OK",
                    202 => "Accepted",
                    401 => "Unauthorized",
                    _ => "Error",
                };
                let mut wire = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    wire.push_str(&format!("{name}: {value}\r\n"));
                }
                wire.push_str("\r\n");
                wire.push_str(&body);
                stream
                    .write_all(wire.as_bytes())
                    .await
                    .expect("write API response");
            }
        });
        Self {
            host: format!("http://{address}"),
            responses,
            requests,
        }
    }

    fn host(&self) -> &str {
        &self.host
    }

    fn enqueue(&self, response: MockResponse) {
        self.responses.send(response).expect("queue API response");
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("API requests").clone()
    }
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.expect("read API request");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if bytes.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8(bytes).expect("UTF-8 API request")
}
