use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use palladin_cli::RuntimeService;
use palladin_core::host::ApiHost;
use palladin_core::profiles::ProfileRepository;
use palladin_core::secret::OrganizationApiKey;
use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
use secrecy::SecretSlice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Clone, Default)]
struct MemoryStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    secrets: BTreeMap<(String, SecretSlot), Vec<u8>>,
    fail_set: Option<SecretSlot>,
    fail_delete: Option<(String, SecretSlot)>,
    fail_delete_slot: Option<SecretSlot>,
}

impl MemoryStore {
    fn contains(&self, owner: &str, slot: SecretSlot) -> bool {
        self.state
            .lock()
            .expect("store")
            .secrets
            .contains_key(&(owner.to_owned(), slot))
    }

    fn count_slot(&self, slot: SecretSlot) -> usize {
        self.state
            .lock()
            .expect("store")
            .secrets
            .keys()
            .filter(|(_, candidate)| *candidate == slot)
            .count()
    }

    fn fail_delete(&self, owner: &str, slot: SecretSlot) {
        self.state.lock().expect("store").fail_delete = Some((owner.to_owned(), slot));
    }

    fn fail_set(&self, slot: SecretSlot) {
        self.state.lock().expect("store").fail_set = Some(slot);
    }

    fn fail_delete_slot(&self, slot: SecretSlot) {
        self.state.lock().expect("store").fail_delete_slot = Some(slot);
    }

    fn clear_failure(&self) {
        let mut state = self.state.lock().expect("store");
        state.fail_set = None;
        state.fail_delete = None;
        state.fail_delete_slot = None;
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        Ok(self
            .state
            .lock()
            .expect("store")
            .secrets
            .get(&(owner_id.to_owned(), slot))
            .cloned()
            .map(Into::into))
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("store");
        if state.fail_set == Some(slot) {
            return Err(StoreError::Unavailable);
        }
        state
            .secrets
            .insert((owner_id.to_owned(), slot), secret.to_vec());
        Ok(())
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("store");
        if state.fail_delete.as_ref() == Some(&(owner_id.to_owned(), slot))
            || state.fail_delete_slot == Some(slot)
        {
            return Err(StoreError::Unavailable);
        }
        state.secrets.remove(&(owner_id.to_owned(), slot));
        Ok(())
    }
}

#[tokio::test]
async fn multiple_agents_share_one_organization_credential_reference_safely() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let first = service.create_profile("first", None).expect("first");
    let second = service.create_profile("second", None).expect("second");
    let (host, _) = response_server(vec![
        Response::pending("agent-first"),
        Response::pending("agent-second"),
    ])
    .await;

    service
        .connect(
            Some("first"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("connect first");
    service
        .connect(
            Some("second"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("connect second");

    let first_config = service
        .repository()
        .load_config(&first.identity_id)
        .expect("first config");
    let second_config = service
        .repository()
        .load_config(&second.identity_id)
        .expect("second config");
    assert_eq!(
        first_config.organization_credential_id,
        second_config.organization_credential_id
    );
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
    assert!(!read_public_files(root.path()).contains("pl_shared_organization_fixture"));
    #[cfg(unix)]
    for directory in [
        root.path().to_path_buf(),
        root.path().join("identities"),
        root.path().join("identities").join(&first.identity_id),
    ] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    service
        .set_default_profile("second")
        .expect("default second");
    service.delete_profile("first").expect("delete first");
    assert!(store.contains(
        &second_config.organization_credential_id,
        SecretSlot::OrganizationApiKey
    ));

    service.create_profile("third", None).expect("third");
    service.set_default_profile("third").expect("default third");
    service.delete_profile("second").expect("delete second");
    assert!(!store.contains(
        &second_config.organization_credential_id,
        SecretSlot::OrganizationApiKey
    ));
}

#[tokio::test]
async fn failed_old_organization_cleanup_is_journaled_and_retried() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let (first_host, _) = response_server(vec![Response::active("agent-build")]).await;
    service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_first_organization".to_owned()),
            ApiHost::parse(&first_host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("first connect");
    let first_config = service
        .repository()
        .load_config(&profile.identity_id)
        .expect("first config");
    store.fail_delete(
        &first_config.organization_credential_id,
        SecretSlot::OrganizationApiKey,
    );

    let (second_host, _) = response_server(vec![Response::active("agent-build")]).await;
    assert!(
        service
            .connect(
                Some("build"),
                OrganizationApiKey::new("pl_second_organization".to_owned()),
                ApiHost::parse(&second_host).expect("host"),
                None,
                None,
                "fixture-host",
            )
            .await
            .is_err()
    );
    let journaled = service
        .repository()
        .load_config(&profile.identity_id)
        .expect("journaled config");
    assert_ne!(
        journaled.organization_credential_id,
        first_config.organization_credential_id
    );
    assert_eq!(
        journaled.retired_organization_credential_ids.as_slice(),
        std::slice::from_ref(&first_config.organization_credential_id)
    );

    store.clear_failure();
    let (status_host, _) = response_server(vec![Response::active("agent-build")]).await;
    let mut current = journaled;
    current.host = status_host;
    service
        .repository()
        .save_config(&profile.identity_id, &current)
        .expect("status host");
    service
        .status(Some("build"), "fixture-host")
        .await
        .expect("status cleanup");
    let cleaned = service
        .repository()
        .load_config(&profile.identity_id)
        .expect("cleaned config");
    assert!(cleaned.retired_organization_credential_ids.is_empty());
    assert!(!store.contains(
        &first_config.organization_credential_id,
        SecretSlot::OrganizationApiKey
    ));
}

#[tokio::test]
async fn failed_reconnect_preserves_working_config_and_removes_unused_candidate_key() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let (host, _) = response_server(vec![Response::active("agent-build")]).await;
    service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_working_organization_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("initial connect");
    let before = service
        .repository()
        .load_config(&profile.identity_id)
        .expect("config before");

    let unavailable = unused_loopback_host().await;
    let outcome = service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_replacement_fixture".to_owned()),
            ApiHost::parse(&unavailable).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("clean unreachable");
    assert!(!outcome.config_saved);
    let after = service
        .repository()
        .load_config(&profile.identity_id)
        .expect("config after");
    assert_eq!(after, before);
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
}

#[test]
fn rename_changes_only_alias_and_partial_delete_is_recoverable() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let first = service.create_profile("first", None).expect("first");
    service.create_profile("second", None).expect("second");

    service.rename_profile("first", "renamed").expect("rename");
    let renamed = service.resolve_profile(Some("renamed")).expect("renamed");
    assert_eq!(renamed.identity_id, first.identity_id);
    assert!(store.contains(&first.identity_id, SecretSlot::X25519PrivateKey));

    service
        .set_default_profile("second")
        .expect("default second");
    store.fail_delete(&first.identity_id, SecretSlot::Ed25519SecretKey);
    assert!(service.delete_profile("renamed").is_err());
    let registry = service.repository().load_registry().expect("registry");
    assert!(!registry.agents.iter().any(|agent| agent.name == "renamed"));
    assert!(!store.contains(&first.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&first.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(service.repository().cleanup_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover deletion");
    assert!(!store.contains(&first.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(!service.repository().cleanup_pending());
}

#[test]
fn failed_identity_creation_keeps_a_durable_cleanup_record_until_recovered() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    store.fail_set(SecretSlot::Ed25519SecretKey);
    store.fail_delete_slot(SecretSlot::X25519PrivateKey);

    assert!(service.create_profile("broken", None).is_err());
    assert_eq!(
        service
            .repository()
            .load_registry()
            .expect("registry")
            .agents
            .len(),
        0
    );
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 1);
    assert!(service.repository().cleanup_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover creation");
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);
    assert!(!service.repository().cleanup_pending());
}

#[tokio::test]
async fn failed_candidate_api_key_cleanup_is_durable_and_retryable() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    store.fail_delete_slot(SecretSlot::OrganizationApiKey);
    let (host, _) = response_server(vec![Response::invalid_key()]).await;

    assert!(
        service
            .connect(
                Some("build"),
                OrganizationApiKey::new("pl_invalid_cleanup_fixture".to_owned()),
                ApiHost::parse(&host).expect("host"),
                None,
                None,
                "fixture-host",
            )
            .await
            .is_err()
    );
    assert!(!service.repository().config_exists(&profile.identity_id));
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
    assert!(service.repository().cleanup_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover API key");
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
    assert!(!service.repository().cleanup_pending());
}

#[tokio::test]
async fn invalid_key_is_not_persisted_in_public_or_secure_storage() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let (host, _) = response_server(vec![Response::invalid_key()]).await;
    let outcome = service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_invalid_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("invalid result");
    assert!(matches!(
        outcome.registration,
        palladin_api::AgentRegistrationResult::InvalidKey
    ));
    assert!(!service.repository().config_exists(&profile.identity_id));
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
}

#[tokio::test]
async fn explicit_purge_removes_native_shared_and_identity_slots() {
    let root = tempfile::tempdir().expect("root");
    let root_path = root.path().to_path_buf();
    let store = MemoryStore::default();
    let service = service(&root_path, store.clone());
    service.create_profile("first", None).expect("first");
    service.create_profile("second", None).expect("second");
    let (host, _) = response_server(vec![
        Response::pending("agent-first"),
        Response::pending("agent-second"),
    ])
    .await;
    for profile in ["first", "second"] {
        service
            .connect(
                Some(profile),
                OrganizationApiKey::new("pl_shared_for_purge".to_owned()),
                ApiHost::parse(&host).expect("host"),
                None,
                None,
                "fixture-host",
            )
            .await
            .expect("connect");
    }
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
    service.purge().expect("purge");
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);
    assert!(!root_path.exists());
}

#[tokio::test]
async fn partial_purge_is_journaled_and_retried_before_public_data_is_removed() {
    let root = tempfile::tempdir().expect("root");
    let root_path = root.path().to_path_buf();
    let store = MemoryStore::default();
    let service = service(&root_path, store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let (host, _) = response_server(vec![Response::pending("agent-build")]).await;
    service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_purge_recovery_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("connect");
    store.fail_delete(&profile.identity_id, SecretSlot::Ed25519SecretKey);

    assert!(service.purge().is_err());
    assert!(!store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(service.repository().cleanup_pending());
    assert!(root_path.exists());

    store.clear_failure();
    service.recover_pending_operations().expect("recover purge");
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);
    assert!(!root_path.exists());
}

#[tokio::test]
async fn transaction_lock_serializes_two_runtime_processes_through_connect_commit() {
    let root = tempfile::tempdir().expect("root");
    let root_path = root.path().to_path_buf();
    let store = MemoryStore::default();
    let first_service = service(&root_path, store.clone());
    first_service
        .create_profile("build", None)
        .expect("profile");
    let (host, request_received, release_response) = gated_pending_server("agent-build").await;

    let first = tokio::spawn(async move {
        first_service
            .connect(
                Some("build"),
                OrganizationApiKey::new("pl_concurrent_organization_fixture".to_owned()),
                ApiHost::parse(&host).expect("host"),
                None,
                None,
                "fixture-host",
            )
            .await
    });
    request_received.await.expect("request received");

    let second_root = root_path.clone();
    let second_store = store.clone();
    let mut second =
        tokio::task::spawn_blocking(move || service(&second_root, second_store).registry());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut second)
            .await
            .is_err(),
        "second runtime must wait for the first transaction"
    );

    release_response.send(()).expect("release response");
    first.await.expect("first task").expect("first connect");
    let registry = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("second runtime resumed")
        .expect("second task")
        .expect("registry");
    assert_eq!(registry.agents.len(), 1);
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 1);
}

#[test]
fn purge_refuses_to_silently_delete_legacy_layout() {
    let root = tempfile::tempdir().expect("root");
    let legacy = root.path().join("agent.key");
    std::fs::write(&legacy, "synthetic-legacy-material").expect("legacy fixture");
    let service = service(root.path(), MemoryStore::default());
    assert!(service.purge().is_err());
    assert!(legacy.exists());
}

#[test]
fn purge_detects_nested_keychain_only_legacy_profile() {
    let root = tempfile::tempdir().expect("root");
    let legacy = root.path().join("agents").join("orphan");
    std::fs::create_dir_all(&legacy).expect("legacy directory");
    std::fs::write(
        legacy.join("config.json"),
        r#"{"host":"https://api.example.test"}"#,
    )
    .expect("legacy config");
    let service = service(root.path(), MemoryStore::default());

    assert!(service.repository().legacy_artifacts_present());
    assert!(service.purge().is_err());
    assert!(legacy.exists());
}

fn service(path: &std::path::Path, store: MemoryStore) -> RuntimeService<MemoryStore> {
    RuntimeService::new(
        ProfileRepository::new(path.to_path_buf()).expect("repository"),
        store,
    )
}

struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Response {
    fn pending(agent_id: &str) -> Self {
        Self {
            status: 401,
            headers: vec![("X-Agent-Id", agent_id.to_owned())],
            body: String::new(),
        }
    }

    fn active(agent_id: &str) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: format!(r#"{{"agentId":"{agent_id}","name":null,"status":"active"}}"#),
        }
    }

    fn invalid_key() -> Self {
        Self {
            status: 401,
            headers: Vec::new(),
            body: String::new(),
        }
    }
}

async fn response_server(responses: Vec<Response>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut bytes = vec![0u8; 8192];
            let read = stream.read(&mut bytes).await.expect("read");
            bytes.truncate(read);
            captured
                .lock()
                .expect("requests")
                .push(String::from_utf8_lossy(&bytes).into_owned());
            let reason = match response.status {
                200 => "OK",
                401 => "Unauthorized",
                _ => "Error",
            };
            let mut wire = format!(
                "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                response.status,
                response.body.len()
            );
            for (name, value) in response.headers {
                wire.push_str(&format!("{name}: {value}\r\n"));
            }
            wire.push_str("\r\n");
            wire.push_str(&response.body);
            stream.write_all(wire.as_bytes()).await.expect("write");
        }
    });
    (format!("http://{address}"), requests)
}

async fn gated_pending_server(
    agent_id: &'static str,
) -> (String, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let (request_sender, request_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut bytes = vec![0u8; 8192];
        let _read = stream.read(&mut bytes).await.expect("read");
        request_sender.send(()).expect("signal request");
        release_receiver.await.expect("release");
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nX-Agent-Id: {agent_id}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.expect("write");
    });
    (
        format!("http://{address}"),
        request_receiver,
        release_sender,
    )
}

async fn unused_loopback_host() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    tokio::time::sleep(Duration::from_millis(5)).await;
    format!("http://{address}")
}

fn read_public_files(root: &std::path::Path) -> String {
    fn walk(path: &std::path::Path, output: &mut String) {
        for entry in std::fs::read_dir(path).expect("read public directory") {
            let entry = entry.expect("entry");
            if entry.path().is_dir() {
                walk(&entry.path(), output);
            } else {
                output.push_str(&std::fs::read_to_string(entry.path()).expect("public UTF-8"));
            }
        }
    }
    let mut output = String::new();
    walk(root, &mut output);
    output
}
