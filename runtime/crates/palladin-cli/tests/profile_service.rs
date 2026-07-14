use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use palladin_cli::{RuntimeError, RuntimeService};
use palladin_core::host::ApiHost;
use palladin_core::profiles::ProfileRepository;
use palladin_core::secret::OrganizationApiKey;
use palladin_crypto::{Ed25519Identity, X25519Identity};
use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
use secrecy::{ExposeSecret, SecretSlice};
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
    operations: Vec<StoreOperation>,
    fail_set: Option<SecretSlot>,
    fail_delete: Option<(String, SecretSlot)>,
    fail_delete_slot: Option<SecretSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoreOperation {
    Get(String, SecretSlot),
    Set(String, SecretSlot),
    Delete(String, SecretSlot),
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

    fn secret(&self, owner: &str, slot: SecretSlot) -> Vec<u8> {
        self.state
            .lock()
            .expect("store")
            .secrets
            .get(&(owner.to_owned(), slot))
            .cloned()
            .expect("secret fixture")
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

    fn clear_operations(&self) {
        self.state.lock().expect("store").operations.clear();
    }

    fn operations(&self) -> Vec<StoreOperation> {
        self.state.lock().expect("store").operations.clone()
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let mut state = self.state.lock().expect("store");
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
        let mut state = self.state.lock().expect("store");
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
        let mut state = self.state.lock().expect("store");
        state
            .operations
            .push(StoreOperation::Delete(owner_id.to_owned(), slot));
        if state.fail_delete.as_ref() == Some(&(owner_id.to_owned(), slot))
            || state.fail_delete_slot == Some(slot)
        {
            return Err(StoreError::Unavailable);
        }
        state.secrets.remove(&(owner_id.to_owned(), slot));
        Ok(())
    }
}

#[test]
fn only_generation_zero_can_repair_a_missing_empty_registry() {
    let root = tempfile::tempdir().expect("root");
    let service = service(root.path(), MemoryStore::default());
    assert!(service.registry().expect("bootstrap").agents.is_empty());
    std::fs::remove_file(root.path().join("registry.json")).expect("remove empty registry");
    assert!(
        service
            .registry()
            .expect("repair empty registry")
            .agents
            .is_empty()
    );
    assert!(root.path().join("registry.json").is_file());

    service.create_profile("build", None).expect("profile");
    std::fs::remove_file(root.path().join("registry.json")).expect("remove committed registry");
    assert!(service.registry().is_err());
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
async fn explicit_profile_purge_preserves_shared_organization_key_until_last_agent() {
    const TRUST_OWNER: &str = "00000000000000000000000000000000";

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
    for profile in ["first", "second"] {
        service
            .connect(
                Some(profile),
                OrganizationApiKey::new("pl_shared_profile_purge_fixture".to_owned()),
                ApiHost::parse(&host).expect("host"),
                None,
                None,
                "fixture-host",
            )
            .await
            .expect("connect");
    }
    let organization_id = service
        .repository()
        .load_config(&second.identity_id)
        .expect("second config")
        .organization_credential_id;
    store
        .set(
            TRUST_OWNER,
            SecretSlot::VersionPolicyTrustStateV1,
            br#"{"schemaVersion":1,"highestSequence":1,"policyDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .expect("version policy trust fixture");

    let removed = service
        .purge_profile(Some("first"))
        .expect("purge default profile");
    assert_eq!(removed.identity_id, first.identity_id);
    assert!(!store.contains(&first.identity_id, SecretSlot::X25519PrivateKey));
    assert!(!store.contains(&first.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(store.contains(&second.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&second.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(store.contains(&organization_id, SecretSlot::OrganizationApiKey));
    assert!(store.contains(TRUST_OWNER, SecretSlot::VersionPolicyTrustStateV1));
    let registry = service.registry().expect("remaining registry");
    assert_eq!(registry.default, "second");

    let removed = service.purge_profile(None).expect("purge last profile");
    assert_eq!(removed.identity_id, second.identity_id);
    assert!(!store.contains(&organization_id, SecretSlot::OrganizationApiKey));
    assert!(store.contains(TRUST_OWNER, SecretSlot::VersionPolicyTrustStateV1));
    assert!(
        service
            .registry()
            .expect("empty registry")
            .agents
            .is_empty()
    );
}

#[test]
fn trust_state_reads_n_minus_one_writes_n_and_future_schema_fails_without_mutation() {
    const TRUST_OWNER: &str = "00000000000000000000000000000000";

    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    service.registry().expect("bootstrap");
    let profile = service.create_profile("build", None).expect("profile");
    let encryption_before = store.secret(&profile.identity_id, SecretSlot::X25519PrivateKey);
    let signing_before = store.secret(&profile.identity_id, SecretSlot::Ed25519SecretKey);

    let mut previous: serde_json::Value =
        serde_json::from_slice(&store.secret(TRUST_OWNER, SecretSlot::IntegrityTrustStateV1))
            .expect("trust JSON");
    previous["trust_schema_version"] = serde_json::json!(1);
    store
        .set(
            TRUST_OWNER,
            SecretSlot::IntegrityTrustStateV1,
            &serde_json::to_vec(&previous).expect("previous JSON"),
        )
        .expect("install N-1 trust fixture");
    store.clear_operations();
    service.registry().expect("current reads N-1");
    assert_only_integrity_reads(&store.operations(), "N-1 trust state");

    service
        .rename_profile("build", "renamed")
        .expect("authenticated journal migration to N");
    let current: serde_json::Value =
        serde_json::from_slice(&store.secret(TRUST_OWNER, SecretSlot::IntegrityTrustStateV1))
            .expect("current trust JSON");
    assert_eq!(current["trust_schema_version"], serde_json::json!(2));
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(
        store.secret(&profile.identity_id, SecretSlot::X25519PrivateKey) == encryption_before,
        "trust migration must preserve the existing X25519 slot bytes"
    );
    assert!(
        store.secret(&profile.identity_id, SecretSlot::Ed25519SecretKey) == signing_before,
        "trust migration must preserve the existing Ed25519 slot bytes"
    );
    assert_eq!(store.count_slot(SecretSlot::IntegrityTrustStateV1), 1);

    let registry_before = std::fs::read(root.path().join("registry.json")).expect("registry");
    let mut future = current;
    future["trust_schema_version"] = serde_json::json!(3);
    store
        .set(
            TRUST_OWNER,
            SecretSlot::IntegrityTrustStateV1,
            &serde_json::to_vec(&future).expect("future JSON"),
        )
        .expect("install future trust fixture");
    store.clear_operations();
    assert!(service.registry().is_err());
    assert_only_integrity_reads(&store.operations(), "future trust state");
    assert_eq!(
        std::fs::read(root.path().join("registry.json")).expect("registry after rejection"),
        registry_before
    );
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
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

    let (second_host, _) = response_server(vec![
        Response::active("agent-build"),
        Response::active("agent-build"),
    ])
    .await;
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
    assert!(journaled.retired_organization_credential_ids.is_empty());
    assert!(service.integrity_recovery_pending());

    store.clear_failure();
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
    assert!(service.integrity_recovery_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover deletion");
    assert!(!store.contains(&first.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(!service.integrity_recovery_pending());
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
    assert!(service.integrity_recovery_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover creation");
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);
    assert!(!service.integrity_recovery_pending());
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
    assert!(service.integrity_recovery_pending());

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("recover API key");
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
    assert!(!service.integrity_recovery_pending());
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
async fn every_public_binding_tamper_fails_before_identity_or_api_key_access() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let (host, _) = response_server(vec![Response::active("agent-build")]).await;
    service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_integrity_fixture".to_owned()),
            ApiHost::parse(&host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("connect");

    let config_path = root
        .path()
        .join("identities")
        .join(&profile.identity_id)
        .join("config.json");
    let registry_path = root.path().join("registry.json");
    let original_config = std::fs::read(&config_path).expect("config bytes");
    let original_registry = std::fs::read(&registry_path).expect("registry bytes");

    for field in [
        "schemaVersion",
        "identityId",
        "host",
        "organizationCredentialId",
        "retiredOrganizationCredentialIds",
        "agentId",
        "encryptionPublicKey",
        "signingPublicKey",
        "bindingSignature",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&original_config).expect("config JSON");
        match field {
            "schemaVersion" => value[field] = serde_json::json!(2),
            "identityId" => value[field] = serde_json::json!("33333333333333333333333333333333"),
            "host" => value[field] = serde_json::json!("https://attacker.test"),
            "organizationCredentialId" => {
                value[field] = serde_json::json!("44444444444444444444444444444444");
            }
            "retiredOrganizationCredentialIds" => {
                value[field] = serde_json::json!(["55555555555555555555555555555555"]);
            }
            "agentId" => value[field] = serde_json::json!("attacker-agent"),
            "encryptionPublicKey" => {
                value[field] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            }
            "signingPublicKey" => {
                value[field] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            }
            "bindingSignature" => {
                value[field] = serde_json::json!(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                )
            }
            _ => unreachable!(),
        }
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&value).expect("JSON"),
        )
        .expect("tamper config");
        store.clear_operations();
        assert!(
            service.open_session(Some("build"), "fixture-host").is_err(),
            "field {field} must fail closed"
        );
        assert_only_integrity_reads(&store.operations(), field);
        std::fs::write(&config_path, &original_config).expect("restore config");
    }

    for field in [
        "schemaVersion",
        "default",
        "name",
        "identityId",
        "createdAt",
        "type",
        "configDigest",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&original_registry).expect("registry JSON");
        match field {
            "schemaVersion" => value[field] = serde_json::json!(2),
            "default" => value[field] = serde_json::json!("attacker"),
            "name" => value["agents"][0][field] = serde_json::json!("attacker"),
            "identityId" => {
                value["agents"][0][field] = serde_json::json!("66666666666666666666666666666666");
            }
            "createdAt" => value["agents"][0][field] = serde_json::json!("2026-07-14T00:00:00Z"),
            "type" => value["agents"][0][field] = serde_json::json!("attacker"),
            "configDigest" => value["agents"][0][field] = serde_json::json!("a".repeat(64)),
            _ => unreachable!(),
        }
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&value).expect("JSON"),
        )
        .expect("tamper registry");
        store.clear_operations();
        assert!(
            service.registry().is_err(),
            "field {field} must fail closed"
        );
        assert_only_integrity_reads(&store.operations(), field);
        std::fs::write(&registry_path, &original_registry).expect("restore registry");
    }
}

#[cfg(unix)]
#[test]
fn unsafe_unconnected_config_fails_before_identity_access() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let config_path = root
        .path()
        .join("identities")
        .join(&profile.identity_id)
        .join("config.json");
    std::fs::create_dir_all(config_path.parent().expect("config parent"))
        .expect("identity directory");
    for directory in [
        root.path().join("identities"),
        config_path.parent().expect("config parent").to_path_buf(),
    ] {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    let target = root.path().join("attacker-config.json");
    write_private_fixture(&target, br#"{}"#);
    symlink(&target, &config_path).expect("config symlink");

    store.clear_operations();
    assert!(service.verify_identity(Some("build")).is_err());
    assert_only_integrity_reads(&store.operations(), "symlinked unconnected config");

    std::fs::remove_file(&config_path).expect("remove symlink");
    std::fs::write(&config_path, br#"{}"#).expect("weak config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644))
        .expect("weak permissions");
    store.clear_operations();
    assert!(service.verify_identity(Some("build")).is_err());
    assert_only_integrity_reads(&store.operations(), "weak unconnected config");
}

#[test]
fn an_unpinned_public_journal_can_never_authorize_secret_deletion() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    let journal = root.path().join("integrity-journal.json");
    std::fs::write(&journal, br#"{"secretDeletions":[{"kind":"identity","identityId":"11111111111111111111111111111111"}]}"#)
        .expect("forged journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))
            .expect("private forged journal");
    }
    store.clear_operations();
    service
        .registry()
        .expect("committed state ignores forged journal");
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(
        !store
            .operations()
            .iter()
            .any(|operation| matches!(operation, StoreOperation::Delete(_, _)))
    );
}

#[cfg(unix)]
#[test]
fn authenticated_recovery_rejects_weak_or_symlinked_journal_without_more_deletes() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    store.fail_delete(&profile.identity_id, SecretSlot::Ed25519SecretKey);
    assert!(service.purge().is_err());
    assert!(service.integrity_recovery_pending());
    store.clear_failure();

    let journal = root.path().join("integrity-journal.json");
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644))
        .expect("weaken journal");
    store.clear_operations();
    assert!(service.recover_pending_operations().is_err());
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert_only_integrity_reads(&store.operations(), "weak journal permissions");

    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))
        .expect("restore journal mode");
    let real = root.path().join("real-integrity-journal.json");
    std::fs::rename(&journal, &real).expect("move real journal");
    symlink(&real, &journal).expect("journal symlink");
    store.clear_operations();
    assert!(service.recover_pending_operations().is_err());
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert_only_integrity_reads(&store.operations(), "symlinked journal");
}

#[test]
fn explicit_v2_upgrade_rotates_slots_and_restored_v2_metadata_cannot_downgrade() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let root = tempfile::tempdir().expect("root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let identity_id = "11111111111111111111111111111111";
    let organization_id = "22222222222222222222222222222222";
    let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("encryption");
    let signing = Ed25519Identity::from_seed(vec![8; 32]).expect("signing");
    let registry = serde_json::json!({
        "schemaVersion": 2,
        "default": "build",
        "agents": [{
            "name": "build",
            "identityId": identity_id,
            "createdAt": "2026-07-13T00:00:00Z",
            "type": "coding"
        }]
    });
    let config = serde_json::json!({
        "schemaVersion": 2,
        "host": "https://api.palladin.io",
        "organizationCredentialId": organization_id,
        "retiredOrganizationCredentialIds": [],
        "agentId": "agent-build",
        "encryptionPublicKey": STANDARD.encode(encryption.public_key()),
        "signingPublicKey": STANDARD.encode(signing.public_key())
    });
    let registry_bytes = serde_json::to_vec_pretty(&registry).expect("registry JSON");
    write_private_fixture(&root.path().join("registry.json"), &registry_bytes);
    let identity_root = root.path().join("identities").join(identity_id);
    std::fs::create_dir_all(&identity_root).expect("identity root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.path().join("identities"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("identities mode");
        std::fs::set_permissions(&identity_root, std::fs::Permissions::from_mode(0o700))
            .expect("identity mode");
    }
    write_private_fixture(
        &identity_root.join("config.json"),
        &serde_json::to_vec_pretty(&config).expect("config JSON"),
    );

    let store = MemoryStore::default();
    store
        .set(
            identity_id,
            SecretSlot::LegacyX25519PrivateKeyV2,
            encryption.private_key_for_secure_storage(),
        )
        .expect("legacy encryption");
    store
        .set(
            identity_id,
            SecretSlot::LegacyEd25519SecretKeyV2,
            signing
                .libsodium_secret_for_secure_storage()
                .expose_secret(),
        )
        .expect("legacy signing");
    store
        .set(
            organization_id,
            SecretSlot::LegacyOrganizationApiKeyV2,
            b"pl_legacy_fixture",
        )
        .expect("legacy API key");
    let service = service(root.path(), store.clone());

    let legacy_cleanup = root.path().join("cleanup-journal.json");
    write_private_fixture(&legacy_cleanup, br#"{"schemaVersion":1,"operations":[]}"#);
    assert!(matches!(
        service.upgrade_security(Some("build")),
        Err(RuntimeError::LegacyCleanupPending)
    ));
    assert!(
        legacy_cleanup.is_file(),
        "upgrade must preserve legacy recovery state"
    );
    service
        .repository()
        .remove_cleanup_journal()
        .expect("simulate previous-version recovery");

    store.fail_set(SecretSlot::Ed25519SecretKey);
    assert!(
        service.upgrade_security(Some("build")).is_err(),
        "interrupted secret copy must leave an authenticated recovery plan"
    );
    assert!(service.integrity_recovery_pending());
    assert!(store.contains(identity_id, SecretSlot::LegacyX25519PrivateKeyV2));
    assert!(store.contains(identity_id, SecretSlot::LegacyEd25519SecretKeyV2));
    assert!(store.contains(organization_id, SecretSlot::LegacyOrganizationApiKeyV2));

    store.clear_failure();
    store.fail_delete(identity_id, SecretSlot::LegacyEd25519SecretKeyV2);
    assert!(
        service.recover_pending_operations().is_err(),
        "partial legacy identity deletion must remain recoverable"
    );
    assert!(!store.contains(identity_id, SecretSlot::LegacyX25519PrivateKeyV2));
    assert!(store.contains(identity_id, SecretSlot::LegacyEd25519SecretKeyV2));
    assert!(store.contains(identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(identity_id, SecretSlot::Ed25519SecretKey));
    assert!(store.contains(organization_id, SecretSlot::OrganizationApiKey));
    store
        .delete(organization_id, SecretSlot::LegacyOrganizationApiKeyV2)
        .expect("simulate crash after legacy organization deletion");

    store.clear_failure();
    service
        .recover_pending_operations()
        .expect("replay partially deleted migration");
    let outcome = service
        .upgrade_security(Some("build"))
        .expect("completed migration");
    assert!(!outcome.migrated);
    assert!(store.contains(identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(organization_id, SecretSlot::OrganizationApiKey));
    assert!(!store.contains(identity_id, SecretSlot::LegacyX25519PrivateKeyV2));
    assert!(!store.contains(identity_id, SecretSlot::LegacyEd25519SecretKeyV2));
    assert!(!store.contains(organization_id, SecretSlot::LegacyOrganizationApiKeyV2));

    write_private_fixture(&root.path().join("registry.json"), &registry_bytes);
    store.clear_operations();
    assert!(
        service.registry().is_err(),
        "restored v2 registry must fail closed"
    );
    assert_only_integrity_reads(&store.operations(), "restored v2 registry");
}

#[tokio::test]
async fn existing_agent_requests_use_its_signing_identity_with_the_shared_organization_key() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store);
    service.create_profile("build", None).expect("profile");
    let (connect_host, requests) = response_server(vec![
        Response::active("agent-build"),
        Response::active("agent-build"),
    ])
    .await;
    service
        .connect(
            Some("build"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            ApiHost::parse(&connect_host).expect("host"),
            None,
            None,
            "fixture-host",
        )
        .await
        .expect("connect");

    service
        .status(Some("build"), "fixture-host")
        .await
        .expect("status");

    let request = requests.lock().expect("requests")[1].to_ascii_lowercase();
    assert!(request.contains("x-agent-id: agent-build\r\n"));
    assert!(request.contains("x-agent-signature: "));
    assert!(request.contains("x-agent-timestamp: "));
    assert!(request.contains("x-agent-nonce: "));
}

#[tokio::test]
async fn explicit_purge_removes_native_shared_and_identity_slots() {
    const TRUST_OWNER: &str = "00000000000000000000000000000000";

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
    store
        .set(
            TRUST_OWNER,
            SecretSlot::VersionPolicyTrustStateV1,
            br#"{"schemaVersion":1,"highestSequence":1,"policyDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .expect("version policy trust fixture");
    service.purge().expect("purge");
    assert_eq!(store.count_slot(SecretSlot::OrganizationApiKey), 0);
    assert_eq!(store.count_slot(SecretSlot::X25519PrivateKey), 0);
    assert_eq!(store.count_slot(SecretSlot::Ed25519SecretKey), 0);
    assert!(!store.contains(TRUST_OWNER, SecretSlot::VersionPolicyTrustStateV1));
    assert!(!root_path.exists());
}

#[test]
fn purge_rejects_unexpected_public_artifacts_before_any_secret_deletion() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    write_private_fixture(&root.path().join("unexpected.txt"), b"preserve me");
    store.clear_operations();

    assert!(service.purge().is_err());
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert!(
        !store
            .operations()
            .iter()
            .any(|operation| matches!(operation, StoreOperation::Delete(_, _))),
        "public preflight must complete before any secure-store deletion"
    );
    assert_eq!(
        std::fs::read(root.path().join("unexpected.txt")).expect("unexpected artifact"),
        b"preserve me"
    );
}

#[test]
fn purge_recovery_preflights_again_before_replaying_any_mutation() {
    let root = tempfile::tempdir().expect("root");
    let store = MemoryStore::default();
    let service = service(root.path(), store.clone());
    let profile = service.create_profile("build", None).expect("profile");
    store.fail_delete(&profile.identity_id, SecretSlot::X25519PrivateKey);
    assert!(service.purge().is_err());
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));

    write_private_fixture(&root.path().join("unexpected.txt"), b"preserve after crash");
    let registry_before = std::fs::read(root.path().join("registry.json")).expect("registry");
    store.clear_failure();
    store.clear_operations();
    assert!(service.recover_pending_operations().is_err());
    assert_only_integrity_reads(&store.operations(), "purge replay preflight");
    assert_eq!(
        std::fs::read(root.path().join("registry.json")).expect("registry after replay rejection"),
        registry_before
    );
    assert!(store.contains(&profile.identity_id, SecretSlot::X25519PrivateKey));
    assert!(store.contains(&profile.identity_id, SecretSlot::Ed25519SecretKey));
    assert_eq!(
        std::fs::read(root.path().join("unexpected.txt")).expect("unexpected artifact"),
        b"preserve after crash"
    );
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
    assert!(service.integrity_recovery_pending());
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("private profile root");
    }
    RuntimeService::new(
        ProfileRepository::new(path.to_path_buf()).expect("repository"),
        store,
    )
}

fn assert_only_integrity_reads(operations: &[StoreOperation], field: &str) {
    assert!(!operations.is_empty(), "{field}: trust root was not read");
    assert!(
        operations.iter().all(|operation| matches!(
            operation,
            StoreOperation::Get(owner, SecretSlot::IntegrityTrustStateV1)
                if owner == "00000000000000000000000000000000"
        )),
        "{field}: unexpected secure-store access: {operations:?}"
    );
}

fn write_private_fixture(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private fixture");
    }
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
