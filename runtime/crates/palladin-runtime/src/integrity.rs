use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicProfileConfig, PublicRegistry, registry_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::RuntimeError;

pub(crate) const TRUST_OWNER_ID: &str = "00000000000000000000000000000000";
// Secure trust metadata follows an N/N-1 reader contract. Version 2 is the first
// production-ready contract; version 1 is accepted only as its immediate predecessor.
// Every write normalizes to N. A previous runtime that supports only version 1 rejects
// version 2 before it can authorize a journal or touch identity slots.
const TRUST_SCHEMA_VERSION: u32 = 2;
const MIN_READABLE_TRUST_SCHEMA_VERSION: u32 = TRUST_SCHEMA_VERSION - 1;
const JOURNAL_SCHEMA_VERSION: u32 = 1;
const JOURNAL_DOMAIN: &[u8] = b"palladin.integrity-journal.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum TrustState {
    Committed {
        trust_schema_version: u32,
        public_schema_version: u32,
        generation: u64,
        registry_digest: String,
    },
    PurgeCommitted {
        trust_schema_version: u32,
        public_schema_version: u32,
        generation: u64,
        registry_digest: String,
    },
    Transition {
        trust_schema_version: u32,
        public_schema_version: u32,
        from_generation: u64,
        from_registry_digest: String,
        to_generation: u64,
        to_registry_digest: String,
        journal_digest: String,
    },
    Allocating {
        trust_schema_version: u32,
        public_schema_version: u32,
        generation: u64,
        registry_digest: String,
        allocations: Vec<SecretAllocation>,
    },
}

impl TrustState {
    pub(crate) fn committed(generation: u64, registry_digest: String) -> Self {
        Self::Committed {
            trust_schema_version: TRUST_SCHEMA_VERSION,
            public_schema_version: PUBLIC_SCHEMA_VERSION,
            generation,
            registry_digest,
        }
    }

    pub(crate) fn transition(
        from_generation: u64,
        from_registry_digest: String,
        to_generation: u64,
        to_registry_digest: String,
        journal_digest: String,
    ) -> Self {
        Self::Transition {
            trust_schema_version: TRUST_SCHEMA_VERSION,
            public_schema_version: PUBLIC_SCHEMA_VERSION,
            from_generation,
            from_registry_digest,
            to_generation,
            to_registry_digest,
            journal_digest,
        }
    }

    pub(crate) fn purge_committed(generation: u64, registry_digest: String) -> Self {
        Self::PurgeCommitted {
            trust_schema_version: TRUST_SCHEMA_VERSION,
            public_schema_version: PUBLIC_SCHEMA_VERSION,
            generation,
            registry_digest,
        }
    }

    pub(crate) fn allocating(
        generation: u64,
        registry_digest: String,
        allocations: Vec<SecretAllocation>,
    ) -> Self {
        Self::Allocating {
            trust_schema_version: TRUST_SCHEMA_VERSION,
            public_schema_version: PUBLIC_SCHEMA_VERSION,
            generation,
            registry_digest,
            allocations,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        self.validate_for_max_schema(TRUST_SCHEMA_VERSION)
    }

    fn validate_for_max_schema(&self, max_schema_version: u32) -> Result<(), RuntimeError> {
        let (trust_schema, public_schema, generation_ok, digests) = match self {
            Self::Committed {
                trust_schema_version,
                public_schema_version,
                registry_digest,
                ..
            }
            | Self::PurgeCommitted {
                trust_schema_version,
                public_schema_version,
                registry_digest,
                ..
            } => (
                *trust_schema_version,
                *public_schema_version,
                true,
                vec![registry_digest.as_str()],
            ),
            Self::Transition {
                trust_schema_version,
                public_schema_version,
                from_generation,
                from_registry_digest,
                to_generation,
                to_registry_digest,
                journal_digest,
            } => (
                *trust_schema_version,
                *public_schema_version,
                *to_generation == from_generation.saturating_add(1),
                vec![
                    from_registry_digest.as_str(),
                    to_registry_digest.as_str(),
                    journal_digest.as_str(),
                ],
            ),
            Self::Allocating {
                trust_schema_version,
                public_schema_version,
                registry_digest,
                allocations,
                ..
            } => {
                if allocations.is_empty()
                    || allocations.iter().any(|allocation| !allocation.is_valid())
                    || allocations.iter().collect::<BTreeSet<_>>().len() != allocations.len()
                {
                    return Err(RuntimeError::IntegrityViolation);
                }
                (
                    *trust_schema_version,
                    *public_schema_version,
                    true,
                    vec![registry_digest.as_str()],
                )
            }
        };
        if !(MIN_READABLE_TRUST_SCHEMA_VERSION..=max_schema_version).contains(&trust_schema)
            || max_schema_version > TRUST_SCHEMA_VERSION
            || public_schema != PUBLIC_SCHEMA_VERSION
            || !generation_ok
            || digests.into_iter().any(|value| !is_digest(value))
        {
            return Err(RuntimeError::IntegrityViolation);
        }
        Ok(())
    }

    fn normalize_for_write(&mut self) {
        let trust_schema_version = match self {
            Self::Committed {
                trust_schema_version,
                ..
            }
            | Self::PurgeCommitted {
                trust_schema_version,
                ..
            }
            | Self::Transition {
                trust_schema_version,
                ..
            }
            | Self::Allocating {
                trust_schema_version,
                ..
            } => trust_schema_version,
        };
        *trust_schema_version = TRUST_SCHEMA_VERSION;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum SecretAllocation {
    Identity { identity_id: String },
    OrganizationCredential { organization_credential_id: String },
}

impl SecretAllocation {
    fn is_valid(&self) -> bool {
        match self {
            Self::Identity { identity_id } => is_opaque_id(identity_id),
            Self::OrganizationCredential {
                organization_credential_id,
            } => is_opaque_id(organization_credential_id),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfigWrite {
    pub identity_id: String,
    pub config: PublicProfileConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum SecretDeletion {
    Identity { identity_id: String },
    OrganizationCredential { organization_credential_id: String },
    LegacyIdentity { identity_id: String },
    LegacyOrganizationCredential { organization_credential_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum SecretCopy {
    LegacyIdentity { identity_id: String },
    LegacyOrganizationCredential { organization_credential_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IntegrityJournal {
    pub schema_version: u32,
    pub from_generation: u64,
    pub from_registry_digest: String,
    pub to_generation: u64,
    pub to_registry_digest: String,
    pub target_registry: PublicRegistry,
    pub config_writes: Vec<ConfigWrite>,
    pub remove_identity_directories: Vec<String>,
    #[serde(default)]
    pub secret_copies: Vec<SecretCopy>,
    pub secret_deletions: Vec<SecretDeletion>,
    pub purge_public_root: bool,
}

impl IntegrityJournal {
    pub(crate) fn new(
        from_generation: u64,
        from_registry_digest: String,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        remove_identity_directories: Vec<String>,
        secret_deletions: Vec<SecretDeletion>,
        purge_public_root: bool,
    ) -> Result<Self, RuntimeError> {
        let to_registry_digest =
            registry_digest(&target_registry).map_err(|_| RuntimeError::IntegrityViolation)?;
        let journal = Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            from_generation,
            from_registry_digest,
            to_generation: from_generation
                .checked_add(1)
                .ok_or(RuntimeError::IntegrityViolation)?,
            to_registry_digest,
            target_registry,
            config_writes,
            remove_identity_directories,
            secret_copies: Vec::new(),
            secret_deletions,
            purge_public_root,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub(crate) fn with_secret_copies(
        mut self,
        secret_copies: Vec<SecretCopy>,
    ) -> Result<Self, RuntimeError> {
        self.secret_copies = secret_copies;
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION
            || self.to_generation != self.from_generation.saturating_add(1)
            || !is_digest(&self.from_registry_digest)
            || !is_digest(&self.to_registry_digest)
            || !registry_digest(&self.target_registry)
                .is_ok_and(|digest| digest == self.to_registry_digest)
            || self.config_writes.iter().any(|write| {
                write.identity_id != write.config.identity_id
                    || !self.target_registry.agents.iter().any(|agent| {
                        agent.identity_id == write.identity_id
                            && agent.config_digest.as_deref()
                                == palladin_core::public_store::profile_config_digest(&write.config)
                                    .ok()
                                    .as_deref()
                    })
            })
            || self
                .remove_identity_directories
                .iter()
                .any(|identity| !is_opaque_id(identity))
            || self
                .remove_identity_directories
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.remove_identity_directories.len()
            || self.secret_deletions.iter().any(|deletion| match deletion {
                SecretDeletion::Identity { identity_id }
                | SecretDeletion::LegacyIdentity { identity_id } => !is_opaque_id(identity_id),
                SecretDeletion::OrganizationCredential {
                    organization_credential_id,
                }
                | SecretDeletion::LegacyOrganizationCredential {
                    organization_credential_id,
                } => !is_opaque_id(organization_credential_id),
            })
            || self.secret_deletions.iter().collect::<BTreeSet<_>>().len()
                != self.secret_deletions.len()
            || self.secret_copies.iter().any(|copy| match copy {
                SecretCopy::LegacyIdentity { identity_id } => !is_opaque_id(identity_id),
                SecretCopy::LegacyOrganizationCredential {
                    organization_credential_id,
                } => !is_opaque_id(organization_credential_id),
            })
            || self.secret_copies.iter().collect::<BTreeSet<_>>().len() != self.secret_copies.len()
            || self
                .config_writes
                .iter()
                .map(|write| &write.identity_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.config_writes.len()
            || (self.purge_public_root
                && (!self.target_registry.agents.is_empty() || !self.config_writes.is_empty()))
        {
            return Err(RuntimeError::IntegrityViolation);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<String, RuntimeError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| RuntimeError::IntegrityViolation)?;
        let mut hash = Sha256::new();
        hash.update(JOURNAL_DOMAIN);
        hash.update((encoded.len() as u64).to_be_bytes());
        hash.update(encoded);
        Ok(hex_digest(hash.finalize()))
    }
}

pub(crate) fn encode_trust_state(state: &TrustState) -> Result<Vec<u8>, RuntimeError> {
    state.validate()?;
    let mut current = state.clone();
    current.normalize_for_write();
    current.validate()?;
    serde_json::to_vec(&current).map_err(|_| RuntimeError::IntegrityViolation)
}

pub(crate) fn decode_trust_state(bytes: &[u8]) -> Result<TrustState, RuntimeError> {
    decode_trust_state_for_max_schema(bytes, TRUST_SCHEMA_VERSION)
}

fn decode_trust_state_for_max_schema(
    bytes: &[u8],
    max_schema_version: u32,
) -> Result<TrustState, RuntimeError> {
    let state: TrustState =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::IntegrityViolation)?;
    state.validate_for_max_schema(max_schema_version)?;
    Ok(state)
}

pub(crate) fn journal_path(root: &Path) -> PathBuf {
    root.join("integrity-journal.json")
}

pub(crate) fn load_journal(root: &Path) -> Result<IntegrityJournal, RuntimeError> {
    validate_private_directory(root)?;
    let path = journal_path(root);
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    validate_private_file(&path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    validate_private_file(
        &file
            .metadata()
            .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?,
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    let journal: IntegrityJournal =
        serde_json::from_slice(&bytes).map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    journal
        .validate()
        .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    Ok(journal)
}

pub(crate) fn save_journal(root: &Path, journal: &IntegrityJournal) -> Result<(), RuntimeError> {
    journal.validate()?;
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| RuntimeError::IntegrityViolation)?;
    save_atomic(&journal_path(root), &bytes)
}

pub(crate) fn remove_journal(root: &Path) -> Result<(), RuntimeError> {
    let path = journal_path(root);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| RuntimeError::IntegrityRecoveryRequired)
        }
        Ok(_) => Err(RuntimeError::IntegrityRecoveryRequired),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RuntimeError::IntegrityRecoveryRequired),
    }
}

fn save_atomic(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let parent = path.parent().ok_or(RuntimeError::IntegrityViolation)?;
    validate_private_directory(parent)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(RuntimeError::IntegrityRecoveryRequired),
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| RuntimeError::RandomGenerationFailed)?;
    let temporary = parent.join(format!(".integrity-{}.tmp", hex_digest(random)));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(RuntimeError::IntegrityRecoveryRequired);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?
        .sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<(), std::io::Error> {
    // Windows does not support opening a directory through std::fs::OpenOptions.
    // The journal file itself is flushed before the atomic rename above.
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RuntimeError::IntegrityRecoveryRequired);
    }
    #[cfg(unix)]
    validate_unix_metadata(&metadata, 0o700)?;
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<(), RuntimeError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RuntimeError::IntegrityRecoveryRequired);
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_metadata(metadata: &fs::Metadata, expected_mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(RuntimeError::IntegrityRecoveryRequired);
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_opaque_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use palladin_core::public_store::{
        PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
        profile_config_digest,
    };

    use super::{
        ConfigWrite, IntegrityJournal, SecretAllocation, SecretCopy, SecretDeletion, TrustState,
        decode_trust_state, decode_trust_state_for_max_schema, encode_trust_state, load_journal,
        remove_journal, save_journal,
    };

    fn fixture() -> (PublicRegistry, ConfigWrite) {
        let config = PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host: "https://api.palladin.io".to_owned(),
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some("agent-build".to_owned()),
            encryption_public_key: Some(STANDARD.encode([3_u8; 32])),
            signing_public_key: Some(STANDARD.encode([4_u8; 32])),
            binding_signature: STANDARD.encode([5_u8; 64]),
        };
        let registry = PublicRegistry {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: "build".to_owned(),
            agents: vec![PublicAgentEntry {
                name: "build".to_owned(),
                identity_id: config.identity_id.clone(),
                created_at: "2026-07-13T00:00:00Z".to_owned(),
                agent_type: Some("coding".to_owned()),
                config_digest: Some(profile_config_digest(&config).expect("digest")),
            }],
        };
        let write = ConfigWrite {
            identity_id: config.identity_id.clone(),
            config,
        };
        (registry, write)
    }

    #[test]
    fn trust_state_is_strictly_versioned_and_rejects_unknown_fields() {
        let state = TrustState::committed(7, "a".repeat(64));
        let encoded = encode_trust_state(&state).expect("encode");
        assert_eq!(decode_trust_state(&encoded).expect("decode"), state);

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON");
        value["unexpected"] = serde_json::json!(true);
        assert!(decode_trust_state(&serde_json::to_vec(&value).expect("JSON")).is_err());

        let mut previous: serde_json::Value =
            serde_json::from_slice(&encoded).expect("current JSON");
        previous["trust_schema_version"] = serde_json::json!(1);
        let previous_bytes = serde_json::to_vec(&previous).expect("previous JSON");
        let decoded_previous = decode_trust_state(&previous_bytes).expect("read N-1");
        let normalized: serde_json::Value = serde_json::from_slice(
            &encode_trust_state(&decoded_previous).expect("write current N"),
        )
        .expect("normalized JSON");
        assert_eq!(normalized["trust_schema_version"], serde_json::json!(2));

        assert!(
            decode_trust_state_for_max_schema(&encoded, 1).is_err(),
            "an N-1 runtime must reject newer secure metadata before mutation"
        );
        let mut future: serde_json::Value = serde_json::from_slice(&encoded).expect("current JSON");
        future["trust_schema_version"] = serde_json::json!(3);
        assert!(decode_trust_state(&serde_json::to_vec(&future).expect("future JSON")).is_err());

        let invalid = TrustState::transition(1, "a".repeat(64), 3, "b".repeat(64), "c".repeat(64));
        assert!(encode_trust_state(&invalid).is_err());

        let allocation = SecretAllocation::Identity {
            identity_id: "11111111111111111111111111111111".to_owned(),
        };
        let allocating = TrustState::allocating(7, "a".repeat(64), vec![allocation.clone()]);
        let encoded = encode_trust_state(&allocating).expect("encode allocating");
        assert_eq!(
            decode_trust_state(&encoded).expect("decode allocating"),
            allocating
        );
        assert!(
            encode_trust_state(&TrustState::allocating(
                7,
                "a".repeat(64),
                vec![allocation.clone(), allocation]
            ))
            .is_err()
        );
    }

    #[test]
    fn journal_digest_binds_transition_plan_and_rejects_duplicate_or_invalid_actions() {
        let (registry, write) = fixture();
        let journal = IntegrityJournal::new(
            0,
            "0".repeat(64),
            registry,
            vec![write],
            Vec::new(),
            vec![SecretDeletion::LegacyIdentity {
                identity_id: "11111111111111111111111111111111".to_owned(),
            }],
            false,
        )
        .expect("journal");
        let digest = journal.digest().expect("digest");

        let copied = journal
            .clone()
            .with_secret_copies(vec![SecretCopy::LegacyIdentity {
                identity_id: "11111111111111111111111111111111".to_owned(),
            }])
            .expect("copy plan");
        assert_ne!(copied.digest().expect("copy digest"), digest);

        let mut changed = journal.clone();
        changed.secret_deletions = vec![SecretDeletion::LegacyOrganizationCredential {
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
        }];
        assert_ne!(changed.digest().expect("changed digest"), digest);

        let mut duplicate = journal.clone();
        duplicate
            .secret_deletions
            .push(duplicate.secret_deletions[0].clone());
        assert!(duplicate.validate().is_err());

        let mut invalid_generation = journal;
        invalid_generation.to_generation = 9;
        assert!(invalid_generation.validate().is_err());
    }

    #[test]
    fn integrity_journal_round_trips_through_an_atomic_platform_save() {
        let root = tempfile::tempdir().expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let (registry, write) = fixture();
        let journal = IntegrityJournal::new(
            0,
            "0".repeat(64),
            registry,
            vec![write],
            Vec::new(),
            Vec::new(),
            false,
        )
        .expect("journal");

        save_journal(root.path(), &journal).expect("save journal");
        assert_eq!(load_journal(root.path()).expect("load journal"), journal);
        remove_journal(root.path()).expect("remove journal");
        assert!(!root.path().join("integrity-journal.json").exists());
    }
}
