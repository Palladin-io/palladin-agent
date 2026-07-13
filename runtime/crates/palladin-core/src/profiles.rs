use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::public_store::{
    LegacyPublicProfileConfigV2, LegacyPublicRegistryV2, PUBLIC_SCHEMA_VERSION, PublicAgentEntry,
    PublicProfileConfig, PublicRegistry, PublicStoreError, is_opaque_id, is_profile_name,
    load_json, load_legacy_profile_config_v2, load_legacy_registry_v2, load_profile_config,
    load_registry, save_json_atomic, save_profile_config, save_registry,
};

const CLEANUP_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupJournal {
    pub schema_version: u32,
    pub operations: Vec<CleanupOperation>,
}

impl Default for CleanupJournal {
    fn default() -> Self {
        Self {
            schema_version: CLEANUP_SCHEMA_VERSION,
            operations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum CleanupOperation {
    CreateIdentity {
        identity_id: String,
    },
    CreateOrganizationCredential {
        organization_credential_id: String,
    },
    DeleteProfile {
        identity_id: String,
        organization_credential_ids: Vec<String>,
    },
    Purge {
        identity_ids: Vec<String>,
        organization_credential_ids: Vec<String>,
    },
}

impl CleanupJournal {
    fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != CLEANUP_SCHEMA_VERSION
            || self.operations.iter().any(|operation| match operation {
                CleanupOperation::CreateIdentity { identity_id } => !is_opaque_id(identity_id),
                CleanupOperation::DeleteProfile {
                    identity_id,
                    organization_credential_ids,
                } => {
                    !is_opaque_id(identity_id)
                        || organization_credential_ids
                            .iter()
                            .any(|value| !is_opaque_id(value))
                }
                CleanupOperation::CreateOrganizationCredential {
                    organization_credential_id,
                } => !is_opaque_id(organization_credential_id),
                CleanupOperation::Purge {
                    identity_ids,
                    organization_credential_ids,
                } => {
                    identity_ids.iter().any(|value| !is_opaque_id(value))
                        || organization_credential_ids
                            .iter()
                            .any(|value| !is_opaque_id(value))
                }
            })
        {
            return Err(ProfileError::InvalidCleanupJournal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn parse(value: &str) -> Result<Self, ProfileError> {
        if !is_profile_name(value) {
            return Err(ProfileError::InvalidProfileName);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct ProfileRepository {
    root: PathBuf,
}

pub struct TransactionLock {
    file: File,
}

impl Drop for TransactionLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

impl ProfileRepository {
    pub fn new(root: PathBuf) -> Result<Self, ProfileError> {
        if !root.is_absolute() || root.file_name().is_none() || root.parent().is_none() {
            return Err(ProfileError::InvalidRoot);
        }
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load_registry(&self) -> Result<PublicRegistry, ProfileError> {
        let path = self.root.join("registry.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(load_registry(&path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(PublicRegistry::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn save_registry(&self, registry: &PublicRegistry) -> Result<(), ProfileError> {
        ensure_private_directory(&self.root)?;
        Ok(save_registry(&self.root.join("registry.json"), registry)?)
    }

    pub fn load_legacy_registry_v2(&self) -> Result<LegacyPublicRegistryV2, ProfileError> {
        Ok(load_legacy_registry_v2(&self.root.join("registry.json"))?)
    }

    pub fn acquire_transaction_lock(&self) -> Result<TransactionLock, ProfileError> {
        let path = self.transaction_lock_path()?;
        let parent = path.parent().ok_or(ProfileError::InvalidRoot)?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(
                private_path_error("transaction lock parent is not a real directory").into(),
            );
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        validate_private_file(&file.metadata()?, "transaction lock")?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(TransactionLock { file })
    }

    pub fn load_config(&self, identity_id: &str) -> Result<PublicProfileConfig, ProfileError> {
        Ok(load_profile_config(&self.config_path(identity_id)?)?)
    }

    pub fn save_config(
        &self,
        identity_id: &str,
        config: &PublicProfileConfig,
    ) -> Result<(), ProfileError> {
        let path = self.config_path(identity_id)?;
        let parent = path.parent().ok_or(ProfileError::InvalidRoot)?;
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.root.join("identities"))?;
        ensure_private_directory(parent)?;
        Ok(save_profile_config(&path, config)?)
    }

    pub fn load_legacy_config_v2(
        &self,
        identity_id: &str,
    ) -> Result<LegacyPublicProfileConfigV2, ProfileError> {
        Ok(load_legacy_profile_config_v2(
            &self.config_path(identity_id)?,
        )?)
    }

    #[must_use]
    pub fn config_exists(&self, identity_id: &str) -> bool {
        self.config_path(identity_id).is_ok_and(|path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && validate_private_file(&metadata, "profile config").is_ok()
            })
        })
    }

    pub fn config_exists_strict(&self, identity_id: &str) -> Result<bool, ProfileError> {
        let path = self.config_path(identity_id)?;
        let identities = self.root.join("identities");
        let identity = path.parent().ok_or(ProfileError::InvalidRoot)?;
        for (directory, kind) in [
            (self.root.as_path(), "profile root"),
            (identities.as_path(), "identities directory"),
            (identity, "identity directory"),
        ] {
            match fs::symlink_metadata(directory) {
                Ok(metadata) => validate_private_directory(&metadata, kind)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            }
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_private_file(&metadata, "profile config")?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn remove_identity_directory(&self, identity_id: &str) -> Result<(), ProfileError> {
        let directory = self.identity_directory(identity_id)?;
        let identities = self.root.join("identities");
        for (parent, kind) in [
            (self.root.as_path(), "profile root"),
            (identities.as_path(), "identities directory"),
        ] {
            match fs::symlink_metadata(parent) {
                Ok(metadata) => validate_private_directory(&metadata, kind)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                validate_private_directory(&metadata, "identity directory")?;
                validate_identity_directory_contents(&directory)?;
                remove_known_file_if_present(&directory.join("config.json"), "profile config")?;
                fs::remove_dir(directory)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn purge_public_data(&self) -> Result<(), ProfileError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) => {
                validate_private_directory(&metadata, "profile root")?;
                validate_public_root_contents(&self.root)?;
                for (name, kind) in [
                    ("registry.json", "public registry"),
                    ("cleanup-journal.json", "cleanup journal"),
                    ("integrity-journal.json", "integrity journal"),
                ] {
                    remove_known_file_if_present(&self.root.join(name), kind)?;
                }
                let identities = self.root.join("identities");
                match fs::symlink_metadata(&identities) {
                    Ok(metadata) => {
                        validate_private_directory(&metadata, "identities directory")?;
                        fs::remove_dir(identities)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                fs::remove_dir(&self.root)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn load_cleanup_journal(&self) -> Result<CleanupJournal, ProfileError> {
        let path = self.cleanup_journal_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CleanupJournal::default());
            }
            Err(error) => return Err(error.into()),
        }
        let journal: CleanupJournal = load_json(&path)?;
        journal.validate()?;
        Ok(journal)
    }

    pub fn save_cleanup_journal(&self, journal: &CleanupJournal) -> Result<(), ProfileError> {
        journal.validate()?;
        ensure_private_directory(&self.root)?;
        save_json_atomic(&self.cleanup_journal_path(), journal)?;
        Ok(())
    }

    pub fn remove_cleanup_journal(&self) -> Result<(), ProfileError> {
        let path = self.cleanup_journal_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_private_file(&metadata, "cleanup journal")?;
                fs::remove_file(path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    #[must_use]
    pub fn cleanup_pending(&self) -> bool {
        path_present_no_follow(&self.cleanup_journal_path())
    }

    #[must_use]
    pub fn legacy_artifacts_present(&self) -> bool {
        ["config.json", "agent.key", "agent.pub", "signing.key"]
            .iter()
            .any(|name| path_present_no_follow(&self.root.join(name)))
            || path_present_no_follow(&self.root.join("agents"))
            || (path_present_no_follow(&self.root.join("registry.json"))
                && self.load_registry().is_err())
    }

    fn config_path(&self, identity_id: &str) -> Result<PathBuf, ProfileError> {
        Ok(self.identity_directory(identity_id)?.join("config.json"))
    }

    fn identity_directory(&self, identity_id: &str) -> Result<PathBuf, ProfileError> {
        if !is_opaque_id(identity_id) {
            return Err(ProfileError::InvalidIdentityId);
        }
        Ok(self.root.join("identities").join(identity_id))
    }

    fn cleanup_journal_path(&self) -> PathBuf {
        self.root.join("cleanup-journal.json")
    }

    fn transaction_lock_path(&self) -> Result<PathBuf, ProfileError> {
        let parent = self.root.parent().ok_or(ProfileError::InvalidRoot)?;
        let name = self
            .root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ProfileError::InvalidRoot)?;
        Ok(parent.join(format!(".{name}.palladin-runtime.lock")))
    }
}

pub fn add_profile(
    registry: &PublicRegistry,
    name: &ProfileName,
    identity_id: String,
    created_at: String,
    agent_type: Option<String>,
) -> Result<PublicRegistry, ProfileError> {
    if registry
        .agents
        .iter()
        .any(|agent| agent.name == name.as_str())
    {
        return Err(ProfileError::AlreadyExists);
    }
    if !is_opaque_id(&identity_id)
        || registry
            .agents
            .iter()
            .any(|agent| agent.identity_id == identity_id)
    {
        return Err(ProfileError::InvalidIdentityId);
    }

    let mut updated = registry.clone();
    updated.agents.push(PublicAgentEntry {
        name: name.as_str().to_owned(),
        identity_id,
        created_at,
        agent_type: agent_type
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        config_digest: None,
    });
    if updated.agents.len() == 1 {
        updated.default = name.as_str().to_owned();
    }
    updated.schema_version = PUBLIC_SCHEMA_VERSION;
    Ok(updated)
}

pub fn rename_profile(
    registry: &PublicRegistry,
    old_name: &ProfileName,
    new_name: &ProfileName,
) -> Result<PublicRegistry, ProfileError> {
    if registry
        .agents
        .iter()
        .any(|agent| agent.name == new_name.as_str())
    {
        return Err(ProfileError::AlreadyExists);
    }
    if !registry
        .agents
        .iter()
        .any(|agent| agent.name == old_name.as_str())
    {
        return Err(ProfileError::NotFound);
    }
    let mut updated = registry.clone();
    for agent in &mut updated.agents {
        if agent.name == old_name.as_str() {
            agent.name = new_name.as_str().to_owned();
        }
    }
    if updated.default == old_name.as_str() {
        updated.default = new_name.as_str().to_owned();
    }
    Ok(updated)
}

pub fn delete_profile(
    registry: &PublicRegistry,
    name: &ProfileName,
) -> Result<(PublicRegistry, PublicAgentEntry), ProfileError> {
    if registry.default == name.as_str() {
        return Err(ProfileError::DefaultCannotBeDeleted);
    }
    let entry = registry
        .agents
        .iter()
        .find(|agent| agent.name == name.as_str())
        .cloned()
        .ok_or(ProfileError::NotFound)?;
    let mut updated = registry.clone();
    updated.agents.retain(|agent| agent.name != name.as_str());
    Ok((updated, entry))
}

pub fn set_default(
    registry: &PublicRegistry,
    name: &ProfileName,
) -> Result<PublicRegistry, ProfileError> {
    if !registry
        .agents
        .iter()
        .any(|agent| agent.name == name.as_str())
    {
        return Err(ProfileError::NotFound);
    }
    let mut updated = registry.clone();
    updated.default = name.as_str().to_owned();
    Ok(updated)
}

pub fn set_profile_type(
    registry: &PublicRegistry,
    name: &ProfileName,
    agent_type: Option<&str>,
) -> Result<PublicRegistry, ProfileError> {
    if !registry
        .agents
        .iter()
        .any(|agent| agent.name == name.as_str())
    {
        return Err(ProfileError::NotFound);
    }
    let normalized = agent_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let mut updated = registry.clone();
    for agent in &mut updated.agents {
        if agent.name == name.as_str() {
            agent.agent_type.clone_from(&normalized);
        }
    }
    Ok(updated)
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error(
        "profile name must use lowercase letters, digits, hyphens, or underscores and cannot be a reserved device name"
    )]
    InvalidProfileName,
    #[error("profile already exists")]
    AlreadyExists,
    #[error("profile was not found")]
    NotFound,
    #[error("the default profile cannot be deleted; set another default first")]
    DefaultCannotBeDeleted,
    #[error("identity identifier is invalid")]
    InvalidIdentityId,
    #[error("cleanup journal contains invalid public recovery metadata")]
    InvalidCleanupJournal,
    #[error("profile root must be an absolute OS-account path")]
    InvalidRoot,
    #[error("public profile store operation failed")]
    Store(#[from] PublicStoreError),
    #[error("profile filesystem operation failed")]
    Io(#[from] std::io::Error),
}

fn ensure_private_directory(path: &Path) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory(&metadata, "profile directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "profile directory has no parent",
                )
            })?;
            let parent_metadata = fs::symlink_metadata(parent)?;
            if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(private_path_error(
                    "profile directory parent is not a real directory",
                ));
            }
            match fs::create_dir(path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            let metadata = fs::symlink_metadata(path)?;
            validate_private_directory(&metadata, "profile directory")
        }
        Err(error) => Err(error),
    }
}

fn path_present_no_follow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn validate_identity_directory_contents(directory: &Path) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() != "config.json" {
            return Err(private_path_error(
                "identity directory contains an unexpected artifact",
            ));
        }
        validate_private_file(&fs::symlink_metadata(entry.path())?, "profile config")?;
    }
    Ok(())
}

fn validate_public_root_contents(root: &Path) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path())?;
        match name.to_str() {
            Some("registry.json") => validate_private_file(&metadata, "public registry")?,
            Some("cleanup-journal.json") => validate_private_file(&metadata, "cleanup journal")?,
            Some("integrity-journal.json") => {
                validate_private_file(&metadata, "integrity journal")?
            }
            Some("identities") => {
                validate_private_directory(&metadata, "identities directory")?;
                if fs::read_dir(entry.path())?.next().transpose()?.is_some() {
                    return Err(private_path_error(
                        "identities directory is not empty during public purge",
                    ));
                }
            }
            _ => {
                return Err(private_path_error(
                    "profile root contains an unexpected artifact",
                ));
            }
        }
    }
    Ok(())
}

fn remove_known_file_if_present(path: &Path, kind: &str) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_file(&metadata, kind)?;
            fs::remove_file(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_private_directory(metadata: &fs::Metadata, kind: &str) -> Result<(), std::io::Error> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(private_path_error(&format!(
            "{kind} is not a real directory"
        )));
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o700, kind)?;
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata, kind: &str) -> Result<(), std::io::Error> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(private_path_error(&format!("{kind} is not a regular file")));
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o600, kind)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_metadata(
    metadata: &fs::Metadata,
    expected_mode: u32,
    kind: &str,
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(private_path_error(&format!(
            "{kind} must be owned by the current user with mode {expected_mode:o}"
        )));
    }
    Ok(())
}

fn private_path_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::{ProfileName, ProfileRepository, add_profile, rename_profile};
    use crate::public_store::PublicRegistry;

    const IDENTITY_ID: &str = "11111111111111111111111111111111";

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        make_private_directory(directory.path());
        directory
    }

    fn make_private_directory(path: &std::path::Path) {
        std::fs::create_dir_all(path).expect("create private directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("private directory permissions");
        }
    }

    fn write_private_file(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write private file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("private file permissions");
        }
    }

    fn identity_directory(root: &std::path::Path) -> std::path::PathBuf {
        let identities = root.join("identities");
        make_private_directory(&identities);
        let identity = identities.join(IDENTITY_ID);
        make_private_directory(&identity);
        identity
    }

    #[test]
    fn profile_names_are_cross_platform_safe() {
        assert!(ProfileName::parse("build-agent_1").is_ok());
        for invalid in ["../escape", "Build", "con", "nul", "a/b", ""] {
            assert!(ProfileName::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn aliases_are_decoupled_from_stable_identity_directories() {
        let root = tempfile::tempdir().expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let old = ProfileName::parse("old").expect("old");
        let new = ProfileName::parse("new").expect("new");
        let identity = "11111111111111111111111111111111";
        let registry = add_profile(
            &PublicRegistry::default(),
            &old,
            identity.to_owned(),
            "2026-07-13T00:00:00Z".to_owned(),
            None,
        )
        .expect("add");
        repository.save_registry(&registry).expect("save");
        let renamed = rename_profile(&registry, &old, &new).expect("rename");
        repository.save_registry(&renamed).expect("save rename");
        assert_eq!(renamed.agents[0].identity_id, identity);
        assert_eq!(renamed.agents[0].name, "new");
    }

    #[cfg(unix)]
    #[test]
    fn repository_refuses_a_symlinked_profile_root() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let parent = tempfile::tempdir().expect("parent");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private parent");
        let real = parent.path().join("real");
        std::fs::create_dir(&real).expect("real root");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))
            .expect("private real root");
        let linked = parent.path().join("linked");
        symlink(&real, &linked).expect("root symlink");
        let repository = ProfileRepository::new(linked).expect("repository shape");

        assert!(
            repository
                .save_registry(&PublicRegistry::default())
                .is_err()
        );
        assert!(!real.join("registry.json").exists());
    }

    #[test]
    fn identity_removal_deletes_only_the_known_config_and_empty_directory() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(root.path());
        write_private_file(&identity.join("config.json"), b"{}");

        repository
            .remove_identity_directory(IDENTITY_ID)
            .expect("remove identity directory");

        assert!(!identity.exists());
        assert!(root.path().join("identities").is_dir());
    }

    #[test]
    fn strict_config_presence_distinguishes_missing_and_valid_private_configs() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        assert!(
            !repository
                .config_exists_strict(IDENTITY_ID)
                .expect("missing config")
        );

        let identity = identity_directory(root.path());
        write_private_file(&identity.join("config.json"), b"{}");
        assert!(
            repository
                .config_exists_strict(IDENTITY_ID)
                .expect("valid config")
        );
    }

    #[test]
    fn strict_config_presence_rejects_a_nonregular_config() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(root.path());
        make_private_directory(&identity.join("config.json"));

        assert!(repository.config_exists_strict(IDENTITY_ID).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn strict_config_presence_rejects_symlinks_and_unsafe_parent_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let linked_root = private_tempdir();
        let linked_repository =
            ProfileRepository::new(linked_root.path().to_path_buf()).expect("repository");
        let real_identities = linked_root.path().join("real-identities");
        make_private_directory(&real_identities);
        symlink(&real_identities, linked_root.path().join("identities"))
            .expect("identities symlink");
        assert!(linked_repository.config_exists_strict(IDENTITY_ID).is_err());

        let weak_root = private_tempdir();
        let weak_repository =
            ProfileRepository::new(weak_root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(weak_root.path());
        write_private_file(&identity.join("config.json"), b"{}");
        std::fs::set_permissions(
            weak_root.path().join("identities"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("weaken identities permissions");
        assert!(weak_repository.config_exists_strict(IDENTITY_ID).is_err());
    }

    #[test]
    fn identity_removal_fails_closed_on_unexpected_contents() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(root.path());
        let config = identity.join("config.json");
        let unexpected = identity.join("unexpected.json");
        write_private_file(&config, b"{}");
        write_private_file(&unexpected, b"{}");

        assert!(repository.remove_identity_directory(IDENTITY_ID).is_err());
        assert!(config.exists(), "preflight must preserve the known config");
        assert!(unexpected.exists());
        assert!(identity.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn identity_removal_rejects_a_symlinked_config_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(root.path());
        let target = root.path().join("target.json");
        write_private_file(&target, b"protected");
        symlink(&target, identity.join("config.json")).expect("config symlink");

        assert!(repository.remove_identity_directory(IDENTITY_ID).is_err());
        assert_eq!(std::fs::read(&target).expect("target"), b"protected");
        assert!(identity.exists());
    }

    #[cfg(unix)]
    #[test]
    fn identity_removal_rejects_a_symlinked_identities_parent() {
        use std::os::unix::fs::symlink;

        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let real_identities = root.path().join("real-identities");
        let identity = real_identities.join(IDENTITY_ID);
        make_private_directory(&identity);
        let config = identity.join("config.json");
        write_private_file(&config, b"protected");
        symlink(&real_identities, root.path().join("identities")).expect("identities symlink");

        assert!(repository.remove_identity_directory(IDENTITY_ID).is_err());
        assert_eq!(std::fs::read(&config).expect("config target"), b"protected");
        assert!(identity.is_dir());
    }

    #[test]
    fn public_purge_removes_only_known_private_artifacts_and_empty_directories() {
        let root = private_tempdir();
        let root_path = root.path().to_path_buf();
        let repository = ProfileRepository::new(root_path.clone()).expect("repository");
        make_private_directory(&root_path.join("identities"));
        for name in [
            "registry.json",
            "cleanup-journal.json",
            "integrity-journal.json",
        ] {
            write_private_file(&root_path.join(name), b"{}");
        }

        repository.purge_public_data().expect("purge public data");

        assert!(!root_path.exists());
    }

    #[test]
    fn public_purge_fails_closed_before_deleting_an_unexpected_artifact() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let registry = root.path().join("registry.json");
        let unexpected = root.path().join("notes.txt");
        write_private_file(&registry, b"{}");
        write_private_file(&unexpected, b"do not delete");

        assert!(repository.purge_public_data().is_err());
        assert!(registry.exists(), "preflight must preserve known artifacts");
        assert_eq!(
            std::fs::read(&unexpected).expect("unexpected artifact"),
            b"do not delete"
        );
    }

    #[test]
    fn public_purge_rejects_a_nonempty_identities_directory() {
        let root = private_tempdir();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let identity = identity_directory(root.path());
        write_private_file(&identity.join("config.json"), b"{}");

        assert!(repository.purge_public_data().is_err());
        assert!(identity.join("config.json").exists());
    }
}
