use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry, PublicStoreError,
    is_opaque_id, is_profile_name, load_json, load_profile_config, load_registry, save_json_atomic,
    save_profile_config, save_registry,
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
        if !path.exists() {
            return Ok(PublicRegistry::default());
        }
        Ok(load_registry(&path)?)
    }

    pub fn save_registry(&self, registry: &PublicRegistry) -> Result<(), ProfileError> {
        ensure_private_directory(&self.root)?;
        Ok(save_registry(&self.root.join("registry.json"), registry)?)
    }

    pub fn acquire_transaction_lock(&self) -> Result<TransactionLock, ProfileError> {
        let path = self.transaction_lock_path()?;
        let parent = path.parent().ok_or(ProfileError::InvalidRoot)?;
        fs::create_dir_all(parent)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
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

    #[must_use]
    pub fn config_exists(&self, identity_id: &str) -> bool {
        self.config_path(identity_id)
            .is_ok_and(|path| path.exists())
    }

    pub fn remove_identity_directory(&self, identity_id: &str) -> Result<(), ProfileError> {
        let directory = self.identity_directory(identity_id)?;
        if directory.exists() {
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    pub fn purge_public_data(&self) -> Result<(), ProfileError> {
        if self.root.exists() {
            fs::remove_dir_all(&self.root)?;
        }
        Ok(())
    }

    pub fn load_cleanup_journal(&self) -> Result<CleanupJournal, ProfileError> {
        let path = self.cleanup_journal_path();
        if !path.exists() {
            return Ok(CleanupJournal::default());
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
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn cleanup_pending(&self) -> bool {
        self.cleanup_journal_path().exists()
    }

    #[must_use]
    pub fn legacy_artifacts_present(&self) -> bool {
        ["config.json", "agent.key", "agent.pub", "signing.key"]
            .iter()
            .any(|name| self.root.join(name).exists())
            || self.root.join("agents").exists()
            || (self.root.join("registry.json").exists() && self.load_registry().is_err())
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
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProfileName, ProfileRepository, add_profile, rename_profile};
    use crate::public_store::PublicRegistry;

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
}
