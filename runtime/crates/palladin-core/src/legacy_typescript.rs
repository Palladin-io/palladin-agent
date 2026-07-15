use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profiles::ProfileName;
use crate::public_store::{is_opaque_id, load_json, save_json_atomic};

const CUTOVER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = ".palladin-typescript-cutover.json";
const CLEANUP_MARKER_FILE: &str = ".typescript-cutover-cleanup.json";
const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;
const LEGACY_FILE_NAMES: &[&str] = &[
    "config.json",
    "agent.key",
    "agent.pub",
    "signing.key",
    "signing.pub",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyTypeScriptProfile {
    pub legacy_name: String,
    pub native_name: String,
    pub identity_id: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyTypeScriptManifest {
    pub schema_version: u32,
    pub cutover_id: String,
    pub source_directory: String,
    pub default: String,
    pub profiles: Vec<LegacyTypeScriptProfile>,
}

impl LegacyTypeScriptManifest {
    pub fn validate(&self) -> Result<(), LegacyTypeScriptError> {
        if self.schema_version != CUTOVER_SCHEMA_VERSION
            || !is_cutover_id(&self.cutover_id)
            || !matches!(self.source_directory.as_str(), ".palladin" | ".claw-vault")
            || ProfileName::parse(&self.default).is_err()
            || self.profiles.is_empty()
        {
            return Err(LegacyTypeScriptError::InvalidManifest);
        }

        let legacy_names = self
            .profiles
            .iter()
            .map(|profile| profile.legacy_name.as_str())
            .collect::<BTreeSet<_>>();
        let native_names = self
            .profiles
            .iter()
            .map(|profile| profile.native_name.as_str())
            .collect::<BTreeSet<_>>();
        if legacy_names.len() != self.profiles.len()
            || native_names.len() != self.profiles.len()
            || !native_names.contains(self.default.as_str())
            || self.profiles.iter().any(|profile| {
                !is_legacy_profile_name(&profile.legacy_name)
                    || ProfileName::parse(&profile.native_name).is_err()
                    || profile.native_name != profile.legacy_name.to_ascii_lowercase()
                    || !is_opaque_id(&profile.identity_id)
                    || profile.agent_type.as_deref().is_some_and(|value| {
                        value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
                    })
            })
        {
            return Err(LegacyTypeScriptError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyTypeScriptStatus {
    Clear,
    Detected {
        source_directory: String,
        profiles: usize,
        file_fallback: bool,
    },
    CutoverPending(LegacyTypeScriptManifest),
}

#[derive(Clone, Debug)]
pub struct LegacyTypeScriptRepository {
    native_root: PathBuf,
    archive_root: PathBuf,
    cleanup_marker: PathBuf,
}

impl LegacyTypeScriptRepository {
    pub fn new(native_root: &Path) -> Result<Self, LegacyTypeScriptError> {
        if !native_root.is_absolute()
            || native_root.file_name().and_then(|value| value.to_str()) != Some(".palladin")
            || native_root.parent().is_none()
        {
            return Err(LegacyTypeScriptError::InvalidRoot);
        }
        let parent = native_root
            .parent()
            .ok_or(LegacyTypeScriptError::InvalidRoot)?;
        Ok(Self {
            native_root: native_root.to_path_buf(),
            archive_root: parent.join(".palladin-typescript-legacy"),
            cleanup_marker: native_root.join(CLEANUP_MARKER_FILE),
        })
    }

    #[must_use]
    pub fn archive_root(&self) -> &Path {
        &self.archive_root
    }

    pub fn status(&self) -> Result<LegacyTypeScriptStatus, LegacyTypeScriptError> {
        if path_exists_no_follow(&self.archive_root) || path_exists_no_follow(&self.cleanup_marker)
        {
            return Ok(LegacyTypeScriptStatus::CutoverPending(
                self.load_manifest()?,
            ));
        }
        let Some((source, inventory)) = self.discover_source()? else {
            return Ok(LegacyTypeScriptStatus::Clear);
        };
        Ok(LegacyTypeScriptStatus::Detected {
            source_directory: source
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(LegacyTypeScriptError::InvalidRoot)?
                .to_owned(),
            profiles: inventory.profiles.len(),
            file_fallback: inventory.file_fallback,
        })
    }

    /// Freezes the legacy TypeScript layout behind a same-filesystem atomic rename.
    ///
    /// Only the registry and file metadata are inspected. Legacy config and private-key
    /// contents are never opened. A manifest written before the rename makes the operation
    /// resumable if the process exits between any later native profile allocations.
    pub fn begin_cutover(
        &self,
        cutover_id: String,
    ) -> Result<LegacyTypeScriptManifest, LegacyTypeScriptError> {
        if path_exists_no_follow(&self.archive_root) || path_exists_no_follow(&self.cleanup_marker)
        {
            let manifest = self.load_manifest()?;
            if manifest.cutover_id != cutover_id {
                return Err(LegacyTypeScriptError::CutoverAlreadyPending);
            }
            return Ok(manifest);
        }
        let (source, inventory) = self
            .discover_source()?
            .ok_or(LegacyTypeScriptError::NotDetected)?;
        if path_exists_no_follow(&self.archive_root) {
            return Err(LegacyTypeScriptError::ArchiveAlreadyExists);
        }
        let manifest = LegacyTypeScriptManifest {
            schema_version: CUTOVER_SCHEMA_VERSION,
            cutover_id,
            source_directory: source
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(LegacyTypeScriptError::InvalidRoot)?
                .to_owned(),
            default: inventory.default,
            profiles: inventory.profiles,
        };
        manifest.validate()?;
        save_json_atomic(&source.join(MANIFEST_FILE), &manifest)?;
        fs::rename(&source, &self.archive_root)?;
        sync_parent(
            self.archive_root
                .parent()
                .ok_or(LegacyTypeScriptError::InvalidRoot)?,
        )?;
        Ok(manifest)
    }

    pub fn pending_manifest(
        &self,
    ) -> Result<Option<LegacyTypeScriptManifest>, LegacyTypeScriptError> {
        if path_exists_no_follow(&self.archive_root) || path_exists_no_follow(&self.cleanup_marker)
        {
            Ok(Some(self.load_manifest()?))
        } else {
            Ok(None)
        }
    }

    /// Persists the non-secret cutover plan in the new private native root.
    ///
    /// The second copy closes the final cleanup crash window: if the archive manifest has
    /// already been removed, a restart can still validate the exact plan and remove an empty
    /// archive before deleting this marker last.
    pub fn ensure_cleanup_marker(
        &self,
        manifest: &LegacyTypeScriptManifest,
    ) -> Result<(), LegacyTypeScriptError> {
        manifest.validate()?;
        if let Some(existing) = self.pending_marker()? {
            if existing != *manifest {
                return Err(LegacyTypeScriptError::InvalidManifest);
            }
            return Ok(());
        }
        save_json_atomic(&self.cleanup_marker, manifest)?;
        Ok(())
    }

    /// Removes only the frozen, allowlisted TypeScript layout.
    ///
    /// The complete tree is validated before the first deletion. Missing known files are
    /// accepted so a process interruption can be resumed, while unknown files and links stop
    /// cleanup without broad recursive removal.
    pub fn cleanup_archive(&self, expected_cutover_id: &str) -> Result<(), LegacyTypeScriptError> {
        let manifest = self.load_manifest()?;
        if manifest.cutover_id != expected_cutover_id {
            return Err(LegacyTypeScriptError::CutoverIdMismatch);
        }
        if path_exists_no_follow(&self.archive_root) {
            self.validate_archive_tree(&manifest)?;

            for name in LEGACY_FILE_NAMES {
                validate_private_directory(&self.archive_root)?;
                remove_private_file_if_present(&self.archive_root.join(name))?;
            }
            let agents = self.archive_root.join("agents");
            if path_exists_no_follow(&agents) {
                validate_private_directory(&self.archive_root)?;
                validate_private_directory(&agents)?;
                for profile in &manifest.profiles {
                    let directory = agents.join(&profile.legacy_name);
                    if path_exists_no_follow(&directory) {
                        for name in LEGACY_FILE_NAMES {
                            validate_private_directory(&agents)?;
                            validate_private_directory(&directory)?;
                            remove_private_file_if_present(&directory.join(name))?;
                        }
                        validate_private_directory(&agents)?;
                        validate_private_directory(&directory)?;
                        fs::remove_dir(directory)?;
                    }
                }
                validate_private_directory(&self.archive_root)?;
                validate_private_directory(&agents)?;
                fs::remove_dir(agents)?;
            }
            validate_private_directory(&self.archive_root)?;
            remove_private_file_if_present(&self.archive_root.join("registry.json"))?;
            validate_private_directory(&self.archive_root)?;
            remove_private_file_if_present(&self.archive_root.join(MANIFEST_FILE))?;
            validate_private_directory(&self.archive_root)?;
            fs::remove_dir(&self.archive_root)?;
            sync_parent(
                self.archive_root
                    .parent()
                    .ok_or(LegacyTypeScriptError::InvalidRoot)?,
            )?;
        }
        remove_private_file_if_present(&self.cleanup_marker)?;
        Ok(())
    }

    fn discover_source(&self) -> Result<Option<(PathBuf, LegacyInventory)>, LegacyTypeScriptError> {
        let parent = self
            .native_root
            .parent()
            .ok_or(LegacyTypeScriptError::InvalidRoot)?;
        let candidates = [self.native_root.clone(), parent.join(".claw-vault")];
        let mut detected = Vec::new();
        for candidate in candidates {
            if let Some(inventory) = inspect_legacy_root(&candidate)? {
                detected.push((candidate, inventory));
            }
        }
        match detected.len() {
            0 => Ok(None),
            1 => Ok(detected.pop()),
            _ => Err(LegacyTypeScriptError::AmbiguousSources),
        }
    }

    fn load_manifest(&self) -> Result<LegacyTypeScriptManifest, LegacyTypeScriptError> {
        let archive_manifest = self.archive_root.join(MANIFEST_FILE);
        let path = if path_exists_no_follow(&archive_manifest) {
            validate_private_directory(&self.archive_root)?;
            archive_manifest
        } else {
            self.cleanup_marker.clone()
        };
        let manifest: LegacyTypeScriptManifest = load_json(&path)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn pending_marker(&self) -> Result<Option<LegacyTypeScriptManifest>, LegacyTypeScriptError> {
        if !path_exists_no_follow(&self.cleanup_marker) {
            return Ok(None);
        }
        let manifest: LegacyTypeScriptManifest = load_json(&self.cleanup_marker)?;
        manifest.validate()?;
        Ok(Some(manifest))
    }

    fn validate_archive_tree(
        &self,
        manifest: &LegacyTypeScriptManifest,
    ) -> Result<(), LegacyTypeScriptError> {
        validate_private_directory(&self.archive_root)?;
        let known_profiles = manifest
            .profiles
            .iter()
            .map(|profile| profile.legacy_name.as_str())
            .collect::<BTreeSet<_>>();
        for entry in fs::read_dir(&self.archive_root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| LegacyTypeScriptError::UnexpectedArtifact)?;
            match name.as_str() {
                "registry.json" | MANIFEST_FILE => validate_private_file(&entry.path())?,
                "agents" => {
                    validate_private_directory(&entry.path())?;
                    for profile_entry in fs::read_dir(entry.path())? {
                        let profile_entry = profile_entry?;
                        let profile_name = profile_entry
                            .file_name()
                            .into_string()
                            .map_err(|_| LegacyTypeScriptError::UnexpectedArtifact)?;
                        if !known_profiles.contains(profile_name.as_str()) {
                            return Err(LegacyTypeScriptError::UnexpectedArtifact);
                        }
                        validate_legacy_profile_directory(&profile_entry.path())?;
                    }
                }
                value if LEGACY_FILE_NAMES.contains(&value) => {
                    validate_private_file(&entry.path())?;
                }
                _ => return Err(LegacyTypeScriptError::UnexpectedArtifact),
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LegacyInventory {
    default: String,
    profiles: Vec<LegacyTypeScriptProfile>,
    file_fallback: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeScriptRegistry {
    default: String,
    agents: Vec<TypeScriptAgent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TypeScriptAgent {
    name: String,
    created_at: String,
    #[serde(rename = "type")]
    agent_type: Option<String>,
}

fn inspect_legacy_root(path: &Path) -> Result<Option<LegacyInventory>, LegacyTypeScriptError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory_metadata(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }

    let registry_path = path.join("registry.json");
    let mut registry = None;
    if path_exists_no_follow(&registry_path) {
        validate_private_file(&registry_path)?;
        let bytes = read_bounded(&registry_path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value.get("schemaVersion").is_some() {
            return Ok(None);
        }
        registry = Some(serde_json::from_value::<TypeScriptRegistry>(value)?);
    }

    let flat_present = LEGACY_FILE_NAMES
        .iter()
        .any(|name| path_exists_no_follow(&path.join(name)));
    let agents_path = path.join("agents");
    let agents_present = path_exists_no_follow(&agents_path);
    if registry.is_none() && !flat_present && !agents_present {
        return Ok(None);
    }

    let registry_default = registry.as_ref().map(|value| value.default.clone());
    let mut raw_profiles = if let Some(registry) = registry {
        if registry.agents.is_empty()
            || !registry
                .agents
                .iter()
                .any(|profile| profile.name == registry.default)
        {
            return Err(LegacyTypeScriptError::InvalidRegistry);
        }
        registry
            .agents
            .into_iter()
            .map(|profile| {
                if profile.created_at.is_empty()
                    || profile.created_at.len() > 128
                    || profile.created_at.chars().any(char::is_control)
                {
                    return Err(LegacyTypeScriptError::InvalidRegistry);
                }
                Ok((profile.name, profile.agent_type))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if agents_present {
        let mut profiles = Vec::new();
        validate_private_directory(&agents_path)?;
        for entry in fs::read_dir(&agents_path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| LegacyTypeScriptError::InvalidRegistry)?;
            validate_legacy_profile_directory(&entry.path())?;
            profiles.push((name, None));
        }
        profiles.sort_by(|left, right| left.0.cmp(&right.0));
        profiles
    } else {
        vec![("default".to_owned(), None)]
    };

    if flat_present && !raw_profiles.iter().any(|(name, _)| name == "default") {
        raw_profiles.push(("default".to_owned(), None));
    }
    let registry_default = if let Some(default) = registry_default {
        default.to_ascii_lowercase()
    } else if raw_profiles.iter().any(|(name, _)| name == "default") {
        "default".to_owned()
    } else {
        raw_profiles
            .first()
            .map(|(name, _)| name.to_ascii_lowercase())
            .ok_or(LegacyTypeScriptError::InvalidRegistry)?
    };

    let mut legacy_names = BTreeSet::new();
    let mut native_names = BTreeSet::new();
    let mut profiles = Vec::with_capacity(raw_profiles.len());
    for (legacy_name, agent_type) in raw_profiles {
        let native_name = legacy_name.to_ascii_lowercase();
        if !is_legacy_profile_name(&legacy_name)
            || ProfileName::parse(&native_name).is_err()
            || !legacy_names.insert(legacy_name.clone())
            || !native_names.insert(native_name.clone())
        {
            return Err(LegacyTypeScriptError::InvalidRegistry);
        }
        let agent_type = agent_type
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        profiles.push(LegacyTypeScriptProfile {
            legacy_name,
            native_name,
            identity_id: generate_opaque_id()?,
            agent_type,
        });
    }
    if !native_names.contains(registry_default.as_str()) {
        return Err(LegacyTypeScriptError::InvalidRegistry);
    }

    validate_legacy_root_tree(path, &legacy_names)?;
    let file_fallback = LEGACY_FILE_NAMES.iter().any(|name| {
        matches!(*name, "agent.key" | "signing.key") && path_exists_no_follow(&path.join(name))
    }) || profiles.iter().any(|profile| {
        ["agent.key", "signing.key"].iter().any(|name| {
            path_exists_no_follow(&path.join("agents").join(&profile.legacy_name).join(name))
        })
    });
    Ok(Some(LegacyInventory {
        default: registry_default,
        profiles,
        file_fallback,
    }))
}

fn validate_legacy_root_tree(
    root: &Path,
    known_profiles: &BTreeSet<String>,
) -> Result<(), LegacyTypeScriptError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LegacyTypeScriptError::UnexpectedArtifact)?;
        match name.as_str() {
            "registry.json" | MANIFEST_FILE => validate_private_file(&entry.path())?,
            "agents" => {
                validate_private_directory(&entry.path())?;
                for profile_entry in fs::read_dir(entry.path())? {
                    let profile_entry = profile_entry?;
                    let profile_name = profile_entry
                        .file_name()
                        .into_string()
                        .map_err(|_| LegacyTypeScriptError::UnexpectedArtifact)?;
                    if !known_profiles.contains(&profile_name) {
                        return Err(LegacyTypeScriptError::UnexpectedArtifact);
                    }
                    validate_legacy_profile_directory(&profile_entry.path())?;
                }
            }
            value if LEGACY_FILE_NAMES.contains(&value) => validate_private_file(&entry.path())?,
            _ => return Err(LegacyTypeScriptError::UnexpectedArtifact),
        }
    }
    Ok(())
}

fn validate_legacy_profile_directory(path: &Path) -> Result<(), LegacyTypeScriptError> {
    validate_private_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LegacyTypeScriptError::UnexpectedArtifact)?;
        if !LEGACY_FILE_NAMES.contains(&name.as_str()) {
            return Err(LegacyTypeScriptError::UnexpectedArtifact);
        }
        validate_private_file(&entry.path())?;
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, LegacyTypeScriptError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_private_file_metadata(&metadata)?;
    if metadata.len() > MAX_REGISTRY_BYTES {
        return Err(LegacyTypeScriptError::RegistryTooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REGISTRY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(LegacyTypeScriptError::RegistryTooLarge);
    }
    Ok(bytes)
}

fn is_legacy_profile_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_cutover_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn generate_opaque_id() -> Result<String, LegacyTypeScriptError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| LegacyTypeScriptError::RandomGenerationFailed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(output)
}

fn path_exists_no_follow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn validate_private_directory(path: &Path) -> Result<(), LegacyTypeScriptError> {
    validate_private_directory_metadata(&fs::symlink_metadata(path)?)
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
) -> Result<(), LegacyTypeScriptError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(LegacyTypeScriptError::UnsafePath);
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o700)?;
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<(), LegacyTypeScriptError> {
    validate_private_file_metadata(&fs::symlink_metadata(path)?)
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), LegacyTypeScriptError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(LegacyTypeScriptError::UnsafePath);
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_metadata(
    metadata: &fs::Metadata,
    expected_mode: u32,
) -> Result<(), LegacyTypeScriptError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(LegacyTypeScriptError::UnsafePath);
    }
    Ok(())
}

fn remove_private_file_if_present(path: &Path) -> Result<(), LegacyTypeScriptError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_private_file(path)?;
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), LegacyTypeScriptError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), LegacyTypeScriptError> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum LegacyTypeScriptError {
    #[error("legacy TypeScript root is invalid")]
    InvalidRoot,
    #[error("legacy TypeScript registry is invalid or contains ambiguous profile aliases")]
    InvalidRegistry,
    #[error("legacy TypeScript registry exceeds the 1 MiB safety limit")]
    RegistryTooLarge,
    #[error("legacy TypeScript layout contains an unsafe path, owner, or permission mode")]
    UnsafePath,
    #[error("legacy TypeScript layout contains an unexpected artifact; nothing was removed")]
    UnexpectedArtifact,
    #[error("both .palladin and .claw-vault legacy roots exist; resolve the ambiguity manually")]
    AmbiguousSources,
    #[error("legacy TypeScript data was not detected")]
    NotDetected,
    #[error("a legacy TypeScript archive already exists")]
    ArchiveAlreadyExists,
    #[error("another legacy cutover is already pending")]
    CutoverAlreadyPending,
    #[error("legacy cutover manifest is invalid")]
    InvalidManifest,
    #[error("legacy cutover confirmation identifier does not match")]
    CutoverIdMismatch,
    #[error("legacy TypeScript filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("legacy TypeScript metadata JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("secure random cutover identifier generation failed")]
    RandomGenerationFailed,
    #[error("legacy TypeScript public-store operation failed")]
    Store(#[from] crate::public_store::PublicStoreError),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        CLEANUP_MARKER_FILE, LEGACY_FILE_NAMES, LegacyTypeScriptError, LegacyTypeScriptRepository,
        LegacyTypeScriptStatus, MANIFEST_FILE,
    };

    fn private_directory(path: &std::path::Path) {
        fs::create_dir_all(path).expect("directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
    }

    fn private_file(path: &std::path::Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        LegacyTypeScriptRepository,
    ) {
        let home = tempfile::tempdir().expect("home");
        private_directory(home.path());
        let root = home.path().join(".palladin");
        private_directory(&root);
        let agents = root.join("agents");
        private_directory(&agents);
        for name in ["Default", "build"] {
            let profile = agents.join(name);
            private_directory(&profile);
            private_file(&profile.join("config.json"), b"must-not-be-read");
        }
        private_file(
            &root.join("registry.json"),
            br#"{"default":"Default","agents":[{"name":"Default","createdAt":"2026-01-01T00:00:00Z"},{"name":"build","createdAt":"2026-01-01T00:00:00Z","type":"ci"}]}"#,
        );
        let repository = LegacyTypeScriptRepository::new(&root).expect("repository");
        (home, root, repository)
    }

    #[test]
    fn detects_and_archives_multiple_profiles_without_opening_configs() {
        let (_home, root, repository) = fixture();
        assert!(matches!(
            repository.status().expect("status"),
            LegacyTypeScriptStatus::Detected { profiles: 2, .. }
        ));
        let id = "11111111111111111111111111111111".to_owned();
        let manifest = repository.begin_cutover(id.clone()).expect("cutover");
        assert!(!root.exists());
        assert_eq!(manifest.default, "default");
        assert_eq!(manifest.profiles[0].legacy_name, "Default");
        assert_eq!(manifest.profiles[0].native_name, "default");
        assert_eq!(repository.begin_cutover(id).expect("resume"), manifest);
    }

    #[test]
    fn cleanup_is_allowlisted_and_resumable() {
        let (_home, _root, repository) = fixture();
        let id = "22222222222222222222222222222222".to_owned();
        repository.begin_cutover(id.clone()).expect("cutover");
        fs::remove_file(repository.archive_root().join("agents/build/config.json"))
            .expect("simulate interrupted deletion");
        repository.cleanup_archive(&id).expect("cleanup");
        assert!(!repository.archive_root().exists());
    }

    #[test]
    fn cleanup_marker_recovers_the_final_empty_archive_window() {
        let (_home, root, repository) = fixture();
        let id = "55555555555555555555555555555555".to_owned();
        let manifest = repository.begin_cutover(id.clone()).expect("cutover");
        private_directory(&root);
        repository
            .ensure_cleanup_marker(&manifest)
            .expect("cleanup marker");

        for profile in &manifest.profiles {
            let directory = repository
                .archive_root()
                .join("agents")
                .join(&profile.legacy_name);
            for name in LEGACY_FILE_NAMES {
                let path = directory.join(name);
                if path.exists() {
                    fs::remove_file(path).expect("remove profile file");
                }
            }
            fs::remove_dir(directory).expect("remove profile directory");
        }
        fs::remove_dir(repository.archive_root().join("agents")).expect("remove agents");
        fs::remove_file(repository.archive_root().join("registry.json")).expect("registry");
        fs::remove_file(repository.archive_root().join(MANIFEST_FILE)).expect("manifest");

        assert!(matches!(
            repository.status().expect("pending status"),
            LegacyTypeScriptStatus::CutoverPending(_)
        ));
        repository.cleanup_archive(&id).expect("finish cleanup");
        assert!(!repository.archive_root().exists());
        assert!(!root.join(CLEANUP_MARKER_FILE).exists());
    }

    #[test]
    fn cleanup_refuses_unknown_artifacts_before_deleting_known_files() {
        let (_home, _root, repository) = fixture();
        let id = "33333333333333333333333333333333".to_owned();
        repository.begin_cutover(id.clone()).expect("cutover");
        private_file(&repository.archive_root().join("unknown.txt"), b"preserve");
        assert!(matches!(
            repository.cleanup_archive(&id),
            Err(LegacyTypeScriptError::UnexpectedArtifact)
        ));
        assert!(repository.archive_root().join(MANIFEST_FILE).exists());
        assert!(repository.archive_root().join("unknown.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let (home, _root, repository) = fixture();
        let id = "44444444444444444444444444444444".to_owned();
        repository.begin_cutover(id.clone()).expect("cutover");
        let target = home.path().join("outside");
        private_file(&target, b"preserve");
        symlink(
            &target,
            repository.archive_root().join("agents/build/agent.key"),
        )
        .expect("symlink");

        assert!(repository.cleanup_archive(&id).is_err());
        assert_eq!(fs::read(&target).expect("target"), b"preserve");
        assert!(repository.archive_root().join(MANIFEST_FILE).exists());
    }

    #[test]
    fn native_registry_is_not_misclassified_as_typescript() {
        let home = tempfile::tempdir().expect("home");
        private_directory(home.path());
        let root = home.path().join(".palladin");
        private_directory(&root);
        private_file(
            &root.join("registry.json"),
            br#"{"schemaVersion":3,"default":"default","agents":[]}"#,
        );
        let repository = LegacyTypeScriptRepository::new(&root).expect("repository");
        assert_eq!(
            repository.status().expect("status"),
            LegacyTypeScriptStatus::Clear
        );
    }
}
