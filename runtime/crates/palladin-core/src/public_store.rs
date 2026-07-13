use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::host::ApiHost;

pub const PUBLIC_SCHEMA_VERSION: u32 = 3;

const REGISTRY_DIGEST_DOMAIN: &[u8] = b"palladin.public-registry.v3\0";
const PROFILE_CONFIG_DIGEST_DOMAIN: &[u8] = b"palladin.public-profile-config.v3\0";
const PROFILE_BINDING_DOMAIN: &[u8] = b"palladin.profile-binding.v1\0";
const SHA256_HEX_LENGTH: usize = 64;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const X25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicAgentEntry {
    pub name: String,
    pub identity_id: String,
    pub created_at: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicRegistry {
    pub schema_version: u32,
    pub default: String,
    pub agents: Vec<PublicAgentEntry>,
}

impl Default for PublicRegistry {
    fn default() -> Self {
        Self {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: "default".to_owned(),
            agents: Vec::new(),
        }
    }
}

impl PublicRegistry {
    fn validate(&self) -> Result<(), PublicStoreError> {
        if self.schema_version != PUBLIC_SCHEMA_VERSION
            || !is_profile_name(&self.default)
            || self.agents.iter().any(|agent| {
                !is_profile_name(&agent.name)
                    || !is_opaque_id(&agent.identity_id)
                    || !is_safe_public_text(&agent.created_at, 128)
                    || agent
                        .agent_type
                        .as_deref()
                        .is_some_and(|value| !is_safe_public_text(value, 128))
                    || agent
                        .config_digest
                        .as_deref()
                        .is_some_and(|value| !is_sha256_hex(value))
            })
        {
            return Err(PublicStoreError::InvalidPublicData);
        }

        let names = self
            .agents
            .iter()
            .map(|agent| agent.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let identity_ids = self
            .agents
            .iter()
            .map(|agent| agent.identity_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if names.len() != self.agents.len()
            || identity_ids.len() != self.agents.len()
            || (!self.agents.is_empty() && !names.contains(self.default.as_str()))
        {
            return Err(PublicStoreError::InvalidPublicData);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicProfileConfig {
    pub schema_version: u32,
    pub identity_id: String,
    pub host: String,
    pub organization_credential_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_organization_credential_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
    pub binding_signature: String,
}

/// Read-only representation used by the explicit pre-production v2 -> v3 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyPublicAgentEntryV2 {
    pub name: String,
    pub identity_id: String,
    pub created_at: String,
    #[serde(rename = "type")]
    pub agent_type: Option<String>,
}

/// Read-only representation used by the explicit pre-production v2 -> v3 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyPublicRegistryV2 {
    pub schema_version: u32,
    pub default: String,
    pub agents: Vec<LegacyPublicAgentEntryV2>,
}

/// Read-only representation used by the explicit pre-production v2 -> v3 migration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyPublicProfileConfigV2 {
    pub schema_version: u32,
    pub host: String,
    pub organization_credential_id: String,
    #[serde(default)]
    pub retired_organization_credential_ids: Vec<String>,
    pub agent_id: Option<String>,
    pub encryption_public_key: Option<String>,
    pub signing_public_key: Option<String>,
}

impl PublicProfileConfig {
    fn validate(&self) -> Result<(), PublicStoreError> {
        self.validate_binding_fields()?;
        if !is_canonical_base64(&self.binding_signature, ED25519_SIGNATURE_BYTES) {
            return Err(PublicStoreError::InvalidPublicData);
        }
        Ok(())
    }

    fn validate_binding_fields(&self) -> Result<(), PublicStoreError> {
        if self.schema_version != PUBLIC_SCHEMA_VERSION
            || !is_opaque_id(&self.identity_id)
            || !is_opaque_id(&self.organization_credential_id)
            || self
                .retired_organization_credential_ids
                .iter()
                .any(|value| !is_opaque_id(value) || value == &self.organization_credential_id)
            || self
                .retired_organization_credential_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.retired_organization_credential_ids.len()
            || self
                .agent_id
                .as_deref()
                .is_some_and(|value| !is_safe_public_text(value, 256))
            || !valid_optional_public_key(
                self.encryption_public_key.as_deref(),
                X25519_PUBLIC_KEY_BYTES,
            )
            || !valid_optional_public_key(
                self.signing_public_key.as_deref(),
                ED25519_PUBLIC_KEY_BYTES,
            )
        {
            return Err(PublicStoreError::InvalidPublicData);
        }

        if self.encryption_public_key.is_none() || self.signing_public_key.is_none() {
            return Err(PublicStoreError::InvalidPublicData);
        }

        ApiHost::parse(&self.host).map_err(|_| PublicStoreError::InvalidPublicData)?;

        Ok(())
    }
}

impl LegacyPublicRegistryV2 {
    fn validate(&self) -> Result<(), PublicStoreError> {
        if self.schema_version != 2
            || !is_profile_name(&self.default)
            || self
                .agents
                .iter()
                .any(|agent| !is_profile_name(&agent.name) || !is_opaque_id(&agent.identity_id))
        {
            return Err(PublicStoreError::InvalidPublicData);
        }
        let names = self
            .agents
            .iter()
            .map(|agent| agent.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let identities = self
            .agents
            .iter()
            .map(|agent| agent.identity_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if names.len() != self.agents.len()
            || identities.len() != self.agents.len()
            || (!self.agents.is_empty() && !names.contains(self.default.as_str()))
        {
            return Err(PublicStoreError::InvalidPublicData);
        }
        Ok(())
    }
}

impl LegacyPublicProfileConfigV2 {
    fn validate(&self) -> Result<(), PublicStoreError> {
        if self.schema_version != 2
            || !is_opaque_id(&self.organization_credential_id)
            || self
                .retired_organization_credential_ids
                .iter()
                .any(|value| !is_opaque_id(value) || value == &self.organization_credential_id)
            || self
                .retired_organization_credential_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.retired_organization_credential_ids.len()
            || !legacy_host_is_valid(&self.host)
        {
            return Err(PublicStoreError::InvalidPublicData);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PublicStoreError {
    #[error("public store I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("public store contains invalid JSON or an unsupported field")]
    Json(#[from] serde_json::Error),
    #[error("public store contains invalid public data")]
    InvalidPublicData,
    #[error("atomic public store persistence failed")]
    Persist,
}

pub fn load_registry(path: &Path) -> Result<PublicRegistry, PublicStoreError> {
    let registry: PublicRegistry = load_json(path)?;
    registry.validate()?;
    Ok(registry)
}

pub fn save_registry(path: &Path, registry: &PublicRegistry) -> Result<(), PublicStoreError> {
    registry.validate()?;
    save_json_atomic(path, registry)
}

pub fn load_profile_config(path: &Path) -> Result<PublicProfileConfig, PublicStoreError> {
    let config: PublicProfileConfig = load_json(path)?;
    config.validate()?;
    Ok(config)
}

pub fn save_profile_config(
    path: &Path,
    config: &PublicProfileConfig,
) -> Result<(), PublicStoreError> {
    config.validate()?;
    save_json_atomic(path, config)
}

pub fn load_legacy_registry_v2(path: &Path) -> Result<LegacyPublicRegistryV2, PublicStoreError> {
    let registry: LegacyPublicRegistryV2 = load_json(path)?;
    registry.validate()?;
    Ok(registry)
}

pub fn load_legacy_profile_config_v2(
    path: &Path,
) -> Result<LegacyPublicProfileConfigV2, PublicStoreError> {
    let config: LegacyPublicProfileConfigV2 = load_json(path)?;
    config.validate()?;
    Ok(config)
}

/// Returns the stable SHA-256 commitment for every security-relevant registry field.
///
/// The encoding is domain-separated and length-prefixed. It deliberately does not hash the
/// serialized JSON representation, so whitespace and object-key ordering cannot change the
/// commitment.
pub fn registry_digest(registry: &PublicRegistry) -> Result<String, PublicStoreError> {
    registry.validate()?;
    let mut digest = CanonicalDigest::new(REGISTRY_DIGEST_DOMAIN);
    digest.u32(registry.schema_version);
    digest.text(&registry.default);
    digest.u64(registry.agents.len() as u64);
    for agent in &registry.agents {
        digest.text(&agent.name);
        digest.text(&agent.identity_id);
        digest.text(&agent.created_at);
        digest.optional_text(agent.agent_type.as_deref());
        digest.optional_text(agent.config_digest.as_deref());
    }
    Ok(digest.finish())
}

/// Returns the stable SHA-256 commitment for the complete public profile configuration,
/// including its identity binding and Ed25519 binding signature.
pub fn profile_config_digest(config: &PublicProfileConfig) -> Result<String, PublicStoreError> {
    config.validate()?;
    let mut digest = CanonicalDigest::new(PROFILE_CONFIG_DIGEST_DOMAIN);
    digest.u32(config.schema_version);
    digest.text(&config.identity_id);
    digest.text(&config.host);
    digest.text(&config.organization_credential_id);
    digest.u64(config.retired_organization_credential_ids.len() as u64);
    for retired in &config.retired_organization_credential_ids {
        digest.text(retired);
    }
    digest.optional_text(config.agent_id.as_deref());
    digest.optional_text(config.encryption_public_key.as_deref());
    digest.optional_text(config.signing_public_key.as_deref());
    digest.text(&config.binding_signature);
    Ok(digest.finish())
}

/// Canonical bytes signed by the Agent's Ed25519 private identity.
///
/// Every trust-tuple field is included. The signature itself is the sole excluded field, avoiding
/// a circular signing input.
pub fn profile_binding_bytes(config: &PublicProfileConfig) -> Result<Vec<u8>, PublicStoreError> {
    config.validate_binding_fields()?;
    let mut bytes = CanonicalBytes::new(PROFILE_BINDING_DOMAIN);
    bytes.u32(config.schema_version);
    bytes.text(&config.identity_id);
    bytes.text(&config.host);
    bytes.text(&config.organization_credential_id);
    bytes.u64(config.retired_organization_credential_ids.len() as u64);
    for retired in &config.retired_organization_credential_ids {
        bytes.text(retired);
    }
    bytes.optional_text(config.agent_id.as_deref());
    bytes.optional_text(config.encryption_public_key.as_deref());
    bytes.optional_text(config.signing_public_key.as_deref());
    Ok(bytes.finish())
}

pub(crate) fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, PublicStoreError> {
    validate_private_parent(path)?;
    let file = open_regular_file_no_follow(path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub(crate) fn save_json_atomic<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), PublicStoreError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "store path has no parent")
    })?;
    validate_private_parent(path)?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_file_metadata(&metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut temporary = NamedTempFile::new_in(parent)?;
    set_private_permissions(temporary.as_file())?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|_| PublicStoreError::Persist)?;
    validate_private_file(path)?;
    sync_parent(parent)?;
    Ok(())
}

struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self(digest)
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn text(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.0.update(value.as_bytes());
    }

    fn optional_text(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.0.update([1]);
                self.text(value);
            }
            None => self.0.update([0]),
        }
    }

    fn finish(self) -> String {
        let bytes = self.0.finalize();
        let mut encoded = String::with_capacity(SHA256_HEX_LENGTH);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }
}

struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    fn new(domain: &[u8]) -> Self {
        Self(domain.to_vec())
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn text(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
    }

    fn optional_text(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.0.push(1);
                self.text(value);
            }
            None => self.0.push(0),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

fn is_safe_public_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_optional_public_key(value: Option<&str>, expected_bytes: usize) -> bool {
    value.is_none_or(|value| is_canonical_base64(value, expected_bytes))
}

fn is_canonical_base64(value: &str, expected_bytes: usize) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == expected_bytes && STANDARD.encode(decoded) == value)
}

fn legacy_host_is_valid(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            let host = host.to_ascii_lowercase();
            host == "localhost"
                || host.ends_with(".localhost")
                || host == "127.0.0.1"
                || matches!(host.as_str(), "::1" | "[::1]")
        });
    (url.scheme() == "https" || local_http)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some()
}

fn validate_private_parent(path: &Path) -> Result<(), PublicStoreError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "store path has no parent")
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(private_path_error("public store parent is not a real directory").into());
    }
    validate_private_directory_metadata(&metadata)?;
    Ok(())
}

fn open_regular_file_no_follow(path: &Path) -> Result<File, PublicStoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    validate_private_file_metadata(&file.metadata()?)?;
    Ok(file)
}

fn validate_private_file(path: &Path) -> Result<(), PublicStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&metadata)
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), PublicStoreError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(private_path_error("public store file is not a regular file").into());
    }
    #[cfg(unix)]
    validate_unix_metadata(metadata, 0o600, "public store file")?;
    Ok(())
}

fn validate_private_directory_metadata(_metadata: &fs::Metadata) -> Result<(), PublicStoreError> {
    #[cfg(unix)]
    validate_unix_metadata(_metadata, 0o700, "public store directory")?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_metadata(
    metadata: &fs::Metadata,
    expected_mode: u32,
    kind: &str,
) -> Result<(), PublicStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(private_path_error(&format!(
            "{kind} must be owned by the current user with mode {expected_mode:o}"
        ))
        .into());
    }
    Ok(())
}

fn private_path_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

pub fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && !matches!(
            name.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

pub fn is_opaque_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &File) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?
        .sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::{
        PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
        load_profile_config, load_registry, profile_binding_bytes, profile_config_digest,
        registry_digest, save_profile_config, save_registry,
    };

    fn fixture_config(host: &str) -> PublicProfileConfig {
        PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host: host.to_owned(),
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some("agent-public-id".to_owned()),
            encryption_public_key: Some(
                base64::engine::general_purpose::STANDARD.encode([3_u8; 32]),
            ),
            signing_public_key: Some(base64::engine::general_purpose::STANDARD.encode([5_u8; 32])),
            binding_signature: base64::engine::general_purpose::STANDARD.encode([7_u8; 64]),
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private tempdir");
        }
        directory
    }

    #[test]
    fn round_trips_public_registry_without_secret_fields() {
        let directory = private_tempdir();
        let path = directory.path().join("registry.json");
        let registry = PublicRegistry {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: "build".to_owned(),
            agents: vec![PublicAgentEntry {
                name: "build".to_owned(),
                identity_id: "11111111111111111111111111111111".to_owned(),
                created_at: "2026-07-12T00:00:00Z".to_owned(),
                agent_type: Some("coding".to_owned()),
                config_digest: Some("a".repeat(64)),
            }],
        };

        save_registry(&path, &registry).expect("save registry");
        let serialized = std::fs::read_to_string(&path).expect("read registry");
        assert!(!serialized.to_ascii_lowercase().contains("apikey"));
        assert!(!serialized.to_ascii_lowercase().contains("privatekey"));
        assert_eq!(load_registry(&path).expect("load registry"), registry);

        let replacement = PublicRegistry::default();
        save_registry(&path, &replacement).expect("atomically replace registry");
        assert_eq!(
            load_registry(&path).expect("load replaced registry"),
            replacement
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path)
                .expect("registry metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn rejects_unknown_fields_in_public_registry() {
        let directory = private_tempdir();
        let path = directory.path().join("registry.json");
        std::fs::write(
            &path,
            r#"{"schemaVersion":1,"default":"default","agents":[],"apiKey":"forbidden"}"#,
        )
        .expect("write invalid fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("private fixture");
        }

        let error = load_registry(&path).expect_err("unknown field must fail");
        assert!(error.to_string().contains("invalid JSON"));
    }

    #[test]
    fn rejects_credentials_inside_public_host() {
        let directory = private_tempdir();
        let path = directory.path().join("config.json");
        let config = fixture_config("https://user:synthetic-password@example.test");

        let error = save_profile_config(&path, &config).expect_err("credential URL must fail");
        assert!(error.to_string().contains("invalid public data"));
        assert!(!path.exists());
    }

    #[cfg(feature = "local-development")]
    #[test]
    fn allows_cleartext_only_for_local_development() {
        for host in ["http://127.0.0.1:5000", "http://[::1]:5000"] {
            let directory = private_tempdir();
            let config = fixture_config(host);
            save_profile_config(&directory.path().join("config.json"), &config)
                .expect("local HTTP must be accepted");
        }
    }

    #[test]
    fn rejects_cleartext_remote_hosts() {
        for host in [
            "http://api.palladin.io",
            "http://192.168.1.10:5000",
            "http://notlocalhost.io",
            "http://localhost:5000",
            "http://api.dev.localhost:5000",
            "https://attacker.test",
        ] {
            let directory = private_tempdir();
            let config = fixture_config(host);
            save_profile_config(&directory.path().join("config.json"), &config)
                .expect_err("remote HTTP must be rejected");
        }
    }

    #[test]
    fn round_trips_valid_public_profile_config() {
        let directory = private_tempdir();
        let path = directory.path().join("config.json");
        let config = fixture_config("https://api.palladin.io");

        save_profile_config(&path, &config).expect("save public config");
        assert_eq!(
            load_profile_config(&path).expect("load public config"),
            config
        );
    }

    #[test]
    fn canonical_commitments_change_for_every_bound_field() {
        type ConfigMutation = (&'static str, Box<dyn Fn(&mut PublicProfileConfig)>);
        type RegistryMutation = (&'static str, Box<dyn Fn(&mut PublicRegistry)>);

        let config = fixture_config("https://api.palladin.io");
        let original_binding = profile_binding_bytes(&config).expect("binding");
        let original_digest = profile_config_digest(&config).expect("config digest");
        let mut mutations: Vec<ConfigMutation> = vec![
            (
                "identityId",
                Box::new(|value| value.identity_id = "33333333333333333333333333333333".to_owned()),
            ),
            (
                "organizationCredentialId",
                Box::new(|value| {
                    value.organization_credential_id =
                        "44444444444444444444444444444444".to_owned();
                }),
            ),
            (
                "retiredOrganizationCredentialIds",
                Box::new(|value| {
                    value.retired_organization_credential_ids =
                        vec!["55555555555555555555555555555555".to_owned()];
                }),
            ),
            (
                "agentId",
                Box::new(|value| value.agent_id = Some("different-agent".to_owned())),
            ),
            (
                "encryptionPublicKey",
                Box::new(|value| {
                    value.encryption_public_key =
                        Some(base64::engine::general_purpose::STANDARD.encode([8_u8; 32]));
                }),
            ),
            (
                "signingPublicKey",
                Box::new(|value| {
                    value.signing_public_key =
                        Some(base64::engine::general_purpose::STANDARD.encode([9_u8; 32]));
                }),
            ),
        ];
        #[cfg(feature = "local-development")]
        mutations.push((
            "host",
            Box::new(|value| value.host = "http://127.0.0.1:5001".to_owned()),
        ));
        for (field, mutation) in mutations.drain(..) {
            let mut changed = config.clone();
            mutation(&mut changed);
            assert_ne!(
                profile_binding_bytes(&changed).expect(field),
                original_binding,
                "binding omitted {field}"
            );
            assert_ne!(
                profile_config_digest(&changed).expect(field),
                original_digest,
                "config digest omitted {field}"
            );
        }

        let mut changed = config.clone();
        changed.binding_signature = base64::engine::general_purpose::STANDARD.encode([8_u8; 64]);
        assert_eq!(
            profile_binding_bytes(&changed).expect("signature excluded"),
            original_binding
        );
        assert_ne!(
            profile_config_digest(&changed).expect("signature included"),
            original_digest
        );

        let registry = PublicRegistry {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: "build".to_owned(),
            agents: vec![PublicAgentEntry {
                name: "build".to_owned(),
                identity_id: config.identity_id.clone(),
                created_at: "2026-07-13T00:00:00Z".to_owned(),
                agent_type: Some("coding".to_owned()),
                config_digest: Some(original_digest),
            }],
        };
        let original_registry = registry_digest(&registry).expect("registry digest");
        let registry_mutations: Vec<RegistryMutation> = vec![
            (
                "default",
                Box::new(|value| {
                    value.agents.push(PublicAgentEntry {
                        name: "deploy".to_owned(),
                        identity_id: "66666666666666666666666666666666".to_owned(),
                        created_at: "2026-07-14T00:00:00Z".to_owned(),
                        agent_type: None,
                        config_digest: None,
                    });
                    value.default = "deploy".to_owned();
                }),
            ),
            (
                "name",
                Box::new(|value| {
                    value.agents[0].name = "builder".to_owned();
                    value.default = "builder".to_owned();
                }),
            ),
            (
                "identityId",
                Box::new(|value| {
                    value.agents[0].identity_id = "77777777777777777777777777777777".to_owned();
                }),
            ),
            (
                "createdAt",
                Box::new(|value| {
                    value.agents[0].created_at = "2026-07-15T00:00:00Z".to_owned();
                }),
            ),
            (
                "type",
                Box::new(|value| value.agents[0].agent_type = Some("deploy".to_owned())),
            ),
            (
                "configDigest",
                Box::new(|value| value.agents[0].config_digest = Some("b".repeat(64))),
            ),
            (
                "agents",
                Box::new(|value| {
                    value.agents.push(PublicAgentEntry {
                        name: "deploy".to_owned(),
                        identity_id: "88888888888888888888888888888888".to_owned(),
                        created_at: "2026-07-16T00:00:00Z".to_owned(),
                        agent_type: None,
                        config_digest: None,
                    });
                }),
            ),
        ];
        for (field, mutation) in registry_mutations {
            let mut changed = registry.clone();
            mutation(&mut changed);
            assert_ne!(
                registry_digest(&changed).expect(field),
                original_registry,
                "registry digest omitted {field}"
            );
        }

        let mut ordered = registry.clone();
        ordered.agents.push(PublicAgentEntry {
            name: "deploy".to_owned(),
            identity_id: "99999999999999999999999999999999".to_owned(),
            created_at: "2026-07-17T00:00:00Z".to_owned(),
            agent_type: None,
            config_digest: None,
        });
        let ordered_digest = registry_digest(&ordered).expect("ordered registry");
        ordered.agents.reverse();
        assert_ne!(
            registry_digest(&ordered).expect("reordered registry"),
            ordered_digest,
            "registry digest omitted agent ordering"
        );

        let mut invalid_schema = config;
        invalid_schema.schema_version = PUBLIC_SCHEMA_VERSION - 1;
        assert!(profile_binding_bytes(&invalid_schema).is_err());
        let mut invalid_registry_schema = registry;
        invalid_registry_schema.schema_version = PUBLIC_SCHEMA_VERSION - 1;
        assert!(registry_digest(&invalid_registry_schema).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_and_overly_permissive_public_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = private_tempdir();
        let real = directory.path().join("real-registry.json");
        save_registry(&real, &PublicRegistry::default()).expect("save real registry");

        let linked = directory.path().join("linked-registry.json");
        symlink(&real, &linked).expect("symlink fixture");
        assert!(load_registry(&linked).is_err(), "symlink must fail closed");

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644))
            .expect("weaken fixture permissions");
        assert!(
            load_registry(&real).is_err(),
            "group/world-readable public state must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_during_atomic_save() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = private_tempdir();
        let real_parent = directory.path().join("real-parent");
        std::fs::create_dir(&real_parent).expect("real parent");
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700))
            .expect("private real parent");
        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("parent symlink");

        assert!(
            save_profile_config(
                &linked_parent.join("config.json"),
                &fixture_config("https://api.palladin.io"),
            )
            .is_err(),
            "atomic save must not traverse a symlinked parent"
        );
        assert!(!real_parent.join("config.json").exists());
    }
}
