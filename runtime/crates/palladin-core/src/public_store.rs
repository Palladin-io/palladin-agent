use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

pub const PUBLIC_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicAgentEntry {
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
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
            || self
                .agents
                .iter()
                .any(|agent| !is_profile_name(&agent.name))
        {
            return Err(PublicStoreError::InvalidPublicData);
        }

        let names = self
            .agents
            .iter()
            .map(|agent| agent.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if names.len() != self.agents.len()
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
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
}

impl PublicProfileConfig {
    fn validate(&self) -> Result<(), PublicStoreError> {
        if self.schema_version != PUBLIC_SCHEMA_VERSION {
            return Err(PublicStoreError::InvalidPublicData);
        }

        let host = Url::parse(&self.host).map_err(|_| PublicStoreError::InvalidPublicData)?;
        if !matches!(host.scheme(), "http" | "https")
            || !host.username().is_empty()
            || host.password().is_some()
            || host.query().is_some()
            || host.fragment().is_some()
            || host.host_str().is_none()
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

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, PublicStoreError> {
    let file = File::open(path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

fn save_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), PublicStoreError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "store path has no parent")
    })?;
    fs::create_dir_all(parent)?;

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
    sync_parent(parent)?;
    Ok(())
}

fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
        load_profile_config, load_registry, save_profile_config, save_registry,
    };

    #[test]
    fn round_trips_public_registry_without_secret_fields() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("registry.json");
        let registry = PublicRegistry {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: "build".to_owned(),
            agents: vec![PublicAgentEntry {
                name: "build".to_owned(),
                created_at: "2026-07-12T00:00:00Z".to_owned(),
                agent_type: Some("coding".to_owned()),
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
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("registry.json");
        std::fs::write(
            &path,
            r#"{"schemaVersion":1,"default":"default","agents":[],"apiKey":"forbidden"}"#,
        )
        .expect("write invalid fixture");

        let error = load_registry(&path).expect_err("unknown field must fail");
        assert!(error.to_string().contains("invalid JSON"));
    }

    #[test]
    fn rejects_credentials_inside_public_host() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.json");
        let config = PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            host: "https://user:synthetic-password@example.test".to_owned(),
            agent_id: None,
            encryption_public_key: None,
            signing_public_key: None,
        };

        let error = save_profile_config(&path, &config).expect_err("credential URL must fail");
        assert!(error.to_string().contains("invalid public data"));
        assert!(!path.exists());
    }

    #[test]
    fn round_trips_valid_public_profile_config() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.json");
        let config = PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            host: "https://api.palladin.io/v1/".to_owned(),
            agent_id: Some("agent-public-id".to_owned()),
            encryption_public_key: Some("public-encryption-key".to_owned()),
            signing_public_key: Some("public-signing-key".to_owned()),
        };

        save_profile_config(&path, &config).expect("save public config");
        assert_eq!(
            load_profile_config(&path).expect("load public config"),
            config
        );
    }
}
