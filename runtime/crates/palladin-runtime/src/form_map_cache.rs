use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use palladin_browser_bridge::FormDiscoveryMap;
use palladin_core::profiles::ProfileRepository;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

const CACHE_SCHEMA_VERSION: u8 = 1;
const DEFAULT_MAX_ENTRIES: usize = 100;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 500;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeConfig {
    form_map_cache: FormMapCacheConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FormMapCacheConfig {
    max_entries: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            form_map_cache: FormMapCacheConfig {
                max_entries: DEFAULT_MAX_ENTRIES,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheKey {
    profile_identity_id: String,
    agent_id: String,
    api_origin: String,
    domain: String,
    provider: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheEntry {
    key: CacheKey,
    map: FormDiscoveryMap,
    last_used: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheFile {
    schema_version: u8,
    entries: Vec<CacheEntry>,
}

pub(crate) struct FormMapCache {
    path: PathBuf,
    maximum_entries: usize,
    next_usage: u64,
    entries: Vec<CacheEntry>,
}

impl FormMapCache {
    pub(crate) fn get_serialized(
        root: &Path,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        domain: &str,
        provider: &str,
    ) -> Result<Option<FormDiscoveryMap>, FormMapCacheError> {
        Self::transact(root, |cache| {
            cache.get(profile_identity_id, agent_id, api_origin, domain, provider)
        })
    }

    pub(crate) fn put_serialized(
        root: &Path,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        map: FormDiscoveryMap,
    ) -> Result<(), FormMapCacheError> {
        Self::transact(root, |cache| {
            cache.put(profile_identity_id, agent_id, api_origin, map)
        })
    }

    pub(crate) fn invalidate_matching_serialized(
        root: &Path,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        domain: &str,
        provider: &str,
        rejected: &FormDiscoveryMap,
    ) -> Result<(), FormMapCacheError> {
        Self::transact(root, |cache| {
            cache.invalidate_matching(
                profile_identity_id,
                agent_id,
                api_origin,
                domain,
                provider,
                rejected,
            )
        })
    }

    fn transact<T>(
        root: &Path,
        operation: impl FnOnce(&mut Self) -> Result<T, FormMapCacheError>,
    ) -> Result<T, FormMapCacheError> {
        let repository = ProfileRepository::new(root.to_path_buf())
            .map_err(|_| FormMapCacheError::TransactionLock)?;
        let _lock = repository
            .acquire_transaction_lock()
            .map_err(|_| FormMapCacheError::TransactionLock)?;
        let mut cache = Self::load(root)?;
        operation(&mut cache)
    }

    pub(crate) fn load(root: &Path) -> Result<Self, FormMapCacheError> {
        let maximum_entries = load_runtime_config(root)?.form_map_cache.max_entries;
        let path = root.join("form-map-cache.json");
        let file = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_private_file(&metadata)?;
                if metadata.len() > MAX_CACHE_BYTES {
                    return Err(FormMapCacheError::InvalidCache);
                }
                let value: CacheFile = read_json(&path)?;
                if value.schema_version != CACHE_SCHEMA_VERSION || value.entries.len() > MAX_ENTRIES
                {
                    return Err(FormMapCacheError::InvalidCache);
                }
                value
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CacheFile {
                schema_version: CACHE_SCHEMA_VERSION,
                entries: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        validate_entries(&file.entries)?;
        let next_usage = file
            .entries
            .iter()
            .map(|entry| entry.last_used)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .unwrap_or(1);
        let mut cache = Self {
            path,
            maximum_entries,
            next_usage,
            entries: file.entries,
        };
        cache.evict();
        Ok(cache)
    }

    pub(crate) fn get(
        &mut self,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        domain: &str,
        provider: &str,
    ) -> Result<Option<FormDiscoveryMap>, FormMapCacheError> {
        let key = cache_key(profile_identity_id, agent_id, api_origin, domain, provider)?;
        let Some(index) = self.entries.iter().position(|entry| entry.key == key) else {
            return Ok(None);
        };
        self.entries[index].last_used = self.take_usage();
        let map = self.entries[index].map.clone();
        self.save()?;
        Ok(Some(map))
    }

    pub(crate) fn put(
        &mut self,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        map: FormDiscoveryMap,
    ) -> Result<(), FormMapCacheError> {
        map.validate(&map.domain, &map.provider)
            .map_err(|_| FormMapCacheError::InvalidCache)?;
        let key = cache_key(
            profile_identity_id,
            agent_id,
            api_origin,
            &map.domain,
            &map.provider,
        )?;
        let last_used = self.take_usage();
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.key == key) {
            entry.map = map;
            entry.last_used = last_used;
        } else {
            self.entries.push(CacheEntry {
                key,
                map,
                last_used,
            });
        }
        self.evict();
        self.save()
    }

    pub(crate) fn invalidate_matching(
        &mut self,
        profile_identity_id: &str,
        agent_id: &str,
        api_origin: &str,
        domain: &str,
        provider: &str,
        rejected: &FormDiscoveryMap,
    ) -> Result<(), FormMapCacheError> {
        let key = cache_key(profile_identity_id, agent_id, api_origin, domain, provider)?;
        self.entries.retain(|entry| {
            entry.key != key
                || entry.map.map_version != rejected.map_version
                || entry.map.fingerprint != rejected.fingerprint
        });
        self.save()
    }

    fn take_usage(&mut self) -> u64 {
        let usage = self.next_usage;
        self.next_usage = self.next_usage.checked_add(1).unwrap_or_else(|| {
            self.entries.sort_by_key(|entry| entry.last_used);
            for (index, entry) in self.entries.iter_mut().enumerate() {
                entry.last_used = index as u64 + 1;
            }
            self.entries.len() as u64 + 2
        });
        usage
    }

    fn evict(&mut self) {
        if self.entries.len() <= self.maximum_entries {
            return;
        }
        self.entries.sort_by_key(|entry| entry.last_used);
        self.entries
            .drain(..self.entries.len().saturating_sub(self.maximum_entries));
    }

    fn save(&self) -> Result<(), FormMapCacheError> {
        let parent = self.path.parent().ok_or(FormMapCacheError::InvalidCache)?;
        validate_private_directory(&fs::symlink_metadata(parent)?)?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => validate_private_file(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut temporary = NamedTempFile::new_in(parent)?;
        set_private_permissions(temporary.as_file())?;
        {
            let mut writer = BufWriter::new(temporary.as_file_mut());
            serde_json::to_writer(
                &mut writer,
                &CacheFile {
                    schema_version: CACHE_SCHEMA_VERSION,
                    entries: self.entries.clone(),
                },
            )?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|_| FormMapCacheError::Persist)?;
        validate_private_file(&fs::symlink_metadata(&self.path)?)?;
        Ok(())
    }
}

fn load_runtime_config(root: &Path) -> Result<RuntimeConfig, FormMapCacheError> {
    let path = root.join("runtime-config.json");
    let config = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            validate_private_file(&metadata)?;
            if metadata.len() > MAX_CONFIG_BYTES {
                return Err(FormMapCacheError::InvalidConfiguration);
            }
            read_json(&path).map_err(|_| FormMapCacheError::InvalidConfiguration)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RuntimeConfig::default(),
        Err(error) => return Err(error.into()),
    };
    if !(1..=MAX_ENTRIES).contains(&config.form_map_cache.max_entries) {
        return Err(FormMapCacheError::InvalidConfiguration);
    }
    Ok(config)
}

fn validate_entries(entries: &[CacheEntry]) -> Result<(), FormMapCacheError> {
    let mut keys = BTreeSet::new();
    for entry in entries {
        validate_cache_key(&entry.key)?;
        entry
            .map
            .validate(&entry.key.domain, &entry.key.provider)
            .map_err(|_| FormMapCacheError::InvalidCache)?;
        if entry.last_used == 0 || !keys.insert(entry.key.clone()) {
            return Err(FormMapCacheError::InvalidCache);
        }
    }
    Ok(())
}

fn cache_key(
    profile_identity_id: &str,
    agent_id: &str,
    api_origin: &str,
    domain: &str,
    provider: &str,
) -> Result<CacheKey, FormMapCacheError> {
    let key = CacheKey {
        profile_identity_id: profile_identity_id.to_owned(),
        agent_id: agent_id.to_owned(),
        api_origin: api_origin.to_owned(),
        domain: domain.to_owned(),
        provider: provider.to_owned(),
    };
    validate_cache_key(&key)?;
    Ok(key)
}

fn validate_cache_key(key: &CacheKey) -> Result<(), FormMapCacheError> {
    let origin = Url::parse(&key.api_origin).map_err(|_| FormMapCacheError::InvalidCache)?;
    if key.profile_identity_id.is_empty()
        || key.profile_identity_id.len() > 256
        || key.agent_id.is_empty()
        || key.agent_id.len() > 256
        || key.domain.is_empty()
        || key.domain.len() > 253
        || key.provider.is_empty()
        || key.provider.len() > 64
        || !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(FormMapCacheError::InvalidCache);
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, FormMapCacheError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CACHE_BYTES {
        return Err(FormMapCacheError::InvalidCache);
    }
    serde_json::from_reader(BufReader::new(bytes.as_slice())).map_err(Into::into)
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), FormMapCacheError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(FormMapCacheError::UnsafePath);
    }
    #[cfg(unix)]
    validate_unix_permissions(metadata, 0o700)?;
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<(), FormMapCacheError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(FormMapCacheError::UnsafePath);
    }
    #[cfg(unix)]
    validate_unix_permissions(metadata, 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn validate_unix_permissions(
    metadata: &fs::Metadata,
    expected_mode: u32,
) -> Result<(), FormMapCacheError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != expected_mode
    {
        return Err(FormMapCacheError::UnsafePath);
    }
    Ok(())
}

fn set_private_permissions(_file: &File) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum FormMapCacheError {
    #[error("Form Discovery Map cache configuration is invalid")]
    InvalidConfiguration,
    #[error("Form Discovery Map cache is invalid")]
    InvalidCache,
    #[error("Form Discovery Map cache path is unsafe")]
    UnsafePath,
    #[error("Form Discovery Map cache could not be persisted")]
    Persist,
    #[error("Form Discovery Map cache transaction lock could not be acquired")]
    TransactionLock,
    #[error("Form Discovery Map cache filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("Form Discovery Map cache JSON is invalid")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> FormDiscoveryMap {
        serde_json::from_str(r#"{
          "mapId":"11111111-1111-4111-8111-111111111111","mapVersion":1,"scope":"system",
          "domain":"accounts.google.com","loginUrl":"https://accounts.google.com/","provider":"playwright",
          "fingerprint":"b556b71b0235e2afbbbaab4d9b65223e47c126c3a952e6ef946321e1602e3288",
          "map":{"version":1,"form":{"version":1,"steps":[
            {"fields":[{"entryFieldId":"credential.username","selector":"input[autocomplete=\"username\"]","control":"username"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"},"waitFor":{"selector":"input[type=\"password\"]"}},
            {"fields":[{"entryFieldId":"credential.password","selector":"input[type=\"password\"]","control":"password"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"}}
          ]}},"updatedAt":"2026-08-15T12:00:00Z"
        }"#).expect("map")
    }

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        }
        root
    }

    fn write_config(root: &Path, maximum_entries: usize) {
        let path = root.join("runtime-config.json");
        fs::write(
            &path,
            format!("{{\"formMapCache\":{{\"maxEntries\":{maximum_entries}}}}}\n"),
        )
        .expect("config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
    }

    #[test]
    fn cache_is_persistent_lru_and_scoped_by_profile_agent_and_api_origin() {
        let root = private_root();
        write_config(root.path(), 2);
        FormMapCache::put_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://one.example",
            map(),
        )
        .expect("first");
        FormMapCache::put_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://two.example",
            map(),
        )
        .expect("second");
        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-a",
                "https://one.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("touch")
            .is_some()
        );
        FormMapCache::put_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://three.example",
            map(),
        )
        .expect("third");

        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-a",
                "https://two.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("evicted")
            .is_none()
        );
        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-a",
                "https://one.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("retained")
            .is_some()
        );
        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-b",
                "agent-a",
                "https://one.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("profile scoped")
            .is_none()
        );
        let rejected = map();
        FormMapCache::invalidate_matching_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://one.example",
            "accounts.google.com",
            "playwright",
            &rejected,
        )
        .expect("invalidate");
        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-a",
                "https://one.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("invalidated")
            .is_none()
        );

        let mut replacement = map();
        replacement.map_version += 1;
        FormMapCache::put_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://one.example",
            replacement.clone(),
        )
        .expect("replacement");
        FormMapCache::invalidate_matching_serialized(
            root.path(),
            "profile-a",
            "agent-a",
            "https://one.example",
            "accounts.google.com",
            "playwright",
            &rejected,
        )
        .expect("conditional invalidate");
        assert_eq!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-a",
                "https://one.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("newer revision retained"),
            Some(replacement)
        );
        assert!(
            FormMapCache::get_serialized(
                root.path(),
                "profile-a",
                "agent-b",
                "https://three.example",
                "accounts.google.com",
                "playwright"
            )
            .expect("agent scoped")
            .is_none()
        );
    }

    #[test]
    fn cache_limit_is_configurable_but_hard_bounded() {
        let root = private_root();
        write_config(root.path(), 0);
        assert!(matches!(
            FormMapCache::load(root.path()),
            Err(FormMapCacheError::InvalidConfiguration)
        ));

        write_config(root.path(), MAX_ENTRIES + 1);
        assert!(matches!(
            FormMapCache::load(root.path()),
            Err(FormMapCacheError::InvalidConfiguration)
        ));
    }

    #[test]
    fn cache_mutations_wait_for_the_cross_process_transaction_lock() {
        let root = private_root();
        let repository =
            ProfileRepository::new(root.path().to_path_buf()).expect("profile repository");
        let lock = repository
            .acquire_transaction_lock()
            .expect("transaction lock");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let result = FormMapCache::put_serialized(
                    root.path(),
                    "profile-a",
                    "agent-a",
                    "https://api.example",
                    map(),
                );
                sender.send(result).expect("send result");
            });
            let was_blocked = receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err();
            drop(lock);
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("mutation completed")
                .expect("cache write");
            assert!(was_blocked);
        });
    }
}
