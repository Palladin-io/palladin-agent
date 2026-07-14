use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use thiserror::Error;

const MAX_ENTRIES: usize = 16_384;
const MAX_DEPTH: usize = 8;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Permanently removes one already-revoked broker-owned principal namespace.
///
/// The root-owned caller retains `/etc/palladin/agents.d/<uid>` as the UID-reuse
/// tombstone. This function touches only paths derived from a validated opaque
/// principal below the fixed broker state root. It atomically detaches the live
/// namespace before recursively deleting preflighted regular files.
pub fn purge_principal_namespace(
    state_root: &Path,
    principal: &str,
    broker_uid: u32,
) -> Result<(), PurgeError> {
    if !state_root.is_absolute() || !valid_principal(principal) || broker_uid == 0 {
        return Err(PurgeError::InvalidInput);
    }
    let state_metadata = fs::symlink_metadata(state_root).map_err(|_| PurgeError::State)?;
    validate_directory(&state_metadata, broker_uid, None)?;
    let device = state_metadata.dev();
    let agents = state_root.join("agents");
    let agents_metadata = fs::symlink_metadata(&agents).map_err(|_| PurgeError::State)?;
    validate_directory(&agents_metadata, broker_uid, Some(device))?;

    let active = agents.join(principal);
    let detached = agents.join(format!(".purging-{principal}"));
    let cache = agents.join(format!(".{principal}.palladin-policy-cache-v1"));
    let lock = agents.join(format!(".{principal}.palladin-runtime.lock"));
    preflight_optional_tree(&cache, broker_uid, device)?;
    preflight_optional_file(&lock, broker_uid, device)?;
    match (
        fs::symlink_metadata(&active),
        fs::symlink_metadata(&detached),
    ) {
        (Ok(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            preflight_tree(&active, broker_uid, device)?;
            fs::rename(&active, &detached).map_err(|_| PurgeError::State)?;
            sync_directory(&agents)?;
        }
        (Err(active_error), Ok(_)) if active_error.kind() == std::io::ErrorKind::NotFound => {}
        (Err(active_error), Err(detached_error))
            if active_error.kind() == std::io::ErrorKind::NotFound
                && detached_error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(PurgeError::State),
    }
    if detached.exists() {
        preflight_tree(&detached, broker_uid, device)?;
        fs::remove_dir_all(&detached).map_err(|_| PurgeError::State)?;
        sync_directory(&agents)?;
    }

    remove_optional_tree(&cache, broker_uid, device)?;
    remove_optional_file(&lock, broker_uid, device)?;
    sync_directory(&agents)
}

fn preflight_optional_tree(path: &Path, owner: u32, device: u64) -> Result<(), PurgeError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => preflight_tree(path, owner, device),
        Err(_) => Err(PurgeError::State),
    }
}

fn preflight_optional_file(path: &Path, owner: u32, device: u64) -> Result<(), PurgeError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) => validate_file(&metadata, owner, device),
        Err(_) => Err(PurgeError::State),
    }
}

fn remove_optional_tree(path: &Path, owner: u32, device: u64) -> Result<(), PurgeError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => {
            preflight_tree(path, owner, device)?;
            fs::remove_dir_all(path).map_err(|_| PurgeError::State)
        }
        Err(_) => Err(PurgeError::State),
    }
}

fn remove_optional_file(path: &Path, owner: u32, device: u64) -> Result<(), PurgeError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) => {
            validate_file(&metadata, owner, device)?;
            fs::remove_file(path).map_err(|_| PurgeError::State)
        }
        Err(_) => Err(PurgeError::State),
    }
}

fn preflight_tree(root: &Path, owner: u32, device: u64) -> Result<(), PurgeError> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut entries = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        entries = entries.checked_add(1).ok_or(PurgeError::State)?;
        if entries > MAX_ENTRIES || depth > MAX_DEPTH {
            return Err(PurgeError::State);
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| PurgeError::State)?;
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            validate_directory(&metadata, owner, Some(device))?;
            for entry in fs::read_dir(&path).map_err(|_| PurgeError::State)? {
                let entry = entry.map_err(|_| PurgeError::State)?;
                pending.push((entry.path(), depth + 1));
            }
        } else {
            validate_file(&metadata, owner, device)?;
        }
    }
    Ok(())
}

fn validate_directory(
    metadata: &fs::Metadata,
    owner: u32,
    device: Option<u64>,
) -> Result<(), PurgeError> {
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o777 != 0o700
        || device.is_some_and(|expected| metadata.dev() != expected)
    {
        return Err(PurgeError::State);
    }
    Ok(())
}

fn validate_file(metadata: &fs::Metadata, owner: u32, device: u64) -> Result<(), PurgeError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.dev() != device
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err(PurgeError::State);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), PurgeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PurgeError::State)
}

fn valid_principal(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PurgeError {
    #[error("the Linux Hardened purge request is invalid")]
    InvalidInput,
    #[error("the Linux Hardened principal state is invalid or could not be purged")]
    State,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{PurgeError, purge_principal_namespace};

    const PRINCIPAL: &str = "0123456789abcdef0123456789abcdef";

    fn private_directory(path: &Path) {
        fs::create_dir_all(path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("permissions");
    }

    use std::fs;
    use std::path::Path;

    #[test]
    fn purge_detaches_only_the_selected_namespace_and_keeps_other_principals() {
        let root = tempfile::tempdir().expect("root");
        private_directory(root.path());
        let agents = root.path().join("agents");
        private_directory(&agents);
        let selected = agents.join(PRINCIPAL);
        private_directory(&selected);
        let identities = selected.join("identities");
        private_directory(&identities);
        fs::write(selected.join("registry.json"), b"public").expect("registry");
        fs::set_permissions(
            selected.join("registry.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("registry permissions");
        let other = agents.join("11111111111111111111111111111111");
        private_directory(&other);

        purge_principal_namespace(root.path(), PRINCIPAL, nix::unistd::geteuid().as_raw())
            .expect("purge");

        assert!(!selected.exists());
        assert!(other.exists());
    }

    #[test]
    fn purge_rejects_symlinks_before_detaching_the_namespace() {
        let root = tempfile::tempdir().expect("root");
        private_directory(root.path());
        let agents = root.path().join("agents");
        private_directory(&agents);
        let selected = agents.join(PRINCIPAL);
        private_directory(&selected);
        let outside = root.path().join("outside");
        fs::write(&outside, b"preserve").expect("outside");
        symlink(&outside, selected.join("config.json")).expect("symlink");

        assert_eq!(
            purge_principal_namespace(root.path(), PRINCIPAL, nix::unistd::geteuid().as_raw()),
            Err(PurgeError::State)
        );
        assert!(selected.exists());
        assert_eq!(fs::read(outside).expect("outside"), b"preserve");
    }
}
