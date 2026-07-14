use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crypto_secretbox::{KeyInit, XSalsa20Poly1305, aead::Aead};
use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
use secrecy::SecretSlice;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"PLSBX02\0";
const CONTEXT_MAGIC: &[u8; 8] = b"PLCTX02\0";
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const OWNER_ID_BYTES: usize = 32;
const SLOT_ID_BYTES: usize = 1;
const SECRET_LENGTH_BYTES: usize = 4;
const AUTH_TAG_BYTES: usize = 16;
const CONTEXT_HEADER_BYTES: usize =
    CONTEXT_MAGIC.len() + OWNER_ID_BYTES + SLOT_ID_BYTES + SECRET_LENGTH_BYTES;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MIN_PROTECTED_SECRET_BYTES: usize =
    MAGIC.len() + NONCE_BYTES + CONTEXT_HEADER_BYTES + 1 + AUTH_TAG_BYTES;
const MAX_PROTECTED_SECRET_BYTES: usize =
    MAGIC.len() + NONCE_BYTES + CONTEXT_HEADER_BYTES + MAX_SECRET_BYTES + AUTH_TAG_BYTES;

#[derive(Clone, Debug)]
pub struct LinuxBrokerSecretStore {
    root: PathBuf,
    master_key_path: PathBuf,
}

impl LinuxBrokerSecretStore {
    pub fn new(profile_root: &Path, master_key_path: &Path) -> Result<Self, StoreError> {
        if !profile_root.is_absolute() || !master_key_path.is_absolute() {
            return Err(StoreError::InvalidConfiguration);
        }
        validate_private_directory(profile_root)?;
        validate_private_file(master_key_path, 0o400)?;
        Ok(Self {
            root: profile_root.join("secrets"),
            master_key_path: master_key_path.to_owned(),
        })
    }

    fn path(&self, owner_id: &str, slot: SecretSlot) -> Result<PathBuf, StoreError> {
        if !valid_owner_id(owner_id) {
            return Err(StoreError::InvalidOwner);
        }
        let (suffix, _) = slot_context(slot);
        Ok(self.root.join(format!("{owner_id}.{suffix}.secretbox")))
    }

    fn key(&self) -> Result<Zeroizing<[u8; KEY_BYTES]>, StoreError> {
        validate_private_file(&self.master_key_path, 0o400)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(&self.master_key_path)
            .map_err(|_| StoreError::Unavailable)?;
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        file.read_exact(key.as_mut())
            .map_err(|_| StoreError::Unavailable)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| StoreError::Unavailable)?
            != 0
        {
            return Err(StoreError::InvalidConfiguration);
        }
        Ok(key)
    }
}

impl SecretStore for LinuxBrokerSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let path = self.path(owner_id, slot)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Unavailable),
        };
        validate_metadata(&metadata, 0o600, false)?;
        validate_protected_length(metadata.len())?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options.open(path).map_err(|_| StoreError::Unavailable)?;
        let opened_metadata = file.metadata().map_err(|_| StoreError::Unavailable)?;
        validate_metadata(&opened_metadata, 0o600, false)?;
        validate_protected_length(opened_metadata.len())?;
        let expected_length = opened_metadata.len() as usize;
        let mut protected = Zeroizing::new(Vec::with_capacity(expected_length));
        file.take((MAX_PROTECTED_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut protected)
            .map_err(|_| StoreError::Unavailable)?;
        if protected.len() != expected_length || protected.len() > MAX_PROTECTED_SECRET_BYTES {
            return Err(StoreError::Unavailable);
        }
        if protected.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(StoreError::Unavailable);
        }
        let nonce: [u8; NONCE_BYTES] = protected[MAGIC.len()..MAGIC.len() + NONCE_BYTES]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?;
        let key = self.key()?;
        let cipher = XSalsa20Poly1305::new(key.as_slice().into());
        let context = Zeroizing::new(
            cipher
                .decrypt((&nonce).into(), &protected[MAGIC.len() + NONCE_BYTES..])
                .map_err(|_| StoreError::Unavailable)?,
        );
        decode_context(owner_id, slot, &context).map(Some)
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(StoreError::InvalidSecret);
        }
        ensure_private_directory(&self.root)?;
        let path = self.path(owner_id, slot)?;
        reject_existing_non_private_file(&path)?;
        let key = self.key()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Unavailable)?;
        let cipher = XSalsa20Poly1305::new(key.as_slice().into());
        let context = encode_context(owner_id, slot, secret)?;
        let encrypted = cipher
            .encrypt((&nonce).into(), context.as_slice())
            .map_err(|_| StoreError::Unavailable)?;
        let mut protected = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + NONCE_BYTES + encrypted.len(),
        ));
        protected.extend_from_slice(MAGIC);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&encrypted);
        nonce.zeroize();
        atomic_replace(&path, &protected)
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        let path = self.path(owner_id, slot)?;
        let parent = path.parent().ok_or(StoreError::InvalidConfiguration)?;
        ensure_private_directory(parent)?;
        delete_path_and_sync(&path, sync_directory)
    }
}

fn slot_context(slot: SecretSlot) -> (&'static str, u8) {
    match slot {
        SecretSlot::IntegrityTrustStateV1 => ("integrity-trust-state-v1", 1),
        SecretSlot::OrganizationApiKey => ("organization-api-key-v3", 2),
        SecretSlot::X25519PrivateKey => ("x25519-private-key-v3", 3),
        SecretSlot::Ed25519SecretKey => ("ed25519-secret-key-v3", 4),
        SecretSlot::LegacyOrganizationApiKeyV2 => ("organization-api-key", 5),
        SecretSlot::LegacyX25519PrivateKeyV2 => ("x25519-private-key", 6),
        SecretSlot::LegacyEd25519SecretKeyV2 => ("ed25519-secret-key", 7),
    }
}

fn encode_context(
    owner_id: &str,
    slot: SecretSlot,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if !valid_owner_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(StoreError::InvalidSecret);
    }
    let secret_length = u32::try_from(secret.len()).map_err(|_| StoreError::InvalidSecret)?;
    let mut context = Zeroizing::new(Vec::with_capacity(CONTEXT_HEADER_BYTES + secret.len()));
    context.extend_from_slice(CONTEXT_MAGIC);
    context.extend_from_slice(owner_id.as_bytes());
    context.push(slot_context(slot).1);
    context.extend_from_slice(&secret_length.to_be_bytes());
    context.extend_from_slice(secret);
    Ok(context)
}

fn decode_context(
    owner_id: &str,
    slot: SecretSlot,
    context: &[u8],
) -> Result<SecretSlice<u8>, StoreError> {
    if context.len() <= CONTEXT_HEADER_BYTES
        || context.get(..CONTEXT_MAGIC.len()) != Some(CONTEXT_MAGIC)
        || context.get(CONTEXT_MAGIC.len()..CONTEXT_MAGIC.len() + OWNER_ID_BYTES)
            != Some(owner_id.as_bytes())
        || context.get(CONTEXT_MAGIC.len() + OWNER_ID_BYTES) != Some(&slot_context(slot).1)
    {
        return Err(StoreError::Unavailable);
    }
    let length_offset = CONTEXT_MAGIC.len() + OWNER_ID_BYTES + SLOT_ID_BYTES;
    let secret_length = u32::from_be_bytes(
        context[length_offset..length_offset + SECRET_LENGTH_BYTES]
            .try_into()
            .map_err(|_| StoreError::Unavailable)?,
    ) as usize;
    if secret_length == 0
        || secret_length > MAX_SECRET_BYTES
        || context.len() != CONTEXT_HEADER_BYTES + secret_length
    {
        return Err(StoreError::Unavailable);
    }
    Ok(context[CONTEXT_HEADER_BYTES..].to_vec().into())
}

fn validate_protected_length(length: u64) -> Result<(), StoreError> {
    if length < MIN_PROTECTED_SECRET_BYTES as u64 || length > MAX_PROTECTED_SECRET_BYTES as u64 {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    open_directory(path)?
        .sync_all()
        .map_err(|_| StoreError::Unavailable)
}

fn delete_path_and_sync(
    path: &Path,
    sync_parent: impl FnOnce(&Path) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidConfiguration)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_metadata(&metadata, 0o600, false)?;
            fs::remove_file(path).map_err(|_| StoreError::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(StoreError::Unavailable),
    }
    sync_parent(parent)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::InvalidConfiguration)?;
    validate_private_directory(parent)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StoreError::Unavailable)?;
    let temporary = parent.join(format!(".secret-{}.tmp", hex(&random)));
    random.zeroize();
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| StoreError::Unavailable)?;
        file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
        file.sync_all().map_err(|_| StoreError::Unavailable)?;
        fs::rename(&temporary, path).map_err(|_| StoreError::Unavailable)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn ensure_private_directory(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata, 0o700, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(StoreError::InvalidConfiguration)?;
            validate_private_directory(parent)?;
            fs::create_dir(path).map_err(|_| StoreError::Unavailable)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| StoreError::Unavailable)?;
            validate_private_directory(path)
        }
        Err(_) => Err(StoreError::Unavailable),
    }
}

fn validate_private_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Unavailable)?;
    validate_metadata(&metadata, 0o700, true)
}

fn validate_private_file(path: &Path, mode: u32) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Unavailable)?;
    validate_metadata(&metadata, mode, false)
}

fn validate_metadata(
    metadata: &fs::Metadata,
    mode: u32,
    directory: bool,
) -> Result<(), StoreError> {
    let correct_type = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !correct_type
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != mode
        || (!directory && metadata.nlink() != 1)
    {
        return Err(StoreError::InvalidConfiguration);
    }
    Ok(())
}

fn reject_existing_non_private_file(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata, 0o600, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::Unavailable),
    }
}

fn open_directory(path: &Path) -> Result<File, StoreError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| StoreError::Unavailable)
}

fn valid_owner_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
    use secrecy::ExposeSecret;

    use super::{
        LinuxBrokerSecretStore, MAX_PROTECTED_SECRET_BYTES, MAX_SECRET_BYTES, delete_path_and_sync,
    };

    fn fixture() -> (tempfile::TempDir, LinuxBrokerSecretStore) {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("permissions");
        let profile = root.path().join("profile");
        fs::create_dir(&profile).expect("profile");
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).expect("permissions");
        let key = root.path().join("master.key");
        fs::write(&key, [7_u8; 32]).expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).expect("permissions");
        let store = LinuxBrokerSecretStore::new(&profile, &key).expect("store");
        (root, store)
    }

    #[test]
    fn encrypted_store_round_trip_never_persists_plaintext() {
        let (root, store) = fixture();
        let owner = "11111111111111111111111111111111";
        store
            .set(owner, SecretSlot::OrganizationApiKey, b"synthetic-api-key")
            .expect("set");
        let stored = fs::read(root.path().join(
            "profile/secrets/11111111111111111111111111111111.organization-api-key-v3.secretbox",
        ))
        .expect("ciphertext");
        assert_eq!(&stored[..8], b"PLSBX02\0");
        let persisted_plaintext = stored
            .windows(17)
            .any(|window| window == b"synthetic-api-key");
        assert!(
            !persisted_plaintext,
            "broker store persisted a plaintext organization credential"
        );
        assert!(
            store
                .get(owner, SecretSlot::OrganizationApiKey)
                .expect("get")
                .expect("secret")
                .expose_secret()
                == b"synthetic-api-key",
            "stored organization credential diverged"
        );
    }

    #[test]
    fn symlink_and_permission_tampering_fail_closed() {
        let (root, store) = fixture();
        let owner = "22222222222222222222222222222222";
        store
            .set(owner, SecretSlot::X25519PrivateKey, b"synthetic-key")
            .expect("set");
        let path = root.path().join(
            "profile/secrets/22222222222222222222222222222222.x25519-private-key-v3.secretbox",
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
        assert!(matches!(
            store.get(owner, SecretSlot::X25519PrivateKey),
            Err(StoreError::InvalidConfiguration)
        ));
    }

    #[test]
    fn ciphertext_cannot_be_swapped_between_owners_or_slots() {
        let (_root, store) = fixture();
        let source_owner = "33333333333333333333333333333333";
        let other_owner = "44444444444444444444444444444444";
        store
            .set(
                source_owner,
                SecretSlot::OrganizationApiKey,
                b"source-secret",
            )
            .expect("source");
        store
            .set(
                other_owner,
                SecretSlot::OrganizationApiKey,
                b"other-owner-secret",
            )
            .expect("other owner");
        store
            .set(
                source_owner,
                SecretSlot::X25519PrivateKey,
                b"other-slot-secret",
            )
            .expect("other slot");

        let source = store
            .path(source_owner, SecretSlot::OrganizationApiKey)
            .expect("source path");
        let other_owner_path = store
            .path(other_owner, SecretSlot::OrganizationApiKey)
            .expect("other owner path");
        fs::copy(&source, &other_owner_path).expect("swap owner ciphertext");
        assert!(matches!(
            store.get(other_owner, SecretSlot::OrganizationApiKey),
            Err(StoreError::Unavailable)
        ));

        let other_slot_path = store
            .path(source_owner, SecretSlot::X25519PrivateKey)
            .expect("other slot path");
        fs::copy(source, &other_slot_path).expect("swap slot ciphertext");
        assert!(matches!(
            store.get(source_owner, SecretSlot::X25519PrivateKey),
            Err(StoreError::Unavailable)
        ));
    }

    #[test]
    fn plaintext_and_ciphertext_limits_are_consistent() {
        let (_root, store) = fixture();
        let owner = "55555555555555555555555555555555";
        let maximum = vec![0x5a; MAX_SECRET_BYTES];
        store
            .set(owner, SecretSlot::Ed25519SecretKey, &maximum)
            .expect("maximum-sized secret");
        assert!(
            store
                .get(owner, SecretSlot::Ed25519SecretKey)
                .expect("get maximum")
                .expect("maximum secret")
                .expose_secret()
                == maximum.as_slice(),
            "maximum-sized secret diverged"
        );
        assert!(matches!(
            store.set(
                owner,
                SecretSlot::Ed25519SecretKey,
                &vec![0x5a; MAX_SECRET_BYTES + 1],
            ),
            Err(StoreError::InvalidSecret)
        ));

        let path = store
            .path(owner, SecretSlot::Ed25519SecretKey)
            .expect("path");
        assert_eq!(
            fs::metadata(&path).expect("metadata").len(),
            MAX_PROTECTED_SECRET_BYTES as u64
        );
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open ciphertext")
            .write_all(&[0])
            .expect("extend ciphertext");
        assert!(matches!(
            store.get(owner, SecretSlot::Ed25519SecretKey),
            Err(StoreError::Unavailable)
        ));
    }

    #[test]
    fn delete_is_durable_and_idempotent() {
        let (_root, store) = fixture();
        let owner = "66666666666666666666666666666666";
        store
            .delete(owner, SecretSlot::X25519PrivateKey)
            .expect("durable missing delete");
        store
            .set(owner, SecretSlot::X25519PrivateKey, b"delete-me")
            .expect("set");
        let path = store
            .path(owner, SecretSlot::X25519PrivateKey)
            .expect("path");

        store
            .delete(owner, SecretSlot::X25519PrivateKey)
            .expect("durable delete");
        assert!(!path.exists());
        assert!(
            store
                .get(owner, SecretSlot::X25519PrivateKey)
                .expect("get after delete")
                .is_none()
        );
        store
            .delete(owner, SecretSlot::X25519PrivateKey)
            .expect("durable idempotent delete");
    }

    #[test]
    fn delete_reports_parent_sync_failure_after_unlink() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("permissions");
        let path = root.path().join("secret");
        fs::write(&path, b"synthetic-secret").expect("secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let sync_called = Cell::new(false);

        assert!(matches!(
            delete_path_and_sync(&path, |parent| {
                assert_eq!(parent, root.path());
                sync_called.set(true);
                Err(StoreError::Unavailable)
            }),
            Err(StoreError::Unavailable)
        ));
        assert!(sync_called.get());
        assert!(!path.exists());
    }
}
