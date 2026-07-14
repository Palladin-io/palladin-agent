use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use palladin_platform::secure_store::{SecretSlot, SecretStore, StoreError};
use secrecy::SecretSlice;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use zeroize::Zeroize;

const MAX_PROTECTED_SECRET_BYTES: u64 = 64 * 1024;
const DPAPI_ENTROPY: &[u8] = b"palladin.windows.broker-secret.v1\0";

#[derive(Clone, Debug)]
pub struct BrokerSecretStore {
    root: PathBuf,
}

impl BrokerSecretStore {
    pub fn new(profile_root: &Path) -> Result<Self, StoreError> {
        if !profile_root.is_absolute() {
            return Err(StoreError::InvalidConfiguration);
        }
        Ok(Self {
            root: profile_root.join("secrets"),
        })
    }

    fn path(&self, owner_id: &str, slot: SecretSlot) -> Result<PathBuf, StoreError> {
        if !valid_owner_id(owner_id) {
            return Err(StoreError::InvalidOwner);
        }
        let suffix = match slot {
            SecretSlot::IntegrityTrustStateV1 => "integrity-trust-state-v1",
            SecretSlot::OrganizationApiKey => "organization-api-key-v3",
            SecretSlot::X25519PrivateKey => "x25519-private-key-v3",
            SecretSlot::Ed25519SecretKey => "ed25519-secret-key-v3",
            SecretSlot::LegacyOrganizationApiKeyV2 => "organization-api-key",
            SecretSlot::LegacyX25519PrivateKeyV2 => "x25519-private-key",
            SecretSlot::LegacyEd25519SecretKeyV2 => "ed25519-secret-key",
        };
        Ok(self.root.join(format!("{owner_id}.{suffix}.dpapi")))
    }
}

impl SecretStore for BrokerSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let path = self.path(owner_id, slot)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Unavailable),
        };
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PROTECTED_SECRET_BYTES
        {
            return Err(StoreError::Unavailable);
        }
        let mut protected = fs::read(path).map_err(|_| StoreError::Unavailable)?;
        let result = unprotect(&protected).map(|secret| Some(secret.into()));
        protected.zeroize();
        result
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        if secret.is_empty() {
            return Err(StoreError::InvalidSecret);
        }
        let path = self.path(owner_id, slot)?;
        fs::create_dir_all(&self.root).map_err(|_| StoreError::Unavailable)?;
        let mut protected = protect(secret)?;
        if protected.len() as u64 > MAX_PROTECTED_SECRET_BYTES {
            protected.zeroize();
            return Err(StoreError::Unavailable);
        }
        let result = atomic_replace(&path, &protected);
        protected.zeroize();
        result
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        match fs::remove_file(self.path(owner_id, slot)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Unavailable),
        }
    }
}

fn protect(secret: &[u8]) -> Result<Vec<u8>, StoreError> {
    let input = blob(secret);
    let entropy = blob(DPAPI_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    take_local_blob(success, output)
}

fn unprotect(protected: &[u8]) -> Result<Vec<u8>, StoreError> {
    let input = blob(protected);
    let entropy = blob(DPAPI_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB::default();
    let success = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    take_local_blob(success, output)
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}

fn take_local_blob(success: i32, output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, StoreError> {
    if success == 0 || output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe { LocalFree(output.pbData.cast()) };
        }
        return Err(StoreError::Unavailable);
    }
    let mut bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    if bytes.is_empty() {
        bytes.zeroize();
        return Err(StoreError::Unavailable);
    }
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StoreError::Unavailable)?;
    let temporary = path.with_extension(format!("tmp-{}", hex(&random)));
    random.zeroize();
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| StoreError::Unavailable)?;
        file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
        file.sync_all().map_err(|_| StoreError::Unavailable)?;
        drop(file);
        let from = wide_path(&temporary);
        let to = wide_path(path);
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(StoreError::Unavailable);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain([0]).collect()
}

fn valid_owner_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod slot_path_tests {
    use std::path::Path;

    use palladin_platform::secure_store::SecretSlot;

    use super::BrokerSecretStore;

    #[test]
    fn schema_v3_and_legacy_slots_use_distinct_dpapi_files() {
        let store = BrokerSecretStore::new(Path::new(r"C:\ProgramData\Palladin\profiles\S-1-5-21"))
            .expect("store");
        let owner = "11111111111111111111111111111111";

        let current = store
            .path(owner, SecretSlot::OrganizationApiKey)
            .expect("current path");
        let legacy = store
            .path(owner, SecretSlot::LegacyOrganizationApiKeyV2)
            .expect("legacy path");
        let trust = store
            .path(owner, SecretSlot::IntegrityTrustStateV1)
            .expect("trust path");
        let current_name = format!("{owner}.organization-api-key-v3.dpapi");
        let legacy_name = format!("{owner}.organization-api-key.dpapi");
        let trust_name = format!("{owner}.integrity-trust-state-v1.dpapi");

        assert_ne!(current, legacy);
        assert_eq!(
            current.file_name().and_then(|value| value.to_str()),
            Some(current_name.as_str())
        );
        assert_eq!(
            legacy.file_name().and_then(|value| value.to_str()),
            Some(legacy_name.as_str())
        );
        assert_eq!(
            trust.file_name().and_then(|value| value.to_str()),
            Some(trust_name.as_str())
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use palladin_platform::secure_store::{SecretSlot, SecretStore};
    use secrecy::ExposeSecret;

    use super::BrokerSecretStore;

    #[test]
    fn organization_credential_is_shared_while_agent_identities_remain_separate() {
        let root = tempfile::tempdir().expect("root");
        let store = BrokerSecretStore::new(root.path()).expect("store");
        let organization = "11111111111111111111111111111111";
        let first_agent = "22222222222222222222222222222222";
        let second_agent = "33333333333333333333333333333333";
        let api_key = b"pl_shared_organization_fixture";

        store
            .set(organization, SecretSlot::OrganizationApiKey, api_key)
            .expect("organization key");
        for (agent, encryption, signing) in [
            (
                first_agent,
                b"first-x25519".as_slice(),
                b"first-ed25519".as_slice(),
            ),
            (
                second_agent,
                b"second-x25519".as_slice(),
                b"second-ed25519".as_slice(),
            ),
        ] {
            store
                .set(agent, SecretSlot::X25519PrivateKey, encryption)
                .expect("encryption identity");
            store
                .set(agent, SecretSlot::Ed25519SecretKey, signing)
                .expect("signing identity");
        }

        let stored = store
            .get(organization, SecretSlot::OrganizationApiKey)
            .expect("read organization key")
            .expect("organization key exists");
        assert!(
            stored.expose_secret() == api_key,
            "stored organization credential diverged"
        );
        let files = std::fs::read_dir(root.path().join("secrets"))
            .expect("secret directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("secret files");
        assert_eq!(files.len(), 5, "one organization key plus two key pairs");
        for file in files {
            let protected = std::fs::read(file.path()).expect("protected file");
            assert!(
                !protected
                    .windows(api_key.len())
                    .any(|window| window == api_key)
            );
        }
    }
}
