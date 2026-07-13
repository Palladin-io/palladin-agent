use secrecy::SecretSlice;
use thiserror::Error;

const SERVICE: &str = "io.palladin.agent";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecretSlot {
    OrganizationApiKey,
    X25519PrivateKey,
    Ed25519SecretKey,
}

impl SecretSlot {
    const fn account_suffix(self) -> &'static str {
        match self {
            Self::OrganizationApiKey => "organization-api-key",
            Self::X25519PrivateKey => "x25519-private-key",
            Self::Ed25519SecretKey => "ed25519-secret-key",
        }
    }
}

pub trait SecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError>;
    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsSecretStore;

impl SecretStore for OsSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let entry = entry(owner_id, slot)?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(secret.into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(StoreError::Unavailable),
        }
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        if secret.is_empty() {
            return Err(StoreError::InvalidSecret);
        }
        entry(owner_id, slot)?
            .set_secret(secret)
            .map_err(|_| StoreError::Unavailable)
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        match entry(owner_id, slot)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(StoreError::Unavailable),
        }
    }
}

pub fn delete_identity<S: SecretStore>(store: &S, identity_id: &str) -> Result<(), StoreError> {
    store.delete(identity_id, SecretSlot::X25519PrivateKey)?;
    store.delete(identity_id, SecretSlot::Ed25519SecretKey)
}

pub fn delete_organization_credential<S: SecretStore>(
    store: &S,
    organization_credential_id: &str,
) -> Result<(), StoreError> {
    store.delete(organization_credential_id, SecretSlot::OrganizationApiKey)
}

#[must_use]
pub const fn convenience_tier_description() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Convenience - macOS Login Keychain; same-user process isolation is not guaranteed"
    }
    #[cfg(target_os = "windows")]
    {
        "Convenience - Windows Credential Manager; same-user process isolation is not guaranteed"
    }
    #[cfg(target_os = "linux")]
    {
        "Convenience - Linux Secret Service; same-UID process isolation is not guaranteed"
    }
}

fn entry(owner_id: &str, slot: SecretSlot) -> Result<keyring::Entry, StoreError> {
    if !valid_opaque_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    let account = format!("{owner_id}:{}", slot.account_suffix());
    keyring::Entry::new(SERVICE, &account).map_err(|_| StoreError::Unavailable)
}

fn valid_opaque_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StoreError {
    #[error("OS secure storage is unavailable; no file or environment fallback is allowed")]
    Unavailable,
    #[error("secret material is empty")]
    InvalidSecret,
    #[error("secret owner identifier is invalid")]
    InvalidOwner,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{
        SecretSlot, SecretStore, StoreError, delete_identity, delete_organization_credential,
    };

    #[derive(Default)]
    struct MemoryStore(Mutex<BTreeMap<(String, String), Vec<u8>>>);

    impl SecretStore for MemoryStore {
        fn get(
            &self,
            owner_id: &str,
            slot: SecretSlot,
        ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("store")
                .get(&(owner_id.to_owned(), slot.account_suffix().to_owned()))
                .cloned()
                .map(Into::into))
        }

        fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
            self.0.lock().expect("store").insert(
                (owner_id.to_owned(), slot.account_suffix().to_owned()),
                secret.to_vec(),
            );
            Ok(())
        }

        fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("store")
                .remove(&(owner_id.to_owned(), slot.account_suffix().to_owned()));
            Ok(())
        }
    }

    #[test]
    fn identity_and_organization_credentials_have_independent_owners() {
        let store = MemoryStore::default();
        let identity = "11111111111111111111111111111111";
        let organization = "22222222222222222222222222222222";
        store
            .set(identity, SecretSlot::X25519PrivateKey, b"box")
            .expect("box");
        store
            .set(identity, SecretSlot::Ed25519SecretKey, b"signing")
            .expect("signing");
        store
            .set(organization, SecretSlot::OrganizationApiKey, b"org-key")
            .expect("API key");

        delete_identity(&store, identity).expect("delete identity");
        assert!(
            store
                .get(organization, SecretSlot::OrganizationApiKey)
                .expect("organization")
                .is_some()
        );
        delete_organization_credential(&store, organization).expect("delete organization");
        assert!(
            store
                .get(organization, SecretSlot::OrganizationApiKey)
                .expect("organization")
                .is_none()
        );
    }
}
