use secrecy::SecretSlice;
use thiserror::Error;

#[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
const SERVICE: &str = "io.palladin.agent";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecretSlot {
    /// Small, non-secret integrity root for the public profile store.
    IntegrityTrustStateV1,
    /// Monotonic sequence and digest for the signed public runtime policy.
    VersionPolicyTrustStateV1,
    OrganizationApiKey,
    X25519PrivateKey,
    Ed25519SecretKey,
    /// Read only during the explicit pre-production schema v2 -> v3 migration.
    LegacyOrganizationApiKeyV2,
    /// Read only during the explicit pre-production schema v2 -> v3 migration.
    LegacyX25519PrivateKeyV2,
    /// Read only during the explicit pre-production schema v2 -> v3 migration.
    LegacyEd25519SecretKeyV2,
}

impl SecretSlot {
    pub(crate) const fn account_suffix(self) -> &'static str {
        match self {
            Self::IntegrityTrustStateV1 => "integrity-trust-state-v1",
            Self::VersionPolicyTrustStateV1 => "version-policy-trust-state-v1",
            Self::OrganizationApiKey => "organization-api-key-v3",
            Self::X25519PrivateKey => "x25519-private-key-v3",
            Self::Ed25519SecretKey => "ed25519-secret-key-v3",
            Self::LegacyOrganizationApiKeyV2 => "organization-api-key",
            Self::LegacyX25519PrivateKeyV2 => "x25519-private-key",
            Self::LegacyEd25519SecretKeyV2 => "ed25519-secret-key",
        }
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) const fn requires_user_presence(self) -> bool {
        matches!(
            self,
            Self::OrganizationApiKey | Self::LegacyOrganizationApiKeyV2
        )
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) const fn keychain_label(self) -> &'static str {
        match self {
            Self::IntegrityTrustStateV1 => "Palladin profile integrity root",
            Self::VersionPolicyTrustStateV1 => "Palladin version policy trust state",
            Self::OrganizationApiKey => "Palladin organization credential",
            Self::X25519PrivateKey => "Palladin Agent encryption identity",
            Self::Ed25519SecretKey => "Palladin Agent signing identity",
            Self::LegacyOrganizationApiKeyV2 => "Legacy Palladin organization credential",
            Self::LegacyX25519PrivateKeyV2 => "Legacy Palladin Agent encryption identity",
            Self::LegacyEd25519SecretKeyV2 => "Legacy Palladin Agent signing identity",
        }
    }
}

pub trait SecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError>;
    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError>;
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
pub struct OsSecretStore;

#[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
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

pub fn delete_legacy_identity<S: SecretStore>(
    store: &S,
    identity_id: &str,
) -> Result<(), StoreError> {
    store.delete(identity_id, SecretSlot::LegacyX25519PrivateKeyV2)?;
    store.delete(identity_id, SecretSlot::LegacyEd25519SecretKeyV2)
}

pub fn delete_organization_credential<S: SecretStore>(
    store: &S,
    organization_credential_id: &str,
) -> Result<(), StoreError> {
    store.delete(organization_credential_id, SecretSlot::OrganizationApiKey)
}

pub fn delete_legacy_organization_credential<S: SecretStore>(
    store: &S,
    organization_credential_id: &str,
) -> Result<(), StoreError> {
    store.delete(
        organization_credential_id,
        SecretSlot::LegacyOrganizationApiKeyV2,
    )
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

#[must_use]
pub fn storage_tier_description() -> &'static str {
    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    {
        if crate::macos_hardened_store::runtime_is_hardened() {
            "Hardened - signed macOS Data Protection Keychain bundle; organization credential requires user presence"
        } else {
            "Unavailable - hardened macOS code-signing requirement failed; no secure-storage fallback is allowed"
        }
    }
    #[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
    {
        convenience_tier_description()
    }
}

#[cfg(all(target_os = "macos", feature = "macos-hardened"))]
pub type NativeSecretStore = crate::macos_hardened_store::MacHardenedSecretStore;

#[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
pub type NativeSecretStore = OsSecretStore;

#[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
fn entry(owner_id: &str, slot: SecretSlot) -> Result<keyring::Entry, StoreError> {
    if !valid_opaque_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    let account = account_name(owner_id, slot);
    keyring::Entry::new(SERVICE, &account).map_err(|_| StoreError::Unavailable)
}

pub(crate) fn account_name(owner_id: &str, slot: SecretSlot) -> String {
    format!("{owner_id}:{}", slot.account_suffix())
}

pub(crate) fn valid_opaque_id(value: &str) -> bool {
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
    #[error("hardened secure storage configuration is invalid")]
    InvalidConfiguration,
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

    #[test]
    fn schema_v3_slots_are_isolated_from_legacy_v2_and_integrity_metadata() {
        assert_eq!(
            SecretSlot::IntegrityTrustStateV1.account_suffix(),
            "integrity-trust-state-v1"
        );
        assert_eq!(
            SecretSlot::VersionPolicyTrustStateV1.account_suffix(),
            "version-policy-trust-state-v1"
        );
        assert_eq!(
            SecretSlot::OrganizationApiKey.account_suffix(),
            "organization-api-key-v3"
        );
        assert_eq!(
            SecretSlot::X25519PrivateKey.account_suffix(),
            "x25519-private-key-v3"
        );
        assert_eq!(
            SecretSlot::Ed25519SecretKey.account_suffix(),
            "ed25519-secret-key-v3"
        );
        assert_eq!(
            SecretSlot::LegacyOrganizationApiKeyV2.account_suffix(),
            "organization-api-key"
        );
        assert_eq!(
            SecretSlot::LegacyX25519PrivateKeyV2.account_suffix(),
            "x25519-private-key"
        );
        assert_eq!(
            SecretSlot::LegacyEd25519SecretKeyV2.account_suffix(),
            "ed25519-secret-key"
        );
    }
}
