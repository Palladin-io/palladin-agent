use thiserror::Error;

const LEGACY_SERVICES: [&str; 2] = ["palladin", "claw-vault"];
const LEGACY_ACCOUNT_SUFFIXES: [&str; 2] = ["private-key", "signing-key"];

/// Delete-only boundary for credentials created by the legacy TypeScript client.
///
/// The interface intentionally has no operation that can read credential bytes.
pub trait LegacyCredentialDeleter {
    fn delete_credential(&self, service: &str, account: &str) -> Result<(), LegacyCredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsLegacyCredentialDeleter;

impl LegacyCredentialDeleter for OsLegacyCredentialDeleter {
    fn delete_credential(&self, service: &str, account: &str) -> Result<(), LegacyCredentialError> {
        delete_os_credential(service, account)
    }
}

#[cfg(target_os = "macos")]
fn delete_os_credential(service: &str, account: &str) -> Result<(), LegacyCredentialError> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework_sys::base::errSecItemNotFound;

    let mut query = ItemSearchOptions::new();
    query
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_refs(true)
        .limit(Limit::All);

    let matches = match query.search() {
        Ok(matches) => matches,
        Err(error) if error.code() == errSecItemNotFound => return Ok(()),
        Err(_) => return Err(LegacyCredentialError::Unavailable),
    };

    for item in matches {
        match item {
            SearchResult::Ref(Reference::KeychainItem(item)) => item.delete(),
            _ => return Err(LegacyCredentialError::Unavailable),
        }
    }

    match query.search() {
        Err(error) if error.code() == errSecItemNotFound => Ok(()),
        Ok(matches) if matches.is_empty() => Ok(()),
        Ok(_) | Err(_) => Err(LegacyCredentialError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn delete_os_credential(service: &str, account: &str) -> Result<(), LegacyCredentialError> {
    let secret_service = delete_linux_secret_service_credential(service, account);
    let keyutils = delete_linux_keyutils_credential(service, account);

    linux_delete_outcome(secret_service, keyutils)
}

#[cfg(target_os = "linux")]
fn delete_linux_secret_service_credential(service: &str, account: &str) -> CredentialDeleteState {
    match keyring::Entry::new(service, account) {
        Ok(entry) => delete_keyring_entry(&entry.inner),
        Err(_) => CredentialDeleteState::Unavailable,
    }
}

#[cfg(target_os = "linux")]
fn delete_linux_keyutils_credential(service: &str, account: &str) -> CredentialDeleteState {
    use std::collections::HashMap;

    use keyring_core::api::CredentialStoreApi;
    use linux_keyutils_keyring_store::Store;

    match Store::new_with_configuration(&HashMap::new())
        .and_then(|store| store.build(service, account, None))
    {
        Ok(entry) => delete_keyring_entry(&entry),
        Err(_) => CredentialDeleteState::Unavailable,
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialDeleteState {
    Deleted,
    Missing,
    Unavailable,
}

#[cfg(any(target_os = "linux", test))]
fn linux_delete_outcome(
    secret_service: CredentialDeleteState,
    keyutils: CredentialDeleteState,
) -> Result<(), LegacyCredentialError> {
    match (secret_service, keyutils) {
        (
            CredentialDeleteState::Deleted | CredentialDeleteState::Missing,
            CredentialDeleteState::Deleted | CredentialDeleteState::Missing,
        ) => Ok(()),
        _ => Err(LegacyCredentialError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn delete_keyring_entry(entry: &keyring_core::Entry) -> CredentialDeleteState {
    match entry.delete_credential() {
        Ok(()) => CredentialDeleteState::Deleted,
        Err(keyring_core::Error::NoEntry) => CredentialDeleteState::Missing,
        Err(_) => CredentialDeleteState::Unavailable,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn delete_os_credential(service: &str, account: &str) -> Result<(), LegacyCredentialError> {
    let entry =
        keyring::Entry::new(service, account).map_err(|_| LegacyCredentialError::Unavailable)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(LegacyCredentialError::Unavailable),
    }
}

/// Deletes all known legacy TypeScript identity credentials for one profile.
///
/// Missing credentials are idempotent at the OS adapter boundary. The function
/// never requests or receives secret material.
pub fn delete_legacy_typescript_credentials<D: LegacyCredentialDeleter>(
    deleter: &D,
    legacy_profile: &str,
) -> Result<(), LegacyCredentialError> {
    if !valid_legacy_profile(legacy_profile) {
        return Err(LegacyCredentialError::InvalidProfile);
    }

    for service in LEGACY_SERVICES {
        for suffix in LEGACY_ACCOUNT_SUFFIXES {
            let account = format!("{legacy_profile}:{suffix}");
            deleter.delete_credential(service, &account)?;
        }
    }
    Ok(())
}

fn valid_legacy_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 64
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LegacyCredentialError {
    #[error("legacy TypeScript profile name is invalid")]
    InvalidProfile,
    #[error("OS secure storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::sync::Mutex;

    #[cfg(not(target_os = "linux"))]
    use super::OsLegacyCredentialDeleter;
    use super::{
        LegacyCredentialDeleter, LegacyCredentialError, delete_legacy_typescript_credentials,
    };

    #[derive(Default)]
    struct RecordingDeleteOnlyAdapter(Mutex<Vec<(String, String)>>);

    #[cfg(target_os = "linux")]
    enum LinuxInteropBackend {
        Keyutils,
        SecretService,
    }

    #[cfg(target_os = "linux")]
    impl LegacyCredentialDeleter for LinuxInteropBackend {
        fn delete_credential(
            &self,
            service: &str,
            account: &str,
        ) -> Result<(), LegacyCredentialError> {
            use super::{
                CredentialDeleteState, delete_linux_keyutils_credential,
                delete_linux_secret_service_credential,
            };

            let state = match self {
                Self::Keyutils => delete_linux_keyutils_credential(service, account),
                Self::SecretService => delete_linux_secret_service_credential(service, account),
            };
            match state {
                CredentialDeleteState::Deleted | CredentialDeleteState::Missing => Ok(()),
                CredentialDeleteState::Unavailable => Err(LegacyCredentialError::Unavailable),
            }
        }
    }

    impl LegacyCredentialDeleter for RecordingDeleteOnlyAdapter {
        fn delete_credential(
            &self,
            service: &str,
            account: &str,
        ) -> Result<(), LegacyCredentialError> {
            self.0
                .lock()
                .expect("delete calls")
                .push((service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    #[test]
    fn delete_only_contract_receives_every_exact_legacy_reference() {
        let adapter = RecordingDeleteOnlyAdapter::default();

        delete_legacy_typescript_credentials(&adapter, "My_agent-2").expect("delete legacy");

        assert_eq!(
            *adapter.0.lock().expect("delete calls"),
            [
                ("palladin".to_owned(), "My_agent-2:private-key".to_owned()),
                ("palladin".to_owned(), "My_agent-2:signing-key".to_owned()),
                ("claw-vault".to_owned(), "My_agent-2:private-key".to_owned()),
                ("claw-vault".to_owned(), "My_agent-2:signing-key".to_owned()),
            ]
        );
    }

    #[test]
    fn deletion_contract_requires_no_secret_read_api() {
        let adapter = RecordingDeleteOnlyAdapter::default();

        delete_legacy_typescript_credentials(&adapter, "default").expect("delete legacy");

        assert_eq!(adapter.0.lock().expect("delete calls").len(), 4);
    }

    #[test]
    fn rejects_empty_paths_and_non_ascii_profile_names_before_deletion() {
        for invalid in [
            "",
            ".",
            "../default",
            "team/agent",
            "team\\agent",
            "żółw",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let adapter = RecordingDeleteOnlyAdapter::default();
            assert_eq!(
                delete_legacy_typescript_credentials(&adapter, invalid),
                Err(LegacyCredentialError::InvalidProfile),
                "accepted invalid profile {invalid:?}"
            );
            assert!(adapter.0.lock().expect("delete calls").is_empty());
        }
    }

    #[test]
    fn accepts_the_complete_legacy_profile_alphabet() {
        let adapter = RecordingDeleteOnlyAdapter::default();

        delete_legacy_typescript_credentials(
            &adapter,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
        )
        .expect("valid legacy profile");

        assert_eq!(adapter.0.lock().expect("delete calls").len(), 4);
    }

    #[test]
    fn linux_cleanup_fails_closed_when_either_backend_is_unavailable() {
        use super::{CredentialDeleteState, linux_delete_outcome};

        for available in [
            CredentialDeleteState::Deleted,
            CredentialDeleteState::Missing,
        ] {
            assert_eq!(
                linux_delete_outcome(available, CredentialDeleteState::Unavailable),
                Err(LegacyCredentialError::Unavailable)
            );
            assert_eq!(
                linux_delete_outcome(CredentialDeleteState::Unavailable, available),
                Err(LegacyCredentialError::Unavailable)
            );
            assert_eq!(linux_delete_outcome(available, available), Ok(()));
        }
        assert_eq!(
            linux_delete_outcome(
                CredentialDeleteState::Deleted,
                CredentialDeleteState::Missing,
            ),
            Ok(())
        );
        assert_eq!(
            linux_delete_outcome(
                CredentialDeleteState::Missing,
                CredentialDeleteState::Deleted,
            ),
            Ok(())
        );
        assert_eq!(
            linux_delete_outcome(
                CredentialDeleteState::Unavailable,
                CredentialDeleteState::Unavailable,
            ),
            Err(LegacyCredentialError::Unavailable)
        );
    }

    #[test]
    #[ignore = "requires synthetic credentials seeded by the Node legacy keyring interop probe"]
    fn os_adapter_deletes_credentials_seeded_by_the_legacy_node_client() {
        let profile = env::var("PALLADIN_LEGACY_KEYRING_TEST_PROFILE")
            .expect("PALLADIN_LEGACY_KEYRING_TEST_PROFILE");

        #[cfg(target_os = "linux")]
        {
            let backend = match env::var("PALLADIN_LEGACY_KEYRING_TEST_BACKEND")
                .expect("PALLADIN_LEGACY_KEYRING_TEST_BACKEND")
                .as_str()
            {
                "keyutils" => LinuxInteropBackend::Keyutils,
                "secret-service" => LinuxInteropBackend::SecretService,
                value => panic!("unsupported Linux legacy keyring test backend: {value}"),
            };
            delete_legacy_typescript_credentials(&backend, &profile)
                .expect("delete Node-seeded legacy credentials");
        }

        #[cfg(not(target_os = "linux"))]
        delete_legacy_typescript_credentials(&OsLegacyCredentialDeleter, &profile)
            .expect("delete Node-seeded legacy credentials");
    }
}
