use secrecy::SecretSlice;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::errSecItemNotFound;

use crate::secure_store::{SecretSlot, SecretStore, StoreError, account_name, valid_opaque_id};

const SERVICE: &str = "io.palladin.runtime";
const ACCESS_GROUP_SUFFIX: &str = ".io.palladin.runtime";
const ACCESS_GROUP: &str = env!(
    "PALLADIN_KEYCHAIN_ACCESS_GROUP",
    "macos-hardened builds require PALLADIN_KEYCHAIN_ACCESS_GROUP at compile time"
);
#[used]
static ACCESS_GROUP_BUILD_MARKER: &str = concat!(
    "\0PALLADIN_KEYCHAIN_ACCESS_GROUP=",
    env!("PALLADIN_KEYCHAIN_ACCESS_GROUP"),
    "\0"
);

/// Data Protection Keychain storage for the signed Palladin macOS app bundle.
///
/// The access group is embedded at compile time. It cannot be selected by the
/// parent Node process, a config file, or the runtime environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacHardenedSecretStore;

impl SecretStore for MacHardenedSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        let options = query(owner_id, slot, false)?;
        match generic_password(options) {
            Ok(secret) => Ok(Some(secret.into())),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(_) => Err(StoreError::Unavailable),
        }
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        if secret.is_empty() {
            return Err(StoreError::InvalidSecret);
        }
        let options = query(owner_id, slot, true)?;
        set_generic_password_options(secret, options).map_err(|_| StoreError::Unavailable)
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        let options = query(owner_id, slot, false)?;
        match delete_generic_password_options(options) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(_) => Err(StoreError::Unavailable),
        }
    }
}

fn query(
    owner_id: &str,
    slot: SecretSlot,
    include_access_control: bool,
) -> Result<PasswordOptions, StoreError> {
    if !valid_opaque_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    if !valid_access_group(ACCESS_GROUP) {
        return Err(StoreError::InvalidConfiguration);
    }
    if !runtime_is_hardened() {
        return Err(StoreError::Unavailable);
    }

    let account = account_name(owner_id, slot);
    let mut options = PasswordOptions::new_generic_password(SERVICE, &account);
    options.use_protected_keychain();
    options.set_access_group(ACCESS_GROUP);
    options.set_access_synchronized(Some(false));

    if include_access_control {
        options.set_label(slot.keychain_label());
        options.set_description("Palladin native Agent runtime secret");
        let flags = if slot.requires_user_presence() {
            AccessControlOptions::USER_PRESENCE.bits()
        } else {
            0
        };
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        )
        .map_err(|_| StoreError::Unavailable)?;
        options.set_access_control(access_control);
    }
    Ok(options)
}

pub(crate) fn runtime_is_hardened() -> bool {
    if !valid_access_group(ACCESS_GROUP) {
        return false;
    }
    let requirement = hardened_requirement(ACCESS_GROUP);
    let Ok(requirement) = requirement.parse::<SecRequirement>() else {
        return false;
    };
    let Ok(code) = SecCode::for_self(Flags::NONE) else {
        return false;
    };
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::CHECK_NESTED_CODE,
        &requirement,
    )
    .is_ok()
}

fn hardened_requirement(access_group: &str) -> String {
    debug_assert!(valid_access_group(access_group));
    let team_id = &access_group[..10];
    let application_identifier = format!("{team_id}.io.palladin.runtime");
    format!(
        "identifier \"io.palladin.runtime\" and anchor apple generic and certificate leaf[subject.OU] = \"{team_id}\" and entitlement[\"com.apple.application-identifier\"] = \"{application_identifier}\" and entitlement[\"keychain-access-groups\"] = \"{access_group}\" and not entitlement[\"com.apple.security.get-task-allow\"] exists"
    )
}

fn valid_access_group(value: &str) -> bool {
    let Some(team_id) = value.strip_suffix(ACCESS_GROUP_SUFFIX) else {
        return false;
    };
    team_id.len() == 10
        && team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && !value.contains('*')
}

#[cfg(test)]
mod tests {
    use super::{ACCESS_GROUP_SUFFIX, hardened_requirement, valid_access_group};
    use crate::secure_store::SecretSlot;

    #[test]
    fn access_group_is_exact_and_team_scoped() {
        assert!(valid_access_group(&format!(
            "A1B2C3D4E5{ACCESS_GROUP_SUFFIX}"
        )));
        assert!(!valid_access_group("io.palladin.runtime"));
        assert!(!valid_access_group("A1B2C3D4E5.*"));
        assert!(!valid_access_group(&format!("short{ACCESS_GROUP_SUFFIX}")));
        assert!(!valid_access_group(&format!(
            "a1b2c3d4e5{ACCESS_GROUP_SUFFIX}"
        )));
    }

    #[test]
    fn organization_credential_gates_use_with_user_presence() {
        assert!(SecretSlot::OrganizationApiKey.requires_user_presence());
        assert!(!SecretSlot::X25519PrivateKey.requires_user_presence());
        assert!(!SecretSlot::Ed25519SecretKey.requires_user_presence());
        assert_eq!(
            SecretSlot::OrganizationApiKey.keychain_label(),
            "Palladin organization credential"
        );
    }

    #[test]
    fn signing_requirement_binds_the_exact_access_group() {
        let requirement = hardened_requirement("A1B2C3D4E5.io.palladin.runtime");
        assert!(requirement.contains(
            "entitlement[\"keychain-access-groups\"] = \"A1B2C3D4E5.io.palladin.runtime\""
        ));
        assert!(requirement.contains(
            "entitlement[\"com.apple.application-identifier\"] = \"A1B2C3D4E5.io.palladin.runtime\""
        ));
        assert!(!requirement.contains("keychain-access-groups\"] exists"));
    }
}
