use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretSlice};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::errSecItemNotFound;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::macos_local_authentication::FreshLocalAuthenticationContext;
use crate::secure_store::{
    AuthorizationPrompt, OperationAuthorization, OperationLease, OperationScope, SecretSlot,
    SecretStore, StoreError, account_name, valid_opaque_id,
};

const LEGACY_SERVICE: &str = "io.palladin.runtime";
const IDENTITY_SERVICE_V2: &str = "io.palladin.runtime.session-v2.identity";
const STATE_SERVICE_V2: &str = "io.palladin.runtime.session-v2.state";
const ACCESS_GROUP_SUFFIX: &str = ".io.palladin.runtime.session-v2";
const CAPABILITY_DOMAIN: &[u8] = b"palladin.operation-authorization.v2\0";
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

pub(crate) struct MacOperationAuthorization {
    context: FreshLocalAuthenticationContext,
    seed: SecretSlice<u8>,
    nonce: [u8; 32],
    tag: [u8; 32],
}

impl MacOperationAuthorization {
    fn new(
        context: FreshLocalAuthenticationContext,
        seed: SecretSlice<u8>,
        scope: &OperationScope,
        binding: &[u8],
    ) -> Result<Self, StoreError> {
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| StoreError::Unavailable)?;
        let tag = capability_tag(
            seed.expose_secret(),
            scope,
            std::process::id(),
            binding,
            &nonce,
        )?;
        Ok(Self {
            context,
            seed,
            nonce,
            tag,
        })
    }

    fn matches(&self, scope: &OperationScope, binding: &[u8]) -> bool {
        let Ok(candidate) = capability_tag(
            self.seed.expose_secret(),
            scope,
            std::process::id(),
            binding,
            &self.nonce,
        ) else {
            return false;
        };
        self.tag.as_slice().ct_eq(candidate.as_slice()).into()
    }
}

fn capability_tag(
    seed: &[u8],
    scope: &OperationScope,
    process_id: u32,
    binding: &[u8],
    nonce: &[u8; 32],
) -> Result<[u8; 32], StoreError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(seed).map_err(|_| StoreError::AuthorizationFailed)?;
    mac.update(CAPABILITY_DOMAIN);
    mac.update(&process_id.to_be_bytes());
    mac.update(scope.identity_owner().as_bytes());
    mac.update(&(scope.organization_owners().len() as u32).to_be_bytes());
    for owner in scope.organization_owners() {
        mac.update(owner.as_bytes());
    }
    let binding_digest: [u8; 32] = Sha256::digest(binding).into();
    mac.update(&binding_digest);
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().into())
}

impl SecretStore for MacHardenedSecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError> {
        if !direct_read_allowed(slot) {
            return Err(StoreError::AuthorizationFailed);
        }
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

    fn requires_operation_authorization(&self) -> bool {
        true
    }

    fn initialize_operation_authorization(&self, identity_id: &str) -> Result<(), StoreError> {
        validate_query(identity_id)?;
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| StoreError::Unavailable)?;
        let result = self.set(
            identity_id,
            SecretSlot::InvocationAuthorizationSeedV2,
            &seed,
        );
        seed.zeroize();
        result
    }

    fn authorize_operation(
        &self,
        scope: &OperationScope,
        prompt: AuthorizationPrompt,
        binding: &[u8],
    ) -> Result<OperationAuthorization, StoreError> {
        OperationAuthorization::validate_binding(binding)?;
        validate_query(scope.identity_owner())?;
        let lease = OperationLease::new(std::time::Duration::from_secs(5 * 60))?;
        crate::macos_lifecycle::register(&lease);
        let context = FreshLocalAuthenticationContext::new(prompt.reason());
        let seed = authorized_password(
            scope.identity_owner(),
            SecretSlot::InvocationAuthorizationSeedV2,
            &context,
        )?
        .ok_or(StoreError::AuthorizationFailed)?;
        lease.ensure_active()?;
        if seed.expose_secret().len() != 32 {
            return Err(StoreError::AuthorizationFailed);
        }
        let authorization = MacOperationAuthorization::new(context, seed, scope, binding)?;
        OperationAuthorization::macos(binding, scope.clone(), lease, authorization)
    }

    fn get_authorized(
        &self,
        owner_id: &str,
        slot: SecretSlot,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<Option<SecretSlice<u8>>, StoreError> {
        authorization.ensure_read_allowed(owner_id, slot, binding)?;
        let macos = authorization
            .macos_authorization()
            .ok_or(StoreError::AuthorizationFailed)?;
        if !macos.matches(authorization.scope(), binding) {
            return Err(StoreError::AuthorizationFailed);
        }
        let secret = authorized_password(owner_id, slot, &macos.context)?;
        authorization.lease().ensure_active()?;
        if !macos.matches(authorization.scope(), binding) {
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(secret)
    }
}

fn direct_read_allowed(slot: SecretSlot) -> bool {
    matches!(
        slot,
        SecretSlot::IntegrityTrustStateV1 | SecretSlot::VersionPolicyTrustStateV1
    )
}

fn service_for(slot: SecretSlot) -> &'static str {
    match slot {
        SecretSlot::OrganizationApiKey
        | SecretSlot::X25519PrivateKey
        | SecretSlot::Ed25519SecretKey
        | SecretSlot::InvocationAuthorizationSeedV2 => IDENTITY_SERVICE_V2,
        SecretSlot::IntegrityTrustStateV1 | SecretSlot::VersionPolicyTrustStateV1 => {
            STATE_SERVICE_V2
        }
        SecretSlot::LegacyOrganizationApiKeyV2
        | SecretSlot::LegacyX25519PrivateKeyV2
        | SecretSlot::LegacyEd25519SecretKeyV2 => LEGACY_SERVICE,
    }
}

fn validate_query(owner_id: &str) -> Result<(), StoreError> {
    if !valid_opaque_id(owner_id) {
        return Err(StoreError::InvalidOwner);
    }
    if !valid_access_group(ACCESS_GROUP) {
        return Err(StoreError::InvalidConfiguration);
    }
    if !runtime_is_hardened() {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

fn authorized_password(
    owner_id: &str,
    slot: SecretSlot,
    context: &FreshLocalAuthenticationContext,
) -> Result<Option<SecretSlice<u8>>, StoreError> {
    validate_query(owner_id)?;
    let mut options = ItemSearchOptions::new();
    options
        .ignore_legacy_keychains()
        .class(ItemClass::generic_password())
        .service(service_for(slot))
        .account(&account_name(owner_id, slot))
        .access_group(ACCESS_GROUP)
        .cloud_sync(Some(false))
        .load_data(true)
        .limit(1_i64);
    context.bind(&mut options);
    match options.search() {
        Ok(mut results) if results.len() == 1 => match results.pop() {
            Some(SearchResult::Data(secret)) if !secret.is_empty() => Ok(Some(secret.into())),
            _ => Err(StoreError::Unavailable),
        },
        Ok(_) => Err(StoreError::Unavailable),
        Err(error) if error.code() == errSecItemNotFound => Ok(None),
        Err(_) => Err(StoreError::AuthorizationFailed),
    }
}

fn query(
    owner_id: &str,
    slot: SecretSlot,
    include_access_control: bool,
) -> Result<PasswordOptions, StoreError> {
    validate_query(owner_id)?;

    let account = account_name(owner_id, slot);
    let mut options = PasswordOptions::new_generic_password(service_for(slot), &account);
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
    use super::{
        ACCESS_GROUP_SUFFIX, IDENTITY_SERVICE_V2, STATE_SERVICE_V2, capability_tag,
        direct_read_allowed, hardened_requirement, service_for, valid_access_group,
    };
    use crate::secure_store::{OperationScope, SecretSlot};

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
        assert!(SecretSlot::InvocationAuthorizationSeedV2.requires_user_presence());
        assert!(SecretSlot::LegacyOrganizationApiKeyV2.requires_user_presence());
        assert!(!SecretSlot::IntegrityTrustStateV1.requires_user_presence());
        assert!(!SecretSlot::VersionPolicyTrustStateV1.requires_user_presence());
        assert!(SecretSlot::X25519PrivateKey.requires_user_presence());
        assert!(SecretSlot::Ed25519SecretKey.requires_user_presence());
        assert_eq!(
            SecretSlot::OrganizationApiKey.keychain_label(),
            "Palladin organization credential"
        );
    }

    #[test]
    fn signing_requirement_binds_the_exact_access_group() {
        let access_group = format!("A1B2C3D4E5{ACCESS_GROUP_SUFFIX}");
        let requirement = hardened_requirement(&access_group);
        assert!(requirement.contains(
            "entitlement[\"keychain-access-groups\"] = \"A1B2C3D4E5.io.palladin.runtime.session-v2\""
        ));
        assert!(requirement.contains(
            "entitlement[\"com.apple.application-identifier\"] = \"A1B2C3D4E5.io.palladin.runtime\""
        ));
        assert!(!requirement.contains("keychain-access-groups\"] exists"));
    }

    #[test]
    fn direct_reads_expose_only_non_secret_trust_state() {
        assert!(direct_read_allowed(SecretSlot::IntegrityTrustStateV1));
        assert!(direct_read_allowed(SecretSlot::VersionPolicyTrustStateV1));
        for slot in [
            SecretSlot::OrganizationApiKey,
            SecretSlot::X25519PrivateKey,
            SecretSlot::Ed25519SecretKey,
            SecretSlot::InvocationAuthorizationSeedV2,
            SecretSlot::LegacyOrganizationApiKeyV2,
            SecretSlot::LegacyX25519PrivateKeyV2,
            SecretSlot::LegacyEd25519SecretKeyV2,
        ] {
            assert!(!direct_read_allowed(slot));
        }
    }

    #[test]
    fn current_secrets_use_fresh_session_v2_namespaces() {
        assert_eq!(
            service_for(SecretSlot::X25519PrivateKey),
            IDENTITY_SERVICE_V2
        );
        assert_eq!(
            service_for(SecretSlot::OrganizationApiKey),
            IDENTITY_SERVICE_V2
        );
        assert_eq!(
            service_for(SecretSlot::IntegrityTrustStateV1),
            STATE_SERVICE_V2
        );
        assert!(IDENTITY_SERVICE_V2.contains("session-v2"));
        assert!(ACCESS_GROUP_SUFFIX.ends_with("session-v2"));
    }

    #[test]
    fn capability_tag_binds_process_scope_binding_and_nonce() {
        let identity = "11111111111111111111111111111111";
        let organization = "22222222222222222222222222222222";
        let other_organization = "33333333333333333333333333333333";
        let scope = OperationScope::new(identity, [organization]).expect("scope");
        let other_scope = OperationScope::new(identity, [other_organization]).expect("other scope");
        let seed = [7_u8; 32];
        let nonce = [9_u8; 32];
        let expected = capability_tag(&seed, &scope, 123, b"binding", &nonce).expect("tag");

        assert_ne!(
            expected,
            capability_tag(&seed, &scope, 124, b"binding", &nonce).expect("PID tag")
        );
        assert_ne!(
            expected,
            capability_tag(&seed, &other_scope, 123, b"binding", &nonce).expect("scope tag")
        );
        assert_ne!(
            expected,
            capability_tag(&seed, &scope, 123, b"other", &nonce).expect("binding tag")
        );
        assert_ne!(
            expected,
            capability_tag(&seed, &scope, 123, b"binding", &[8_u8; 32]).expect("nonce tag")
        );
    }
}
