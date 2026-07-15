use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use secrecy::SecretSlice;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

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
    /// Random per-identity capability root, private to hardened macOS.
    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    InvocationAuthorizationSeedV2,
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
            #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
            Self::InvocationAuthorizationSeedV2 => "invocation-authorization-seed-v2",
            Self::LegacyOrganizationApiKeyV2 => "organization-api-key",
            Self::LegacyX25519PrivateKeyV2 => "x25519-private-key",
            Self::LegacyEd25519SecretKeyV2 => "ed25519-secret-key",
        }
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) const fn requires_user_presence(self) -> bool {
        matches!(
            self,
            Self::OrganizationApiKey
                | Self::X25519PrivateKey
                | Self::Ed25519SecretKey
                | Self::InvocationAuthorizationSeedV2
                | Self::LegacyOrganizationApiKeyV2
                | Self::LegacyX25519PrivateKeyV2
                | Self::LegacyEd25519SecretKeyV2
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
            Self::InvocationAuthorizationSeedV2 => "Palladin operation authorization",
            Self::LegacyOrganizationApiKeyV2 => "Legacy Palladin organization credential",
            Self::LegacyX25519PrivateKeyV2 => "Legacy Palladin Agent encryption identity",
            Self::LegacyEd25519SecretKeyV2 => "Legacy Palladin Agent signing identity",
        }
    }
}

const MAX_OPERATION_BINDING_BYTES: usize = 64 * 1024;
const MAX_OPERATION_ORGANIZATIONS: usize = 64;
const MAX_OPERATION_LEASE: Duration = Duration::from_secs(5 * 60);

/// The exact secret owners an approved operation may use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationScope {
    identity_owner: String,
    organization_owners: Vec<String>,
}

impl OperationScope {
    pub fn new<I, O>(identity_owner: I, organization_owners: O) -> Result<Self, StoreError>
    where
        I: Into<String>,
        O: IntoIterator,
        O::Item: Into<String>,
    {
        let identity_owner = identity_owner.into();
        if !valid_opaque_id(&identity_owner) {
            return Err(StoreError::InvalidOwner);
        }
        let organization_owners = organization_owners
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if organization_owners.len() > MAX_OPERATION_ORGANIZATIONS
            || organization_owners
                .iter()
                .any(|owner| !valid_opaque_id(owner))
        {
            return Err(StoreError::InvalidOwner);
        }
        Ok(Self {
            identity_owner,
            organization_owners: organization_owners.into_iter().collect(),
        })
    }

    #[must_use]
    pub fn identity_owner(&self) -> &str {
        &self.identity_owner
    }

    #[must_use]
    pub fn organization_owners(&self) -> &[String] {
        &self.organization_owners
    }

    fn allows(&self, owner_id: &str, slot: SecretSlot) -> bool {
        match slot {
            SecretSlot::X25519PrivateKey | SecretSlot::Ed25519SecretKey => {
                owner_id == self.identity_owner
            }
            SecretSlot::OrganizationApiKey => self
                .organization_owners
                .binary_search_by(|candidate| candidate.as_str().cmp(owner_id))
                .is_ok(),
            SecretSlot::IntegrityTrustStateV1
            | SecretSlot::VersionPolicyTrustStateV1
            | SecretSlot::LegacyOrganizationApiKeyV2
            | SecretSlot::LegacyX25519PrivateKeyV2
            | SecretSlot::LegacyEd25519SecretKeyV2 => false,
            #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
            SecretSlot::InvocationAuthorizationSeedV2 => false,
        }
    }
}

/// Runtime-owned operations with fixed, non-spoofable OS prompt copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationPrompt {
    Connect,
    Status,
    SearchEntries,
    GetCredential,
    ExecWithCredential,
    ReportCredentialStale,
    IdentityManagement,
    DestructiveIdentityManagement,
}

impl AuthorizationPrompt {
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Connect => "Allow Palladin to connect this Agent",
            Self::Status => "Allow Palladin to inspect Agent status",
            Self::SearchEntries => "Allow Palladin to search vault entries",
            Self::GetCredential => "Allow Palladin to retrieve a credential",
            Self::ExecWithCredential => "Allow Palladin to run a command with a credential",
            Self::ReportCredentialStale => "Allow Palladin to report a stale credential",
            Self::IdentityManagement => "Allow Palladin to manage this Agent identity",
            Self::DestructiveIdentityManagement => "Allow Palladin to remove this Agent identity",
        }
    }
}

#[derive(Debug)]
pub(crate) struct OperationLeaseState {
    process_id: u32,
    deadline: Instant,
    cancellation: CancellationToken,
    commit_state: AtomicU8,
}

impl OperationLeaseState {
    pub(crate) fn revoke(&self) {
        loop {
            match self.commit_state.load(Ordering::SeqCst) {
                COMMIT_ACTIVE => {
                    if self
                        .commit_state
                        .compare_exchange(
                            COMMIT_ACTIVE,
                            COMMIT_REVOKED,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        self.cancellation.cancel();
                        return;
                    }
                }
                COMMIT_PREPARING => {
                    if self
                        .commit_state
                        .compare_exchange(
                            COMMIT_PREPARING,
                            COMMIT_REVOKE_PENDING,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        self.cancellation.cancel();
                        return;
                    }
                }
                COMMIT_REVOKED | COMMIT_REVOKE_PENDING | COMMIT_SEALED => {
                    self.cancellation.cancel();
                    return;
                }
                _ => {
                    self.cancellation.cancel();
                    return;
                }
            }
        }
    }
}

const COMMIT_ACTIVE: u8 = 0;
const COMMIT_PREPARING: u8 = 1;
const COMMIT_REVOKED: u8 = 2;
const COMMIT_REVOKE_PENDING: u8 = 3;
const COMMIT_SEALED: u8 = 4;

/// A cloneable, thread-safe lifetime signal for work derived from one approval.
#[derive(Clone, Debug)]
pub struct OperationLease {
    state: Arc<OperationLeaseState>,
}

/// Linearizes one durable operation commit against lifecycle revocation.
///
/// The guard is intentionally opaque. Holding it authorizes only the journal
/// commit marker; recovery may finish an already committed transaction.
pub struct OperationCommitGuard<'a> {
    state: &'a OperationLeaseState,
    sealed: bool,
}

impl OperationCommitGuard<'_> {
    pub fn seal(&mut self) -> Result<(), StoreError> {
        if self.sealed
            || self.state.process_id != std::process::id()
            || Instant::now() >= self.state.deadline
            || self.state.cancellation.is_cancelled()
        {
            return Err(StoreError::AuthorizationFailed);
        }
        self.state
            .commit_state
            .compare_exchange(
                COMMIT_PREPARING,
                COMMIT_SEALED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| StoreError::AuthorizationFailed)?;
        self.sealed = true;
        Ok(())
    }
}

impl Drop for OperationCommitGuard<'_> {
    fn drop(&mut self) {
        let expected = if self.sealed {
            COMMIT_SEALED
        } else {
            COMMIT_PREPARING
        };
        if self
            .state
            .commit_state
            .compare_exchange(expected, COMMIT_ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
            && !self.sealed
        {
            let _ = self.state.commit_state.compare_exchange(
                COMMIT_REVOKE_PENDING,
                COMMIT_REVOKED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
    }
}

impl OperationLease {
    pub(crate) fn new(duration: Duration) -> Result<Self, StoreError> {
        if duration.is_zero() || duration > MAX_OPERATION_LEASE {
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(Self {
            state: Arc::new(OperationLeaseState {
                process_id: std::process::id(),
                deadline: Instant::now() + duration,
                cancellation: CancellationToken::new(),
                commit_state: AtomicU8::new(COMMIT_ACTIVE),
            }),
        })
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.state.cancellation.clone()
    }

    pub fn ensure_active(&self) -> Result<(), StoreError> {
        if self.state.process_id != std::process::id()
            || Instant::now() >= self.state.deadline
            || self.state.cancellation.is_cancelled()
        {
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<Duration, StoreError> {
        self.ensure_active()?;
        self.state
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(StoreError::AuthorizationFailed)
    }

    pub fn begin_commit(&self) -> Result<OperationCommitGuard<'_>, StoreError> {
        self.ensure_active()?;
        self.state
            .commit_state
            .compare_exchange(
                COMMIT_ACTIVE,
                COMMIT_PREPARING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| StoreError::AuthorizationFailed)?;
        let guard = OperationCommitGuard {
            state: &self.state,
            sealed: false,
        };
        if self.ensure_active().is_err() {
            drop(guard);
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(guard)
    }

    pub fn cancel(&self) {
        self.state.revoke();
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) fn weak_state(&self) -> std::sync::Weak<OperationLeaseState> {
        Arc::downgrade(&self.state)
    }
}

/// Non-serializable, non-cloneable authorization for one exact native
/// operation. On hardened macOS it owns the fresh LocalAuthentication context
/// and a MAC derived from the per-identity authorization seed.
pub struct OperationAuthorization {
    binding_digest: [u8; 32],
    scope: OperationScope,
    lease: OperationLease,
    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    macos: Option<crate::macos_hardened_store::MacOperationAuthorization>,
}

impl std::fmt::Debug for OperationAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationAuthorization")
            .field("binding", &"redacted")
            .field("scope", &"redacted")
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl OperationAuthorization {
    pub(crate) fn validate_binding(binding: &[u8]) -> Result<[u8; 32], StoreError> {
        if binding.is_empty() || binding.len() > MAX_OPERATION_BINDING_BYTES {
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(Sha256::digest(binding).into())
    }

    #[doc(hidden)]
    pub fn for_current_platform(
        scope: &OperationScope,
        binding: &[u8],
    ) -> Result<Self, StoreError> {
        Ok(Self {
            binding_digest: Self::validate_binding(binding)?,
            scope: scope.clone(),
            lease: OperationLease::new(MAX_OPERATION_LEASE)?,
            #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
            macos: None,
        })
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) fn macos(
        binding: &[u8],
        scope: OperationScope,
        lease: OperationLease,
        authorization: crate::macos_hardened_store::MacOperationAuthorization,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            binding_digest: Self::validate_binding(binding)?,
            scope,
            lease,
            macos: Some(authorization),
        })
    }

    #[must_use]
    pub fn matches(&self, binding: &[u8]) -> bool {
        if self.lease.ensure_active().is_err() {
            return false;
        }
        let candidate: [u8; 32] = Sha256::digest(binding).into();
        subtle::ConstantTimeEq::ct_eq(self.binding_digest.as_slice(), candidate.as_slice()).into()
    }

    #[doc(hidden)]
    pub fn ensure_read_allowed(
        &self,
        owner_id: &str,
        slot: SecretSlot,
        binding: &[u8],
    ) -> Result<(), StoreError> {
        if !self.matches(binding) || !self.scope.allows(owner_id, slot) {
            return Err(StoreError::AuthorizationFailed);
        }
        Ok(())
    }

    pub fn into_lease(self) -> Result<OperationLease, StoreError> {
        self.lease.ensure_active()?;
        Ok(self.lease.clone())
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) fn lease(&self) -> &OperationLease {
        &self.lease
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) fn scope(&self) -> &OperationScope {
        &self.scope
    }

    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    pub(crate) fn macos_authorization(
        &self,
    ) -> Option<&crate::macos_hardened_store::MacOperationAuthorization> {
        self.macos.as_ref()
    }
}

pub trait SecretStore {
    fn get(&self, owner_id: &str, slot: SecretSlot) -> Result<Option<SecretSlice<u8>>, StoreError>;
    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError>;

    fn requires_operation_authorization(&self) -> bool {
        false
    }

    fn initialize_operation_authorization(&self, identity_id: &str) -> Result<(), StoreError> {
        if !valid_opaque_id(identity_id) {
            return Err(StoreError::InvalidOwner);
        }
        Ok(())
    }

    fn authorize_operation(
        &self,
        scope: &OperationScope,
        _prompt: AuthorizationPrompt,
        binding: &[u8],
    ) -> Result<OperationAuthorization, StoreError> {
        OperationAuthorization::for_current_platform(scope, binding)
    }

    fn get_authorized(
        &self,
        owner_id: &str,
        slot: SecretSlot,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<Option<SecretSlice<u8>>, StoreError> {
        authorization.ensure_read_allowed(owner_id, slot, binding)?;
        self.get(owner_id, slot)
    }
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

    fn requires_operation_authorization(&self) -> bool {
        false
    }

    fn initialize_operation_authorization(&self, identity_id: &str) -> Result<(), StoreError> {
        if !valid_opaque_id(identity_id) {
            return Err(StoreError::InvalidOwner);
        }
        Ok(())
    }

    fn authorize_operation(
        &self,
        scope: &OperationScope,
        _prompt: AuthorizationPrompt,
        binding: &[u8],
    ) -> Result<OperationAuthorization, StoreError> {
        OperationAuthorization::for_current_platform(scope, binding)
    }

    fn get_authorized(
        &self,
        owner_id: &str,
        slot: SecretSlot,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<Option<SecretSlice<u8>>, StoreError> {
        authorization.ensure_read_allowed(owner_id, slot, binding)?;
        self.get(owner_id, slot)
    }
}

pub fn delete_identity<S: SecretStore>(store: &S, identity_id: &str) -> Result<(), StoreError> {
    store.delete(identity_id, SecretSlot::X25519PrivateKey)?;
    store.delete(identity_id, SecretSlot::Ed25519SecretKey)?;
    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    store.delete(identity_id, SecretSlot::InvocationAuthorizationSeedV2)?;
    Ok(())
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
    #[error("fresh operating-system authorization is required for this operation")]
    AuthorizationFailed,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{
        AuthorizationPrompt, MAX_OPERATION_LEASE, MAX_OPERATION_ORGANIZATIONS,
        OperationAuthorization, OperationLease, OperationScope, SecretSlot, SecretStore,
        StoreError, delete_identity, delete_organization_credential,
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

        fn requires_operation_authorization(&self) -> bool {
            false
        }

        fn initialize_operation_authorization(&self, identity_id: &str) -> Result<(), StoreError> {
            if !super::valid_opaque_id(identity_id) {
                return Err(StoreError::InvalidOwner);
            }
            Ok(())
        }

        fn authorize_operation(
            &self,
            scope: &OperationScope,
            _prompt: AuthorizationPrompt,
            binding: &[u8],
        ) -> Result<OperationAuthorization, StoreError> {
            OperationAuthorization::for_current_platform(scope, binding)
        }

        fn get_authorized(
            &self,
            owner_id: &str,
            slot: SecretSlot,
            authorization: &OperationAuthorization,
            binding: &[u8],
        ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
            authorization.ensure_read_allowed(owner_id, slot, binding)?;
            self.get(owner_id, slot)
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

    #[test]
    fn operation_scope_is_validated_sorted_and_deduplicated() {
        let identity = "11111111111111111111111111111111";
        let first = "22222222222222222222222222222222";
        let second = "33333333333333333333333333333333";
        let scope = OperationScope::new(identity, [second, first, second]).expect("scope");
        assert_eq!(scope.identity_owner(), identity);
        assert_eq!(
            scope.organization_owners(),
            &[first.to_owned(), second.to_owned()]
        );
        assert!(OperationScope::new("invalid", [first]).is_err());
        assert!(OperationScope::new(identity, ["INVALID"]).is_err());

        let too_many = (0..=MAX_OPERATION_ORGANIZATIONS)
            .map(|value| format!("{value:032x}"))
            .collect::<Vec<_>>();
        assert!(OperationScope::new(identity, too_many).is_err());
    }

    #[test]
    fn authorization_is_bound_to_scope_slot_binding_and_process_lease() {
        let identity = "11111111111111111111111111111111";
        let organization = "22222222222222222222222222222222";
        let other = "33333333333333333333333333333333";
        let scope = OperationScope::new(identity, [organization]).expect("scope");
        let authorization =
            OperationAuthorization::for_current_platform(&scope, b"binding").expect("auth");

        assert!(
            authorization
                .ensure_read_allowed(identity, SecretSlot::X25519PrivateKey, b"binding")
                .is_ok()
        );
        assert!(
            authorization
                .ensure_read_allowed(organization, SecretSlot::OrganizationApiKey, b"binding")
                .is_ok()
        );
        assert!(
            authorization
                .ensure_read_allowed(other, SecretSlot::OrganizationApiKey, b"binding")
                .is_err()
        );
        assert!(
            authorization
                .ensure_read_allowed(identity, SecretSlot::OrganizationApiKey, b"binding")
                .is_err()
        );
        assert!(
            authorization
                .ensure_read_allowed(identity, SecretSlot::Ed25519SecretKey, b"different")
                .is_err()
        );

        let lease = authorization.into_lease().expect("lease");
        lease.cancel();
        assert_eq!(lease.ensure_active(), Err(StoreError::AuthorizationFailed));
        assert!(lease.cancellation_token().is_cancelled());
    }

    #[test]
    fn lease_rejects_zero_and_more_than_five_minutes() {
        assert!(OperationLease::new(std::time::Duration::ZERO).is_err());
        assert!(OperationLease::new(MAX_OPERATION_LEASE).is_ok());
        assert!(
            OperationLease::new(MAX_OPERATION_LEASE + std::time::Duration::from_nanos(1)).is_err()
        );
    }

    #[test]
    fn durable_commit_linearizes_against_revocation() {
        let lease = OperationLease::new(MAX_OPERATION_LEASE).expect("lease");
        let mut guard = lease.begin_commit().expect("commit guard");
        let cancellation = lease.cancellation_token();
        let revoking = lease.clone();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            revoking.cancel();
            finished_tx.send(()).expect("finished");
        });

        finished_rx.recv().expect("revocation finished");
        task.join().expect("revocation task");
        assert!(cancellation.is_cancelled());
        assert!(guard.seal().is_err());
        drop(guard);
        assert!(lease.begin_commit().is_err());

        let committed = OperationLease::new(MAX_OPERATION_LEASE).expect("committed lease");
        let mut committed_guard = committed.begin_commit().expect("committed guard");
        committed_guard.seal().expect("seal commit");
        committed.cancel();
        assert!(committed.cancellation_token().is_cancelled());
        drop(committed_guard);
        assert!(committed.begin_commit().is_err());
    }

    #[test]
    fn authorization_rejects_empty_and_oversized_bindings() {
        let scope = OperationScope::new(
            "11111111111111111111111111111111",
            std::iter::empty::<String>(),
        )
        .expect("scope");
        assert!(OperationAuthorization::for_current_platform(&scope, b"").is_err());
        assert!(
            OperationAuthorization::for_current_platform(
                &scope,
                &vec![0_u8; super::MAX_OPERATION_BINDING_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn prompt_reasons_are_fixed_runtime_copy() {
        assert_eq!(
            AuthorizationPrompt::GetCredential.reason(),
            "Allow Palladin to retrieve a credential"
        );
        assert!(!AuthorizationPrompt::ExecWithCredential.reason().is_empty());
    }
}
