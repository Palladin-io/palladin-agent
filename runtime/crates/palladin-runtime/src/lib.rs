#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod integrity;
pub mod version_policy;

use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_api::{
    AgentRegistrationResult, ApiClient, ApiError, CredentialAccess, CredentialMethod,
    EntrySearchResult, GetCredentialOptions, ReportCredentialStaleInput,
};
use palladin_core::host::ApiHost;
use palladin_core::legacy_typescript::{LegacyTypeScriptError, LegacyTypeScriptRepository};
use palladin_core::profiles::{
    ProfileError, ProfileName, ProfileRepository, add_profile, delete_profile, purge_profile,
    rename_profile, set_default, set_profile_type,
};
use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
    profile_binding_bytes, profile_config_digest, registry_digest,
};
use palladin_core::secret::OrganizationApiKey;
use palladin_credential::wait::{
    HeartbeatInfo, WaitError, WaitHints, WaitOptions, WaitPolicyError, await_grant,
    resolve_wait_policy,
};
use palladin_crypto::{
    DecryptedCredential, Ed25519Identity, X25519Identity, decrypt_credential,
    verify_profile_binding,
};
use palladin_exec::{
    EnvironmentError, SecretEnvironment, resolve_interpreter, run_command, run_script,
    validate_command, validate_reference_name,
};
pub use palladin_platform::secure_store::SecretStore;
use palladin_platform::secure_store::{
    AuthorizationPrompt, OperationAuthorization, OperationLease, OperationScope, SecretSlot,
    StoreError, delete_identity, delete_legacy_identity, delete_legacy_organization_credential,
    delete_organization_credential,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use integrity::{
    ConfigWrite, IntegrityJournal, SecretAllocation, SecretCopy, SecretDeletion, TRUST_OWNER_ID,
    TrustState, decode_trust_state, encode_trust_state, journal_path, load_journal, remove_journal,
    save_journal,
};

use palladin_credential::fields::{FieldSelector, resolve_field};
use palladin_credential::secret::{ScriptPayload, parse_secret};

pub use palladin_exec::{ExecError, ExecResult, OperatorOutput};

pub struct RuntimeService<S> {
    repository: ProfileRepository,
    secrets: S,
}

const OPERATION_BINDING_DOMAIN: &[u8] = b"palladin.runtime.exact-operation.v1";
const OPERATION_TTL_MS: i128 = 300_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOperation {
    Connect,
    Status,
    SearchEntries,
    GetCredential,
    ExecWithCredential,
    ReportCredentialStale,
    VerifyIdentity,
    DeleteProfile,
    PurgeProfile,
    PurgeAll,
    UpgradeSecurity,
}

impl RuntimeOperation {
    const fn protocol_name(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Status => "status",
            Self::SearchEntries => "search_entries",
            Self::GetCredential => "get_credential",
            Self::ExecWithCredential => "exec_with_credential",
            Self::ReportCredentialStale => "report_credential_stale",
            Self::VerifyIdentity => "verify_identity",
            Self::DeleteProfile => "delete_profile",
            Self::PurgeProfile => "purge_profile",
            Self::PurgeAll => "purge_all",
            Self::UpgradeSecurity => "upgrade_security",
        }
    }

    const fn authorization_prompt(self) -> AuthorizationPrompt {
        match self {
            Self::Connect => AuthorizationPrompt::Connect,
            Self::Status => AuthorizationPrompt::Status,
            Self::SearchEntries => AuthorizationPrompt::SearchEntries,
            Self::GetCredential => AuthorizationPrompt::GetCredential,
            Self::ExecWithCredential => AuthorizationPrompt::ExecWithCredential,
            Self::ReportCredentialStale => AuthorizationPrompt::ReportCredentialStale,
            Self::VerifyIdentity | Self::UpgradeSecurity => AuthorizationPrompt::IdentityManagement,
            Self::DeleteProfile | Self::PurgeProfile | Self::PurgeAll => {
                AuthorizationPrompt::DestructiveIdentityManagement
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationSurface {
    Cli,
    Mcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialOutputPolicy {
    CliSecretStdout,
    McpSecretResponse,
    CliChildProcess,
    McpChildProcessWithheld,
}

pub enum OperationDescriptor {
    Connect {
        host: String,
        display_name: Option<String>,
        agent_type: Option<String>,
        api_key_digest: [u8; 32],
    },
    Status,
    SearchEntries {
        surface: InvocationSurface,
        query: String,
        cursor: Option<String>,
        page_size: Option<u32>,
    },
    GetCredential {
        surface: InvocationSurface,
        vault_id: String,
        entry_id: String,
        reason: Option<String>,
        wait: WaitOptions,
        field: Option<String>,
        field_id: Option<String>,
        output: CredentialOutputPolicy,
    },
    ExecWithCredential {
        surface: InvocationSurface,
        vault_id: String,
        entry_id: String,
        reason: Option<String>,
        wait: WaitOptions,
        command: Vec<String>,
        env_mappings: Vec<String>,
        output: CredentialOutputPolicy,
    },
    ReportCredentialStale {
        surface: InvocationSurface,
        vault_id: String,
        entry_id: String,
        code: String,
        note: Option<String>,
    },
    VerifyIdentity,
    DeleteProfile,
    PurgeProfile,
    PurgeAll,
    UpgradeSecurity,
}

impl std::fmt::Debug for OperationDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationDescriptor")
            .field("operation", &self.operation())
            .field("arguments", &"redacted")
            .finish_non_exhaustive()
    }
}

impl OperationDescriptor {
    #[must_use]
    pub const fn operation(&self) -> RuntimeOperation {
        match self {
            Self::Connect { .. } => RuntimeOperation::Connect,
            Self::Status => RuntimeOperation::Status,
            Self::SearchEntries { .. } => RuntimeOperation::SearchEntries,
            Self::GetCredential { .. } => RuntimeOperation::GetCredential,
            Self::ExecWithCredential { .. } => RuntimeOperation::ExecWithCredential,
            Self::ReportCredentialStale { .. } => RuntimeOperation::ReportCredentialStale,
            Self::VerifyIdentity => RuntimeOperation::VerifyIdentity,
            Self::DeleteProfile => RuntimeOperation::DeleteProfile,
            Self::PurgeProfile => RuntimeOperation::PurgeProfile,
            Self::PurgeAll => RuntimeOperation::PurgeAll,
            Self::UpgradeSecurity => RuntimeOperation::UpgradeSecurity,
        }
    }

    fn digest(&self) -> [u8; 32] {
        let mut encoder = BindingEncoder::new(b"descriptor");
        encoder.field(self.operation().protocol_name().as_bytes());
        match self {
            Self::Connect {
                host,
                display_name,
                agent_type,
                api_key_digest,
            } => {
                encoder.field(host.as_bytes());
                encoder.optional(display_name.as_deref());
                encoder.optional(agent_type.as_deref());
                encoder.field(api_key_digest);
            }
            Self::Status
            | Self::VerifyIdentity
            | Self::DeleteProfile
            | Self::PurgeProfile
            | Self::PurgeAll
            | Self::UpgradeSecurity => {}
            Self::SearchEntries {
                surface,
                query,
                cursor,
                page_size,
            } => {
                encoder.surface(*surface);
                encoder.field(query.as_bytes());
                encoder.optional(cursor.as_deref());
                encoder.optional_u64(page_size.map(u64::from));
            }
            Self::GetCredential {
                surface,
                vault_id,
                entry_id,
                reason,
                wait,
                field,
                field_id,
                output,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.optional(reason.as_deref());
                encoder.wait(*wait);
                encoder.optional(field.as_deref());
                encoder.optional(field_id.as_deref());
                encoder.output(*output);
            }
            Self::ExecWithCredential {
                surface,
                vault_id,
                entry_id,
                reason,
                wait,
                command,
                env_mappings,
                output,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.optional(reason.as_deref());
                encoder.wait(*wait);
                encoder.strings(command);
                encoder.strings(env_mappings);
                encoder.output(*output);
            }
            Self::ReportCredentialStale {
                surface,
                vault_id,
                entry_id,
                code,
                note,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.field(code.as_bytes());
                encoder.optional(note.as_deref());
            }
        }
        encoder.finish()
    }
}

pub struct OperationConnection {
    nonce: [u8; 32],
    lifecycle_epoch: [u8; 32],
    next_sequence: AtomicU64,
}

impl std::fmt::Debug for OperationConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationConnection")
            .field("binding", &"redacted")
            .finish_non_exhaustive()
    }
}

impl OperationConnection {
    pub fn new() -> Result<Self, RuntimeError> {
        let mut nonce = [0_u8; 32];
        let mut lifecycle_epoch = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| RuntimeError::RandomGenerationFailed)?;
        getrandom::fill(&mut lifecycle_epoch).map_err(|_| RuntimeError::RandomGenerationFailed)?;
        Ok(Self {
            nonce,
            lifecycle_epoch,
            next_sequence: AtomicU64::new(1),
        })
    }

    fn request(&self, descriptor: &OperationDescriptor) -> Result<OperationRequest, RuntimeError> {
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RuntimeError::OperationSequenceExhausted)?;
        OperationRequest::new(descriptor, self.nonce, sequence, self.lifecycle_epoch)
    }
}

/// Exact bounded input for one native identity operation. Semantic arguments
/// are reduced to a digest immediately and never enter diagnostics.
struct OperationRequest {
    operation: RuntimeOperation,
    request_digest: [u8; 32],
    connection_nonce: [u8; 32],
    sequence: u64,
    lifecycle_epoch: [u8; 32],
    process_id: u32,
    not_after_unix_ms: i128,
}

impl std::fmt::Debug for OperationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationRequest")
            .field("operation", &self.operation)
            .field("request", &"redacted")
            .field("sequence", &self.sequence)
            .field("lifecycle_epoch", &"redacted")
            .finish_non_exhaustive()
    }
}

impl OperationRequest {
    fn new(
        descriptor: &OperationDescriptor,
        connection_nonce: [u8; 32],
        sequence: u64,
        lifecycle_epoch: [u8; 32],
    ) -> Result<Self, RuntimeError> {
        if sequence == 0 {
            return Err(RuntimeError::OperationSequenceExhausted);
        }
        let not_after_unix_ms = OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .checked_div(1_000_000)
            .and_then(|now| now.checked_add(OPERATION_TTL_MS))
            .ok_or(RuntimeError::OperationAuthorizationExpired)?;
        Ok(Self {
            operation: descriptor.operation(),
            request_digest: descriptor.digest(),
            connection_nonce,
            sequence,
            lifecycle_epoch,
            process_id: std::process::id(),
            not_after_unix_ms,
        })
    }

    fn binding(
        &self,
        state: &VerifiedState,
        profile: &PublicAgentEntry,
        config: Option<&PublicProfileConfig>,
        hostname: &str,
        organization_owners: &[String],
    ) -> Vec<u8> {
        let mut encoder = BindingEncoder::new(OPERATION_BINDING_DOMAIN);
        encoder.field(env!("CARGO_PKG_VERSION").as_bytes());
        encoder.field(
            option_env!("SOURCE_SHA")
                .unwrap_or("development")
                .as_bytes(),
        );
        encoder.field(&self.process_id.to_be_bytes());
        encoder.field(&self.connection_nonce);
        encoder.field(&self.sequence.to_be_bytes());
        encoder.field(&self.lifecycle_epoch);
        encoder.field(&self.not_after_unix_ms.to_be_bytes());
        encoder.field(&state.generation.to_be_bytes());
        encoder.field(state.registry_digest.as_bytes());
        encoder.field(profile.name.as_bytes());
        encoder.field(profile.identity_id.as_bytes());
        encoder.optional(profile.config_digest.as_deref());
        encoder.optional(config.map(|value| value.host.as_str()));
        encoder.field(hostname.as_bytes());
        encoder.strings(organization_owners);
        encoder.field(self.operation.protocol_name().as_bytes());
        encoder.field(&self.request_digest);
        encoder.into_bytes()
    }
}

struct BindingEncoder {
    bytes: Vec<u8>,
}

impl BindingEncoder {
    fn new(domain: &[u8]) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.field(domain);
        encoder
    }

    fn field(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    fn optional(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.field(&[1]);
                self.field(value.as_bytes());
            }
            None => self.field(&[0]),
        }
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.field(&[1]);
                self.field(&value.to_be_bytes());
            }
            None => self.field(&[0]),
        }
    }

    fn strings(&mut self, values: &[String]) {
        self.field(
            &u64::try_from(values.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for value in values {
            self.field(value.as_bytes());
        }
    }

    fn wait(&mut self, wait: WaitOptions) {
        self.optional_u64(wait.wait_ms);
        self.optional_u64(wait.poll_ms);
        self.field(&[match wait.progress {
            None => 0,
            Some(palladin_credential::wait::ProgressMode::Plain) => 1,
            Some(palladin_credential::wait::ProgressMode::Json) => 2,
            Some(palladin_credential::wait::ProgressMode::None) => 3,
        }]);
    }

    fn surface(&mut self, surface: InvocationSurface) {
        self.field(&[match surface {
            InvocationSurface::Cli => 1,
            InvocationSurface::Mcp => 2,
        }]);
    }

    fn output(&mut self, output: CredentialOutputPolicy) {
        self.field(&[match output {
            CredentialOutputPolicy::CliSecretStdout => 1,
            CredentialOutputPolicy::McpSecretResponse => 2,
            CredentialOutputPolicy::CliChildProcess => 3,
            CredentialOutputPolicy::McpChildProcessWithheld => 4,
        }]);
    }

    fn finish(self) -> [u8; 32] {
        Sha256::digest(self.bytes).into()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

struct VerifiedState {
    generation: u64,
    registry_digest: String,
    registry: PublicRegistry,
    configs: BTreeMap<String, PublicProfileConfig>,
}

impl<S: SecretStore> RuntimeService<S> {
    #[must_use]
    pub fn new(repository: ProfileRepository, secrets: S) -> Self {
        Self {
            repository,
            secrets,
        }
    }

    #[must_use]
    pub fn repository(&self) -> &ProfileRepository {
        &self.repository
    }

    #[must_use]
    pub fn integrity_recovery_pending(&self) -> bool {
        journal_path(self.repository.root()).exists()
            || self.read_trust_state().is_ok_and(|state| {
                matches!(
                    state,
                    Some(
                        TrustState::Allocating { .. }
                            | TrustState::Transition { .. }
                            | TrustState::PurgeCommitted { .. }
                    )
                )
            })
    }

    pub fn registry(&self) -> Result<PublicRegistry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        Ok(self.verified_state_locked()?.registry)
    }

    pub fn resolve_profile(
        &self,
        explicit_name: Option<&str>,
    ) -> Result<PublicAgentEntry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        self.resolve_profile_locked(explicit_name)
    }

    fn resolve_profile_locked(
        &self,
        explicit_name: Option<&str>,
    ) -> Result<PublicAgentEntry, RuntimeError> {
        let registry = self.verified_state_locked()?.registry;
        let name = explicit_name.unwrap_or(&registry.default);
        ProfileName::parse(name)?;
        registry
            .agents
            .into_iter()
            .find(|agent| agent.name == name)
            .ok_or(RuntimeError::ProfileNotFound)
    }

    pub fn create_profile(
        &self,
        name: &str,
        agent_type: Option<String>,
    ) -> Result<CreatedProfile, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        self.create_profile_locked(name, agent_type)
    }

    fn create_profile_locked(
        &self,
        name: &str,
        agent_type: Option<String>,
    ) -> Result<CreatedProfile, RuntimeError> {
        self.create_profile_locked_with_identity_id(name, agent_type, generate_opaque_id()?)
    }

    fn create_profile_locked_with_identity_id(
        &self,
        name: &str,
        agent_type: Option<String>,
        identity_id: String,
    ) -> Result<CreatedProfile, RuntimeError> {
        let name = ProfileName::parse(name)?;
        let state = self.verified_state_locked()?;
        if state
            .registry
            .agents
            .iter()
            .any(|entry| entry.name == name.as_str())
        {
            return Err(ProfileError::AlreadyExists.into());
        }
        if state
            .registry
            .agents
            .iter()
            .any(|entry| entry.identity_id == identity_id)
        {
            return Err(ProfileError::InvalidIdentityId.into());
        }
        let encryption = X25519Identity::generate()?;
        let signing = Ed25519Identity::generate()?;

        self.begin_allocation(
            &state,
            vec![SecretAllocation::Identity {
                identity_id: identity_id.clone(),
            }],
        )?;

        if let Err(error) = self.secrets.set(
            &identity_id,
            SecretSlot::X25519PrivateKey,
            encryption.private_key_for_secure_storage(),
        ) {
            self.rollback_allocation(
                &state,
                &[SecretAllocation::Identity {
                    identity_id: identity_id.clone(),
                }],
            )?;
            return Err(error.into());
        }
        let signing_secret = signing.libsodium_secret_for_secure_storage();
        if let Err(error) = self.secrets.set(
            &identity_id,
            SecretSlot::Ed25519SecretKey,
            signing_secret.expose_secret(),
        ) {
            self.rollback_allocation(
                &state,
                &[SecretAllocation::Identity {
                    identity_id: identity_id.clone(),
                }],
            )?;
            return Err(error.into());
        }
        if let Err(error) = self
            .secrets
            .initialize_operation_authorization(&identity_id)
        {
            self.rollback_allocation(
                &state,
                &[SecretAllocation::Identity {
                    identity_id: identity_id.clone(),
                }],
            )?;
            return Err(error.into());
        }

        let updated = add_profile(
            &state.registry,
            &name,
            identity_id.clone(),
            now_rfc3339()?,
            agent_type,
        )?;
        self.commit_transition(&state, updated, Vec::new(), Vec::new(), Vec::new(), false)?;

        Ok(CreatedProfile {
            name: name.as_str().to_owned(),
            identity_id,
            encryption_public_key: STANDARD.encode(encryption.public_key()),
            signing_public_key: STANDARD.encode(signing.public_key()),
        })
    }

    pub fn rename_profile(&self, old_name: &str, new_name: &str) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let old_name = ProfileName::parse(old_name)?;
        let new_name = ProfileName::parse(new_name)?;
        let state = self.verified_state_locked()?;
        let updated = rename_profile(&state.registry, &old_name, &new_name)?;
        self.commit_transition(&state, updated, Vec::new(), Vec::new(), Vec::new(), false)?;
        Ok(())
    }

    pub fn set_default_profile(&self, name: &str) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let name = ProfileName::parse(name)?;
        let state = self.verified_state_locked()?;
        let updated = set_default(&state.registry, &name)?;
        self.commit_transition(&state, updated, Vec::new(), Vec::new(), Vec::new(), false)?;
        Ok(())
    }

    pub fn delete_profile(
        &self,
        name: &str,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let name = ProfileName::parse(name)?;
        let state = self.verified_state_locked()?;
        let profile = resolve_profile_in(&state.registry, Some(name.as_str()))?;
        let authorization = self.authorize_profile_operation(
            &state,
            &profile,
            hostname,
            connection,
            &OperationDescriptor::DeleteProfile,
        )?;
        let lease = authorization.into_lease()?;
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let (updated, deleted) = delete_profile(&state.registry, &name)?;
        self.commit_profile_removal(&state, updated, deleted)
    }

    /// Deliberately removes the selected local Agent identity.
    ///
    /// This is the native implementation behind `disconnect --purge --confirm`.
    /// An organization credential survives while any remaining Agent config references
    /// it; the selected Agent's X25519 and Ed25519 slots are always removed.
    pub fn purge_profile(
        &self,
        explicit_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<PublicAgentEntry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let name = ProfileName::parse(explicit_name.unwrap_or(&state.registry.default))?;
        let profile = resolve_profile_in(&state.registry, Some(name.as_str()))?;
        let authorization = self.authorize_profile_operation(
            &state,
            &profile,
            hostname,
            connection,
            &OperationDescriptor::PurgeProfile,
        )?;
        let lease = authorization.into_lease()?;
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let (updated, deleted) = purge_profile(&state.registry, &name)?;
        self.commit_profile_removal(&state, updated, deleted.clone())?;
        Ok(deleted)
    }

    fn commit_profile_removal(
        &self,
        state: &VerifiedState,
        updated: PublicRegistry,
        deleted: PublicAgentEntry,
    ) -> Result<(), RuntimeError> {
        let organization_ids = state
            .configs
            .get(&deleted.identity_id)
            .cloned()
            .map(|config| {
                let mut ids = config.retired_organization_credential_ids;
                ids.push(config.organization_credential_id);
                ids
            })
            .unwrap_or_default();
        let remaining_configs = state
            .configs
            .iter()
            .filter(|(identity, _)| *identity != &deleted.identity_id)
            .map(|(identity, config)| (identity.clone(), config.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut deletions = vec![SecretDeletion::Identity {
            identity_id: deleted.identity_id.clone(),
        }];
        for organization_id in organization_ids {
            if !organization_referenced_in(&remaining_configs, &organization_id) {
                deletions.push(SecretDeletion::OrganizationCredential {
                    organization_credential_id: organization_id,
                });
            }
        }
        self.commit_transition(
            state,
            updated,
            Vec::new(),
            vec![deleted.identity_id],
            deletions,
            false,
        )?;
        Ok(())
    }

    pub fn purge(
        &self,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        if self
            .repository
            .root()
            .file_name()
            .and_then(|value| value.to_str())
            == Some(".palladin")
            && !matches!(
                LegacyTypeScriptRepository::new(self.repository.root())?.status()?,
                palladin_core::legacy_typescript::LegacyTypeScriptStatus::Clear
            )
        {
            return Err(RuntimeError::LegacyMigrationRequired);
        }
        if self.repository.legacy_artifacts_present() {
            return Err(RuntimeError::LegacyMigrationRequired);
        }
        let state = self.verified_state_locked()?;
        let authorization = if state.registry.agents.is_empty() {
            None
        } else {
            let profile = resolve_profile_in(&state.registry, None)?;
            Some(self.authorize_profile_operation(
                &state,
                &profile,
                hostname,
                connection,
                &OperationDescriptor::PurgeAll,
            )?)
        };
        let lease = authorization
            .map(OperationAuthorization::into_lease)
            .transpose()?;
        if let Some(lease) = &lease {
            lease
                .ensure_active()
                .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        }
        let mut organizations = BTreeSet::new();
        let mut identities = Vec::new();
        for agent in &state.registry.agents {
            identities.push(agent.identity_id.clone());
            if let Some(config) = state.configs.get(&agent.identity_id) {
                organizations.insert(config.organization_credential_id.clone());
                organizations.extend(config.retired_organization_credential_ids.iter().cloned());
            }
        }
        self.repository.preflight_public_purge(&identities)?;
        let mut deletions = identities
            .iter()
            .cloned()
            .map(|identity_id| SecretDeletion::Identity { identity_id })
            .collect::<Vec<_>>();
        deletions.extend(organizations.into_iter().map(|organization_credential_id| {
            SecretDeletion::OrganizationCredential {
                organization_credential_id,
            }
        }));
        self.commit_transition(
            &state,
            PublicRegistry::default(),
            Vec::new(),
            identities,
            deletions,
            true,
        )?;
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the security boundary binds every typed connect input explicitly"
    )]
    pub async fn connect(
        &self,
        profile_name: Option<&str>,
        organization_api_key: OrganizationApiKey,
        host: ApiHost,
        display_name: Option<&str>,
        agent_type: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<ConnectOutcome, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        if !organization_api_key
            .expose_for_authorized_request()
            .starts_with("pl_")
        {
            return Err(RuntimeError::InvalidApiKey);
        }

        let agent = match self.resolve_profile_locked(profile_name) {
            Ok(agent) => agent,
            Err(RuntimeError::ProfileNotFound) => {
                let name = profile_name.unwrap_or("default");
                self.create_profile_locked(name, agent_type.map(str::to_owned))?;
                self.resolve_profile_locked(Some(name))?
            }
            Err(error) => return Err(error),
        };
        let mut state = self.verified_state_locked()?;
        if let Some(agent_type) = agent_type {
            let name = ProfileName::parse(&agent.name)?;
            let updated = set_profile_type(&state.registry, &name, Some(agent_type))?;
            self.commit_transition(&state, updated, Vec::new(), Vec::new(), Vec::new(), false)?;
            state = self.verified_state_locked()?;
        }
        let existing_config = state.configs.get(&agent.identity_id).cloned();
        let mut organization_owners = state
            .configs
            .values()
            .flat_map(|config| {
                config
                    .retired_organization_credential_ids
                    .iter()
                    .chain(std::iter::once(&config.organization_credential_id))
            })
            .cloned()
            .collect::<Vec<_>>();
        organization_owners.sort();
        organization_owners.dedup();
        let api_key_digest: [u8; 32] = Sha256::digest(
            organization_api_key
                .expose_for_authorized_request()
                .as_bytes(),
        )
        .into();
        let descriptor = OperationDescriptor::Connect {
            host: host.as_url().as_str().trim_end_matches('/').to_owned(),
            display_name: display_name.map(str::to_owned),
            agent_type: agent_type.map(str::to_owned),
            api_key_digest,
        };
        let request = connection.request(&descriptor)?;
        let operation_binding = request.binding(
            &state,
            &agent,
            existing_config.as_ref(),
            hostname,
            &organization_owners,
        );
        let scope = OperationScope::new(&agent.identity_id, &organization_owners)?;
        let authorization = self.secrets.authorize_operation(
            &scope,
            request.operation.authorization_prompt(),
            &operation_binding,
        )?;
        let (encryption, signing) = self.load_identity_verified_authorized(
            &agent.identity_id,
            existing_config.as_ref(),
            &authorization,
            &operation_binding,
        )?;
        let (_, signing_for_binding) = self.load_identity_verified_authorized(
            &agent.identity_id,
            existing_config.as_ref(),
            &authorization,
            &operation_binding,
        )?;
        let (organization_credential_id, created_organization) = self
            .find_or_create_organization_credential_authorized(
                &state,
                &organization_api_key,
                &authorization,
                &operation_binding,
            )?;
        let host_string = host.as_url().as_str().trim_end_matches('/').to_owned();
        let signing_public_key_bytes = *signing.public_key();
        let signing_public_key = STANDARD.encode(signing_public_key_bytes);
        let encryption_public_key = STANDARD.encode(encryption.public_key());
        let signing_context = existing_config
            .as_ref()
            .and_then(|config| config.agent_id.as_ref())
            .map(|agent_id| palladin_api::SigningContext {
                agent_id: agent_id.clone(),
                identity: signing,
            });
        let client = match ApiClient::new(
            host,
            organization_api_key,
            &encryption,
            hostname,
            signing_context,
        ) {
            Ok(client) => client,
            Err(error) => {
                self.cleanup_unused_new_organization(
                    &state,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Err(error.into());
            }
        };
        let lease = authorization.into_lease()?;
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let cancellation = lease.cancellation_token();
        let remaining = lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let registration_result = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                None
            }
            () = tokio::time::sleep(remaining) => {
                None
            }
            result = client.register_agent(
                display_name.or_else(|| (agent.name != "default").then_some(agent.name.as_str())),
                agent_type.or(agent.agent_type.as_deref()),
                Some(&signing_public_key_bytes),
            ) => Some(result),
        };
        let Some(registration_result) = registration_result else {
            self.cleanup_unused_new_organization(
                &state,
                &organization_credential_id,
                created_organization,
            )?;
            return Err(RuntimeError::OperationAuthorizationExpired);
        };
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let registration = match registration_result {
            Ok(registration) => registration,
            Err(error) => {
                self.cleanup_unused_new_organization(
                    &state,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Err(error.into());
            }
        };

        let agent_active = matches!(&registration, AgentRegistrationResult::Active { .. });
        let agent_id = match &registration {
            AgentRegistrationResult::Pending { agent_id }
            | AgentRegistrationResult::Active { agent_id, .. }
            | AgentRegistrationResult::Deactivated { agent_id } => Some(agent_id.clone()),
            AgentRegistrationResult::InvalidKey => {
                self.cleanup_unused_new_organization(
                    &state,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Ok(ConnectOutcome {
                    registration,
                    config_saved: false,
                });
            }
            AgentRegistrationResult::Unreachable { .. } => None,
        };

        let should_save = agent_id.is_some() || existing_config.is_none();
        if should_save {
            let mut config = PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                identity_id: agent.identity_id.clone(),
                host: host_string,
                organization_credential_id: organization_credential_id.clone(),
                retired_organization_credential_ids: existing_config
                    .as_ref()
                    .map(|config| {
                        let mut retired = config.retired_organization_credential_ids.clone();
                        if config.organization_credential_id != organization_credential_id {
                            retired.push(config.organization_credential_id.clone());
                        }
                        retired.retain(|value| value != &organization_credential_id);
                        retired.sort();
                        retired.dedup();
                        retired
                    })
                    .unwrap_or_default(),
                agent_id,
                agent_active,
                encryption_public_key: Some(encryption_public_key),
                signing_public_key: Some(signing_public_key),
                binding_signature: STANDARD.encode([0_u8; 64]),
            };
            let binding =
                profile_binding_bytes(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
            config.binding_signature =
                STANDARD.encode(signing_for_binding.sign_profile_binding(&binding));
            let digest =
                profile_config_digest(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
            let mut registry = state.registry.clone();
            let entry = registry
                .agents
                .iter_mut()
                .find(|entry| entry.identity_id == agent.identity_id)
                .ok_or(RuntimeError::IntegrityViolation)?;
            entry.config_digest = Some(digest);
            self.commit_transition(
                &state,
                registry,
                vec![ConfigWrite {
                    identity_id: agent.identity_id.clone(),
                    config,
                }],
                Vec::new(),
                Vec::new(),
                false,
            )?;
            let refreshed = self.verified_state_locked()?;
            self.cleanup_retired_organizations_with_signing(
                &agent.identity_id,
                &refreshed,
                &signing_for_binding,
            )?;
        } else {
            self.cleanup_unused_new_organization(
                &state,
                &organization_credential_id,
                created_organization,
            )?;
        }

        Ok(ConnectOutcome {
            registration,
            config_saved: should_save,
        })
    }

    pub async fn status(
        &self,
        profile_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<StatusOutcome, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let agent = resolve_profile_in(&state.registry, profile_name)?;
        let mut config = state
            .configs
            .get(&agent.identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        let mut organization_owners = config.retired_organization_credential_ids.clone();
        organization_owners.push(config.organization_credential_id.clone());
        organization_owners.sort();
        organization_owners.dedup();
        let request = connection.request(&OperationDescriptor::Status)?;
        let operation_binding = request.binding(
            &state,
            &agent,
            Some(&config),
            hostname,
            &organization_owners,
        );
        let scope = OperationScope::new(&agent.identity_id, &organization_owners)?;
        let authorization = self.secrets.authorize_operation(
            &scope,
            request.operation.authorization_prompt(),
            &operation_binding,
        )?;
        let (encryption, signing) = self.load_identity_verified_authorized(
            &agent.identity_id,
            Some(&config),
            &authorization,
            &operation_binding,
        )?;
        let signing_public_key = *signing.public_key();
        let organization_api_key = self.load_organization_api_key_authorized(
            &config.organization_credential_id,
            &authorization,
            &operation_binding,
        )?;
        let (_, signing_for_binding) = self.load_identity_verified_authorized(
            &agent.identity_id,
            Some(&config),
            &authorization,
            &operation_binding,
        )?;
        let host = ApiHost::parse(&config.host).map_err(|_| RuntimeError::InvalidPublicConfig)?;
        let signing_context =
            config
                .agent_id
                .as_ref()
                .map(|agent_id| palladin_api::SigningContext {
                    agent_id: agent_id.clone(),
                    identity: signing,
                });
        let client = ApiClient::new(
            host,
            organization_api_key,
            &encryption,
            hostname,
            signing_context,
        )?;
        let lease = authorization.into_lease()?;
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let cancellation = lease.cancellation_token();
        let remaining = lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let registration = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            () = tokio::time::sleep(remaining) => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            result = client.register_agent(
                None,
                agent.agent_type.as_deref(),
                Some(&signing_public_key),
            ) => result?,
        };
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        if let AgentRegistrationResult::Pending { agent_id }
        | AgentRegistrationResult::Active { agent_id, .. }
        | AgentRegistrationResult::Deactivated { agent_id } = &registration
        {
            config.agent_id = Some(agent_id.clone());
            config.agent_active = matches!(&registration, AgentRegistrationResult::Active { .. });
            config.encryption_public_key = Some(STANDARD.encode(encryption.public_key()));
            config.signing_public_key = Some(STANDARD.encode(signing_public_key));
            let binding =
                profile_binding_bytes(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
            config.binding_signature =
                STANDARD.encode(signing_for_binding.sign_profile_binding(&binding));
            let digest =
                profile_config_digest(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
            let mut registry = state.registry.clone();
            registry
                .agents
                .iter_mut()
                .find(|entry| entry.identity_id == agent.identity_id)
                .ok_or(RuntimeError::IntegrityViolation)?
                .config_digest = Some(digest);
            self.commit_transition(
                &state,
                registry,
                vec![ConfigWrite {
                    identity_id: agent.identity_id.clone(),
                    config: config.clone(),
                }],
                Vec::new(),
                Vec::new(),
                false,
            )?;
        }
        Ok(StatusOutcome {
            profile: agent,
            config,
            registration,
        })
    }

    pub fn open_session(
        &self,
        profile_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
        descriptor: OperationDescriptor,
    ) -> Result<RuntimeSession, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let profile = resolve_profile_in(&state.registry, profile_name)?;
        let config = state
            .configs
            .get(&profile.identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        let mut organization_owners = config.retired_organization_credential_ids.clone();
        organization_owners.push(config.organization_credential_id.clone());
        organization_owners.sort();
        organization_owners.dedup();
        let request = connection.request(&descriptor)?;
        let operation = request.operation;
        let binding = request.binding(
            &state,
            &profile,
            Some(&config),
            hostname,
            &organization_owners,
        );
        let scope = OperationScope::new(&profile.identity_id, &organization_owners)?;
        let authorization = self.secrets.authorize_operation(
            &scope,
            request.operation.authorization_prompt(),
            &binding,
        )?;
        let (encryption, signing) = self.load_identity_verified_authorized(
            &profile.identity_id,
            Some(&config),
            &authorization,
            &binding,
        )?;
        let organization_api_key = self.load_organization_api_key_authorized(
            &config.organization_credential_id,
            &authorization,
            &binding,
        )?;
        let host = ApiHost::parse(&config.host).map_err(|_| RuntimeError::InvalidPublicConfig)?;
        let agent_id = config
            .agent_id
            .as_ref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let signing = Some(palladin_api::SigningContext {
            agent_id: agent_id.clone(),
            identity: signing,
        });
        let api = ApiClient::new(host, organization_api_key, &encryption, hostname, signing)?;
        let lease = authorization.into_lease()?;
        Ok(RuntimeSession {
            profile,
            config,
            api,
            encryption,
            lease,
            operation,
            consumed: AtomicBool::new(false),
        })
    }

    pub fn verify_identity(
        &self,
        profile_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<PublicAgentEntry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let profile = resolve_profile_in(&state.registry, profile_name)?;
        let (authorization, binding) = self.authorize_profile_operation_with_binding(
            &state,
            &profile,
            hostname,
            connection,
            &OperationDescriptor::VerifyIdentity,
        )?;
        let _identity = self.load_identity_verified_authorized(
            &profile.identity_id,
            state.configs.get(&profile.identity_id),
            &authorization,
            &binding,
        )?;
        let lease = authorization.into_lease()?;
        lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        Ok(profile)
    }

    /// Replaces exportable TypeScript identities with fresh native identities.
    ///
    /// This operation never opens a legacy config or private-key slot. The old filesystem is
    /// frozen by `LegacyTypeScriptRepository` and remains available only for an explicit,
    /// separately confirmed cleanup after every new Agent has completed enrollment.
    pub fn cutover_legacy_typescript(
        &self,
        confirmed: bool,
    ) -> Result<LegacyCutoverOutcome, RuntimeError> {
        if !confirmed {
            return Err(RuntimeError::LegacyCutoverConfirmationRequired);
        }
        let _lock = self.repository.acquire_transaction_lock()?;
        let legacy_repository = LegacyTypeScriptRepository::new(self.repository.root())?;
        let pending = legacy_repository.pending_manifest()?;
        if pending.is_none()
            && matches!(
                legacy_repository.status()?,
                palladin_core::legacy_typescript::LegacyTypeScriptStatus::Detected {
                    source_directory,
                    ..
                } if source_directory == ".palladin"
            )
            && self.read_trust_state()?.is_some()
        {
            return Err(RuntimeError::IntegrityViolation);
        }

        let cutover_id = pending
            .as_ref()
            .map(|manifest| manifest.cutover_id.clone())
            .unwrap_or(generate_opaque_id()?);
        let manifest = legacy_repository.begin_cutover(cutover_id.clone())?;

        if self.read_trust_state()?.is_some() {
            self.recover_pending_operations_locked()?;
        } else {
            self.bootstrap_integrity_root()?;
        }
        legacy_repository.ensure_cleanup_marker(&manifest)?;

        let mut created = 0_usize;
        for planned in &manifest.profiles {
            let state = self.verified_state_locked()?;
            if let Some(existing) = state
                .registry
                .agents
                .iter()
                .find(|entry| entry.name == planned.native_name)
            {
                if existing.identity_id != planned.identity_id {
                    return Err(RuntimeError::LegacyProfileConflict);
                }
                self.load_identity_verified(
                    &existing.identity_id,
                    state.configs.get(&existing.identity_id),
                )?;
                continue;
            }
            if state
                .registry
                .agents
                .iter()
                .any(|entry| entry.identity_id == planned.identity_id)
            {
                return Err(RuntimeError::LegacyProfileConflict);
            }
            self.create_profile_locked_with_identity_id(
                &planned.native_name,
                planned.agent_type.clone(),
                planned.identity_id.clone(),
            )?;
            created += 1;
        }

        let state = self.verified_state_locked()?;
        if state.registry.default != manifest.default {
            let default = ProfileName::parse(&manifest.default)?;
            let updated = set_default(&state.registry, &default)?;
            self.commit_transition(&state, updated, Vec::new(), Vec::new(), Vec::new(), false)?;
        }

        Ok(LegacyCutoverOutcome {
            cutover_id,
            created,
            profiles: manifest.profiles.len(),
            profile_names: manifest
                .profiles
                .iter()
                .map(|profile| profile.native_name.clone())
                .collect(),
        })
    }

    /// Deletes the frozen TypeScript credentials only after every fresh profile has a signed,
    /// last-known active backend registration. The injected deleter intentionally exposes no
    /// read operation.
    pub fn cleanup_legacy_typescript<F>(
        &self,
        confirmed: bool,
        cutover_id: &str,
        mut delete_legacy_credentials: F,
    ) -> Result<LegacyCleanupOutcome, RuntimeError>
    where
        F: FnMut(&str) -> Result<(), StoreError>,
    {
        if !confirmed {
            return Err(RuntimeError::LegacyCleanupConfirmationRequired);
        }
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let legacy_repository = LegacyTypeScriptRepository::new(self.repository.root())?;
        let manifest = legacy_repository
            .pending_manifest()?
            .ok_or(RuntimeError::LegacyCutoverNotPending)?;
        if manifest.cutover_id != cutover_id {
            return Err(RuntimeError::LegacyCutoverIdMismatch);
        }

        let state = self.verified_state_locked()?;
        for planned in &manifest.profiles {
            let entry = state
                .registry
                .agents
                .iter()
                .find(|entry| entry.name == planned.native_name)
                .ok_or(RuntimeError::LegacyProfilesNotConnected)?;
            if entry.identity_id != planned.identity_id
                || state
                    .configs
                    .get(&entry.identity_id)
                    .is_none_or(|config| config.agent_id.is_none() || !config.agent_active)
            {
                return Err(RuntimeError::LegacyProfilesNotConnected);
            }
        }

        for planned in &manifest.profiles {
            delete_legacy_credentials(&planned.legacy_name)?;
        }
        legacy_repository.cleanup_archive(cutover_id)?;
        Ok(LegacyCleanupOutcome {
            profiles: manifest.profiles.len(),
        })
    }

    pub fn upgrade_security(
        &self,
        profile_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
    ) -> Result<SecurityUpgradeOutcome, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        if self.read_trust_state()?.is_some() {
            self.recover_pending_operations_locked()?;
            let state = self.verified_state_locked()?;
            let profile = resolve_profile_in(&state.registry, profile_name)?;
            let (authorization, binding) = self.authorize_profile_operation_with_binding(
                &state,
                &profile,
                hostname,
                connection,
                &OperationDescriptor::UpgradeSecurity,
            )?;
            self.load_identity_verified_authorized(
                &profile.identity_id,
                state.configs.get(&profile.identity_id),
                &authorization,
                &binding,
            )?;
            let lease = authorization.into_lease()?;
            lease
                .ensure_active()
                .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
            return Ok(SecurityUpgradeOutcome {
                profile,
                migrated: false,
            });
        }

        if self.secrets.requires_operation_authorization() {
            return Err(RuntimeError::PreBoundaryIdentityResetRequired);
        }

        let legacy = self.repository.load_legacy_registry_v2()?;
        if self.repository.cleanup_pending() {
            return Err(RuntimeError::LegacyCleanupPending);
        }
        let mut legacy_configs = BTreeMap::new();
        for entry in &legacy.agents {
            if self
                .repository
                .config_exists_strict(&entry.identity_id)
                .map_err(|_| RuntimeError::IntegrityViolation)?
            {
                let config = self.repository.load_legacy_config_v2(&entry.identity_id)?;
                ApiHost::parse(&config.host).map_err(|_| RuntimeError::InvalidPublicConfig)?;
                legacy_configs.insert(entry.identity_id.clone(), config);
            }
        }
        let mut target = PublicRegistry {
            schema_version: PUBLIC_SCHEMA_VERSION,
            default: legacy.default,
            agents: Vec::with_capacity(legacy.agents.len()),
        };
        let mut config_writes = Vec::new();
        let mut copies = Vec::new();
        let mut deletions = Vec::new();
        let mut legacy_organizations = BTreeSet::new();

        for legacy_entry in legacy.agents {
            let identity_id = legacy_entry.identity_id;
            let encryption_secret = self
                .secrets
                .get(&identity_id, SecretSlot::LegacyX25519PrivateKeyV2)?
                .ok_or(RuntimeError::MissingIdentity)?;
            let signing_secret = self
                .secrets
                .get(&identity_id, SecretSlot::LegacyEd25519SecretKeyV2)?
                .ok_or(RuntimeError::MissingIdentity)?;
            let encryption =
                X25519Identity::from_private_bytes(encryption_secret.expose_secret().to_vec())?;
            let signing =
                Ed25519Identity::from_libsodium_secret(signing_secret.expose_secret().to_vec())?;
            copies.push(SecretCopy::LegacyIdentity {
                identity_id: identity_id.clone(),
            });

            let mut entry = PublicAgentEntry {
                name: legacy_entry.name,
                identity_id: identity_id.clone(),
                created_at: legacy_entry.created_at,
                agent_type: legacy_entry.agent_type,
                config_digest: None,
            };
            if let Some(legacy_config) = legacy_configs.remove(&identity_id) {
                let encryption_public_key = STANDARD.encode(encryption.public_key());
                let signing_public_key = STANDARD.encode(signing.public_key());
                if legacy_config
                    .encryption_public_key
                    .as_deref()
                    .is_some_and(|value| value != encryption_public_key)
                    || legacy_config
                        .signing_public_key
                        .as_deref()
                        .is_some_and(|value| value != signing_public_key)
                {
                    return Err(RuntimeError::IntegrityViolation);
                }
                let mut organization_ids =
                    legacy_config.retired_organization_credential_ids.clone();
                organization_ids.push(legacy_config.organization_credential_id.clone());
                for organization_id in organization_ids {
                    if legacy_organizations.insert(organization_id.clone()) {
                        self.secrets
                            .get(&organization_id, SecretSlot::LegacyOrganizationApiKeyV2)?
                            .ok_or(RuntimeError::MissingOrganizationCredential)?;
                        copies.push(SecretCopy::LegacyOrganizationCredential {
                            organization_credential_id: organization_id,
                        });
                    }
                }
                let mut config = PublicProfileConfig {
                    schema_version: PUBLIC_SCHEMA_VERSION,
                    identity_id: identity_id.clone(),
                    host: legacy_config.host,
                    organization_credential_id: legacy_config.organization_credential_id,
                    retired_organization_credential_ids: legacy_config
                        .retired_organization_credential_ids,
                    agent_id: legacy_config.agent_id,
                    agent_active: false,
                    encryption_public_key: Some(encryption_public_key),
                    signing_public_key: Some(signing_public_key),
                    binding_signature: STANDARD.encode([0_u8; 64]),
                };
                let binding =
                    profile_binding_bytes(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
                config.binding_signature = STANDARD.encode(signing.sign_profile_binding(&binding));
                entry.config_digest = Some(
                    profile_config_digest(&config).map_err(|_| RuntimeError::IntegrityViolation)?,
                );
                config_writes.push(ConfigWrite {
                    identity_id: identity_id.clone(),
                    config,
                });
            }
            target.agents.push(entry);
            deletions.push(SecretDeletion::LegacyIdentity { identity_id });
        }
        deletions.extend(
            legacy_organizations
                .into_iter()
                .map(
                    |organization_credential_id| SecretDeletion::LegacyOrganizationCredential {
                        organization_credential_id,
                    },
                ),
        );

        let synthetic_current = VerifiedState {
            generation: 0,
            registry_digest: "0".repeat(64),
            registry: PublicRegistry::default(),
            configs: BTreeMap::new(),
        };
        self.commit_transition_with_copies(
            &synthetic_current,
            target,
            config_writes,
            Vec::new(),
            copies,
            deletions,
            false,
        )?;
        let state = self.verified_state_locked()?;
        let profile = resolve_profile_in(&state.registry, profile_name)?;
        Ok(SecurityUpgradeOutcome {
            profile,
            migrated: true,
        })
    }

    fn authorize_profile_operation(
        &self,
        state: &VerifiedState,
        profile: &PublicAgentEntry,
        hostname: &str,
        connection: &OperationConnection,
        descriptor: &OperationDescriptor,
    ) -> Result<OperationAuthorization, RuntimeError> {
        self.authorize_profile_operation_with_binding(
            state, profile, hostname, connection, descriptor,
        )
        .map(|(authorization, _)| authorization)
    }

    fn authorize_profile_operation_with_binding(
        &self,
        state: &VerifiedState,
        profile: &PublicAgentEntry,
        hostname: &str,
        connection: &OperationConnection,
        descriptor: &OperationDescriptor,
    ) -> Result<(OperationAuthorization, Vec<u8>), RuntimeError> {
        let config = state.configs.get(&profile.identity_id);
        let mut organization_owners = config
            .map(|config| config.retired_organization_credential_ids.clone())
            .unwrap_or_default();
        if let Some(config) = config {
            organization_owners.push(config.organization_credential_id.clone());
        }
        organization_owners.sort();
        organization_owners.dedup();
        let request = connection.request(descriptor)?;
        let binding = request.binding(state, profile, config, hostname, &organization_owners);
        let scope = OperationScope::new(&profile.identity_id, &organization_owners)?;
        let authorization = self.secrets.authorize_operation(
            &scope,
            request.operation.authorization_prompt(),
            &binding,
        )?;
        Ok((authorization, binding))
    }

    fn load_identity_verified(
        &self,
        identity_id: &str,
        expected: Option<&PublicProfileConfig>,
    ) -> Result<(X25519Identity, Ed25519Identity), RuntimeError> {
        let encryption = self
            .secrets
            .get(identity_id, SecretSlot::X25519PrivateKey)?
            .ok_or(RuntimeError::MissingIdentity)?;
        let signing = self
            .secrets
            .get(identity_id, SecretSlot::Ed25519SecretKey)?
            .ok_or(RuntimeError::MissingIdentity)?;
        let encryption = X25519Identity::from_private_bytes(encryption.expose_secret().to_vec())?;
        let signing = Ed25519Identity::from_libsodium_secret(signing.expose_secret().to_vec())?;
        if let Some(expected) = expected {
            let encryption_public = STANDARD.encode(encryption.public_key());
            let signing_public = STANDARD.encode(signing.public_key());
            if expected.encryption_public_key.as_deref() != Some(encryption_public.as_str())
                || expected.signing_public_key.as_deref() != Some(signing_public.as_str())
            {
                return Err(RuntimeError::IntegrityViolation);
            }
        }
        Ok((encryption, signing))
    }

    fn load_identity_verified_authorized(
        &self,
        identity_id: &str,
        expected: Option<&PublicProfileConfig>,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<(X25519Identity, Ed25519Identity), RuntimeError> {
        let encryption = self
            .secrets
            .get_authorized(
                identity_id,
                SecretSlot::X25519PrivateKey,
                authorization,
                binding,
            )?
            .ok_or(RuntimeError::MissingIdentity)?;
        let signing = self
            .secrets
            .get_authorized(
                identity_id,
                SecretSlot::Ed25519SecretKey,
                authorization,
                binding,
            )?
            .ok_or(RuntimeError::MissingIdentity)?;
        let encryption = X25519Identity::from_private_bytes(encryption.expose_secret().to_vec())?;
        let signing = Ed25519Identity::from_libsodium_secret(signing.expose_secret().to_vec())?;
        if let Some(expected) = expected {
            let encryption_public = STANDARD.encode(encryption.public_key());
            let signing_public = STANDARD.encode(signing.public_key());
            if expected.encryption_public_key.as_deref() != Some(encryption_public.as_str())
                || expected.signing_public_key.as_deref() != Some(signing_public.as_str())
            {
                return Err(RuntimeError::IntegrityViolation);
            }
        }
        Ok((encryption, signing))
    }

    fn load_organization_api_key_authorized(
        &self,
        organization_id: &str,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<OrganizationApiKey, RuntimeError> {
        let secret = self
            .secrets
            .get_authorized(
                organization_id,
                SecretSlot::OrganizationApiKey,
                authorization,
                binding,
            )?
            .ok_or(RuntimeError::MissingOrganizationCredential)?;
        let bytes = Zeroizing::new(secret.expose_secret().to_vec());
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| RuntimeError::InvalidStoredSecret)?
            .to_owned();
        Ok(OrganizationApiKey::new(value))
    }

    fn find_or_create_organization_credential_authorized(
        &self,
        state: &VerifiedState,
        candidate: &OrganizationApiKey,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<(String, bool), RuntimeError> {
        let candidate = candidate.expose_for_authorized_request().as_bytes();
        let mut visited = BTreeSet::new();
        for config in state.configs.values() {
            let mut organization_ids = config.retired_organization_credential_ids.clone();
            organization_ids.push(config.organization_credential_id.clone());
            for organization_id in organization_ids {
                if !visited.insert(organization_id.clone()) {
                    continue;
                }
                if let Some(stored) = self.secrets.get_authorized(
                    &organization_id,
                    SecretSlot::OrganizationApiKey,
                    authorization,
                    binding,
                )? && bool::from(stored.expose_secret().ct_eq(candidate))
                {
                    return Ok((organization_id, false));
                }
            }
        }

        let organization_id = generate_opaque_id()?;
        let allocation = SecretAllocation::OrganizationCredential {
            organization_credential_id: organization_id.clone(),
        };
        self.begin_allocation(state, vec![allocation.clone()])?;
        if let Err(error) =
            self.secrets
                .set(&organization_id, SecretSlot::OrganizationApiKey, candidate)
        {
            self.rollback_allocation(state, &[allocation])?;
            return Err(error.into());
        }
        Ok((organization_id, true))
    }

    fn cleanup_unused_new_organization(
        &self,
        state: &VerifiedState,
        organization_id: &str,
        created: bool,
    ) -> Result<(), RuntimeError> {
        if created && !organization_referenced_in(&state.configs, organization_id) {
            self.rollback_allocation(
                state,
                &[SecretAllocation::OrganizationCredential {
                    organization_credential_id: organization_id.to_owned(),
                }],
            )?;
        }
        Ok(())
    }

    fn begin_allocation(
        &self,
        current: &VerifiedState,
        allocations: Vec<SecretAllocation>,
    ) -> Result<(), RuntimeError> {
        self.write_trust_state(&TrustState::allocating(
            current.generation,
            current.registry_digest.clone(),
            allocations,
        ))
    }

    fn rollback_allocation(
        &self,
        current: &VerifiedState,
        allocations: &[SecretAllocation],
    ) -> Result<(), RuntimeError> {
        self.delete_allocations(allocations)?;
        self.write_trust_state(&TrustState::committed(
            current.generation,
            current.registry_digest.clone(),
        ))
    }

    fn delete_allocations(&self, allocations: &[SecretAllocation]) -> Result<(), RuntimeError> {
        for allocation in allocations {
            match allocation {
                SecretAllocation::Identity { identity_id } => {
                    delete_identity(&self.secrets, identity_id)?;
                }
                SecretAllocation::OrganizationCredential {
                    organization_credential_id,
                } => {
                    delete_organization_credential(&self.secrets, organization_credential_id)?;
                }
            }
        }
        Ok(())
    }

    fn cleanup_retired_organizations_with_signing(
        &self,
        identity_id: &str,
        state: &VerifiedState,
        signing: &Ed25519Identity,
    ) -> Result<(), RuntimeError> {
        let Some(mut config) = state.configs.get(identity_id).cloned() else {
            return Ok(());
        };
        if config.retired_organization_credential_ids.is_empty() {
            return Ok(());
        }
        let retired = std::mem::take(&mut config.retired_organization_credential_ids);
        let binding =
            profile_binding_bytes(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
        config.binding_signature = STANDARD.encode(signing.sign_profile_binding(&binding));
        let digest =
            profile_config_digest(&config).map_err(|_| RuntimeError::IntegrityViolation)?;
        let mut registry = state.registry.clone();
        registry
            .agents
            .iter_mut()
            .find(|entry| entry.identity_id == identity_id)
            .ok_or(RuntimeError::IntegrityViolation)?
            .config_digest = Some(digest);
        let mut target_configs = state.configs.clone();
        target_configs.insert(identity_id.to_owned(), config.clone());
        let mut deletions = Vec::new();
        for organization_id in retired {
            if !organization_referenced_in(&target_configs, &organization_id) {
                deletions.push(SecretDeletion::OrganizationCredential {
                    organization_credential_id: organization_id,
                });
            }
        }
        self.commit_transition(
            state,
            registry,
            vec![ConfigWrite {
                identity_id: identity_id.to_owned(),
                config,
            }],
            Vec::new(),
            deletions,
            false,
        )?;
        Ok(())
    }

    pub fn recover_pending_operations(&self) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()
    }

    /// Creates only the authenticated empty-state root needed before release-policy
    /// enforcement can persist its protected anti-rollback metadata.
    ///
    /// No Agent identity or organization credential is created or opened here. Existing
    /// and legacy repositories are deliberately left untouched so their normal integrity
    /// and migration checks still decide whether an identity operation may proceed.
    pub fn prepare_empty_state_for_version_policy(&self) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        if self.read_trust_state()?.is_some() {
            return Ok(());
        }
        let root_is_empty = match std::fs::read_dir(self.repository.root()) {
            Ok(mut entries) => entries.next().transpose()?.is_none(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if root_is_empty {
            self.bootstrap_integrity_root()?;
        }
        Ok(())
    }

    fn recover_pending_operations_locked(&self) -> Result<(), RuntimeError> {
        match self.read_trust_state()? {
            None => self.bootstrap_integrity_root(),
            Some(TrustState::Committed {
                generation,
                registry_digest,
                ..
            }) => {
                if journal_path(self.repository.root()).exists() {
                    remove_journal(self.repository.root())?;
                }
                if self.repository.cleanup_pending() {
                    self.repository.remove_cleanup_journal()?;
                }
                self.repair_initial_registry_if_missing(generation, &registry_digest)?;
                self.verified_state_locked().map(|_| ())
            }
            Some(TrustState::PurgeCommitted { .. }) => self.finish_purge(),
            Some(TrustState::Allocating {
                generation,
                registry_digest,
                allocations,
                ..
            }) => {
                self.delete_allocations(&allocations)?;
                self.write_trust_state(&TrustState::committed(generation, registry_digest))?;
                if journal_path(self.repository.root()).exists() {
                    remove_journal(self.repository.root())?;
                }
                self.verified_state_locked().map(|_| ())
            }
            Some(transition @ TrustState::Transition { .. }) => {
                let journal = load_journal(self.repository.root())?;
                let journal_digest = journal.digest()?;
                let TrustState::Transition {
                    from_generation,
                    from_registry_digest,
                    to_generation,
                    to_registry_digest,
                    journal_digest: expected_journal_digest,
                    ..
                } = transition
                else {
                    unreachable!()
                };
                if journal_digest != expected_journal_digest
                    || journal.from_generation != from_generation
                    || journal.from_registry_digest != from_registry_digest
                    || journal.to_generation != to_generation
                    || journal.to_registry_digest != to_registry_digest
                {
                    return Err(RuntimeError::IntegrityRecoveryRequired);
                }
                self.apply_journal(&journal)?;
                let committed = if journal.purge_public_root {
                    TrustState::purge_committed(
                        journal.to_generation,
                        journal.to_registry_digest.clone(),
                    )
                } else {
                    TrustState::committed(journal.to_generation, journal.to_registry_digest.clone())
                };
                self.write_trust_state(&committed)?;
                remove_journal(self.repository.root())?;
                self.finish_purge_if_requested(&journal)
            }
        }
    }

    fn bootstrap_integrity_root(&self) -> Result<(), RuntimeError> {
        let root = self.repository.root();
        let has_public_artifacts = match std::fs::read_dir(root) {
            Ok(mut entries) => entries.next().transpose()?.is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if has_public_artifacts {
            return Err(RuntimeError::LegacyMigrationRequired);
        }
        let registry = PublicRegistry::default();
        let digest = registry_digest(&registry).map_err(|_| RuntimeError::IntegrityViolation)?;
        self.write_trust_state(&TrustState::committed(0, digest))?;
        self.repository.save_registry(&registry)?;
        Ok(())
    }

    fn repair_initial_registry_if_missing(
        &self,
        generation: u64,
        expected_digest: &str,
    ) -> Result<(), RuntimeError> {
        match std::fs::symlink_metadata(self.repository.root().join("registry.json")) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let registry = PublicRegistry::default();
                let digest =
                    registry_digest(&registry).map_err(|_| RuntimeError::IntegrityViolation)?;
                if generation != 0 || digest != expected_digest {
                    return Err(RuntimeError::IntegrityViolation);
                }
                self.repository.save_registry(&registry)?;
                Ok(())
            }
            Err(_) => Err(RuntimeError::IntegrityViolation),
        }
    }

    fn read_trust_state(&self) -> Result<Option<TrustState>, RuntimeError> {
        self.secrets
            .get(TRUST_OWNER_ID, SecretSlot::IntegrityTrustStateV1)?
            .map(|secret| decode_trust_state(secret.expose_secret()))
            .transpose()
    }

    fn write_trust_state(&self, state: &TrustState) -> Result<(), RuntimeError> {
        let encoded = Zeroizing::new(encode_trust_state(state)?);
        self.secrets
            .set(TRUST_OWNER_ID, SecretSlot::IntegrityTrustStateV1, &encoded)?;
        Ok(())
    }

    fn verified_state_locked(&self) -> Result<VerifiedState, RuntimeError> {
        let Some(TrustState::Committed {
            generation,
            registry_digest: expected_digest,
            ..
        }) = self.read_trust_state()?
        else {
            return Err(RuntimeError::IntegrityRecoveryRequired);
        };
        let registry = self.repository.load_registry()?;
        let actual_digest =
            registry_digest(&registry).map_err(|_| RuntimeError::IntegrityViolation)?;
        if actual_digest != expected_digest {
            return Err(RuntimeError::IntegrityViolation);
        }
        let configs = self.validate_registry_configs(&registry)?;
        Ok(VerifiedState {
            generation,
            registry_digest: expected_digest,
            registry,
            configs,
        })
    }

    fn validate_registry_configs(
        &self,
        registry: &PublicRegistry,
    ) -> Result<BTreeMap<String, PublicProfileConfig>, RuntimeError> {
        let mut configs = BTreeMap::new();
        for entry in &registry.agents {
            let config_present = self
                .repository
                .config_exists_strict(&entry.identity_id)
                .map_err(|_| RuntimeError::IntegrityViolation)?;
            match (entry.config_digest.as_deref(), config_present) {
                (None, false) => {}
                (None, true) | (Some(_), false) => {
                    return Err(RuntimeError::IntegrityViolation);
                }
                (Some(expected_digest), true) => {
                    let config = self
                        .repository
                        .load_config(&entry.identity_id)
                        .map_err(|_| RuntimeError::IntegrityViolation)?;
                    let digest = profile_config_digest(&config)
                        .map_err(|_| RuntimeError::IntegrityViolation)?;
                    if config.identity_id != entry.identity_id || digest != expected_digest {
                        return Err(RuntimeError::IntegrityViolation);
                    }
                    verify_config_signature(&config)?;
                    configs.insert(entry.identity_id.clone(), config);
                }
            }
        }
        Ok(configs)
    }

    fn commit_transition(
        &self,
        current: &VerifiedState,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        remove_identity_directories: Vec<String>,
        secret_deletions: Vec<SecretDeletion>,
        purge_public_root: bool,
    ) -> Result<(), RuntimeError> {
        self.commit_transition_with_copies(
            current,
            target_registry,
            config_writes,
            remove_identity_directories,
            Vec::new(),
            secret_deletions,
            purge_public_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_transition_with_copies(
        &self,
        current: &VerifiedState,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        remove_identity_directories: Vec<String>,
        secret_copies: Vec<SecretCopy>,
        secret_deletions: Vec<SecretDeletion>,
        purge_public_root: bool,
    ) -> Result<(), RuntimeError> {
        let journal = IntegrityJournal::new(
            current.generation,
            current.registry_digest.clone(),
            target_registry,
            config_writes,
            remove_identity_directories,
            secret_deletions,
            purge_public_root,
        )?
        .with_secret_copies(secret_copies)?;
        if journal_path(self.repository.root()).exists() {
            remove_journal(self.repository.root())?;
        }
        save_journal(self.repository.root(), &journal)?;
        let transition = TrustState::transition(
            journal.from_generation,
            journal.from_registry_digest.clone(),
            journal.to_generation,
            journal.to_registry_digest.clone(),
            journal.digest()?,
        );
        self.write_trust_state(&transition)?;
        self.apply_journal(&journal)?;
        let committed = if journal.purge_public_root {
            TrustState::purge_committed(journal.to_generation, journal.to_registry_digest.clone())
        } else {
            TrustState::committed(journal.to_generation, journal.to_registry_digest.clone())
        };
        self.write_trust_state(&committed)?;
        remove_journal(self.repository.root())?;
        self.finish_purge_if_requested(&journal)
    }

    fn finish_purge_if_requested(&self, journal: &IntegrityJournal) -> Result<(), RuntimeError> {
        if journal.purge_public_root {
            self.finish_purge()?;
        }
        Ok(())
    }

    fn finish_purge(&self) -> Result<(), RuntimeError> {
        self.repository.purge_public_data()?;
        version_policy::purge_version_policy_cache(self.repository.root())?;
        self.secrets
            .delete(TRUST_OWNER_ID, SecretSlot::VersionPolicyTrustStateV1)?;
        self.secrets
            .delete(TRUST_OWNER_ID, SecretSlot::IntegrityTrustStateV1)?;
        Ok(())
    }

    fn apply_journal(&self, journal: &IntegrityJournal) -> Result<(), RuntimeError> {
        journal.validate()?;
        if journal.purge_public_root {
            self.repository
                .preflight_public_purge(&journal.remove_identity_directories)?;
        }
        for copy in &journal.secret_copies {
            match copy {
                SecretCopy::LegacyIdentity { identity_id } => {
                    if let Some(encryption) = self
                        .secrets
                        .get(identity_id, SecretSlot::LegacyX25519PrivateKeyV2)?
                    {
                        self.secrets.set(
                            identity_id,
                            SecretSlot::X25519PrivateKey,
                            encryption.expose_secret(),
                        )?;
                    }
                    if let Some(signing) = self
                        .secrets
                        .get(identity_id, SecretSlot::LegacyEd25519SecretKeyV2)?
                    {
                        self.secrets.set(
                            identity_id,
                            SecretSlot::Ed25519SecretKey,
                            signing.expose_secret(),
                        )?;
                    }
                    let expected = journal
                        .config_writes
                        .iter()
                        .find(|write| write.identity_id == *identity_id)
                        .map(|write| &write.config);
                    self.load_identity_verified(identity_id, expected)?;
                }
                SecretCopy::LegacyOrganizationCredential {
                    organization_credential_id,
                } => {
                    if let Some(secret) = self.secrets.get(
                        organization_credential_id,
                        SecretSlot::LegacyOrganizationApiKeyV2,
                    )? {
                        self.secrets.set(
                            organization_credential_id,
                            SecretSlot::OrganizationApiKey,
                            secret.expose_secret(),
                        )?;
                    }
                    self.secrets
                        .get(organization_credential_id, SecretSlot::OrganizationApiKey)?
                        .ok_or(RuntimeError::MissingOrganizationCredential)?;
                }
            }
        }
        for write in &journal.config_writes {
            self.repository
                .save_config(&write.identity_id, &write.config)?;
        }
        self.repository.save_registry(&journal.target_registry)?;
        let target_configs = self.validate_registry_configs(&journal.target_registry)?;
        for deletion in &journal.secret_deletions {
            match deletion {
                SecretDeletion::Identity { identity_id } => {
                    if journal
                        .target_registry
                        .agents
                        .iter()
                        .any(|entry| entry.identity_id == *identity_id)
                    {
                        return Err(RuntimeError::IntegrityRecoveryRequired);
                    }
                    delete_identity(&self.secrets, identity_id)?;
                }
                SecretDeletion::OrganizationCredential {
                    organization_credential_id,
                } => {
                    if organization_referenced_in(&target_configs, organization_credential_id) {
                        return Err(RuntimeError::IntegrityRecoveryRequired);
                    }
                    delete_organization_credential(&self.secrets, organization_credential_id)?;
                }
                SecretDeletion::LegacyIdentity { identity_id } => {
                    delete_legacy_identity(&self.secrets, identity_id)?;
                }
                SecretDeletion::LegacyOrganizationCredential {
                    organization_credential_id,
                } => delete_legacy_organization_credential(
                    &self.secrets,
                    organization_credential_id,
                )?,
            }
        }
        for identity_id in &journal.remove_identity_directories {
            if journal
                .target_registry
                .agents
                .iter()
                .any(|entry| entry.identity_id == *identity_id)
            {
                return Err(RuntimeError::IntegrityRecoveryRequired);
            }
            self.repository.remove_identity_directory(identity_id)?;
        }
        Ok(())
    }
}

fn resolve_profile_in(
    registry: &PublicRegistry,
    explicit_name: Option<&str>,
) -> Result<PublicAgentEntry, RuntimeError> {
    let name = explicit_name.unwrap_or(&registry.default);
    ProfileName::parse(name)?;
    registry
        .agents
        .iter()
        .find(|agent| agent.name == name)
        .cloned()
        .ok_or(RuntimeError::ProfileNotFound)
}

fn verify_config_signature(config: &PublicProfileConfig) -> Result<(), RuntimeError> {
    let signing_public_key: [u8; 32] = STANDARD
        .decode(
            config
                .signing_public_key
                .as_deref()
                .ok_or(RuntimeError::IntegrityViolation)?,
        )
        .map_err(|_| RuntimeError::IntegrityViolation)?
        .try_into()
        .map_err(|_| RuntimeError::IntegrityViolation)?;
    let signature: [u8; 64] = STANDARD
        .decode(&config.binding_signature)
        .map_err(|_| RuntimeError::IntegrityViolation)?
        .try_into()
        .map_err(|_| RuntimeError::IntegrityViolation)?;
    let binding = profile_binding_bytes(config).map_err(|_| RuntimeError::IntegrityViolation)?;
    verify_profile_binding(&signing_public_key, &binding, &signature)
        .map_err(|_| RuntimeError::IntegrityViolation)
}

fn organization_referenced_in(
    configs: &BTreeMap<String, PublicProfileConfig>,
    organization_id: &str,
) -> bool {
    configs.values().any(|config| {
        config.organization_credential_id == organization_id
            || config
                .retired_organization_credential_ids
                .iter()
                .any(|retired| retired == organization_id)
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedProfile {
    pub name: String,
    pub identity_id: String,
    pub encryption_public_key: String,
    pub signing_public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectOutcome {
    pub registration: AgentRegistrationResult,
    pub config_saved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusOutcome {
    pub profile: PublicAgentEntry,
    pub config: PublicProfileConfig,
    pub registration: AgentRegistrationResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityUpgradeOutcome {
    pub profile: PublicAgentEntry,
    pub migrated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCutoverOutcome {
    pub cutover_id: String,
    pub created: usize,
    pub profiles: usize,
    pub profile_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyCleanupOutcome {
    pub profiles: usize,
}

pub struct RuntimeSession {
    profile: PublicAgentEntry,
    config: PublicProfileConfig,
    api: ApiClient,
    encryption: X25519Identity,
    lease: OperationLease,
    operation: RuntimeOperation,
    consumed: AtomicBool,
}

struct OperationCancellation {
    token: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl OperationCancellation {
    fn new(
        caller: &CancellationToken,
        lease: CancellationToken,
        remaining: std::time::Duration,
    ) -> Self {
        let token = CancellationToken::new();
        let cancelled = token.clone();
        let caller = caller.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                () = lease.cancelled() => {}
                () = caller.cancelled() => {}
                () = tokio::time::sleep(remaining) => {}
            }
            cancelled.cancel();
        });
        Self { token, task }
    }

    fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for OperationCancellation {
    fn drop(&mut self) {
        self.token.cancel();
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CredentialDeliveryRequest<'a> {
    pub vault_id: &'a str,
    pub entry_id: &'a str,
    pub reason: Option<&'a str>,
    pub wait: WaitOptions,
}

pub struct CredentialExecRequest<'a> {
    pub delivery: CredentialDeliveryRequest<'a>,
    pub command: Option<&'a [String]>,
    pub env_mappings: &'a [String],
    pub output: OperatorOutput,
}

impl RuntimeSession {
    #[must_use]
    pub fn profile(&self) -> &PublicAgentEntry {
        &self.profile
    }

    #[must_use]
    pub fn config(&self) -> &PublicProfileConfig {
        &self.config
    }

    fn ensure_authorized(&self) -> Result<(), RuntimeError> {
        self.lease
            .ensure_active()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)
    }

    fn ensure_operation(&self, expected: RuntimeOperation) -> Result<(), RuntimeError> {
        if self.operation != expected {
            return Err(RuntimeError::OperationAuthorizationMismatch);
        }
        self.ensure_authorized()
    }

    fn begin_operation(&self, expected: RuntimeOperation) -> Result<(), RuntimeError> {
        self.ensure_operation(expected)?;
        self.consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| RuntimeError::OperationAuthorizationConsumed)?;
        Ok(())
    }

    fn operation_cancellation(
        &self,
        caller: &CancellationToken,
    ) -> Result<OperationCancellation, RuntimeError> {
        let remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        Ok(OperationCancellation::new(
            caller,
            self.lease.cancellation_token(),
            remaining,
        ))
    }

    pub async fn search_entries(
        &self,
        query: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<EntrySearchResult, RuntimeError> {
        self.begin_operation(RuntimeOperation::SearchEntries)?;
        let cancellation = self.lease.cancellation_token();
        let remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                Err(RuntimeError::OperationAuthorizationExpired)
            }
            () = tokio::time::sleep(remaining) => {
                Err(RuntimeError::OperationAuthorizationExpired)
            }
            result = self.api.search_entries(query, cursor, page_size) => {
                self.ensure_authorized()?;
                result.map_err(RuntimeError::Api)
            }
        }
    }

    pub async fn report_credential_stale(
        &self,
        input: &ReportCredentialStaleInput,
    ) -> Result<(), RuntimeError> {
        self.begin_operation(RuntimeOperation::ReportCredentialStale)?;
        let cancellation = self.lease.cancellation_token();
        let remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                Err(RuntimeError::OperationAuthorizationExpired)
            }
            () = tokio::time::sleep(remaining) => {
                Err(RuntimeError::OperationAuthorizationExpired)
            }
            result = self.api.report_credential_stale(input) => {
                self.ensure_authorized()?;
                result.map_err(RuntimeError::Api)
            }
        }
    }

    /// The only production path from a grant response to credential plaintext.
    ///
    /// The exact backend method is fixed before the request. Every non-granted state exits before
    /// decryption, and decrypted material is returned in a non-serializable scoped wrapper.
    pub async fn deliver_for_get<H>(
        &self,
        request: CredentialDeliveryRequest<'_>,
        cancellation: &CancellationToken,
        heartbeat: H,
    ) -> Result<CredentialDelivery, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.begin_operation(RuntimeOperation::GetCredential)?;
        self.deliver_credential(request, CredentialMethod::Get, cancellation, heartbeat)
            .await
    }

    pub async fn execute_with_credential<H>(
        &self,
        request: CredentialExecRequest<'_>,
        cancellation: &CancellationToken,
        mut heartbeat: H,
    ) -> Result<CredentialExecOutcome, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.ensure_operation(RuntimeOperation::ExecWithCredential)?;
        let operation_cancellation = self.operation_cancellation(cancellation)?;
        let cancellation = operation_cancellation.token();
        if let Some(command) = request.command.filter(|command| !command.is_empty()) {
            validate_command(command)?;
        }
        let delivery = self
            .deliver_credential(
                request.delivery,
                CredentialMethod::Exec,
                cancellation,
                &mut heartbeat,
            )
            .await?;
        let CredentialDelivery::Granted(credential) = delivery else {
            let CredentialDelivery::NotGranted(access) = delivery else {
                unreachable!("credential delivery variants are exhaustive")
            };
            return Ok(CredentialExecOutcome::NotGranted(access));
        };
        let mut parsed = parse_secret(credential.expose_for_authorized_operation())
            .map_err(|_| RuntimeError::InvalidCredentialPayload)?;
        drop(credential);

        let result = if let Some(script) = parsed.script.take() {
            if request.command.is_some_and(|command| !command.is_empty()) {
                return Err(RuntimeError::CommandProvidedForScript);
            }
            if !request.env_mappings.is_empty() {
                return Err(RuntimeError::EnvironmentMappingForScript);
            }
            let interpreter = resolve_interpreter(&script.interpreter)?;
            drop(parsed);
            let environment = self
                .prepare_script_environment(
                    &request.delivery,
                    &script,
                    cancellation,
                    &mut heartbeat,
                )
                .await?;
            run_script(
                &script.script,
                &interpreter,
                environment,
                request.output,
                cancellation,
            )
            .await?
        } else {
            let command = request
                .command
                .filter(|command| !command.is_empty())
                .ok_or(RuntimeError::MissingExecCommand)?;
            let mut environment = SecretEnvironment::for_credential(&parsed);
            prepare_explicit_environment(&parsed, request.env_mappings, &mut environment)?;
            drop(parsed);
            run_command(command, environment, request.output, cancellation).await?
        };
        self.ensure_authorized()?;
        Ok(CredentialExecOutcome::Completed(result))
    }

    async fn prepare_script_environment<H>(
        &self,
        main: &CredentialDeliveryRequest<'_>,
        script: &ScriptPayload,
        cancellation: &CancellationToken,
        heartbeat: &mut H,
    ) -> Result<SecretEnvironment, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        preflight_script_references(script)?;
        let mut environment = SecretEnvironment::new();
        for reference in &script.refs {
            let vault_id = reference.vault_id.as_deref().unwrap_or(main.vault_id);
            let delivery = self
                .deliver_credential(
                    CredentialDeliveryRequest {
                        vault_id,
                        entry_id: &reference.entry_id,
                        reason: main.reason,
                        wait: main.wait,
                    },
                    CredentialMethod::Exec,
                    cancellation,
                    &mut *heartbeat,
                )
                .await?;
            let CredentialDelivery::Granted(credential) = delivery else {
                let CredentialDelivery::NotGranted(_access) = delivery else {
                    unreachable!("credential delivery variants are exhaustive")
                };
                return Err(RuntimeError::ScriptReferenceNotGranted);
            };
            let parsed = parse_secret(credential.expose_for_authorized_operation())
                .map_err(|_| RuntimeError::InvalidCredentialPayload)?;
            drop(credential);
            let value = if let Some(field) = &reference.field {
                resolve_field(
                    &parsed,
                    &FieldSelector {
                        field: Some(field.clone()),
                        field_id: None,
                    },
                )
                .map_err(|_| RuntimeError::InvalidEnvironmentField)?
                .expose_for_authorized_operation()
                .to_owned()
            } else {
                parsed.password.expose_secret().to_owned()
            };
            environment.insert_reference(&reference.env, value.into())?;
        }
        Ok(environment)
    }

    async fn deliver_credential<H>(
        &self,
        request: CredentialDeliveryRequest<'_>,
        method: CredentialMethod,
        cancellation: &CancellationToken,
        heartbeat: H,
    ) -> Result<CredentialDelivery, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.ensure_authorized()?;
        let operation_cancellation = self.operation_cancellation(cancellation)?;
        let cancellation = operation_cancellation.token();
        let options = GetCredentialOptions {
            reason: request
                .reason
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            method: Some(method),
            requested_methods: Vec::new(),
        };
        let initial = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                self.ensure_authorized()?;
                return Err(RuntimeError::WaitCancelled);
            }
            result = self.api.get_credential(request.vault_id, request.entry_id, &options) => result?,
        };
        self.ensure_authorized()?;
        let hints = match &initial {
            CredentialAccess::Pending {
                poll_interval_ms,
                max_wait_ms,
                ..
            } => WaitHints {
                poll_interval_ms: *poll_interval_ms,
                max_wait_ms: *max_wait_ms,
            },
            _ => WaitHints::default(),
        };
        let policy = resolve_wait_policy(request.wait, hints)?;
        let access = await_grant(
            initial,
            policy,
            cancellation,
            || {
                self.api
                    .get_credential(request.vault_id, request.entry_id, &options)
            },
            tokio::time::sleep,
            heartbeat,
        )
        .await
        .map_err(|error| match error {
            WaitError::Cancelled => RuntimeError::WaitCancelled,
            WaitError::Poll(error) => RuntimeError::Api(error),
        })?;
        let CredentialAccess::Granted {
            entry_id,
            label,
            url_domain,
            envelope,
        } = access
        else {
            return Ok(CredentialDelivery::NotGranted(access));
        };
        self.ensure_authorized()?;
        let credential = decrypt_credential(&envelope, &self.encryption)?;
        self.ensure_authorized()?;
        Ok(CredentialDelivery::Granted(DeliveredCredential {
            entry_id,
            label,
            url_domain,
            credential,
        }))
    }
}

pub enum CredentialDelivery {
    Granted(DeliveredCredential),
    NotGranted(CredentialAccess),
}

#[derive(Debug, Eq, PartialEq)]
pub enum CredentialExecOutcome {
    Completed(ExecResult),
    NotGranted(CredentialAccess),
}

impl std::fmt::Debug for CredentialDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted(_) => formatter.write_str("CredentialDelivery::Granted([REDACTED])"),
            Self::NotGranted(access) => formatter
                .debug_tuple("CredentialDelivery::NotGranted")
                .field(access)
                .finish(),
        }
    }
}

pub struct DeliveredCredential {
    pub entry_id: String,
    pub label: String,
    pub url_domain: Option<String>,
    credential: DecryptedCredential,
}

impl DeliveredCredential {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.credential.expose_for_authorized_operation()
    }
}

impl std::fmt::Debug for DeliveredCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveredCredential")
            .field("entry_id", &self.entry_id)
            .field("label", &"[REDACTED]")
            .field("url_domain", &self.url_domain)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("signed runtime version policy is not configured; no identity was opened")]
    VersionPolicyNotConfigured,
    #[error("signed runtime version policy is unavailable; no identity was opened")]
    VersionPolicyUnavailable,
    #[error("signed runtime version policy verification failed; no identity was opened")]
    VersionPolicyViolation,
    #[error("this runtime version is blocked by signed policy; no identity was opened")]
    VersionPolicyBlocked,
    #[error("signed runtime version policy rollback was rejected; no identity was opened")]
    VersionPolicyRollback,
    #[error("profile operation failed: {0}")]
    Profile(#[from] ProfileError),
    #[error("runtime filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("profile does not exist; run: palladin agents create <name>")]
    ProfileNotFound,
    #[error("OS secure storage operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("cryptographic identity operation failed")]
    Crypto(#[from] palladin_crypto::CryptoError),
    #[error("API client operation failed: {0}")]
    Api(#[from] ApiError),
    #[error("API key is invalid; it must start with pl_")]
    InvalidApiKey,
    #[error("stored Agent identity is incomplete")]
    MissingIdentity,
    #[error("stored organization credential is missing")]
    MissingOrganizationCredential,
    #[error("Agent is not registered; run palladin status or reconnect it")]
    MissingAgentId,
    #[error("stored secret has an invalid format")]
    InvalidStoredSecret,
    #[error("public profile configuration is invalid")]
    InvalidPublicConfig,
    #[error(
        "legacy Agent data requires an explicit migration - use palladin security legacy-status for TypeScript state or palladin security upgrade for native schema v2"
    )]
    LegacyMigrationRequired,
    #[error("legacy cutover is destructive and requires --confirm-pre-production-reset")]
    LegacyCutoverConfirmationRequired,
    #[error("legacy cleanup requires --confirm and the exact cutover identifier")]
    LegacyCleanupConfirmationRequired,
    #[error("a legacy TypeScript cutover is not pending")]
    LegacyCutoverNotPending,
    #[error("legacy cutover identifier does not match the pending archive")]
    LegacyCutoverIdMismatch,
    #[error("a planned legacy profile conflicts with an existing native profile")]
    LegacyProfileConflict,
    #[error(
        "fresh Agents are not all enrolled; connect and approve every cutover profile before cleanup"
    )]
    LegacyProfilesNotConnected,
    #[error("legacy TypeScript cutover failed: {0}")]
    LegacyTypeScript(#[from] LegacyTypeScriptError),
    #[error(
        "legacy cleanup is still pending; recover it with the previous runtime before upgrading"
    )]
    LegacyCleanupPending,
    #[error("public Agent metadata failed integrity verification; no credential was opened")]
    IntegrityViolation,
    #[error("an authenticated integrity transition could not be recovered; no new operation ran")]
    IntegrityRecoveryRequired,
    #[error("secure rollback failed; run palladin doctor before retrying")]
    CleanupFailed,
    #[error("secure random identifier generation failed")]
    RandomGenerationFailed,
    #[error("operation authorization sequence is exhausted; restart the native runtime")]
    OperationSequenceExhausted,
    #[error("fresh operating-system authorization expired or was revoked")]
    OperationAuthorizationExpired,
    #[error("operation does not match the exact operating-system authorization")]
    OperationAuthorizationMismatch,
    #[error("the exact operating-system authorization was already consumed")]
    OperationAuthorizationConsumed,
    #[error(
        "this pre-boundary macOS identity cannot be migrated in place; purge it and create a fresh Agent identity"
    )]
    PreBoundaryIdentityResetRequired,
    #[error("system clock formatting failed")]
    Clock,
    #[error("credential wait was cancelled")]
    WaitCancelled,
    #[error("credential wait policy is invalid: {0}")]
    InvalidWaitPolicy(#[from] WaitPolicyError),
    #[error("credential execution failed: {0}")]
    Exec(#[from] ExecError),
    #[error("credential execution environment is invalid: {0}")]
    Environment(#[from] EnvironmentError),
    #[error("the credential payload is invalid")]
    InvalidCredentialPayload,
    #[error("no command was provided for a non-Script entry")]
    MissingExecCommand,
    #[error("a command cannot be provided for a Script entry")]
    CommandProvidedForScript,
    #[error("explicit environment mappings cannot be provided for a Script entry")]
    EnvironmentMappingForScript,
    #[error("an environment mapping is invalid")]
    InvalidEnvironmentMapping,
    #[error("an environment mapping selects an unavailable field")]
    InvalidEnvironmentField,
    #[error("a Script entry reference was not granted")]
    ScriptReferenceNotGranted,
}

fn prepare_explicit_environment(
    secret: &palladin_credential::secret::ParsedSecret,
    mappings: &[String],
    environment: &mut SecretEnvironment,
) -> Result<(), RuntimeError> {
    let mut parsed = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let Some((name, field)) = mapping.split_once('=') else {
            return Err(RuntimeError::InvalidEnvironmentMapping);
        };
        let name = name.trim();
        let field = field.trim();
        if field.is_empty() {
            return Err(RuntimeError::InvalidEnvironmentMapping);
        }
        validate_reference_name(name)?;
        if parsed
            .iter()
            .any(|(existing, _): &(String, String)| existing.eq_ignore_ascii_case(name))
        {
            return Err(EnvironmentError::DuplicateName.into());
        }
        parsed.push((name.to_owned(), field.to_owned()));
    }
    for (name, field) in parsed {
        let value = resolve_field(
            secret,
            &FieldSelector {
                field: Some(field),
                field_id: None,
            },
        )
        .map_err(|_| RuntimeError::InvalidEnvironmentField)?
        .expose_for_authorized_operation()
        .to_owned();
        environment.insert_reference(&name, value.into())?;
    }
    Ok(())
}

fn preflight_script_references(script: &ScriptPayload) -> Result<(), RuntimeError> {
    let mut names = BTreeSet::new();
    for reference in &script.refs {
        validate_reference_name(&reference.env)?;
        let normalized = reference.env.to_ascii_uppercase();
        if !names.insert(normalized) {
            return Err(EnvironmentError::DuplicateName.into());
        }
        if reference.entry_id.trim().is_empty()
            || reference
                .vault_id
                .as_ref()
                .is_some_and(|vault_id| vault_id.trim().is_empty())
        {
            return Err(RuntimeError::InvalidEnvironmentMapping);
        }
    }
    Ok(())
}

fn generate_opaque_id() -> Result<String, RuntimeError> {
    loop {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeError::RandomGenerationFailed)?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(32);
        for byte in bytes {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        if value != TRUST_OWNER_ID {
            return Ok(value);
        }
    }
}

fn now_rfc3339() -> Result<String, RuntimeError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| RuntimeError::Clock)
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn test_lease() -> OperationLease {
        let scope = OperationScope::new(
            "11111111111111111111111111111111",
            std::iter::empty::<String>(),
        )
        .expect("scope");
        OperationAuthorization::for_current_platform(&scope, b"runtime-test-operation")
            .expect("authorization")
            .into_lease()
            .expect("lease")
    }

    #[test]
    fn operation_descriptor_digest_binds_semantic_inputs_and_redacts_debug() {
        let base = OperationDescriptor::GetCredential {
            surface: InvocationSurface::Mcp,
            vault_id: "vault-a".to_owned(),
            entry_id: "entry-a".to_owned(),
            reason: Some("approval reason".to_owned()),
            wait: WaitOptions {
                wait_ms: Some(1_000),
                poll_ms: Some(250),
                progress: Some(palladin_credential::wait::ProgressMode::Json),
            },
            field: Some("password".to_owned()),
            field_id: None,
            output: CredentialOutputPolicy::McpSecretResponse,
        };
        let base_digest = base.digest();
        let mutations = [
            OperationDescriptor::GetCredential {
                surface: InvocationSurface::Cli,
                vault_id: "vault-a".to_owned(),
                entry_id: "entry-a".to_owned(),
                reason: Some("approval reason".to_owned()),
                wait: WaitOptions {
                    wait_ms: Some(1_000),
                    poll_ms: Some(250),
                    progress: Some(palladin_credential::wait::ProgressMode::Json),
                },
                field: Some("password".to_owned()),
                field_id: None,
                output: CredentialOutputPolicy::McpSecretResponse,
            },
            OperationDescriptor::GetCredential {
                surface: InvocationSurface::Mcp,
                vault_id: "vault-b".to_owned(),
                entry_id: "entry-a".to_owned(),
                reason: Some("approval reason".to_owned()),
                wait: WaitOptions {
                    wait_ms: Some(1_000),
                    poll_ms: Some(250),
                    progress: Some(palladin_credential::wait::ProgressMode::Json),
                },
                field: Some("password".to_owned()),
                field_id: None,
                output: CredentialOutputPolicy::McpSecretResponse,
            },
            OperationDescriptor::GetCredential {
                surface: InvocationSurface::Mcp,
                vault_id: "vault-a".to_owned(),
                entry_id: "entry-b".to_owned(),
                reason: Some("approval reason".to_owned()),
                wait: WaitOptions {
                    wait_ms: Some(1_000),
                    poll_ms: Some(250),
                    progress: Some(palladin_credential::wait::ProgressMode::Json),
                },
                field: Some("password".to_owned()),
                field_id: None,
                output: CredentialOutputPolicy::McpSecretResponse,
            },
            OperationDescriptor::GetCredential {
                surface: InvocationSurface::Mcp,
                vault_id: "vault-a".to_owned(),
                entry_id: "entry-a".to_owned(),
                reason: Some("different reason".to_owned()),
                wait: WaitOptions {
                    wait_ms: Some(2_000),
                    poll_ms: Some(250),
                    progress: Some(palladin_credential::wait::ProgressMode::Json),
                },
                field: None,
                field_id: Some("field-id".to_owned()),
                output: CredentialOutputPolicy::CliSecretStdout,
            },
        ];
        assert!(
            mutations
                .iter()
                .all(|descriptor| descriptor.digest() != base_digest)
        );
        let debug = format!("{base:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("vault-a"));
        assert!(!debug.contains("approval reason"));
    }

    #[tokio::test]
    async fn delivery_enforces_the_exact_method_and_never_decrypts_before_granted() {
        let non_granted_bodies = [
            r#"{"access":"denied"}"#,
            r#"{"access":"revoked"}"#,
            r#"{"access":"expired"}"#,
            r#"{"access":"consumed"}"#,
            r#"{"access":"method-not-allowed"}"#,
            r#"{"access":"script-exec-only"}"#,
            r#"{"access":"unavailable"}"#,
            r#"{"access":"blocked"}"#,
        ];
        let mut bodies = vec![
            r#"{"access":"pending","grantId":"grant-get"}"#,
            r#"{"access":"pending","grantId":"grant-exec"}"#,
            r#"{"access":"pending","grantId":"grant-inject"}"#,
        ];
        bodies.extend(non_granted_bodies);
        let (host, requests) = credential_server(bodies).await;
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let session = RuntimeSession {
            profile: PublicAgentEntry {
                name: "fixture".to_owned(),
                identity_id: "11111111111111111111111111111111".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                agent_type: None,
                config_digest: None,
            },
            config: PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                identity_id: "11111111111111111111111111111111".to_owned(),
                host,
                organization_credential_id: "22222222222222222222222222222222".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: None,
                agent_active: false,
                encryption_public_key: None,
                signing_public_key: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            },
            api,
            encryption,
            lease: test_lease(),
            operation: RuntimeOperation::GetCredential,
            consumed: AtomicBool::new(false),
        };

        let get = session
            .deliver_credential(
                request(),
                CredentialMethod::Get,
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        let exec = session
            .deliver_credential(
                request(),
                CredentialMethod::Exec,
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        let inject = session
            .deliver_credential(
                request(),
                CredentialMethod::Inject,
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        for delivery in [get, exec, inject] {
            let delivery = delivery.expect("pending is a valid delivery result");
            assert!(matches!(
                delivery,
                CredentialDelivery::NotGranted(CredentialAccess::Pending { .. })
            ));
        }

        for _ in non_granted_bodies {
            let delivery = session
                .deliver_credential(
                    request(),
                    CredentialMethod::Get,
                    &CancellationToken::new(),
                    |_| {},
                )
                .await
                .expect("non-granted state is a valid delivery result");
            assert!(matches!(delivery, CredentialDelivery::NotGranted(_)));
        }

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 11);
        for (request, method) in requests.iter().take(3).zip(["Get", "Exec", "Inject"]) {
            let contains_key = request.contains("x-api-key: pl_shared_organization_fixture\r\n");
            assert!(contains_key, "request omitted the organization credential");
            assert!(request.contains(&format!(r#""method":"{method}""#)));
            assert!(!request.contains("requestedMethods"));
        }
    }

    #[tokio::test]
    async fn native_exec_delivers_with_exec_and_runs_without_shell_or_protocol_stdin() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/v1/encrypted-envelope.json"
        ))
        .expect("envelope fixture");
        let mut body = json!({
            "access": "granted",
            "entryId": "entry-fixture",
            "label": "Fixture credential",
            "urlDomain": "example.test",
        });
        body.as_object_mut().expect("body").extend(
            fixture
                .get("envelope")
                .and_then(serde_json::Value::as_object)
                .expect("envelope")
                .clone(),
        );
        let body = body.to_string();
        let (host, requests) = credential_server_owned(vec![body]).await;
        let private_key = STANDARD
            .decode(
                fixture
                    .pointer("/keyFixture/privateKeyBase64")
                    .and_then(serde_json::Value::as_str)
                    .expect("private key"),
            )
            .expect("private key base64");
        let encryption = X25519Identity::from_private_bytes(private_key).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let session = runtime_session(host, api, encryption);
        let command = native_exec_test_command();
        let outcome = session
            .execute_with_credential(
                CredentialExecRequest {
                    delivery: request(),
                    command: Some(&command),
                    env_mappings: &[],
                    output: OperatorOutput::Discard,
                },
                &CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("exec");
        assert_eq!(
            outcome,
            CredentialExecOutcome::Completed(ExecResult {
                exit_code: 0,
                cancelled: false,
            })
        );
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains(r#""method":"Exec""#));
        let contains_key = requests[0].contains("x-api-key: pl_shared_organization_fixture\r\n");
        assert!(contains_key, "request omitted the organization credential");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn script_resolves_every_reference_before_spawning_the_allowlisted_interpreter() {
        let main = r#"{"access":"granted","entryId":"script-entry","label":"Fixture Script","urlDomain":null,"nonce":"p4zno4W6mNfd0WESkmk6Kg2IzO9VsLxw","reEncryptedBlob":"sd652QzdkDm9esJ/oNXFj2J5fC1yiVt40hc3KdkrX9oosfMa1mNPQq9uJs0aY+MJlcID+MJpSALUZssy1+4pg3nYTsg0Tg/58BaKvfs34FT3vDZZvBexrh4l+erGCHrxX1ZMuPcz3E1Y5dcXH9hTb9d0imuq0udEc3ggfR5NcTkj9qLTrWUGyUKta0MWzJ10t8GmsJD899XLNnLu/IpmDcLoiUaPICtNrKMQUco=","agentWrappedDek":"7zIytOfJ4bPy68f1zA6o9hCieaMWSV/KbhQlaMQbtXiNP+okqawLXloq78+y7TU+OaldelM2pCAx/bBrw7WKIVq+MRhs/AXtAxHXeIzqgB8="}"#.to_owned();
        let reference = r#"{"access":"granted","entryId":"entry-ref","label":"Fixture Reference","urlDomain":null,"nonce":"ESDpZ93lTBOWJ52IGTpCvMNF76YvF0V7","reEncryptedBlob":"OOLe+QqjuYw/m+64+bzeSsU5T3/G91MQDV5/H+sizDmk4XfZ/77ghOhd2e9P3gKRVO33YZFycDLtzw==","agentWrappedDek":"I3SAjwhivFjXmwGAb2AQgmVsafe1vptGc/HhvGzb2gVn2n+7VykBumldS5PEq3zwH/IL76EUo9vstSOxY+e4BtmpsbcOm1r08la/FFTxyjg="}"#.to_owned();
        let (host, requests) = credential_server_owned(vec![main, reference]).await;
        let (api, encryption) = fixture_api(&host);
        let session = runtime_session(host, api, encryption);
        let outcome = session
            .execute_with_credential(
                CredentialExecRequest {
                    delivery: CredentialDeliveryRequest {
                        vault_id: "script-vault",
                        entry_id: "script-entry",
                        reason: Some("fixture reason"),
                        wait: WaitOptions {
                            wait_ms: Some(0),
                            poll_ms: None,
                            progress: None,
                        },
                    },
                    command: None,
                    env_mappings: &[],
                    output: OperatorOutput::Discard,
                },
                &CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("script exec");
        assert_eq!(
            outcome,
            CredentialExecOutcome::Completed(ExecResult {
                exit_code: 0,
                cancelled: false,
            })
        );
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("/vaults/script-vault/entries/script-entry/credential"));
        assert!(requests[1].contains("/vaults/script-vault/entries/entry-ref/credential"));
        assert!(
            requests
                .iter()
                .all(|request| request.contains(r#""method":"Exec""#))
        );
    }

    #[cfg(not(windows))]
    #[test]
    #[ignore = "subprocess helper"]
    fn native_exec_child() {
        let mut byte = [0_u8; 1];
        let stdin_is_eof = std::io::stdin().read(&mut byte).expect("stdin") == 0;
        assert!(stdin_is_eof);
        let credential_matches =
            std::env::var("CLAW_SECRET").as_deref() == Ok("fixture-password-not-production");
        assert!(credential_matches, "credential environment value diverged");
        let username_matches = std::env::var("CLAW_USERNAME").as_deref() == Ok("fixture-user");
        assert!(username_matches, "username environment value diverged");
        assert!(std::env::var_os("PALLADIN_API_KEY").is_none());
    }

    #[cfg(not(windows))]
    fn native_exec_test_command() -> Vec<String> {
        vec![
            std::env::current_exe()
                .expect("test executable")
                .to_string_lossy()
                .into_owned(),
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "tests::native_exec_child".to_owned(),
            "--nocapture".to_owned(),
        ]
    }

    #[cfg(windows)]
    fn native_exec_test_command() -> Vec<String> {
        vec![
            "cmd.exe".to_owned(),
            "/D".to_owned(),
            "/S".to_owned(),
            "/C".to_owned(),
            "setlocal EnableExtensions DisableDelayedExpansion & set /p PALLADIN_INPUT= & if not errorlevel 1 exit /b 90 & if not x%CLAW_SECRET%==xfixture-password-not-production exit /b 91 & if not x%CLAW_USERNAME%==xfixture-user exit /b 92 & if defined PALLADIN_API_KEY exit /b 93 & exit /b 0".to_owned(),
        ]
    }

    fn request() -> CredentialDeliveryRequest<'static> {
        CredentialDeliveryRequest {
            vault_id: "vault-fixture",
            entry_id: "entry-fixture",
            reason: Some("fixture reason"),
            wait: WaitOptions {
                wait_ms: Some(0),
                poll_ms: None,
                progress: None,
            },
        }
    }

    async fn credential_server(bodies: Vec<&'static str>) -> (String, Arc<Mutex<Vec<String>>>) {
        credential_server_owned(bodies.into_iter().map(str::to_owned).collect()).await
    }

    async fn credential_server_owned(bodies: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            for body in bodies {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let request = read_request(&mut stream).await;
                captured.lock().expect("requests").push(request);
                let response = format!(
                    "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.expect("write");
            }
        });
        (format!("http://{address}"), requests)
    }

    fn runtime_session(host: String, api: ApiClient, encryption: X25519Identity) -> RuntimeSession {
        RuntimeSession {
            profile: PublicAgentEntry {
                name: "fixture".to_owned(),
                identity_id: "11111111111111111111111111111111".to_owned(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                agent_type: None,
                config_digest: None,
            },
            config: PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                identity_id: "11111111111111111111111111111111".to_owned(),
                host,
                organization_credential_id: "22222222222222222222222222222222".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: None,
                agent_active: false,
                encryption_public_key: None,
                signing_public_key: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            },
            api,
            encryption,
            lease: test_lease(),
            operation: RuntimeOperation::ExecWithCredential,
            consumed: AtomicBool::new(false),
        }
    }

    #[cfg(not(windows))]
    fn fixture_api(host: &str) -> (ApiClient, X25519Identity) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/v1/encrypted-envelope.json"
        ))
        .expect("envelope fixture");
        let private_key = STANDARD
            .decode(
                fixture
                    .pointer("/keyFixture/privateKeyBase64")
                    .and_then(serde_json::Value::as_str)
                    .expect("private key"),
            )
            .expect("private key base64");
        let encryption = X25519Identity::from_private_bytes(private_key).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        (api, encryption)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.expect("read");
            assert!(read > 0, "request ended before its body");
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_bytes = &bytes[..header_end + 4];
                let headers = String::from_utf8_lossy(header_bytes);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        String::from_utf8(bytes).expect("request is UTF-8")
    }
}
