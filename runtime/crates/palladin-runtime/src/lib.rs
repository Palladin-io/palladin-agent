#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod discovery;
mod form_map_cache;
mod integrity;
pub mod version_policy;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_api::{
    AgentDiscoveryEnvelope, AgentDiscoveryEnvelopeDescriptor, AgentDiscoverySyncItem,
    AgentPairingActivationResponse, AgentPairingStatus, AgentPairingStatusResponse,
    AgentRegistrationResult, AgentVaultManifestsResponse, AgentVisibleField, ApiClient, ApiError,
    CredentialAccess, CredentialCiphertext, CredentialGrantType, CredentialMethod,
    EntrySearchResult, FormDiscoveryMap, GetCredentialOptions, GrantStatus,
    ReportCredentialStaleInput, VaultManifest,
};
use palladin_browser_bridge::secure_transport::{BrowserHostIdentity, SecureTransportError};
use palladin_browser_bridge::{
    FormDiscoveryMapDefinition, InjectionFormDefinition, form_discovery_map_fingerprint,
    form_discovery_map_login_url,
};
use palladin_core::host::ApiHost;
use palladin_core::legacy_typescript::{LegacyTypeScriptError, LegacyTypeScriptRepository};
use palladin_core::profiles::{
    ProfileError, ProfileName, ProfileRepository, TransactionLock, add_profile, delete_profile,
    purge_profile, rename_profile, set_default, set_profile_type,
};
use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicDiscoveryCacheCommitment, PublicProfileConfig,
    PublicRegistry, PublicVaultTrustAnchor, profile_binding_bytes, profile_config_digest,
    registry_digest,
};
use palladin_core::secret::OrganizationApiKey;
use palladin_core::terminal::shorten_identifier;
use palladin_credential::wait::{
    HeartbeatInfo, WaitError, WaitHints, WaitOptions, WaitPolicyError, await_grant_exponential,
    resolve_wait_policy,
};
use palladin_crypto::{
    AgentIdentityBinding, CredentialEnvelopeContext, DecryptedCredential, Ed25519Identity,
    EncodedSuitePayload, EncryptedReasonContext, EnvelopeBinding, EnvelopeDescriptor,
    EnvelopePurpose, EnvelopeScope, ExpectedScriptExecutionPackageContext,
    FullCredentialEnvelopeContext, FullScriptMemberSecretContext, PairingCandidate,
    PairingRelayStatus, PinnedVaultTrust, RecipientKeyKind, SealedWrappedKey, SecretBytes,
    VaultManifestV2, WrapperContext, WrapperPurpose, X25519Identity, X25519SealedBoxSuite,
    XChaChaVaultSuite, confirm_pairing_from_relay, decode_base64url, decrypt_credential,
    decrypt_full_credential, decrypt_full_script_member_secret, encode_script_execution_parameters,
    key_fingerprint, open_local_discovery_cache, open_script_execution_package, prepare_pairing,
    seal_local_discovery_cache, verify_agent_wrapped_vault_key_producer, verify_current_manifest,
    verify_profile_binding,
};
use palladin_exec::{
    CapturedScriptResult, EnvironmentError, SecretEnvironment, resolve_interpreter, run_command,
    run_script_captured, validate_command, validate_reference_name,
};
pub use palladin_platform::secure_store::SecretStore;
use palladin_platform::secure_store::{
    AuthorizationPrompt, BROWSER_HOST_IDENTITY_OWNER_ID, OperationAuthorization, OperationLease,
    OperationScope, SecretSlot, StoreError, delete_identity, delete_legacy_identity,
    delete_legacy_organization_credential, delete_organization_credential,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const AGENT_DISCOVERY_VDK_WRAPPER_PURPOSE: &str = "agentDiscoveryVdk";
const AGENT_X25519_RECIPIENT_KEY_KIND: &str = "agentX25519";
const AGENT_WRAPPED_VDK_DIGEST_PREFIX: &[u8] = b"PLDNV2DG:AGENT-WRAPPED-VDK:";

use discovery::{DiscoveryPlaintext, LocalDiscoveryIndex};
use form_map_cache::{FormMapCache, FormMapCacheError};

use integrity::{
    ConfigWrite, DiscoveryCacheWrite, IntegrityJournal, MAX_DISCOVERY_CACHE_CIPHERTEXT_BYTES,
    SecretAllocation, SecretCopy, SecretDeletion, TRUST_OWNER_ID, TrustState, decode_trust_state,
    encode_trust_state, hex_digest, journal_path, load_journal, remove_journal, save_journal,
};

use palladin_credential::fields::{FieldSelector, resolve_field};
use palladin_credential::secret::{
    parse_member_script, parse_secret, resolve_grant_payload_field,
    resolve_script_reference_member_field,
};

const DISCOVERY_SYNC_PAGE_SIZE: usize = 200;
const MAX_DISCOVERY_SYNC_PAGES: usize = 1_000;
const MAX_SYNC_STATE_CHANGED_ATTEMPTS: usize = 3;
const SYNC_STATE_CHANGED_BACKOFF_MS: u64 = 50;

fn update_registered_agent_id(config: &mut PublicProfileConfig, agent_id: &str) {
    if config.agent_id.as_deref() != Some(agent_id) {
        config.vault_trust_anchors.clear();
    }
    config.agent_id = Some(agent_id.to_owned());
}

pub use palladin_exec::{ExecError, ExecResult, OperatorOutput};

pub struct RuntimeService<S> {
    repository: ProfileRepository,
    secrets: S,
    discovery: Arc<tokio::sync::Mutex<LocalDiscoveryIndex>>,
}

const OPERATION_BINDING_DOMAIN: &[u8] = b"palladin.runtime.exact-operation.v1";
const OPERATION_TTL_MS: i128 = 300_000;
const BROWSER_HOST_LIFECYCLE_TOKEN_BYTES: usize = 32;

/// Installation-scoped browser identity and the unforgeable lifecycle generation that was
/// current when it was opened. The token is intentionally opaque and never crosses either wire.
pub struct BrowserHostPairing {
    identity: BrowserHostIdentity,
    lifecycle_token: BrowserHostLifecycleToken,
}

impl BrowserHostPairing {
    #[must_use]
    pub fn identity(&self) -> &BrowserHostIdentity {
        &self.identity
    }

    #[must_use]
    pub fn lifecycle_token(&self) -> &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES] {
        self.lifecycle_token.as_bytes()
    }
}

struct BrowserHostLifecycleToken(Zeroizing<[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES]>);

impl BrowserHostLifecycleToken {
    fn new(value: [u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES]) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_bytes(&self) -> &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES] {
        &self.0
    }
}

/// Shared cross-process lease held from the final secure-store token recheck through a complete
/// browser request/response. Explicit unpair takes the exclusive side of the same lock.
pub struct BrowserHostLifecycleGuard {
    _lock: TransactionLock,
}

/// Final Inject forwarding authorization. It owns the shared lifecycle lock and exposes only the
/// already-rechecked time budget for the single ciphertext send/response exchange.
pub struct BrowserInjectForwardGuard {
    _lifecycle: BrowserHostLifecycleGuard,
    deadline: std::time::Instant,
}

impl BrowserInjectForwardGuard {
    #[must_use]
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
    }
}

/// Exclusive revocation lease. Callers keep this alive through manifest cleanup so a concurrent
/// install cannot publish a new pairing until the unpair command has reached its success point.
pub struct BrowserHostRevocationGuard {
    _lock: TransactionLock,
}

/// Exclusive provisioning lease kept through manifest publication so install and unpair have one
/// total cross-process order.
pub struct BrowserHostProvisioningGuard {
    pairing: BrowserHostPairing,
    _lock: TransactionLock,
}

impl BrowserHostProvisioningGuard {
    #[must_use]
    pub fn identity(&self) -> &BrowserHostIdentity {
        self.pairing.identity()
    }
}

fn new_browser_host_lifecycle_token() -> Result<BrowserHostLifecycleToken, RuntimeError> {
    let mut token = [0_u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_| RuntimeError::RandomGenerationFailed)?;
    Ok(BrowserHostLifecycleToken::new(token))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeOperation {
    Connect,
    Status,
    SearchEntries,
    GetCredential,
    InjectCredential,
    ExecWithCredential,
    ReportCredentialStale,
    PairVaults,
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
            Self::InjectCredential => "inject_credential",
            Self::ExecWithCredential => "exec_with_credential",
            Self::ReportCredentialStale => "report_credential_stale",
            Self::PairVaults => "pair_vaults",
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
            Self::InjectCredential => AuthorizationPrompt::InjectCredential,
            Self::ExecWithCredential => AuthorizationPrompt::ExecWithCredential,
            Self::ReportCredentialStale => AuthorizationPrompt::ReportCredentialStale,
            Self::VerifyIdentity | Self::UpgradeSecurity | Self::PairVaults => {
                AuthorizationPrompt::IdentityManagement
            }
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
    TrustedInjectionProvider,
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
    InjectCredential {
        surface: InvocationSurface,
        vault_id: String,
        entry_id: String,
        reason: Option<String>,
        wait: WaitOptions,
        provider: String,
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
        parameters_digest: [u8; 32],
        output: CredentialOutputPolicy,
    },
    ReportCredentialStale {
        surface: InvocationSurface,
        vault_id: String,
        entry_id: String,
        code: String,
    },
    PairVaults {
        activation_id: String,
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
            Self::InjectCredential { .. } => RuntimeOperation::InjectCredential,
            Self::ExecWithCredential { .. } => RuntimeOperation::ExecWithCredential,
            Self::ReportCredentialStale { .. } => RuntimeOperation::ReportCredentialStale,
            Self::PairVaults { .. } => RuntimeOperation::PairVaults,
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
            Self::InjectCredential {
                surface,
                vault_id,
                entry_id,
                reason,
                wait,
                provider,
                output,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.optional(reason.as_deref());
                encoder.wait(*wait);
                encoder.field(provider.as_bytes());
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
                parameters_digest,
                output,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.optional(reason.as_deref());
                encoder.wait(*wait);
                encoder.strings(command);
                encoder.strings(env_mappings);
                encoder.field(parameters_digest);
                encoder.output(*output);
            }
            Self::ReportCredentialStale {
                surface,
                vault_id,
                entry_id,
                code,
            } => {
                encoder.surface(*surface);
                encoder.field(vault_id.as_bytes());
                encoder.field(entry_id.as_bytes());
                encoder.field(code.as_bytes());
            }
            Self::PairVaults { activation_id } => encoder.field(activation_id.as_bytes()),
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
            CredentialOutputPolicy::TrustedInjectionProvider => 5,
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

impl<S: SecretStore + Sync> RuntimeService<S> {
    #[must_use]
    pub fn new(repository: ProfileRepository, secrets: S) -> Self {
        Self {
            repository,
            secrets,
            discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
        }
    }

    #[must_use]
    pub fn repository(&self) -> &ProfileRepository {
        &self.repository
    }

    /// Load the installation-scoped browser host identity. A Native Messaging host must never
    /// create trust on first use; absence means explicit browser pairing has not completed.
    pub fn browser_host_identity(&self) -> Result<BrowserHostIdentity, RuntimeError> {
        Ok(self.browser_host_pairing()?.identity)
    }

    /// Open one consistent browser pairing snapshot under the shared lifecycle lock.
    pub fn browser_host_pairing(&self) -> Result<BrowserHostPairing, RuntimeError> {
        let _lock = self.repository.acquire_shared_transaction_lock()?;
        self.load_browser_host_pairing()
    }

    /// Provision the durable host identity only from the explicit pairing flow. The repository
    /// transaction lock prevents concurrent pairing processes from pinning different keys.
    pub fn provision_browser_host_identity(&self) -> Result<BrowserHostIdentity, RuntimeError> {
        Ok(self.provision_browser_host_pairing()?.identity)
    }

    /// Provision both the durable signing identity and a fresh lifecycle token. Existing
    /// pre-token installations are upgraded only from this explicit install flow.
    pub fn provision_browser_host_pairing(&self) -> Result<BrowserHostPairing, RuntimeError> {
        let BrowserHostProvisioningGuard {
            pairing,
            _lock: lock,
        } = self.provision_browser_host_pairing_locked()?;
        drop(lock);
        Ok(pairing)
    }

    /// Provision while retaining the exclusive lifecycle lease. The CLI holds the returned value
    /// until the exact Native Messaging manifest has been durably published.
    pub fn provision_browser_host_pairing_locked(
        &self,
    ) -> Result<BrowserHostProvisioningGuard, RuntimeError> {
        let lock = self.repository.acquire_transaction_lock()?;
        let pairing = self.provision_browser_host_pairing_unlocked()?;
        Ok(BrowserHostProvisioningGuard {
            pairing,
            _lock: lock,
        })
    }

    fn provision_browser_host_pairing_unlocked(&self) -> Result<BrowserHostPairing, RuntimeError> {
        let stored_identity = self.secrets.get(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostEd25519SecretKeyV1,
        )?;
        let stored_token = self.secrets.get(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostLifecycleTokenV1,
        )?;
        if stored_identity.is_some() && stored_token.is_some() {
            return self.load_browser_host_pairing();
        }
        if stored_identity.is_none() && stored_token.is_some() {
            return Err(RuntimeError::InvalidStoredSecret);
        }
        if let Some(secret) = stored_identity {
            let identity = BrowserHostIdentity::from_secret_slice(secret.expose_secret())?;
            let lifecycle_token = new_browser_host_lifecycle_token()?;
            self.secrets.set(
                BROWSER_HOST_IDENTITY_OWNER_ID,
                SecretSlot::BrowserHostLifecycleTokenV1,
                lifecycle_token.as_bytes(),
            )?;
            return Ok(BrowserHostPairing {
                identity,
                lifecycle_token,
            });
        }
        let identity = BrowserHostIdentity::generate()?;
        let lifecycle_token = new_browser_host_lifecycle_token()?;
        let secret = identity.secret_bytes();
        self.secrets.set(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostEd25519SecretKeyV1,
            secret.as_ref(),
        )?;
        if let Err(error) = self.secrets.set(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostLifecycleTokenV1,
            lifecycle_token.as_bytes(),
        ) {
            if self
                .secrets
                .delete(
                    BROWSER_HOST_IDENTITY_OWNER_ID,
                    SecretSlot::BrowserHostEd25519SecretKeyV1,
                )
                .is_err()
            {
                return Err(RuntimeError::CleanupFailed);
            }
            return Err(error.into());
        }
        Ok(BrowserHostPairing {
            identity,
            lifecycle_token,
        })
    }

    /// Revalidate a pairing generation while holding the shared side of the cross-process
    /// lifecycle lock. The returned guard must live across the complete external forward and its
    /// response so an exclusive unpair cannot report success while that operation is active.
    pub fn browser_host_lifecycle_guard(
        &self,
        expected: &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES],
    ) -> Result<BrowserHostLifecycleGuard, RuntimeError> {
        let lock = self.repository.acquire_shared_transaction_lock()?;
        self.validate_browser_host_lifecycle_token(expected)?;
        Ok(BrowserHostLifecycleGuard { _lock: lock })
    }

    /// Acquire and validate a browser-host lifecycle lease without waiting past `max_wait`.
    /// This keeps an installation or revocation operation from extending a bounded browser
    /// protocol operation indefinitely.
    pub fn browser_host_lifecycle_guard_within(
        &self,
        expected: &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES],
        max_wait: std::time::Duration,
    ) -> Result<BrowserHostLifecycleGuard, RuntimeError> {
        let lock = self
            .repository
            .acquire_shared_transaction_lock_for(max_wait)?
            .ok_or(RuntimeError::BrowserHostLifecycleBusy)?;
        self.validate_browser_host_lifecycle_token(expected)?;
        Ok(BrowserHostLifecycleGuard { _lock: lock })
    }

    fn validate_browser_host_lifecycle_token(
        &self,
        expected: &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES],
    ) -> Result<(), RuntimeError> {
        let current = self
            .secrets
            .get(
                BROWSER_HOST_IDENTITY_OWNER_ID,
                SecretSlot::BrowserHostLifecycleTokenV1,
            )?
            .ok_or(RuntimeError::BrowserHostRevoked)?;
        if current.expose_secret().len() != expected.len()
            || current.expose_secret().ct_eq(expected).unwrap_u8() != 1
        {
            return Err(RuntimeError::BrowserHostRevoked);
        }
        Ok(())
    }

    /// Revoke active browser sessions first, then remove their signing key. The repository's
    /// exclusive lock makes this linearizable against every shared forwarding lease.
    pub fn unpair_browser_host_identity(&self) -> Result<BrowserHostRevocationGuard, RuntimeError> {
        let lock = self.repository.acquire_transaction_lock()?;
        self.secrets.delete(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostLifecycleTokenV1,
        )?;
        self.secrets.delete(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostEd25519SecretKeyV1,
        )?;
        Ok(BrowserHostRevocationGuard { _lock: lock })
    }

    fn load_browser_host_pairing(&self) -> Result<BrowserHostPairing, RuntimeError> {
        let identity = self.secrets.get(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostEd25519SecretKeyV1,
        )?;
        let lifecycle = self.secrets.get(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostLifecycleTokenV1,
        )?;
        let (Some(identity), Some(lifecycle)) = (identity, lifecycle) else {
            return Err(RuntimeError::BrowserHostNotPaired);
        };
        if lifecycle.expose_secret().len() != BROWSER_HOST_LIFECYCLE_TOKEN_BYTES {
            return Err(RuntimeError::InvalidStoredSecret);
        }
        let mut lifecycle_token = [0_u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES];
        lifecycle_token.copy_from_slice(lifecycle.expose_secret());
        Ok(BrowserHostPairing {
            identity: BrowserHostIdentity::from_secret_slice(identity.expose_secret())?,
            lifecycle_token: BrowserHostLifecycleToken::new(lifecycle_token),
        })
    }

    /// Verifies the complete public registry/config/signature chain without opening any secret.
    /// The protected trust-state commitment remains a separate secure-store check performed when
    /// an authorized operation opens a profile.
    pub fn verify_public_metadata(&self) -> Result<(), RuntimeError> {
        let registry = self.repository.load_registry()?;
        self.validate_registry_configs(&registry).map(|_| ())
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
        self.commit_profile_removal(&state, updated, deleted, &lease)
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
        self.commit_profile_removal(&state, updated, deleted.clone(), &lease)?;
        Ok(deleted)
    }

    fn commit_profile_removal(
        &self,
        state: &VerifiedState,
        updated: PublicRegistry,
        deleted: PublicAgentEntry,
        lease: &OperationLease,
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
        self.commit_authorized_transition(
            state,
            updated,
            Vec::new(),
            vec![deleted.identity_id],
            deletions,
            false,
            lease,
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
        if let Some(lease) = &lease {
            self.commit_authorized_transition(
                &state,
                PublicRegistry::default(),
                Vec::new(),
                identities,
                deletions,
                true,
                lease,
            )?;
        } else {
            self.commit_transition(
                &state,
                PublicRegistry::default(),
                Vec::new(),
                identities,
                deletions,
                true,
            )?;
        }
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
                vault_trust_anchors: existing_config
                    .as_ref()
                    .filter(|config| config.agent_id == agent_id)
                    .map(|config| config.vault_trust_anchors.clone())
                    .unwrap_or_default(),
                discovery_cache: existing_config
                    .as_ref()
                    .filter(|config| config.agent_id == agent_id)
                    .and_then(|config| config.discovery_cache.clone()),
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
            update_registered_agent_id(&mut config, agent_id);
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
        if !matches!(&registration, AgentRegistrationResult::Active { .. }) {
            self.discovery.lock().await.purge();
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
    ) -> Result<RuntimeSession<'_>, RuntimeError> {
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
        let pairing_activation_id = match &descriptor {
            OperationDescriptor::PairVaults { activation_id } => Some(activation_id.clone()),
            _ => None,
        };
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
        let profile_signing = Ed25519Identity::from_libsodium_secret(
            signing
                .libsodium_secret_for_secure_storage()
                .expose_secret()
                .to_vec(),
        )?;
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
            pairing_activation_id,
            discovery: Arc::clone(&self.discovery),
            manifest_persistence: Some(self),
            profile_signing: Some(profile_signing),
            form_map_root: self.repository.root().to_path_buf(),
        })
    }

    #[cfg(test)]
    fn persist_advanced_manifest_revision(
        &self,
        identity_id: &str,
        expected_anchor: &PublicVaultTrustAnchor,
        advanced: &PinnedVaultTrust,
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let mut config = state
            .configs
            .get(identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        let anchor = config
            .vault_trust_anchors
            .iter_mut()
            .find(|anchor| anchor.vault_id == expected_anchor.vault_id)
            .ok_or(RuntimeError::UntrustedVaultManifest)?;
        let current_revision = anchor
            .manifest_revision
            .parse::<u64>()
            .map_err(|_| RuntimeError::InvalidPublicConfig)?;
        let expected_profile_signing_key = STANDARD.encode(signing.public_key());
        if advanced.manifest_revision < current_revision
            || advanced.vdk_version < anchor.vdk_version
            || anchor.organization_id != expected_anchor.organization_id
            || anchor.vault_signing_public_key
                != URL_SAFE_NO_PAD.encode(advanced.signing_public_key)
            || anchor.vault_signing_key_fingerprint
                != URL_SAFE_NO_PAD.encode(advanced.signing_key_fingerprint)
            || anchor.manifest_signing_key_version != advanced.manifest_signing_key_version
            || config.signing_public_key.as_deref() != Some(expected_profile_signing_key.as_str())
        {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        if advanced.manifest_revision == current_revision
            && advanced.vdk_version == anchor.vdk_version
        {
            return Ok(());
        }
        anchor.manifest_revision = advanced.manifest_revision.to_string();
        anchor.vdk_version = advanced.vdk_version;
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
        self.commit_authorized_transition(
            &state,
            registry,
            vec![ConfigWrite {
                identity_id: identity_id.to_owned(),
                config,
            }],
            Vec::new(),
            Vec::new(),
            false,
            lease,
        )
    }

    fn persist_manifest_batch(
        &self,
        identity_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let mut config = state
            .configs
            .get(identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        let expected_profile_signing_key = STANDARD.encode(signing.public_key());
        if config.signing_public_key.as_deref() != Some(expected_profile_signing_key.as_str()) {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        if config.vault_trust_anchors == next_anchors {
            return Ok(());
        }
        if config.vault_trust_anchors != expected_anchors {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        config.vault_trust_anchors = next_anchors.to_vec();
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
        self.commit_authorized_transition(
            &state,
            registry,
            vec![ConfigWrite {
                identity_id: identity_id.to_owned(),
                config,
            }],
            Vec::new(),
            Vec::new(),
            false,
            lease,
        )
    }

    fn load_discovery_cache(
        &self,
        identity_id: &str,
        agent_id: &str,
        commitment: Option<&PublicDiscoveryCacheCommitment>,
        encryption: &X25519Identity,
    ) -> Result<LocalDiscoveryIndex, RuntimeError> {
        let Some(commitment) = commitment else {
            let mut index = LocalDiscoveryIndex::new();
            index.scope_to_identity(identity_id, agent_id);
            return Ok(index);
        };
        let ciphertext = self
            .repository
            .load_discovery_cache(identity_id, MAX_DISCOVERY_CACHE_CIPHERTEXT_BYTES)
            .map_err(|_| RuntimeError::IntegrityViolation)?;
        if hex_digest(Sha256::digest(&ciphertext)) != commitment.ciphertext_sha256 {
            return Err(RuntimeError::IntegrityViolation);
        }
        let binding = discovery_cache_binding(identity_id, agent_id, commitment.generation)?;
        let plaintext = open_local_discovery_cache(encryption, &binding, &ciphertext)
            .map_err(|_| RuntimeError::IntegrityViolation)?;
        LocalDiscoveryIndex::decode_durable_cache(
            plaintext.expose_for_crypto_operation(),
            identity_id,
            agent_id,
        )
        .map_err(|_| RuntimeError::IntegrityViolation)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_discovery_batch(
        &self,
        identity_id: &str,
        agent_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        expected_cache: Option<&PublicDiscoveryCacheCommitment>,
        next_cache: &PublicDiscoveryCacheCommitment,
        ciphertext: &[u8],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let mut config = state
            .configs
            .get(identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        if config.agent_id.as_deref() != Some(agent_id)
            || config.vault_trust_anchors != expected_anchors
            || config.discovery_cache.as_ref() != expected_cache
            || config.signing_public_key.as_deref()
                != Some(STANDARD.encode(signing.public_key()).as_str())
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_DISCOVERY_CACHE_CIPHERTEXT_BYTES
            || hex_digest(Sha256::digest(ciphertext)) != next_cache.ciphertext_sha256
            || next_cache.generation
                != expected_cache.map_or(1, |cache| cache.generation.saturating_add(1))
        {
            return Err(RuntimeError::IntegrityViolation);
        }
        config.vault_trust_anchors = next_anchors.to_vec();
        config.discovery_cache = Some(next_cache.clone());
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
        self.commit_authorized_transition_with_cache(
            &state,
            registry,
            vec![ConfigWrite {
                identity_id: identity_id.to_owned(),
                config,
            }],
            vec![DiscoveryCacheWrite {
                identity_id: identity_id.to_owned(),
                ciphertext_base64: STANDARD.encode(ciphertext),
            }],
            lease,
        )
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

    /// Atomically commits trust anchors produced by a locally verified pairing transcript.
    /// The caller must retain the in-memory candidate until Member confirmation succeeds; this
    /// method accepts only the resulting public anchors and binds them to signed profile state.
    pub fn persist_pairing_anchors(
        &self,
        profile_name: Option<&str>,
        hostname: &str,
        connection: &OperationConnection,
        confirmed: ConfirmedRuntimePairing,
    ) -> Result<PublicProfileConfig, RuntimeError> {
        let activation_id = confirmed.activation_id;
        let expected_identity = confirmed.identity;
        let mut anchors = confirmed.anchors;
        anchors.sort_by(|left, right| left.vault_id.cmp(&right.vault_id));
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let state = self.verified_state_locked()?;
        let profile = resolve_profile_in(&state.registry, profile_name)?;
        let descriptor = OperationDescriptor::PairVaults { activation_id };
        let (authorization, binding) = self.authorize_profile_operation_with_binding(
            &state,
            &profile,
            hostname,
            connection,
            &descriptor,
        )?;
        let (encryption, signing) = self.load_identity_verified_authorized(
            &profile.identity_id,
            state.configs.get(&profile.identity_id),
            &authorization,
            &binding,
        )?;
        let mut config = state
            .configs
            .get(&profile.identity_id)
            .cloned()
            .ok_or(RuntimeError::InvalidPublicConfig)?;
        validate_confirmed_pairing_identity(
            &expected_identity,
            &anchors,
            &config,
            encryption.public_key(),
            signing.public_key(),
        )?;
        config.vault_trust_anchors = anchors;
        let profile_binding =
            profile_binding_bytes(&config).map_err(|_| RuntimeError::InvalidPublicConfig)?;
        config.binding_signature = STANDARD.encode(signing.sign_profile_binding(&profile_binding));
        let config_digest =
            profile_config_digest(&config).map_err(|_| RuntimeError::InvalidPublicConfig)?;
        let mut registry = state.registry.clone();
        registry
            .agents
            .iter_mut()
            .find(|entry| entry.identity_id == profile.identity_id)
            .ok_or(RuntimeError::IntegrityViolation)?
            .config_digest = Some(config_digest);
        let lease = authorization.into_lease()?;
        self.commit_authorized_transition(
            &state,
            registry,
            vec![ConfigWrite {
                identity_id: profile.identity_id,
                config: config.clone(),
            }],
            Vec::new(),
            Vec::new(),
            false,
            &lease,
        )?;
        Ok(config)
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
                    vault_trust_anchors: Vec::new(),
                    discovery_cache: None,
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
        self.commit_transition_with_copies_inner(
            current,
            target_registry,
            config_writes,
            Vec::new(),
            remove_identity_directories,
            Vec::new(),
            secret_deletions,
            purge_public_root,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_authorized_transition(
        &self,
        current: &VerifiedState,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        remove_identity_directories: Vec<String>,
        secret_deletions: Vec<SecretDeletion>,
        purge_public_root: bool,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        self.commit_transition_with_copies_inner(
            current,
            target_registry,
            config_writes,
            Vec::new(),
            remove_identity_directories,
            Vec::new(),
            secret_deletions,
            purge_public_root,
            Some(lease),
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
        self.commit_transition_with_copies_inner(
            current,
            target_registry,
            config_writes,
            Vec::new(),
            remove_identity_directories,
            secret_copies,
            secret_deletions,
            purge_public_root,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_authorized_transition_with_cache(
        &self,
        current: &VerifiedState,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        discovery_cache_writes: Vec<DiscoveryCacheWrite>,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        self.commit_transition_with_copies_inner(
            current,
            target_registry,
            config_writes,
            discovery_cache_writes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            false,
            Some(lease),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_transition_with_copies_inner(
        &self,
        current: &VerifiedState,
        target_registry: PublicRegistry,
        config_writes: Vec<ConfigWrite>,
        discovery_cache_writes: Vec<DiscoveryCacheWrite>,
        remove_identity_directories: Vec<String>,
        secret_copies: Vec<SecretCopy>,
        secret_deletions: Vec<SecretDeletion>,
        purge_public_root: bool,
        operation_lease: Option<&OperationLease>,
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
        .with_secret_copies(secret_copies)?
        .with_discovery_cache_writes(discovery_cache_writes)?;
        // Lifecycle revocation and the durable transition marker are linearized
        // by this guard. Before the marker, revocation aborts with no committed
        // deletion. After the marker, recovery must finish the atomic journal.
        let mut commit_guard = operation_lease
            .map(OperationLease::begin_commit)
            .transpose()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
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
        if let Some(guard) = &mut commit_guard
            && guard.seal().is_err()
        {
            remove_journal(self.repository.root())?;
            return Err(RuntimeError::OperationAuthorizationExpired);
        }
        self.write_trust_state(&transition)?;
        drop(commit_guard);
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
        self.secrets.delete(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostLifecycleTokenV1,
        )?;
        self.secrets.delete(
            BROWSER_HOST_IDENTITY_OWNER_ID,
            SecretSlot::BrowserHostEd25519SecretKeyV1,
        )?;
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
        for write in &journal.discovery_cache_writes {
            let ciphertext = STANDARD
                .decode(&write.ciphertext_base64)
                .map_err(|_| RuntimeError::IntegrityRecoveryRequired)?;
            self.repository
                .save_discovery_cache(&write.identity_id, &ciphertext)?;
        }
        for write in &journal.config_writes {
            if write.config.discovery_cache.is_none() {
                self.repository
                    .remove_discovery_cache_if_present(&write.identity_id)?;
            }
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

pub struct RuntimeSession<'a> {
    profile: PublicAgentEntry,
    config: PublicProfileConfig,
    api: ApiClient,
    encryption: X25519Identity,
    lease: OperationLease,
    operation: RuntimeOperation,
    consumed: AtomicBool,
    pairing_activation_id: Option<String>,
    discovery: Arc<tokio::sync::Mutex<LocalDiscoveryIndex>>,
    manifest_persistence: Option<&'a dyn ManifestRevisionPersistence>,
    profile_signing: Option<Ed25519Identity>,
    form_map_root: std::path::PathBuf,
}

trait ManifestRevisionPersistence: Sync {
    fn persist_manifest_batch(
        &self,
        identity_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError>;

    fn load_discovery_cache(
        &self,
        identity_id: &str,
        agent_id: &str,
        commitment: Option<&PublicDiscoveryCacheCommitment>,
        encryption: &X25519Identity,
    ) -> Result<LocalDiscoveryIndex, RuntimeError>;

    #[allow(clippy::too_many_arguments)]
    fn persist_discovery_batch(
        &self,
        identity_id: &str,
        agent_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        expected_cache: Option<&PublicDiscoveryCacheCommitment>,
        next_cache: &PublicDiscoveryCacheCommitment,
        ciphertext: &[u8],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError>;
}

impl<S: SecretStore + Sync> ManifestRevisionPersistence for RuntimeService<S> {
    fn persist_manifest_batch(
        &self,
        identity_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        RuntimeService::persist_manifest_batch(
            self,
            identity_id,
            expected_anchors,
            next_anchors,
            signing,
            lease,
        )
    }

    fn load_discovery_cache(
        &self,
        identity_id: &str,
        agent_id: &str,
        commitment: Option<&PublicDiscoveryCacheCommitment>,
        encryption: &X25519Identity,
    ) -> Result<LocalDiscoveryIndex, RuntimeError> {
        RuntimeService::load_discovery_cache(self, identity_id, agent_id, commitment, encryption)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_discovery_batch(
        &self,
        identity_id: &str,
        agent_id: &str,
        expected_anchors: &[PublicVaultTrustAnchor],
        next_anchors: &[PublicVaultTrustAnchor],
        expected_cache: Option<&PublicDiscoveryCacheCommitment>,
        next_cache: &PublicDiscoveryCacheCommitment,
        ciphertext: &[u8],
        signing: &Ed25519Identity,
        lease: &OperationLease,
    ) -> Result<(), RuntimeError> {
        RuntimeService::persist_discovery_batch(
            self,
            identity_id,
            agent_id,
            expected_anchors,
            next_anchors,
            expected_cache,
            next_cache,
            ciphertext,
            signing,
            lease,
        )
    }
}

struct PreparedManifestItem {
    manifest: VaultManifestV2,
    vdk: SecretBytes,
}

struct PreparedManifestBatch {
    items: Vec<PreparedManifestItem>,
    next_anchors: Vec<PublicVaultTrustAnchor>,
}

struct PreparedDiscoveryCache {
    commitment: PublicDiscoveryCacheCommitment,
    ciphertext: Vec<u8>,
}

struct PreparedCredentialOptions {
    options: GetCredentialOptions,
    organization_id: Option<String>,
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
    pub parameters: &'a serde_json::Value,
    pub output: OperatorOutput,
}

impl RuntimeSession<'_> {
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

    fn inject_forward_remaining(
        &self,
        credential: &DeliveredCredential,
    ) -> Result<std::time::Duration, RuntimeError> {
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        if !self.consumed.load(Ordering::SeqCst) {
            return Err(RuntimeError::OperationAuthorizationMismatch);
        }
        let lease_remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let grant_remaining = credential
            .credential
            .remaining_validity_at(OffsetDateTime::now_utc())
            .map_err(|error| match error {
                palladin_crypto::CryptoError::StaleInput => RuntimeError::CredentialGrantExpired,
                error => RuntimeError::Crypto(error),
            })?;
        Ok(grant_remaining.map_or(lease_remaining, |grant| lease_remaining.min(grant)))
    }

    /// Acquire the final browser forwarding lease without waiting beyond either the OS operation
    /// lease or the authenticated grant expiry. Both are rechecked after lock acquisition and the
    /// one-shot operation remains consumed; this does not request or consume another grant.
    pub fn browser_inject_forward_guard<S: SecretStore + Sync>(
        &self,
        service: &RuntimeService<S>,
        expected_lifecycle_token: &[u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES],
        credential: &DeliveredCredential,
    ) -> Result<BrowserInjectForwardGuard, RuntimeError> {
        let remaining = self.inject_forward_remaining(credential)?;
        let lock = service
            .repository
            .acquire_shared_transaction_lock_for(remaining)?;
        let Some(lock) = lock else {
            self.inject_forward_remaining(credential)?;
            return Err(RuntimeError::BrowserHostLifecycleBusy);
        };
        service.validate_browser_host_lifecycle_token(expected_lifecycle_token)?;
        let remaining = self.inject_forward_remaining(credential)?;
        Ok(BrowserInjectForwardGuard {
            _lifecycle: BrowserHostLifecycleGuard { _lock: lock },
            deadline: std::time::Instant::now() + remaining,
        })
    }

    fn begin_operation(&self, expected: RuntimeOperation) -> Result<(), RuntimeError> {
        self.ensure_operation(expected)?;
        self.consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| RuntimeError::OperationAuthorizationConsumed)?;
        Ok(())
    }

    fn ensure_pairing_activation(&self, activation_id: &str) -> Result<(), RuntimeError> {
        if self.pairing_activation_id.as_deref() != Some(activation_id) {
            return Err(RuntimeError::OperationAuthorizationMismatch);
        }
        Ok(())
    }

    pub async fn resolve_form_discovery_map(
        &self,
        domain: &str,
        provider: &str,
        rejected: Option<&FormDiscoveryMap>,
    ) -> Result<Option<FormDiscoveryMap>, RuntimeError> {
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        let api_origin = &self.config.host;
        if let Some(rejected) = rejected {
            rejected
                .validate(domain, provider)
                .map_err(|_| RuntimeError::FormMapCache)?;
            FormMapCache::invalidate_matching_serialized(
                &self.form_map_root,
                api_origin,
                domain,
                provider,
                rejected,
            )?;
        } else if let Some(map) =
            FormMapCache::get_serialized(&self.form_map_root, api_origin, domain, provider)?
        {
            self.ensure_authorized()?;
            return Ok(Some(map));
        }

        let map = self.api.get_form_discovery_map(domain, provider).await?;
        self.ensure_authorized()?;
        if let (Some(rejected), Some(refreshed)) = (rejected, map.as_ref())
            && refreshed.map_version == rejected.map_version
            && refreshed.fingerprint == rejected.fingerprint
        {
            // Another process may have re-cached the rejected response while this request was in
            // flight. Remove only that exact revision and never delete a concurrently published
            // replacement.
            FormMapCache::invalidate_matching_serialized(
                &self.form_map_root,
                api_origin,
                domain,
                provider,
                rejected,
            )?;
            return Ok(None);
        }
        let map = if let Some(map) = map {
            FormMapCache::put_serialized(&self.form_map_root, api_origin, map)?
        } else {
            None
        };
        Ok(map)
    }

    pub async fn submit_form_discovery_map_candidate(
        &self,
        domain: &str,
        current_url: &str,
        provider: &str,
        form: &InjectionFormDefinition,
    ) -> Result<(), RuntimeError> {
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        let login_url = form_discovery_map_login_url(current_url, domain)
            .map_err(|_| RuntimeError::InvalidFormDiscoveryMap)?;
        let map = FormDiscoveryMapDefinition {
            version: 1,
            form: form.clone(),
            cookie_overlays: Vec::new(),
        };
        let fingerprint = form_discovery_map_fingerprint(domain, &login_url, provider, &map)
            .map_err(|_| RuntimeError::InvalidFormDiscoveryMap)?;
        self.api
            .submit_form_discovery_map_candidate(domain, &login_url, provider, &fingerprint, &map)
            .await?;
        self.ensure_authorized()
    }

    /// Consumes a renewed PairVaults authorization for polling an existing, exactly bound
    /// activation without creating a second pairing candidate.
    pub fn resume_pairing_polling(&self, activation_id: &str) -> Result<(), RuntimeError> {
        self.ensure_pairing_activation(activation_id)?;
        self.begin_operation(RuntimeOperation::PairVaults)
    }

    /// Creates an authenticated pairing transcript for the exact activation bound to this
    /// operation. The organization identifier is introduced by the Member-confirmed transcript;
    /// the Agent identifier and both Agent key fingerprints are derived from local identity state.
    pub async fn create_pairing_activation(
        &self,
        activation_id: &str,
    ) -> Result<RuntimePairingCandidate, RuntimeError> {
        self.ensure_pairing_activation(activation_id)?;
        self.begin_operation(RuntimeOperation::PairVaults)?;
        if !self.config.agent_active {
            return Err(RuntimeError::AgentNotActive);
        }
        let cancellation = self.lease.cancellation_token();
        let remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            () = tokio::time::sleep(remaining) => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            response = self.api.create_pairing_activation(activation_id) => response?,
        };
        self.ensure_authorized()?;
        if response.activation_id != activation_id {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        let identity = self.pairing_identity_binding(&response.organization_id)?;
        prepare_runtime_pairing(response, &identity)
    }

    /// Polls only after the activation call consumed this PairVaults authorization.
    pub async fn get_pairing_status(
        &self,
        activation_id: &str,
    ) -> Result<AgentPairingStatusResponse, RuntimeError> {
        self.ensure_pairing_activation(activation_id)?;
        self.ensure_operation(RuntimeOperation::PairVaults)?;
        if !self.consumed.load(Ordering::SeqCst) {
            return Err(RuntimeError::OperationAuthorizationMismatch);
        }
        let cancellation = self.lease.cancellation_token();
        let remaining = self
            .lease
            .remaining()
            .map_err(|_| RuntimeError::OperationAuthorizationExpired)?;
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            () = tokio::time::sleep(remaining) => {
                return Err(RuntimeError::OperationAuthorizationExpired);
            }
            response = self.api.get_pairing_status(activation_id) => response?,
        };
        self.ensure_authorized()?;
        Ok(response)
    }

    async fn credential_options(
        &self,
        request: CredentialDeliveryRequest<'_>,
        method: CredentialMethod,
    ) -> Result<PreparedCredentialOptions, RuntimeError> {
        let requested_methods = Vec::new();
        let reason = request
            .reason
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if reason.is_none() {
            return Ok(PreparedCredentialOptions {
                options: GetCredentialOptions {
                    encrypted_reason: None,
                    method: Some(method),
                    requested_methods,
                },
                organization_id: self
                    .config
                    .vault_trust_anchors
                    .iter()
                    .find(|anchor| anchor.vault_id == request.vault_id)
                    .map(|anchor| anchor.organization_id.clone()),
            });
        }
        let response = self.api.list_vault_manifests().await?;
        let batch = self.prepare_manifest_batch(response)?;
        let manifest = batch
            .items
            .iter()
            .find(|item| item.manifest.vault_id == request.vault_id)
            .ok_or(RuntimeError::UntrustedVaultManifest)?
            .manifest
            .clone();
        let identity = self.agent_identity_binding_for_organization(&manifest.organization_id)?;
        self.persist_prepared_manifest_batch(&batch)?;

        let reason = reason.ok_or(RuntimeError::UntrustedVaultManifest)?;

        let mut request_id = [0_u8; 16];
        getrandom::fill(&mut request_id).map_err(|_| RuntimeError::RandomGenerationFailed)?;
        request_id[6] = (request_id[6] & 0x0f) | 0x40;
        request_id[8] = (request_id[8] & 0x3f) | 0x80;
        let recipient_key = decode_32_url(&manifest.vault_agent_message_public_key)?;
        let recipient_fingerprint = decode_32_url(&manifest.vault_agent_message_key_fingerprint)?;
        let encrypted_reason = self.api.encrypt_access_reason(
            reason,
            EncryptedReasonContext {
                organization_id: identity.organization_id,
                vault_id: Uuid::parse_str(request.vault_id)
                    .map_err(|_| RuntimeError::InvalidPublicConfig)?,
                entry_id: Uuid::parse_str(request.entry_id)
                    .map_err(|_| RuntimeError::InvalidPublicConfig)?,
                grant_request_id: Uuid::from_bytes(request_id),
                agent_id: identity.agent_id,
                request_revision: 1,
                reason_key_version: 1,
                agent_message_key_version: manifest.agent_message_key_version,
                member_key_generation: manifest.agent_message_key_version,
                requested_methods: credential_method_mask(method),
                recipient_agent_message_public_key: recipient_key,
                recipient_agent_message_key_fingerprint: recipient_fingerprint,
            },
        )?;
        Ok(PreparedCredentialOptions {
            options: GetCredentialOptions {
                encrypted_reason: Some(encrypted_reason),
                method: Some(method),
                requested_methods,
            },
            organization_id: Some(identity.organization_id.to_string()),
        })
    }

    fn agent_identity_binding_for_organization(
        &self,
        organization_id: &str,
    ) -> Result<AgentIdentityBinding, RuntimeError> {
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let signing_public_key = self
            .config
            .signing_public_key
            .as_deref()
            .ok_or(RuntimeError::InvalidPublicConfig)
            .and_then(decode_32_standard)?;
        Ok(AgentIdentityBinding {
            organization_id: Uuid::parse_str(organization_id)
                .map_err(|_| RuntimeError::InvalidPublicConfig)?,
            agent_id: Uuid::parse_str(agent_id).map_err(|_| RuntimeError::InvalidPublicConfig)?,
            x25519_fingerprint: key_fingerprint(1, self.encryption.public_key())?,
            ed25519_fingerprint: key_fingerprint(2, &signing_public_key)?,
        })
    }

    fn pairing_identity_binding(
        &self,
        organization_id: &str,
    ) -> Result<AgentIdentityBinding, RuntimeError> {
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let signing_public_key = self
            .config
            .signing_public_key
            .as_deref()
            .ok_or(RuntimeError::InvalidPublicConfig)
            .and_then(decode_32_standard)?;
        Ok(AgentIdentityBinding {
            organization_id: Uuid::parse_str(organization_id)
                .map_err(|_| RuntimeError::InvalidPublicConfig)?,
            agent_id: Uuid::parse_str(agent_id).map_err(|_| RuntimeError::InvalidPublicConfig)?,
            x25519_fingerprint: key_fingerprint(1, self.encryption.public_key())?,
            ed25519_fingerprint: key_fingerprint(2, &signing_public_key)?,
        })
    }

    fn prepare_manifest_batch(
        &self,
        response: AgentVaultManifestsResponse,
    ) -> Result<PreparedManifestBatch, RuntimeError> {
        let agent_access_epoch = u64::from(response.agent_access_epoch);
        if agent_access_epoch == 0
            || self
                .config
                .vault_trust_anchors
                .iter()
                .any(|anchor| anchor.agent_access_epoch != agent_access_epoch)
        {
            return Err(RuntimeError::UntrustedVaultManifest);
        }

        let manifests = response
            .items
            .iter()
            .map(|item| vault_manifest_v2(item.manifest.clone()))
            .collect::<Vec<_>>();
        let next_anchors = if let Some(first) = manifests.first() {
            let identity = self.agent_identity_binding_for_organization(&first.organization_id)?;
            prepare_manifest_anchors(
                &self.config.vault_trust_anchors,
                agent_access_epoch,
                &manifests,
                &identity,
            )?
        } else {
            self.config.vault_trust_anchors.clone()
        };

        let items = response
            .items
            .into_iter()
            .zip(manifests)
            .map(|(item, manifest)| {
                let vdk = self.open_manifest_vdk(&manifest, item.envelope)?;
                Ok(PreparedManifestItem { manifest, vdk })
            })
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        Ok(PreparedManifestBatch {
            items,
            next_anchors,
        })
    }

    fn persist_prepared_manifest_batch(
        &self,
        batch: &PreparedManifestBatch,
    ) -> Result<(), RuntimeError> {
        let persistence = self
            .manifest_persistence
            .ok_or(RuntimeError::IntegrityViolation)?;
        let signing = self
            .profile_signing
            .as_ref()
            .ok_or(RuntimeError::IntegrityViolation)?;
        self.ensure_authorized()?;
        persistence.persist_manifest_batch(
            &self.profile.identity_id,
            &self.config.vault_trust_anchors,
            &batch.next_anchors,
            signing,
            &self.lease,
        )?;
        self.ensure_authorized()
    }

    fn persist_prepared_discovery_batch(
        &self,
        batch: &PreparedManifestBatch,
        cache: &PreparedDiscoveryCache,
    ) -> Result<(), RuntimeError> {
        let persistence = self
            .manifest_persistence
            .ok_or(RuntimeError::IntegrityViolation)?;
        let signing = self
            .profile_signing
            .as_ref()
            .ok_or(RuntimeError::IntegrityViolation)?;
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        self.ensure_authorized()?;
        persistence.persist_discovery_batch(
            &self.profile.identity_id,
            agent_id,
            &self.config.vault_trust_anchors,
            &batch.next_anchors,
            self.config.discovery_cache.as_ref(),
            &cache.commitment,
            &cache.ciphertext,
            signing,
            &self.lease,
        )?;
        self.ensure_authorized()
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
            result = self.search_local_discovery(query, cursor, page_size) => {
                self.ensure_authorized()?;
                result
            }
        }
    }

    async fn search_local_discovery(
        &self,
        query: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<EntrySearchResult, RuntimeError> {
        self.sync_local_discovery().await?;
        self.discovery.lock().await.search(query, cursor, page_size)
    }

    async fn sync_local_discovery(&self) -> Result<(), RuntimeError> {
        let result = retry_sync_state_changed(|| self.sync_local_discovery_attempt()).await;
        if result.is_err() {
            self.discovery.lock().await.clear_live_heads_and_cursors();
        }
        result
    }

    async fn sync_local_discovery_attempt(&self) -> Result<(), RuntimeError> {
        self.ensure_discovery_cache_loaded().await?;
        let manifests = self.api.list_vault_manifests().await?;
        let batch = self.prepare_manifest_batch(manifests)?;
        let mut index_guard = self.discovery.lock().await;
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        index_guard.scope_to_identity(&self.profile.identity_id, agent_id);
        let mut next_index = index_guard.clone();
        let result = async {
            let mut authorized_vaults = BTreeSet::new();
            for item in &batch.items {
                let vault_id = item.manifest.vault_id.clone();
                authorized_vaults.insert(vault_id.clone());
                if let Err(error) = self
                    .sync_discovery_vault(
                        &vault_id,
                        item.manifest.vdk_version,
                        &item.vdk,
                        &mut next_index,
                    )
                    .await
                {
                    if matches!(error, RuntimeError::Api(ApiError::ResetRequired { .. })) {
                        next_index.require_resnapshot(&vault_id);
                        self.sync_discovery_vault(
                            &vault_id,
                            item.manifest.vdk_version,
                            &item.vdk,
                            &mut next_index,
                        )
                        .await?;
                    } else {
                        return Err(error);
                    }
                }
            }
            next_index.retain_vaults(&authorized_vaults);
            Ok(())
        }
        .await;
        let prepared_cache = match &result {
            Ok(()) => Some(self.prepare_discovery_cache(&next_index)?),
            Err(_) => None,
        };
        publish_discovery_attempt(&mut index_guard, next_index, result, || {
            self.ensure_authorized()?;
            self.persist_prepared_discovery_batch(
                &batch,
                prepared_cache
                    .as_ref()
                    .ok_or(RuntimeError::IntegrityViolation)?,
            )
        })
    }

    async fn ensure_discovery_cache_loaded(&self) -> Result<(), RuntimeError> {
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let mut index = self.discovery.lock().await;
        if index.is_scoped_to(&self.profile.identity_id, agent_id) {
            return Ok(());
        }
        let persistence = self
            .manifest_persistence
            .ok_or(RuntimeError::IntegrityViolation)?;
        *index = persistence.load_discovery_cache(
            &self.profile.identity_id,
            agent_id,
            self.config.discovery_cache.as_ref(),
            &self.encryption,
        )?;
        Ok(())
    }

    fn prepare_discovery_cache(
        &self,
        index: &LocalDiscoveryIndex,
    ) -> Result<PreparedDiscoveryCache, RuntimeError> {
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let generation = self
            .config
            .discovery_cache
            .as_ref()
            .map_or(1, |cache| cache.generation.saturating_add(1));
        let binding = discovery_cache_binding(&self.profile.identity_id, agent_id, generation)?;
        let plaintext = index.encode_durable_cache()?;
        let ciphertext =
            seal_local_discovery_cache(self.encryption.public_key(), &binding, plaintext.as_ref())?;
        let commitment = PublicDiscoveryCacheCommitment {
            generation,
            ciphertext_sha256: hex_digest(Sha256::digest(&ciphertext)),
        };
        Ok(PreparedDiscoveryCache {
            commitment,
            ciphertext,
        })
    }

    fn open_manifest_vdk(
        &self,
        manifest: &VaultManifestV2,
        envelope: palladin_api::AgentVaultDiscoveryEnvelope,
    ) -> Result<SecretBytes, RuntimeError> {
        let descriptor = &envelope.wrapped_vdk.descriptor;
        let scope = &descriptor.scope;
        let structural_mismatch = envelope.protocol_version != manifest.protocol_version
            || envelope.organization_id != manifest.organization_id
            || envelope.vault_id != manifest.vault_id
            || envelope.agent_id != manifest.agent_id
            || envelope.vdk_version != manifest.vdk_version
            || envelope.manifest_revision != manifest.manifest_revision
            || envelope.manifest_signature != manifest.signature;
        let descriptor_mismatch = descriptor.protocol_version != envelope.protocol_version
            || descriptor.wrapper_suite_id != manifest.wrapper_suite_id
            || descriptor.purpose != AGENT_DISCOVERY_VDK_WRAPPER_PURPOSE
            || scope.organization_id != envelope.organization_id
            || scope.vault_id != envelope.vault_id
            || scope.agent_id.as_deref() != Some(envelope.agent_id.as_str())
            || scope.entry_id.is_some()
            || scope.grant_or_request_id.is_some()
            || scope.member_id.is_some()
            || descriptor.resource_revision != envelope.vdk_version.to_string()
            || descriptor.wrapped_key_version != envelope.vdk_version
            || descriptor.member_key_generation.is_some()
            || descriptor.recipient_key_kind != AGENT_X25519_RECIPIENT_KEY_KIND
            || descriptor.recipient_key_version == 0
            || descriptor.recipient_fingerprint != manifest.agent_x25519_fingerprint
            || descriptor.parent_descriptor_hash.is_some();
        if structural_mismatch || descriptor_mismatch {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        let wrapped = decode_base64url(&envelope.wrapped_vdk.encoded_sealed_key_package)?;
        let mut digest_input = Sha256::new();
        digest_input.update(AGENT_WRAPPED_VDK_DIGEST_PREFIX);
        digest_input.update(envelope.protocol_version.to_be_bytes());
        digest_input.update(&wrapped);
        let digest = URL_SAFE_NO_PAD.encode(digest_input.finalize());
        if digest
            .as_bytes()
            .ct_eq(manifest.agent_wrapped_vdk_digest.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        let wrapped = SealedWrappedKey::from_bytes(wrapped)?;
        let organization_id = Uuid::parse_str(&scope.organization_id)
            .map_err(|_| RuntimeError::UntrustedVaultManifest)?;
        let vault_id =
            Uuid::parse_str(&scope.vault_id).map_err(|_| RuntimeError::UntrustedVaultManifest)?;
        let agent_id = Uuid::parse_str(
            scope
                .agent_id
                .as_deref()
                .ok_or(RuntimeError::UntrustedVaultManifest)?,
        )
        .map_err(|_| RuntimeError::UntrustedVaultManifest)?;
        let resource_revision = descriptor
            .resource_revision
            .parse::<u64>()
            .map_err(|_| RuntimeError::UntrustedVaultManifest)?;
        let recipient_fingerprint = decode_32_url(&descriptor.recipient_fingerprint)?;
        let context = WrapperContext {
            protocol_version: descriptor.protocol_version,
            wrapper_suite_id: descriptor.wrapper_suite_id.clone(),
            purpose: WrapperPurpose::AgentVdk,
            scope: EnvelopeScope {
                organization_id: *organization_id.as_bytes(),
                vault_id: *vault_id.as_bytes(),
                entry_id: None,
                grant_or_request_id: None,
                agent_id: Some(*agent_id.as_bytes()),
                member_id: None,
            },
            resource_revision,
            wrapped_key_version: descriptor.wrapped_key_version,
            member_key_generation: descriptor.member_key_generation,
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: descriptor.recipient_key_version,
            recipient_fingerprint,
            parent_descriptor_hash: None,
        };
        Ok(X25519SealedBoxSuite::unwrap_secret(
            &wrapped,
            &self.encryption,
            &context,
        )?)
    }

    async fn sync_discovery_vault(
        &self,
        vault_id: &str,
        vdk_version: u32,
        vdk: &SecretBytes,
        index: &mut LocalDiscoveryIndex,
    ) -> Result<(), RuntimeError> {
        if index.prepare_vault(vault_id, vdk_version) {
            let after = index
                .applied_sequence(vault_id)
                .ok_or(RuntimeError::InvalidDiscoveryPayload)?
                .to_owned();
            return self
                .apply_discovery_delta(vault_id, vdk_version, &after, vdk, index)
                .await;
        }
        let mut snapshot_cursor = None;
        let mut snapshot_base = None;
        let mut heads = Vec::new();
        for _ in 0..MAX_DISCOVERY_SYNC_PAGES {
            let page = self
                .api
                .get_agent_discovery_snapshot(
                    vault_id,
                    snapshot_cursor.as_deref(),
                    Some(DISCOVERY_SYNC_PAGE_SIZE as u32),
                )
                .await?;
            if page.items.len() > DISCOVERY_SYNC_PAGE_SIZE {
                return Err(RuntimeError::DiscoveryIndexLimitExceeded);
            }
            validate_sequence(&page.snapshot_base_sequence)?;
            if snapshot_base
                .as_ref()
                .is_some_and(|base| base != &page.snapshot_base_sequence)
            {
                return Err(RuntimeError::InvalidDiscoveryPayload);
            }
            snapshot_base = Some(page.snapshot_base_sequence);
            for item in page.items {
                match item {
                    AgentDiscoverySyncItem::Head {
                        entry_id,
                        agent_discovery_revision,
                        agent_discovery,
                    } => {
                        let revision = validate_sequence(&agent_discovery_revision)?;
                        let envelope_digest = discovery_envelope_digest(&agent_discovery);
                        let plaintext = self.decrypt_discovery(
                            vault_id,
                            vdk_version,
                            &entry_id,
                            &agent_discovery_revision,
                            agent_discovery,
                            vdk,
                        )?;
                        heads.push((entry_id, revision, envelope_digest, plaintext));
                    }
                    AgentDiscoverySyncItem::Tombstone { .. } => {
                        return Err(RuntimeError::InvalidDiscoveryPayload);
                    }
                }
                if heads.len() > 10_000 {
                    return Err(RuntimeError::DiscoveryIndexLimitExceeded);
                }
            }
            snapshot_cursor = page.next_cursor;
            if snapshot_cursor.is_none() {
                break;
            }
        }
        if snapshot_cursor.is_some() {
            return Err(RuntimeError::DiscoveryIndexLimitExceeded);
        }
        index.replace_vault(vault_id, heads)?;
        let after = snapshot_base.ok_or(RuntimeError::InvalidDiscoveryPayload)?;
        self.apply_discovery_delta(vault_id, vdk_version, &after, vdk, index)
            .await
    }

    async fn apply_discovery_delta(
        &self,
        vault_id: &str,
        vdk_version: u32,
        initial_after: &str,
        vdk: &SecretBytes,
        index: &mut LocalDiscoveryIndex,
    ) -> Result<(), RuntimeError> {
        let mut after = initial_after.to_owned();
        let mut applied = validate_sequence(&after)?;
        let mut delta_upper_bound = None;
        let mut continuation = None;
        for _ in 0..MAX_DISCOVERY_SYNC_PAGES {
            let page = self
                .api
                .get_agent_discovery_delta(
                    vault_id,
                    continuation.is_none().then_some(after.as_str()),
                    continuation.as_deref(),
                    Some(DISCOVERY_SYNC_PAGE_SIZE as u32),
                )
                .await?;
            if page.items.len() > DISCOVERY_SYNC_PAGE_SIZE {
                return Err(RuntimeError::DiscoveryIndexLimitExceeded);
            }
            let upper_bound = validate_sequence(&page.delta_upper_bound)?;
            let applied_through = validate_sequence(&page.applied_through_sequence)?;
            if delta_upper_bound.is_some_and(|expected| expected != upper_bound)
                || applied_through < applied
                || applied_through > upper_bound
            {
                return Err(RuntimeError::InvalidDiscoveryPayload);
            }
            delta_upper_bound = Some(upper_bound);
            for item in page.items {
                match item {
                    AgentDiscoverySyncItem::Head {
                        entry_id,
                        agent_discovery_revision,
                        agent_discovery,
                    } => {
                        let revision = validate_sequence(&agent_discovery_revision)?;
                        let envelope_digest = discovery_envelope_digest(&agent_discovery);
                        index.upsert(
                            vault_id,
                            &entry_id,
                            revision,
                            envelope_digest,
                            self.decrypt_discovery(
                                vault_id,
                                vdk_version,
                                &entry_id,
                                &agent_discovery_revision,
                                agent_discovery,
                                vdk,
                            )?,
                        )?;
                    }
                    AgentDiscoverySyncItem::Tombstone {
                        entry_id,
                        agent_discovery_revision,
                        agent_discovery,
                    } => {
                        if agent_discovery_revision.is_some() || agent_discovery.is_some() {
                            return Err(RuntimeError::InvalidDiscoveryPayload);
                        }
                        index.remove(vault_id, &entry_id);
                    }
                }
            }
            after = page.applied_through_sequence;
            applied = applied_through;
            continuation = page.continuation_cursor;
            if continuation.is_none() {
                if applied != upper_bound {
                    return Err(RuntimeError::InvalidDiscoveryPayload);
                }
                index.mark_applied(vault_id, after);
                return Ok(());
            }
        }
        Err(RuntimeError::DiscoveryIndexLimitExceeded)
    }

    fn decrypt_discovery(
        &self,
        expected_vault_id: &str,
        expected_vdk_version: u32,
        expected_entry_id: &str,
        expected_revision: &str,
        envelope: AgentDiscoveryEnvelope,
        vdk: &SecretBytes,
    ) -> Result<DiscoveryPlaintext, RuntimeError> {
        let crypto_descriptor = validate_discovery_envelope_scope(
            expected_vault_id,
            expected_vdk_version,
            expected_entry_id,
            expected_revision,
            envelope.descriptor,
        )?;
        let payload =
            EncodedSuitePayload::from_bytes(decode_base64url(&envelope.encoded_suite_payload)?)?;
        let key =
            XChaChaVaultSuite::derive_key(vdk.expose_for_crypto_operation(), &crypto_descriptor)?;
        let aad = crypto_descriptor.canonical_aad()?;
        let plaintext = XChaChaVaultSuite::open(&key, &payload, &aad)?;
        serde_json::from_slice(plaintext.expose_secret())
            .map_err(|_| RuntimeError::InvalidDiscoveryPayload)
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

    /// Delivers a grant-scoped Inject credential only to a trusted provider boundary.
    /// The caller must consume the returned non-serializable value without emitting it.
    pub async fn deliver_for_inject<H>(
        &self,
        request: CredentialDeliveryRequest<'_>,
        cancellation: &CancellationToken,
        heartbeat: H,
    ) -> Result<CredentialDelivery, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.begin_operation(RuntimeOperation::InjectCredential)?;
        self.deliver_credential(request, CredentialMethod::Inject, cancellation, heartbeat)
            .await
    }

    pub async fn authenticated_inject_username(
        &self,
        vault_id: &str,
        entry_id: &str,
        entry_revision: u64,
    ) -> Result<Option<Zeroizing<String>>, RuntimeError> {
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        self.sync_local_discovery().await?;
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        let value = self.discovery.lock().await.field_at_revision(
            vault_id,
            entry_id,
            entry_revision,
            "credential.username",
        )?;
        self.ensure_operation(RuntimeOperation::InjectCredential)?;
        Ok(value.map(Zeroizing::new))
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
        self.begin_operation(RuntimeOperation::ExecWithCredential)?;
        let operation_cancellation = self.operation_cancellation(cancellation)?;
        let cancellation = operation_cancellation.token();
        let has_command = request.command.is_some_and(|command| !command.is_empty());
        if has_command
            && self
                .discovery
                .lock()
                .await
                .entry_type(request.delivery.vault_id, request.delivery.entry_id)
                == Some("script")
        {
            return Err(RuntimeError::CommandProvidedForScript);
        }
        if !has_command {
            self.sync_local_discovery().await?;
            self.ensure_operation(RuntimeOperation::ExecWithCredential)?;
            let entry_type = self
                .discovery
                .lock()
                .await
                .entry_type(request.delivery.vault_id, request.delivery.entry_id)
                .map(str::to_owned);
            if entry_type.as_deref() != Some("script") {
                return Err(RuntimeError::MissingExecCommand);
            }
            if !request.env_mappings.is_empty() {
                return Err(RuntimeError::EnvironmentMappingForScript);
            }
            return self.execute_atomic_script(&request, cancellation).await;
        }
        if request
            .parameters
            .as_object()
            .is_none_or(|parameters| !parameters.is_empty())
        {
            return Err(RuntimeError::InvalidScriptParameters);
        }
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
        let parsed = parse_secret(credential.expose_for_authorized_operation())
            .map_err(|_| RuntimeError::InvalidCredentialPayload)?;
        drop(credential);
        if parsed.script.is_some() {
            return Err(RuntimeError::InvalidCredentialPayload);
        }
        let command = request
            .command
            .filter(|command| !command.is_empty())
            .ok_or(RuntimeError::MissingExecCommand)?;
        let mut environment = SecretEnvironment::for_credential(&parsed);
        prepare_explicit_environment(&parsed, request.env_mappings, &mut environment)?;
        drop(parsed);
        let result = run_command(command, environment, request.output, cancellation).await?;
        self.ensure_authorized()?;
        Ok(CredentialExecOutcome::Completed(result))
    }

    async fn execute_atomic_script(
        &self,
        request: &CredentialExecRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<CredentialExecOutcome, RuntimeError> {
        let discovery = self
            .discovery
            .lock()
            .await
            .script_execution(request.delivery.vault_id, request.delivery.entry_id)?;
        let parameter_frame =
            encode_script_execution_parameters(&discovery.parameters, request.parameters)
                .map_err(|_| RuntimeError::InvalidScriptParameters)?;
        let parameter_frame = std::str::from_utf8(parameter_frame.expose_for_crypto_operation())
            .map_err(|_| RuntimeError::InvalidScriptParameters)?
            .to_owned();
        let parameter_frame = SecretString::from(parameter_frame);
        let agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let anchor = self
            .config
            .vault_trust_anchors
            .iter()
            .find(|anchor| anchor.vault_id == request.delivery.vault_id)
            .ok_or(RuntimeError::UntrustedVaultManifest)?;
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(RuntimeError::WaitCancelled),
            response = self.api.get_script_execution_package(
                request.delivery.vault_id,
                request.delivery.entry_id,
                &discovery.script_revision,
            ) => match response {
                Ok(response) => response,
                Err(ApiError::Http(404)) => {
                    return Ok(CredentialExecOutcome::NotGranted(CredentialAccess::Unavailable));
                }
                Err(ApiError::Http(403)) => {
                    return Ok(CredentialExecOutcome::NotGranted(CredentialAccess::Expired));
                }
                Err(ApiError::Http(429)) => {
                    return Ok(CredentialExecOutcome::NotGranted(CredentialAccess::Consumed));
                }
                Err(ApiError::ScriptStaleDiscovery) => {
                    return Err(RuntimeError::StaleScriptDiscovery);
                }
                Err(ApiError::ScriptInvalidPackage) => {
                    return Err(RuntimeError::InvalidScriptExecutionPackage);
                }
                Err(error) => return Err(RuntimeError::Api(error)),
            },
        };
        self.ensure_authorized()?;
        if response.organization_id != anchor.organization_id
            || response.vault_id != request.delivery.vault_id
            || response.agent_id != agent_id
            || u64::from(response.agent_access_epoch) != anchor.agent_access_epoch
            || response.script_entry_id != request.delivery.entry_id
            || response.script_revision != discovery.script_revision
        {
            return Err(RuntimeError::InvalidScriptExecutionPackage);
        }

        let authorization_source = response.authorization_source.clone();
        let grant_id = response.grant_id.clone();
        let expires_at = response.expires_at.clone();
        let mut environment = SecretEnvironment::new();
        let mut protected_literals = Vec::<SecretString>::new();
        let (script, interpreter_name, return_result_to_agent) = if authorization_source
            == "scriptExecution"
        {
            let package = response
                .script_package
                .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
            let recipient_key_version = package.recipient_agent_key_version;
            let package_revision = package.package_revision.clone();
            let mut opened = open_script_execution_package(
                package,
                &self.encryption,
                &ExpectedScriptExecutionPackageContext {
                    organization_id: anchor.organization_id.clone(),
                    vault_id: request.delivery.vault_id.to_owned(),
                    grant_id: grant_id.clone(),
                    agent_id: agent_id.to_owned(),
                    agent_access_epoch: response.agent_access_epoch,
                    script_entry_id: request.delivery.entry_id.to_owned(),
                    script_revision: discovery.script_revision.clone(),
                    package_revision,
                    recipient_agent_key_version: recipient_key_version,
                    vault_signing_key_version: anchor.manifest_signing_key_version,
                    vault_signing_key_fingerprint: anchor.vault_signing_key_fingerprint.clone(),
                    vault_signing_public_key: decode_32_url(&anchor.vault_signing_public_key)?,
                },
            )?;
            if opened.manifest.description != discovery.description
                || opened.manifest.parameters != discovery.parameters
                || opened.manifest.return_result_to_agent != discovery.return_result_to_agent
            {
                return Err(RuntimeError::InvalidScriptExecutionPackage);
            }
            let entries = opened
                .entries
                .iter()
                .map(|entry| (entry.entry_id.as_str(), entry))
                .collect::<BTreeMap<_, _>>();
            for reference in &opened.manifest.references {
                let entry = entries
                    .get(reference.entry_id.as_str())
                    .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
                if entry.entry_revision != reference.entry_revision {
                    return Err(RuntimeError::InvalidScriptExecutionPackage);
                }
                let resolved = resolve_grant_payload_field(
                    entry.encoded_grant_payload.expose_for_crypto_operation(),
                    &reference.field_id,
                )
                .map_err(|_| RuntimeError::InvalidEnvironmentField)?;
                protected_literals.push(resolved.value.clone());
                environment.insert_reference(&reference.env, resolved.value)?;
            }
            (
                SecretString::from(std::mem::take(&mut opened.manifest.script_source)),
                opened.manifest.interpreter.clone(),
                opened.manifest.return_result_to_agent,
            )
        } else if authorization_source == "full" {
            let wrapped_vault_key = response
                .agent_wrapped_vault_key
                .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
            verify_agent_wrapped_vault_key_producer(
                &wrapped_vault_key,
                anchor.manifest_signing_key_version,
                &anchor.vault_signing_key_fingerprint,
                &decode_32_url(&anchor.vault_signing_public_key)?,
            )
            .map_err(|_| RuntimeError::InvalidScriptExecutionPackage)?;
            let entries = response
                .vault_entries
                .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
            let entry_count = entries.len();
            let mut entries = entries
                .into_iter()
                .map(|entry| (entry.entry_id.clone(), entry))
                .collect::<BTreeMap<_, _>>();
            if entries.len() != entry_count {
                return Err(RuntimeError::InvalidScriptExecutionPackage);
            }
            let script_entry = entries
                .remove(request.delivery.entry_id)
                .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
            if script_entry.entry_revision != discovery.script_revision
                || script_entry.delivery_policy != 1
            {
                return Err(RuntimeError::InvalidScriptExecutionPackage);
            }
            let script_member_secret = decrypt_full_script_member_secret(
                &wrapped_vault_key,
                &script_entry.entry_key,
                &script_entry.member_secret,
                &self.encryption,
                &FullScriptMemberSecretContext {
                    organization_id: &anchor.organization_id,
                    vault_id: request.delivery.vault_id,
                    grant_id: &grant_id,
                    agent_id,
                    agent_access_epoch: response.agent_access_epoch,
                    entry_id: request.delivery.entry_id,
                    entry_revision: &script_entry.entry_revision,
                    expires_at: expires_at.as_deref(),
                },
            )?;
            let script = parse_member_script(script_member_secret.expose_for_crypto_operation())
                .map_err(|_| RuntimeError::InvalidScriptExecutionPackage)?;
            let metadata = script
                .execution
                .as_ref()
                .ok_or(RuntimeError::ScriptExecutionMetadataUnavailable)?;
            if metadata.contract_version != discovery.contract_version
                || metadata.description != discovery.description
                || metadata.parameters != discovery.parameters
                || metadata.effective_return_result_to_agent() != discovery.return_result_to_agent
            {
                return Err(RuntimeError::InvalidScriptExecutionPackage);
            }
            let return_result_to_agent = metadata.effective_return_result_to_agent();
            preflight_script_references_raw(&script.refs, request.delivery.vault_id)?;
            for reference in &script.refs {
                let entry = entries
                    .get(&reference.entry_id)
                    .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
                if entry.delivery_policy == 2 {
                    return Err(RuntimeError::InvalidScriptExecutionPackage);
                }
                let member_secret = decrypt_full_script_member_secret(
                    &wrapped_vault_key,
                    &entry.entry_key,
                    &entry.member_secret,
                    &self.encryption,
                    &FullScriptMemberSecretContext {
                        organization_id: &anchor.organization_id,
                        vault_id: request.delivery.vault_id,
                        grant_id: &grant_id,
                        agent_id,
                        agent_access_epoch: response.agent_access_epoch,
                        entry_id: &entry.entry_id,
                        entry_revision: &entry.entry_revision,
                        expires_at: expires_at.as_deref(),
                    },
                )?;
                let field_id = reference
                    .field_id
                    .as_deref()
                    .ok_or(RuntimeError::InvalidScriptExecutionPackage)?;
                let resolved = resolve_script_reference_member_field(
                    member_secret.expose_for_crypto_operation(),
                    field_id,
                )
                .map_err(|_| RuntimeError::InvalidEnvironmentField)?;
                protected_literals.push(resolved.value.clone());
                environment.insert_reference(&reference.env, resolved.value)?;
            }
            (script.script, script.interpreter, return_result_to_agent)
        } else {
            return Err(RuntimeError::InvalidScriptExecutionPackage);
        };
        let interpreter = resolve_interpreter(&interpreter_name)?;
        let captured = run_script_captured(
            &script,
            &interpreter,
            environment,
            &parameter_frame,
            cancellation,
        )
        .await?;
        self.ensure_authorized()?;
        Ok(CredentialExecOutcome::ScriptCompleted(
            finalize_script_result(captured, return_result_to_agent, &protected_literals),
        ))
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
        let prepared = self.credential_options(request, method).await?;
        let options = &prepared.options;
        let initial = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                self.ensure_authorized()?;
                return Err(RuntimeError::WaitCancelled);
            }
            result = self.api.get_credential(request.vault_id, request.entry_id, options) => result?,
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
        let pending_grant_id = match &initial {
            CredentialAccess::Pending { grant_id, .. } => Some(grant_id.clone()),
            _ => None,
        };
        let access = await_grant_exponential(
            initial,
            policy,
            cancellation,
            || async {
                let Some(grant_id) = pending_grant_id.as_deref() else {
                    return Err(ApiError::InvalidResponse);
                };
                let status = self
                    .api
                    .get_grant_status(request.vault_id, grant_id)
                    .await?;
                match status.status {
                    GrantStatus::Pending => Ok(CredentialAccess::Pending {
                        grant_id: status.grant_id,
                        created: None,
                        poll_interval_ms: None,
                        max_wait_ms: None,
                    }),
                    GrantStatus::Active => {
                        self.api
                            .get_credential(request.vault_id, request.entry_id, options)
                            .await
                    }
                    GrantStatus::Denied => Ok(CredentialAccess::Denied),
                    GrantStatus::Revoked => Ok(CredentialAccess::Revoked),
                    GrantStatus::Expired => Ok(CredentialAccess::Expired),
                    GrantStatus::Consumed => Ok(CredentialAccess::Consumed),
                }
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
            organization_id: _,
            vault_id: _,
            grant_id,
            agent_id: _,
            agent_access_epoch,
            approved_methods,
            entry_id: _,
            grant_type,
            delivery_policy,
            expires_at,
            material,
        } = access
        else {
            return Ok(CredentialDelivery::NotGranted(access));
        };
        self.ensure_authorized()?;
        let organization_id = if let Some(organization_id) = prepared.organization_id {
            organization_id
        } else {
            let batch = self.prepare_manifest_batch(self.api.list_vault_manifests().await?)?;
            let organization_id = batch
                .items
                .iter()
                .find(|item| item.manifest.vault_id == request.vault_id)
                .ok_or(RuntimeError::UntrustedVaultManifest)?
                .manifest
                .organization_id
                .clone();
            self.persist_prepared_manifest_batch(&batch)?;
            organization_id
        };
        let expected_agent_id = self
            .config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)?;
        let requested_method = credential_method_mask(method);
        let (credential, entry_revision) = match (grant_type, material) {
            (CredentialGrantType::Granular, CredentialCiphertext::Granular(envelope)) => {
                let entry_revision = envelope
                    .descriptor
                    .binding
                    .entry_revision
                    .parse::<u64>()
                    .map_err(|_| RuntimeError::InvalidCredentialPayload)?;
                let credential = decrypt_credential(
                    &envelope,
                    &self.encryption,
                    &CredentialEnvelopeContext {
                        organization_id: &organization_id,
                        vault_id: request.vault_id,
                        grant_id: &grant_id,
                        agent_id: expected_agent_id,
                        entry_id: request.entry_id,
                        approved_methods,
                        requested_vault_id: request.vault_id,
                        requested_entry_id: request.entry_id,
                        requested_method,
                    },
                )?;
                (credential, entry_revision)
            }
            (
                CredentialGrantType::Full,
                CredentialCiphertext::Full {
                    agent_wrapped_vault_key,
                    entry_key,
                    member_secret,
                },
            ) => {
                let entry_revision = member_secret
                    .descriptor
                    .resource_revision
                    .parse::<u64>()
                    .map_err(|_| RuntimeError::InvalidCredentialPayload)?;
                let credential = decrypt_full_credential(
                    &agent_wrapped_vault_key,
                    &entry_key,
                    &member_secret,
                    &self.encryption,
                    &FullCredentialEnvelopeContext {
                        organization_id: &organization_id,
                        vault_id: request.vault_id,
                        grant_id: &grant_id,
                        agent_id: expected_agent_id,
                        agent_access_epoch,
                        entry_id: request.entry_id,
                        approved_methods,
                        delivery_policy,
                        expires_at: expires_at.as_deref(),
                        requested_vault_id: request.vault_id,
                        requested_entry_id: request.entry_id,
                        requested_method,
                    },
                )?;
                (credential, entry_revision)
            }
            _ => return Err(RuntimeError::InvalidCredentialPayload),
        };
        let (authenticated_domain, authenticated_fields) = if method == CredentialMethod::Inject {
            authenticated_inject_metadata(credential.expose_for_authorized_operation())?
        } else {
            (None, Vec::new())
        };
        self.ensure_authorized()?;
        let entry_id = request.entry_id.to_owned();
        let label = shorten_identifier(&entry_id);
        Ok(CredentialDelivery::Granted(DeliveredCredential {
            grant_id,
            entry_id,
            label,
            entry_revision,
            authenticated_domain,
            authenticated_fields,
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
    ScriptCompleted(ScriptExecutionResult),
    NotGranted(CredentialAccess),
}

#[derive(Eq, PartialEq)]
pub struct ScriptExecutionResult {
    pub exit_code: i32,
    pub cancelled: bool,
    pub result: Option<Zeroizing<String>>,
    pub withheld: Option<ScriptResultWithheld>,
}

impl std::fmt::Debug for ScriptExecutionResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptExecutionResult")
            .field("exit_code", &self.exit_code)
            .field("cancelled", &self.cancelled)
            .field("result", &self.result.as_ref().map(|_| "[REDACTED]"))
            .field("withheld", &self.withheld)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptResultWithheld {
    PolicyDisabled,
    LegacyPolicyDefault,
    ResultTooLarge,
    ResultInvalidText,
    ProtectedLiteralDetected,
    Cancelled,
}

impl ScriptResultWithheld {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "policy-disabled",
            Self::LegacyPolicyDefault => "legacy-policy-default",
            Self::ResultTooLarge => "result-too-large",
            Self::ResultInvalidText => "result-invalid-text",
            Self::ProtectedLiteralDetected => "protected-literal-detected",
            Self::Cancelled => "cancelled",
        }
    }
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
    pub grant_id: String,
    pub entry_id: String,
    pub label: String,
    entry_revision: u64,
    authenticated_domain: Option<String>,
    authenticated_fields: Vec<AgentVisibleField>,
    credential: DecryptedCredential,
}

impl DeliveredCredential {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.credential.expose_for_authorized_operation()
    }

    #[must_use]
    pub fn authenticated_domain(&self) -> Option<&str> {
        self.authenticated_domain.as_deref()
    }

    #[must_use]
    pub fn entry_revision(&self) -> u64 {
        self.entry_revision
    }

    #[must_use]
    pub fn authenticated_field(&self, field_id: &str) -> Option<&str> {
        self.authenticated_fields
            .iter()
            .find(|field| field.label == field_id)
            .map(|field| field.value.as_str())
    }
}

impl std::fmt::Debug for DeliveredCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveredCredential")
            .field("grant_id", &shorten_identifier(&self.grant_id))
            .field("entry_id", &self.entry_id)
            .field("label", &"[REDACTED]")
            .field("entry_revision", &self.entry_revision)
            .field(
                "authenticated_domain",
                &self.authenticated_domain.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authenticated_fields", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

pub struct RuntimePairingCandidate {
    identity: AgentIdentityBinding,
    agent_access_epoch: u64,
    candidate: PairingCandidate,
}

pub struct ConfirmedRuntimePairing {
    activation_id: String,
    identity: AgentIdentityBinding,
    anchors: Vec<PublicVaultTrustAnchor>,
}

impl RuntimePairingCandidate {
    #[must_use]
    pub fn transcript_digest(&self) -> &str {
        self.candidate.transcript_digest()
    }

    #[must_use]
    pub fn short_authentication_string(&self) -> &str {
        self.candidate.short_authentication_string()
    }

    pub fn confirm_from_relay(
        self,
        response: AgentPairingStatusResponse,
        now: OffsetDateTime,
    ) -> Result<ConfirmedRuntimePairing, RuntimeError> {
        let activation_id = self.candidate.transcript().activation_id.clone();
        let status = match response.status {
            AgentPairingStatus::Pending => "pending",
            AgentPairingStatus::Confirmed => "confirmed",
            AgentPairingStatus::Expired => "expired",
            AgentPairingStatus::Stale => "stale",
        };
        let anchors = confirm_pairing_from_relay(
            self.candidate,
            &PairingRelayStatus {
                activation_id: response.activation_id,
                status: status.to_owned(),
                expires_at: response.expires_at,
                confirmed_pairing_digest: response.confirmed_pairing_digest,
            },
            now,
        )?;
        Ok(ConfirmedRuntimePairing {
            activation_id,
            identity: self.identity.clone(),
            anchors: public_anchors_from_pairing(
                self.identity.organization_id,
                self.agent_access_epoch,
                anchors,
            )?,
        })
    }
}

pub fn prepare_runtime_pairing(
    response: AgentPairingActivationResponse,
    expected_identity: &AgentIdentityBinding,
) -> Result<RuntimePairingCandidate, RuntimeError> {
    let activation_id =
        Uuid::parse_str(&response.activation_id).map_err(|_| RuntimeError::InvalidPublicConfig)?;
    let organization_id = Uuid::parse_str(&response.organization_id)
        .map_err(|_| RuntimeError::InvalidPublicConfig)?;
    let agent_id =
        Uuid::parse_str(&response.agent_id).map_err(|_| RuntimeError::InvalidPublicConfig)?;
    if organization_id != expected_identity.organization_id
        || agent_id != expected_identity.agent_id
        || response.agent_access_epoch == 0
        || decode_32_url(&response.agent_x25519_fingerprint)?
            != expected_identity.x25519_fingerprint
        || decode_32_url(&response.agent_ed25519_fingerprint)?
            != expected_identity.ed25519_fingerprint
    {
        return Err(RuntimeError::UntrustedVaultManifest);
    }
    OffsetDateTime::parse(&response.expires_at, &Rfc3339)
        .map_err(|_| RuntimeError::InvalidPublicConfig)?;
    let manifests = response
        .candidate_manifests
        .into_iter()
        .map(vault_manifest_v2)
        .collect::<Vec<_>>();
    let candidate = prepare_pairing(activation_id, expected_identity, &manifests)?;
    Ok(RuntimePairingCandidate {
        identity: expected_identity.clone(),
        agent_access_epoch: u64::from(response.agent_access_epoch),
        candidate,
    })
}

fn vault_manifest_v2(manifest: VaultManifest) -> VaultManifestV2 {
    VaultManifestV2 {
        protocol_version: manifest.protocol_version,
        crypto_suite_id: manifest.crypto_suite_id,
        wrapper_suite_id: manifest.wrapper_suite_id,
        signature_suite_id: manifest.signature_suite_id,
        organization_id: manifest.organization_id,
        vault_id: manifest.vault_id,
        agent_id: manifest.agent_id,
        agent_x25519_fingerprint: manifest.agent_x25519_fingerprint,
        agent_ed25519_fingerprint: manifest.agent_ed25519_fingerprint,
        vault_signing_public_key: manifest.vault_signing_public_key,
        vault_signing_key_fingerprint: manifest.vault_signing_key_fingerprint,
        manifest_signing_key_version: manifest.manifest_signing_key_version,
        vault_agent_message_public_key: manifest.vault_agent_message_public_key,
        vault_agent_message_key_fingerprint: manifest.vault_agent_message_key_fingerprint,
        agent_message_key_version: manifest.agent_message_key_version,
        vdk_version: manifest.vdk_version,
        agent_wrapped_vdk_digest: manifest.agent_wrapped_vdk_digest,
        manifest_revision: manifest.manifest_revision,
        issued_at: manifest.issued_at,
        minimum_agent_runtime_protocol: manifest.minimum_agent_runtime_protocol,
        signature: manifest.signature,
    }
}

fn discovery_envelope_digest(envelope: &AgentDiscoveryEnvelope) -> [u8; 32] {
    Sha256::digest(envelope.encoded_suite_payload.as_bytes()).into()
}

fn discovery_cache_binding(
    identity_id: &str,
    agent_id: &str,
    generation: u64,
) -> Result<Vec<u8>, RuntimeError> {
    if identity_id.is_empty()
        || identity_id.len() > 256
        || agent_id.is_empty()
        || agent_id.len() > 256
        || generation == 0
    {
        return Err(RuntimeError::IntegrityViolation);
    }
    let mut binding = Vec::with_capacity(identity_id.len() + agent_id.len() + 40);
    binding.extend_from_slice(b"palladin.discovery-cache.binding.v1\0");
    binding.extend_from_slice(&(identity_id.len() as u32).to_be_bytes());
    binding.extend_from_slice(identity_id.as_bytes());
    binding.extend_from_slice(&(agent_id.len() as u32).to_be_bytes());
    binding.extend_from_slice(agent_id.as_bytes());
    binding.extend_from_slice(&generation.to_be_bytes());
    Ok(binding)
}

fn validate_sequence(value: &str) -> Result<u64, RuntimeError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RuntimeError::InvalidDiscoveryPayload);
    }
    value
        .parse()
        .map_err(|_| RuntimeError::InvalidDiscoveryPayload)
}

fn validate_discovery_envelope_scope(
    expected_vault_id: &str,
    expected_vdk_version: u32,
    expected_entry_id: &str,
    expected_revision: &str,
    descriptor: AgentDiscoveryEnvelopeDescriptor,
) -> Result<EnvelopeDescriptor, RuntimeError> {
    let scope = descriptor.scope;
    let organization_id = Uuid::parse_str(&scope.organization_id)
        .map_err(|_| RuntimeError::InvalidDiscoveryPayload)?;
    let vault_id =
        Uuid::parse_str(&scope.vault_id).map_err(|_| RuntimeError::InvalidDiscoveryPayload)?;
    let entry_id = Uuid::parse_str(
        scope
            .entry_id
            .as_deref()
            .ok_or(RuntimeError::InvalidDiscoveryPayload)?,
    )
    .map_err(|_| RuntimeError::InvalidDiscoveryPayload)?;
    let revision = validate_sequence(&descriptor.resource_revision)?;
    if descriptor.protocol_version != 2
        || descriptor.crypto_suite_id != "palladin-vault-xchacha-v1"
        || descriptor.purpose != "agentDiscovery"
        || scope.vault_id != expected_vault_id
        || scope.entry_id.as_deref() != Some(expected_entry_id)
        || descriptor.resource_revision != expected_revision
        || descriptor.key_version != expected_vdk_version
        || descriptor
            .member_key_generation
            .is_none_or(|generation| generation == 0)
        || scope.grant_or_request_id.is_some()
        || scope.agent_id.is_some()
        || scope.member_id.is_some()
    {
        return Err(RuntimeError::InvalidDiscoveryPayload);
    }
    Ok(EnvelopeDescriptor {
        protocol_version: descriptor.protocol_version,
        crypto_suite_id: descriptor.crypto_suite_id,
        purpose: EnvelopePurpose::AgentDiscovery,
        scope: EnvelopeScope {
            organization_id: *organization_id.as_bytes(),
            vault_id: *vault_id.as_bytes(),
            entry_id: Some(*entry_id.as_bytes()),
            grant_or_request_id: None,
            agent_id: None,
            member_id: None,
        },
        resource_revision: revision,
        key_version: descriptor.key_version,
        member_key_generation: descriptor.member_key_generation,
        binding: EnvelopeBinding::None,
    })
}

fn decode_32_url(value: &str) -> Result<[u8; 32], RuntimeError> {
    decode_base64url(value)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidPublicConfig)
}

fn decode_32_standard(value: &str) -> Result<[u8; 32], RuntimeError> {
    STANDARD
        .decode(value)
        .map_err(|_| RuntimeError::InvalidPublicConfig)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidPublicConfig)
}

fn pinned_vault_trust(anchor: &PublicVaultTrustAnchor) -> Result<PinnedVaultTrust, RuntimeError> {
    Ok(PinnedVaultTrust {
        vault_id: Uuid::parse_str(&anchor.vault_id)
            .map_err(|_| RuntimeError::InvalidPublicConfig)?,
        signing_public_key: decode_32_url(&anchor.vault_signing_public_key)?,
        signing_key_fingerprint: decode_32_url(&anchor.vault_signing_key_fingerprint)?,
        manifest_revision: anchor
            .manifest_revision
            .parse()
            .map_err(|_| RuntimeError::InvalidPublicConfig)?,
        manifest_signing_key_version: anchor.manifest_signing_key_version,
        vdk_version: anchor.vdk_version,
    })
}

fn prepare_manifest_anchors(
    current_anchors: &[PublicVaultTrustAnchor],
    agent_access_epoch: u64,
    manifests: &[VaultManifestV2],
    identity: &AgentIdentityBinding,
) -> Result<Vec<PublicVaultTrustAnchor>, RuntimeError> {
    let organization_id = identity.organization_id.to_string();
    if agent_access_epoch == 0
        || current_anchors.iter().any(|anchor| {
            anchor.agent_access_epoch != agent_access_epoch
                || anchor.organization_id != organization_id
        })
    {
        return Err(RuntimeError::UntrustedVaultManifest);
    }

    let mut next = current_anchors.to_vec();
    let mut seen = BTreeSet::new();
    for manifest in manifests {
        if !seen.insert(manifest.vault_id.clone()) {
            return Err(RuntimeError::UntrustedVaultManifest);
        }
        let advanced = if let Some(anchor) = current_anchors
            .iter()
            .find(|anchor| anchor.vault_id == manifest.vault_id)
        {
            verify_current_manifest(manifest, identity, &pinned_vault_trust(anchor)?)
                .map_err(|_| RuntimeError::UntrustedVaultManifest)?
        } else {
            initial_vault_trust(manifest, identity)?
        };
        let public = PublicVaultTrustAnchor {
            organization_id: organization_id.clone(),
            vault_id: advanced.vault_id.to_string(),
            agent_access_epoch,
            vault_signing_public_key: URL_SAFE_NO_PAD.encode(advanced.signing_public_key),
            vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(advanced.signing_key_fingerprint),
            manifest_revision: advanced.manifest_revision.to_string(),
            manifest_signing_key_version: advanced.manifest_signing_key_version,
            vdk_version: advanced.vdk_version,
        };
        if let Some(anchor) = next
            .iter_mut()
            .find(|anchor| anchor.vault_id == public.vault_id)
        {
            *anchor = public;
        } else {
            next.push(public);
        }
    }
    next.sort_by(|left, right| left.vault_id.cmp(&right.vault_id));
    Ok(next)
}

fn initial_vault_trust(
    manifest: &VaultManifestV2,
    identity: &AgentIdentityBinding,
) -> Result<PinnedVaultTrust, RuntimeError> {
    let signing_public_key = decode_32_url(&manifest.vault_signing_public_key)?;
    let signing_key_fingerprint = decode_32_url(&manifest.vault_signing_key_fingerprint)?;
    if key_fingerprint(3, &signing_public_key)? != signing_key_fingerprint {
        return Err(RuntimeError::UntrustedVaultManifest);
    }
    let tentative = PinnedVaultTrust {
        vault_id: Uuid::parse_str(&manifest.vault_id)
            .map_err(|_| RuntimeError::UntrustedVaultManifest)?,
        signing_public_key,
        signing_key_fingerprint,
        manifest_revision: validate_sequence(&manifest.manifest_revision)?,
        manifest_signing_key_version: manifest.manifest_signing_key_version,
        vdk_version: manifest.vdk_version,
    };
    verify_current_manifest(manifest, identity, &tentative)
        .map_err(|_| RuntimeError::UntrustedVaultManifest)
}

async fn retry_sync_state_changed<T, F, Fut>(mut operation: F) -> Result<T, RuntimeError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, RuntimeError>>,
{
    for attempt in 0..MAX_SYNC_STATE_CHANGED_ATTEMPTS {
        match operation().await {
            Err(RuntimeError::Api(ApiError::SyncStateChanged))
                if attempt + 1 < MAX_SYNC_STATE_CHANGED_ATTEMPTS =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(
                    SYNC_STATE_CHANGED_BACKOFF_MS * (attempt + 1) as u64,
                ))
                .await;
            }
            result => return result,
        }
    }
    Err(RuntimeError::Api(ApiError::SyncStateChanged))
}

fn publish_discovery_attempt<T, F>(
    live: &mut LocalDiscoveryIndex,
    working: LocalDiscoveryIndex,
    result: Result<T, RuntimeError>,
    persist: F,
) -> Result<T, RuntimeError>
where
    F: FnOnce() -> Result<(), RuntimeError>,
{
    let value = result?;
    persist()?;
    *live = working;
    Ok(value)
}

fn public_anchors_from_pairing(
    organization_id: Uuid,
    agent_access_epoch: u64,
    anchors: Vec<PinnedVaultTrust>,
) -> Result<Vec<PublicVaultTrustAnchor>, RuntimeError> {
    if agent_access_epoch == 0 {
        return Err(RuntimeError::InvalidPublicConfig);
    }
    let mut public = anchors
        .into_iter()
        .map(|anchor| PublicVaultTrustAnchor {
            organization_id: organization_id.to_string(),
            vault_id: anchor.vault_id.to_string(),
            agent_access_epoch,
            vault_signing_public_key: URL_SAFE_NO_PAD.encode(anchor.signing_public_key),
            vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(anchor.signing_key_fingerprint),
            manifest_revision: anchor.manifest_revision.to_string(),
            manifest_signing_key_version: anchor.manifest_signing_key_version,
            vdk_version: anchor.vdk_version,
        })
        .collect::<Vec<_>>();
    public.sort_by(|left, right| left.vault_id.cmp(&right.vault_id));
    Ok(public)
}

fn validate_confirmed_pairing_identity(
    expected: &AgentIdentityBinding,
    anchors: &[PublicVaultTrustAnchor],
    config: &PublicProfileConfig,
    encryption_public_key: &[u8; 32],
    signing_public_key: &[u8; 32],
) -> Result<(), RuntimeError> {
    let configured_agent_id = config
        .agent_id
        .as_deref()
        .ok_or(RuntimeError::MissingAgentId)
        .and_then(|value| Uuid::parse_str(value).map_err(|_| RuntimeError::InvalidPublicConfig))?;
    if configured_agent_id != expected.agent_id
        || key_fingerprint(1, encryption_public_key)? != expected.x25519_fingerprint
        || key_fingerprint(2, signing_public_key)? != expected.ed25519_fingerprint
        || anchors
            .iter()
            .any(|anchor| anchor.organization_id != expected.organization_id.to_string())
    {
        return Err(RuntimeError::UntrustedVaultManifest);
    }
    Ok(())
}

const fn credential_method_mask(method: CredentialMethod) -> u16 {
    match method {
        CredentialMethod::Get => 1,
        CredentialMethod::Exec => 2,
        CredentialMethod::Inject => 4,
    }
}

fn authenticated_inject_metadata(
    plaintext: &[u8],
) -> Result<(Option<String>, Vec<AgentVisibleField>), RuntimeError> {
    let parsed = parse_secret(plaintext).map_err(|_| RuntimeError::InvalidCredentialPayload)?;
    let domain = parsed
        .fields
        .get("urlDomain")
        .map(|value| value.expose_secret().trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            parsed.url.as_ref().and_then(|value| {
                url::Url::parse(value.expose_secret())
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            })
        });
    let authenticated_fields = parsed
        .username
        .as_ref()
        .map(|username| AgentVisibleField {
            label: "credential.username".to_owned(),
            value: username.expose_secret().to_owned(),
        })
        .into_iter()
        .collect();
    Ok((domain, authenticated_fields))
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
    #[error("browser host is not paired; complete explicit extension pairing first")]
    BrowserHostNotPaired,
    #[error("the authenticated browser host pairing was revoked")]
    BrowserHostRevoked,
    #[error("the authenticated browser host lifecycle is busy")]
    BrowserHostLifecycleBusy,
    #[error("authenticated browser host transport failed: {0}")]
    BrowserHostTransport(#[from] SecureTransportError),
    #[error("cryptographic identity operation failed: {0}")]
    Crypto(#[from] palladin_crypto::CryptoError),
    #[error("API client operation failed: {0}")]
    Api(#[from] ApiError),
    #[error("local Form Discovery Map cache operation failed")]
    FormMapCache,
    #[error("the value-free Form Discovery Map candidate is invalid")]
    InvalidFormDiscoveryMap,
    #[error("API key is invalid; it must start with pl_")]
    InvalidApiKey,
    #[error("stored Agent identity is incomplete")]
    MissingIdentity,
    #[error("stored organization credential is missing")]
    MissingOrganizationCredential,
    #[error("Agent is not registered; run palladin status or reconnect it")]
    MissingAgentId,
    #[error("Agent is not active; approve it in Palladin, then run palladin pair")]
    AgentNotActive,
    #[error("stored secret has an invalid format")]
    InvalidStoredSecret,
    #[error("public profile configuration is invalid")]
    InvalidPublicConfig,
    #[error("decrypted Discovery payload is invalid")]
    InvalidDiscoveryPayload,
    #[error("local Discovery query is invalid")]
    InvalidDiscoveryQuery,
    #[error("local Discovery cursor is invalid or stale")]
    InvalidDiscoveryCursor,
    #[error("Agent Discovery does not match the granted Entry revision")]
    DiscoveryRevisionMismatch,
    #[error(
        "Script execution metadata is unavailable; refresh Discovery after updating the Script"
    )]
    ScriptExecutionMetadataUnavailable,
    #[error("local Discovery index exceeds its hard entry limit")]
    DiscoveryIndexLimitExceeded,
    #[error(
        "vault manifest is not bound to an independently paired local trust anchor; run palladin pair"
    )]
    UntrustedVaultManifest,
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
    #[error("the authenticated credential grant expired before browser injection")]
    CredentialGrantExpired,
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
    #[error("Script parameter values do not match the current Discovery schema")]
    InvalidScriptParameters,
    #[error("Script Discovery is stale; refresh Discovery before retrying")]
    StaleScriptDiscovery,
    #[error("the atomic Script execution package is invalid, stale or substituted")]
    InvalidScriptExecutionPackage,
}

impl From<FormMapCacheError> for RuntimeError {
    fn from(_: FormMapCacheError) -> Self {
        Self::FormMapCache
    }
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

fn preflight_script_references_raw(
    references: &[palladin_credential::secret::ScriptRef],
    expected_vault_id: &str,
) -> Result<(), RuntimeError> {
    let mut names = BTreeSet::new();
    for reference in references {
        validate_reference_name(&reference.env)?;
        let normalized = reference.env.to_ascii_uppercase();
        if !names.insert(normalized) {
            return Err(EnvironmentError::DuplicateName.into());
        }
        if Uuid::parse_str(&reference.entry_id).is_err()
            || reference.vault_id.as_deref() != Some(expected_vault_id)
            || reference.field_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(RuntimeError::InvalidEnvironmentMapping);
        }
    }
    Ok(())
}

fn finalize_script_result(
    captured: CapturedScriptResult,
    return_result_to_agent: bool,
    protected_literals: &[SecretString],
) -> ScriptExecutionResult {
    let CapturedScriptResult {
        exit_code,
        cancelled,
        mut stdout,
        stdout_too_large,
    } = captured;
    let withheld = if cancelled {
        Some(ScriptResultWithheld::Cancelled)
    } else if !return_result_to_agent {
        Some(ScriptResultWithheld::PolicyDisabled)
    } else if stdout_too_large {
        Some(ScriptResultWithheld::ResultTooLarge)
    } else if std::str::from_utf8(&stdout).is_err() {
        Some(ScriptResultWithheld::ResultInvalidText)
    } else if protected_literals.iter().any(|literal| {
        let literal = literal.expose_secret().as_bytes();
        !literal.is_empty()
            && stdout
                .windows(literal.len())
                .any(|window| window == literal)
    }) {
        Some(ScriptResultWithheld::ProtectedLiteralDetected)
    } else {
        None
    };
    let result = withheld.is_none().then(|| {
        let bytes = std::mem::take(stdout.as_mut());
        Zeroizing::new(String::from_utf8(bytes).expect("UTF-8 was validated above"))
    });
    ScriptExecutionResult {
        exit_code,
        cancelled,
        result,
        withheld,
    }
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

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use palladin_crypto::{
        EncodedSuitePayload, EncryptedCredential, EnvelopeBinding, EnvelopeDescriptor,
        EnvelopePurpose, EnvelopeScope, GrantEnvelopeBinding, GrantEnvelopeDescriptor,
        GrantEnvelopeScope, RecipientKeyKind, VAULT_XCHACHA_V1, WrappedGrantDek, WrapperContext,
        WrapperPurpose, X25519_WRAPPER_V1, X25519SealedBoxSuite, XChaChaVaultSuite,
        compute_field_set_commitment, compute_key_fingerprint,
    };
    use secrecy::{ExposeSecret, SecretBox};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn script_result_is_returned_only_when_policy_and_literal_scan_allow_it() {
        let allowed = finalize_script_result(
            CapturedScriptResult {
                exit_code: 0,
                cancelled: false,
                stdout: Zeroizing::new(b"42 users".to_vec()),
                stdout_too_large: false,
            },
            true,
            &[SecretString::from("fixture-secret".to_owned())],
        );
        assert_eq!(
            allowed.result.as_deref().map(String::as_str),
            Some("42 users")
        );
        assert_eq!(allowed.withheld, None);

        let blocked = finalize_script_result(
            CapturedScriptResult {
                exit_code: 0,
                cancelled: false,
                stdout: Zeroizing::new(b"prefix fixture-secret suffix".to_vec()),
                stdout_too_large: false,
            },
            true,
            &[SecretString::from("fixture-secret".to_owned())],
        );
        assert!(blocked.result.is_none());
        assert_eq!(
            blocked.withheld,
            Some(ScriptResultWithheld::ProtectedLiteralDetected)
        );
    }

    #[test]
    fn script_result_policy_large_invalid_and_cancelled_states_are_explicit() {
        for (captured, enabled, expected) in [
            (
                CapturedScriptResult {
                    exit_code: 0,
                    cancelled: false,
                    stdout: Zeroizing::new(b"safe".to_vec()),
                    stdout_too_large: false,
                },
                false,
                ScriptResultWithheld::PolicyDisabled,
            ),
            (
                CapturedScriptResult {
                    exit_code: 0,
                    cancelled: false,
                    stdout: Zeroizing::new(b"safe".to_vec()),
                    stdout_too_large: true,
                },
                true,
                ScriptResultWithheld::ResultTooLarge,
            ),
            (
                CapturedScriptResult {
                    exit_code: 0,
                    cancelled: false,
                    stdout: Zeroizing::new(vec![0xff]),
                    stdout_too_large: false,
                },
                true,
                ScriptResultWithheld::ResultInvalidText,
            ),
            (
                CapturedScriptResult {
                    exit_code: 130,
                    cancelled: true,
                    stdout: Zeroizing::new(Vec::new()),
                    stdout_too_large: false,
                },
                true,
                ScriptResultWithheld::Cancelled,
            ),
        ] {
            let result = finalize_script_result(captured, enabled, &[]);
            assert!(result.result.is_none());
            assert_eq!(result.withheld, Some(expected));
        }
    }

    const TEST_ORGANIZATION_ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
    const TEST_VAULT_ID: &str = "11112222-3333-4444-8555-666677778888";
    const TEST_ENTRY_ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    #[cfg(not(windows))]
    const TEST_REFERENCE_ENTRY_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const TEST_GRANT_ID: &str = "12345678-1234-4234-8234-1234567890ab";
    const TEST_AGENT_ID: &str = "fedcba98-7654-4321-8765-abcdefabcdef";
    const TEST_FORM_MAP: &str = r#"{
      "mapId":"11111111-1111-4111-8111-111111111111","mapVersion":1,
      "domain":"accounts.google.com","loginUrl":"https://accounts.google.com/","provider":"playwright",
      "fingerprint":"f6f9b42f136c52f404542e6596a7aae9af598d05d49004a29615a83e3479aa35",
      "map":{"version":1,"form":{"version":1,"steps":[
        {"fields":[{"entryFieldId":"credential.username","selector":"input[autocomplete=\"username\"]","control":"username"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"},"waitFor":{"selector":"input[type=\"password\"]"}},
        {"fields":[{"entryFieldId":"credential.password","selector":"input[type=\"password\"]","control":"password"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"}}
      ]}},"updatedAt":"2026-08-15T12:00:00Z"
    }"#;

    type MemorySecretValues = BTreeMap<(String, SecretSlot), Vec<u8>>;

    #[derive(Clone, Default)]
    struct MemorySecretStore(Arc<Mutex<MemorySecretValues>>);

    #[tokio::test]
    async fn stale_refresh_never_recaches_the_rejected_revision() {
        let (host, _) = single_response_server(200, TEST_FORM_MAP.to_owned()).await;
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let root = tempfile::tempdir().expect("cache root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("cache root mode");
        }
        let rejected: FormDiscoveryMap = serde_json::from_str(TEST_FORM_MAP).expect("map");
        FormMapCache::put_serialized(root.path(), &host, rejected.clone())
            .expect("cache rejected revision")
            .expect("accepted initial revision");
        let mut session = runtime_session(host.clone(), api, encryption);
        session.operation = RuntimeOperation::InjectCredential;
        session.form_map_root = root.path().to_path_buf();

        assert!(
            session
                .resolve_form_discovery_map("accounts.google.com", "playwright", Some(&rejected))
                .await
                .expect("refresh")
                .is_none()
        );
        assert!(
            FormMapCache::get_serialized(root.path(), &host, "accounts.google.com", "playwright")
                .expect("cache lookup")
                .is_none()
        );
    }

    impl SecretStore for MemorySecretStore {
        fn get(
            &self,
            owner_id: &str,
            slot: SecretSlot,
        ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
            Ok(self
                .0
                .lock()
                .expect("store")
                .get(&(owner_id.to_owned(), slot))
                .cloned()
                .map(Into::into))
        }

        fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("store")
                .insert((owner_id.to_owned(), slot), secret.to_vec());
            Ok(())
        }

        fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
            self.0
                .lock()
                .expect("store")
                .remove(&(owner_id.to_owned(), slot));
            Ok(())
        }
    }

    #[test]
    fn browser_host_identity_requires_explicit_pairing_and_is_stable() {
        assert!(std::mem::needs_drop::<BrowserHostLifecycleToken>());
        let root = tempfile::tempdir().expect("root");
        let repository = ProfileRepository::new(root.path().join("state")).expect("repository");
        let store = MemorySecretStore::default();
        let service = RuntimeService::new(repository, store.clone());

        assert!(matches!(
            service.browser_host_identity(),
            Err(RuntimeError::BrowserHostNotPaired)
        ));
        let provisioned = service
            .provision_browser_host_identity()
            .expect("provision identity");
        let reopened = service.browser_host_identity().expect("reopen identity");
        let repeated = service
            .provision_browser_host_identity()
            .expect("repeat pairing");
        let pairing = service.browser_host_pairing().expect("pairing snapshot");
        let repeated_pairing = service
            .provision_browser_host_pairing()
            .expect("repeat pairing snapshot");
        assert_eq!(provisioned.public_key(), reopened.public_key());
        assert_eq!(provisioned.public_key(), repeated.public_key());
        assert_eq!(provisioned.fingerprint(), reopened.fingerprint());
        assert_eq!(
            pairing.lifecycle_token(),
            repeated_pairing.lifecycle_token(),
            "ordinary install must not revoke already paired sessions"
        );
        assert_eq!(
            store
                .0
                .lock()
                .expect("store")
                .get(&(
                    BROWSER_HOST_IDENTITY_OWNER_ID.to_owned(),
                    SecretSlot::BrowserHostEd25519SecretKeyV1,
                ))
                .map(Vec::len),
            Some(32)
        );
        assert_eq!(
            store
                .0
                .lock()
                .expect("store")
                .get(&(
                    BROWSER_HOST_IDENTITY_OWNER_ID.to_owned(),
                    SecretSlot::BrowserHostLifecycleTokenV1,
                ))
                .map(Vec::len),
            Some(BROWSER_HOST_LIFECYCLE_TOKEN_BYTES)
        );
    }

    #[test]
    fn malformed_browser_host_identity_never_rotates_on_load() {
        let root = tempfile::tempdir().expect("root");
        let repository = ProfileRepository::new(root.path().join("state")).expect("repository");
        let store = MemorySecretStore::default();
        store
            .set(
                BROWSER_HOST_IDENTITY_OWNER_ID,
                SecretSlot::BrowserHostEd25519SecretKeyV1,
                &[9_u8; 31],
            )
            .expect("seed malformed identity");
        store
            .set(
                BROWSER_HOST_IDENTITY_OWNER_ID,
                SecretSlot::BrowserHostLifecycleTokenV1,
                &[7_u8; BROWSER_HOST_LIFECYCLE_TOKEN_BYTES],
            )
            .expect("seed lifecycle token");
        let service = RuntimeService::new(repository, store.clone());

        assert!(matches!(
            service.browser_host_identity(),
            Err(RuntimeError::BrowserHostTransport(
                SecureTransportError::InvalidHostIdentity
            ))
        ));
        assert_eq!(
            store
                .0
                .lock()
                .expect("store")
                .get(&(
                    BROWSER_HOST_IDENTITY_OWNER_ID.to_owned(),
                    SecretSlot::BrowserHostEd25519SecretKeyV1,
                ))
                .map(Vec::len),
            Some(31)
        );
    }

    #[test]
    fn concurrent_unpair_linearizes_inflight_inject_and_blocks_post_success_forward() {
        use std::sync::mpsc;
        use std::time::Duration;

        let root = tempfile::tempdir().expect("root");
        let state = root.path().join("state");
        let store = MemorySecretStore::default();
        let active = RuntimeService::new(
            ProfileRepository::new(state.clone()).expect("active repository"),
            store.clone(),
        );
        let revoker = RuntimeService::new(
            ProfileRepository::new(state).expect("revoker repository"),
            store,
        );
        let pairing = active
            .provision_browser_host_pairing()
            .expect("provision pairing");
        let forward = active
            .browser_host_lifecycle_guard(pairing.lifecycle_token())
            .expect("begin in-flight forward");

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let unpair = std::thread::spawn(move || {
            started_tx.send(()).expect("started");
            let result = revoker.unpair_browser_host_identity();
            done_tx.send(result).expect("done");
        });
        started_rx.recv().expect("unpair started");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "unpair must not report success while a forwarding lease is active"
        );

        drop(forward);
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("unpair completed")
            .expect("unpair succeeded");
        unpair.join().expect("unpair thread");
        assert!(matches!(
            active.browser_host_lifecycle_guard(pairing.lifecycle_token()),
            Err(RuntimeError::BrowserHostRevoked)
        ));
        let mut extension_received_inject = false;
        if let Ok(_forward) = active.browser_host_lifecycle_guard(pairing.lifecycle_token()) {
            extension_received_inject = true;
        }
        assert!(
            !extension_received_inject,
            "a loaded session must not forward Inject after unpair succeeds"
        );
        let values = active.secrets.0.lock().expect("store");
        assert!(!values.contains_key(&(
            BROWSER_HOST_IDENTITY_OWNER_ID.to_owned(),
            SecretSlot::BrowserHostLifecycleTokenV1,
        )));
        assert!(!values.contains_key(&(
            BROWSER_HOST_IDENTITY_OWNER_ID.to_owned(),
            SecretSlot::BrowserHostEd25519SecretKeyV1,
        )));
    }

    #[test]
    fn exclusive_lifecycle_lock_cannot_extend_inject_past_authenticated_grant_expiry() {
        let root = tempfile::tempdir().expect("root");
        let state = root.path().join("state");
        let store = MemorySecretStore::default();
        let service =
            RuntimeService::new(ProfileRepository::new(state).expect("repository"), store);
        let pairing = service
            .provision_browser_host_pairing()
            .expect("provision pairing");

        let encryption = X25519Identity::from_private_bytes(vec![61; 32]).expect("identity");
        let expires_at =
            OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() + 2)
                .expect("whole-second expiry");
        let body = grant_response_with_expiry(
            &encryption,
            TEST_ENTRY_ID,
            r#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture-sensitive-value"},{"id":"credential.urlDomain","kind":"text","mode":"value","value":"example.test"}],"schema":"palladin.grant-payload.v1"}"#,
            &["credential.password", "credential.urlDomain"],
            4,
            Some(expires_at),
        );
        let CredentialAccess::Granted {
            grant_id,
            approved_methods,
            material: CredentialCiphertext::Granular(envelope),
            ..
        } = serde_json::from_str(&body).expect("granted response")
        else {
            panic!("expected granted response")
        };
        let credential = decrypt_credential(
            &envelope,
            &encryption,
            &CredentialEnvelopeContext {
                organization_id: TEST_ORGANIZATION_ID,
                vault_id: TEST_VAULT_ID,
                grant_id: &grant_id,
                agent_id: TEST_AGENT_ID,
                entry_id: TEST_ENTRY_ID,
                approved_methods,
                requested_vault_id: TEST_VAULT_ID,
                requested_entry_id: TEST_ENTRY_ID,
                requested_method: 4,
            },
        )
        .expect("decrypt fresh grant");
        let remaining = credential
            .remaining_validity_at(OffsetDateTime::now_utc())
            .expect("validity")
            .expect("bounded grant");
        if remaining > std::time::Duration::from_millis(100) {
            std::thread::sleep(remaining - std::time::Duration::from_millis(100));
        }
        let delivered = DeliveredCredential {
            grant_id,
            entry_id: TEST_ENTRY_ID.to_owned(),
            label: "[REDACTED]".to_owned(),
            entry_revision: 1,
            authenticated_domain: Some("example.test".to_owned()),
            authenticated_fields: Vec::new(),
            credential,
        };
        let api = ApiClient::new(
            ApiHost::parse("https://api.stage.palladin.io").expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let mut session =
            runtime_session("https://api.stage.palladin.io".to_owned(), api, encryption);
        session.operation = RuntimeOperation::InjectCredential;
        session.consumed = AtomicBool::new(true);

        let exclusive = service
            .repository
            .acquire_transaction_lock()
            .expect("exclusive lifecycle lock");
        let mut extension_received_inject = false;
        let result =
            session.browser_inject_forward_guard(&service, pairing.lifecycle_token(), &delivered);
        if result.is_ok() {
            extension_received_inject = true;
        }
        assert!(matches!(result, Err(RuntimeError::CredentialGrantExpired)));
        assert!(
            !extension_received_inject,
            "an exclusive lifecycle operation must not extend a grant beyond expiry"
        );
        drop(exclusive);
    }

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

    #[test]
    fn inject_metadata_comes_from_the_fresh_authenticated_grant_payload() {
        let (domain, fields) = authenticated_inject_metadata(
            br#"{"username":"visible-user","password":"secret","url":"https://login.example.com/path","urlDomain":"login.example.com"}"#,
        )
        .expect("metadata");

        assert_eq!(domain.as_deref(), Some("login.example.com"));
        assert!(fields.iter().any(|field| {
            field.label == "credential.username" && field.value == "visible-user"
        }));
    }

    #[test]
    fn discovery_outer_entry_id_must_match_authenticated_envelope_scope() {
        let descriptor: palladin_api::AgentDiscoveryEnvelopeDescriptor =
            serde_json::from_value(serde_json::json!({
                "protocolVersion": 2,
                "cryptoSuiteId": "palladin-vault-xchacha-v1",
                "purpose": "agentDiscovery",
                "scope": {
                    "organizationId": "11111111-1111-4111-8111-111111111111",
                    "vaultId": "22222222-2222-4222-8222-222222222222",
                    "entryId": "33333333-3333-4333-8333-333333333333",
                    "grantOrRequestId": null,
                    "agentId": null,
                    "memberId": null
                },
                "resourceRevision": "7",
                "keyVersion": 2,
                "memberKeyGeneration": 1,
                "binding": {}
            }))
            .expect("descriptor");

        assert!(
            validate_discovery_envelope_scope(
                "22222222-2222-4222-8222-222222222222",
                2,
                "33333333-3333-4333-8333-333333333333",
                "7",
                descriptor.clone(),
            )
            .is_ok()
        );
        assert!(matches!(
            validate_discovery_envelope_scope(
                "22222222-2222-4222-8222-222222222222",
                2,
                "44444444-4444-4444-8444-444444444444",
                "7",
                descriptor,
            ),
            Err(RuntimeError::InvalidDiscoveryPayload)
        ));
    }

    fn signed_manifest_fixture() -> (AgentIdentityBinding, Vec<VaultManifestV2>) {
        let agent_encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("X25519");
        let agent_signing = Ed25519Identity::from_seed(vec![9; 32]).expect("Ed25519");
        let identity = AgentIdentityBinding {
            organization_id: Uuid::parse_str(TEST_ORGANIZATION_ID).expect("organization"),
            agent_id: Uuid::parse_str(TEST_AGENT_ID).expect("agent"),
            x25519_fingerprint: key_fingerprint(1, agent_encryption.public_key())
                .expect("X25519 fingerprint"),
            ed25519_fingerprint: key_fingerprint(2, agent_signing.public_key())
                .expect("Ed25519 fingerprint"),
        };
        let vault_ids = ["01112222-3333-4444-8555-666677778888", TEST_VAULT_ID];
        let manifests = vault_ids
            .into_iter()
            .enumerate()
            .map(|(index, vault_id)| {
                let signing = SigningKey::from_bytes(&[(index + 3) as u8; 32]);
                let signing_public_key = signing.verifying_key().to_bytes();
                let signing_fingerprint =
                    key_fingerprint(3, &signing_public_key).expect("Vault signing fingerprint");
                let mut manifest = VaultManifestV2 {
                    protocol_version: 2,
                    crypto_suite_id: "palladin-vault-xchacha-v1".to_owned(),
                    wrapper_suite_id: "palladin-x25519-sealed-box-v1".to_owned(),
                    signature_suite_id: "palladin-ed25519-v1".to_owned(),
                    organization_id: identity.organization_id.to_string(),
                    vault_id: vault_id.to_owned(),
                    agent_id: identity.agent_id.to_string(),
                    agent_x25519_fingerprint: URL_SAFE_NO_PAD.encode(identity.x25519_fingerprint),
                    agent_ed25519_fingerprint: URL_SAFE_NO_PAD.encode(identity.ed25519_fingerprint),
                    vault_signing_public_key: URL_SAFE_NO_PAD.encode(signing_public_key),
                    vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(signing_fingerprint),
                    manifest_signing_key_version: 1,
                    vault_agent_message_public_key: URL_SAFE_NO_PAD.encode([11 + index as u8; 32]),
                    vault_agent_message_key_fingerprint: URL_SAFE_NO_PAD
                        .encode([21 + index as u8; 32]),
                    agent_message_key_version: 1,
                    vdk_version: 1,
                    agent_wrapped_vdk_digest: URL_SAFE_NO_PAD.encode([31 + index as u8; 32]),
                    manifest_revision: "1".to_owned(),
                    issued_at: "2026-08-13T00:00:00Z".to_owned(),
                    minimum_agent_runtime_protocol: 2,
                    signature: String::new(),
                };
                let mut unsigned = serde_json::to_value(&manifest).expect("manifest JSON");
                unsigned
                    .as_object_mut()
                    .expect("manifest object")
                    .remove("signature");
                let canonical = serde_json::to_vec(&unsigned).expect("canonical manifest");
                let mut signed = b"PLDNV2SIG:VAULT-MANIFEST:".to_vec();
                signed.extend_from_slice(&2_u16.to_be_bytes());
                signed.extend_from_slice(&canonical);
                manifest.signature = URL_SAFE_NO_PAD.encode(signing.sign(&signed).to_bytes());
                manifest
            })
            .collect();
        (identity, manifests)
    }

    #[test]
    fn authenticated_manifest_batch_adds_a_future_vault_and_pins_its_signing_key() {
        let (identity, manifests) = signed_manifest_fixture();
        let parent = PublicVaultTrustAnchor {
            organization_id: identity.organization_id.to_string(),
            vault_id: manifests[0].vault_id.clone(),
            agent_access_epoch: 7,
            vault_signing_public_key: manifests[0].vault_signing_public_key.clone(),
            vault_signing_key_fingerprint: manifests[0].vault_signing_key_fingerprint.clone(),
            manifest_revision: manifests[0].manifest_revision.clone(),
            manifest_signing_key_version: manifests[0].manifest_signing_key_version,
            vdk_version: manifests[0].vdk_version,
        };

        let anchors = prepare_manifest_anchors(&[parent], 7, &manifests[1..], &identity)
            .expect("authenticated future Vault manifest");
        assert_eq!(anchors.len(), 2);
        assert!(
            anchors
                .iter()
                .any(|anchor| anchor.vault_id == manifests[1].vault_id)
        );

        let mut tampered = manifests[1].clone();
        tampered.vault_signing_public_key = URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
        assert!(matches!(
            prepare_manifest_anchors(&anchors[..1], 7, &[tampered], &identity),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
    }

    #[test]
    fn authenticated_initial_manifest_batch_pins_only_fully_valid_vault_keys() {
        let (identity, manifests) = signed_manifest_fixture();
        let anchors = prepare_manifest_anchors(&[], 7, &manifests, &identity)
            .expect("fully valid authenticated batch");
        assert_eq!(anchors.len(), manifests.len());
        assert!(anchors.iter().all(|anchor| anchor.agent_access_epoch == 7));
    }

    #[test]
    fn manifest_epoch_or_organization_mismatch_is_rejected_before_batch_application() {
        let (identity, manifests) = signed_manifest_fixture();
        let current = manifests
            .iter()
            .map(|manifest| PublicVaultTrustAnchor {
                organization_id: identity.organization_id.to_string(),
                vault_id: manifest.vault_id.clone(),
                agent_access_epoch: 7,
                vault_signing_public_key: manifest.vault_signing_public_key.clone(),
                vault_signing_key_fingerprint: manifest.vault_signing_key_fingerprint.clone(),
                manifest_revision: manifest.manifest_revision.clone(),
                manifest_signing_key_version: manifest.manifest_signing_key_version,
                vdk_version: manifest.vdk_version,
            })
            .collect::<Vec<_>>();
        let unchanged = current.clone();
        assert!(matches!(
            prepare_manifest_anchors(&current, 8, &manifests, &identity),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
        assert_eq!(current, unchanged);
        assert!(matches!(
            prepare_manifest_anchors(&[], 0, &manifests, &identity),
            Err(RuntimeError::UntrustedVaultManifest)
        ));

        let mut foreign_organization = unchanged;
        foreign_organization[0].organization_id = "99999999-9999-4999-8999-999999999999".to_owned();
        assert!(matches!(
            prepare_manifest_anchors(&foreign_organization, 7, &manifests, &identity),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
    }

    #[test]
    fn invalid_second_manifest_rolls_back_the_entire_anchor_batch_without_secret_leakage() {
        const SECRET_CANARY: &str = "private-key-secret-canary-must-not-leak";
        let (identity, mut manifests) = signed_manifest_fixture();
        manifests[1].signature = SECRET_CANARY.to_owned();
        let current = manifests
            .iter()
            .map(|manifest| PublicVaultTrustAnchor {
                organization_id: identity.organization_id.to_string(),
                vault_id: manifest.vault_id.clone(),
                agent_access_epoch: 7,
                vault_signing_public_key: manifest.vault_signing_public_key.clone(),
                vault_signing_key_fingerprint: manifest.vault_signing_key_fingerprint.clone(),
                manifest_revision: manifest.manifest_revision.clone(),
                manifest_signing_key_version: manifest.manifest_signing_key_version,
                vdk_version: manifest.vdk_version,
            })
            .collect::<Vec<_>>();
        let unchanged = current.clone();
        let error = prepare_manifest_anchors(&current, 7, &manifests, &identity)
            .expect_err("invalid second signature must reject the batch");

        assert_eq!(current, unchanged, "no prefix anchor was committed");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(SECRET_CANARY));
    }

    #[test]
    fn duplicate_or_substituted_first_use_anchor_is_rejected_atomically() {
        let (identity, mut manifests) = signed_manifest_fixture();
        manifests.push(manifests[0].clone());
        assert!(prepare_manifest_anchors(&[], 7, &manifests, &identity).is_err());

        let (identity, mut manifests) = signed_manifest_fixture();
        manifests[1].vault_signing_public_key = URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
        assert!(prepare_manifest_anchors(&[], 7, &manifests, &identity).is_err());
    }

    #[tokio::test]
    async fn sync_state_change_retries_the_whole_operation_and_then_succeeds() {
        let attempts = AtomicU64::new(0);
        let result = retry_sync_state_changed(|| async {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(RuntimeError::Api(ApiError::SyncStateChanged))
            } else {
                Ok("fresh-authorization")
            }
        })
        .await
        .expect("second fresh attempt");

        assert_eq!(result, "fresh-authorization");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sync_state_change_retry_is_bounded_and_other_conflicts_are_not_retried() {
        let exhausted = AtomicU64::new(0);
        let error = retry_sync_state_changed(|| async {
            exhausted.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(RuntimeError::Api(ApiError::SyncStateChanged))
        })
        .await
        .expect_err("bounded retry exhaustion");
        assert!(matches!(
            error,
            RuntimeError::Api(ApiError::SyncStateChanged)
        ));
        assert_eq!(
            exhausted.load(Ordering::SeqCst),
            MAX_SYNC_STATE_CHANGED_ATTEMPTS as u64
        );

        let other = AtomicU64::new(0);
        let error = retry_sync_state_changed(|| async {
            other.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(RuntimeError::Api(ApiError::InvalidResponse))
        })
        .await
        .expect_err("unrecognized conflict");
        assert!(matches!(
            error,
            RuntimeError::Api(ApiError::InvalidResponse)
        ));
        assert_eq!(other.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_discovery_attempt_neither_persists_nor_swaps_the_live_index() {
        for error in [
            RuntimeError::Api(ApiError::SyncStateChanged),
            RuntimeError::UntrustedVaultManifest,
        ] {
            let mut live = LocalDiscoveryIndex::new();
            live.upsert(
                TEST_VAULT_ID,
                TEST_ENTRY_ID,
                1,
                [1; 32],
                serde_json::from_value(json!({
                    "schema": "palladin.agent-discovery.v1",
                    "agentLabel": "existing-live-entry",
                    "capabilities": ["get"],
                    "fields": [{"id":"credential.username","value":"existing-user"}],
                    "entryType": "credential"
                }))
                .expect("discovery fixture"),
            )
            .expect("seed live index");
            let mut partially_applied = live.clone();
            partially_applied.purge();
            let persistence_calls = AtomicU64::new(0);

            publish_discovery_attempt(&mut live, partially_applied, Err::<(), _>(error), || {
                persistence_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect_err("failed attempt");

            assert_eq!(persistence_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                live.search("existing", None, None)
                    .expect("unchanged live index")
                    .items
                    .len(),
                1
            );
        }
    }

    #[derive(Default)]
    struct CountingManifestPersistence(AtomicU64);

    impl ManifestRevisionPersistence for CountingManifestPersistence {
        fn persist_manifest_batch(
            &self,
            _identity_id: &str,
            _expected_anchors: &[PublicVaultTrustAnchor],
            _next_anchors: &[PublicVaultTrustAnchor],
            _signing: &Ed25519Identity,
            _lease: &OperationLease,
        ) -> Result<(), RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn load_discovery_cache(
            &self,
            identity_id: &str,
            agent_id: &str,
            _commitment: Option<&PublicDiscoveryCacheCommitment>,
            _encryption: &X25519Identity,
        ) -> Result<LocalDiscoveryIndex, RuntimeError> {
            let mut index = LocalDiscoveryIndex::new();
            index.scope_to_identity(identity_id, agent_id);
            Ok(index)
        }

        fn persist_discovery_batch(
            &self,
            _identity_id: &str,
            _agent_id: &str,
            _expected_anchors: &[PublicVaultTrustAnchor],
            _next_anchors: &[PublicVaultTrustAnchor],
            _expected_cache: Option<&PublicDiscoveryCacheCommitment>,
            _next_cache: &PublicDiscoveryCacheCommitment,
            _ciphertext: &[u8],
            _signing: &Ed25519Identity,
            _lease: &OperationLease,
        ) -> Result<(), RuntimeError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn unchanged_manifest_batch_still_revalidates_durable_anchors() {
        let host = "http://127.0.0.1:5000".to_owned();
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let persistence = CountingManifestPersistence::default();
        let mut session = runtime_session(host, api, encryption);
        session.manifest_persistence = Some(&persistence);
        session.profile_signing = Some(Ed25519Identity::from_seed(vec![9; 32]).expect("signing"));
        let batch = PreparedManifestBatch {
            items: Vec::new(),
            next_anchors: session.config.vault_trust_anchors.clone(),
        };

        session
            .persist_prepared_manifest_batch(&batch)
            .expect("durable anchor validation");

        assert_eq!(persistence.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn epoch_rejection_clears_live_discovery_without_publishing_partial_state() {
        let (host, _) =
            single_response_server(200, r#"{"agentAccessEpoch":2,"items":[]}"#.to_owned()).await;
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("identity");
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let persistence = Box::leak(Box::new(CountingManifestPersistence::default()));
        let mut session = runtime_session(host, api, encryption);
        session.manifest_persistence = Some(persistence);
        session.profile_signing = Some(Ed25519Identity::from_seed(vec![9; 32]).expect("signing"));
        {
            let mut live = session.discovery.lock().await;
            live.upsert(
                TEST_VAULT_ID,
                TEST_ENTRY_ID,
                1,
                [1; 32],
                serde_json::from_value(json!({
                    "schema": "palladin.agent-discovery.v1",
                    "agentLabel": "existing-live-entry",
                    "capabilities": ["get"],
                    "fields": [{"id":"credential.username","value":"existing-user"}],
                    "entryType": "credential"
                }))
                .expect("discovery fixture"),
            )
            .expect("seed live index");
        }

        let error = session
            .sync_local_discovery()
            .await
            .expect_err("epoch mismatch");

        assert!(matches!(error, RuntimeError::UntrustedVaultManifest));
        assert_eq!(persistence.0.load(Ordering::SeqCst), 0);
        assert!(
            session
                .discovery
                .lock()
                .await
                .search("existing", None, None)
                .expect("cleared live index")
                .items
                .is_empty()
        );
    }

    #[test]
    fn manifest_revision_advance_survives_restart_and_rejects_regression() {
        let root = tempfile::tempdir().expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let store = MemorySecretStore::default();
        let repository = ProfileRepository::new(root.path().to_path_buf()).expect("repository");
        let service = RuntimeService::new(repository, store.clone());
        let created = service.create_profile("default", None).expect("profile");
        let signing_secret = store
            .get(&created.identity_id, SecretSlot::Ed25519SecretKey)
            .expect("read signing key")
            .expect("signing key");
        let signing =
            Ed25519Identity::from_libsodium_secret(signing_secret.expose_secret().to_vec())
                .expect("signing identity");
        let vault_signing_key = [3_u8; 32];
        let vault_signing_fingerprint =
            key_fingerprint(3, &vault_signing_key).expect("fingerprint");
        let anchor = PublicVaultTrustAnchor {
            organization_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            vault_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            agent_access_epoch: 1,
            vault_signing_public_key: URL_SAFE_NO_PAD.encode(vault_signing_key),
            vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(vault_signing_fingerprint),
            manifest_revision: "7".to_owned(),
            manifest_signing_key_version: 2,
            vdk_version: 3,
        };
        {
            let _lock = service
                .repository
                .acquire_transaction_lock()
                .expect("transaction lock");
            let state = service.verified_state_locked().expect("verified state");
            let mut config = PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                identity_id: created.identity_id.clone(),
                host: "https://api.stage.palladin.io".to_owned(),
                organization_credential_id: "44444444444444444444444444444444".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: Some("55555555-5555-4555-8555-555555555555".to_owned()),
                agent_active: true,
                encryption_public_key: Some(created.encryption_public_key.clone()),
                signing_public_key: Some(created.signing_public_key.clone()),
                vault_trust_anchors: vec![anchor.clone()],
                discovery_cache: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            };
            let binding = profile_binding_bytes(&config).expect("binding");
            config.binding_signature = STANDARD.encode(signing.sign_profile_binding(&binding));
            let digest = profile_config_digest(&config).expect("config digest");
            let mut registry = state.registry.clone();
            registry.agents[0].config_digest = Some(digest);
            service
                .commit_transition(
                    &state,
                    registry,
                    vec![ConfigWrite {
                        identity_id: created.identity_id.clone(),
                        config,
                    }],
                    Vec::new(),
                    Vec::new(),
                    false,
                )
                .expect("seed paired profile");
        }
        let advanced = PinnedVaultTrust {
            vault_id: Uuid::parse_str(&anchor.vault_id).expect("vault id"),
            signing_public_key: vault_signing_key,
            signing_key_fingerprint: vault_signing_fingerprint,
            manifest_revision: 8,
            manifest_signing_key_version: 2,
            vdk_version: 4,
        };
        service
            .persist_advanced_manifest_revision(
                &created.identity_id,
                &anchor,
                &advanced,
                &signing,
                &test_lease(),
            )
            .expect("persist manifest advance");

        let restarted = RuntimeService::new(
            ProfileRepository::new(root.path().to_path_buf()).expect("restart repository"),
            store,
        );
        restarted.registry().expect("restart verification");
        let persisted = restarted
            .repository
            .load_config(&created.identity_id)
            .expect("persisted config");
        assert_eq!(persisted.vault_trust_anchors[0].manifest_revision, "8");
        assert_eq!(persisted.vault_trust_anchors[0].vdk_version, 4);
        let regressed = PinnedVaultTrust {
            manifest_revision: 7,
            ..advanced
        };
        assert!(matches!(
            restarted.persist_advanced_manifest_revision(
                &created.identity_id,
                &anchor,
                &regressed,
                &signing,
                &test_lease(),
            ),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
        let downgraded_vdk = PinnedVaultTrust {
            manifest_revision: 9,
            vdk_version: 3,
            ..advanced
        };
        assert!(matches!(
            restarted.persist_advanced_manifest_revision(
                &created.identity_id,
                &anchor,
                &downgraded_vdk,
                &signing,
                &test_lease(),
            ),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
    }

    #[test]
    fn encrypted_discovery_cache_survives_restart_and_rejects_file_rollback() {
        let root = tempfile::tempdir().expect("root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let store = MemorySecretStore::default();
        let service = RuntimeService::new(
            ProfileRepository::new(root.path().to_path_buf()).expect("repository"),
            store.clone(),
        );
        let created = service.create_profile("default", None).expect("profile");
        let signing = Ed25519Identity::from_libsodium_secret(
            store
                .get(&created.identity_id, SecretSlot::Ed25519SecretKey)
                .expect("read signing key")
                .expect("signing key")
                .expose_secret()
                .to_vec(),
        )
        .expect("signing identity");
        let encryption = X25519Identity::from_private_bytes(
            store
                .get(&created.identity_id, SecretSlot::X25519PrivateKey)
                .expect("read encryption key")
                .expect("encryption key")
                .expose_secret()
                .to_vec(),
        )
        .expect("encryption identity");
        let agent_id = "55555555-5555-4555-8555-555555555555";
        {
            let _lock = service
                .repository
                .acquire_transaction_lock()
                .expect("transaction lock");
            let state = service.verified_state_locked().expect("verified state");
            let mut config = PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                identity_id: created.identity_id.clone(),
                host: "https://api.stage.palladin.io".to_owned(),
                organization_credential_id: "44444444444444444444444444444444".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: Some(agent_id.to_owned()),
                agent_active: true,
                encryption_public_key: Some(created.encryption_public_key.clone()),
                signing_public_key: Some(created.signing_public_key.clone()),
                vault_trust_anchors: Vec::new(),
                discovery_cache: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            };
            let binding = profile_binding_bytes(&config).expect("binding");
            config.binding_signature = STANDARD.encode(signing.sign_profile_binding(&binding));
            let digest = profile_config_digest(&config).expect("config digest");
            let mut registry = state.registry.clone();
            registry.agents[0].config_digest = Some(digest);
            service
                .commit_transition(
                    &state,
                    registry,
                    vec![ConfigWrite {
                        identity_id: created.identity_id.clone(),
                        config,
                    }],
                    Vec::new(),
                    Vec::new(),
                    false,
                )
                .expect("seed active profile");
        }

        let vault_id = "11111111-1111-4111-8111-111111111111";
        let entry_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let mut index = LocalDiscoveryIndex::new();
        index.scope_to_identity(&created.identity_id, agent_id);
        index.prepare_vault(vault_id, 1);
        index
            .upsert(
                vault_id,
                entry_id,
                1,
                [1; 32],
                serde_json::from_value(json!({
                    "schema": "palladin.agent-discovery.v1",
                    "agentLabel": "restart sentinel",
                    "capabilities": ["inject"],
                    "fields": [{"id":"credential.username","value":"alice"}],
                    "entryType": "credential"
                }))
                .expect("discovery fixture"),
            )
            .expect("head");
        index.mark_applied(vault_id, "12".to_owned());

        let plaintext = index.encode_durable_cache().expect("encode cache");
        let first_binding =
            discovery_cache_binding(&created.identity_id, agent_id, 1).expect("cache binding");
        let first_ciphertext =
            seal_local_discovery_cache(encryption.public_key(), &first_binding, plaintext.as_ref())
                .expect("seal cache");
        let first_commitment = PublicDiscoveryCacheCommitment {
            generation: 1,
            ciphertext_sha256: hex_digest(Sha256::digest(&first_ciphertext)),
        };
        service
            .persist_discovery_batch(
                &created.identity_id,
                agent_id,
                &[],
                &[],
                None,
                &first_commitment,
                &first_ciphertext,
                &signing,
                &test_lease(),
            )
            .expect("persist cache");

        let restarted = RuntimeService::new(
            ProfileRepository::new(root.path().to_path_buf()).expect("restart repository"),
            store,
        );
        let config = restarted
            .repository
            .load_config(&created.identity_id)
            .expect("persisted config");
        let restored = restarted
            .load_discovery_cache(
                &created.identity_id,
                agent_id,
                config.discovery_cache.as_ref(),
                &encryption,
            )
            .expect("restart cache");
        assert_eq!(restored.applied_sequence(vault_id), Some("12"));
        assert_eq!(
            restored
                .search("restart sentinel", None, None)
                .expect("search cache")
                .items
                .len(),
            1
        );

        let second_binding =
            discovery_cache_binding(&created.identity_id, agent_id, 2).expect("cache binding");
        let second_ciphertext = seal_local_discovery_cache(
            encryption.public_key(),
            &second_binding,
            plaintext.as_ref(),
        )
        .expect("seal next cache");
        let second_commitment = PublicDiscoveryCacheCommitment {
            generation: 2,
            ciphertext_sha256: hex_digest(Sha256::digest(&second_ciphertext)),
        };
        restarted
            .persist_discovery_batch(
                &created.identity_id,
                agent_id,
                &[],
                &[],
                Some(&first_commitment),
                &second_commitment,
                &second_ciphertext,
                &signing,
                &test_lease(),
            )
            .expect("advance cache generation");
        restarted
            .repository
            .save_discovery_cache(&created.identity_id, &first_ciphertext)
            .expect("simulate file rollback");
        let rolled_back = restarted
            .repository
            .load_config(&created.identity_id)
            .expect("current config");
        assert!(matches!(
            restarted.load_discovery_cache(
                &created.identity_id,
                agent_id,
                rolled_back.discovery_cache.as_ref(),
                &encryption,
            ),
            Err(RuntimeError::IntegrityViolation)
        ));
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
                vault_trust_anchors: Vec::new(),
                discovery_cache: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            },
            api,
            encryption,
            lease: test_lease(),
            operation: RuntimeOperation::GetCredential,
            consumed: AtomicBool::new(false),
            pairing_activation_id: None,
            discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
            manifest_persistence: None,
            profile_signing: None,
            form_map_root: std::path::PathBuf::new(),
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
    async fn granted_inject_uses_one_credential_request_and_never_syncs_discovery() {
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
        let payload = r#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture-password-not-production"},{"id":"credential.urlDomain","kind":"text","mode":"value","value":"login.example.test"},{"id":"credential.username","kind":"text","mode":"value","value":"fixture-user"}],"schema":"palladin.grant-payload.v1"}"#;
        let body = grant_response(
            &encryption,
            TEST_ENTRY_ID,
            payload,
            &[
                "credential.password",
                "credential.urlDomain",
                "credential.username",
            ],
            4,
        );
        let (host, requests) = credential_server_owned(vec![body]).await;
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let mut session = runtime_session(host, api, encryption);
        session.operation = RuntimeOperation::InjectCredential;

        let delivery = session
            .deliver_for_inject(request(), &CancellationToken::new(), |_| {})
            .await
            .expect("Inject delivery");
        let CredentialDelivery::Granted(delivered) = delivery else {
            panic!("expected granted Inject");
        };

        assert_eq!(delivered.authenticated_domain(), Some("login.example.test"));
        assert_eq!(
            delivered.authenticated_field("credential.username"),
            Some("fixture-user")
        );
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("/credential"));
        assert!(!requests[0].contains("/discovery"));
        assert!(!requests[0].contains("/manifests"));
    }

    #[tokio::test]
    async fn native_exec_consumes_the_canonical_credential_envelope() {
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
        let payload = r#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture-password-not-production"},{"id":"credential.url","kind":"url","mode":"value","value":"https://example.test/login"},{"id":"credential.username","kind":"text","mode":"value","value":"fixture-user"}],"schema":"palladin.grant-payload.v1"}"#;
        let body = grant_response(
            &encryption,
            TEST_ENTRY_ID,
            payload,
            &[
                "credential.password",
                "credential.url",
                "credential.username",
            ],
            2,
        );
        let (host, requests) = credential_server_owned(vec![body]).await;
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
                    parameters: &serde_json::json!({}),
                    output: OperatorOutput::Discard,
                },
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        assert_eq!(
            outcome.expect("native exec"),
            CredentialExecOutcome::Completed(ExecResult {
                exit_code: 0,
                cancelled: false,
            })
        );
        let replay = session
            .execute_with_credential(
                CredentialExecRequest {
                    delivery: request(),
                    command: Some(&command),
                    env_mappings: &[],
                    parameters: &serde_json::json!({}),
                    output: OperatorOutput::Discard,
                },
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        assert!(matches!(
            replay,
            Err(RuntimeError::OperationAuthorizationConsumed)
        ));
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains(r#""method":"Exec""#));
        let contains_key = requests[0].contains("x-api-key: pl_shared_organization_fixture\r\n");
        assert!(contains_key, "request omitted the organization credential");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn legacy_script_delivery_never_falls_back_to_n_plus_one_reference_requests() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/v1/encrypted-envelope.json"
        ))
        .expect("identity fixture");
        let private_key = STANDARD
            .decode(
                fixture
                    .pointer("/keyFixture/privateKeyBase64")
                    .and_then(serde_json::Value::as_str)
                    .expect("private key"),
            )
            .expect("private key base64");
        let encryption = X25519Identity::from_private_bytes(private_key).expect("identity");
        let main_payload = format!(
            r#"{{"entryType":"script","fields":[{{"id":"script.interpreter","kind":"interpreter","mode":"runtime","value":"sh"}},{{"id":"script.refs","kind":"refs","mode":"runtime","value":[{{"entryId":"{TEST_REFERENCE_ENTRY_ID}","env":"TEST_SECRET","fieldId":"credential.password","vaultId":"{TEST_VAULT_ID}"}}]}},{{"id":"script.source","kind":"script","mode":"runtime","value":"test \"$TEST_SECRET\" = fixture-password-not-production"}}],"schema":"palladin.grant-payload.v1"}}"#
        );
        let main = grant_response(
            &encryption,
            TEST_ENTRY_ID,
            &main_payload,
            &["script.interpreter", "script.refs", "script.source"],
            2,
        );
        let (host, requests) = credential_server_owned(vec![main]).await;
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
                    delivery: CredentialDeliveryRequest {
                        vault_id: TEST_VAULT_ID,
                        entry_id: TEST_ENTRY_ID,
                        reason: None,
                        wait: WaitOptions {
                            wait_ms: Some(0),
                            poll_ms: None,
                            progress: None,
                        },
                    },
                    command: Some(&command),
                    env_mappings: &[],
                    parameters: &serde_json::json!({}),
                    output: OperatorOutput::Discard,
                },
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        assert!(matches!(
            outcome,
            Err(RuntimeError::InvalidCredentialPayload)
        ));
        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains(&format!(
            "/vaults/{TEST_VAULT_ID}/entries/{TEST_ENTRY_ID}/credential"
        )));
        assert!(!requests[0].contains(TEST_REFERENCE_ENTRY_ID));
        assert!(requests[0].contains(r#""method":"Exec""#));
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
            vault_id: TEST_VAULT_ID,
            entry_id: TEST_ENTRY_ID,
            reason: None,
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

    async fn single_response_server(
        status: u16,
        body: String,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_request(&mut stream).await;
            captured.lock().expect("requests").push(request);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        (format!("http://{address}"), requests)
    }

    fn runtime_session(
        host: String,
        api: ApiClient,
        encryption: X25519Identity,
    ) -> RuntimeSession<'static> {
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
                agent_id: Some(TEST_AGENT_ID.to_owned()),
                agent_active: true,
                encryption_public_key: None,
                signing_public_key: None,
                vault_trust_anchors: vec![PublicVaultTrustAnchor {
                    organization_id: TEST_ORGANIZATION_ID.to_owned(),
                    vault_id: TEST_VAULT_ID.to_owned(),
                    agent_access_epoch: 1,
                    vault_signing_public_key: STANDARD.encode([1_u8; 32]),
                    vault_signing_key_fingerprint: STANDARD.encode([2_u8; 32]),
                    manifest_revision: "1".to_owned(),
                    manifest_signing_key_version: 1,
                    vdk_version: 1,
                }],
                discovery_cache: None,
                binding_signature: STANDARD.encode([0_u8; 64]),
            },
            api,
            encryption,
            lease: test_lease(),
            operation: RuntimeOperation::ExecWithCredential,
            consumed: AtomicBool::new(false),
            pairing_activation_id: None,
            discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
            manifest_persistence: None,
            profile_signing: None,
            form_map_root: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn registration_agent_id_change_invalidates_pairing_anchors() {
        let mut config = PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host: "https://example.test".to_owned(),
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some("agent-current".to_owned()),
            agent_active: true,
            encryption_public_key: None,
            signing_public_key: None,
            vault_trust_anchors: vec![PublicVaultTrustAnchor {
                organization_id: TEST_ORGANIZATION_ID.to_owned(),
                vault_id: TEST_VAULT_ID.to_owned(),
                agent_access_epoch: 1,
                vault_signing_public_key: STANDARD.encode([1_u8; 32]),
                vault_signing_key_fingerprint: STANDARD.encode([2_u8; 32]),
                manifest_revision: "1".to_owned(),
                manifest_signing_key_version: 1,
                vdk_version: 1,
            }],
            discovery_cache: None,
            binding_signature: STANDARD.encode([0_u8; 64]),
        };

        update_registered_agent_id(&mut config, "agent-current");
        assert_eq!(config.vault_trust_anchors.len(), 1);

        update_registered_agent_id(&mut config, "agent-replacement");
        assert_eq!(config.agent_id.as_deref(), Some("agent-replacement"));
        assert!(config.vault_trust_anchors.is_empty());
    }

    #[test]
    fn confirmed_pairing_cannot_cross_agent_identity() {
        let encryption = X25519Identity::generate().expect("encryption identity");
        let signing = Ed25519Identity::generate().expect("signing identity");
        let agent_id = Uuid::parse_str(TEST_AGENT_ID).expect("agent id");
        let organization_id = Uuid::parse_str(TEST_ORGANIZATION_ID).expect("organization id");
        let expected = AgentIdentityBinding {
            organization_id,
            agent_id,
            x25519_fingerprint: key_fingerprint(1, encryption.public_key()).expect("fingerprint"),
            ed25519_fingerprint: key_fingerprint(2, signing.public_key()).expect("fingerprint"),
        };
        let anchor = PublicVaultTrustAnchor {
            organization_id: TEST_ORGANIZATION_ID.to_owned(),
            vault_id: TEST_VAULT_ID.to_owned(),
            agent_access_epoch: 1,
            vault_signing_public_key: STANDARD.encode([1_u8; 32]),
            vault_signing_key_fingerprint: STANDARD.encode([2_u8; 32]),
            manifest_revision: "1".to_owned(),
            manifest_signing_key_version: 1,
            vdk_version: 1,
        };
        let mut config = PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host: "https://example.test".to_owned(),
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some(TEST_AGENT_ID.to_owned()),
            agent_active: true,
            encryption_public_key: Some(STANDARD.encode(encryption.public_key())),
            signing_public_key: Some(STANDARD.encode(signing.public_key())),
            vault_trust_anchors: Vec::new(),
            discovery_cache: None,
            binding_signature: STANDARD.encode([0_u8; 64]),
        };

        validate_confirmed_pairing_identity(
            &expected,
            std::slice::from_ref(&anchor),
            &config,
            encryption.public_key(),
            signing.public_key(),
        )
        .expect("matching identity");

        config.agent_id = Some("55555555-5555-4555-8555-555555555555".to_owned());
        assert!(matches!(
            validate_confirmed_pairing_identity(
                &expected,
                &[anchor],
                &config,
                encryption.public_key(),
                signing.public_key(),
            ),
            Err(RuntimeError::UntrustedVaultManifest)
        ));
    }

    #[tokio::test]
    async fn pair_vaults_session_renews_polling_for_the_bound_activation() {
        let activation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let encryption =
            X25519Identity::from_private_bytes(vec![41; 32]).expect("encryption identity");
        let signing = Ed25519Identity::from_seed(vec![42; 32]).expect("signing identity");
        let identity = AgentIdentityBinding {
            organization_id: Uuid::parse_str(TEST_ORGANIZATION_ID).expect("organization id"),
            agent_id: Uuid::parse_str(TEST_AGENT_ID).expect("agent id"),
            x25519_fingerprint: key_fingerprint(1, encryption.public_key()).expect("fingerprint"),
            ed25519_fingerprint: key_fingerprint(2, signing.public_key()).expect("fingerprint"),
        };
        let expected_candidate = prepare_pairing(
            Uuid::parse_str(activation_id).expect("activation id"),
            &identity,
            &[],
        )
        .expect("candidate");
        let expires_at = "2099-01-01T00:00:00Z";
        let activation = json!({
            "activationId": activation_id,
            "organizationId": TEST_ORGANIZATION_ID,
            "agentId": TEST_AGENT_ID,
            "agentAccessEpoch": 1,
            "agentX25519Fingerprint": URL_SAFE_NO_PAD.encode(identity.x25519_fingerprint),
            "agentEd25519Fingerprint": URL_SAFE_NO_PAD.encode(identity.ed25519_fingerprint),
            "expiresAt": expires_at,
            "candidateManifests": [],
        })
        .to_string();
        let pending = json!({
            "activationId": activation_id,
            "status": "pending",
            "expiresAt": expires_at,
            "confirmedPairingDigest": null,
        })
        .to_string();
        let confirmed = json!({
            "activationId": activation_id,
            "status": "confirmed",
            "expiresAt": expires_at,
            "confirmedPairingDigest": expected_candidate.transcript_digest(),
        })
        .to_string();
        let (host, requests) = credential_server_owned(vec![activation, pending, confirmed]).await;
        let api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_pairing_fixture".to_owned()),
            &encryption,
            "fixture-host",
            None,
        )
        .expect("API client");
        let profile = || PublicAgentEntry {
            name: "fixture".to_owned(),
            identity_id: "11111111111111111111111111111111".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            agent_type: None,
            config_digest: None,
        };
        let config = |host: String, identity: &X25519Identity| PublicProfileConfig {
            schema_version: PUBLIC_SCHEMA_VERSION,
            identity_id: "11111111111111111111111111111111".to_owned(),
            host,
            organization_credential_id: "22222222222222222222222222222222".to_owned(),
            retired_organization_credential_ids: Vec::new(),
            agent_id: Some(TEST_AGENT_ID.to_owned()),
            agent_active: true,
            encryption_public_key: Some(STANDARD.encode(identity.public_key())),
            signing_public_key: Some(STANDARD.encode(signing.public_key())),
            vault_trust_anchors: Vec::new(),
            discovery_cache: None,
            binding_signature: STANDARD.encode([0_u8; 64]),
        };
        let session = RuntimeSession {
            profile: profile(),
            config: config(host.clone(), &encryption),
            api,
            encryption,
            lease: test_lease(),
            operation: RuntimeOperation::PairVaults,
            consumed: AtomicBool::new(false),
            pairing_activation_id: Some(activation_id.to_owned()),
            discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
            manifest_persistence: None,
            profile_signing: None,
            form_map_root: std::path::PathBuf::new(),
        };

        let candidate = session
            .create_pairing_activation(activation_id)
            .await
            .expect("create pairing activation");
        assert_eq!(
            session
                .get_pairing_status(activation_id)
                .await
                .expect("pending status")
                .status,
            AgentPairingStatus::Pending
        );
        drop(session);

        let renewed_encryption =
            X25519Identity::from_private_bytes(vec![41; 32]).expect("renewed encryption identity");
        let renewed_api = ApiClient::new(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_pairing_fixture".to_owned()),
            &renewed_encryption,
            "fixture-host",
            None,
        )
        .expect("renewed API client");
        let renewed = RuntimeSession {
            profile: profile(),
            config: config(host, &renewed_encryption),
            api: renewed_api,
            encryption: renewed_encryption,
            lease: test_lease(),
            operation: RuntimeOperation::PairVaults,
            consumed: AtomicBool::new(false),
            pairing_activation_id: Some(activation_id.to_owned()),
            discovery: Arc::new(tokio::sync::Mutex::new(LocalDiscoveryIndex::new())),
            manifest_persistence: None,
            profile_signing: None,
            form_map_root: std::path::PathBuf::new(),
        };
        assert!(matches!(
            renewed.resume_pairing_polling("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Err(RuntimeError::OperationAuthorizationMismatch)
        ));
        renewed
            .resume_pairing_polling(activation_id)
            .expect("resume bound polling");
        let relay = renewed
            .get_pairing_status(activation_id)
            .await
            .expect("confirmed status");
        let pairing = candidate
            .confirm_from_relay(relay, OffsetDateTime::now_utc())
            .expect("confirmed pairing");
        assert!(pairing.anchors.is_empty());
        let requests = requests.lock().expect("requests");
        assert!(requests[0].starts_with("POST /api/agent/pairing/activations "));
        assert!(requests[1].starts_with(&format!(
            "GET /api/agent/pairing/activations/{activation_id} "
        )));
        assert!(requests[2].starts_with(&format!(
            "GET /api/agent/pairing/activations/{activation_id} "
        )));
    }

    fn grant_response(
        recipient: &X25519Identity,
        entry_id: &str,
        plaintext: &str,
        field_ids: &[&str],
        approved_methods: u16,
    ) -> String {
        grant_response_with_expiry(
            recipient,
            entry_id,
            plaintext,
            field_ids,
            approved_methods,
            None,
        )
    }

    fn grant_response_with_expiry(
        recipient: &X25519Identity,
        entry_id: &str,
        plaintext: &str,
        field_ids: &[&str],
        approved_methods: u16,
        expires_at: Option<OffsetDateTime>,
    ) -> String {
        let scope = EnvelopeScope {
            organization_id: test_uuid(TEST_ORGANIZATION_ID),
            vault_id: test_uuid(TEST_VAULT_ID),
            entry_id: Some(test_uuid(entry_id)),
            grant_or_request_id: Some(test_uuid(TEST_GRANT_ID)),
            agent_id: Some(test_uuid(TEST_AGENT_ID)),
            member_id: None,
        };
        let fingerprint =
            compute_key_fingerprint(recipient.public_key(), RecipientKeyKind::AgentX25519);
        let commitment =
            compute_field_set_commitment(field_ids.iter().copied()).expect("field-set commitment");
        let descriptor = EnvelopeDescriptor {
            protocol_version: 2,
            crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
            purpose: EnvelopePurpose::GrantPayload,
            scope: scope.clone(),
            resource_revision: 1,
            key_version: 1,
            member_key_generation: Some(1),
            binding: EnvelopeBinding::Grant {
                entry_revision: 1,
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                recipient_agent_key_version: 1,
                recipient_agent_key_fingerprint: fingerprint,
                approved_methods,
                delivery_policy: 0,
                field_set_commitment: commitment,
                expires_at: expires_at.map(|value| palladin_crypto::InstantBinding {
                    unix_seconds: value.unix_timestamp(),
                    nanosecond: value.nanosecond(),
                }),
                remaining_uses: Some(1),
            },
        };
        let aad = descriptor.canonical_aad().expect("AAD");
        let grant_dek = SecretBox::new(Box::new([0x31; 32]));
        let payload_key = XChaChaVaultSuite::derive_key(grant_dek.expose_secret(), &descriptor)
            .expect("payload key");
        let payload: EncodedSuitePayload =
            XChaChaVaultSuite::seal(&payload_key, plaintext.as_bytes(), &aad).expect("payload");
        let wrapper_context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::GrantDek,
            scope,
            resource_revision: 1,
            wrapped_key_version: 1,
            member_key_generation: Some(1),
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: 1,
            recipient_fingerprint: fingerprint,
            parent_descriptor_hash: Some(Sha256::digest(aad).into()),
        };
        let wrapped =
            X25519SealedBoxSuite::wrap(&grant_dek, *recipient.public_key(), &wrapper_context)
                .expect("wrapped DEK");
        let envelope = EncryptedCredential {
            descriptor: GrantEnvelopeDescriptor {
                protocol_version: 2,
                crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
                purpose: 10,
                scope: GrantEnvelopeScope {
                    organization_id: TEST_ORGANIZATION_ID.to_owned(),
                    vault_id: TEST_VAULT_ID.to_owned(),
                    entry_id: Some(entry_id.to_owned()),
                    grant_or_request_id: Some(TEST_GRANT_ID.to_owned()),
                    agent_id: Some(TEST_AGENT_ID.to_owned()),
                    member_id: None,
                },
                resource_revision: "1".to_owned(),
                key_version: 1,
                member_key_generation: Some(1),
                binding: GrantEnvelopeBinding {
                    entry_revision: "1".to_owned(),
                    wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                    recipient_key_version: 1,
                    recipient_key_fingerprint: URL_SAFE_NO_PAD.encode(fingerprint),
                    approved_methods,
                    delivery_policy: 0,
                    field_set_commitment: URL_SAFE_NO_PAD.encode(commitment),
                    expires_at: expires_at
                        .map(|value| value.format(&Rfc3339).expect("RFC3339 expiry")),
                    remaining_uses: Some(1),
                },
            },
            encoded_suite_payload: URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            wrapped_grant_dek: WrappedGrantDek::from_context(&wrapper_context, &wrapped),
            field_ids: field_ids.iter().map(|value| (*value).to_owned()).collect(),
        };
        json!({
            "access": "granted",
            "organizationId": TEST_ORGANIZATION_ID,
            "vaultId": TEST_VAULT_ID,
            "grantId": TEST_GRANT_ID,
            "agentId": TEST_AGENT_ID,
            "agentAccessEpoch": 1,
            "approvedMethods": approved_methods,
            "entryId": entry_id,
            "grantType": "granular",
            "deliveryPolicy": "standard",
            "expiresAt": expires_at.map(|value| value.format(&Rfc3339).expect("RFC3339 expiry")),
            "grantEnvelope": envelope,
        })
        .to_string()
    }

    fn test_uuid(value: &str) -> [u8; 16] {
        hex::decode(value.replace('-', ""))
            .expect("UUID hex")
            .try_into()
            .expect("UUID length")
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
