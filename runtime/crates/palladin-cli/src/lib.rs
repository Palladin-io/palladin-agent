#![forbid(unsafe_code)]

pub mod args;
pub mod output;

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_api::{AgentRegistrationResult, ApiClient, ApiError};
use palladin_core::host::ApiHost;
use palladin_core::profiles::{
    CleanupJournal, CleanupOperation, ProfileError, ProfileName, ProfileRepository, add_profile,
    delete_profile, rename_profile, set_default, set_profile_type,
};
use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
};
use palladin_core::secret::OrganizationApiKey;
pub use palladin_core::terminal::{safe_terminal_text, shorten_identifier};
use palladin_crypto::{
    DecryptedCredential, Ed25519Identity, EncryptedCredential, X25519Identity, decrypt_credential,
};
use palladin_platform::secure_store::{
    SecretSlot, SecretStore, StoreError, delete_identity, delete_organization_credential,
};
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

pub struct RuntimeService<S> {
    repository: ProfileRepository,
    secrets: S,
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

    pub fn registry(&self) -> Result<PublicRegistry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        Ok(self.repository.load_registry()?)
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
        let registry = self.repository.load_registry()?;
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
        let name = ProfileName::parse(name)?;
        let registry = self.repository.load_registry()?;
        let identity_id = generate_opaque_id()?;
        let encryption = X25519Identity::generate()?;
        let signing = Ed25519Identity::generate()?;

        self.schedule_cleanup(CleanupOperation::CreateIdentity {
            identity_id: identity_id.clone(),
        })?;

        if let Err(error) = self.secrets.set(
            &identity_id,
            SecretSlot::X25519PrivateKey,
            encryption.private_key_for_secure_storage(),
        ) {
            self.recover_or_cleanup_failed_locked()?;
            return Err(error.into());
        }
        let signing_secret = signing.libsodium_secret_for_secure_storage();
        if let Err(error) = self.secrets.set(
            &identity_id,
            SecretSlot::Ed25519SecretKey,
            signing_secret.expose_secret(),
        ) {
            self.recover_or_cleanup_failed_locked()?;
            return Err(error.into());
        }

        let updated = add_profile(
            &registry,
            &name,
            identity_id.clone(),
            now_rfc3339()?,
            agent_type,
        )?;
        if let Err(error) = self.repository.save_registry(&updated) {
            self.recover_or_cleanup_failed_locked()?;
            return Err(error.into());
        }
        self.recover_pending_operations_locked()?;

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
        let registry = self.repository.load_registry()?;
        let updated = rename_profile(&registry, &old_name, &new_name)?;
        self.repository.save_registry(&updated)?;
        Ok(())
    }

    pub fn set_default_profile(&self, name: &str) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let name = ProfileName::parse(name)?;
        let registry = self.repository.load_registry()?;
        self.repository
            .save_registry(&set_default(&registry, &name)?)?;
        Ok(())
    }

    pub fn delete_profile(&self, name: &str) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let name = ProfileName::parse(name)?;
        let registry = self.repository.load_registry()?;
        let (updated, deleted) = delete_profile(&registry, &name)?;
        let organization_ids = self
            .repository
            .config_exists(&deleted.identity_id)
            .then(|| self.repository.load_config(&deleted.identity_id))
            .transpose()?
            .map(|config| {
                let mut ids = config.retired_organization_credential_ids;
                ids.push(config.organization_credential_id);
                ids
            })
            .unwrap_or_default();

        self.schedule_cleanup(CleanupOperation::DeleteProfile {
            identity_id: deleted.identity_id.clone(),
            organization_credential_ids: organization_ids,
        })?;
        if let Err(error) = self.repository.save_registry(&updated) {
            self.recover_or_cleanup_failed_locked()?;
            return Err(error.into());
        }
        self.recover_pending_operations_locked()?;
        Ok(())
    }

    pub fn purge(&self) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        if self.repository.legacy_artifacts_present() {
            return Err(RuntimeError::LegacyMigrationRequired);
        }
        let registry = self.repository.load_registry()?;
        let mut organizations = BTreeSet::new();
        let mut identities = Vec::new();
        for agent in &registry.agents {
            identities.push(agent.identity_id.clone());
            if self.repository.config_exists(&agent.identity_id) {
                let config = self.repository.load_config(&agent.identity_id)?;
                organizations.insert(config.organization_credential_id);
                organizations.extend(config.retired_organization_credential_ids);
            }
        }
        self.schedule_cleanup(CleanupOperation::Purge {
            identity_ids: identities,
            organization_credential_ids: organizations.into_iter().collect(),
        })?;
        self.recover_pending_operations_locked()?;
        Ok(())
    }

    pub async fn connect(
        &self,
        profile_name: Option<&str>,
        organization_api_key: OrganizationApiKey,
        host: ApiHost,
        display_name: Option<&str>,
        agent_type: Option<&str>,
        hostname: &str,
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
        let mut registry = self.repository.load_registry()?;
        if let Some(agent_type) = agent_type {
            let name = ProfileName::parse(&agent.name)?;
            registry = set_profile_type(&registry, &name, Some(agent_type))?;
            self.repository.save_registry(&registry)?;
        }
        let existing_config = self
            .repository
            .config_exists(&agent.identity_id)
            .then(|| self.repository.load_config(&agent.identity_id))
            .transpose()?;
        let (encryption, signing) = self.load_identity(&agent.identity_id)?;
        let (organization_credential_id, created_organization) =
            self.find_or_create_organization_credential(&registry, &organization_api_key)?;
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
                    &registry,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Err(error.into());
            }
        };
        let registration = match client
            .register_agent(
                display_name.or_else(|| (agent.name != "default").then_some(agent.name.as_str())),
                agent_type.or(agent.agent_type.as_deref()),
                Some(&signing_public_key_bytes),
            )
            .await
        {
            Ok(registration) => registration,
            Err(error) => {
                self.cleanup_unused_new_organization(
                    &registry,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Err(error.into());
            }
        };

        let agent_id = match &registration {
            AgentRegistrationResult::Pending { agent_id }
            | AgentRegistrationResult::Active { agent_id, .. }
            | AgentRegistrationResult::Deactivated { agent_id } => Some(agent_id.clone()),
            AgentRegistrationResult::InvalidKey => {
                self.cleanup_unused_new_organization(
                    &registry,
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
            let config = PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
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
                encryption_public_key: Some(encryption_public_key),
                signing_public_key: Some(signing_public_key),
            };
            if let Err(error) = self.repository.save_config(&agent.identity_id, &config) {
                self.cleanup_unused_new_organization(
                    &registry,
                    &organization_credential_id,
                    created_organization,
                )?;
                return Err(error.into());
            }
            self.recover_pending_operations_locked()?;
            let mut config = config;
            self.cleanup_retired_organizations(&agent.identity_id, &mut config, &registry)?;
        } else {
            self.cleanup_unused_new_organization(
                &registry,
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
    ) -> Result<StatusOutcome, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let agent = self.resolve_profile_locked(profile_name)?;
        let mut config = self.repository.load_config(&agent.identity_id)?;
        let registry = self.repository.load_registry()?;
        self.cleanup_retired_organizations(&agent.identity_id, &mut config, &registry)?;
        let (encryption, signing) = self.load_identity(&agent.identity_id)?;
        let signing_public_key = *signing.public_key();
        let organization_api_key =
            self.load_organization_api_key(&config.organization_credential_id)?;
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
        let registration = client
            .register_agent(None, agent.agent_type.as_deref(), Some(&signing_public_key))
            .await?;
        if let AgentRegistrationResult::Pending { agent_id }
        | AgentRegistrationResult::Active { agent_id, .. }
        | AgentRegistrationResult::Deactivated { agent_id } = &registration
        {
            config.agent_id = Some(agent_id.clone());
            config.encryption_public_key = Some(STANDARD.encode(encryption.public_key()));
            config.signing_public_key = Some(STANDARD.encode(signing_public_key));
            self.repository.save_config(&agent.identity_id, &config)?;
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
    ) -> Result<RuntimeSession, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let profile = self.resolve_profile_locked(profile_name)?;
        let mut config = self.repository.load_config(&profile.identity_id)?;
        let registry = self.repository.load_registry()?;
        self.cleanup_retired_organizations(&profile.identity_id, &mut config, &registry)?;
        let (encryption, signing) = self.load_identity(&profile.identity_id)?;
        let organization_api_key =
            self.load_organization_api_key(&config.organization_credential_id)?;
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
        Ok(RuntimeSession {
            profile,
            config,
            api,
            encryption,
        })
    }

    pub fn verify_identity(
        &self,
        profile_name: Option<&str>,
    ) -> Result<PublicAgentEntry, RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()?;
        let profile = self.resolve_profile_locked(profile_name)?;
        let _identity = self.load_identity(&profile.identity_id)?;
        Ok(profile)
    }

    fn load_identity(
        &self,
        identity_id: &str,
    ) -> Result<(X25519Identity, Ed25519Identity), RuntimeError> {
        let encryption = self
            .secrets
            .get(identity_id, SecretSlot::X25519PrivateKey)?
            .ok_or(RuntimeError::MissingIdentity)?;
        let signing = self
            .secrets
            .get(identity_id, SecretSlot::Ed25519SecretKey)?
            .ok_or(RuntimeError::MissingIdentity)?;
        Ok((
            X25519Identity::from_private_bytes(encryption.expose_secret().to_vec())?,
            Ed25519Identity::from_libsodium_secret(signing.expose_secret().to_vec())?,
        ))
    }

    fn load_organization_api_key(
        &self,
        organization_id: &str,
    ) -> Result<OrganizationApiKey, RuntimeError> {
        let secret = self
            .secrets
            .get(organization_id, SecretSlot::OrganizationApiKey)?
            .ok_or(RuntimeError::MissingOrganizationCredential)?;
        let bytes = Zeroizing::new(secret.expose_secret().to_vec());
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| RuntimeError::InvalidStoredSecret)?
            .to_owned();
        Ok(OrganizationApiKey::new(value))
    }

    fn find_or_create_organization_credential(
        &self,
        registry: &PublicRegistry,
        candidate: &OrganizationApiKey,
    ) -> Result<(String, bool), RuntimeError> {
        let candidate = candidate.expose_for_authorized_request().as_bytes();
        let mut visited = BTreeSet::new();
        for agent in &registry.agents {
            if !self.repository.config_exists(&agent.identity_id) {
                continue;
            }
            let config = self.repository.load_config(&agent.identity_id)?;
            let mut organization_ids = config.retired_organization_credential_ids;
            organization_ids.push(config.organization_credential_id);
            for organization_id in organization_ids {
                if !visited.insert(organization_id.clone()) {
                    continue;
                }
                if let Some(stored) = self
                    .secrets
                    .get(&organization_id, SecretSlot::OrganizationApiKey)?
                    && bool::from(stored.expose_secret().ct_eq(candidate))
                {
                    return Ok((organization_id, false));
                }
            }
        }

        let organization_id = generate_opaque_id()?;
        self.schedule_cleanup(CleanupOperation::CreateOrganizationCredential {
            organization_credential_id: organization_id.clone(),
        })?;
        if let Err(error) =
            self.secrets
                .set(&organization_id, SecretSlot::OrganizationApiKey, candidate)
        {
            self.recover_or_cleanup_failed_locked()?;
            return Err(error.into());
        }
        Ok((organization_id, true))
    }

    fn organization_is_referenced(
        &self,
        registry: &PublicRegistry,
        organization_id: &str,
    ) -> Result<bool, RuntimeError> {
        for agent in &registry.agents {
            if self.repository.config_exists(&agent.identity_id)
                && self
                    .repository
                    .load_config(&agent.identity_id)?
                    .organization_credential_id
                    == organization_id
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn cleanup_unused_new_organization(
        &self,
        registry: &PublicRegistry,
        organization_id: &str,
        created: bool,
    ) -> Result<(), RuntimeError> {
        if created && !self.organization_is_referenced(registry, organization_id)? {
            self.recover_pending_operations_locked()?;
        }
        Ok(())
    }

    fn cleanup_retired_organizations(
        &self,
        identity_id: &str,
        config: &mut PublicProfileConfig,
        registry: &PublicRegistry,
    ) -> Result<(), RuntimeError> {
        if config.retired_organization_credential_ids.is_empty() {
            return Ok(());
        }
        for retired in &config.retired_organization_credential_ids {
            if !self.organization_is_referenced(registry, retired)? {
                delete_organization_credential(&self.secrets, retired)?;
            }
        }
        config.retired_organization_credential_ids.clear();
        self.repository.save_config(identity_id, config)?;
        Ok(())
    }

    pub fn recover_pending_operations(&self) -> Result<(), RuntimeError> {
        let _lock = self.repository.acquire_transaction_lock()?;
        self.recover_pending_operations_locked()
    }

    fn recover_pending_operations_locked(&self) -> Result<(), RuntimeError> {
        let mut journal = self.repository.load_cleanup_journal()?;
        while let Some(operation) = journal.operations.first().cloned() {
            let public_root_removed = match &operation {
                CleanupOperation::CreateIdentity { identity_id } => {
                    let registry = self.repository.load_registry()?;
                    if !registry
                        .agents
                        .iter()
                        .any(|agent| agent.identity_id == *identity_id)
                    {
                        delete_identity(&self.secrets, identity_id)?;
                    }
                    false
                }
                CleanupOperation::CreateOrganizationCredential {
                    organization_credential_id,
                } => {
                    let registry = self.repository.load_registry()?;
                    if !self.organization_is_referenced(&registry, organization_credential_id)? {
                        delete_organization_credential(&self.secrets, organization_credential_id)?;
                    }
                    false
                }
                CleanupOperation::DeleteProfile {
                    identity_id,
                    organization_credential_ids,
                } => {
                    let registry = self.repository.load_registry()?;
                    if !registry
                        .agents
                        .iter()
                        .any(|agent| agent.identity_id == *identity_id)
                    {
                        delete_identity(&self.secrets, identity_id)?;
                        for organization_id in organization_credential_ids {
                            if !self.organization_is_referenced(&registry, organization_id)? {
                                delete_organization_credential(&self.secrets, organization_id)?;
                            }
                        }
                        self.repository.remove_identity_directory(identity_id)?;
                    }
                    false
                }
                CleanupOperation::Purge {
                    identity_ids,
                    organization_credential_ids,
                } => {
                    for identity_id in identity_ids {
                        delete_identity(&self.secrets, identity_id)?;
                    }
                    for organization_id in organization_credential_ids {
                        delete_organization_credential(&self.secrets, organization_id)?;
                    }
                    self.repository.purge_public_data()?;
                    true
                }
            };

            if public_root_removed {
                return Ok(());
            }
            journal.operations.remove(0);
            self.persist_cleanup_journal(&journal)?;
        }
        Ok(())
    }

    fn schedule_cleanup(&self, operation: CleanupOperation) -> Result<(), RuntimeError> {
        let mut journal = self.repository.load_cleanup_journal()?;
        if !journal.operations.contains(&operation) {
            journal.operations.push(operation);
            self.repository.save_cleanup_journal(&journal)?;
        }
        Ok(())
    }

    fn persist_cleanup_journal(&self, journal: &CleanupJournal) -> Result<(), RuntimeError> {
        if journal.operations.is_empty() {
            self.repository.remove_cleanup_journal()?;
        } else {
            self.repository.save_cleanup_journal(journal)?;
        }
        Ok(())
    }

    fn recover_or_cleanup_failed_locked(&self) -> Result<(), RuntimeError> {
        self.recover_pending_operations_locked()
            .map_err(|_| RuntimeError::CleanupFailed)
    }
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

pub struct RuntimeSession {
    pub profile: PublicAgentEntry,
    pub config: PublicProfileConfig,
    pub api: ApiClient,
    encryption: X25519Identity,
}

impl RuntimeSession {
    pub fn decrypt(
        &self,
        envelope: &EncryptedCredential,
    ) -> Result<DecryptedCredential, RuntimeError> {
        decrypt_credential(envelope, &self.encryption).map_err(RuntimeError::Crypto)
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("profile operation failed: {0}")]
    Profile(#[from] ProfileError),
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
    #[error("legacy Agent data requires the explicit pre-production migration before purge")]
    LegacyMigrationRequired,
    #[error("secure rollback failed; run palladin doctor before retrying")]
    CleanupFailed,
    #[error("secure random identifier generation failed")]
    RandomGenerationFailed,
    #[error("system clock formatting failed")]
    Clock,
}

fn generate_opaque_id() -> Result<String, RuntimeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeError::RandomGenerationFailed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(value)
}

fn now_rfc3339() -> Result<String, RuntimeError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| RuntimeError::Clock)
}
