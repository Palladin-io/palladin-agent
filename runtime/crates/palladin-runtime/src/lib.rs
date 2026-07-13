#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_api::{
    AgentRegistrationResult, ApiClient, ApiError, CredentialAccess, CredentialMethod,
    EntrySearchResult, GetCredentialOptions, ReportCredentialStaleInput,
};
use palladin_core::host::ApiHost;
use palladin_core::profiles::{
    CleanupJournal, CleanupOperation, ProfileError, ProfileName, ProfileRepository, add_profile,
    delete_profile, rename_profile, set_default, set_profile_type,
};
use palladin_core::public_store::{
    PUBLIC_SCHEMA_VERSION, PublicAgentEntry, PublicProfileConfig, PublicRegistry,
};
use palladin_core::secret::OrganizationApiKey;
use palladin_credential::wait::{
    HeartbeatInfo, WaitError, WaitHints, WaitOptions, await_grant, resolve_wait_policy,
};
use palladin_crypto::{DecryptedCredential, Ed25519Identity, X25519Identity, decrypt_credential};
use palladin_exec::{
    EnvironmentError, SecretEnvironment, resolve_interpreter, run_command, run_script,
    validate_command, validate_reference_name,
};
use palladin_platform::secure_store::{
    SecretSlot, SecretStore, StoreError, delete_identity, delete_organization_credential,
};
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use palladin_credential::fields::{FieldSelector, resolve_field};
use palladin_credential::secret::{ScriptPayload, parse_secret};

pub use palladin_exec::{ExecError, ExecResult, OperatorOutput};

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
    profile: PublicAgentEntry,
    config: PublicProfileConfig,
    api: ApiClient,
    encryption: X25519Identity,
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

    pub async fn search_entries(
        &self,
        query: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<EntrySearchResult, RuntimeError> {
        self.api
            .search_entries(query, cursor, page_size)
            .await
            .map_err(RuntimeError::Api)
    }

    pub async fn report_credential_stale(
        &self,
        input: &ReportCredentialStaleInput,
    ) -> Result<(), RuntimeError> {
        self.api
            .report_credential_stale(input)
            .await
            .map_err(RuntimeError::Api)
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
        self.deliver_credential(request, CredentialMethod::Get, cancellation, heartbeat)
            .await
    }

    pub async fn deliver_for_exec<H>(
        &self,
        request: CredentialDeliveryRequest<'_>,
        cancellation: &CancellationToken,
        heartbeat: H,
    ) -> Result<CredentialDelivery, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.deliver_credential(request, CredentialMethod::Exec, cancellation, heartbeat)
            .await
    }

    pub async fn deliver_for_inject<H>(
        &self,
        request: CredentialDeliveryRequest<'_>,
        cancellation: &CancellationToken,
        heartbeat: H,
    ) -> Result<CredentialDelivery, RuntimeError>
    where
        H: FnMut(HeartbeatInfo),
    {
        self.deliver_credential(request, CredentialMethod::Inject, cancellation, heartbeat)
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
        if let Some(command) = request.command.filter(|command| !command.is_empty()) {
            validate_command(command)?;
        }
        let delivery = self
            .deliver_for_exec(request.delivery, cancellation, &mut heartbeat)
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
                .deliver_for_exec(
                    CredentialDeliveryRequest {
                        vault_id,
                        entry_id: &reference.entry_id,
                        reason: main.reason,
                        wait: main.wait,
                    },
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
            () = cancellation.cancelled() => return Err(RuntimeError::WaitCancelled),
            result = self.api.get_credential(request.vault_id, request.entry_id, &options) => result?,
        };
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
        let policy = resolve_wait_policy(request.wait, hints);
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
        let credential = decrypt_credential(&envelope, &self.encryption)?;
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
    #[error("credential wait was cancelled")]
    WaitCancelled,
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

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use std::io::Read;
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

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
            },
            config: PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                host,
                organization_credential_id: "22222222222222222222222222222222".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: None,
                encryption_public_key: None,
                signing_public_key: None,
            },
            api,
            encryption,
        };

        let get = session
            .deliver_for_get(request(), &CancellationToken::new(), |_| {})
            .await;
        let exec = session
            .deliver_for_exec(request(), &CancellationToken::new(), |_| {})
            .await;
        let inject = session
            .deliver_for_inject(request(), &CancellationToken::new(), |_| {})
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
                .deliver_for_get(request(), &CancellationToken::new(), |_| {})
                .await
                .expect("non-granted state is a valid delivery result");
            assert!(matches!(delivery, CredentialDelivery::NotGranted(_)));
        }

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 11);
        for (request, method) in requests.iter().take(3).zip(["Get", "Exec", "Inject"]) {
            assert!(request.contains("x-api-key: pl_shared_organization_fixture\r\n"));
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
        assert!(requests[0].contains("x-api-key: pl_shared_organization_fixture\r\n"));
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
        assert_eq!(
            std::env::var("CLAW_SECRET").as_deref(),
            Ok("fixture-password-not-production")
        );
        assert_eq!(
            std::env::var("CLAW_USERNAME").as_deref(),
            Ok("fixture-user")
        );
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
            },
            config: PublicProfileConfig {
                schema_version: PUBLIC_SCHEMA_VERSION,
                host,
                organization_credential_id: "22222222222222222222222222222222".to_owned(),
                retired_organization_credential_ids: Vec::new(),
                agent_id: None,
                encryption_public_key: None,
                signing_public_key: None,
            },
            api,
            encryption,
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
