//! Agent Entry Submissions: approver pinning, submission build/POST, status with re-wrap, and the
//! fresh pre-approval Inject delivery of the Agent's own submission.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use palladin_api::{AgentSubmissionSummary, AgentVisibleField, ApiError, SubmissionRejection};
use palladin_core::public_store::PublicApproverTrustAnchor;
use palladin_core::terminal::shorten_identifier;
use palladin_credential::generator::{PasswordPolicy, PasswordPolicyError, generate_password};
use palladin_crypto::{
    AgentEntrySubmission, OrganizationApproverManifest, PinnedApproverTrust, SubmissionAuthority,
    SubmissionBuildContext, SubmissionContent, SubmissionEntryType, SubmissionError,
    SubmissionIdentity, SubmissionKind, SubmissionRecipient, SubmissionTarget,
    build_agent_submission, open_agent_submission, rewrap_agent_submission,
    verify_approver_manifest_chain,
};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::{DeliveredCredential, RuntimeError, RuntimeOperation, RuntimeSession};

const LABEL_MAX_BYTES: usize = 256;

/// The contract's value-free `notSavedCodes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionNotSaved {
    NoApprovers,
    ApproverKeyUnavailable,
    ApproverKeyUntrusted,
    UpdateNotGranted,
    InvalidInput,
    UnsupportedEntryType,
    PasswordPolicyUnsatisfiable,
    SubmissionConflict,
    ServiceUnavailable,
}

impl SubmissionNotSaved {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoApprovers => "no-approvers",
            Self::ApproverKeyUnavailable => "approver-key-unavailable",
            Self::ApproverKeyUntrusted => "approver-key-untrusted",
            Self::UpdateNotGranted => "update-not-granted",
            Self::InvalidInput => "invalid-input",
            Self::UnsupportedEntryType => "unsupported-entry-type",
            Self::PasswordPolicyUnsatisfiable => "password-policy-unsatisfiable",
            Self::SubmissionConflict => "submission-conflict",
            Self::ServiceUnavailable => "service-unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionRequestTarget<'a> {
    New {
        suggested_vault_id: Option<&'a str>,
    },
    /// The revision and entry type come from the side-effect-free submission target.
    Update {
        vault_id: &'a str,
        entry_id: &'a str,
    },
}

/// Non-secret fields of a submission request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmissionRequest<'a> {
    pub target: SubmissionRequestTarget<'a>,
    pub entry_type: Option<SubmissionEntryType>,
    pub label: Option<&'a str>,
    pub url: Option<&'a str>,
    pub username: Option<&'a str>,
}

impl SubmissionRequest<'_> {
    /// Value-free digest bound into the operating-system authorization for this operation.
    #[must_use]
    pub fn digest(&self, generated: bool) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut field = |value: Option<&str>| match value {
            Some(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value.as_bytes());
            }
            None => hasher.update([0]),
        };
        match self.target {
            SubmissionRequestTarget::New { suggested_vault_id } => {
                field(Some("new"));
                field(suggested_vault_id);
            }
            SubmissionRequestTarget::Update { vault_id, entry_id } => {
                field(Some("update"));
                field(Some(vault_id));
                field(Some(entry_id));
            }
        }
        field(self.entry_type.map(SubmissionEntryType::name));
        field(self.label);
        field(self.url);
        field(self.username);
        field(Some(if generated { "generate" } else { "provided" }));
        hasher.finalize().into()
    }
}

/// Where the secret comes from. A provided secret was read from protected human input.
pub enum SubmissionSecret {
    Generate(PasswordPolicy),
    Provided(SecretString),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionResult {
    pub kind: SubmissionKind,
    pub outcome: Result<SubmissionSaved, SubmissionNotSaved>,
    /// Present whenever an ID was chosen, including an unconfirmed attempt the operator can check.
    pub submission_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionSaved {
    pub state: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RewrapOutcome {
    NotRequired,
    Rewrapped { submission_revision: u64 },
    Failed(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionStatusItem {
    pub summary: AgentSubmissionSummary,
    pub rewrap: RewrapOutcome,
}

struct TrustedApprover {
    pin: PinnedApproverTrust,
    agent_key_version: u32,
    agent_access_epoch: u64,
}

enum Failure {
    NotSaved(SubmissionNotSaved),
    Runtime(RuntimeError),
}

impl From<RuntimeError> for Failure {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl RuntimeSession<'_> {
    /// Builds and saves one submission. Approver-key trust is established before any secret is
    /// generated or encrypted; nothing secret is persisted or returned.
    pub async fn submit_entry(
        &self,
        request: SubmissionRequest<'_>,
        secret: SubmissionSecret,
    ) -> Result<SubmissionResult, RuntimeError> {
        self.begin_operation(RuntimeOperation::SubmitEntry)?;
        let kind = match request.target {
            SubmissionRequestTarget::New { .. } => SubmissionKind::New,
            SubmissionRequestTarget::Update { .. } => SubmissionKind::Update,
        };
        let not_saved = |code, submission_id: Option<&Uuid>| SubmissionResult {
            kind,
            outcome: Err(code),
            submission_id: submission_id.map(Uuid::to_string),
        };
        if let SubmissionSecret::Generate(policy) = &secret
            && policy.validate().is_err()
        {
            return Ok(not_saved(
                SubmissionNotSaved::PasswordPolicyUnsatisfiable,
                None,
            ));
        }
        if let Err(code) = validate_request(&request) {
            return Ok(not_saved(code, None));
        }
        let submission_id = random_uuid()?;
        let approver = match self.trusted_approver().await {
            Ok(approver) => approver,
            Err(Failure::NotSaved(code)) => return Ok(not_saved(code, None)),
            Err(Failure::Runtime(error)) => return Err(error),
        };
        self.ensure_authorized()?;
        let (target, entry_type) = match request.target {
            SubmissionRequestTarget::New { suggested_vault_id } => (
                SubmissionTarget::New {
                    suggested_vault_id: suggested_vault_id.map(parse_uuid).transpose()?,
                },
                request
                    .entry_type
                    .ok_or(RuntimeError::Submission(SubmissionError::InvalidInput))?,
            ),
            SubmissionRequestTarget::Update { vault_id, entry_id } => {
                match self.update_target(vault_id, entry_id).await? {
                    Ok(target) => target,
                    Err(code) => return Ok(not_saved(code, None)),
                }
            }
        };
        let secret = match secret {
            SubmissionSecret::Generate(policy) => match generate_password(&policy) {
                Ok(secret) => secret,
                Err(PasswordPolicyError::Unsatisfiable) => {
                    return Ok(not_saved(
                        SubmissionNotSaved::PasswordPolicyUnsatisfiable,
                        None,
                    ));
                }
                Err(PasswordPolicyError::RandomGenerationFailed) => {
                    return Err(RuntimeError::RandomGenerationFailed);
                }
            },
            SubmissionSecret::Provided(secret) => secret,
        };
        let label = request.label.map(normalize_label);
        let username = request
            .username
            .map(|value| SecretString::from(value.to_owned()));
        let url = request.url.map(str::to_owned);
        let content = match entry_type {
            SubmissionEntryType::Credential => SubmissionContent::Credential {
                username,
                password: secret,
                url,
                notes: None,
            },
            SubmissionEntryType::Key if username.is_none() => SubmissionContent::Key {
                value: secret,
                url,
                notes: None,
            },
            SubmissionEntryType::Key => {
                return Ok(not_saved(SubmissionNotSaved::InvalidInput, None));
            }
        };
        let identity = SubmissionIdentity {
            organization_id: approver.pin.organization_id,
            submission_id,
            agent_id: self.agent_uuid()?,
            entry_type,
            target,
        };
        let mut approver = approver;
        let mut rotated = false;
        loop {
            let submission = match self.build(&identity, &approver, label.as_deref(), &content) {
                Ok(submission) => submission,
                Err(RuntimeError::Submission(SubmissionError::InvalidInput)) => {
                    return Ok(not_saved(SubmissionNotSaved::InvalidInput, None));
                }
                Err(error) => return Err(error),
            };
            self.ensure_authorized()?;
            let result = self.api.create_submission(&submission.to_value()).await;
            self.ensure_authorized()?;
            let outcome = match result {
                Ok(accepted) if accepted.submission_id == submission_id.to_string() => {
                    Ok(SubmissionSaved {
                        state: accepted.state,
                    })
                }
                Ok(_) => Err(RuntimeError::Api(ApiError::InvalidResponse)),
                Err(ApiError::SubmissionRejected(SubmissionRejection::ApproverKeyRotated))
                    if !rotated =>
                {
                    rotated = true;
                    approver = match self.trusted_approver().await {
                        Ok(next) if next.pin.key_version > approver.pin.key_version => next,
                        Ok(_) => {
                            return Ok(not_saved(SubmissionNotSaved::ApproverKeyUnavailable, None));
                        }
                        Err(Failure::NotSaved(code)) => return Ok(not_saved(code, None)),
                        Err(Failure::Runtime(error)) => return Err(error),
                    };
                    continue;
                }
                Err(ApiError::SubmissionRejected(rejection)) => {
                    return Ok(not_saved(rejection_code(rejection), None));
                }
                Err(ApiError::Http(400)) => {
                    return Ok(not_saved(SubmissionNotSaved::InvalidInput, None));
                }
                Err(_) => self.reconcile(&submission_id).await,
            };
            return Ok(match outcome {
                Ok(saved) => SubmissionResult {
                    kind,
                    outcome: Ok(saved),
                    submission_id: Some(submission_id.to_string()),
                },
                Err(_) => not_saved(SubmissionNotSaved::ServiceUnavailable, Some(&submission_id)),
            });
        }
    }

    /// Lists the Agent's own submissions and re-wraps pending ones whose approver key rotated.
    pub async fn submission_status(
        &self,
        submission_id: Option<&str>,
    ) -> Result<Vec<SubmissionStatusItem>, RuntimeError> {
        self.begin_operation(RuntimeOperation::SubmissionStatus)?;
        let list = self.api.list_submissions().await?;
        self.ensure_authorized()?;
        let mut approver: Option<Result<TrustedApprover, &'static str>> = None;
        let mut items = Vec::new();
        for summary in list.items {
            if submission_id.is_some_and(|id| id != summary.submission_id) {
                continue;
            }
            let rewrap_required = summary.state == "pending"
                && !summary.agent_use_suspended
                && summary
                    .current_approver_key_version
                    .is_some_and(|current| current > summary.approver_key_version);
            let rewrap = if rewrap_required {
                if approver.is_none() {
                    approver = Some(self.trusted_approver().await.map_err(
                        |failure| match failure {
                            Failure::NotSaved(code) => code.code(),
                            Failure::Runtime(_) => "approver-key-untrusted",
                        },
                    ));
                }
                match approver.as_ref() {
                    Some(Ok(approver)) => self.rewrap(&summary, approver).await,
                    Some(Err(code)) => RewrapOutcome::Failed(code),
                    None => RewrapOutcome::Failed("approver-key-unavailable"),
                }
            } else {
                RewrapOutcome::NotRequired
            };
            items.push(SubmissionStatusItem { summary, rewrap });
        }
        self.ensure_authorized()?;
        Ok(items)
    }

    /// Fetches the Agent's own submission fresh, verifies its signature and bindings, and opens it
    /// for the trusted Inject provider only. There is no local cache.
    pub async fn deliver_submission_for_inject(
        &self,
        submission_id: &str,
    ) -> Result<DeliveredCredential, RuntimeError> {
        self.begin_operation(RuntimeOperation::InjectCredential)?;
        let requested = parse_uuid(submission_id)?;
        let pin = self
            .config
            .approver_trust_anchor
            .as_ref()
            .ok_or(RuntimeError::UntrustedApproverManifest)
            .and_then(pinned_approver)?;
        let value = match self.api.get_submission(submission_id).await {
            Ok(value) => value,
            Err(ApiError::SubmissionRejected(SubmissionRejection::SubmissionNotUsable)) => {
                return Err(RuntimeError::SubmissionNotUsable);
            }
            Err(error) => return Err(RuntimeError::Api(error)),
        };
        self.ensure_authorized()?;
        let submission = AgentEntrySubmission::from_value(&value)?;
        if submission.identity.submission_id != requested {
            return Err(RuntimeError::Submission(SubmissionError::ContextMismatch));
        }
        let signing_public_key = self.agent_signing_public_key()?;
        // Our own signature covers the declared key version; the fingerprint is recomputed from
        // the locally held X25519 key, so a substituted recipient cannot open.
        let opened = open_agent_submission(
            &submission,
            &SubmissionAuthority {
                organization_id: pin.organization_id,
                agent_id: self.agent_uuid()?,
                agent_signing_public_key: &signing_public_key,
                recipient: SubmissionRecipient::Agent {
                    key_version: submission.agent_key_version,
                    identity: &self.encryption,
                },
            },
        )?;
        let authenticated_domain = opened
            .content
            .url()
            .and_then(|value| url::Url::parse(value).ok())
            .filter(|url| url.scheme() == "https")
            .and_then(|url| url.host_str().map(str::to_owned));
        let authenticated_fields = opened
            .content
            .username()
            .map(|username| AgentVisibleField {
                label: "credential.username".to_owned(),
                value: username.to_owned(),
            })
            .into_iter()
            .collect();
        let (entry_id, entry_revision) = match &submission.identity.target {
            SubmissionTarget::Update {
                entry_id,
                expected_entry_revision,
                ..
            } => (entry_id.to_string(), *expected_entry_revision),
            SubmissionTarget::New { .. } => (submission_id.to_owned(), 0),
        };
        let credential = opened.into_inject_credential()?;
        self.ensure_authorized()?;
        Ok(DeliveredCredential {
            grant_id: submission_id.to_owned(),
            label: shorten_identifier(&entry_id),
            entry_id,
            entry_revision,
            inject_discovery_binding: None,
            authenticated_domain,
            authenticated_fields,
            credential,
        })
    }

    async fn trusted_approver(&self) -> Result<TrustedApprover, Failure> {
        let stored = self.current_approver_anchor();
        let pinned = stored.as_ref().map(pinned_approver).transpose()?;
        let response = match self
            .api
            .list_approver_manifests(pinned.as_ref().map(|pin| pin.manifest_revision))
            .await
        {
            Ok(response) => response,
            Err(ApiError::SubmissionRejected(SubmissionRejection::NoApprovers)) => {
                return Err(Failure::NotSaved(SubmissionNotSaved::NoApprovers));
            }
            Err(_) => return Err(Failure::NotSaved(SubmissionNotSaved::ServiceUnavailable)),
        };
        self.ensure_authorized()?;
        let untrusted = Failure::NotSaved(SubmissionNotSaved::ApproverKeyUntrusted);
        let organization_id = Uuid::parse_str(&response.organization_id)
            .ok()
            .filter(|parsed| parsed.to_string() == response.organization_id)
            .ok_or(Failure::Runtime(RuntimeError::Api(
                ApiError::InvalidResponse,
            )))?;
        // Paired Vault anchors are an independent record of this Agent's organization.
        if self
            .config
            .vault_trust_anchors
            .iter()
            .any(|anchor| anchor.organization_id != response.organization_id)
        {
            return Err(untrusted);
        }
        let agent_access_epoch = response
            .agent_access_epoch
            .parse::<u64>()
            .ok()
            .filter(|epoch| *epoch > 0 && epoch.to_string() == response.agent_access_epoch)
            .ok_or(Failure::Runtime(RuntimeError::Api(
                ApiError::InvalidResponse,
            )))?;
        let manifests = response
            .manifests
            .iter()
            .map(OrganizationApproverManifest::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Failure::NotSaved(SubmissionNotSaved::ApproverKeyUntrusted))?;
        let pin = verify_approver_manifest_chain(&manifests, organization_id, pinned.as_ref())
            .map_err(|_| Failure::NotSaved(SubmissionNotSaved::ApproverKeyUntrusted))?
            .ok_or(Failure::NotSaved(
                SubmissionNotSaved::ApproverKeyUnavailable,
            ))?;
        if pinned.as_ref() != Some(&pin) {
            self.persist_approver_pin(stored.as_ref(), &pin)?;
        }
        Ok(TrustedApprover {
            pin,
            agent_key_version: response.agent_key_version,
            agent_access_epoch,
        })
    }

    fn current_approver_anchor(&self) -> Option<PublicApproverTrustAnchor> {
        self.approver_anchor
            .lock()
            .ok()
            .and_then(|current| current.clone())
            .or_else(|| self.config.approver_trust_anchor.clone())
    }

    fn persist_approver_pin(
        &self,
        expected: Option<&PublicApproverTrustAnchor>,
        pin: &PinnedApproverTrust,
    ) -> Result<(), RuntimeError> {
        let persistence = self
            .manifest_persistence
            .ok_or(RuntimeError::IntegrityViolation)?;
        let signing = self
            .profile_signing
            .as_ref()
            .ok_or(RuntimeError::IntegrityViolation)?;
        let next = PublicApproverTrustAnchor {
            organization_id: pin.organization_id.to_string(),
            key_version: pin.key_version,
            manifest_revision: pin.manifest_revision.to_string(),
            signing_public_key: URL_SAFE_NO_PAD.encode(pin.signing_public_key),
            message_public_key: URL_SAFE_NO_PAD.encode(pin.message_public_key),
        };
        self.ensure_authorized()?;
        persistence.persist_approver_anchor(
            &self.profile.identity_id,
            expected,
            &next,
            signing,
            &self.lease,
        )?;
        if let Ok(mut current) = self.approver_anchor.lock() {
            *current = Some(next);
        }
        self.ensure_authorized()
    }

    /// Reads the granted Entry's current revision and type from the side-effect-free
    /// submission-target endpoint; never from a credential delivery.
    async fn update_target(
        &self,
        vault_id: &str,
        entry_id: &str,
    ) -> Result<Result<(SubmissionTarget, SubmissionEntryType), SubmissionNotSaved>, RuntimeError>
    {
        let target = match self.api.get_submission_target(vault_id, entry_id).await {
            Ok(target) => target,
            Err(ApiError::SubmissionRejected(SubmissionRejection::UpdateNotGranted)) => {
                return Ok(Err(SubmissionNotSaved::UpdateNotGranted));
            }
            Err(_) => return Ok(Err(SubmissionNotSaved::ServiceUnavailable)),
        };
        self.ensure_authorized()?;
        // Bind the answer to the Entry the operator named, not to the response itself.
        if target.vault_id != vault_id || target.entry_id != entry_id {
            return Err(RuntimeError::Api(ApiError::InvalidResponse));
        }
        let entry_type = match target.entry_type {
            0 => SubmissionEntryType::Key,
            1 => SubmissionEntryType::Credential,
            _ => return Ok(Err(SubmissionNotSaved::UnsupportedEntryType)),
        };
        let expected_entry_revision = target
            .entry_revision
            .parse::<u64>()
            .ok()
            .filter(|revision| revision.to_string() == target.entry_revision)
            .ok_or(RuntimeError::Api(ApiError::InvalidResponse))?;
        Ok(Ok((
            SubmissionTarget::Update {
                vault_id: parse_uuid(vault_id)?,
                entry_id: parse_uuid(entry_id)?,
                expected_entry_revision,
            },
            entry_type,
        )))
    }

    async fn rewrap(
        &self,
        summary: &AgentSubmissionSummary,
        approver: &TrustedApprover,
    ) -> RewrapOutcome {
        if summary.current_approver_key_version != Some(approver.pin.key_version) {
            return RewrapOutcome::Failed("approver-key-unavailable");
        }
        let result = async {
            let signing = self
                .profile_signing
                .as_ref()
                .ok_or(RuntimeError::IntegrityViolation)?;
            let value = self.api.get_submission(&summary.submission_id).await?;
            let stored = AgentEntrySubmission::from_value(&value)?;
            if stored.identity.submission_id.to_string() != summary.submission_id {
                return Err(RuntimeError::Submission(SubmissionError::ContextMismatch));
            }
            let candidate = rewrap_agent_submission(
                &stored,
                self.agent_uuid()?,
                &self.encryption,
                signing,
                &approver.pin,
            )?;
            self.ensure_authorized()?;
            self.api
                .rewrap_submission(&summary.submission_id, &candidate.to_value())
                .await?;
            Ok(candidate.submission_revision)
        }
        .await;
        match result {
            Ok(submission_revision) => RewrapOutcome::Rewrapped {
                submission_revision,
            },
            Err(RuntimeError::Api(ApiError::SubmissionRejected(rejection))) => {
                RewrapOutcome::Failed(match rejection {
                    SubmissionRejection::RevisionReplay => "revision-replay",
                    SubmissionRejection::RewrapChangedPayload => "rewrap-changed-payload",
                    SubmissionRejection::ApproverKeyRotated => "approver-key-rotated",
                    SubmissionRejection::AgentKeyMismatch => "agent-key-mismatch",
                    SubmissionRejection::SubmissionNotPending => "submission-not-pending",
                    _ => "service-unavailable",
                })
            }
            Err(RuntimeError::Submission(error)) => RewrapOutcome::Failed(error.code()),
            Err(_) => RewrapOutcome::Failed("service-unavailable"),
        }
    }

    fn build(
        &self,
        identity: &SubmissionIdentity,
        approver: &TrustedApprover,
        label: Option<&str>,
        content: &SubmissionContent,
    ) -> Result<AgentEntrySubmission, RuntimeError> {
        let signing = self
            .profile_signing
            .as_ref()
            .ok_or(RuntimeError::IntegrityViolation)?;
        Ok(build_agent_submission(
            &SubmissionBuildContext {
                identity: identity.clone(),
                agent_access_epoch: approver.agent_access_epoch,
                agent_key_version: approver.agent_key_version,
                agent_encryption_public_key: self.encryption.public_key(),
                agent_signing: signing,
                approver: &approver.pin,
            },
            label,
            content,
        )?)
    }

    /// Resolves an ambiguous POST by looking for the Agent-chosen ID; never resends the secret.
    async fn reconcile(&self, submission_id: &Uuid) -> Result<SubmissionSaved, RuntimeError> {
        let list = self.api.list_submissions().await?;
        self.ensure_authorized()?;
        list.items
            .into_iter()
            .find(|item| item.submission_id == submission_id.to_string())
            .map(|item| SubmissionSaved { state: item.state })
            .ok_or(RuntimeError::Api(ApiError::Transport))
    }

    fn agent_uuid(&self) -> Result<Uuid, RuntimeError> {
        self.config
            .agent_id
            .as_deref()
            .ok_or(RuntimeError::MissingAgentId)
            .and_then(parse_uuid)
    }

    fn agent_signing_public_key(&self) -> Result<[u8; 32], RuntimeError> {
        self.profile_signing
            .as_ref()
            .map(|signing| *signing.public_key())
            .ok_or(RuntimeError::IntegrityViolation)
    }
}

fn validate_request(request: &SubmissionRequest<'_>) -> Result<(), SubmissionNotSaved> {
    match request.target {
        SubmissionRequestTarget::New { suggested_vault_id } => {
            let entry_type = request.entry_type.ok_or(SubmissionNotSaved::InvalidInput)?;
            let label = normalize_label(request.label.unwrap_or_default());
            let url_valid = request.url.is_none_or(valid_https_url);
            let username_valid = match entry_type {
                SubmissionEntryType::Credential => request
                    .username
                    .is_some_and(|value| !value.trim().is_empty() && value.len() <= 1024),
                SubmissionEntryType::Key => request.username.is_none(),
            };
            if label.is_empty()
                || label.len() > LABEL_MAX_BYTES
                || label.chars().any(char::is_control)
                || !url_valid
                || !username_valid
                || suggested_vault_id.is_some_and(|id| parse_uuid(id).is_err())
            {
                return Err(SubmissionNotSaved::InvalidInput);
            }
        }
        SubmissionRequestTarget::Update { vault_id, entry_id } => {
            // The entry type comes from the submission target; every other field is an optional
            // change merged by the approver.
            let label_valid = request.label.is_none_or(|label| {
                let label = normalize_label(label);
                !label.is_empty()
                    && label.len() <= LABEL_MAX_BYTES
                    && !label.chars().any(char::is_control)
            });
            if parse_uuid(vault_id).is_err()
                || parse_uuid(entry_id).is_err()
                || request.entry_type.is_some()
                || !label_valid
                || !request.url.is_none_or(valid_https_url)
                || !request
                    .username
                    .is_none_or(|value| !value.trim().is_empty() && value.len() <= 1024)
            {
                return Err(SubmissionNotSaved::InvalidInput);
            }
        }
    }
    Ok(())
}

fn valid_https_url(value: &str) -> bool {
    value.len() <= 2048
        && url::Url::parse(value)
            .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some())
}

fn normalize_label(value: &str) -> String {
    value.trim().nfc().collect()
}

fn rejection_code(rejection: SubmissionRejection) -> SubmissionNotSaved {
    match rejection {
        SubmissionRejection::NoApprovers => SubmissionNotSaved::NoApprovers,
        SubmissionRejection::UpdateNotGranted => SubmissionNotSaved::UpdateNotGranted,
        SubmissionRejection::SubmissionConflict => SubmissionNotSaved::SubmissionConflict,
        SubmissionRejection::ApproverKeyRotated => SubmissionNotSaved::ApproverKeyUnavailable,
        SubmissionRejection::InvalidInput => SubmissionNotSaved::InvalidInput,
        SubmissionRejection::UnsupportedEntryType => SubmissionNotSaved::UnsupportedEntryType,
        // A pending approver rotation, stale Agent key state or an inactive Agent are transient
        // from the operator's view; the rest indicate a defect, never a reason to retry with
        // another secret.
        SubmissionRejection::ApproverKeyUnavailable
        | SubmissionRejection::AgentKeyMismatch
        | SubmissionRejection::AgentNotActive
        | SubmissionRejection::InvalidAgentSignature
        | SubmissionRejection::ContextMismatch
        | SubmissionRejection::RevisionReplay
        | SubmissionRejection::RewrapChangedPayload
        | SubmissionRejection::SubmissionNotUsable
        | SubmissionRejection::SubmissionNotPending
        | SubmissionRejection::SubmissionNotFound => SubmissionNotSaved::ServiceUnavailable,
    }
}

fn pinned_approver(
    anchor: &PublicApproverTrustAnchor,
) -> Result<PinnedApproverTrust, RuntimeError> {
    let decode = |value: &str| -> Result<[u8; 32], RuntimeError> {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| RuntimeError::InvalidPublicConfig)?
            .try_into()
            .map_err(|_| RuntimeError::InvalidPublicConfig)
    };
    Ok(PinnedApproverTrust {
        organization_id: parse_uuid(&anchor.organization_id)?,
        key_version: anchor.key_version,
        manifest_revision: anchor
            .manifest_revision
            .parse()
            .map_err(|_| RuntimeError::InvalidPublicConfig)?,
        signing_public_key: decode(&anchor.signing_public_key)?,
        message_public_key: decode(&anchor.message_public_key)?,
    })
}

fn parse_uuid(value: &str) -> Result<Uuid, RuntimeError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(RuntimeError::Submission(SubmissionError::InvalidInput))
}

fn random_uuid() -> Result<Uuid, RuntimeError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeError::RandomGenerationFailed)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests;
