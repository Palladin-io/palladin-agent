#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", test))]
mod live;

#[cfg(target_os = "macos")]
mod transport;

use palladin_api::CredentialAccess;
use palladin_browser_bridge::{InjectionError, InjectionFormDefinition, ProviderId};
use palladin_credential::wait::{HeartbeatInfo, WaitOptions};
use palladin_runtime::{
    InvocationSurface, OperationConnection, RuntimeError, RuntimeService, SecretStore,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[cfg(any(target_os = "macos", test))]
use palladin_api::ApiError;
#[cfg(any(target_os = "macos", test))]
use palladin_browser_bridge::{
    InjectionControl, InjectionCredential, InjectionFormField, InjectionTarget,
};
#[cfg(any(target_os = "macos", test))]
use palladin_credential::fields::{FieldSelector, ResolvedField, ResolvedFieldType, resolve_field};
#[cfg(any(target_os = "macos", test))]
use palladin_credential::secret::parse_secret;
#[cfg(target_os = "macos")]
use palladin_runtime::{
    CredentialDelivery, CredentialDeliveryRequest, CredentialOutputPolicy, OperationDescriptor,
};
#[cfg(any(target_os = "macos", test))]
use secrecy::ExposeSecret;
#[cfg(any(target_os = "macos", test))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "macos", test))]
use zeroize::Zeroize;

#[cfg(target_os = "macos")]
use palladin_browser_bridge::secure_transport::INJECT_PROVIDER_PROTOCOL;
#[cfg(target_os = "macos")]
use palladin_browser_bridge::validate_https_page_url;
#[cfg(target_os = "macos")]
use transport::NativeBrowserError;
#[cfg(target_os = "macos")]
use transport::{
    ExtensionClient, InjectFieldValue, InjectRequest, OPERATION_TIMEOUT, monotonic_not_after_ns,
    monotonic_now_ns,
};

pub struct InjectOperation<'a> {
    pub surface: InvocationSurface,
    pub profile: Option<&'a str>,
    pub hostname: &'a str,
    pub connection: &'a OperationConnection,
    pub vault_id: &'a str,
    pub entry_id: &'a str,
    pub reason: Option<&'a str>,
    pub wait: WaitOptions,
    pub provider: &'a ProviderId,
    pub target: Option<BrowserTarget<'a>>,
    pub fallback_form: Option<&'a InjectionFormDefinition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserTarget<'a> {
    pub tab_id: u64,
    pub page_url: &'a str,
}

#[derive(Debug)]
pub enum InjectExecution {
    Injected {
        provider: String,
        candidate_recording_failed: bool,
    },
    LiveFlow {
        provider: String,
        steps: usize,
        outcome: &'static str,
    },
    NotGranted(CredentialAccess),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRejection {
    Rejected,
    NoPasswordField,
    NoSubmitControl,
    OriginMismatch,
    InsecureOrigin,
    AmbiguousForm,
    ProviderUnavailable,
    StaleFormMap,
}

impl ProviderRejection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::NoPasswordField => "no-password-field",
            Self::NoSubmitControl => "no-submit-control",
            Self::OriginMismatch => "origin-mismatch",
            Self::InsecureOrigin => "insecure-origin",
            Self::AmbiguousForm => "ambiguous-form",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::StaleFormMap => "stale-form-map",
        }
    }
}

pub async fn inject<S, H>(
    service: &RuntimeService<S>,
    operation: InjectOperation<'_>,
    cancellation: &CancellationToken,
    heartbeat: H,
) -> Result<InjectExecution, InjectServiceError>
where
    S: SecretStore + Sync,
    H: FnMut(HeartbeatInfo),
{
    if operation.provider.as_str() != "extension" {
        return Err(InjectServiceError::UnsupportedProvider);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, operation, cancellation, heartbeat);
        Err(InjectServiceError::UnsupportedPlatform)
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(target) = operation.target {
            if target.tab_id == 0 || target.tab_id > 9_007_199_254_740_991 {
                return Err(InjectServiceError::InvalidPage);
            }
            validate_https_page_url(target.page_url).map_err(InjectServiceError::Injection)?;
        }
        inject_extension(service, operation, cancellation, heartbeat).await
    }
}

#[cfg(target_os = "macos")]
async fn inject_extension<S, H>(
    service: &RuntimeService<S>,
    operation: InjectOperation<'_>,
    cancellation: &CancellationToken,
    heartbeat: H,
) -> Result<InjectExecution, InjectServiceError>
where
    S: SecretStore + Sync,
    H: FnMut(HeartbeatInfo),
{
    let flag = std::env::var("PALLADIN_EXPERIMENTAL_LIVE_FORMS");
    let live_forms = match flag {
        Ok(value) => live::enabled(Some(&value))?,
        Err(std::env::VarError::NotPresent) => live::enabled(None)?,
        Err(_) => return Err(InjectServiceError::InvalidLiveFlag),
    };
    if live_forms && (operation.target.is_none() || operation.fallback_form.is_some()) {
        return Err(InjectServiceError::LiveTargetRequired);
    }
    let authorization = service.browser_host_authorization()?;
    let mut operation_nonce = [0_u8; 32];
    getrandom::fill(&mut operation_nonce).map_err(|_| InjectServiceError::Randomness)?;
    let nonce = hex::encode(operation_nonce);
    let lifecycle = service
        .browser_host_lifecycle_guard_within(authorization.lifecycle_token(), OPERATION_TIMEOUT)?;
    let (mut extension, prepared) = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(InjectServiceError::Cancelled),
        result = ExtensionClient::connect_prepared(service.repository().root(), authorization.identity(),
            &nonce, operation.target, live_forms) => {
            result.map_err(InjectServiceError::Transport)?
        },
    };
    drop(lifecycle);
    match prepared.outcome.as_str() {
        "ready" => {}
        "unsupported-live-detection" => return Err(InjectServiceError::LiveDiscoveryUnsupported),
        "target-tab-unavailable" => return Err(InjectServiceError::TargetTabUnavailable),
        "target-url-mismatch" => return Err(InjectServiceError::TargetUrlMismatch),
        _ => return Err(InjectServiceError::ProviderNotReady),
    }
    let current_url = prepared
        .current_url
        .as_deref()
        .ok_or(InjectServiceError::InvalidPage)?;

    // DOM/provider is an independent trust boundary: no arbitrary granted fields.
    if live_forms {
        live::validate(
            prepared
                .live_form
                .as_ref()
                .ok_or(InjectServiceError::InvalidLiveForm)?,
        )?;
    }
    let descriptor = OperationDescriptor::InjectCredential {
        surface: operation.surface,
        vault_id: operation.vault_id.to_owned(),
        entry_id: operation.entry_id.to_owned(),
        reason: operation.reason.map(str::to_owned),
        wait: operation.wait,
        provider: operation.provider.as_str().to_owned(),
        output: CredentialOutputPolicy::TrustedInjectionProvider,
    };
    let session = service.open_session(
        operation.profile,
        operation.hostname,
        operation.connection,
        descriptor,
    )?;
    let delivery = session
        .deliver_for_inject(
            CredentialDeliveryRequest {
                vault_id: operation.vault_id,
                entry_id: operation.entry_id,
                reason: operation.reason,
                wait: operation.wait,
            },
            cancellation,
            heartbeat,
        )
        .await?;
    let delivered = match delivery {
        CredentialDelivery::Granted(delivered) => delivered,
        CredentialDelivery::NotGranted(access) => {
            return Ok(InjectExecution::NotGranted(access));
        }
    };
    let parsed = parse_secret(delivered.expose_for_authorized_operation())
        .map_err(|_| InjectServiceError::InvalidCredentialPayload)?;
    let target = resolve_authenticated_injection_target(
        parsed
            .fields
            .get("urlDomain")
            .map(|domain| domain.expose_secret()),
        delivered.authenticated_domain(),
    )?;
    target
        .verify_url(current_url)
        .map_err(InjectServiceError::Injection)?;
    let form_map = if live_forms {
        None
    } else {
        match session
            .resolve_form_discovery_map(target.expected_domain(), operation.provider.as_str(), None)
            .await
        {
            Ok(Some(map)) if map.applies_to_url(current_url) => Some(map),
            Ok(_) => None,
            Err(error)
                if operation.fallback_form.is_some() && map_lookup_allows_fallback(&error) =>
            {
                None
            }
            Err(error) => return Err(InjectServiceError::Runtime(error)),
        }
    };
    let form = form_map
        .as_ref()
        .map(|map| &map.map.form)
        .or(if live_forms {
            prepared.live_form.as_ref()
        } else {
            operation.fallback_form
        })
        .ok_or(InjectServiceError::NoForm)?;
    // One delivery remains native-only for this bounded operation. The browser receives only
    // fields needed by the current stage; TOTP is generated freshly at the TOTP stage.
    let mut flow = if live_forms {
        Some(
            palladin_browser_bridge::live_login::LiveLoginFlow::new(current_url, form.clone())
                .map_err(InjectServiceError::Injection)?,
        )
    } else {
        None
    };
    let deadline =
        std::time::Instant::now() + palladin_browser_bridge::live_login::LIVE_FLOW_TIMEOUT;
    let mut current_form = form.clone();
    let mut discovery_username = None;
    let mut retained_credential = Some(delivered);
    let mut retained_payload = Some(parsed);
    loop {
        let delivered = retained_credential
            .as_ref()
            .ok_or(InjectServiceError::InvalidCredentialPayload)?;
        let parsed = retained_payload
            .as_ref()
            .ok_or(InjectServiceError::InvalidCredentialPayload)?;
        if cancellation.is_cancelled() {
            return Err(InjectServiceError::Cancelled);
        }
        if delivered
            .authenticated_field("credential.username")
            .is_none()
            && discovery_username.is_none()
            && current_form
                .field_ids()
                .any(|id| id == "credential.username")
        {
            discovery_username = session
                .authenticated_inject_username(
                    operation.vault_id,
                    operation.entry_id,
                    delivered.inject_discovery_revision()?,
                )
                .await?;
        }
        let authenticated_username = delivered
            .authenticated_field("credential.username")
            .or_else(|| discovery_username.as_ref().map(|value| value.as_str()));
        let (forward, credential) = acquire_then_resolve_injection(
            || {
                session.browser_inject_forward_guard_until(
                    service,
                    authorization.lifecycle_token(),
                    delivered,
                    live_forms.then_some(deadline),
                )
            },
            parsed,
            authenticated_username,
            &current_form,
        )?;
        let mut transaction_bytes = [0_u8; 16];
        getrandom::fill(&mut transaction_bytes).map_err(|_| InjectServiceError::Randomness)?;
        let transaction_id = hex::encode(transaction_bytes);
        let values = credential
            .fields()
            .iter()
            .map(|(entry_field_id, value)| InjectFieldValue {
                entry_field_id,
                value,
            })
            .collect();
        let monotonic_sample = monotonic_now_ns().map_err(InjectServiceError::Transport)?;
        let mut authorization_remaining = forward
            .remaining()
            .ok_or(InjectServiceError::AuthorizationExpired)?;
        if live_forms {
            authorization_remaining = authorization_remaining
                .min(deadline.saturating_duration_since(std::time::Instant::now()));
        }
        let not_after_monotonic_ns =
            monotonic_not_after_ns(monotonic_sample, authorization_remaining)
                .map_err(InjectServiceError::Transport)?;
        let wire = InjectRequest {
            continue_live: live_forms.then_some(true),
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: &transaction_id,
            grant_id: &delivered.grant_id,
            entry_id: &delivered.entry_id,
            expected_domain: target.expected_domain(),
            form: &current_form,
            values,
        };
        let sealed = extension
            .seal_inject(&wire, not_after_monotonic_ns)
            .map_err(InjectServiceError::Transport)?;
        drop(wire);
        drop(credential);
        if !live_forms {
            // Preserve the original map/fallback lifetime: it has no native continuation.
            drop(retained_payload.take());
            drop(retained_credential.take());
            drop(discovery_username.take());
        }
        if cancellation.is_cancelled() {
            return Err(InjectServiceError::Cancelled);
        }
        // No reconnect or cancellation retry after handoff: a timed-out submitted step is
        // ambiguous. Wait for its bounded value-free response, then recheck before any next step.
        let response = extension
            .send_inject(sealed, authorization_remaining)
            .await
            .map_err(InjectServiceError::Transport)?;
        drop(forward);
        if response.outcome != "injected" {
            let rejection = parse_provider_rejection(&response.outcome)?;
            if live_forms && rejection == ProviderRejection::StaleFormMap {
                return Err(InjectServiceError::LiveFormChanged);
            }
            if rejection == ProviderRejection::StaleFormMap
                && let Some(rejected) = form_map.as_ref()
            {
                session
                    .resolve_form_discovery_map(
                        target.expected_domain(),
                        operation.provider.as_str(),
                        Some(rejected),
                    )
                    .await
                    .map_err(InjectServiceError::StaleMapRefresh)?;
            }
            return Err(InjectServiceError::ProviderRejected(rejection));
        }
        let Some(flow) = flow.as_mut() else { break };
        flow.submitted().map_err(InjectServiceError::Injection)?;
        let continuation = response.continuation.unwrap_or(
            palladin_browser_bridge::live_login::LiveContinuation::ProviderUnavailable {},
        );
        if !flow
            .advance(&continuation)
            .map_err(InjectServiceError::Injection)?
        {
            return Ok(InjectExecution::LiveFlow {
                provider: operation.provider.as_str().to_owned(),
                steps: flow.steps(),
                outcome: continuation.outcome(),
            });
        }
        if let palladin_browser_bridge::live_login::LiveContinuation::Ready {
            current_url, ..
        } = &continuation
        {
            target
                .verify_url(current_url)
                .map_err(InjectServiceError::Injection)?;
        }
        current_form = flow.form().clone();
    }
    drop(discovery_username);
    drop(retained_payload);
    drop(retained_credential);
    let candidate_recording_failed = if form_map.is_none()
        && let Some(fallback_form) = operation.fallback_form
    {
        session
            .submit_form_discovery_map_candidate(
                target.expected_domain(),
                current_url,
                operation.provider.as_str(),
                fallback_form,
            )
            .await
            .is_err()
    } else {
        false
    };
    Ok(InjectExecution::Injected {
        provider: operation.provider.as_str().to_owned(),
        candidate_recording_failed,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_provider_rejection(value: &str) -> Result<ProviderRejection, InjectServiceError> {
    match value {
        "rejected" => Ok(ProviderRejection::Rejected),
        "no-password-field" => Ok(ProviderRejection::NoPasswordField),
        "no-submit-control" => Ok(ProviderRejection::NoSubmitControl),
        "origin-mismatch" => Ok(ProviderRejection::OriginMismatch),
        "insecure-origin" => Ok(ProviderRejection::InsecureOrigin),
        "ambiguous-form" => Ok(ProviderRejection::AmbiguousForm),
        "provider-unavailable" => Ok(ProviderRejection::ProviderUnavailable),
        "stale-form-map" => Ok(ProviderRejection::StaleFormMap),
        _ => Err(InjectServiceError::InvalidProviderOutcome),
    }
}

#[cfg(any(target_os = "macos", test))]
fn map_lookup_allows_fallback(error: &RuntimeError) -> bool {
    match error {
        RuntimeError::Api(ApiError::Transport) => true,
        RuntimeError::Api(ApiError::Http(status)) => (500..=599).contains(status),
        _ => false,
    }
}

#[cfg(any(target_os = "macos", test))]
fn resolve_authenticated_injection_target(
    grant_domain: Option<&str>,
    discovery_domain: Option<&str>,
) -> Result<InjectionTarget, InjectServiceError> {
    let grant_target = grant_domain
        .map(|domain| InjectionTarget::parse(domain.to_owned()))
        .transpose()
        .map_err(InjectServiceError::Injection)?;
    let discovery_target = discovery_domain
        .map(|domain| InjectionTarget::parse(domain.to_owned()))
        .transpose()
        .map_err(InjectServiceError::Injection)?;
    match (grant_target, discovery_target) {
        (Some(grant), Some(discovery)) if grant != discovery => {
            Err(InjectServiceError::DomainMismatch)
        }
        (Some(grant), _) => Ok(grant),
        (None, Some(discovery)) => Ok(discovery),
        (None, None) => Err(InjectServiceError::MissingDomain),
    }
}

// Resolve dynamic values only inside the final authorized handoff, after any lock wait.
#[cfg(any(target_os = "macos", test))]
fn acquire_then_resolve_injection<G>(
    acquire: impl FnOnce() -> Result<G, RuntimeError>,
    parsed: &palladin_credential::secret::ParsedSecret,
    authenticated_username: Option<&str>,
    form: &InjectionFormDefinition,
) -> Result<(G, InjectionCredential), InjectServiceError> {
    let forward = acquire()?;
    let credential = resolve_injection_credential(parsed, authenticated_username, form)?;
    Ok((forward, credential))
}

#[cfg(any(target_os = "macos", test))]
fn resolve_injection_credential(
    parsed: &palladin_credential::secret::ParsedSecret,
    authenticated_username: Option<&str>,
    form: &InjectionFormDefinition,
) -> Result<InjectionCredential, InjectServiceError> {
    form.validate().map_err(InjectServiceError::Injection)?;
    let mut values = SensitiveFieldMap::default();
    for step in &form.steps {
        for field in &step.fields {
            let value = resolve_injection_field(parsed, authenticated_username, field)?;
            values.insert(field.entry_field_id.clone(), value);
        }
    }
    InjectionCredential::from_fields(std::mem::take(&mut values.0))
        .map_err(InjectServiceError::Injection)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
struct SensitiveFieldMap(BTreeMap<String, String>);

#[cfg(any(target_os = "macos", test))]
impl SensitiveFieldMap {
    fn insert(&mut self, entry_field_id: String, value: String) {
        if let Some(mut replaced) = self.0.insert(entry_field_id, value) {
            replaced.zeroize();
        }
    }
}

#[cfg(any(target_os = "macos", test))]
impl Drop for SensitiveFieldMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
        self.0.clear();
    }
}

#[cfg(any(target_os = "macos", test))]
fn resolve_injection_field(
    parsed: &palladin_credential::secret::ParsedSecret,
    authenticated_username: Option<&str>,
    field: &InjectionFormField,
) -> Result<String, InjectServiceError> {
    let (mut resolved, kind) = match field.entry_field_id.as_str() {
        "credential.username" => {
            let value = parsed
                .username
                .as_ref()
                .map(|value| value.expose_secret())
                .filter(|value| !value.is_empty())
                .or(authenticated_username)
                .ok_or(InjectServiceError::InvalidCredentialPayload)?;
            (value.to_owned(), ResolvedKind::Text)
        }
        "credential.password" => {
            let value = parsed.password.expose_secret();
            if value.is_empty() {
                return Err(InjectServiceError::InvalidCredentialPayload);
            }
            (value.to_owned(), ResolvedKind::Concealed)
        }
        "credential.url" => resolve_selected_field(parsed, "url", None)?,
        "credential.notes" | "notes" => resolve_selected_field(parsed, "notes", None)?,
        "credential.value" => resolve_selected_field(parsed, "value", None)?,
        "credential.totp" => resolve_login_totp(parsed)?,
        custom_id => resolve_selected_field(
            parsed,
            "",
            Some(custom_id.strip_prefix("custom:").unwrap_or(custom_id)),
        )?,
    };
    let compatible = matches!(
        (kind, field.control),
        (ResolvedKind::Concealed, InjectionControl::Password)
            | (
                ResolvedKind::Otp,
                InjectionControl::Otp | InjectionControl::Text | InjectionControl::Tel,
            )
            | (
                ResolvedKind::Text,
                InjectionControl::Username
                    | InjectionControl::Text
                    | InjectionControl::Email
                    | InjectionControl::Tel,
            )
    );
    if resolved.is_empty() || !compatible {
        resolved.zeroize();
        return Err(InjectServiceError::InvalidCredentialPayload);
    }
    Ok(resolved)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy)]
enum ResolvedKind {
    Text,
    Concealed,
    Otp,
}

#[cfg(any(target_os = "macos", test))]
fn resolve_login_totp(
    parsed: &palladin_credential::secret::ParsedSecret,
) -> Result<(String, ResolvedKind), InjectServiceError> {
    use palladin_credential::secret::CustomFieldType;
    let primary = parsed
        .custom_fields
        .iter()
        .filter(|field| field.id == "credential.totp")
        .collect::<Vec<_>>();
    if !primary.is_empty() {
        if primary.len() != 1 {
            return Err(InjectServiceError::InvalidCredentialPayload);
        }
        // V1 snapshots carry no absolute validity time. Do not forward one as
        // a fresh code; only a protected typed source may be derived here.
        if primary[0].field_type != CustomFieldType::Totp {
            return Err(InjectServiceError::TotpRefreshRequired);
        }
        let (mut value, kind) = resolve_selected_field(parsed, "", Some("credential.totp"))?;
        if matches!(kind, ResolvedKind::Otp) {
            return Ok((value, ResolvedKind::Otp));
        }
        value.zeroize();
        return Err(InjectServiceError::InvalidCredentialPayload);
    }
    if let Some(source) = &parsed.legacy_totp {
        let params = palladin_credential::secret::parse_totp_value(source.expose_secret())
            .ok_or(InjectServiceError::InvalidCredentialPayload)?;
        let code = palladin_credential::totp::generate_totp(&params)
            .map_err(|_| InjectServiceError::InvalidCredentialPayload)?;
        return Ok((code.code.expose_secret().to_owned(), ResolvedKind::Otp));
    }
    let mut candidates = parsed
        .custom_fields
        .iter()
        .filter(|field| field.field_type == CustomFieldType::Totp);
    let candidate = candidates
        .next()
        .ok_or(InjectServiceError::TotpNotDelivered)?;
    if candidates.next().is_some() {
        return Err(InjectServiceError::AmbiguousTotp);
    }
    resolve_selected_field(parsed, "", Some(&candidate.id))
}

#[cfg(any(target_os = "macos", test))]
fn resolve_selected_field(
    parsed: &palladin_credential::secret::ParsedSecret,
    label: &str,
    field_id: Option<&str>,
) -> Result<(String, ResolvedKind), InjectServiceError> {
    let selected = resolve_field(
        parsed,
        &FieldSelector {
            field: field_id.is_none().then(|| label.to_owned()),
            field_id: field_id.map(str::to_owned),
        },
    )
    .map_err(|_| InjectServiceError::InvalidCredentialPayload)?;
    let kind = match &selected {
        ResolvedField::Totp { .. } => ResolvedKind::Otp,
        ResolvedField::Value { field_type, .. } => match field_type {
            ResolvedFieldType::Concealed => ResolvedKind::Concealed,
            ResolvedFieldType::WellKnown
            | ResolvedFieldType::Text
            | ResolvedFieldType::Multiline => ResolvedKind::Text,
        },
    };
    Ok((selected.expose_for_authorized_operation().to_owned(), kind))
}

#[derive(Debug, Error)]
pub enum InjectServiceError {
    #[error("PALLADIN_EXPERIMENTAL_LIVE_FORMS must be 0 or 1")]
    InvalidLiveFlag,
    #[error(
        "experimental live discovery requires an exact target tab and URL and cannot use --form-json"
    )]
    LiveTargetRequired,
    #[error(
        "no unambiguous live login/TOTP step is available; inspect the page before any next operation"
    )]
    InvalidLiveForm,
    #[error(
        "live form changed or could not be safely completed; no stored form map was used and Inject was not retried"
    )]
    LiveFormChanged,
    #[error(
        "the running browser extension rejected live form discovery; matching updated runtime and extension versions are required"
    )]
    LiveDiscoveryUnsupported,
    #[error("only the authenticated Palladin extension provider is supported")]
    UnsupportedProvider,
    #[error("the authenticated browser extension provider is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("the Inject operation was cancelled")]
    Cancelled,
    #[error("could not create an Inject transaction")]
    Randomness,
    #[error("the authenticated Palladin extension is not ready for Inject")]
    ProviderNotReady,
    #[error("the browser framework target tab is unavailable to the Palladin extension")]
    TargetTabUnavailable,
    #[error("the browser framework target URL no longer matches the live tab")]
    TargetUrlMismatch,
    #[error("the authenticated Palladin extension returned an invalid page")]
    InvalidPage,
    #[error("the Inject credential payload is invalid")]
    InvalidCredentialPayload,
    #[error(
        "the approved Inject delivery does not contain TOTP; check TOTP field access and grant material for the selected Entry"
    )]
    TotpNotDelivered,
    #[error(
        "the approved Inject delivery contains multiple TOTP sources; select a primary login TOTP field"
    )]
    AmbiguousTotp,
    #[error(
        "the approved TOTP grant contains a saved code without verifiable freshness; refresh its encrypted grant material with a current Palladin client"
    )]
    TotpRefreshRequired,
    #[error("the grant and Discovery domains do not match")]
    DomainMismatch,
    #[error("the Inject credential has no authenticated domain")]
    MissingDomain,
    #[error("no verified Form Discovery Map or fallback form is available")]
    NoForm,
    #[error("the authenticated browser authorization expired")]
    AuthorizationExpired,
    #[error("the trusted browser provider returned an invalid outcome")]
    InvalidProviderOutcome,
    #[error(
        "the trusted browser provider did not complete Inject (outcome={})",
        .0.as_str()
    )]
    ProviderRejected(ProviderRejection),
    #[error(
        "the trusted browser provider reported a stale Form Discovery Map, but cache invalidation or refresh failed: {0}"
    )]
    StaleMapRefresh(RuntimeError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    Injection(InjectionError),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Transport(NativeBrowserError),
}

impl InjectServiceError {
    #[must_use]
    pub fn is_authorization_expired(&self) -> bool {
        match self {
            Self::AuthorizationExpired => true,
            #[cfg(target_os = "macos")]
            Self::Transport(NativeBrowserError::AuthorizationExpired) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use palladin_browser_bridge::{
        InjectionFormStep, InjectionSubmit, InjectionSubmitKind, InjectionWaitFor,
    };

    #[test]
    fn authenticated_domains_must_match_or_one_must_exist() {
        assert_eq!(
            resolve_authenticated_injection_target(Some("X.COM"), Some("x.com"))
                .expect("target")
                .expected_domain(),
            "x.com"
        );
        assert!(matches!(
            resolve_authenticated_injection_target(Some("evil.test"), Some("x.com")),
            Err(InjectServiceError::DomainMismatch)
        ));
        assert!(matches!(
            resolve_authenticated_injection_target(None, None),
            Err(InjectServiceError::MissingDomain)
        ));
    }

    #[test]
    fn authorization_expiry_classification_includes_the_transport_boundary() {
        assert!(InjectServiceError::AuthorizationExpired.is_authorization_expired());
        #[cfg(target_os = "macos")]
        {
            assert!(
                InjectServiceError::Transport(NativeBrowserError::AuthorizationExpired)
                    .is_authorization_expired()
            );
            assert!(
                !InjectServiceError::Transport(NativeBrowserError::Unavailable)
                    .is_authorization_expired()
            );
        }
    }

    #[test]
    fn provider_rejections_are_closed_and_value_free() {
        assert_eq!(
            parse_provider_rejection("stale-form-map").expect("outcome"),
            ProviderRejection::StaleFormMap
        );
        assert!(parse_provider_rejection("injected-with-secret").is_err());
    }

    #[test]
    fn fallback_form_is_used_only_for_transient_map_lookup_unavailability() {
        assert!(map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Transport
        )));
        assert!(map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Http(503)
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Http(401)
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::InvalidResponse
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::FormMapCache));
    }

    #[test]
    fn form_resolution_keeps_only_declared_fields() {
        let secret = br#"{"username":"fixture-user","password":"fixture-password"}"#;
        let parsed = parse_secret(secret).expect("secret");
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![
                    InjectionFormField {
                        entry_field_id: "credential.username".to_owned(),
                        selector: "#username".to_owned(),
                        control: InjectionControl::Username,
                    },
                    InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "#password".to_owned(),
                        control: InjectionControl::Password,
                    },
                ],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::Click,
                    selector: "button[type=submit]".to_owned(),
                },
                wait_for: None,
            }],
        };
        let credential = resolve_injection_credential(&parsed, None, &form).expect("credential");
        assert_eq!(credential.fields().len(), 2);
        assert_eq!(credential.username(), Some("fixture-user"));
        assert_eq!(credential.password(), "fixture-password");
        assert_eq!(format!("{credential:?}"), "InjectionCredential([REDACTED])");
    }

    #[test]
    fn authenticated_discovery_username_can_complete_the_granted_credential() {
        let secret = br#"{"password":"fixture-password","urlDomain":"example.com"}"#;
        let parsed = parse_secret(secret).expect("secret");
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![
                    InjectionFormField {
                        entry_field_id: "credential.username".to_owned(),
                        selector: "#username".to_owned(),
                        control: InjectionControl::Username,
                    },
                    InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "#password".to_owned(),
                        control: InjectionControl::Password,
                    },
                ],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::Click,
                    selector: "button[type=submit]".to_owned(),
                },
                wait_for: None,
            }],
        };
        let credential =
            resolve_injection_credential(&parsed, Some("fixture-user"), &form).expect("credential");
        assert_eq!(credential.username(), Some("fixture-user"));
        assert_eq!(credential.password(), "fixture-password");
    }

    #[test]
    fn repeated_field_across_steps_has_one_final_plaintext_owner() {
        let secret = br#"{"username":"fixture-user","password":"fixture-password"}"#;
        let parsed = parse_secret(secret).expect("secret");
        let repeated_username = InjectionFormField {
            entry_field_id: "credential.username".to_owned(),
            selector: "#username".to_owned(),
            control: InjectionControl::Username,
        };
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![
                InjectionFormStep {
                    fields: vec![repeated_username.clone()],
                    submit: InjectionSubmit {
                        action: InjectionSubmitKind::Click,
                        selector: "button[type=submit]".to_owned(),
                    },
                    wait_for: Some(InjectionWaitFor {
                        selector: "#username-confirmation".to_owned(),
                        timeout_ms: Some(20_000),
                    }),
                },
                InjectionFormStep {
                    fields: vec![repeated_username],
                    submit: InjectionSubmit {
                        action: InjectionSubmitKind::PressEnter,
                        selector: "#username".to_owned(),
                    },
                    wait_for: None,
                },
            ],
        };

        let credential = resolve_injection_credential(&parsed, None, &form).expect("credential");
        assert_eq!(credential.fields().len(), 1);
        assert_eq!(credential.username(), Some("fixture-user"));
    }
}

#[cfg(test)]
#[path = "totp_tests.rs"]
mod totp_tests;
