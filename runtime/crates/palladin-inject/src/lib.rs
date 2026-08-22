#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod transport;

use palladin_api::{ApiError, CredentialAccess};
use palladin_browser_bridge::{
    InjectionControl, InjectionCredential, InjectionError, InjectionFormDefinition,
    InjectionFormField, InjectionTarget, ProviderId,
};
use palladin_credential::fields::{FieldSelector, ResolvedField, ResolvedFieldType, resolve_field};
use palladin_credential::secret::parse_secret;
use palladin_credential::wait::{HeartbeatInfo, WaitOptions};
use palladin_runtime::{
    CredentialDelivery, CredentialDeliveryRequest, CredentialOutputPolicy, InvocationSurface,
    OperationConnection, OperationDescriptor, RuntimeError, RuntimeService, SecretStore,
};
use secrecy::ExposeSecret;
use std::collections::BTreeMap;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

#[cfg(target_os = "macos")]
use palladin_browser_bridge::secure_transport::INJECT_PROVIDER_PROTOCOL;
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
    pub fallback_form: Option<&'a InjectionFormDefinition>,
}

#[derive(Debug)]
pub enum InjectExecution {
    Injected {
        provider: String,
        candidate_recording_failed: bool,
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
    let pairing = service.browser_host_pairing()?;
    let mut extension = ExtensionClient::connect(service.repository().root(), pairing.identity())
        .await
        .map_err(InjectServiceError::Transport)?;
    let mut operation_nonce = [0_u8; 32];
    getrandom::fill(&mut operation_nonce).map_err(|_| InjectServiceError::Randomness)?;
    let nonce = hex::encode(operation_nonce);
    let lifecycle = service
        .browser_host_lifecycle_guard_within(pairing.lifecycle_token(), OPERATION_TIMEOUT)?;
    let prepared = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(InjectServiceError::Cancelled),
        result = extension.prepare(&nonce) => result.map_err(InjectServiceError::Transport)?,
    };
    drop(lifecycle);
    if prepared.outcome != "ready" {
        return Err(InjectServiceError::ProviderNotReady);
    }
    let current_url = prepared
        .current_url
        .as_deref()
        .ok_or(InjectServiceError::InvalidPage)?;

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
    let form_map = match session
        .resolve_form_discovery_map(target.expected_domain(), operation.provider.as_str(), None)
        .await
    {
        Ok(Some(map)) if map.applies_to_url(current_url) => Some(map),
        Ok(_) => None,
        Err(error) if operation.fallback_form.is_some() && map_lookup_allows_fallback(&error) => {
            None
        }
        Err(error) => return Err(InjectServiceError::Runtime(error)),
    };
    let form = form_map
        .as_ref()
        .map(|map| &map.map.form)
        .or(operation.fallback_form)
        .ok_or(InjectServiceError::NoForm)?;
    let credential = resolve_injection_credential(
        &parsed,
        delivered.authenticated_field("credential.username"),
        form,
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
    let forward =
        session.browser_inject_forward_guard(service, pairing.lifecycle_token(), &delivered)?;
    let monotonic_sample = monotonic_now_ns().map_err(InjectServiceError::Transport)?;
    let authorization_remaining = forward
        .remaining()
        .ok_or(InjectServiceError::AuthorizationExpired)?;
    let not_after_monotonic_ns = monotonic_not_after_ns(monotonic_sample, authorization_remaining)
        .map_err(InjectServiceError::Transport)?;
    let wire = InjectRequest {
        protocol: INJECT_PROVIDER_PROTOCOL,
        message_type: "inject",
        transaction_id: &transaction_id,
        grant_id: &delivered.grant_id,
        entry_id: &delivered.entry_id,
        expected_domain: target.expected_domain(),
        form,
        values,
    };
    let sealed = extension
        .seal_inject(&wire, not_after_monotonic_ns)
        .map_err(InjectServiceError::Transport)?;
    drop(wire);
    drop(credential);
    drop(parsed);
    drop(delivered);
    let authorization_remaining = forward
        .remaining()
        .ok_or(InjectServiceError::AuthorizationExpired)?;
    let response = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(InjectServiceError::Cancelled),
        result = extension.send_inject(sealed, authorization_remaining) => {
            result.map_err(InjectServiceError::Transport)?
        }
    };
    drop(forward);
    if response.outcome != "injected" {
        let rejection = parse_provider_rejection(&response.outcome)?;
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

fn map_lookup_allows_fallback(error: &RuntimeError) -> bool {
    match error {
        RuntimeError::Api(ApiError::Transport) => true,
        RuntimeError::Api(ApiError::Http(status)) => (500..=599).contains(status),
        _ => false,
    }
}

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
            values.0.insert(field.entry_field_id.clone(), value);
        }
    }
    InjectionCredential::from_fields(std::mem::take(&mut values.0))
        .map_err(InjectServiceError::Injection)
}

#[derive(Default)]
struct SensitiveFieldMap(BTreeMap<String, String>);

impl Drop for SensitiveFieldMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
        self.0.clear();
    }
}

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
        "credential.totp" => resolve_selected_field(parsed, "totp", None)?,
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

#[derive(Clone, Copy)]
enum ResolvedKind {
    Text,
    Concealed,
    Otp,
}

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
    #[error("the authenticated Palladin extension returned an invalid page")]
    InvalidPage,
    #[error("the Inject credential payload is invalid")]
    InvalidCredentialPayload,
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

#[cfg(test)]
mod tests {
    use super::*;
    use palladin_browser_bridge::{InjectionFormStep, InjectionSubmit, InjectionSubmitKind};

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
}
