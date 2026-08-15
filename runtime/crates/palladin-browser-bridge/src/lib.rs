#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_FIELD_BYTES: usize = 64 * 1024;
const MAX_SELECTOR_BYTES: usize = 1_024;
const MAX_FORM_STEPS: usize = 8;
const MAX_FORM_FIELDS: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionControl {
    Username,
    Password,
    Text,
    Email,
    Tel,
    Otp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionFormField {
    pub entry_field_id: String,
    pub selector: String,
    pub control: InjectionControl,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionSubmitKind {
    Click,
    PressEnter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionSubmit {
    pub action: InjectionSubmitKind,
    pub selector: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionWaitFor {
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionFormStep {
    pub fields: Vec<InjectionFormField>,
    pub submit: InjectionSubmit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<InjectionWaitFor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionFormDefinition {
    pub version: u8,
    pub steps: Vec<InjectionFormStep>,
}

impl InjectionFormDefinition {
    pub fn validate(&self) -> Result<(), InjectionError> {
        if self.version != 1 || self.steps.is_empty() || self.steps.len() > MAX_FORM_STEPS {
            return Err(InjectionError::InvalidFormDefinition);
        }
        let mut field_count = 0_usize;
        for (step_index, step) in self.steps.iter().enumerate() {
            if step.fields.is_empty()
                || (step_index + 1 < self.steps.len() && step.wait_for.is_none())
                || !valid_selector(&step.submit.selector)
            {
                return Err(InjectionError::InvalidFormDefinition);
            }
            let mut step_field_ids = BTreeSet::new();
            for field in &step.fields {
                field_count = field_count.saturating_add(1);
                if field_count > MAX_FORM_FIELDS
                    || !valid_identifier(&field.entry_field_id)
                    || !valid_selector(&field.selector)
                    || !step_field_ids.insert(field.entry_field_id.as_str())
                {
                    return Err(InjectionError::InvalidFormDefinition);
                }
            }
            if step.submit.action == InjectionSubmitKind::PressEnter
                && !step
                    .fields
                    .iter()
                    .any(|field| field.selector == step.submit.selector)
            {
                return Err(InjectionError::InvalidFormDefinition);
            }
            if let Some(wait_for) = &step.wait_for
                && (!valid_selector(&wait_for.selector)
                    || wait_for
                        .timeout_ms
                        .is_some_and(|timeout| !(100..=60_000).contains(&timeout)))
            {
                return Err(InjectionError::InvalidFormDefinition);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn field_ids(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().flat_map(|step| {
            step.fields
                .iter()
                .map(|field| field.entry_field_id.as_str())
        })
    }
}

/// Stable identifier of one browser-delivery implementation.
///
/// Providers are selected by identifier and registered at the composition root. Adding a new
/// browser automation integration does not change grant delivery or the credential contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn parse(value: impl Into<String>) -> Result<Self, InjectionError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(InjectionError::InvalidProviderId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The exact top-level origin constraint authenticated by the encrypted Entry payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectionTarget {
    expected_domain: String,
}

impl InjectionTarget {
    pub fn parse(expected_domain: impl Into<String>) -> Result<Self, InjectionError> {
        let expected_domain = expected_domain.into().to_ascii_lowercase();
        if !valid_domain(&expected_domain) {
            return Err(InjectionError::InvalidDomain);
        }
        Ok(Self { expected_domain })
    }

    #[must_use]
    pub fn expected_domain(&self) -> &str {
        &self.expected_domain
    }

    pub fn verify_url(&self, url: &str) -> Result<(), InjectionError> {
        let parsed = Url::parse(url).map_err(|_| InjectionError::InvalidOrigin)?;
        if parsed.scheme() != "https" {
            return Err(InjectionError::InsecureOrigin);
        }
        let host = parsed
            .host_str()
            .ok_or(InjectionError::InvalidOrigin)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host == self.expected_domain || host.ends_with(&format!(".{}", self.expected_domain)) {
            Ok(())
        } else {
            Err(InjectionError::OriginMismatch)
        }
    }
}

/// Secret material transferred once to one trusted provider implementation.
///
/// It is deliberately non-serializable and its Debug output is always redacted. Transport-specific
/// adapters must copy it only into their private in-memory channel and never into argv, environment,
/// logs, MCP results, or persistent storage.
pub struct InjectionCredential {
    fields: BTreeMap<String, String>,
}

impl Drop for InjectionCredential {
    fn drop(&mut self) {
        for value in self.fields.values_mut() {
            value.zeroize();
        }
        self.fields.clear();
    }
}

impl InjectionCredential {
    pub fn new(username: Option<String>, password: String) -> Result<Self, InjectionError> {
        if password.is_empty()
            || password.len() > MAX_FIELD_BYTES
            || username
                .as_deref()
                .is_some_and(|value| value.len() > MAX_FIELD_BYTES)
        {
            return Err(InjectionError::InvalidCredential);
        }
        let mut fields = BTreeMap::new();
        if let Some(username) = username {
            fields.insert("credential.username".to_owned(), username);
        }
        fields.insert("credential.password".to_owned(), password);
        Ok(Self { fields })
    }

    pub fn from_fields(fields: BTreeMap<String, String>) -> Result<Self, InjectionError> {
        if fields.is_empty()
            || fields.len() > MAX_FORM_FIELDS
            || fields
                .iter()
                .any(|(id, value)| !valid_identifier(id) || value.len() > MAX_FIELD_BYTES)
        {
            return Err(InjectionError::InvalidCredential);
        }
        Ok(Self { fields })
    }

    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.fields.get("credential.username").map(String::as_str)
    }

    #[must_use]
    pub fn password(&self) -> &str {
        self.fields
            .get("credential.password")
            .map_or("", String::as_str)
    }

    #[must_use]
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

impl std::fmt::Debug for InjectionCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InjectionCredential([REDACTED])")
    }
}

pub struct InjectionRequest {
    pub transaction_id: String,
    pub grant_id: String,
    pub entry_id: String,
    pub target: InjectionTarget,
    pub credential: InjectionCredential,
}

impl InjectionRequest {
    pub fn validate(&self) -> Result<(), InjectionError> {
        if !valid_identifier(&self.transaction_id)
            || !valid_identifier(&self.grant_id)
            || !valid_identifier(&self.entry_id)
        {
            return Err(InjectionError::InvalidRequest);
        }
        Ok(())
    }
}

impl std::fmt::Debug for InjectionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InjectionRequest")
            .field("transaction_id", &self.transaction_id)
            .field("grant_id", &self.grant_id)
            .field("entry_id", &self.entry_id)
            .field("target", &self.target)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionOutcome {
    Injected,
    Rejected,
    NoPasswordField,
    NoSubmitControl,
    OriginMismatch,
    InsecureOrigin,
    AmbiguousForm,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionResult {
    pub transaction_id: String,
    pub outcome: InjectionOutcome,
}

pub type InjectionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<InjectionResult, InjectionError>> + Send + 'a>>;

/// Open/Closed boundary for browser automation integrations.
pub trait InjectionProvider: Send + Sync {
    fn id(&self) -> &ProviderId;
    fn inject(&self, request: InjectionRequest) -> InjectionFuture<'_>;
}

#[derive(Default)]
pub struct InjectionProviderRegistry {
    providers: BTreeMap<ProviderId, Arc<dyn InjectionProvider>>,
}

impl InjectionProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, provider: Arc<dyn InjectionProvider>) -> Result<(), InjectionError> {
        let id = provider.id().clone();
        if self.providers.insert(id, provider).is_some() {
            return Err(InjectionError::DuplicateProvider);
        }
        Ok(())
    }

    pub async fn inject(
        &self,
        provider: &ProviderId,
        request: InjectionRequest,
    ) -> Result<InjectionResult, InjectionError> {
        request.validate()?;
        self.providers
            .get(provider)
            .ok_or(InjectionError::ProviderUnavailable)?
            .inject(request)
            .await
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InjectionError {
    #[error("invalid injection provider identifier")]
    InvalidProviderId,
    #[error("injection provider is already registered")]
    DuplicateProvider,
    #[error("injection provider is unavailable")]
    ProviderUnavailable,
    #[error("invalid injection request")]
    InvalidRequest,
    #[error("invalid injection credential")]
    InvalidCredential,
    #[error("invalid Inject form definition")]
    InvalidFormDefinition,
    #[error("invalid credential domain")]
    InvalidDomain,
    #[error("invalid browser origin")]
    InvalidOrigin,
    #[error("browser origin must use HTTPS")]
    InsecureOrigin,
    #[error("browser origin does not match the credential domain")]
    OriginMismatch,
    #[error("browser provider rejected the injection operation")]
    ProviderRejected,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DOMAIN_BYTES
        && value == value.trim()
        && !value.contains('/')
        && !value.contains(':')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SELECTOR_BYTES
        && value == value.trim()
        && !value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingProvider {
        id: ProviderId,
        seen_password: Arc<Mutex<Option<String>>>,
    }

    impl InjectionProvider for RecordingProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }

        fn inject(&self, request: InjectionRequest) -> InjectionFuture<'_> {
            Box::pin(async move {
                *self.seen_password.lock().expect("recording lock") =
                    Some(request.credential.password().to_owned());
                Ok(InjectionResult {
                    transaction_id: request.transaction_id,
                    outcome: InjectionOutcome::Injected,
                })
            })
        }
    }

    fn request() -> InjectionRequest {
        InjectionRequest {
            transaction_id: "tx-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            entry_id: "entry-1".to_owned(),
            target: InjectionTarget::parse("example.com").expect("target"),
            credential: InjectionCredential::new(
                Some("fixture-user".to_owned()),
                "fixture-password-not-production".to_owned(),
            )
            .expect("credential"),
        }
    }

    #[tokio::test]
    async fn registry_dispatches_without_knowing_provider_implementation() {
        let seen = Arc::new(Mutex::new(None));
        let provider = Arc::new(RecordingProvider {
            id: ProviderId::parse("playwright").expect("provider id"),
            seen_password: Arc::clone(&seen),
        });
        let mut registry = InjectionProviderRegistry::new();
        registry.register(provider).expect("register provider");

        let result = registry
            .inject(&ProviderId::parse("playwright").expect("id"), request())
            .await
            .expect("inject");

        assert_eq!(result.outcome, InjectionOutcome::Injected);
        assert_eq!(
            seen.lock().expect("recording lock").as_deref(),
            Some("fixture-password-not-production")
        );
    }

    #[test]
    fn secret_debug_is_redacted_and_origin_is_https_and_domain_bound() {
        let request = request();
        let debug = format!("{request:?}");
        assert_eq!(
            debug,
            "InjectionRequest { transaction_id: \"tx-1\", grant_id: \"grant-1\", entry_id: \"entry-1\", target: InjectionTarget { expected_domain: \"example.com\" }, credential: \"[REDACTED]\" }"
        );
        assert!(
            request
                .target
                .verify_url("https://login.example.com/path")
                .is_ok()
        );
        assert_eq!(
            request.target.verify_url("https://example.net"),
            Err(InjectionError::OriginMismatch)
        );
        assert_eq!(
            request.target.verify_url("http://example.com"),
            Err(InjectionError::InsecureOrigin)
        );
    }

    #[test]
    fn form_definition_is_bounded_and_requires_explicit_transitions() {
        let valid = InjectionFormDefinition {
            version: 1,
            steps: vec![
                InjectionFormStep {
                    fields: vec![InjectionFormField {
                        entry_field_id: "credential.username".to_owned(),
                        selector: "#username".to_owned(),
                        control: InjectionControl::Username,
                    }],
                    submit: InjectionSubmit {
                        action: InjectionSubmitKind::PressEnter,
                        selector: "#username".to_owned(),
                    },
                    wait_for: Some(InjectionWaitFor {
                        selector: "#password".to_owned(),
                        timeout_ms: Some(20_000),
                    }),
                },
                InjectionFormStep {
                    fields: vec![InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "#password".to_owned(),
                        control: InjectionControl::Password,
                    }],
                    submit: InjectionSubmit {
                        action: InjectionSubmitKind::Click,
                        selector: "button[type=submit]".to_owned(),
                    },
                    wait_for: None,
                },
            ],
        };
        assert!(valid.validate().is_ok());
        let mut missing_transition = valid.clone();
        missing_transition.steps[0].wait_for = None;
        assert_eq!(
            missing_transition.validate(),
            Err(InjectionError::InvalidFormDefinition)
        );
        let mut duplicate = valid;
        let repeated = duplicate.steps[0].fields[0].clone();
        duplicate.steps[0].fields.push(repeated);
        assert_eq!(
            duplicate.validate(),
            Err(InjectionError::InvalidFormDefinition)
        );
    }

    #[tokio::test]
    async fn registry_fails_closed_for_unknown_or_duplicate_providers() {
        let seen = Arc::new(Mutex::new(None));
        let provider = Arc::new(RecordingProvider {
            id: ProviderId::parse("agent-browser").expect("provider id"),
            seen_password: seen,
        });
        let mut registry = InjectionProviderRegistry::new();
        registry
            .register(provider.clone())
            .expect("first registration");
        assert_eq!(
            registry.register(provider),
            Err(InjectionError::DuplicateProvider)
        );
        assert_eq!(
            registry
                .inject(&ProviderId::parse("unknown").expect("id"), request())
                .await,
            Err(InjectionError::ProviderUnavailable)
        );
    }
}
