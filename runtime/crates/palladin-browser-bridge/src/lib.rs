#![forbid(unsafe_code)]

pub mod framing;
pub mod local_transport;
pub mod secure_transport;

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_ENTRY_FIELD_ID_BYTES: usize = 128;
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
                    || !valid_entry_field_id(&field.entry_field_id)
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
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CookieOverlayDismiss {
    pub selector: String,
    pub action: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CookieOverlay {
    pub selectors: Vec<String>,
    pub dismiss: CookieOverlayDismiss,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disappears: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FormDiscoveryMapDefinition {
    pub version: u8,
    pub form: InjectionFormDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookie_overlays: Vec<CookieOverlay>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FormDiscoveryMap {
    pub map_id: String,
    pub map_version: u32,
    pub domain: String,
    pub login_url: String,
    pub provider: String,
    pub fingerprint: String,
    pub map: FormDiscoveryMapDefinition,
    pub updated_at: String,
}

impl FormDiscoveryMap {
    pub fn validate(
        &self,
        expected_domain: &str,
        expected_provider: &str,
    ) -> Result<(), InjectionError> {
        let provider = ProviderId::parse(self.provider.clone())?;
        if self.map_id.is_empty()
            || self.map_id.len() > 64
            || self.map_version == 0
            || self.map_version > i32::MAX as u32
            || self.domain != expected_domain
            || provider.as_str() != expected_provider
            || !valid_catalog_domain(&self.domain)
            || self.updated_at.is_empty()
            || self.updated_at.len() > 128
            || self.fingerprint.len() != 64
            || !self
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.map.version != 1
            || self.map.form.validate().is_err()
            || !valid_map_login_url(&self.login_url, &self.domain)
            || !valid_cookie_overlays(&self.map.cookie_overlays)
            || self.fingerprint != map_fingerprint(self)?
        {
            return Err(InjectionError::InvalidFormDiscoveryMap);
        }
        Ok(())
    }

    #[must_use]
    pub fn applies_to_url(&self, value: &str) -> bool {
        Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str() == Some(self.domain.as_str())
                && url.port_or_known_default() == Some(443)
                && url.username().is_empty()
                && url.password().is_none()
        })
    }
}

fn valid_cookie_overlays(overlays: &[CookieOverlay]) -> bool {
    overlays.len() <= 4
        && overlays.iter().all(|overlay| {
            !overlay.selectors.is_empty()
                && overlay.selectors.len() <= 8
                && overlay
                    .selectors
                    .iter()
                    .all(|selector| valid_selector(selector))
                && overlay.dismiss.action == "click"
                && valid_selector(&overlay.dismiss.selector)
                && overlay.disappears.as_deref().is_none_or(valid_selector)
                && overlay
                    .frame
                    .as_deref()
                    .is_none_or(|frame| matches!(frame, "top" | "same-origin"))
        })
}

fn valid_map_login_url(value: &str, domain: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        value.len() <= 2_048
            && url.scheme() == "https"
            && url.host_str() == Some(domain)
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.query().is_none()
    })
}

pub fn form_discovery_map_login_url(
    current_url: &str,
    domain: &str,
) -> Result<String, InjectionError> {
    let mut url = Url::parse(current_url).map_err(|_| InjectionError::InvalidFormDiscoveryMap)?;
    url.set_query(None);
    url.set_fragment(None);
    let login_url = url.to_string();
    if !valid_catalog_domain(domain) || !valid_map_login_url(&login_url, domain) {
        return Err(InjectionError::InvalidFormDiscoveryMap);
    }
    Ok(login_url)
}

fn valid_catalog_domain(value: &str) -> bool {
    value.len() <= MAX_DOMAIN_BYTES
        && value.contains('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && value
            .rsplit('.')
            .next()
            .is_some_and(|label| label.len() >= 2)
}

pub fn form_discovery_map_fingerprint(
    domain: &str,
    login_url: &str,
    provider: &str,
    map: &FormDiscoveryMapDefinition,
) -> Result<String, InjectionError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintInput<'a> {
        domain: &'a str,
        login_url: &'a str,
        provider: &'a str,
        map: &'a FormDiscoveryMapDefinition,
    }

    if !valid_catalog_domain(domain)
        || ProviderId::parse(provider.to_owned()).is_err()
        || !valid_map_login_url(login_url, domain)
        || map.version != 1
        || map.form.validate().is_err()
        || !valid_cookie_overlays(&map.cookie_overlays)
    {
        return Err(InjectionError::InvalidFormDiscoveryMap);
    }
    let login_url = Url::parse(login_url).map_err(|_| InjectionError::InvalidFormDiscoveryMap)?;
    let input = serde_json::to_vec(&FingerprintInput {
        domain,
        login_url: login_url.path(),
        provider,
        map,
    })
    .map_err(|_| InjectionError::InvalidFormDiscoveryMap)?;
    let digest = Sha256::digest(input);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn map_fingerprint(map: &FormDiscoveryMap) -> Result<String, InjectionError> {
    form_discovery_map_fingerprint(&map.domain, &map.login_url, &map.provider, &map.map)
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

pub fn validate_https_page_url(value: &str) -> Result<(), InjectionError> {
    if value.is_empty() || value.len() > 4_096 || value != value.trim() {
        return Err(InjectionError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| InjectionError::InvalidOrigin)?;
    if parsed.scheme() != "https" {
        return Err(InjectionError::InsecureOrigin);
    }
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(InjectionError::InvalidOrigin);
    }
    Ok(())
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
    pub fn new(mut username: Option<String>, mut password: String) -> Result<Self, InjectionError> {
        if password.is_empty()
            || password.len() > MAX_FIELD_BYTES
            || username
                .as_deref()
                .is_some_and(|value| value.len() > MAX_FIELD_BYTES)
        {
            if let Some(username) = username.as_mut() {
                username.zeroize();
            }
            password.zeroize();
            return Err(InjectionError::InvalidCredential);
        }
        let mut fields = BTreeMap::new();
        if let Some(username) = username {
            fields.insert("credential.username".to_owned(), username);
        }
        fields.insert("credential.password".to_owned(), password);
        Ok(Self { fields })
    }

    pub fn from_fields(mut fields: BTreeMap<String, String>) -> Result<Self, InjectionError> {
        if fields.is_empty()
            || fields.len() > MAX_FORM_FIELDS
            || fields.iter().any(|(id, value)| {
                !valid_entry_field_id(id) || value.is_empty() || value.len() > MAX_FIELD_BYTES
            })
        {
            for value in fields.values_mut() {
                value.zeroize();
            }
            fields.clear();
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
    #[error("invalid Form Discovery Map")]
    InvalidFormDiscoveryMap,
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

fn valid_entry_field_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ENTRY_FIELD_ID_BYTES
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
    fn target_page_hint_requires_a_bounded_credential_free_https_url() {
        assert!(validate_https_page_url("https://example.com/login?flow=agent").is_ok());
        assert_eq!(
            validate_https_page_url("http://example.com/login"),
            Err(InjectionError::InsecureOrigin)
        );
        assert_eq!(
            validate_https_page_url("https://user:password@example.com/login"),
            Err(InjectionError::InvalidOrigin)
        );
    }

    #[test]
    fn arbitrary_field_credentials_reject_empty_values() {
        let mut fields = BTreeMap::new();
        fields.insert("custom:account.code".to_owned(), String::new());
        assert!(matches!(
            InjectionCredential::from_fields(fields),
            Err(InjectionError::InvalidCredential)
        ));
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

    #[test]
    fn backend_form_map_wire_contract_is_fingerprint_bound_and_exact_origin() {
        let map: FormDiscoveryMap = serde_json::from_str(r#"{
          "mapId":"11111111-1111-4111-8111-111111111111",
          "mapVersion":1,
          "domain":"accounts.google.com",
          "loginUrl":"https://accounts.google.com/",
          "provider":"playwright",
          "fingerprint":"f6f9b42f136c52f404542e6596a7aae9af598d05d49004a29615a83e3479aa35",
          "map":{"version":1,"form":{"version":1,"steps":[
            {"fields":[{"entryFieldId":"credential.username","selector":"input[autocomplete=\"username\"]","control":"username"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"},"waitFor":{"selector":"input[type=\"password\"]"}},
            {"fields":[{"entryFieldId":"credential.password","selector":"input[type=\"password\"]","control":"password"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"}}
          ]}},
          "updatedAt":"2026-08-15T12:00:00Z"
        }"#).expect("backend map");

        assert!(map.validate("accounts.google.com", "playwright").is_ok());
        assert!(valid_map_login_url(
            "https://accounts.google.com/pl/zaloguj/na-konto",
            "accounts.google.com"
        ));
        assert!(!valid_map_login_url(
            "https://accounts.google.com/?access_token=secret",
            "accounts.google.com"
        ));
        assert!(valid_map_login_url(
            "https://accounts.google.com/reset/one-time-token",
            "accounts.google.com"
        ));
        assert!(!valid_selector(&"😀".repeat(500)));
        assert!(map.applies_to_url("https://accounts.google.com/signin"));
        assert!(!map.applies_to_url("https://login.accounts.google.com/signin"));
        let mut wrong_origin = map.clone();
        wrong_origin.login_url = "https://login.accounts.google.com/".to_owned();
        assert_eq!(
            wrong_origin.validate("accounts.google.com", "playwright"),
            Err(InjectionError::InvalidFormDiscoveryMap)
        );
        let mut open_contract = map.clone();
        open_contract.provider = "selenium-grid".to_owned();
        open_contract.login_url = "https://accounts.google.com/pl/zaloguj".to_owned();
        open_contract.map.form.steps[0].fields[0].entry_field_id = "credential.totp".to_owned();
        open_contract.map.form.steps[0].fields[0].control = InjectionControl::Otp;
        open_contract.fingerprint = map_fingerprint(&open_contract).expect("fingerprint");
        assert!(
            open_contract
                .validate("accounts.google.com", "selenium-grid")
                .is_ok()
        );
        let mut overflowing_version = map.clone();
        overflowing_version.map_version = i32::MAX as u32 + 1;
        assert_eq!(
            overflowing_version.validate("accounts.google.com", "playwright"),
            Err(InjectionError::InvalidFormDiscoveryMap)
        );
        let mut wrong_fingerprint = map;
        wrong_fingerprint.map.form.steps[0].fields[0].selector = "#changed".to_owned();
        assert_eq!(
            wrong_fingerprint.validate("accounts.google.com", "playwright"),
            Err(InjectionError::InvalidFormDiscoveryMap)
        );

        let localized: FormDiscoveryMap = serde_json::from_str(r#"{
          "mapId":"22222222-2222-4222-8222-222222222222",
          "mapVersion":1,
          "domain":"example.org",
          "loginUrl":"https://example.org/pl/zaloguj-si%C4%99",
          "provider":"custom-browser",
          "fingerprint":"48807755c6780b76aa7842675e59dccdecd1aab96874c7979078ac489d934e9a",
          "map":{"version":1,"form":{"version":1,"steps":[{
            "fields":[{"entryFieldId":"credential.password","selector":"input[aria-label=\"Hasło użytkownika\"]","control":"password"}],
            "submit":{"action":"click","selector":"button[type=submit]"}
          }]},"cookieOverlays":[{
            "selectors":["[data-testid=cmp]"],
            "dismiss":{"selector":"button[data-action=accept]","action":"click"},
            "disappears":"[data-testid=cmp]",
            "frame":"same-origin"
          }]},
          "updatedAt":"2026-08-15T12:00:00Z"
        }"#).expect("localized map");
        assert!(localized.validate("example.org", "custom-browser").is_ok());
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
