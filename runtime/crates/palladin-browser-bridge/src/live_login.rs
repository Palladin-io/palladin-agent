//! Value-free, bounded live-login continuation across the native/browser boundary.
//! A continuation is untrusted page-derived input, never an authorization to change origin.
use std::collections::BTreeSet;
use std::time::Duration;

use crate::{
    InjectionControl, InjectionError, InjectionFormDefinition, InjectionSubmitKind,
    validate_https_page_url,
};
use serde::{Deserialize, Serialize};

pub const MAX_LIVE_STEPS: usize = 8;
pub const LIVE_FLOW_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LiveContinuation {
    Ready {
        #[serde(rename = "currentUrl")]
        current_url: String,
        #[serde(rename = "documentId")]
        document_id: String,
        #[serde(rename = "liveForm")]
        live_form: InjectionFormDefinition,
    },
    Challenge {},
    NoForm {},
    Timeout {},
    OriginMismatch {},
    InsecureOrigin {},
    ProviderUnavailable {},
}

impl LiveContinuation {
    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Challenge {} => "challenge",
            Self::NoForm {} => "no-form",
            Self::Timeout {} => "timeout",
            Self::OriginMismatch {} => "origin-mismatch",
            Self::InsecureOrigin {} => "insecure-origin",
            Self::ProviderUnavailable {} => "provider-unavailable",
        }
    }
}

/// Holds only public selectors and submitted field identities. Both the runtime and host use
/// this boundary to prevent fresh selector handles from replaying an already submitted stage.
pub struct LiveLoginFlow {
    origin: url::Origin,
    current_url: String,
    form: InjectionFormDefinition,
    submitted_fields: BTreeSet<String>,
    steps: usize,
}

impl LiveLoginFlow {
    pub fn new(url: &str, form: InjectionFormDefinition) -> Result<Self, InjectionError> {
        validate_live_form(&form)?;
        Ok(Self {
            origin: exact_origin(url)?,
            current_url: url.to_owned(),
            form,
            submitted_fields: BTreeSet::new(),
            steps: 0,
        })
    }

    #[must_use]
    pub fn form(&self) -> &InjectionFormDefinition {
        &self.form
    }

    #[must_use]
    pub fn current_url(&self) -> &str {
        &self.current_url
    }

    #[must_use]
    pub const fn steps(&self) -> usize {
        self.steps
    }

    pub fn submitted(&mut self) -> Result<(), InjectionError> {
        if self.steps >= MAX_LIVE_STEPS || self.repeats_submitted_stage(&self.form) {
            return Err(InjectionError::InvalidFormDefinition);
        }
        self.submitted_fields
            .extend(self.form.field_ids().map(str::to_owned));
        self.steps += 1;
        Ok(())
    }

    fn repeats_submitted_stage(&self, form: &InjectionFormDefinition) -> bool {
        let new_password = !self.submitted_fields.contains("credential.password")
            && form.field_ids().any(|id| id == "credential.password");
        form.field_ids().any(|id| {
            self.submitted_fields.contains(id) && !(id == "credential.username" && new_password)
        })
    }

    /// Returns true only for a fresh next stage on the original exact HTTPS origin.
    /// Terminal no-form means discovery ended; it is not proof of authentication.
    pub fn advance(&mut self, continuation: &LiveContinuation) -> Result<bool, InjectionError> {
        let LiveContinuation::Ready {
            current_url,
            document_id,
            live_form,
        } = continuation
        else {
            return Ok(false);
        };
        if self.steps == 0
            || self.steps >= MAX_LIVE_STEPS
            || document_id.is_empty()
            || document_id.len() > 256
            || !document_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || exact_origin(current_url)? != self.origin
            || self.repeats_submitted_stage(live_form)
        {
            return Err(InjectionError::InvalidFormDefinition);
        }
        validate_live_form(live_form)?;
        self.form = live_form.clone();
        self.current_url.clone_from(current_url);
        Ok(true)
    }
}

pub fn validate_live_form(form: &InjectionFormDefinition) -> Result<(), InjectionError> {
    if is_deferred(form) {
        let step = &form.steps[0];
        // The extension freezes each field's writable/preserve mode at discovery.
        // A carried readonly/disabled identity is comparison-only, never rewritten.
        let shapes: Vec<_> = step
            .fields
            .iter()
            .map(|field| (field.entry_field_id.as_str(), field.control))
            .collect();
        if step.wait_for.is_some()
            || !matches!(
                shapes.as_slice(),
                [("credential.username", InjectionControl::Username)]
                    | [("credential.password", InjectionControl::Password)]
                    | [
                        ("credential.username", InjectionControl::Username),
                        ("credential.password", InjectionControl::Password)
                    ]
            )
        {
            return Err(InjectionError::InvalidFormDefinition);
        }
        let snapshot = live_snapshot(&step.submit.selector)?;
        let mut selectors = BTreeSet::from([step.submit.selector.as_str()]);
        for field in &step.fields {
            if live_snapshot(&field.selector)? != snapshot
                || !selectors.insert(field.selector.as_str())
            {
                return Err(InjectionError::InvalidFormDefinition);
            }
        }
        return Ok(());
    }
    form.validate()?;
    if form.steps.len() != 1 {
        return Err(InjectionError::InvalidFormDefinition);
    }
    let step = &form.steps[0];
    if step.wait_for.is_some()
        || step.submit.action != InjectionSubmitKind::Click
        || step.fields.len() > 2
    {
        return Err(InjectionError::InvalidFormDefinition);
    }
    let snapshot = live_snapshot(&step.submit.selector)?;
    let mut ids = BTreeSet::new();
    for field in &step.fields {
        if live_snapshot(&field.selector)? != snapshot
            || !ids.insert(field.entry_field_id.as_str())
            || !matches!(
                (field.entry_field_id.as_str(), field.control),
                ("credential.username", InjectionControl::Username)
                    | ("credential.password", InjectionControl::Password)
                    | ("credential.totp", InjectionControl::Otp)
            )
        {
            return Err(InjectionError::InvalidFormDefinition);
        }
    }
    if ids.contains("credential.totp") && ids.len() != 1 {
        return Err(InjectionError::InvalidFormDefinition);
    }
    Ok(())
}

/// A v2 selector here names a bound credential scope, not a guessed click target.
#[must_use]
pub fn is_deferred(form: &InjectionFormDefinition) -> bool {
    form.version == 2
        && form.steps.len() == 1
        && form.steps[0].submit.action == InjectionSubmitKind::DeferredNativeClick
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitReady {
    pub pending_id: String,
    pub current_url: String,
    pub document_id: String,
    pub submit_selector: String,
}
impl SubmitReady {
    pub fn validate(
        &self,
        original_url: &str,
        form: &InjectionFormDefinition,
    ) -> Result<(), InjectionError> {
        validate_live_form(form)?;
        if !is_deferred(form)
            || self.pending_id.len() != 32
            || !self
                .pending_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.document_id.is_empty()
            || self.document_id.len() > 256
            || !self
                .document_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || self.current_url != original_url
            || exact_origin(&self.current_url)? != exact_origin(original_url)?
        {
            return Err(InjectionError::InvalidFormDefinition);
        }
        if live_snapshot(&self.submit_selector)? != self.pending_id {
            return Err(InjectionError::InvalidFormDefinition);
        }
        Ok(())
    }
}

/// Value-free, one-shot second phase. Authorization is checked again before forwarding.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub transaction_id: String,
    pub prepared_transaction_id: String,
    pub grant_id: String,
    pub entry_id: String,
    pub expected_domain: String,
    pub submit_ready: SubmitReady,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelSubmitRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub transaction_id: String,
    pub prepared_transaction_id: String,
    pub pending_id: String,
}

fn exact_origin(value: &str) -> Result<url::Origin, InjectionError> {
    validate_https_page_url(value)?;
    url::Url::parse(value)
        .map(|url| url.origin())
        .map_err(|_| InjectionError::InvalidFormDefinition)
}

fn live_snapshot(selector: &str) -> Result<&str, InjectionError> {
    let (snapshot, reference) = selector
        .strip_prefix("palladin-live:")
        .and_then(|tail| tail.split_once(':'))
        .ok_or(InjectionError::InvalidFormDefinition)?;
    if [snapshot, reference].iter().any(|s| {
        s.len() != 32
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err(InjectionError::InvalidFormDefinition);
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form(field: &str, control: &str, snapshot: &str) -> InjectionFormDefinition {
        serde_json::from_value(serde_json::json!({"version":1,"steps":[{"fields":[{"entryFieldId":field,"control":control,"selector":format!("palladin-live:{}:{}",snapshot.repeat(32),"a".repeat(32))}],"submit":{"action":"click","selector":format!("palladin-live:{}:{}",snapshot.repeat(32),"b".repeat(32))}}]})).unwrap()
    }
    fn ready(url: &str, field: &str, control: &str, snapshot: &str) -> LiveContinuation {
        LiveContinuation::Ready {
            current_url: url.into(),
            document_id: "document-2".into(),
            live_form: form(field, control, snapshot),
        }
    }
    fn deferred_form() -> serde_json::Value {
        let mut value = serde_json::to_value(form("credential.username", "username", "a")).unwrap();
        value["version"] = serde_json::json!(2);
        value["steps"][0]["submit"]["action"] = serde_json::json!("deferred-native-click");
        value
    }
    #[test]
    fn deferred_identifier_has_explicit_scope_and_cannot_be_a_map() {
        let form: InjectionFormDefinition = serde_json::from_value(deferred_form()).unwrap();
        validate_live_form(&form).unwrap();
        assert!(
            form.validate().is_err(),
            "v2 live plan must not become a stored v1 map"
        );
        let mut flow = LiveLoginFlow::new("https://example.test/login", form).unwrap();
        assert_eq!(flow.steps(), 0, "filling alone does not commit a stage");
        flow.submitted().unwrap();
        assert_eq!(flow.steps(), 1);
    }
    #[test]
    fn deferred_identifier_rejects_scope_expansion_and_fake_clicks() {
        for (id, control) in [
            ("credential.password", "username"),
            ("credential.totp", "otp"),
            ("custom:other", "username"),
        ] {
            let mut value = deferred_form();
            value["steps"][0]["fields"][0]["entryFieldId"] = serde_json::json!(id);
            value["steps"][0]["fields"][0]["control"] = serde_json::json!(control);
            let form: InjectionFormDefinition = serde_json::from_value(value).unwrap();
            assert!(validate_live_form(&form).is_err());
        }
        let mut value = deferred_form();
        value["steps"][0]["submit"]["action"] = serde_json::json!("click");
        assert!(validate_live_form(&serde_json::from_value(value).unwrap()).is_err());
        let mut value = deferred_form();
        let extra =
            serde_json::to_value(form("credential.password", "password", "a")).unwrap()["steps"][0]
                ["fields"][0]
                .clone();
        value["steps"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(extra);
        assert!(validate_live_form(&serde_json::from_value(value).unwrap()).is_err());
    }

    fn deferred_password(carried_username: bool) -> InjectionFormDefinition {
        let mut value = deferred_form();
        let mut password = value["steps"][0]["fields"][0].clone();
        password["entryFieldId"] = serde_json::json!("credential.password");
        password["control"] = serde_json::json!("password");
        password["selector"] = serde_json::json!(format!(
            "palladin-live:{}:{}",
            "a".repeat(32),
            "c".repeat(32)
        ));
        if carried_username {
            value["steps"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(password);
        } else {
            value["steps"][0]["fields"][0] = password;
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn deferred_password_is_a_fresh_stage_with_optional_comparison_only_identity() {
        for carried in [false, true] {
            let password = deferred_password(carried);
            validate_live_form(&password).unwrap();
            assert!(
                password.validate().is_err(),
                "private v2 must not become a map"
            );
            assert!(LiveLoginFlow::new("https://example.test/password", password.clone()).is_ok());
            let mut flow = LiveLoginFlow::new(
                "https://example.test/login",
                serde_json::from_value(deferred_form()).unwrap(),
            )
            .unwrap();
            flow.submitted().unwrap();
            let next = LiveContinuation::Ready {
                current_url: "https://example.test/login#password".into(),
                document_id: "same-document".into(),
                live_form: password,
            };
            assert!(flow.advance(&next).unwrap());
            assert_eq!(flow.current_url(), "https://example.test/login#password");
            assert_eq!(flow.steps(), 1, "preparation does not count as a submit");
            flow.submitted().unwrap();
            assert_eq!(flow.steps(), 2);
            assert!(flow.advance(&next).is_err(), "password must never replay");
            assert!(
                flow.advance(&ready(
                    "https://example.test/otp",
                    "credential.totp",
                    "otp",
                    "d"
                ))
                .unwrap()
            );
            flow.submitted().unwrap();
            assert_eq!(flow.steps(), 3);
        }
    }

    #[test]
    fn deferred_password_rejects_reordered_duplicate_or_cross_snapshot_handles() {
        let valid = deferred_password(true);
        for mutation in [
            "order",
            "alias",
            "scope-alias",
            "snapshot",
            "otp",
            "duplicate",
        ] {
            let mut form = valid.clone();
            let step = &mut form.steps[0];
            match mutation {
                "order" => step.fields.reverse(),
                "alias" => step.fields[1].selector = step.fields[0].selector.clone(),
                "scope-alias" => step.fields[1].selector = step.submit.selector.clone(),
                "snapshot" => {
                    step.fields[1].selector =
                        format!("palladin-live:{}:{}", "d".repeat(32), "c".repeat(32))
                }
                "otp" => {
                    step.fields[1].entry_field_id = "credential.totp".into();
                    step.fields[1].control = InjectionControl::Otp;
                }
                "duplicate" => step.fields.push(step.fields[1].clone()),
                _ => unreachable!(),
            }
            assert!(validate_live_form(&form).is_err(), "{mutation}");
        }
    }

    #[test]
    fn one_flow_advances_username_password_totp() {
        let mut flow = LiveLoginFlow::new(
            "https://login.example.test/start",
            form("credential.username", "username", "a"),
        )
        .unwrap();
        flow.submitted().unwrap();
        assert!(
            flow.advance(&ready(
                "https://login.example.test/password",
                "credential.password",
                "password",
                "b"
            ))
            .unwrap()
        );
        flow.submitted().unwrap();
        assert!(
            flow.advance(&ready(
                "https://login.example.test/mfa",
                "credential.totp",
                "otp",
                "c"
            ))
            .unwrap()
        );
        flow.submitted().unwrap();
        assert!(!flow.advance(&LiveContinuation::NoForm {}).unwrap());
        assert_eq!(flow.steps(), 3);
    }
    #[test]
    fn username_can_carry_forward_only_with_a_new_password_stage() {
        let mut flow = LiveLoginFlow::new(
            "https://login.example.test",
            form("credential.username", "username", "a"),
        )
        .unwrap();
        flow.submitted().unwrap();
        let mut combined = form("credential.password", "password", "b");
        combined.steps[0]
            .fields
            .push(form("credential.username", "username", "b").steps[0].fields[0].clone());
        combined.steps[0].fields[1].selector =
            format!("palladin-live:{}:{}", "b".repeat(32), "d".repeat(32));
        let next = LiveContinuation::Ready {
            current_url: "https://login.example.test/password".into(),
            document_id: "document-2".into(),
            live_form: combined,
        };
        assert!(flow.advance(&next).unwrap());
        flow.submitted().unwrap();
        assert!(flow.advance(&next).is_err());
        assert_eq!(flow.steps(), 2);
    }

    #[test]
    fn fresh_handles_cannot_replay_a_submitted_field() {
        let mut flow = LiveLoginFlow::new(
            "https://login.example.test",
            form("credential.password", "password", "a"),
        )
        .unwrap();
        flow.submitted().unwrap();
        assert!(
            flow.advance(&ready(
                "https://login.example.test/retry",
                "credential.password",
                "password",
                "b"
            ))
            .is_err()
        );
        assert!(flow.submitted().is_err());
    }
    #[test]
    fn ready_cannot_broaden_origin_or_supply_arbitrary_fields() {
        for url in [
            "http://login.example.test",
            "https://other.example.test",
            "https://login.example.test:8443",
            "https://login.example.test.evil.test",
        ] {
            let mut flow = LiveLoginFlow::new(
                "https://login.example.test",
                form("credential.username", "username", "a"),
            )
            .unwrap();
            flow.submitted().unwrap();
            assert!(
                flow.advance(&ready(url, "credential.password", "password", "b"))
                    .is_err()
            );
        }
        let mut flow = LiveLoginFlow::new(
            "https://login.example.test",
            form("credential.username", "username", "a"),
        )
        .unwrap();
        flow.submitted().unwrap();
        assert!(
            flow.advance(&ready(
                "https://login.example.test",
                "custom.secret",
                "text",
                "b"
            ))
            .is_err()
        );
    }
    #[test]
    fn challenge_never_advances_and_terminal_results_cannot_carry_form_data() {
        let mut flow = LiveLoginFlow::new(
            "https://login.example.test",
            form("credential.username", "username", "a"),
        )
        .unwrap();
        flow.submitted().unwrap();
        assert!(!flow.advance(&LiveContinuation::Challenge {}).unwrap());
        assert!(
            serde_json::from_value::<LiveContinuation>(
                serde_json::json!({"outcome":"challenge","liveForm":{}})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<LiveContinuation>(
                serde_json::json!({"outcome":"ready","currentUrl":"https://login.example.test"})
            )
            .is_err()
        );
    }
}
