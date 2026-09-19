//! Native-only rollout flag; discovery never changes credential authorization.
use crate::InjectServiceError;
use palladin_browser_bridge::InjectionFormDefinition;
#[cfg(test)]
use palladin_browser_bridge::{InjectionControl, InjectionSubmitKind};
pub(crate) fn enabled(value: Option<&str>) -> Result<bool, InjectServiceError> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(InjectServiceError::InvalidLiveFlag),
    }
}
pub(crate) fn validate(form: &InjectionFormDefinition) -> Result<(), InjectServiceError> {
    palladin_browser_bridge::live_login::validate_live_form(form)
        .map_err(|_| InjectServiceError::InvalidLiveForm)
}
#[cfg(test)]
mod tests {
    use super::*;
    use palladin_browser_bridge::{InjectionFormField, InjectionFormStep, InjectionSubmit};
    fn form(id: &str, control: InjectionControl) -> InjectionFormDefinition {
        let selector =
            |reference: &str| format!("palladin-live:{}:{}", "a".repeat(32), reference.repeat(32));
        InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![InjectionFormField {
                    entry_field_id: id.into(),
                    control,
                    selector: selector("b"),
                }],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::Click,
                    selector: selector("c"),
                },
                wait_for: None,
            }],
        }
    }
    #[test]
    fn rollout_flag_is_explicit_and_reversible() {
        assert!(!enabled(None).unwrap());
        assert!(!enabled(Some("0")).unwrap());
        assert!(enabled(Some("1")).unwrap());
        assert!(enabled(Some("true")).is_err());
        assert!(enabled(Some("")).is_err());
    }
    #[test]
    fn live_plan_cannot_request_notes_custom_fields_or_persistent_selectors() {
        for (id, control) in [
            ("credential.username", InjectionControl::Username),
            ("credential.password", InjectionControl::Password),
            ("credential.totp", InjectionControl::Otp),
        ] {
            validate(&form(id, control)).unwrap();
        }
        for id in ["credential.notes", "custom:secret", "credential.url"] {
            assert!(validate(&form(id, InjectionControl::Username)).is_err());
        }
        let mut changed = form("credential.password", InjectionControl::Password);
        changed.steps[0].fields[0].selector = "#password".into();
        assert!(validate(&changed).is_err());
        changed.steps[0].fields[0].selector =
            format!("palladin-live:{}:{}", "d".repeat(32), "b".repeat(32));
        assert!(validate(&changed).is_err());
    }
    #[test]
    fn missing_totp_grant_fails_without_using_another_field() {
        let parsed =
            palladin_credential::secret::parse_secret(br#"{"password":"synthetic-only"}"#).unwrap();
        let Err(error) = crate::resolve_injection_credential(
            &parsed,
            None,
            &form("credential.totp", InjectionControl::Otp),
        ) else {
            panic!("missing TOTP must fail before forwarding");
        };
        assert_eq!(
            error.to_string(),
            "the approved Inject delivery does not contain TOTP; check TOTP field access and grant material for the selected Entry"
        );
    }
    #[test]
    fn totp_is_generated_natively_and_only_current_code_enters_provider_values() {
        let parsed = palladin_credential::secret::parse_secret(br#"{"password":"synthetic-only","totp":"otpauth://totp/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}"#).unwrap();
        let value = crate::resolve_injection_credential(
            &parsed,
            None,
            &form("credential.totp", InjectionControl::Otp),
        )
        .unwrap();
        assert_eq!(value.fields().len(), 1);
        assert!(
            value.fields()["credential.totp"]
                .bytes()
                .all(|b| b.is_ascii_digit())
        );
        assert_eq!(value.fields()["credential.totp"].len(), 6);
    }
    #[test]
    fn live_frozen_v1_code_requires_refresh_before_provider_forward() {
        let parsed = palladin_credential::secret::parse_secret(br#"{"fields":[{"id":"credential.totp","label":"credential.totp","type":"text","value":"123456","agentVisible":true}]}"#).unwrap();
        let plan = form("credential.totp", InjectionControl::Otp);
        validate(&plan).unwrap();
        assert!(matches!(
            crate::resolve_injection_credential(&parsed, None, &plan),
            Err(InjectServiceError::TotpRefreshRequired)
        ));
    }

    #[test]
    fn live_v2_primary_or_unique_custom_source_forwards_only_current_code() {
        for id in [
            "credential.totp",
            "custom:11111111-1111-4111-8111-111111111111",
        ] {
            let source = serde_json::json!({"source":"totp","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":30});
            // Exact protected projection emitted by authenticated v2 normalization.
            let normalized = serde_json::to_vec(&serde_json::json!({"fields":[{"id":id.strip_prefix("custom:").unwrap_or(id),"label":"Authenticator","type":"totp","agentVisible":true,"value":source}]})).unwrap();
            let parsed = palladin_credential::secret::parse_secret(&normalized).unwrap();
            let plan = form("credential.totp", InjectionControl::Otp);
            validate(&plan).unwrap();
            let value = crate::resolve_injection_credential(&parsed, None, &plan).unwrap();
            assert_eq!(value.fields().len(), 1);
            let code = &value.fields()["credential.totp"];
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }
    #[test]
    fn live_ambiguous_custom_sources_fail_before_provider_forward() {
        let fields = ["a", "b"].map(|id| serde_json::json!({"id":id,"label":"totp","type":"totp","value":{"source":"totp","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":30}}));
        let normalized = serde_json::to_vec(&serde_json::json!({"fields":fields})).unwrap();
        let parsed = palladin_credential::secret::parse_secret(&normalized).unwrap();
        let plan = form("credential.totp", InjectionControl::Otp);
        validate(&plan).unwrap();
        assert!(matches!(
            crate::resolve_injection_credential(&parsed, None, &plan),
            Err(InjectServiceError::AmbiguousTotp)
        ));
    }
}
