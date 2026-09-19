use super::*;
use palladin_credential::secret::parse_secret;

#[test]
fn v1_saved_code_requires_refresh_before_any_provider_forward() {
    let parsed = parse_secret(br#"{"fields":[{"id":"credential.totp","label":"credential.totp","type":"text","value":"123456"}]}"#).unwrap();
    assert!(matches!(
        resolve_injection_field(&parsed, None, &otp_field()),
        Err(InjectServiceError::TotpRefreshRequired)
    ));
}

fn otp_field() -> InjectionFormField {
    InjectionFormField {
        entry_field_id: "credential.totp".into(),
        selector: "#otp".into(),
        control: InjectionControl::Otp,
    }
}

#[test]
fn primary_or_unique_typed_custom_source_derives_only_code() {
    for id in ["credential.totp", "11111111-1111-4111-8111-111111111111"] {
        let bytes = serde_json::to_vec(&serde_json::json!({"fields":[{"id":id,"label":"arbitrary","type":"totp","value":{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8,"period":30}}]})).unwrap();
        let parsed = parse_secret(&bytes).unwrap();
        let code = resolve_injection_field(&parsed, None, &otp_field()).expect("typed source");
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }
}

#[test]
fn label_cannot_select_source_and_multiple_custom_totp_fail_closed() {
    let parsed =
        parse_secret(br#"{"fields":[{"id":"a","label":"totp","type":"text","value":"123456"}]}"#)
            .unwrap();
    assert!(resolve_injection_field(&parsed, None, &otp_field()).is_err());
    let bytes = serde_json::to_vec(&serde_json::json!({"fields":[
        {"id":"a","label":"totp","type":"totp","value":{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}},
        {"id":"b","label":"other","type":"totp","value":{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}}
    ]})).unwrap();
    let parsed = parse_secret(&bytes).unwrap();
    assert!(resolve_injection_field(&parsed, None, &otp_field()).is_err());
}

#[test]
fn authenticated_primary_wins_over_multiple_custom_sources() {
    let fields = ["credential.totp", "a", "b"].map(|id| serde_json::json!({
        "id":id,"label":"irrelevant","type":"totp","value":{
            "secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":if id == "credential.totp" {8} else {6},"period":30
        }
    }));
    let bytes = serde_json::to_vec(&serde_json::json!({"fields":fields})).unwrap();
    let parsed = parse_secret(&bytes).unwrap();
    let code = resolve_injection_field(&parsed, None, &otp_field()).unwrap();
    assert_eq!(code.len(), 8);
}

#[test]
fn custom_source_yields_only_otp_destination_value_in_provider_credential() {
    use palladin_browser_bridge::{InjectionFormStep, InjectionSubmit, InjectionSubmitKind};
    let parsed = parse_secret(br#"{"fields":[{"id":"a","label":"Authenticator","type":"totp","value":{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}}]}"#).unwrap();
    let form = InjectionFormDefinition {
        version: 1,
        steps: vec![InjectionFormStep {
            fields: vec![otp_field()],
            submit: InjectionSubmit {
                action: InjectionSubmitKind::Click,
                selector: "#submit".into(),
            },
            wait_for: None,
        }],
    };
    let credential = resolve_injection_credential(&parsed, None, &form).unwrap();
    assert_eq!(credential.fields().len(), 1);
    let code = &credential.fields()["credential.totp"];
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
}
