//! Converts local capture to encrypted submission content without a printable intermediate.
use palladin_browser_bridge::capture::{CapturePlan, CaptureResult};
use palladin_crypto::{SubmissionContentV2, SubmissionCustomFieldV2, SubmissionEntryType};
use secrecy::SecretString;
use std::collections::BTreeMap;

pub fn validate_plan(
    plan: &CapturePlan,
    entry_type: SubmissionEntryType,
) -> Result<(), &'static str> {
    plan.validate()
        .map_err(|_| "invalid browser capture plan")?;
    for field in &plan.fields {
        match field.entry_field_id.as_str() {
            "username" | "password" if entry_type == SubmissionEntryType::Credential => {}
            "value" if entry_type == SubmissionEntryType::Key => {}
            "url" | "notes" => {}
            id if custom_field(id).is_some() => {}
            _ => return Err("unsupported captured entry field"),
        }
    }
    Ok(())
}
fn custom_field(id: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<_> = id.split(':').collect();
    if parts.len() != 4
        || parts[0] != "custom"
        || uuid::Uuid::parse_str(parts[1]).ok()?.to_string() != parts[1]
        || !matches!(parts[2], "text" | "multiline" | "concealed" | "totp")
        || !matches!(parts[3], "value" | "label")
    {
        return None;
    }
    Some((parts[1], parts[2], parts[3]))
}
pub fn into_content(
    mut result: CaptureResult,
    entry_type: SubmissionEntryType,
) -> Result<SubmissionContentV2, &'static str> {
    if result.outcome != "captured" {
        return Err("browser capture was not completed");
    }
    let mut content = SubmissionContentV2 {
        entry_type,
        username: None,
        password: None,
        value: None,
        url: None,
        notes: None,
        custom_fields: Vec::new(),
    };
    let mut custom: BTreeMap<String, (String, Option<SecretString>, Option<SecretString>)> =
        BTreeMap::new();
    for mut field in result.values.take().ok_or("missing captured fields")? {
        let value = std::mem::take(&mut field.value);
        let value = SecretString::from(value);
        match field.entry_field_id.as_str() {
            "username" if entry_type == SubmissionEntryType::Credential => {
                content.username = Some(value)
            }
            "password" if entry_type == SubmissionEntryType::Credential => {
                content.password = Some(value)
            }
            "value" if entry_type == SubmissionEntryType::Key => content.value = Some(value),
            "url" => content.url = Some(value),
            "notes" => content.notes = Some(value),
            id => {
                let (id, kind, part) =
                    custom_field(id).ok_or("unsupported captured entry field")?;
                let item = custom
                    .entry(format!("custom:{id}"))
                    .or_insert_with(|| (kind.into(), None, None));
                if item.0 != kind {
                    return Err("conflicting custom field types");
                }
                if part == "label" {
                    item.1 = Some(value);
                } else {
                    item.2 = Some(value);
                }
            }
        }
    }
    for (id, (field_type, label, value)) in custom {
        let value = value.ok_or("custom field value must be captured")?;
        content.custom_fields.push(SubmissionCustomFieldV2 {
            id,
            label: label.map(|label| {
                use secrecy::ExposeSecret;
                label.expose_secret().to_owned()
            }),
            field_type,
            value,
        });
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use serde_json::json;
    #[test]
    fn typed_custom_fields_and_sparse_builtin_values_are_preserved_without_literal_values() {
        let result:CaptureResult=serde_json::from_value(json!({"protocol":"palladin.inject-provider.v1","type":"capture.result","transactionId":"capture-1","outcome":"captured","values":[
            {"entryFieldId":"username","value":"synthetic-user"},
            {"entryFieldId":"custom:11111111-1111-4111-8111-111111111111:concealed:value","value":"synthetic-token"},
            {"entryFieldId":"custom:11111111-1111-4111-8111-111111111111:concealed:label","value":"Captured label"}
        ]})).unwrap();
        let content = into_content(result, SubmissionEntryType::Credential).unwrap();
        assert!(content.password.is_none());
        assert!(
            content.username.as_ref().unwrap().expose_secret() == "synthetic-user",
            "captured value differs from synthetic fixture"
        );
        assert_eq!(
            content.custom_fields[0].id,
            "custom:11111111-1111-4111-8111-111111111111"
        );
        assert!(
            content.custom_fields[0].value.expose_secret() == "synthetic-token",
            "captured value differs from synthetic fixture"
        );
        assert_eq!(
            content.custom_fields[0].label.as_deref(),
            Some("Captured label")
        );
        assert!(!format!("{content:?}").contains("synthetic"));
    }
    #[test]
    fn unsupported_type_field_and_custom_metadata_fail_closed() {
        for id in [
            "password",
            "script",
            "custom:bad:text:value",
            "custom:11111111-1111-4111-8111-111111111111:executable:value",
        ] {
            let plan=CapturePlan::parse(&json!({"targetTabId":7,"targetUrl":"https://example.test","fields":[{"entryFieldId":id,"selector":"#field","read":"value"}]}).to_string()).unwrap();
            assert!(validate_plan(&plan, SubmissionEntryType::Key).is_err());
        }
    }
}
